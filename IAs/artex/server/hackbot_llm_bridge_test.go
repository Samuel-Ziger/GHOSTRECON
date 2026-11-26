package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/norma/llm"
)

type bridgeFakeProvider struct{}

func (bridgeFakeProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

func (bridgeFakeProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	name := "none"
	if len(req.Tools) > 0 {
		name = req.Tools[0].Name
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
		{Type: llm.BlockToolUse, ID: "call-fake", Name: name, Input: json.RawMessage(`{"ok":true}`)},
	}}, "tool_use", llm.Usage{InputTokens: 12, OutputTokens: 4}, nil
}

type bridgeResponsesProvider struct {
	terminal bool
}

func (p bridgeResponsesProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "resposta"}, nil) {
			return
		}
		if p.terminal {
			yield(llm.StreamEvent{
				Type: llm.SEMessageDelta, StopReason: "end_turn",
				Usage: llm.Usage{InputTokens: 8, OutputTokens: 2},
			}, nil)
		}
	}
}

func (bridgeResponsesProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	panic("Complete must not be called in this test")
}

func TestBridgeCollectAcceptsResponsesTerminalDelta(t *testing.T) {
	msg, stop, usage, err := bridgeCollect(
		context.Background(), bridgeResponsesProvider{terminal: true}, true, llm.CompletionRequest{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Text() != "resposta" || stop != "end_turn" || usage.OutputTokens != 2 {
		t.Fatalf("unexpected collected response: msg=%#v stop=%q usage=%#v", msg, stop, usage)
	}
}

func TestBridgeCollectRejectsBareEOFWithoutTerminalEvent(t *testing.T) {
	_, _, _, err := bridgeCollect(
		context.Background(), bridgeResponsesProvider{terminal: false}, true, llm.CompletionRequest{},
	)
	if err == nil || !strings.Contains(err.Error(), "terminal event") {
		t.Fatalf("expected terminal event error, got %v", err)
	}
}

func TestBridgeProviderFailureStatusDoesNotRetryExhaustedPlan(t *testing.T) {
	err := errors.New("openai-responses: The ChatGPT user has reached their Subscription Sharing usage limit")
	if got := bridgeProviderFailureStatus(err); got != http.StatusPaymentRequired {
		t.Fatalf("quota status = %d, want %d", got, http.StatusPaymentRequired)
	}
	if got := bridgeProviderFailureStatus(context.DeadlineExceeded); got != http.StatusGatewayTimeout {
		t.Fatalf("timeout status = %d, want %d", got, http.StatusGatewayTimeout)
	}
}

func TestBridgeCompletionRequestPreservesTools(t *testing.T) {
	arguments := `{"query":"CVE"}`
	request := hackbotBridgeRequest{
		Messages: []hackbotBridgeMessage{
			{Role: "system", Content: json.RawMessage(`"defensive assistant"`)},
			{Role: "user", Content: json.RawMessage(`"research this"`)},
			{Role: "assistant", ToolCalls: []hackbotBridgeToolCall{{
				ID: "call-1", Type: "function", Function: struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				}{Name: "search", Arguments: arguments},
			}}},
			{Role: "tool", ToolCallID: "call-1", Content: json.RawMessage(`"result"`)},
		},
	}
	request.Tools = append(request.Tools, hackbotBridgeTool{Type: "function", Function: struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	}{Name: "search", Description: "search", Parameters: map[string]any{"type": "object"}}})

	got, err := bridgeCompletionRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.System) != 1 || got.System[0] != "defensive assistant" {
		t.Fatalf("system prompt was not preserved: %#v", got.System)
	}
	if len(got.Tools) != 1 || got.Tools[0].Name != "search" {
		t.Fatalf("tool schema was not preserved: %#v", got.Tools)
	}
	if len(got.Messages) != 3 || len(got.Messages[1].ToolUses()) != 1 {
		t.Fatalf("tool call history was not preserved: %#v", got.Messages)
	}
	if got.Messages[2].Content[0].Type != llm.BlockToolResult || got.Messages[2].Content[0].ToolUseID != "call-1" {
		t.Fatalf("tool result was not preserved: %#v", got.Messages[2])
	}
}

func TestBridgeOpenAIMessageReturnsFunctionCalls(t *testing.T) {
	msg := llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
		llm.TextBlock("checking"),
		{Type: llm.BlockToolUse, ID: "call-9", Name: "lookup", Input: json.RawMessage(`{"id":9}`)},
	}}
	got, hasTools := bridgeOpenAIMessage(msg)
	if !hasTools || got["content"] != "checking" {
		t.Fatalf("unexpected conversion: %#v", got)
	}
	calls, ok := got["tool_calls"].([]map[string]any)
	if !ok || len(calls) != 1 || calls[0]["id"] != "call-9" {
		t.Fatalf("unexpected tool calls: %#v", got["tool_calls"])
	}
}

func TestHackbotProfileCompletionUsesCachedProfileWithoutLeakingCredential(t *testing.T) {
	s := &Server{provByProfile: map[int64]*provEntry{
		7: {prov: bridgeFakeProvider{}, cfg: agent.Config{Model: "private-model", Stream: false}},
	}}
	body := []byte(`{
		"model":"ignored-client-model",
		"messages":[{"role":"user","content":"look up"}],
		"tools":[{"type":"function","function":{"name":"lookup","description":"lookup","parameters":{"type":"object"}}}]
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/hackbot/llm/profiles/7/v1/chat/completions", bytes.NewReader(body))
	req.SetPathValue("id", "7")
	recorder := httptest.NewRecorder()

	s.hackbotProfileCompletion(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", recorder.Code, recorder.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["model"] != "private-model" || !strings.Contains(recorder.Body.String(), `"lookup"`) {
		t.Fatalf("unexpected bridge response: %s", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "ignored-client-model") {
		t.Fatalf("client-selected model leaked into provider response: %s", recorder.Body.String())
	}
}
