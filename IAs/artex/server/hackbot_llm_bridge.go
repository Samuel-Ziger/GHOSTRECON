package server

// This file exposes a deliberately small OpenAI Chat Completions compatibility
// boundary for local, authenticated GHOSTRECON components.  It lets HackBot use
// an Artex LLM profile by id without copying the profile's API key (or the
// ChatGPT Plan refresh token) into HackBot's configuration.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/norma/llm"
)

type hackbotBridgeToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type hackbotBridgeMessage struct {
	Role       string                  `json:"role"`
	Content    json.RawMessage         `json:"content"`
	ToolCalls  []hackbotBridgeToolCall `json:"tool_calls"`
	ToolCallID string                  `json:"tool_call_id"`
}

type hackbotBridgeTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

type hackbotBridgeRequest struct {
	Model               string                 `json:"model"`
	Messages            []hackbotBridgeMessage `json:"messages"`
	Tools               []hackbotBridgeTool    `json:"tools"`
	MaxTokens           int                    `json:"max_tokens"`
	MaxCompletionTokens int                    `json:"max_completion_tokens"`
	Temperature         *float64               `json:"temperature"`
	Stop                json.RawMessage        `json:"stop"`
	Stream              bool                   `json:"stream"`
}

func bridgeContentText(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var plain string
	if err := json.Unmarshal(raw, &plain); err == nil {
		return plain, nil
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err != nil {
		return "", errors.New("message content must be text")
	}
	var out strings.Builder
	for _, part := range parts {
		switch part.Type {
		case "text", "input_text", "output_text", "":
			out.WriteString(part.Text)
		default:
			return "", fmt.Errorf("unsupported message content type %q", part.Type)
		}
	}
	return out.String(), nil
}

func bridgeStop(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil && one != "" {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	return nil
}

func bridgeCompletionRequest(in hackbotBridgeRequest) (llm.CompletionRequest, error) {
	out := llm.CompletionRequest{
		Temperature: in.Temperature,
		Stop:        bridgeStop(in.Stop),
		MaxTokens:   in.MaxTokens,
	}
	if out.MaxTokens <= 0 {
		out.MaxTokens = in.MaxCompletionTokens
	}
	for _, tool := range in.Tools {
		if tool.Type != "" && tool.Type != "function" {
			continue
		}
		if strings.TrimSpace(tool.Function.Name) == "" {
			return out, errors.New("tool function name is required")
		}
		params := tool.Function.Parameters
		if params == nil {
			params = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		out.Tools = append(out.Tools, llm.ToolSchema{
			Name: tool.Function.Name, Description: tool.Function.Description, InputSchema: params,
		})
	}
	for _, msg := range in.Messages {
		text, err := bridgeContentText(msg.Content)
		if err != nil {
			return out, err
		}
		switch strings.ToLower(strings.TrimSpace(msg.Role)) {
		case "system", "developer":
			if text != "" {
				out.System = append(out.System, text)
			}
		case "user":
			out.Messages = append(out.Messages, llm.UserText(text))
		case "assistant":
			content := make([]llm.ContentBlock, 0, 1+len(msg.ToolCalls))
			if text != "" {
				content = append(content, llm.TextBlock(text))
			}
			for _, call := range msg.ToolCalls {
				arguments := strings.TrimSpace(call.Function.Arguments)
				if arguments == "" || !json.Valid([]byte(arguments)) {
					arguments = "{}"
				}
				content = append(content, llm.ContentBlock{
					Type: llm.BlockToolUse, ID: call.ID, Name: call.Function.Name, Input: json.RawMessage(arguments),
				})
			}
			out.Messages = append(out.Messages, llm.Message{Role: llm.RoleAssistant, Content: content})
		case "tool":
			if msg.ToolCallID == "" {
				return out, errors.New("tool_call_id is required for tool messages")
			}
			out.Messages = append(out.Messages, llm.Message{
				Role:    llm.RoleUser,
				Content: []llm.ContentBlock{llm.ToolResultText(msg.ToolCallID, text, false)},
			})
		default:
			return out, fmt.Errorf("unsupported message role %q", msg.Role)
		}
	}
	if len(out.Messages) == 0 {
		return out, errors.New("at least one user or assistant message is required")
	}
	return out, nil
}

func bridgeCollect(ctx context.Context, provider llm.Provider, cfgStreaming bool, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	if !cfgStreaming {
		return provider.Complete(ctx, req)
	}
	acc := llm.NewAccumulator()
	terminal := false
	for event, err := range provider.Stream(ctx, req) {
		if err != nil {
			return llm.Message{}, "", acc.Usage, err
		}
		acc.Add(event)
		// Anthropic and Chat Completions emit message_stop. Norma's Responses
		// adapter instead emits a terminal message_delta (with stop_reason) and
		// then reaches EOF. Both are successful terminal contracts.
		if event.Type == llm.SEMessageStop || (event.Type == llm.SEMessageDelta && event.StopReason != "") {
			terminal = true
		}
	}
	if !terminal {
		return llm.Message{}, "", acc.Usage, errors.New("provider stream ended before a terminal event")
	}
	return acc.Message(), acc.StopReason, acc.Usage, nil
}

func bridgeFinishReason(reason string, hasTools bool) string {
	if hasTools {
		return "tool_calls"
	}
	switch strings.ToLower(reason) {
	case "max_tokens", "length":
		return "length"
	case "content_filter":
		return "content_filter"
	default:
		return "stop"
	}
}

func bridgeProviderFailureStatus(err error) int {
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout
	}
	message := strings.ToLower(err.Error())
	// OpenAI-compatible clients retry 429 and 5xx automatically. A plan quota is
	// not transient, so use 402 at this internal boundary; the HackBot adapter
	// translates it to an actionable 429 for the browser without retrying it.
	if strings.Contains(message, "subscription sharing usage limit") ||
		strings.Contains(message, "insufficient_quota") ||
		strings.Contains(message, "quota exceeded") {
		return http.StatusPaymentRequired
	}
	if strings.Contains(message, "content was flagged") {
		return http.StatusForbidden
	}
	return http.StatusBadGateway
}

func bridgeID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err == nil {
		return "chatcmpl-artex-" + hex.EncodeToString(buf)
	}
	return fmt.Sprintf("chatcmpl-artex-%d", time.Now().UnixNano())
}

func bridgeOpenAIMessage(msg llm.Message) (map[string]any, bool) {
	text := msg.Text()
	tools := msg.ToolUses()
	out := map[string]any{"role": "assistant", "content": text}
	if text == "" {
		out["content"] = nil
	}
	if len(tools) > 0 {
		calls := make([]map[string]any, 0, len(tools))
		for _, tool := range tools {
			args := strings.TrimSpace(string(tool.Input))
			if args == "" {
				args = "{}"
			}
			calls = append(calls, map[string]any{
				"id": tool.ID, "type": "function",
				"function": map[string]any{"name": tool.Name, "arguments": args},
			})
		}
		out["tool_calls"] = calls
	}
	return out, len(tools) > 0
}

func bridgeUsage(usage llm.Usage) map[string]any {
	return map[string]any{
		"prompt_tokens": usage.InputTokens, "completion_tokens": usage.OutputTokens,
		"total_tokens":          usage.InputTokens + usage.OutputTokens,
		"prompt_tokens_details": map[string]any{"cached_tokens": usage.CacheReadTokens},
	}
}

func writeBridgeSSE(w http.ResponseWriter, id, model string, msg map[string]any, finish string, usage map[string]any) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	created := time.Now().Unix()
	chunk := func(delta map[string]any, finishReason any, includeUsage any) {
		body := map[string]any{
			"id": id, "object": "chat.completion.chunk", "created": created, "model": model,
			"choices": []map[string]any{{"index": 0, "delta": delta, "finish_reason": finishReason}},
		}
		if includeUsage != nil {
			body["usage"] = includeUsage
		}
		encoded, _ := json.Marshal(body)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", encoded)
	}
	delta := map[string]any{"role": "assistant"}
	if content, ok := msg["content"]; ok && content != nil {
		delta["content"] = content
	}
	if calls, ok := msg["tool_calls"].([]map[string]any); ok {
		streamCalls := make([]map[string]any, 0, len(calls))
		for index, call := range calls {
			streamCalls = append(streamCalls, map[string]any{
				"index": index, "id": call["id"], "type": "function", "function": call["function"],
			})
		}
		delta["tool_calls"] = streamCalls
	}
	chunk(delta, nil, nil)
	chunk(map[string]any{}, finish, usage)
	_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
}

func (s *Server) hackbotProfileCompletion(w http.ResponseWriter, r *http.Request) {
	profileID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || profileID <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid LLM profile id")
		return
	}
	var body hackbotBridgeRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
	if err := decoder.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid chat completion request")
		return
	}
	req, err := bridgeCompletionRequest(body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	provider, cfg, ok := s.providerForProfile(profileID)
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "LLM profile is unavailable or has no usable credential")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	msg, stop, usage, err := bridgeCollect(ctx, provider, cfg.Stream || cfg.ChatGPTPlan, req)
	if err != nil {
		writeErr(w, bridgeProviderFailureStatus(err), "LLM profile request failed: "+err.Error())
		return
	}
	openAIMessage, hasTools := bridgeOpenAIMessage(msg)
	id := bridgeID()
	finish := bridgeFinishReason(stop, hasTools)
	usageBody := bridgeUsage(usage)
	if body.Stream {
		writeBridgeSSE(w, id, cfg.Model, openAIMessage, finish, usageBody)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": id, "object": "chat.completion", "created": time.Now().Unix(), "model": cfg.Model,
		"choices": []map[string]any{{"index": 0, "message": openAIMessage, "finish_reason": finish}},
		"usage":   usageBody,
	})
}
