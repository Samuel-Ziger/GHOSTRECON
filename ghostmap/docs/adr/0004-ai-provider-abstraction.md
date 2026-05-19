# ADR-0004 — AI Layer Multi-Provider

## Status
Accepted — 2026-05-19

## Context
A camada de IA precisa:
- usar **múltiplos providers** (Anthropic, Google Gemini, OpenRouter — com vários modelos do OpenRouter contando como providers distintos — e Ollama local);
- permitir que **agentes diferentes** usem **modelos diferentes** (heatmap pode rodar em Ollama local barato; hipóteses ofensivas, num modelo de fronteira);
- isolar prompts e ferramentas por agente;
- **nunca** atacar automaticamente (apenas análise contextual).

## Decision
Arquitetura em três camadas:

```
+------------------------------------------------------+
|  Agents (flow_analyzer, trust_boundary_detector,     |
|          hypothesis_generator, heatmap_classifier)   |
+--------------------+---------------------------------+
                     | usa
                     v
+------------------------------------------------------+
|  AIOrchestrator (routing por policy, retries,        |
|                  fallback, cost tracking)            |
+--------------------+---------------------------------+
                     | chama
                     v
+------------------------------------------------------+
|  Providers (Anthropic | Gemini | OpenRouter[model] | |
|             Ollama) - interface comum LLMProvider    |
+------------------------------------------------------+
```

Cada agente declara em `agent.policy.yaml`:

```yaml
agent: hypothesis_generator
prefer: ["anthropic:claude-sonnet-4-6", "openrouter:openai/gpt-5"]
fallback: ["gemini:gemini-2.5-pro", "ollama:qwen3:32b"]
max_cost_usd: 0.05
require_json: true
```

Embeddings locais via Ollama (`nomic-embed-text` ou `bge-m3`) para evitar enviar payloads sensíveis de bug bounty para APIs externas por padrão.

## Princípios de Segurança Ofensiva
1. **No-attack policy** — agentes podem **classificar, correlacionar e hipotetizar**; nunca disparar exploit, fuzz payload em endpoint vivo, ou enviar requests modificadas sem o hunter clicar "replay".
2. **PII / token redaction** — antes de mandar para provider externo, `RedactionFilter` substitui JWTs, cookies de sessão, API keys e PII por placeholders. Ollama (local) recebe payload cru.
3. **Audit trail** — toda chamada para provider externo é logada em `ai_invocations` (Postgres) com hash do prompt para auditoria.

## Consequences
- **+** Pluggable: adicionar novo modelo OpenRouter = nova entrada de config.
- **+** Hunter mantém soberania de dados via Ollama.
- **+** Custo controlado por agente.
- **−** Mais código de plumbing — vale o investimento, pois testamos cada provider isoladamente.

## Alternativas Consideradas
- **LiteLLM** como gateway único: bom, mas adiciona dependência runtime; preferimos abstração própria fina.
- **LangChain agents**: overhead alto, comportamento difícil de auditar para uso ofensivo.
