# Paridade da migração Vue → React

Inventário executado em 2026-11-18 sobre o antigo `frontend/index.html`.

## Superfícies migradas

- sidebar: health GHOST/Ollama/HexStrike, modelos, instalação, parâmetros
  Ollama, estatísticas, sessões e ações rápidas;
- chat: categorias, quick prompts, histórico, stream NDJSON, cancelamento,
  Markdown seguro, cópia de código e feedback bom/ruim;
- GHOSTRECON: ingestão SQLite, run JSON e NDJSON, runs/findings, análise IA e
  Auto determinístico;
- HexStrike: status, health completo, análise de alvo, seleção de ferramentas,
  comando genérico, relay JSON e injeção do resultado no chat;
- CodeScan: repositório/arquivo, filtros, análise estática e LLM, snippet,
  assembly/disassembly e cancelamento;
- memória: busca, categorias, exclusão e exportação;
- ensino: item individual e importação JSON em lote.

## Endpoints preservados

`/chat/stream`, `/health`, `/stats`, `/quickprompts`, `/models/install`,
`/sessions`, `/sessions/:id`, `/sessions/save`, `/memory/all`,
`/memory/categories`, `/memory/feedback`, `/memory/teach`,
`/memory/teach/bulk`, `/memory/:id`, `/memory/export`, `/ghostrecon/runs`,
`/ghostrecon/findings/:id`, `/ghostrecon/ingest/sqlite`,
`/ghostrecon/ingest/run`, `/ghostrecon/ingest/ndjson`,
`/ghostrecon/analyze`, `/ghostrecon/auto/stream`, `/hexstrike/status`,
`/hexstrike/health`, `/hexstrike/relay`, `/codescan/repo`,
`/codescan/snippet` e `/codescan/disasm`.

## Alterações deliberadas

- Vue CDN foi removido; React/ReactDOM entram no bundle local.
- Google Fonts remoto foi removido; os fallbacks CSS locais permanecem.
- saída Markdown agora escapa HTML do modelo antes da renderização.
- timers e `AbortController` são limpos no unmount.
- respostas HTTP não-2xx geram erro explícito nos fluxos principais.

## Validação

- teste unitário do recompositor NDJSON, API base, Markdown e eventos Auto;
- build Vite de produção;
- Playwright headless cobrindo as seis tabs, modal Auto e editor de snippet;
- Playwright com APIs simuladas cobrindo chat streaming, Auto streaming e
  CodeScan streaming;
- comparação automatizada confirmou paridade da lista de endpoints.
