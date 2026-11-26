# GHOST Local UI

Interface React local servida pelo FastAPI em `/gui/`.

## Desenvolvimento

```bash
npm install
npm run dev
```

O Vite usa a porta `5174` e encaminha as APIs para `127.0.0.1:8000`.

## Build e testes

```bash
npm test
npm run build
```

O build é gravado em `dist/`. O backend publica `dist/index.html` e monta os
assets em `/gui/assets`. React e ReactDOM estão no bundle; a UI não depende de
Vue nem de CDN em runtime.

## Contratos preservados

- streams NDJSON de chat, análise GHOSTRECON, Auto e CodeScan;
- cancelamento com `AbortController`;
- sessões, feedback, memória, ensino e exportação;
- ingestão SQLite, run JSON e NDJSON;
- bridge HexStrike e relay avançado;
- análise de repositório, snippet e disassembly;
- mesma origem da API em HTTP/HTTPS e fallback `127.0.0.1:8000` em `file://`.
