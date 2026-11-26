# GHOSTRECON React UI

Este diretório contém o host React 18/TypeScript das dez rotas servidas pela
API Express: cockpit raiz e nove páginas auxiliares. Os documentos em
`templates/` são fontes versionadas de layout, estilos e contratos; os arquivos
em `public/` são shells com `#root` e o bundle local.

## Estado real

Toda a árvore visual passa pelo reconciler React, sem
`dangerouslySetInnerHTML`. As seis páginas auxiliares interativas são
React/TypeScript nativo:

- Cortex;
- Reporte;
- Pós-exploração;
- Tor Validator;
- Vigolium Workbench;
- Wi-Fi Pentest.
- GhostIA/Artex, com chat, histórico, teste real do provider e configuração de perfil.

O guia é estático e o MITRE Map local é somente um redirect compatível para
a rota React do GhostMap.

O cockpit raiz ainda é **híbrido**. React controla a árvore, o formulário
principal, Pipeline, Findings, overlays e stores; serviços TypeScript controlam
API/auth/CSRF, NDJSON, Manual Recon, Auto/Forge, infraestrutura/histórico,
Vigolium, exports e integrações. O script de compatibilidade ainda coordena
`startRecon`, `startAutoModeRecon`, efeitos dos eventos NDJSON e parte da
apresentação. Ele não possui chamadas `fetch` operacionais: todas delegam para
serviços tipados.

Não descreva o cockpit como 100% declarativo enquanto
`CockpitPage.tsx` continuar chamando `executeScripts`.

## Estrutura

- `src/features/cockpit/`: host e bridge dos serviços;
- `src/features/run-form/`: modelo, store, controles e dispatcher NDJSON;
- `src/features/execution/`: store compartilhado, Pipeline e Findings;
- `src/features/manual-recon/`, `auto-forge/`, `infra-history/`, `vigolium/`:
  transportes e modelos por domínio;
- `src/features/exports-integrations/`: exports, popups, storage e canais;
- `src/features/help/`: overlays declarativos;
- `src/features/pages/`: rotas auxiliares nativas;
- `src/services/`: API, storage seguro e framing NDJSON;
- `contracts/`: inventário e matriz auditável;
- `templates/`: conteúdo visual/compatibilidade preservado.

## Contratos protegidos

- 225 IDs do cockpit e 88 valores de módulo;
- URLs públicas existentes;
- API key, CSRF, headers/cookies opcionais e modo `file://`;
- lote de até 25 alvos e cascata de até 50 subdomínios por raiz;
- storage, BroadcastChannel, globals de integração e nomes de download;
- popups abertos antes de operações assíncronas;
- eventos NDJSON, estados de pipeline e resultados terminais.

As contagens e o limite do adapter estão documentados em
`contracts/cockpit-migration-matrix.json`; gere novamente o inventário sempre
que um template ou contrato mudar.

## Comandos

```bash
npm run ui:dev
npm run ui:inventory
npm run ui:typecheck
npm run ui:build
npm run test:ui
npm run ui:smoke
```

O build Vite é IIFE, sem CDN e sem módulos no navegador. Os artefatos estáveis
ficam em `public/assets/ghostrecon-ui.js` e
`public/assets/ghostrecon-ui.css`, compatíveis com HTTP e `file://`.

Veja o inventário completo em `../docs/FRONTEND-REACT-MAP.md`.
