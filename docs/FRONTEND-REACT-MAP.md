# Mapa da migração React

Data da consolidação: 2026-11-18

Este documento é o inventário funcional das interfaces do GHOSTRECON depois
da migração. Ele separa três situações que não devem ser confundidas:

- interface reescrita com estado, efeitos e eventos React;
- interface que já era React e foi preservada;
- cockpit renderizado pelo React, mas ainda apoiado por um controller de
  compatibilidade para parte da orquestração.

Portanto, é correto afirmar que todas as superfícies operacionais mapeadas são
servidas por React. Ainda não é correto afirmar que o cockpit raiz é 100%
declarativo ou 100% React nativo.

## Matriz das superfícies

| Superfície | Situação anterior | Situação atual | Estado real |
| --- | --- | --- | --- |
| Cockpit raiz | HTML/CSS/JS inline | React 18, TypeScript e Vite/IIFE | Híbrido: árvore React, serviços tipados e controller compatível |
| Nove rotas públicas auxiliares | Documentos HTML independentes | Mesmo bundle React do cockpit | Sete interativas nativas, guia estático e redirect MITRE compatível |
| GhostDesk | Vue 3/Vite | React 18/Vite | Reescrito |
| GhostTrace | React 18/Next 15 | React 18/Next 15 | Preservado |
| GhostMap | React 18/Next 14 | React 18/Next 14 | Preservado e ampliado |
| MITRE Live do GhostMap | iframe HTML/JS | Componente React/Next | Reescrito; HTML antigo é fallback não canônico |
| GHOST Local | Vue por CDN em um HTML | React 18/Vite local | Reescrito |
| Vigolium Workbench do cockpit | HTML/JS inline | React/TypeScript no bundle raiz | Reescrito |
| Workbench e relatórios do motor Vigolium | React/Next e React/Vite | Mantidos no motor | Preservados |
| News Verifier / LinkSeguro | HTML/CSS/JS standalone | React 18/Vite | Reescrito |

Diretórios `clone/`, fixtures de teste, cópias de sites analisados e
artefatos importados não são interfaces do produto e não fazem parte desta
migração.

## Host React do cockpit e das rotas públicas

O host vive em `frontend/`. Os documentos completos foram movidos para
`frontend/templates/`; os arquivos em `public/` agora são shells pequenos com
`#root`, CSS e o bundle IIFE. O registro em `frontend/src/page-registry.ts`
mantém as URLs existentes:

- `/` e `/index.html`: cockpit;
- `/como-usar.html`: guia estático;
- `/cortex.html`: Cortex;
- `/mitre-map.html`: redirect compatível para o GhostMap;
- `/post-exploitation.html`: trilha de pós-exploração;
- `/reporte.html`: checklist e relatório;
- `/tor-validator.html`: validação de túnel/Tor;
- `/vigolium-workbench.html`: Workbench integrado;
- `/wifi-pentest.html`: readiness e execução Wi-Fi autorizada.
- `/ghostia.html`: chat dedicado do Artex, diagnóstico do provider e histórico GhostIA.

O conversor de DOM cria elementos React sem
`dangerouslySetInnerHTML`. O build local não depende de React por CDN e produz
nomes estáveis:

- `public/assets/ghostrecon-ui.js`;
- `public/assets/ghostrecon-ui.css`.

O formato IIFE, URLs relativas e os fallbacks de API preservam o modo
`file://`. Source maps públicos não são gerados.

### Métricas auditáveis do cockpit

A fonte de verdade é
`frontend/contracts/cockpit-migration-matrix.json`; o inventário mecânico fica
em `frontend/contracts/ui-inventory.json`.

| Medida no template do cockpit | Baseline | Atual |
| --- | ---: | ---: |
| Funções nomeadas | 180 | 101 |
| Arrow functions | 16 | 11 |
| Handlers inline | 309 | 89 |
| `addEventListener` | 38 | 34 |
| Ocorrências de `fetch(` | 32 | 4 |
| Chamadas `fetch` operacionais no controller | 32 | 0 |
| IDs de DOM preservados | 225 | 225 |
| Valores de módulo preservados | 88 | 88 |

As quatro ocorrências atuais de `fetch(` são texto inerte do cheatsheet XSS,
não chamadas de rede do controller. O template atual tem aproximadamente
9,3 mil linhas; contagens exatas devem ser regeneradas com
`npm run ui:inventory`.

### Domínios nativos extraídos

Os seguintes blocos não fazem mais transporte direto pelo controller:

- API base, API key, auth opcional, headers de programa e CSRF;
- framing e consumo incremental de NDJSON;
- estado compartilhado de alvo, fila, cascata, stats, pipeline, cobertura,
  findings e bundle final;
- Pipeline e Findings declarativos, inclusive busca, filtros, chips, score,
  OWASP, MITRE, OPEN, COPY e descarte por fingerprint;
- projeção controlada de alvo, lote, perfil e 88 checkboxes de módulo;
- normalização de alvo, lote de até 25 itens, cascata de até 50
  subdomínios por raiz e regras fora de escopo;
- construção do payload manual com auth, OPSEC, FrameSeven e Vigolium;
- autorização temporária, preflight, plano selado, approval e abertura do
  stream Manual Recon;
- stream, resume, cancelamento, polling terminal, approval e persistência do
  modo Auto;
- listagem, inspeção, decisão, canary, promoção, rollback e veredito do
  Forge;
- auto-auth local, Auto RAG, intelligence corpus, PATH de ferramentas, túnel,
  histórico de runs, validações manuais e preflight LM Studio;
- perfis, presets, auth compare, guardrails, capabilities, health e catálogo
  Vigolium;
- exports JSON completo/high/validado, bundle de plataforma, Markdown
  técnico/bounty, TXT e downloads históricos;
- integrações com Reporte, GhostMap, Cortex, History, Workbench, GhostDesk,
  GHOST Local, Wi-Fi e pós-exploração;
- oito overlays de ajuda/consentimento, Escape, backdrop, clipboard e seleção
  de provedor.

### Contratos funcionais preservados

1. Execução e escopo
   - alvo único, lote sequencial e cascata de subdomínios;
   - quick, standard e deep;
   - exclusões fora de escopo e baselines cumulativos;
   - engagement, operador, playbook e autorização vinculada ao hash do plano.

2. Auto, Forge e motores opcionais
   - sessão nova, retomada, cancelamento e confirmação terminal;
   - estados completed, partial, timeout, stalled, failed e cancelled;
   - FrameSeven e Vigolium condicionados por autonomia/autorização;
   - inspeção e ciclo de vida de artefatos Forge.

3. Eventos e apresentação
   - `log`, `progress`, `pipe`, `pipe_detail`, `stats`, `finding` e `done`;
   - eventos de Auto, Forge, coverage, inteligência e motores;
   - fases started/done/partial/timeout/skipped/failed/cancelled;
   - terminal, progresso, tempo, estatísticas e correlação final.

4. Persistência e comunicação
   - `ghostrecon_api_base`, `ghostrecon_auth_json`,
     `ghostrecon_profile`, `ghostrecon_dismissed_fps`;
   - `ghostrecon.auto.lastSessionId`, engagement, operador, playbook,
     identidade, Navigator, Tor, Proxychains e preferências anônimas;
   - `ghostrecon_mitre_live_session_id`, payloads Reporte e perfil Vigolium;
   - `ghostrecon-mitre-${sessionId}`, `ghostrecon-history` e evento de storage
     `ghostrecon_manual_val_bump`.

5. Integrações de janela
   - popups são abertos sincronamente quando necessário para não serem
     bloqueados pelo navegador;
   - handoff Reporte/GhostTrace e sincronização GhostMap permanecem;
   - nomes de globals, arquivos exportados, storage e canais foram mantidos
     durante a transição.

### Limite ainda existente no cockpit

`CockpitPage.tsx` ainda executa o script versionado de
`frontend/templates/index.html` depois do commit React. Permanecem ali:

- `startRecon` e `startAutoModeRecon` como coordenadores de alto nível;
- efeitos de eventos NDJSON, prompts de aprovação e apresentação terminal;
- construção visual de partes de Auto/Forge, catálogo/health Vigolium e
  configurações OPSEC;
- espelho mutável de findings para compatibilidade;
- handlers inline confiáveis convertidos para callbacks React pelo reconciler.

O controller não possui mais `fetch` operacional: ele chama os serviços
TypeScript. Essa arquitetura reduz o risco de perder funções, mas continua
híbrida. A remoção definitiva do controller exige portar esses efeitos e
coordenadores para hooks/componentes e ampliar os smokes de Auto e RUN.

## Rotas auxiliares do bundle raiz

### Cortex

React/TypeScript nativo, sem executar o controller do template. Mantém 35 IDs,
categorias e detalhes do Brain, modo demo, busca, descrições educativas,
notas/marcação, drawer, atalhos, grid e grafo com física/drag. Mantém os
contratos de categorias, detalhe, CSRF, descrição e validação manual.

### Reporte

React/TypeScript nativo, sem controller legado. Preserva payload de sessão e
compartilhado, histórico de runs, import/dock JSON, filtros, notas, validações
por fingerprint, Brain, BroadcastChannel, handoff GhostTrace e exports
JSON/Markdown/HTML/PDF/clipboard.

### Vigolium Workbench integrado

React/TypeScript nativo. Preserva overview/status, scans, requests, findings,
OAST, relatórios, catálogo de módulos e sessões do agente. Mantém filtros,
agrupamento, detalhes, import de relatório, templates de review, envio de
request/finding ao agente e modos do agente.

### Pós-exploração

React/TypeScript nativo. Mantém os nove módulos, progresso em localStorage,
busca/filtros, navegação por módulo, cópia de comandos e SearchSploit com
fallback para comando manual.

### Tor Validator

React/TypeScript nativo. Mantém validação direta/Tor/serviço, resumo e opção
de repetir a validação automaticamente a cada 12 segundos.

### Wi-Fi Pentest

React/TypeScript nativo. Mantém capabilities/readiness, alvos e wordlist,
confirmação explícita de rede autorizada, stream, parada por AbortController,
log e findings.

### GhostIA

React/TypeScript nativo. O cockpit expõe a GhostIA como uma ferramenta e abre
`/ghostia.html` em tela própria. A página possui três áreas nativas: chat
Artex, multiagentes HackBot e engagements NeuroSploit. O chat mantém conversas
e perfis separados, mostra atividades e erros do Artex, busca o detalhe
integral das respostas e oferece um teste real do provider antes do envio.
Trocar o perfil prepara uma nova conversa para impedir que uma sessão antiga
continue silenciosamente presa ao modelo anterior.

O workspace NeuroSploit reaproveita os mesmos perfis API/Codex, permite
configurar modo e estratégia, aplica o gate de engagement nos modos de rede e
mostra progresso, logs redigidos, findings, Cortex e downloads autenticados.
Ele não incorpora o frontend original do motor.

O modal nativo do Modo Auto também pertence ao NeuroSploit. Ele conserva os
controles de alvo, autonomia, OPSEC, engagement e motores, acrescenta a
configuração multiagente e envia tudo no próprio stream Auto. Não existe mais
uma tarefa Artex lateral no controller do cockpit.

### Guia e redirect MITRE

O guia é conteúdo estático renderizado como árvore React e não possui
controller. `/mitre-map.html` é apenas a rota de compatibilidade que encaminha
para o GhostMap e ainda usa o adapter documental; a experiência MITRE canônica
é a rota React nativa do GhostMap.

## GhostDesk

O Vue foi removido. A aplicação React preserva as rotas hash Dashboard,
Scans, Projetos, Clientes e Intel, o layout/sidebar, busca global e o cliente
HTTP. Também mantém:

- auto-auth loopback, API key e CSRF;
- toggle SQLite/Supabase;
- CRUD e relacionamento projeto-cliente;
- filtros, detalhes e acompanhamento de scans;
- fluxo `report-payload -> anotacao-handoff -> /anotacao/ghostrecon/import`.

## GhostTrace

GhostTrace já era React/Next e foi preservado. Continua servindo documentação
operacional, projetos, vulnerabilidades, editor TipTap e relatórios sob o proxy
`/anotacao`. Typecheck e build fazem parte do job de frontend da CI.

## GhostMap e MITRE Live

GhostMap já era React/Next e foi preservado. A rota
`/ghostmap/ghostrecon` agora monta `MitreLivePage` diretamente, sem iframe.
Foram mantidos matriz MITRE/OWASP, milestones, HUD, busca/filtros, zoom,
findings, peers, cascata, import/export JSON, replay e BroadcastChannel. O HTML
antigo permanece somente como fallback não canônico.

## GHOST Local

O Vue por CDN foi substituído por React/Vite local. Foram preservados:

- chat NDJSON, cancelamento, Markdown seguro, cópia e feedback;
- health do GHOST/Ollama/HexStrike, modelos e parâmetros;
- sessões, memória, ensino individual e import/export em lote;
- ingestão SQLite/run/NDJSON, consulta de runs/findings e análise;
- Auto determinístico;
- status, health, relay e ferramentas HexStrike;
- CodeScan de repositório/snippet/disassembly.

O FastAPI serve o `dist`; os scripts de setup/start compilam ou usam fallback
controlado quando necessário.

## Vigolium

O motor Go e suas interfaces React existentes foram preservados. O cockpit
ganhou dois níveis React:

- controles e serviços tipados de perfil, presets, auth compare, guardrails,
  health e catálogo dentro do cockpit;
- a rota nativa `/vigolium-workbench.html` para dados do servidor Vigolium.

O Workbench Next e os relatórios estáticos React do repositório Vigolium não
foram reimplementados desnecessariamente.

## News Verifier

O LinkSeguro standalone usa React 18/Vite e o mesmo bundle nas entradas
`index.html` e `dicas.html`. A análise local de URL continua sendo o padrão; a
consulta de conteúdo via proxy exige consentimento. O catálogo aponta para
`dist/index.html`, com assets relativos compatíveis com `file://`.

## Build, instalação e CI

- a CI instala, testa, valida e compila cockpit, GhostDesk, GHOST Local,
  GhostMap e News Verifier; em GhostTrace executa typecheck e build;
- a CI sobe uma API mínima autenticada e executa o smoke Playwright das rotas,
  RUN, Auto, presets e páginas auxiliares;
- o Docker usa um estágio de build para o bundle raiz e o News Verifier antes
  da imagem de runtime; a imagem final usa `HOST=0.0.0.0` para que a porta
  publicada seja alcançável, mantendo auth obrigatória;
- `install.sh` e `scripts/setup-ghostrecon-vps.sh` compilam as interfaces;
- o inventário versionado impede perda silenciosa de IDs, módulos, endpoints,
  storage, handlers e recursos externos.

## Verificação recomendada

```bash
npm run ui:inventory
npm run ui:typecheck
npm run ui:build
npm run test:ui
npm run ui:smoke

npm --prefix GhostDesk/frontend test
npm --prefix GhostDesk/frontend run build

npm --prefix GhostTrace run type-check
npm --prefix GhostTrace run build

npm --prefix ghost-local-v5/ghost-local/frontend test
npm --prefix ghost-local-v5/ghost-local/frontend run build

npm --prefix ghostmap/frontend test
npm --prefix ghostmap/frontend run typecheck
npm --prefix ghostmap/frontend run build

npm --prefix server/modules/external-tools/standalone/news-verifier test
npm --prefix server/modules/external-tools/standalone/news-verifier run build
```

O smoke raiz deve ser executado com a API em `127.0.0.1:3847` e auth local
disponível. As dívidas de dependência do Next devem ser tratadas separadamente:
eliminá-las exige upgrades major e não deve ser confundido com a migração de
framework descrita aqui.

Gate final desta consolidação: 52/52 testes do bundle raiz, smoke 8/8, 4/4
GhostDesk, 4/4 GHOST Local, 2/2 GhostMap/MITRE, 5/5 News Verifier, 1.237/1.237
no núcleo, 28/28 CLI e 159/159 integrações. Todos os builds passaram,
inclusive imagem Docker e smoke externo do container.
