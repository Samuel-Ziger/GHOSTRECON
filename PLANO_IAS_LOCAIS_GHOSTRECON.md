# Plano de Integracao de IAs Locais no GHOSTRECON

## Objetivo

Elevar o nivel tecnico do pipeline adicionando duas IAs locais:

1. **Shannon (white-box)**: analisa codigo-fonte de repositorios encontrados durante o recon.
2. **PentestGPT (validacao pos-recon)**: revisa achados finais para aumentar precisao e reduzir ruido.

Escopo desta etapa: **planejamento tecnico e requisitos** (sem implementar UI/modulos ainda).

---

## Fluxo proposto (alto nivel)

1. O `ghost` executa recon normal.
2. Quando houver sinal em GitHub, o sistema identifica repositorios relevantes.
3. O sistema clona o repo para uma pasta local dedicada `clone/`.
4. O `ghost` chama a IA **Shannon** com:
   - URL alvo;
   - caminho da pasta clonada;
   - metadados de contexto do recon.
5. O `ghost` acompanha logs/status da Shannon ate finalizar.
6. Ao concluir, o `ghost` coleta o relatorio gerado pela Shannon no workspace dela.
7. Findings da Shannon entram no pipeline (dedupe/priorizacao/correlacao).
8. No fim do recon, o `ghost` chama a IA **PentestGPT** para validar os achados finais.
9. O retorno da PentestGPT complementa/ajusta confianca dos findings.
10. O relatorio consolidado e enviado via webhook.

---

## Onde integrar no codigo atual

Arquivos-chave existentes:

- `server/index.js` (orquestracao do pipeline e stream NDJSON)
- `server/modules/github.js` (GitHub atual: busca de leaks, sem clone)
- `server/modules/ai-dual-report.js` (infra atual de IA para relatorios)
- `server/modules/webhook-notify.js` (envio de webhook recon/IA)
- `index.html` (UI de modulos e envio de `modules[]`)

Pontos de extensao recomendados:

### 1) Shannon (durante pipeline)

- Criar modulo novo, ex.: `server/modules/shannon-local.js`.
- Chamar no `runPipeline` apos fase GitHub e antes da fase final de score/correlacao.
- Emitir eventos NDJSON novos (ex.: `pipe=shannon`, `log`, `finding`).

### 2) PentestGPT (pos-recon)

- Criar modulo novo, ex.: `server/modules/pentestgpt-local.js`.
- Executar apos consolidacao de findings (ou em paralelo ao bloco atual de IA de relatorio).
- Reusar payload estruturado gerado por `buildPipelineExportPayloadForAi`.
- Opcional: incluir retorno da PentestGPT no webhook final.

---

## Requisitos tecnicos obrigatorios

## 1) Armazenamento local de clones

- Criar pasta raiz: `clone/`.
- Adicionar `clone/` ao `.gitignore` para nunca subir repositorios clonados ao git.
- Definir politica de limpeza (TTL por horas/dias ou limpeza ao fim da execucao).
- Limitar tamanho/quantidade de repos clonados por alvo.

## 2) Execucao de processos locais

- Garantir `git` disponivel no host.
- Criar executor seguro para comando de clone (sem shell injection).
- Timeouts por etapa:
  - descoberta do repo;
  - clone;
  - execucao Shannon;
  - execucao PentestGPT.
- Controle de concorrencia para evitar travamento do servidor.

## 3) Contrato de integracao (entrada/saida)

### Shannon - entrada minima

- `targetDomain`
- `targetUrl` (quando aplicavel)
- `repoUrl`
- `clonePath`
- `runId`
- `context` (resumo do recon relevante)

### Shannon - saida minima

- `status` (`ok` | `error`)
- `reportPath` (arquivo gerado)
- `findings[]` com:
  - `type`
  - `title`
  - `severity`
  - `evidence`
  - `filePath` / `line` (quando existir)
  - `confidence`

### PentestGPT - entrada minima

- payload final do recon (findings + contexto + score)
- opcional: resumo Shannon ja processado

### PentestGPT - saida minima

- `validatedFindings[]`
- `falsePositives[]`
- `missingChecks[]`
- `precisionNotes`
- `overallConfidence`

## 4) Observabilidade

- Logs estruturados por fase:
  - descoberta GitHub
  - clone
  - Shannon start/progress/done
  - PentestGPT start/progress/done
- Persistir erros com causa e acao sugerida.
- Eventos NDJSON para UI acompanhar progresso em tempo real.

## 5) Seguranca

- Sanitizar paths e argumentos de processos.
- Bloquear repositorios acima de limite de tamanho/arquivos.
- Evitar exfiltracao de segredo no prompt.
- Rodar IAs locais com isolamento minimo (processo/usuario dedicado, quando possivel).
- Respeitar escopo autorizado (nao analisar repos fora de escopo do alvo).

---

## Mudancas futuras na UI (nao implementar agora)

Na area de modulos, adicionar futuramente:

- modulo `shannon_whitebox`
- modulo `pentestgpt_validation`

Tambem prever:

- estado visual no pipeline (`pipe-node`) para cada nova fase;
- exibicao de resumo Shannon/PentestGPT no painel de findings;
- opcao para habilitar/desabilitar envio desses resultados no webhook.

---

## MCP Hexstrike vs PentestGPT

Voce pode adotar tres estrategias:

1. **PentestGPT apenas** (mais simples para primeira entrega).
2. **Hexstrike apenas** (se qualidade/latencia estiver melhor no seu ambiente).
3. **Hibrido**: PentestGPT como validador principal + Hexstrike como second opinion em achados criticos.

Recomendacao inicial: implementar PentestGPT primeiro e deixar Hexstrike como modulo opcional de validacao extra.

---

## Plano de implementacao por fases (sugerido)

### Fase 1 - Base GitHub + Clone

- evoluir `server/modules/github.js` para retornar repos candidatos (nao apenas leaks).
- criar helper de clone em pasta `clone/`.
- adicionar limites de tempo/tamanho.

### Fase 2 - Integracao Shannon

- criar `server/modules/shannon-local.js`.
- definir contrato de entrada/saida.
- injetar findings da Shannon no pipeline.

### Fase 3 - Integracao PentestGPT

- criar `server/modules/pentestgpt-local.js`.
- validar findings finais e anexar observacoes ao resultado final.

### Fase 4 - Persistencia, webhook e UX

- salvar artefatos minimos no run (sem dados excessivos).
- enviar bloco Shannon/PentestGPT no webhook.
- adicionar modulos na UI e fases visuais.

### Fase 5 - Hardening

- testes unitarios e smoke tests.
- retry/backoff para IAs locais.
- limpeza automatica da pasta `clone/`.

---

## Checklist objetivo para comecar implementacao

- [ ] Definir endpoint/forma de execucao da Shannon local.
- [ ] Definir endpoint/forma de execucao do PentestGPT local.
- [ ] Definir formato de `findings` de ambas as IAs (compatibilidade com schema atual).
- [ ] Adicionar `clone/` ao `.gitignore`.
- [ ] Criar feature flags/env vars para ativar/desativar cada IA.
- [ ] Definir limites operacionais em `server/config.js`.
- [ ] Definir politica de limpeza de clones e relatorios temporarios.

---

## Variaveis de ambiente sugeridas

- `GHOSTRECON_GITHUB_CLONE_ENABLED=1`
- `GHOSTRECON_CLONE_DIR=clone`
- `GHOSTRECON_CLONE_MAX_REPOS=3`
- `GHOSTRECON_CLONE_MAX_SIZE_MB=200`
- `GHOSTRECON_CLONE_TIMEOUT_MS=120000`
- `GHOSTRECON_SHANNON_ENABLED=1`
- `GHOSTRECON_SHANNON_BASE_URL=http://127.0.0.1:9001`
- `GHOSTRECON_SHANNON_TIMEOUT_MS=180000`
- `GHOSTRECON_PENTESTGPT_ENABLED=1`
- `GHOSTRECON_PENTESTGPT_BASE_URL=http://127.0.0.1:9002`
- `GHOSTRECON_PENTESTGPT_TIMEOUT_MS=180000`
- `GHOSTRECON_CLONE_CLEANUP_ON_FINISH=1`

---

## Resultado esperado

Com essas duas IAs locais, o GHOSTRECON passa a operar em duas camadas:

- **Camada tecnica de codigo (Shannon)**: evidencia white-box real de repositorios relacionados ao alvo.
- **Camada de validacao final (PentestGPT)**: maior assertividade, menos falso positivo e relatorio final mais confiavel para bug bounty.

