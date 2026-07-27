# Melhorias pendentes do Modo Auto

Criado em: 2026-07-20

Atualizado em: 2026-07-26

Este é o backlog operacional do Auto. O contrato atual está em
`MODO-AUTO-GHOSTRECON.md`; a investigação e a sequência histórica estão em
`PLANO-MELHORIAS-AUTO-IA.md`. A fotografia verificável do que já foi entregue
e do que ainda bloqueia a finalização está em
`STATUS-FINALIZACAO-MODO-AUTO.md`.

## Classificação atual

**Estado:** beta supervisionado em desenvolvimento ativo.

Os caminhos `observation` e `assisted` possuem os controles locais necessários
para testes com fixtures e alvos controlados. `authorized` e
`authorized_opsec` continuam experimentais até a validação ponta a ponta com
engagement real autorizado e navegador autenticado controlado, além da paridade
residual entre RUN e Auto.

Nenhum nível do Auto delega capacidades destrutivas.

## Concluído nesta evolução

### Plano e catálogo

- [x] Ampliar o catálogo além da antiga lista passiva fixa.
- [x] Combinar manifests, capacidades legadas, módulos Forge e engines.
- [x] Vincular o `catalogHash` e o plano efetivo à integridade dos módulos Forge
      e à identidade observável dos binários FrameSeven/Vigolium.
- [x] Revalidar a identidade selada de FrameSeven/Vigolium imediatamente antes
      de cada `spawn`, recusando troca posterior à aprovação.
- [x] Classificar `passive`, `deep_passive`, `active`, `intrusive`,
      `hexstrike_intel` e excluir `destructive`.
- [x] Remover do Auto capacidades de credenciais, ocultação de identidade e
      expansão perigosa de escopo.
- [x] Tornar HexStrike, Vigolium e FrameSeven opt-ins no catálogo Auto.
- [x] Expandir módulos, dependências, Kali e engines antes dos gates.
- [x] Congelar o plano efetivo e identificá-lo por hash.
- [x] Impedir que o perfil `deep` injete fases não selecionadas após aprovação.
- [x] Executar somente os módulos e flags presentes no plano congelado.
- [x] Usar a classe de maior risco e combinar requisitos quando manifest e
      capacidade legada divergem.
- [x] Exigir capacidades explícitas no Auto para HTTP/WAF, verify, descoberta
      ativa de parâmetros, assets/takeover, recheck HIGH, browser XSS e
      ferramentas/follow-ups Kali.
- [x] Impedir que fontes passivas de URL habilitem fetch de bundles do alvo sem
      uma capacidade target-touching aprovada.

### Autonomia, RBAC e aprovação

- [x] Formalizar `observation`, `assisted`, `authorized` e
      `authorized_opsec`.
- [x] Exigir aprovação humana do plano nos níveis 2, 3 e 4.
- [x] Exigir `recon.intrusive` na rota para níveis 3/4.
- [x] Aplicar preflight de engagement/ROE e gate OPSEC ao plano expandido.
- [x] Exigir no RUN manual, para qualquer módulo intrusivo do plano expandido,
      `recon.intrusive`, engagement formal ativo/assinado/no escopo/na janela e
      `confirmActive`.
- [x] Tratar o perfil ofensivo explícito do FrameSeven como intrusivo, sem
      depender de `tools all`, e manter engagement/ROE/confirmação cumulativos.
- [x] Manter o FrameSeven como único motor com perfil ofensivo no Auto; o
      Vigolium não recebe essa autorização por toggle, autonomia ou provider.
- [x] Congelar o perfil ofensivo FrameSeven em
      `recon,access,redirect,misconfig,cve,crawler,content,subdomain,ports,nmap,bannergrab`,
      sem `-active-scan` nem write probes.
- [x] Tornar recon, active e authenticated mutuamente exclusivos e impedir que
      `finish`/`abstain` injetem o engine.
- [x] Impedir que `GHOSTRECON_CONFIRM_ACTIVE=1` substitua a confirmação da
      requisição HTTP.
- [x] Mostrar alvo, risco, módulos, engines, limites e hash na aprovação.
- [x] Fazer qualquer recusa encerrar sem pipeline, módulo ou engine.
- [x] Impedir continuação automática de “restante seguro” após uma recusa.
- [x] Manter classe destrutiva fora da autonomia 4.

### Contrato e providers

- [x] Exigir `objective`, `reasoningSummary`, `requestedModules` e
      `confidence` válida.
- [x] Normalizar `request_modules` e `execute_modules` para `run_modules`.
- [x] Aplicar invariantes por ação e requisitos completos de `forgeRequest`.
- [x] Limitar o reparo de JSON.
- [x] Preservar a causa do App Server e do fallback.
- [x] Fechar stdin do `codex exec`.
- [x] Encerrar App Server/CLI por grupo de processo com
      `SIGTERM` → `SIGKILL`.
- [x] Impedir que provider não selecionado participe do conselho.
- [x] Resolver conflito sem elevar privilégio no fallback.

### Sessão e ciclo de vida

- [x] Isolar listagem, cancelamento, aprovação e retomada pelo proprietário.
- [x] Rejeitar `sessionId` ativo duplicado.
- [x] Tornar aprovação single-flight e abort-aware.
- [x] Persistir snapshots atomicamente com permissão restrita.
- [x] Reconciliar snapshot `running` órfão como interrompido.
- [x] Bloquear retomada de estado terminal incompatível.
- [x] Validar alvo, autonomia, proprietário, `catalogHash` e `promptVersion`.
- [x] Criar checkpoint v2 semântico com `resumePolicyHash`, plano pronto,
      módulos e cadeia de hashes.
- [x] Restringir retomada às fronteiras `ready_for_iteration` e
      `ready_for_next_iteration`.
- [x] Manter checkpoint v1 legível, mas não retomável.
- [x] Consumir cada checkpoint pronto com claim atômico `wx`, durável e
      resistente a replay/rollback entre processos.
- [x] Recusar retomada no meio de pipeline, engine ou avaliação para não repetir
      efeitos.
- [x] Expor fase, atividade atual e heartbeat sem confundi-lo com progresso.
- [x] Preservar estados `cancelled`, `interrupted`, `timed_out`, `stalled` e
      `budget_exceeded`.

### Pipeline e processos

- [x] Criar deadline por fase no caminho Auto.
- [x] Propagar `AbortSignal` ao contexto de processos gerenciados.
- [x] Emitir `phase_outcome` e `module_outcome`.
- [x] Registrar timeout/falha recuperável e seguir somente depois do settle.
- [x] Interromper a run quando a fase não encerra dentro do período de graça.
- [x] Nunca recuperar cancelamento explícito do operador.
- [x] Manter o recon manual fail-fast por padrão.
- [x] Marcar resultado com falhas recuperáveis como `partial`.
- [x] Tornar pausa/probe e subprocessos cobertos abort-aware, sem usar heartbeat
      como progresso.
- [x] Criar `AbortController` no RUN manual e propagar desconexão/cancelamento
      ao pipeline, Vigolium e FrameSeven.

### RAG, Forge e engines

- [x] Centralizar redação recursiva antes do RAG/observações.
- [x] Redigir recursivamente todos os eventos produzidos pelo orquestrador Auto
      antes da sessão e do NDJSON, removendo segredos e caminhos locais
      absolutos de artefatos.
- [x] Limitar tamanho de arquivos, objetos, listas e previews.
- [x] Gravar RAG atomicamente com permissões restritas.
- [x] Deduplicar e resumir o observation bundle.
- [x] Executar módulo Forge no runner forte Bubblewrap em Linux, sem rede do
      host, com ambiente limpo, filesystem somente leitura e `/tmp` efêmero.
- [x] Marcar Forge como indisponível e falhar fechado quando o sandbox forte não
      existe.
- [x] Limitar tempo, memória e saída do runtime Forge.
- [x] Selar artefatos Forge com hash e falhar fechado em adulteração.
- [x] Fazer CAS de alvo, artefato e binding/version/hash do engagement sob lock
      exclusivo de lifecycle.
- [x] Revalidar o engagement dentro da transição, imediatamente antes e depois
      do canário.
- [x] Restringir o primeiro canário ao runner do único módulo dinâmico aprovado,
      com timeout/cancelamento e zero pipeline legado, DNS, finalize ou engines
      implícitas.
- [x] Exigir atestação forte por operação/challenge no sandbox e
      acknowledgement **mais** settle real após timeout/cancelamento.
- [x] Manter aprovação Forge em `active_pending_first_run` e
      `pipelineEnabled=false` até o canário exclusivo.
- [x] Vincular o resultado do primeiro canário ao `activationId` e aos hashes
      aprovados, rejeitando resultado repetido, atrasado ou adulterado.
- [x] Mascarar findings de segredo antes de eventos/persistência e manter o
      material cru somente em memória não enumerável.
- [x] Tornar `secret_validation` intrusivo e dependente de seleção explícita.
- [x] Manter captura de token opt-in, redigida e com permissões `0700`/`0600`.
- [x] Manter writes/signup Supabase e Firebase desligados no pipeline, sem
      elevação por env, token ou `service_role`.
- [x] Separar o FTP `STOR` dos follow-ups de leitura e mantê-lo desligado por
      padrão.
- [x] Tornar AuthContext FrameSeven origin-bound, TTL e single-use.
- [x] Encerrar árvore do FrameSeven com `SIGTERM` → `SIGKILL`.
- [x] Separar deadlines FrameSeven de captura auth, aprovação, `before_scan` e
      scan, aguardando o assentamento limitado antes de continuar.
- [x] Transportar auth do Vigolium por arquivo temporário restrito, sem segredo
      em argv/log, com cleanup idempotente.
- [x] Preservar a ordem GHOSTRECON → Vigolium → FrameSeven no Auto.
- [x] Emitir resultado separado por engine e preservar proveniência.
- [x] Validar, normalizar e mesclar o `report.json` FrameSeven com deduplicação
      que agrega fontes/evidências.
- [x] Emitir um único terminal FrameSeven somente após o merge; reportar como
      `partial` scan útil, relatório incompleto ou falha recuperável de merge.
- [x] Gerar os relatórios expostos apenas de findings normalizados/redigidos e
      permitir somente HTML/JSON/Markdown, sem PDF ou artefato bruto.
- [x] Servir relatórios FrameSeven por rota `recon.read`, validando owner e
      engagement, com `O_NOFOLLOW`, leitura pelo FD, `fstat`, limite de tamanho
      e CSP sandbox sem scripts.

## Pendências abertas

### P0 — validação E2E autenticada controlada

- [ ] Executar, em laboratório autorizado, o fluxo completo de navegador no RUN
      e no Auto: captura, aprovação e recusa, compartilhamento single-use,
      cancelamento, limpeza de temporários e ausência de segredos em
      NDJSON/snapshot/RAG/relatório.
- [ ] Repetir o canário autenticado controlado com Vigolium e FrameSeven,
      confirmando outcomes e proveniência sem processo/browser residual.

### P1 — catálogo, deadlines, transporte e paridade

- [ ] Migrar módulos legados agrupados em fases para deadlines individuais.
- [ ] Unificar classificação de risco em manifest, catálogo, OPSEC, RBAC e
      engagement, com teste automático de paridade.
- [ ] Fazer progresso por módulo substituir marcadores amplos como `urls`,
      `assets` ou nome da fase.
- [ ] Integrar FrameSeven ao perfil Tor/proxy estrito; o adapter atual usa
      allowlist de ambiente que não propaga essa política.
- [ ] Fechar a paridade residual RUN/Auto no plano efetivo, autenticação,
      proveniência e relatório unificado. O normalizador/merge do
      `report.json` já é compartilhado; o E2E ainda não.

## Migração necessária

Pacotes Forge ativos criados antes do selo `runtimeIntegrity` falham fechado no
loader atual. Eles precisam ser:

1. revisados;
2. testados novamente;
3. aprovados novamente;
4. selados pela versão atual do lifecycle.

Não complete hashes manualmente e não desative o gate para preservar um pacote
antigo.

## Matriz mínima de teste

| Cenário | Resultado esperado |
| --- | --- |
| `observation` pede módulo ativo | decisão rejeitada ou filtrada, sem execução |
| `assisted` aprovada | executa exatamente o hash exibido |
| `assisted` recusada | termina sem executar módulos |
| nível 3/4 sem `recon.intrusive` | HTTP 403 antes da sessão |
| nível 3/4 com engagement inválido | preflight bloqueia |
| plano intrusivo recusado | termina sem pipeline, módulo ou engine |
| RUN manual com qualquer módulo intrusivo sem engagement/ROE/confirm | bloqueado antes de preparar/spawnar engine |
| RUN manual com perfil ofensivo FrameSeven explícito | segue a mesma regra intrusiva mesmo sem auth-browser |
| FrameSeven recebe `tools all` ou `-active-scan` | plano/adapter recusa antes do spawn |
| cliente fecha o stream manual | `AbortSignal` chega ao pipeline e engines |
| fase recuperável falha e assenta | próxima fase roda; status final `partial` |
| fase não assenta | `PIPELINE_PHASE_UNSETTLED`; nenhuma próxima engine |
| cancelamento do operador | status `cancelled`; nenhuma recuperação |
| outro principal lista/cancela/aprova | sessão oculta ou HTTP 403 |
| checkpoint v1 solicitado para retomada | leitura permitida; retomada recusada |
| checkpoint v2 `ready` já claimed | replay recusado de forma durável |
| checkpoint `running`/avaliação | retomada recusada; nenhuma repetição de engine |
| Forge sem Linux/Bubblewrap | módulo indisponível e canário bloqueado |
| alvo/artefato/engagement Forge muda sob lock | aprovação/canário falha fechado |
| canário Forge aprovado | somente módulo dinâmico; zero DNS/legado/finalize |
| sandbox atesta outra operação/challenge | resultado recusado |
| sandbox confirma kill sem assentar | `AUTO_FORGE_SANDBOX_UNTERMINATED` |
| resultado Forge com `activationId` obsoleto | rejeitado sem reabilitar pacote |
| Forge adulterado | loader falha com erro de integridade |
| Forge legado sem hash | loader falha fechado e exige reaprovação |
| FrameSeven sem opt-in | não aparece nem executa |
| FrameSeven auth sem toggle | requisição rejeitada |
| identidade FrameSeven/Vigolium muda após o plano | spawn recusado |
| timeout em captura/aprovação/before-scan/scan | TERM→KILL, settle e cleanup |
| FrameSeven com erro/truncamento no relatório | um único `engine_partial` após merge |
| relatório FrameSeven PDF/raw, symlink ou trocado durante leitura | rota responde 404 |
| relatório FrameSeven de outro owner/engagement inválido | rota responde 403 |
| relatório HTML FrameSeven | CSP sandbox sem scripts |
| Vigolium/HexStrike sem opt-in | não aparecem no catálogo da sessão |
| evento Auto com segredo/path local aninhado | segredo redigido e path omitido |
| Auto sem `http_probe`/`wafw00f` | nenhum probe/WAF implícito por perfil |
| write env/token presente | Supabase/Firebase continuam sem operação mutável |
| `secret_validation` ausente | nenhum probe online de segredo |
| FTP follow-up de leitura | não executa `STOR` sem gate dedicado |

## Checks locais

```bash
node --test \
  server/tests/auto-agent.test.js \
  server/tests/auto-planner-contract.test.js \
  server/tests/auto-effective-plan.test.js \
  server/tests/auto-session-security.test.js \
  server/tests/auto-resume-checkpoint.test.js \
  server/tests/auto-event-redaction.test.js \
  server/tests/auto-route-public-data.test.js \
  server/tests/auto-rag-runtime-security.test.js \
  server/tests/auto-strict-phase-gates.test.js \
  server/tests/auto-content-network-gates.test.js \
  server/tests/pipeline-resilience.test.js \
  server/tests/process-cancellation.test.js \
  server/tests/probe-cancellation.test.js \
  server/tests/kali-execution-policy.test.js \
  server/tests/secret-safety.test.js \
  server/tests/write-probes-safety.test.js \
  server/tests/forge-security.test.js \
  server/tests/recon-stream-route.test.js \
  server/tests/frameseven-integration.test.js \
  server/tests/vigolium-bridge.test.js \
  server/tests/vigolium-agent.test.js
```

Os checks acima usam mocks e fixtures. Nesta entrega não foi executado scan real
de rede, navegador autenticado, DAST, Kali, Nmap ou sqlmap.

## Critério de aptidão

O nível 2 pode sair de beta quando os testes locais e três canários controlados
consecutivos terminarem com o hash executado igual ao aprovado, sem processo
órfão nem segredo persistido.

Os níveis 3/4 só podem ser promovidos depois de:

1. o E2E autenticado P0 passar repetidamente em laboratório;
2. RBAC, engagement, aprovação e recusa serem exercitados pela UI/endpoint
   reais, sem ampliar escopo;
3. cancelamento encerrar cada engine/browser e limpar contexto/temporários;
4. a paridade residual RUN/Auto estar documentada e verificada;
5. uma revisão confirmar que nenhuma classe destrutiva chega ao catálogo.
