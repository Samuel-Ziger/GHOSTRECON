# Status de finalização do Modo Auto

Atualizado em: 2026-07-30

## Finalidade

Este documento registra **somente o que ainda falta** para considerar o Modo
Auto concluído. Histórico de entregas, itens marcados como concluídos e
contagens antigas de testes foram removidos.

Código, schemas e testes continuam sendo a fonte de verdade. O contrato
operacional está em `MODO-AUTO-GHOSTRECON.md` e o backlog executável em
`MELHORIAS-PENDENTES-MODO-AUTO.md`.

## Veredito atual

O Modo Auto permanece **beta supervisionado**. Nenhuma autonomia deve ser
tratada como finalizada:

| Caminho | Estado de liberação |
| --- | --- |
| Testes com fixtures | sem aprovação de release até a regressão hermética ficar verde |
| `observation` | somente piloto passivo, em alvo próprio/laboratório e com operador acompanhando |
| `assisted` | somente laboratório controlado; não liberar operacionalmente |
| `authorized` | implementado experimentalmente; não liberado e deve permanecer desabilitado por política |
| `authorized_opsec` | implementado experimentalmente; não liberado e deve permanecer desabilitado por política |
| Vigolium no Auto | não liberado; deve permanecer desabilitado até expansão interna, gates e contenção de escopo |
| FrameSeven ofensivo/autenticado | não liberado; deve permanecer desabilitado até contenção de escopo, cleanup e E2E |
| Provider externo com evidência autenticada | não liberado; deve permanecer desabilitado até consentimento, isolamento, redação e custo verificáveis |
| Writes, credential attempts e `-active-scan` | fora do Auto atual |

O evento `completed` atual não comprova execução integral, persistência
consolidada nem limpeza de todos os recursos.

## P0 — bloqueadores de segurança e correção

### 1. Expandir integralmente o Vigolium antes dos gates

- [ ] Resolver os IDs internos reais selecionados por `vigolium_dast`, `-m`,
      tags e filtros; expandir `--only` para as fases/capabilities concretas
      antes de RBAC, engagement, OPSEC e aprovação.
- [ ] Impedir que seleção vazia, tag inexistente ou filtro ambíguo seja
      convertido em `all`.
- [ ] Incluir no plano/hash cada módulo interno, classe de risco, timeout,
      concorrência e requisito operacional.
- [ ] Separar leitura, ação ativa, intrusiva, tentativa de credencial, escrita
      e destrutiva.
- [ ] Manter uploads, stored XSS, verbos mutáveis e tentativas de login
      desligados por padrão e fora de um consentimento genérico do engine.
- [ ] Instrumentar o wrapper para provar que nenhum módulo não aprovado foi
      carregado, inclusive extensões.

### 2. Aplicar a mesma política de escopo a toda operação de rede

- [ ] Propagar a `scopePolicy` congelada para FrameSeven e Vigolium.
- [ ] Representar no transporte allowlist de domínios, wildcards, IPs, CIDRs,
      exclusões e binding do engagement.
- [ ] Revalidar antes de cada request redirects, subdomínios, DNS→IP, crawler,
      `jwks_uri`, endpoints descobertos e origem autenticada.
- [ ] Corrigir módulos internos que usam `redirect: follow` sem validar a URL
      resultante.
- [ ] Falhar fechado quando um engine não conseguir impor a política aprovada.

### 3. Tornar cancelamento, timeout e falha fatal incontornáveis

- [ ] Repropagar `AbortError`, timeout, desconexão e falhas fatais no conselho,
      providers, dispatcher, pipeline e adapters.
- [ ] Impedir qualquer fallback, nova iteração, engine, avaliação ou
      persistência de sucesso depois de cancelamento.
- [ ] Remover o caminho em que o dispatcher captura erro e ainda emite `done`.
- [ ] Verificar `session.assertActive()` depois de cada fronteira assíncrona e
      imediatamente antes de checkpoint ou terminal.
- [ ] Aplicar deadline independente a cada turno de provider e impedir que
      atividade de outro turno masque um provider travado.

### 4. Emitir outcomes e terminais verdadeiros

- [ ] Derivar `done`, `skipped`, `failed`, `timeout` e `cancelled` da execução
      real de cada módulo, sem inferência ampla por fase.
- [ ] Tornar `completed`, `partial`, `failed`, `cancelled`, `timed_out`,
      `stalled` e `budget_exceeded` estados terminais distintos.
- [ ] Nunca converter `evaluation.status=partial` em `completed`.
- [ ] Fazer a UI continuar consumindo o stream após `error` recuperável.
- [ ] Remover “AUTO COMPLETO” quando o terminal não estiver confirmado como
      integral.

### 5. Preservar orçamento e comprovar cleanup

- [ ] Persistir um `deadlineAt` absoluto e usar somente o tempo restante após
      restart/resume.
- [ ] Vincular à política de retomada limites de sessão, chamadas, custo,
      iterações, providers e engines.
- [ ] Impedir que a retomada substitua limites históricos por limites novos.
- [ ] Persistir aprovação pendente antes da espera e sua resolução antes de
      continuar.
- [ ] Aguardar browser, App Server, process groups, workers e temporários
      encerrarem antes do snapshot/evento terminal.
- [ ] Tornar falhas de checkpoint, snapshot, RAG e terminal observáveis e
      fail-closed quando a trilha durável for obrigatória.

### 6. Fechar isolamento de dados e comportamento degradado

- [ ] Particionar RAG, snapshots e artefatos derivados por principal,
      engagement e alvo.
- [ ] Aplicar TTL e impedir busca/leitura cruzada entre operadores ou
      engagements.
- [ ] Exigir consentimento explícito antes de enviar alvo ou evidência a
      provider externo.
- [ ] Tornar redação, política de dados e contabilização de custo verificáveis
      para todos os providers.
- [ ] Quando nenhum provider selecionado estiver utilizável, falhar ou entrar
      em estado `degraded` explícito sujeito à decisão do operador.
- [ ] Proibir fallback determinístico silencioso apresentado como decisão das
      IAs selecionadas.

### 7. Renovar a evidência de teste

- [ ] Corrigir `pipelineState is not defined` em
      `server/tests/auto-agent.test.js`.
- [ ] Corrigir o teste de binding de principal entre processos para funcionar
      de forma hermética no Node 22.
- [ ] Criar um comando/target hermético oficial e usá-lo na CI.
- [ ] Separar `pipeline-smoke.test.js` em job de rede opt-in e autorizado.
- [ ] Manter CLI, MCP e smoke de import no gate local.
- [ ] Executar E2E controlado cobrindo todas as autonomias, aprovação, recusa,
      cancelamento em cada estágio, timeout, restart/resume, redirect fora do
      escopo, autenticação, redação e ausência de resíduos.

## P1 — necessário para operação real

- [ ] Exigir engagement/ROE formal para qualquer plano ativo operacional, não
      apenas para módulos classificados como intrusivos.
- [ ] Aplicar timeout, cancelamento, outcome e progresso por módulo.
- [ ] Criar um `runId` Auto único e relatório consolidado de todas as
      iterações, engines, aprovações, outcomes, findings e proveniência.
- [ ] Fazer o catálogo refletir executabilidade real, dependências, binários,
      credenciais necessárias e motivo de indisponibilidade.
- [ ] Exigir binding persistente do principal quando autenticação e retomada
      owner-bound forem habilitadas.
- [ ] Tornar reconciliação de startup aguardada, auditável e configurável pelo
      mesmo ambiente injetado.
- [ ] Adicionar limites de concorrência por principal, sessão e engine.
- [ ] Definir retenção/TTL comum para RAG, snapshots, relatórios, SQLite e
      evidência autenticada.
- [ ] Validar o runtime Forge real em Bubblewrap, permissões do store, escrita
      atômica, timeout e ausência de processo residual.

> O runtime Forge atual já usa Bubblewrap. “Isolar o runtime final do Forge”
> não é pendência vigente; falta provar e endurecer seu comportamento real.

## P2 — paridade e produto

- [ ] Unificar a classificação de risco entre manifests, catálogo, OPSEC, RBAC
      e engagement, com teste exaustivo de paridade.
- [ ] Implementar Tor/proxy estrito para FrameSeven ou bloquear explicitamente
      o engine quando esse perfil for exigido.
- [ ] Listar snapshots retomáveis na API/UI e exibir motivo de bloqueio,
      degradação ou incompatibilidade.
- [ ] Adicionar comando Auto à CLI ou documentar formalmente sua ausência.
- [ ] Definir o fluxo de aprovação do Auto no MCP; hoje a execução interativa
      não possui paridade com o cockpit.
- [ ] Implementar `stop/status` confiáveis para sidecars iniciados pela stack.
- [ ] Remover configurações mortas/enganosas ou implementá-las com testes.
- [ ] Atualizar schemas e documentação depois da estabilização.

## Definition of Done

O Modo Auto só pode ser declarado concluído quando todos os itens abaixo forem
verdadeiros:

- [ ] o plano mostrado e hashado é exatamente o executado, incluindo módulos
      internos, engines, limites, escopo e identidades;
- [ ] RBAC, scope, engagement, OPSEC e aprovação passam antes de qualquer
      preparação ou `spawn`;
- [ ] nenhum redirect, subdomínio, IP, crawler ou origem autenticada sai da
      allowlist;
- [ ] cancelamento, timeout e falha fatal impedem qualquer continuação e geram
      o terminal correto;
- [ ] o terminal só é publicado após cleanup e assentamento comprovados;
- [ ] retomada preserva deadline/orçamentos e recusa drift, replay e snapshot
      incompatível;
- [ ] relatório consolidado representa resultado integral, parcial, falhas e
      proveniência real;
- [ ] RAG, snapshots, SQLite, NDJSON e relatórios não vazam segredos nem dados
      entre principals/engagements;
- [ ] providers externos possuem consentimento, redação, política de dados e
      custo verificáveis;
- [ ] regressão hermética, CLI, MCP e smoke de import passam no estado final;
- [ ] E2E controlado repetido deixa zero browser, processo ou temporário
      residual;
- [ ] README, contrato operacional, status e backlog descrevem o código final
      sem garantias aspiracionais.

## Ordem recomendada

1. bloquear temporariamente os caminhos P0 no produto;
2. corrigir expansão interna do Vigolium e contenção de escopo;
3. corrigir propagação de falhas e verdade terminal;
4. corrigir retomada, orçamento e cleanup;
5. isolar dados e comportamento de providers;
6. consolidar relatório, progresso e executabilidade;
7. passar a regressão hermética;
8. executar os E2E controlados;
9. revisar a liberação de cada autonomia separadamente.
