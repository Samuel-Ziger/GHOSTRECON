# Pendências de IA do Modo Auto

Atualizado em: 2026-07-30

O plano histórico foi absorvido pelo código e pelos documentos operacionais.
Este arquivo contém somente lacunas ainda abertas na participação das IAs.

O backlog geral está em `MELHORIAS-PENDENTES-MODO-AUTO.md` e o estado de
liberação em `STATUS-FINALIZACAO-MODO-AUTO.md`.

## P0 — decisão, cancelamento e degradação

- [ ] Repropagar cancelamento, timeout e desconexão em proposal, review,
      arbitragem e conselho pós-pipeline.
- [ ] Impedir que um turno cancelado seja convertido em `ok:false`, fallback
      determinístico, `finish` ou terminal `completed`.
- [ ] Aplicar deadline independente por chamada de provider, com settle
      confirmado antes de continuar.
- [ ] Impedir que atividade de outro provider atualize o watchdog de um turno
      travado.
- [ ] Passar o `AbortSignal` da sessão à detecção de providers.
- [ ] Limpar `currentStage` ao final de cada turno.
- [ ] Verificar a sessão antes de persistir decisão, abrir aprovação, iniciar
      engine ou emitir terminal.

## P0 — provider selecionado indisponível

- [ ] Se nenhum provider selecionado estiver utilizável, falhar antes do
      pipeline ou apresentar estado `degraded` explícito.
- [ ] Exigir confirmação do operador antes de usar baseline determinístico
      quando ele substitui uma decisão de IA.
- [ ] Identificar no NDJSON e no relatório quem decidiu: provider/modelo,
      arbitragem, operador ou fallback.
- [ ] Remover ou corrigir configurações que anunciam provider “permitido” sem
      torná-lo utilizável pelo conselho.
- [ ] Mostrar na UI instalação, configuração, autenticação, alcance,
      usabilidade e causa da indisponibilidade.

## P0 — dados enviados a providers

- [ ] Definir política explícita para alvo, findings, URLs, logs, RAG e
      evidência autenticada.
- [ ] Exigir consentimento específico antes de enviar dados privados a cloud.
- [ ] Implementar a configuração de redação anunciada ou removê-la.
- [ ] Registrar provider, modelo, política, consentimento e categorias de dados
      enviadas, sem persistir o conteúdo sensível.
- [ ] Bloquear provider cloud para evidência autenticada enquanto a política
      não for verificável.
- [ ] Garantir que prompt, resposta, erro, usage e handoff passem pela mesma
      redação central.

## P0 — custo e limites

- [ ] Obter métricas de tokens/custo para cada provider suportado.
- [ ] Quando a métrica não existir, declarar `cost_unverified` em vez de
      afirmar que `maxCostUsd` é limite rígido.
- [ ] Persistir o orçamento original e o saldo restante.
- [ ] Impedir que restart/resume renove chamadas, custo ou iterações.
- [ ] Encerrar chamadas que excederem deadline ou orçamento e impedir fallback
      posterior.

## P0 — RAG e isolamento

- [ ] Particionar decisões, avaliações, lessons, Forge e handoffs por
      principal, engagement e alvo.
- [ ] Aplicar filtros equivalentes nas APIs de busca/status.
- [ ] Definir TTL e política de retenção.
- [ ] Impedir que memória de outro operador ou engagement entre no prompt.
- [ ] Tornar falha de persistência observável quando a trilha de decisão for
      obrigatória.
- [ ] Testar redação de objetos aninhados, URLs, headers, erros e respostas dos
      providers.

## P1 — catálogo apresentado às IAs

- [ ] Expor executabilidade real, dependências, binários e motivo de
      indisponibilidade.
- [ ] Substituir `vigolium_dast` por IDs internos concretos já classificados e
      aprováveis.
- [ ] Não apresentar engine que não consiga aplicar a `scopePolicy` da sessão.
- [ ] Unificar classificação de risco e requisitos entre catálogo, manifest,
      OPSEC, RBAC e engagement.
- [ ] Incluir limites reais por módulo no contexto do planner.
- [ ] Impedir que catálogo ou RAG anunciem uma capability não executável.

## P1 — conselho e explicabilidade

- [ ] Registrar conflito, veto de política, módulos rejeitados e motivo do
      veredito final.
- [ ] Diferenciar `ask_operator` por conflito de decisão de
      `ask_operator` por indisponibilidade operacional.
- [ ] Impedir que uma decisão `finish` esconda falhas de provider ou execução
      parcial.
- [ ] Expor confiança por provider sem tratar maioria como autorização.
- [ ] Limitar tamanho e concorrência do conselho por sessão/principal.

## P2 — superfícies do produto

- [ ] Exibir na UI o estado real de cada turno, custo e motivo de degradação.
- [ ] Exibir `partial` e failures na conclusão da sessão.
- [ ] Adicionar fluxo de Auto à CLI ou documentar formalmente sua ausência.
- [ ] Definir como o MCP obtém aprovação interativa; `approvalMode: deny` não
      oferece paridade com o cockpit.
- [ ] Permitir listar e selecionar sessões retomáveis sem digitar ID bruto.

## Testes ainda necessários

- [ ] Cancelar durante proposal, review e conselho pós-pipeline.
- [ ] Provider ignorando abort deve ser encerrado antes do terminal.
- [ ] Dois providers concorrentes: um progride e outro trava.
- [ ] Todos os providers indisponíveis: zero pipeline sem decisão explícita.
- [ ] Fallback degradado aprovado e recusado.
- [ ] Resume próximo do deadline/custo máximo.
- [ ] Evidência autenticada com provider cloud bloqueado sem consentimento.
- [ ] Isolamento RAG entre dois principals e dois engagements.
- [ ] Falha de gravação de decisão/RAG.
- [ ] Usage ausente deve produzir `cost_unverified`.
- [ ] Prompt injection em finding, HTML, URL, RAG e proposta de outro agente.

## Critério de encerramento deste plano

- [ ] Toda decisão possui origem e estado operacional inequívocos.
- [ ] Nenhum cancelamento/timeout pode virar fallback ou sucesso.
- [ ] Provider externo recebe somente dados consentidos e redigidos.
- [ ] Limites de tempo, chamadas e custo sobrevivem à retomada.
- [ ] RAG não cruza principal, engagement ou retenção.
- [ ] Catálogo entregue à IA corresponde a capabilities executáveis e já
      gateadas.
- [ ] Regressões herméticas e E2E controlados passam sem segredo ou processo
      residual.
