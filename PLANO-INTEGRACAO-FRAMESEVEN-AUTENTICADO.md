# Pendências da integração FrameSeven autenticada

Atualizado em: 2026-07-30

Este documento contém somente o trabalho ainda necessário. O comportamento
vigente continua subordinado a:

- `server/integrations/frameseven-policy.mjs`;
- `server/integrations/frameseven-adapter.mjs`;
- `server/integrations/frameseven-auth-context.mjs`;
- `server/integrations/frameseven-runner.mjs`;
- `FrameSeven/AGENTS.md`.

## Estado de liberação

O fluxo autenticado não está liberado para operação real. Captura de sessão,
popup ou identidade selada do binário não provam contenção de escopo, limpeza
completa ou terminal correto.

`offensive_v1` continua intrusivo mesmo sem `-active-scan`. O perfil não
autoriza write probes e não pode ser executado sem plano efetivo, papel
`red/admin`, engagement/ROE, escopo e confirmação específicos.

## P0 — política de escopo dentro do engine

- [ ] Adicionar `scopePolicy` selada ao contrato do adapter/runner.
- [ ] Transportar domínios, wildcards, IPs, CIDRs e exclusões.
- [ ] Revalidar cada redirect, subdomínio, URL de crawler e IP/porta descoberta
      antes da operação.
- [ ] Impedir que a ferramenta amplie o alvo a partir de conteúdo,
      autenticação ou resposta do servidor.
- [ ] Bloquear a execução se a versão do CLI não suportar a política.
- [ ] Revalidar o binding do engagement imediatamente antes do primeiro probe.

## P0 — autenticação single-use e limpeza

- [ ] Provar que o contexto só pode ser consumido uma vez em execução real.
- [ ] Validar origem, alvo e TTL no momento do consumo.
- [ ] Persistir a aprovação pendente antes de aguardar o operador.
- [ ] Fechar navegador em recusa, cancelamento, timeout, desconexão e erro.
- [ ] Aguardar remoção do arquivo `0600` e diretório `0700`.
- [ ] Aguardar encerramento da árvore do CLI antes do evento terminal.
- [ ] Falhar fechado se cleanup ou settle não puder ser comprovado.

## P0 — cancelamento, timeout e terminal

- [ ] Repropagar abort e falha fatal até o terminal da sessão Auto.
- [ ] Impedir que erro recuperável da integração faça a UI abandonar o stream.
- [ ] Distinguir scan `done`, `partial`, `failed`, `timeout` e `cancelled`.
- [ ] Impedir `completed` depois de cancelamento durante captura, aprovação,
      `before_scan`, scan ou merge.
- [ ] Incluir deadlines de captura, aprovação, preparação, scan e settle no
      plano/hash compatível.
- [ ] Confirmar `exit/close` depois de TERM→KILL.

## P0 — proteção de dados autenticados

- [ ] Inspecionar NDJSON, logs, argv, RAG, snapshots, SQLite e relatórios em
      E2E real.
- [ ] Bloquear envio a provider externo sem consentimento específico.
- [ ] Particionar artefatos por principal e engagement.
- [ ] Aplicar TTL aos metadados e relatórios autenticados.
- [ ] Impedir exposição de artefato bruto, symlink ou arquivo trocado.
- [ ] Redigir headers, cookies, query strings, paths locais e dados pessoais.

## P1 — relatório e proveniência

- [ ] Criar um `runId` Auto consolidado.
- [ ] Incorporar findings FrameSeven ao mesmo run que GHOSTRECON/Vigolium.
- [ ] Agregar todas as iterações, não apenas eventos da iteração corrente.
- [ ] Preservar engine, ferramenta, perfil, auth/private flag e evidência.
- [ ] Representar relatório incompleto como `partial`.
- [ ] Tornar falha de merge/persistência visível no terminal.

## P1 — OPSEC e operação

- [ ] Transportar Tor/proxy estrito ao CLI ou bloquear o engine quando a
      política exigir esse transporte.
- [ ] Limitar concorrência e processos por principal/sessão.
- [ ] Exibir no popup a política de escopo realmente transportada.
- [ ] Exibir claramente quais dados autenticados serão compartilhados com cada
      motor.
- [ ] Listar sessão retomável e estado de cleanup na UI.

## Testes ainda necessários

- [ ] Fake CLI tenta redirect para origem externa.
- [ ] Fake CLI tenta subdomínio excluído e IP fora do CIDR.
- [ ] Captura sem aprovação: nenhum outro motor ou scan.
- [ ] Recusa: navegador/contexto removidos.
- [ ] Aprovação: consumo único.
- [ ] Cancelamento em captura, aprovação, `before_scan`, scan e merge.
- [ ] Timeout em cada etapa.
- [ ] Processo ignora TERM e recebe KILL; terminal somente após settle.
- [ ] Desconexão HTTP fecha browser e processo.
- [ ] Restart com aprovação pendente não retoma efeitos.
- [ ] Mudança de engagement ou binário invalida o plano.
- [ ] Relatório parcial preserva evidência/proveniência.
- [ ] Nenhum segredo em todos os sinks.
- [ ] Zero browser, processo e temporário residual.

## Critério de liberação

- [ ] Scope formal imposto dentro do FrameSeven.
- [ ] Aprovação e contexto autenticado são duráveis, owner-bound e single-use.
- [ ] Cancelamento/timeout impedem qualquer continuação.
- [ ] Cleanup termina antes do estado terminal.
- [ ] Relatório Auto consolidado representa resultado real.
- [ ] Redação e isolamento autenticados passam no E2E.
- [ ] Tor/proxy é aplicado ou a seleção falha fechado.
- [ ] Regressão hermética e canários controlados repetidos passam.
