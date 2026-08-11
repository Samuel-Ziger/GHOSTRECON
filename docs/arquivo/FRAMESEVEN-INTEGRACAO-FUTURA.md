# Pendências futuras da integração FrameSeven

Atualizado em: 2026-07-30

O histórico da integração foi removido. O trabalho aberto detalhado está em
`PLANO-INTEGRACAO-FRAMESEVEN-AUTENTICADO.md`.

## Estado de liberação

FrameSeven ofensivo e autenticado estão implementados experimentalmente, mas
não estão liberados no Modo Auto e devem permanecer desabilitados por política.
O perfil `recon_v1` só deve ser usado como piloto controlado depois das
correções P0 de terminal, cancelamento e contenção de escopo.

## Trabalho restante

- [ ] Propagar e impor a `scopePolicy` formal no processo FrameSeven.
- [ ] Bloquear redirects, crawler, subdomínios, IPs e portas fora da allowlist.
- [ ] Transportar Tor/proxy estrito ou bloquear o engine nesse perfil.
- [ ] Garantir que cancelamento não seja convertido em `completed` e que timeout
      do engine seja registrado como `engine_timeout`; a sessão agregada só pode
      ser `partial` se preservar explicitamente esse timeout.
- [ ] Aguardar navegador, árvore de processos e temporários encerrarem antes do
      terminal.
- [ ] Consolidar findings e proveniência num único `runId` Auto.
- [ ] Validar autenticação single-use e ausência de segredo em todos os sinks.
- [ ] Executar E2E controlado de captura, aprovação, recusa, timeout,
      cancelamento, restart e cleanup.
- [ ] Demonstrar zero browser, processo ou temporário residual.

## Critério para retomar a liberação

- [ ] Scope formal aplicado dentro do engine.
- [ ] Terminais e outcomes correspondem à execução real.
- [ ] Cleanup comprovado antes da conclusão.
- [ ] Relatório consolidado e redigido.
- [ ] Regressão hermética e E2E autenticado verdes.
