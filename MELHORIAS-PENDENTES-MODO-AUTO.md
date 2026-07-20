# Melhorias pendentes do Modo Auto

Criado em: 2026-07-20

Este documento é o backlog operacional do Modo Auto. O plano arquitetural e o histórico permanecem em `PLANO-MELHORIAS-AUTO-IA.md`.

## Classificação atual

**Estado:** beta supervisionado — desenvolvimento pausado temporariamente.

O Auto pode ser usado em testes controlados, preferencialmente com módulos passivos. Ainda não deve ser tratado como executor autônomo sem supervisão.

## Prioridade P0 — necessário antes do próximo teste real

- [x] Botão visível para cancelar a sessão Auto atual.
- [x] Cancelar o stream do navegador e chamar o endpoint de cancelamento do servidor.
- [x] Mostrar `sessionId`, fase, módulo, tempo na fase e última atividade no estado/eventos da sessão.
- [x] Marcar snapshots `running` de processos anteriores como `interrupted`.
- [x] Watchdog detectar falta de progresso, não apenas ausência de heartbeat.
- [x] Persistir o estado final em cancelamento e timeout.
- [x] Testar ciclos reais `planner -> pipeline -> evaluate -> completed`.

## Prioridade P1 — confiabilidade

- [ ] Propagar `AbortSignal` a todos os módulos do catálogo Auto.
- [ ] Aplicar deadline duro por módulo e encerrar subprocessos descendentes.
- [ ] Diferenciar heartbeat de progresso real.
- [ ] Registrar causa primária e causa de fallback dos provedores.
- [ ] Impedir retomada de snapshot `completed`, `cancelled` ou incompatível.
- [ ] Validar hash de catálogo e versão de prompt antes da retomada.
- [ ] Criar testes de reinicialização durante planner, pipeline e avaliação.

## Prioridade P2 — operação autônoma

- [ ] Perfis explícitos `passive`, `deep-passive` e `active-authorized`.
- [ ] Confirmação humana separada para escalada ativa.
- [ ] Métricas de taxa de conclusão, timeout, fallback e falso positivo.
- [ ] Teste de credenciais/conectividade de cada provedor selecionado.
- [ ] Cenário canário local antes de alvos autorizados externos.
- [ ] Política de retenção e redação de snapshots e evidências.

## Estado da autonomia 3/4

A interface e o contrato de sessão já aceitam quatro níveis de autonomia. O catálogo condicional e o canal de aprovação humana foram implementados, mas ainda faltam testes completos com módulos intrusivos e confirmação/recusa no navegador. Até essa validação, os níveis 3/4 permanecem experimentais e o Auto deve ser usado preferencialmente com módulos passivos.

O desenvolvimento fica pausado a partir de 2026-07-20 para priorizar a estabilização do pipeline manual e a revisão do escopo antes de adicionar novos executores.

## Critério de aptidão

O Modo Auto passa de beta supervisionado para apto quando:

1. três execuções passivas consecutivas terminarem em `completed`;
2. cancelamento pela UI encerrar a sessão e suas requisições;
3. timeout encerrar módulos e subprocessos sem atividade residual;
4. reinicialização marcar a sessão anterior como interrompida;
5. retomada continuar somente de checkpoint compatível;
6. nenhum provedor não selecionado participar do conselho;
7. o relatório final registrar módulos, evidências, decisões e erros.

## FrameSeven

O FrameSeven está integrado ao RUN comum e ao catálogo Auto, com autenticação opcional, ordem GHOSTRECON → Vigolium → FrameSeven e deduplicação conjunta. Consulte `FRAMESEVEN-INTEGRACAO-FUTURA.md` para melhorias restantes.
