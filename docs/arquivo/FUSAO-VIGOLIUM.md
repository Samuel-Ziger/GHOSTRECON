# Pendências da integração GHOSTRECON + Vigolium

Atualizado em: 2026-07-30

Este documento contém somente o trabalho ainda necessário na integração. O
binário em `engines/vigolium` é artefato gerado; mudanças pertencem à fonte em
`vigolium/` e devem seguir `vigolium/AGENTS.md`, `vigolium/CLAUDE.md` e o
`Makefile` local.

## Estado de liberação

O Vigolium está implementado, mas **não está liberado no Modo Auto** e deve
permanecer desabilitado por política até que os P0 abaixo estejam resolvidos.
Um único item `vigolium_dast` ainda não representa o conjunto real de operações
internas que o engine pode carregar.

Seleção vazia, tag inválida ou filtro ambíguo não pode virar `all`. Estratégia
`deep`, opt-in do engine, autonomia elevada ou seleção de Codex não constituem
consentimento para write probes, uploads, payload persistente ou tentativas de
credencial.

## P0 — expansão interna antes dos gates

- [ ] Adicionar introspecção determinística do registry Vigolium.
- [ ] Resolver estratégia, módulos e tags para IDs exatos; expandir `--only`
      para fases/capabilities concretas e resolver extensões antes do plano
      GHOSTRECON.
- [ ] Incluir cada ID, classe, requisito, timeout e concorrência no catálogo e
      no hash aprovado.
- [ ] Falhar fechado para resolução vazia, inexistente, fuzzy ou `all`
      implícito.
- [ ] Recusar qualquer módulo carregado depois do freeze.
- [ ] Comparar a resolução aprovada com a resolução observada imediatamente
      antes da execução.

## P0 — separar capacidades de risco

- [ ] Classificar individualmente operações passivas, ativas, intrusivas, de
      credencial, escrita e destrutivas.
- [ ] Separar uploads e stored payloads de probes de leitura.
- [ ] Separar verbos HTTP mutáveis.
- [ ] Separar tentativas de login/default credentials.
- [ ] Manter todas essas capacidades fora do Auto atual.
- [ ] Exigir laboratório, capability própria, aprovação própria, marcador
      não destrutivo e cleanup verificável antes de considerar qualquer write.
- [ ] Criar teste de paridade entre registry interno, catálogo GHOSTRECON,
      OPSEC, RBAC e engagement.

## P0 — contenção formal de escopo

- [ ] Definir transporte selado da `scopePolicy` para o processo Vigolium.
- [ ] Representar domínios, wildcards, IPs, CIDRs e exclusões.
- [ ] Aplicar a política a redirects, crawler, endpoints descobertos e DNS→IP.
- [ ] Não tratar `--scope-origin strict` como substituto da allowlist formal.
- [ ] Bloquear o engine se a versão instalada não conseguir impor a política.
- [ ] Impedir external harvest quando não estiver explicitamente autorizado e
      representado no plano.

## P0 — cancelamento, timeout e outcomes

- [ ] Repropagar abort, timeout, identity mismatch e processo não encerrado até
      o terminal da sessão.
- [ ] Impedir que as fases Go emitam `done` quando o resultado contém
      `ok:false`.
- [ ] Aplicar outcome real a cada módulo interno.
- [ ] Aguardar `exit/close`, TERM→KILL e cleanup antes de continuar para
      FrameSeven ou outra iteração.
- [ ] Aplicar deadline individual aos modos scan, audit, swarm e autopilot.
- [ ] Garantir que o agente Codex do Vigolium também respeite o sinal e o
      orçamento da sessão.

## P0 — autenticação e artefatos

- [ ] Provar em E2E que auth nunca entra em argv, log, NDJSON, RAG, SQLite ou
      relatório.
- [ ] Validar consumo único e origem do bundle autenticado.
- [ ] Aguardar remoção de arquivo/diretório temporário antes do terminal.
- [ ] Impedir persistência de JSONL/SQLite/HTML bruto em contexto autenticado.
- [ ] Particionar relatórios e artefatos por principal e engagement.
- [ ] Aplicar TTL e contenção de caminho em todas as rotas.

## P1 — relatório e proveniência

- [ ] Incorporar findings Vigolium ao `runId` consolidado da sessão Auto.
- [ ] Preservar módulo interno, estratégia, engine, versão e evidência na
      proveniência.
- [ ] Distinguir claramente executado, recomendado, skipped, partial, failed,
      timeout e cancelled.
- [ ] Deduplicar sem apagar fontes ou evidências distintas.
- [ ] Exibir no cockpit o conjunto interno aprovado e o resultado real.

## P1 — executabilidade e supply chain

- [ ] Fazer readiness validar binário, identidade, versão, dependências e
      capabilities necessárias.
- [ ] Bloquear versão incompatível com introspecção/escopo.
- [ ] Manter hash/tamanho/metadados selados até cada spawn.
- [ ] Definir política de rebuild e atualização do artefato gerado.
- [ ] Executar builds apenas via `Makefile` local ou `npm run engine:build`.
- [ ] Registrar limitações de dependências que exigem rede, Bun, Docker ou
      laboratórios vulneráveis.

## P2 — paridade operacional

- [ ] Fechar paridade de plano, auth, cancelamento, relatório e proveniência
      entre RUN e Auto.
- [ ] Definir limites de concorrência por sessão e principal.
- [ ] Expor status/stop confiável para qualquer serviço Vigolium iniciado pela
      stack.
- [ ] Documentar quais modos do agente são suportados em cada superfície.

## Testes ainda necessários

- [ ] Sem filtro: bloquear em vez de executar `all`.
- [ ] Tag inexistente: bloquear.
- [ ] Filtro fuzzy: expandir e mostrar todos os IDs.
- [ ] Extensão inesperada: recusar antes do spawn.
- [ ] Write/credential module: zero execução sob opt-in genérico.
- [ ] Redirect/subdomínio/IP fora do escopo: zero request.
- [ ] Cancelamento e timeout em scan/audit/swarm/autopilot.
- [ ] Processo que ignora TERM: KILL, settle e terminal fatal.
- [ ] Auth em sucesso, recusa, erro, timeout e cancelamento.
- [ ] Identidade do binário alterada depois do popup.
- [ ] Relatório consolidado com proveniência de cada módulo interno.
- [ ] Zero processo, arquivo ou segredo residual.

## Licença e distribuição

O Vigolium é AGPL. Antes de copiar, modificar, distribuir, oferecer como
serviço ou incorporar código:

- [ ] revisar as obrigações aplicáveis ao modelo de distribuição;
- [ ] preservar LICENSE, notices e atribuições;
- [ ] documentar a oferta do source correspondente quando exigida;
- [ ] revisar dependências e assets incorporados;
- [ ] não editar ou redistribuir o binário gerado como se fosse source.

## Critério de liberação

- [ ] Todo módulo interno aparece no plano aprovado.
- [ ] Nenhuma capacidade de escrita/credencial entra por opt-in genérico.
- [ ] A mesma allowlist é aplicada dentro do engine.
- [ ] Cancelamento, timeout e falha fatal produzem outcomes verdadeiros.
- [ ] Auth e artefatos são redigidos, isolados e removidos.
- [ ] Relatório unificado preserva proveniência.
- [ ] Regressão hermética e E2E controlado passam sem resíduos.
