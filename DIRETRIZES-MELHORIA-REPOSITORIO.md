# Diretrizes de melhoria do repositório GHOSTRECON

**Estado de referência:** 2026-08-12
**Escopo:** arquitetura, segurança operacional, qualidade, manutenção e
priorização do produto.

Este documento transforma a análise técnica do repositório em um roteiro de
execução. Ele não substitui contratos, código, schemas, testes nem o
`AGENTS.md`. Em caso de divergência, essas fontes continuam prevalecendo.

## 1. Resumo executivo

O GHOSTRECON é uma plataforma local-first de recon autorizado, OSINT,
validação defensiva, organização de evidências e gestão de findings. O núcleo
Node/Express, o pipeline NDJSON, CLI, MCP e SQLite formam a base mais madura.
Vigolium, FrameSeven, Auto Mode, Forge e os demais serviços ampliam a cobertura,
mas também elevam a complexidade de integração, autorização e cleanup.

### Pontos fortes

- visão de produto coerente, do alvo ao relatório;
- operação local-first e passiva por padrão;
- controles cumulativos de autenticação, RBAC, CSRF, scope, engagement e OPSEC;
- pipeline progressivamente extraído do monólito e organizado por fases;
- ampla suíte de regressão para segurança, cancelamento e subprocessos;
- documentação transparente sobre limitações experimentais do Auto Mode.

### Risco estrutural principal

O projeto já possui mais componentes do que uma única matriz de integração
consegue estabilizar com facilidade. A prioridade deve ser provar invariantes e
manter gates herméticos antes de expandir funcionalidades.

## 2. Estado atual após o saneamento P0

O ciclo P0 iniciado a partir desta análise cobre:

1. correção dos testes de RAG para o layout particionado por tenant;
2. preservação controlada de hashes de evidência fora do contexto cloud;
3. teste hermético da política Bubblewrap sem exigir o binário do host;
4. sincronização da expectativa do registry com `cve_correlation`;
5. catálogo Vigolium testado contra fonte Go sintética local;
6. DNS injetável nos testes de infraestrutura de domínio, sem rede real;
7. documentação do gate sem registrar falhas temporárias como contrato;
8. descrição do pacote alinhada ao produto atual.

O comportamento de produção do Forge continua fail-closed sem Bubblewrap. A
injeção usada no teste não relaxa essa política. Da mesma forma, os testes do
Vigolium validam somente parsing e filtros: não executam o motor.

## 3. Princípios de evolução

1. **Plano efetivo antes dos gates:** tudo que possa executar deve estar
   expandido, classificado, aprovado e congelado antes do primeiro side effect.
2. **Hermeticidade por padrão:** testes padrão não acessam DNS, HTTP, browsers,
   scanners ou serviços externos.
3. **Fail-closed verificável:** indisponibilidade, timeout ou cleanup não
   confirmado nunca podem ser convertidos em sucesso.
4. **Uma fonte operacional por contrato:** documentação descreve o estado
   comprovado por código e testes, não intenções futuras.
5. **Integrações opcionais:** ausência de engine não deve degradar a segurança
   nem impedir o núcleo passivo de informar readiness tipada.
6. **Sem segredos em fronteiras públicas:** NDJSON, logs, relatórios, RAG, DB e
   argv recebem somente representações redigidas e mínimas.

## 4. Priorização

### P0 — gate e segurança operacional

- manter `npm test` verde e hermético;
- impedir regressões de permissões `0700`/`0600` e escrita atômica no RAG;
- preservar fingerprints apenas em campos semânticos validados;
- manter Forge fail-closed sem sandbox forte;
- manter fixtures sintéticas para catálogos sem depender de fontes externas;
- bloquear execução Auto intrusiva enquanto a expansão nativa do Vigolium não
  estiver integralmente representada antes dos gates;
- atualizar imediatamente documentação que descreva um gate antigo.

### P1 — estabilização arquitetural

**Estado:** em andamento. O primeiro incremento implementou a matriz tipada de
suporte/readiness em `/api/capabilities` e separou os gates herméticos `core`,
`auto` e `integrations`. A consolidação dos catálogos por hash e da fonte única
de risco permanece pendente.

- evoluir a matriz de suporte com níveis `stable`, `beta`, `experimental` e
  `external`, separados da readiness `available`, `degraded`, `unavailable` ou
  `unknown`;
- separar gates de CI em `core`, `auto`, `integrations`, `environment` e
  `network`;
- tornar catálogos Node, Vigolium, FrameSeven e Forge determinísticos e
  versionados por hash;
- gerar automaticamente matriz de módulos, risco, requisitos e readiness;
- substituir listas históricas rígidas por testes de invariantes, mantendo
  testes explícitos para módulos obrigatórios;
- definir compatibilidade de versões entre API, CLI, MCP e engines.

### P2 — produto e manutenção

- publicar uma arquitetura de referência do núcleo mínimo;
- separar claramente código-fonte, vendor, runtime, dados e build outputs;
- medir cobertura e duração por subsistema;
- reduzir o cockpit monolítico por extrações cirúrgicas, preservando contratos
  DOM e NDJSON;
- documentar licenças e obrigações de distribuição de cada integração;
- manter health/readiness distinto de “instalado”, “configurado” e “executável”.

## 5. Camadas oficiais de suporte propostas

### Núcleo suportado

- API Node/Express;
- pipeline e streaming NDJSON;
- SQLite local;
- cockpit principal;
- CLI e MCP;
- recon passivo e módulos nativos conservadores.

### Integrações suportadas sob readiness

- Vigolium;
- FrameSeven;
- GhostTrace e GhostMap;
- HexStrike como inteligência, sem equivaler recomendação a execução.

### Experimental ou laboratório

- Auto `authorized` e `authorized_opsec`;
- Forge e canários dinâmicos;
- browser autenticado e compartilhamento de sessão;
- Wi-Fi, Kali e validações intrusivas;
- qualquer write probe, mesmo não destrutivo.

## 6. Estratégia de testes

### Gate padrão

Deve usar apenas fixtures, executores injetados, diretórios temporários e
endereços locais controlados. Nenhum teste deve depender de resolução DNS real
ou da presença de Bubblewrap, Go engines, navegadores ou sidecars.

### Gate de ambiente

Valida binários e políticas reais, por exemplo Bubblewrap e engines locais. A
ausência de requisito deve resultar em diagnóstico/skip explícito no job, nunca
em relaxamento do runtime.

### Gate de rede/laboratório

Deve ser opt-in, possuir alvo autorizado e limites conhecidos. Resultados desse
gate não podem ser confundidos com testes unitários nem executados por padrão.

### Regressões obrigatórias em mudanças de segurança/Auto

- caminho positivo e negação;
- timeout cooperativo e processo não cooperativo;
- cancelamento e desconexão;
- restart e resume;
- contenção de scope e redirects;
- redação de segredos;
- cleanup sem resíduos;
- identidade/hash do artefato antes e depois da aprovação.

## 7. Indicadores de conclusão

Uma etapa só pode ser marcada como concluída quando:

- os testes direcionados e o gate aplicável passam;
- o plano executado é idêntico ao plano autorizado;
- timeout e cancelamento encerram a árvore de recursos;
- não há rede em testes declarados herméticos;
- findings mantêm proveniência sem material autenticado;
- documentação, schemas e clientes afetados foram sincronizados;
- limitações restantes estão descritas como pendências, não como salvaguardas.

## 8. Próximo ciclo recomendado

1. medir e publicar duração dos grupos de testes já separados;
2. consolidar a fonte de classificação de risco dos módulos;
3. versionar os catálogos executáveis por hash verificável;
4. concluir expansão efetiva do Vigolium antes de RBAC/engagement/OPSEC;
5. executar E2E apenas em laboratório controlado para browser, DAST e cleanup;
6. somente depois reavaliar a liberação operacional dos níveis Auto 3 e 4.
