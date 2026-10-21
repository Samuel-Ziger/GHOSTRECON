# Análise dos módulos do modo manual

## Veredito

O modo manual, como conjunto, está em **Falta muito para ficar excelente**.

- Estrutura: **Bom**
- Qualidade de implementação: **Falta muito**
- Precisão dos achados: **Falta muito**
- Confiabilidade operacional: **Falta muito**
- Módulos **Top**: 4 (`api_contract_diff`, `robots_sitemap`,
  `cookie_session_audit`, `security_headers`)
- Módulos **Excelentes**: 0

Foram analisadas as 90 opções manuais expostas pela interface, além do toggle
FrameSeven. A base tem componentes fortes, mas severidades inconsistentes,
módulos inertes, gates incompletos, heurísticas apresentadas como vulnerabilidade
e cancelamentos que nem sempre encerram o trabalho.

Escala das notas: `E/Q/P/C` = estrutura, qualidade, precisão e confiabilidade,
de 0 a 10. “Excelente” exige 10 nas quatro dimensões, testes E2E,
timeout/cancelamento real, escopo integral e precisão medida contra ground truth.
“Top” representa 9/9/9/9 no código e nos testes herméticos: ainda não atesta
comportamento de navegador, rede, proxy ou provider real.

As notas são estimativas de engenharia baseadas no código e nos testes citados.
Para os demais módulos elas ainda não são medições estatísticas de
precisão/recall. `api_contract_diff` também foi medido no corpus sintético,
controlado e versionado descrito abaixo; esse resultado não cobre documentos
modulares com referências externas nem representa todas as APIs reais. Reduzir
risco ou limitar um módulo não comprova que ele executa sua proposta completa.

## Estado do lote Falta muito — 2026-09-06

| Faixa | Quantidade atual | Situação |
|---|---:|---|
| Horrível | 0 | Os 6 módulos originalmente nessa faixa foram corrigidos. |
| Ruim | 0 | Os 27 IDs/opções originalmente nessa faixa foram corrigidos. |
| Falta muito | 4 | Dos 12 desse lote, 7 passaram a Bom e 1 a Ótimo. Os outros 4 receberam correções, mas mantêm lacunas importantes. |

As contagens de Horrível/Ruim preservam a revisão de 2026-09-01; esta rodada
reavaliou especificamente os 12 anteriormente em Falta muito. Nenhum foi
promovido a Excelente, e a faixa **ainda não está encerrada**.

| Módulo deste lote | Nível atual | Correção verificada localmente | Pendência principal |
|---|---|---|---|
| `wafw00f` | Bom | Executor/sinal injetáveis, capability em cache, parser e estados distintos de falha/timeout/negativo/inconclusivo. | Corpus de versões reais e E2E do processo; formato não reconhecido não prova ausência de WAF. |
| `dom_clobbering_audit` | Bom | Padrões isolados são inventário; correlação exige referência ao script no documento e continua candidato estático. | AST/data-flow, controle real do elemento e benchmark; proximidade lexical não prova exploração. |
| `firebase_audit` | Bom | Somente GET, coleções observadas no cliente, JSON/schema validados, limites e estados tipados. Leitura pública não vira crítico. | Ground truth das regras e intenção do proprietário; impacto continua não verificado. |
| `panel_exposure_audit` | Bom | Baseline por origem contra catch-all/SPA, assinatura de conteúdo, scope/sinal e painel como inventário. | Corpus de soft-404 dinâmico e política de acesso; login público não prova acesso indevido. |
| `info_disclosure_errors` | Bom | Compara assinatura com baseline, entradas malformadas genéricas, corpo limitado e stream fechado mesmo em erro. Wrapper/pipeline distinguem falha, timeout e cancelamento de sucesso. | Corpus negativo mais amplo, orçamento global e E2E do wrapper. |
| `mysql_3306_intel` | Ótimo | Inventário estruturado do Nmap, proveniência e candidato por porta; remove comandos de exploração sugeridos. | Corpus de banners/proxies; não verifica segurança da configuração ou backports. |
| `shannon_whitebox` | Falta muito | Findings normalizados como candidatos IA, saída limitada/redigida e pedido de cancelamento pelo ID real, independente da UI. | Pedido aceito não atesta término das atividades Temporal: `cleanup.confirmed=false`; próximos clones não iniciam quando isso permanece incerto. |
| `webshell_probe` | Bom | GET sem parâmetros, sem `cmd=id`; scope/sinal/corpo limitado. Resposta semelhante a identidade Unix é apenas candidato. | Corpus negativo e baseline; não testa execução de comandos nem confirma webshell. |
| `kali_dirsearch` | Falta muito | Concorrência/profundidade menores, limite de saída, filtros de origem/status e outcomes reais de processo/parse. | Falta baseline própria de soft-404/catch-all e prova de escopo durante redirects/recursão do binário. |
| `kali_ffuf` | Bom | Autocalibração, limites menores, metadados HTTP e 3xx/401/403 como inventário; falha não vira busca vazia concluída. | E2E com versão fixada e calibração contra respostas dinâmicas. |
| `vigolium_swarm` | Falta muito | Fail-closed no bridge antes de autenticação/processo; UI e catálogo indicam indisponibilidade. | Motor nativo ainda pode ampliar tarefas depois da aprovação. Desabilitá-lo não conclui sua implementação. |
| `vigolium_autopilot` | Falta muito | Somente prévia `dry-run`, sem prescan/discovery/verificação posterior nem compartilhamento de auth. Exemplos de stdout não viram findings. | Aprovação por comando e plano nativo auditável, retomada, cancelamento e E2E; não é scan autônomo disponível. |

Todas as verificações desta rodada usaram fixtures e executores simulados.
Nenhum alvo externo, scanner real, workflow Temporal ou engine Go foi executado.

## Promoção de Ótimo para Top — 2026-09-09

Quatro módulos chegaram inicialmente a Top somente com correções estruturais e
testes herméticos, sem depender de scan externo. O marco é histórico, mas a
tabela mostra o estado revalidado atual; o detalhamento de
`api_contract_diff` está na seção seguinte.

| Módulo | Nível | E/Q/P/C | O que foi concluído | O que ainda falta para Excelente |
|---|---:|---:|---|---|
| `api_contract_diff` | Top | 9/9/9/9 | Snapshot schema 2/canonicalização 8 com hash e proveniência, migração explícita de v1, validação contra adulteração, identidade exata da API, diff semântico e outcomes tipados. Limites, deadline, cancelamento e espera de baseline são testados sem rede. | Referências externas continuam detect-only; faltam corpus real amplo e E2E autorizado com providers remotos. |
| `robots_sitemap` | Top | 9/9/9/9 | Parser XML estrito com namespaces, entidades e CDATA; rejeição de DTD/XXE; sitemap index recursivo com gzip, ciclos, limites e escopo em redirects. Proveniência por URL, métricas e estados `done/partial/failed` agora chegam ao pipeline. Timeout local não derruba as demais origens. | Benchmark com corpus real de sitemaps grandes/malformados e E2E autorizado de rede/redirect/CDN. |
| `cookie_session_audit` | Top | 9/9/9/9 | Public Suffix List real injetável ou carregada de caminhos fixos do sistema, com hash de proveniência e algoritmo para regras exatas, wildcard, exceções, domínios privados e IDN. Sem PSL, a decisão sensível falha fechada. Domain, prefixos `__Host-`/`__Secure-`, `Partitioned`, expiração e nomes de sessão são validados com entrada limitada e valores redigidos. | E2E de browser/proxy/TLS e política reproduzível de distribuição/atualização da PSL. |
| `security_headers` | Top | 9/9/9/9 | CSP aplicada e Report-Only são separadas; múltiplas políticas e diretivas duplicadas são preservadas/analisadas, tokens são comparados semanticamente e resultados incompletos ficam `unknown/partial`. Findings são observações de configuração com evidência/proveniência, sem afirmar exploração no navegador. | Testes E2E em navegadores e proxies/CDNs para medir a política efetivamente aplicada e um corpus real de combinações de headers. |

Os quatro módulos permanecem abaixo de Excelente porque 9/9/9/9 não
substitui ground truth, benchmark nem validação E2E autorizada.

## Revalidação de `api_contract_diff` no nível Top — 2026-09-14

`api_contract_diff` permanece **Top (9/9/9/9)**. A revisão fortaleceu a
canonicalização, a coleta concorrente, o deadline e a persistência, mas não
transforma cobertura parcial em Excelente absoluto.

O dispatcher também passou a redigir e limitar `reason`, `error` e logs antes
do NDJSON, com allowlist para o nível de log; regressões cobrem sucesso parcial,
falha, timeout e cancelamento sem expor segredos sintéticos.

| Módulo | Nível | E/Q/P/C | Evidência atual e limite conhecido |
|---|---:|---:|---|
| `api_contract_diff` | Top | 9/9/9/9 | Envelope de snapshot schema 2 com canonicalização 8, hash e proveniência validados; canonicalizações 2–7 são aceitas para leitura, mas nunca comparadas silenciosamente com a 8. Swagger 2 e OpenAPI 3.0–3.2 cobrem paths, webhooks, `QUERY` 3.2, `additionalOperations`, parâmetros/body, respostas, security, servers, callbacks, componentes e XML. JSON/YAML duplicado falha fechado; defaults de Parameter/Header/Request Body são normalizados inclusive em components, e versões persistidas impossíveis ou divergentes falham fechado. Referências internas incorporadas são validadas por contexto e tipo, inclusive JSON Pointer, `operationRef`, Schema booleano, `$id` e anchors; dados runtime de Link e keywords fora do draft não viram refs, e dialeto desconhecido deixa a cobertura parcial. Redirects são manuais e revalidados por escopo. A coleta usa concorrência 2 (1 em stealth), commit determinístico, limites cumulativos de corpo/snapshot/baseline e deadline cooperativo também nos loops escalares; cancelamento do operador é fatal. SQLite foi exercitado por save/close/reopen/dispatcher/diff. Referências externas ainda são apenas detectadas, e PostgreSQL/Supabase foram testados com adapters, não serviços reais. |

O corpus `api-contract-ground-truth-v1.json` possui 18 pares revisáveis: 13
mudanças positivas e 5 equivalências negativas. O resultado observado foi
TP=13, TN=5, FP=0 e FN=0, portanto precisão=100% e recall=100% **somente nesse
corpus controlado**, sem documentos externos modulares. O laboratório HTTP
executou três cenários em
`127.0.0.1`: redirect interno com JSON fragmentado, bloqueio do redirect fora
do escopo antes da segunda request e cancelamento do body/conexão no deadline.
Nenhum alvo externo foi consultado.

Na regressão de 2026-09-14, os arquivos dirigidos de contrato,
persistência, dispatcher, runner e escopo passaram; o laboratório HTTP local
passou 3/3 e o teste versionado passou em 12 execuções simultâneas. A suíte
hermética global ficou em 191/196 arquivos: todos os arquivos de
`api_contract_diff` passaram. As cinco falhas restantes foram em
`auth-principal-restart`, `auto-agent`, `forge-security`, `tor-tunnel` e
`vigolium-server-client`; `process-cancellation` passou nesta rodada, e as
falhas correspondem às limitações de subprocesso/loopback já registradas
neste documento. Na repetição dirigida, `forge-security` passou e os outros
quatro permaneceram indisponíveis neste sandbox.

A primeira execução após um baseline de canonicalização 2–7 grava
deliberadamente um baseline 8 novo. Isso evita comparar representações
semanticamente incompatíveis. Para chegar a Excelente ainda é necessário
fixar e validar no transporte o IP realmente conectado contra o escopo, para
evitar DNS rebinding, e só então resolver o grafo de referências externas com
limites, ciclos e proveniência; ampliar o corpus real; e executar E2E autorizado
contra PostgreSQL/Supabase reais, incluindo TLS, RLS, falha e recuperação.

## Resultado do lote dos 30 módulos Ótimos — 2026-09-09

O hardening de código e a revalidação hermética deste lote foram concluídos.
Os 30 IDs abaixo receberam melhorias de limites, cancelamento, escopo,
proveniência, parsing e/ou classificação conforme a proposta de cada módulo.
Isso não promove automaticamente nenhum deles a **Excelente**: E2E com motores
reais, corpus de ground truth, versões fixadas e medição de precisão continuam
sendo requisitos para 10/10.

| Grupo | IDs incluídos | Estado conservador desta rodada |
|---|---|---|
| Arquivos e OSINT | `gau`, `waybackurls`, `shodan`, `robots_sitemap`, `pastebin`, `github` | Saída e cardinalidade limitadas, escopo reaplicado, provenance/freshness explícitos e estados operacionais separados. URL histórica ou indexada continua corretamente como disponibilidade atual não verificada. |
| Transporte e identidade | `navegation`, `identity_rotation`, `kali_proxychains` | Tor só passa com `IsTor=true` e IPs válidos/distintos; dispatchers são reutilizados/encerrados e Nmap sob proxy recusa UDP/raw/flags compactas incompatíveis. Não houve validação Tor/proxy real. |
| HTTP, contratos e cliente | `api_contract_diff`, `cookie_session_audit`, `cors_audit`, `email_security_deep`, `graphql_probe`, `http3_quic_surface`, `lovable_fingerprint`, `nginx_http3_cve_2026_42530`, `security_headers`, `supabase_audit` | Baseline OpenAPI por URL exata, parsers/limites/deadlines, escopo por request e separação de inventário/candidato. Supabase anônimo aceita apenas `sb_publishable_*` ou JWT legado `role=anon`; credenciais privilegiadas/custom falham antes da rede e o `ref` legado precisa coincidir. Lovable usa o mesmo extrator, limita respostas/tabelas e persiste apenas claims allowlisted e snippets redigidos. Token de usuário explícito continua somente leitura e sem assinatura atestada. |
| Validações limitadas | `curl_probe`, `micro_exploit`, `pentestgpt_validate`, `secret_validation`, `verify_sqli_deep` | Permanecem sem métodos mutáveis, payload executável ou uso de segredo descoberto; agora têm limites, cancelamento, redação e estados inconclusivos testados. |
| Serviços e Kali | `mysql_3306_intel`, `nmap_service_followups`, `kali_nmap`, `kali_wpscan`, `kali_xss_vibes` | Ingestão estruturada e limitada, escopo por host, exit/timeout reais, serviços como inventário e CVEs de versão como candidatas. Nmap TCP/UDP recusa scripts, alvos e saídas injetados; intensidade agressiva é separada, portas do base são limitadas e UDP usa lista validada de até 128 portas. Nenhum binário real foi executado. |
| FTP com escrita | `ftp_write_probe` | Continua separado e exclusivo de laboratório descartável: opt-in, confirmação específica e allowlist. Desde o reply preliminar de `STOR`, estado remoto possível é registrado; timeout/falha tenta `DELE`+`SIZE` quando ainda há prazo. Cleanup incerto gera finding alto, outcome próprio `failed` e bloqueia writes seguintes, inclusive após cancelamento. |
| FTP para bug bounty | `ftp_anonymous_audit` (novo, fora dos 30 originais) | Capacidade intrusiva explícita: inclui `kali_nmap` antes dos gates, usa/revalida o IP observado no XML, confere o peer, diferencia outcomes e testa somente `USER anonymous` com duas variantes públicas antes de `QUIT`. Não trata `ftp-data`/FTPS como controle plaintext, aguarda fechamento/cleanup atestado e não lista nem transfere arquivos; flood pós-login preserva evidência e degrada para parcial. |

Para programas de bug bounty autorizados, `ftp_anonymous_audit` é o caminho FTP
**sem escrita**. Sua dependência `kali_nmap` entra no plano efetivo antes da
autorização; o runtime reaplica escopo por host e separa esse check dos demais
follow-ups. Antes do socket, o runtime exige o IP observado no resultado Nmap,
revalida-o contra a política e confere se o peer do socket é esse endereço.
Login aceito sem listagem é uma observação de baixa severidade, pois pode ser
intencional. O fechamento ou a destruição local precisa ser atestado. Ele
não envia `LIST`, `RETR`, `STOR`, `APPE`, `DELE`, upload,
alteração de permissão ou criação de diretório. O `ftp_write_probe` permanece
uma capacidade distinta e exclusiva de laboratório.
Nem `ftp_anonymous_audit` nem `ftp_write_probe` habilitam os checks SMB/RPC de
`nmap_service_followups`; cada seleção conserva apenas suas dependências reais.

Evidências defensivas verificadas no código deste lote incluem saída limitada e
outcomes explícitos para coletores de arquivo; dados Shodan marcados como
históricos/candidatos não verificados; correspondência de snapshot OpenAPI pela
URL exata; parsing de cookies mais estrito com clock injetável; auditoria
Supabase geral somente leitura com chave pública validada antes da rede; e
redução de inferências de impacto em achados heurísticos. A bateria dirigida
final passou em 42 de 42 arquivos; as limitações
de validação externa permanecem descritas abaixo.

Portanto, não existe atualmente uma lista de módulos **Ruins** para
apresentar como pendência. A relação abaixo registra os 27 que eram Ruins e
o nível alcançado depois das correções:

| IDs/opções anteriormente Ruins | Nível atual |
|---|---:|
| `directory`, `documents`, `config`, `database`, `logs`, `backup`, `login`, `sqlerrors`, `phperrors`, `phpinfo`, `passwords`, `sensitive` | Bom |
| `stealth_requests` | Bom |
| `client_auth_audit`, `client_surface_audit` | Bom |
| `github` | Ótimo |
| `navegation`, `kali_proxychains` | Ótimo |
| `cors_audit`, `graphql_probe`, `lovable_fingerprint`, `supabase_audit`, `nginx_http3_cve_2026_42530` | Ótimo |
| `secret_validation`, `pentestgpt_validate`, `nmap_service_followups`, `micro_exploit` | Ótimo |

Isso totaliza 15 opções em **Bom** e 12 em **Ótimo**. A mudança de faixa
não significa Excelência: cada linha da análise ainda informa o que falta
para chegar ao nível máximo.

Os seis módulos originalmente classificados como Horrível foram reescritos ou
limitados. Nenhum deles permanece nessa faixa. As notas abaixo avaliam o código
e os testes herméticos atuais; o nível Excelente continua reservado para 10/10
nas quatro dimensões, incluindo benchmark e E2E real em ambiente autorizado.

- `pastebin`: consulta passiva real via Google CSE, allowlist de provedores,
  correspondência exata do alvo e snippets não persistidos.
- `identity_rotation`: ID legado preservado, mas a execução agora mantém proxy,
  User-Agent e idioma estáveis; 403/captcha não causam retry ou troca de identidade.
- `curl_probe`: somente GET/HEAD/OPTIONS, sem SQLi ou escrita, redirect manual,
  corpo limitado, temporários restritos e evidência redigida.
- `ftp_write_probe`: exclusivo de laboratório, com três gates cumulativos,
  allowlist exata, estado remoto possível desde o reply preliminar de `STOR` e
  cleanup atestado apenas por `DELE` seguido de ausência via `SIZE`.
- `verify_sqli_deep`: checkbox funcional, baselines repetidas, diferencial
  limitado, sem UNION/delay/login bypass e sem classificar heurística como confirmada.
- `kali_xss_vibes`: scanner Python legado removido do caminho executável;
  substituído por reflexão contextual repetida com marcador não executável.

Os 27 IDs/opções originalmente classificados como Ruim também foram
corrigidos. Nenhum permanece nessa faixa. Os novos níveis abaixo refletem
testes herméticos e controles implementados, mas não equivalem a Excelente:
faltam corpus de ground truth e E2E autorizado para atingir 10/10.

## Descoberta, OSINT e controles

| Módulo | Nível | E/Q/P/C | Para chegar a Excelente |
|---|---:|---:|---|
| `amass`, `subfinder` | Bom | 7/6/8/6 | Propagar `AbortSignal`, injetar executor, testes negativos/timeout e registrar versão da ferramenta. |
| `subdomains` | Bom | 7/7/7/7 | Corrigir validação por sufixo de domínio, detectar wildcard DNS e medir falsos positivos. |
| `wayback`, `common_crawl` | Bom | 7/7/7/7 | Deduplicação semântica, freshness, provenance e testes de redirects/volumes extremos. |
| `gau`, `waybackurls` | Ótimo | 8/8/8/8 | Fixar versão do binário, cobertura de indisponibilidade e benchmark de completude. |
| `rdap` | Bom | 6/6/8/6 | `fetch` injetável, parent signal, limite de resposta e redirect restrito. |
| `dns_enrichment` | Bom | 6/6/8/6 | Cancelar a consulta DNS real no timeout e injetar resolver/clock. |
| `virustotal` | Bom | 6/6/7/6 | Signal, rate budget, mock completo e diferenciação entre dado histórico e ativo atual. |
| `shodan` | Ótimo | 8/8/8/8 | CVEs agora são candidatas com `observedAt`/`retrievedAt` e respostas têm schema/limite; falta benchmark de freshness e precisão com fixtures versionadas do provider. |
| `wafw00f` | Bom | 8/8/7/7 | Cache, parser e outcomes implementados; falta corpus de formatos/versões e E2E de timeout/cancelamento do binário. |
| `robots_sitemap` | Top | 9/9/9/9 | XML estrito, recursão/gzip/ciclos, limites, scope em redirects, outcomes e provenance ponta a ponta implementados; falta corpus real amplo, benchmark e E2E autorizado. |
| `wellknown_openid`, `wellknown_security_txt` | Bom | 7/6/7/6 | Limitar corpo, parent signal e validação semântica dos documentos. |
| `directory`, `documents`, `config`, `database`, `logs`, `backup`, `login`, `sqlerrors`, `phperrors`, `phpinfo`, `passwords`, `sensitive` | Bom | 8/8/7/7 | CSE e validação real foram implementados; falta segundo provider, paginação e benchmark de recall. |
| `google_cse` | Bom | 6/6/6/6 | Signal, quota/budget, deduplicação, cobertura de paginação e validação posterior dos resultados. |
| `pastebin` | Ótimo | 9/9/8/8 | Adicionar segundo provider, paginação/freshness e medir precisão/recall em corpus real autorizado. |
| `github` | Ótimo | 9/8/8/8 | Conteúdo é validado antes de secret finding, clone é opt-in/0700/TTL e TruffleHog local roda sem verificação remota; falta E2E com CLI real. |
| `out_of_scope` | Bom | 8/8/9/6 | Fazer engines, redirects, crawlers, IPs e subdomínios obedecerem à mesma política selada. |
| `stealth_requests` | Bom | 8/8/8/7 | Política estável, sem rotação/retry e fetch central foram implementados; faltam migrar todos os clientes legados e provar E2E. |
| `navegation` | Ótimo | 9/9/8/8 | Só valida com `IsTor=true`, IPs válidos/distintos e bootstrap concluído; comparação de IP deixou de ser chamada de teste DNS. Falta E2E Tor/DNS controlado. |
| `identity_rotation` | Ótimo | 9/9/9/8 | Conexão estável não lê o body antecipadamente, reutiliza dispatchers HTTP e os encerra no fim do request. Falta migrar o ID legado e comprovar E2E HTTP/SOCKS/Tor. |
| `kali_proxychains` | Ótimo | 9/9/9/8 | Nmap sob proxy aceita apenas TCP connect; caminhos absolutos e flags raw compactas também falham antes da rede. Falta E2E de rota. |

## Auditorias HTTP, cliente e contratos

| Módulo | Nível | E/Q/P/C | Para chegar a Excelente |
|---|---:|---:|---|
| `api_contract_diff` | Top | 9/9/9/9 | Snapshot schema 2/canonicalização 8, migração v1, integridade/proveniência, identidade exata, diff semântico, refs internas tipadas, limites e outcomes implementados; falta resolver grafo de referências externas com escopo/limites/ciclos/proveniência, ampliar o corpus real e executar E2E autorizado com PostgreSQL/Supabase reais. |
| `client_auth_audit` | Bom | 8/8/7/8 | Strings/rotas/storage agora são candidato ou inventário, sem payload de bypass; falta data-flow interprocedural. |
| `client_surface_audit` | Bom | 8/8/7/8 | Correlação local source-to-sink, limites e escopo em source maps implementados; falta taint analysis completa. |
| `cookie_session_audit` | Top | 9/9/9/9 | PSL real com regras exact/wildcard/exception/private/IDN, hash e fail-closed, além de Domain/prefixos/Partitioned/clock/redaction; falta E2E browser/proxy/TLS e ciclo reproduzível de atualização da PSL. |
| `cors_audit` | Ótimo | 9/9/8/8 | Duas origins não relacionadas, escopo por request e severidade contextual; falta validação browser autenticada E2E. |
| `csrf_flow_audit` | Bom | 7/7/5/7 | Analisar cookies, SameSite, headers/framework e provar requisição cross-site viável. |
| `cve_correlation` | Bom | 8/7/5/6 | Backports/distro, versões não semver, freshness, CPE preciso e severidade canônica. |
| `dom_clobbering_audit` | Bom | 8/7/6/7 | Vínculo documental e candidato lexical implementados; falta AST, fluxo de dados e controle real do elemento. |
| `email_security_deep` | Ótimo | 8/8/8/8 | DNS real recebe cancelamento/deadline e erro deixa de significar registro ausente; faltam descoberta de seletores DKIM e corpus internacional de políticas. |
| `firebase_audit` | Bom | 8/8/7/8 | Coleções observadas, read-only, estados inconclusivos e evidência mínima implementados; falta corpus de regras/impacto e E2E autorizado. |
| `graphql_probe` | Ótimo | 9/9/9/8 | Confirma `__typename` antes da introspecção, limita corpo/escopo e trata introspecção como inventário; falta E2E. |
| `header_intel` | Bom | 7/7/6/7 | Reduzir recomendações genéricas e contextualizar banners, CDN e reverse proxy. |
| `hpp_param_pollution` | Bom | 7/7/6/7 | Corrigir parâmetros duplicados e validar comportamento servidor-side diferencial. |
| `http3_quic_surface` | Ótimo | 8/8/9/8 | Confirmação QUIC real e cobertura de proxies/CDNs. |
| `jwt_jwks_audit` | Bom | 8/7/6/7 | Melhorar contexto do IdP, tamanho RSA preciso e reduzir heurísticas de `kid`. |
| `lovable_fingerprint` | Ótimo | 9/8/8/8 | Seleção Supabase compartilhada/fail-closed fecha o bypass de `service_role`; respostas/tabelas e PoC local são limitados/redigidos. Anon/publishable é inventário; falta benchmark/E2E. |
| `nginx_http3_cve_2026_42530` | Ótimo | 9/9/8/8 | Sempre emite candidato com build/backport não verificados; falta confirmação de pacote/vendor para chegar a Excelente. |
| `openapi_specs` | Bom | 7/6/6/6 | Body limit durante streaming, signal, fetch injetável e separar exposição intencional de vazamento. |
| `panel_exposure_audit` | Bom | 8/8/7/7 | Baseline e inventário sem falso impacto implementados; falta corpus dinâmico, prazo integral e política de autorização contextual. |
| `risk_explainer` | Bom | 7/7/5/7 | Mais regras testadas, provenance e explicação sem alterar classificação original. |
| `secrets_context_ranker` | Bom | 7/7/6/7 | Validação contextual, entropia por formato, testes corpus e calibração de score. |
| `security_headers` | Top | 9/9/9/9 | Policies CSP múltiplas, duplicates e enforce/report-only são separadas; gaps têm estado parcial/evidência/provenance e não alegam exploit. Falta E2E em navegadores/proxies e corpus real. |
| `service_worker_audit` | Bom | 8/7/5/7 | Diferenciar padrões normais de risco e correlacionar caches com conteúdo realmente sensível. |
| `supabase_audit` | Ótimo | 9/9/8/8 | Schema REST dinâmico, RLS somente com linhas, inventário separado e writes recusados. Requests anônimos aceitam apenas `sb_publishable_*` ou JWT legado `role=anon` do projeto; `sb_secret_*`, `service_role`, authenticated/custom e opacos inválidos falham antes da rede, com validação repetida no runner. JWT de usuário explícito continua read-only e sem assinatura atestada. Falta E2E autorizado. |
| `websocket_recon` | Bom | 7/6/5/6 | Handshake controlado, análise de autorização e redação específica de tokens em URL. |

## Validação ativa e Kali

| Módulo | Nível | E/Q/P/C | Para chegar a Excelente |
|---|---:|---:|---|
| `curl_probe` | Ótimo | 9/9/8/9 | Adicionar E2E local com curl real e corpus calibrado para CORS/auth; o módulo já não envia métodos mutáveis. |
| `ftp_write_probe` | Ótimo (laboratório) | 9/9/9/8 | O lifecycle próprio falha com possível resíduo desde o reply preliminar, tenta cleanup quando possível e bloqueia writes seguintes. Falta E2E em servidor FTP descartável cobrindo timeout, `DELE`, resíduo e recuperação. Para bug bounty use `ftp_anonymous_audit` sem escrita. |
| `info_disclosure_errors` | Bom | 7/8/7/7 | Baseline diferencial, limites e fechamento de stream implementados; falta corpus negativo amplo e E2E do subprocesso. |
| `info_disclosure_hunter` | Bom | 7/7/6/6 | Testes completos, menor monólito e validação contextual de PII/segredos. |
| `micro_exploit` | Ótimo | 9/9/9/8 | Usa canário SVG inerte, nunca declara execução e exige candidato anterior; falta confirmação browser isolada. |
| `mysql_3306_intel` | Ótimo | 8/8/9/8 | Inventário estruturado, limitado e revalidado por host; nomes por substring não confirmam MySQL. Falta corpus Nmap/banners/proxies e proveniência ponta a ponta. |
| `nmap_backport_review` | Bom | 7/7/5/7 | Base de backports/distro e correlação por pacote, não apenas texto de contexto. |
| `nmap_cve_match` | Bom | 7/7/5/7 | CPE/versionamento preciso, freshness e confirmação de backport. |
| `nmap_service_followups` | Ótimo | 9/9/8/8 | Gate intrusivo, UI off, revalidação de host, evidência específica e Exploit-DB como candidato; falta E2E de ferramentas. |
| `pentestgpt_validate` | Ótimo | 9/9/8/8 | Loopback/allowlist, consentimento remoto, signal, limites e saída IA sempre não verificada; falta schema assinado e benchmark. |
| `secret_validation` | Ótimo | 9/9/9/8 | 403/429 inconclusivos, anon key pública, service-role não exercida e chaves genéricas não são enviadas; falta E2E provider. |
| `shannon_whitebox` | Falta muito | 8/7/6/5 | Candidatos normalizados, limites/redação e pedido de cancelamento implementados; falta observar término Temporal e provar ausência de atividades órfãs. |
| `sqlmap` | Bom | 8/7/7/6 | Scope em redirects, congelar `--dbs` antes do gate e parser estruturado sem substring ambígua. |
| `verify_sqli_deep` | Ótimo | 9/9/8/9 | Calibrar contra ground truth de frameworks/DBs e adicionar confirmação separada aprovada; heurística permanece no máximo `probable`. |
| `webshell_probe` | Bom | 7/7/6/7 | Sem comandos; somente indicador de conteúdo com escopo/sinal/limite. Falta corpus negativo e baseline; não é verificação de execução. |
| `kali_dalfox` | Bom | 7/7/7/6 | Limitar workers, pin da versão e confirmação browser isolada. |
| `kali_dirsearch` | Falta muito | 7/7/5/7 | Limites e outcomes implementados; falta baseline própria soft-404/catch-all e E2E de escopo em redirects/recursão. |
| `kali_ffuf` | Bom | 8/8/7/7 | Autocalibração, inventário HTTP e outcomes implementados; falta versão fixada, corpus de calibração dinâmica e E2E do binário. |
| `kali_nmap` | Ótimo | 8/8/8/8 | Exit não zero/timeout não vira sucesso, XML é limitado, a ingestão reaplica escopo e overrides recusam scripts/alvos/saídas; `-A`, `-p-`, `-T5` e `--min-rate` ficam no agressivo. Falta versão fixada e E2E de cancelamento da árvore. |
| `kali_nmap_aggressive` | Bom | 7/6/8/6 | Orçamento por host/porta, aprovação detalhada e presets menos amplos que `-A -p-`. |
| `kali_nmap_udp` | Bom | 7/6/7/6 | `-sU` obrigatório, args sem scripts/alvos/saídas/portas extras e lista separada validada de até 128 portas. Falta E2E, versão fixada e orçamento de timeout calibrado. |
| `kali_nuclei` | Bom | 7/6/7/6 | Fixar templates/versionamento e política por template, não somente por severidade/tag. |
| `kali_whois` | Bom | 6/6/7/6 | Parser RDAP-first e testes para formatos internacionais. |
| `kali_wpscan` | Ótimo | 8/8/8/8 | CVEs de base são candidatas não verificadas, JSON/exit/timeout têm validação e versões são inventário. Falta fixar versão/database e E2E local. |
| `kali_xss_vibes` | Ótimo | 9/9/8/9 | Integrar confirmação browser isolada e medir contextos/encodings em corpus; reflexão continua corretamente como candidato. |

## Vigolium e FrameSeven

| Motor | Nível | E/Q/P/C | Para chegar a Excelente |
|---|---:|---:|---|
| `vigolium_audit` | Bom | 8/7/5/5 | Precisão reproduzível da análise IA, schemas rígidos e plano nativo expandido antes dos gates. |
| `vigolium_dast` | Bom | 8/7/6/5 | Expandir os módulos internos antes de RBAC/scope/engagement/OPSEC, além de cancelamento e relatórios normalizados E2E. |
| `vigolium_swarm` | Falta muito | 8/7/5/4 | Indisponível no bridge/catálogo. Falta impedir expansão no motor nativo e comprovar escopo, limites e cancelamento antes de disponibilizar execução. |
| `vigolium_autopilot` | Falta muito | 8/7/4/5 | Disponível apenas como prévia, sem achados de scan; falta plano nativo auditável, aprovação granular e retomada/cancelamento comprovados. |
| FrameSeven `offensive_v1` | Bom | 8/7/6/6 | Revalidar escopo em cada URL/subdomínio/IP descoberto e cancelar a ferramenta Go real no timeout, não apenas abandonar a goroutine. |

## Problemas restantes que derrubam o modo manual inteiro

1. A taxonomia de severidade está fragmentada. Alguns módulos produzem
   `critical`/`medium`, enquanto o relatório ainda reduz qualquer coisa
   diferente de `high`/`med` para low. Já existe um normalizador, mas ele não foi
   adotado em todas as fronteiras: `server/pipeline/phases/finalize.mjs` e
   `server/lib/severity.mjs`.

2. O caminho manual da prévia Autopilot agora resolve IDs concretos antes da
   aprovação. Isso não garante enforcement de execução nativa: Swarm está
   indisponível e Autopilot é somente prévia. Demais caminhos de engine ainda
   precisam ser verificados individualmente.

3. A cobertura do `fetchImpl` central ainda não alcança todos os clientes
   legados; os módulos corrigidos nesta rodada já usam adapter, scope e signal.

4. O pipeline híbrido possui boas fases, mas manifests e timeouts ainda não
   governam todos os módulos igualmente: `server/pipeline/run-pipeline.mjs`.

## Ordem recomendada para chegar a Excelente

1. Tornar `info/low/med/high/critical` a única taxonomia interna.
2. Expandir e congelar Vigolium/FrameSeven/follow-ups antes dos gates.
3. Unificar todos os módulos no registry e impor timeout, signal, scope e
   provenance pelo dispatcher.
4. Separar resultados em `inventário`, `candidato`, `provável` e `confirmado`.
5. Criar corpus de ground truth e medir precisão/recall por módulo.
6. Exigir para cada módulo testes positivo, negativo, timeout, cancelamento,
   scope, redirect e ausência de segredos.

## Verificação do lote Ótimo — 2026-09-09

### Complemento da promoção para Top

Após as correções finais, passaram **21 de 21 arquivos de testes dirigidos**.
Esse conjunto cobre snapshots OpenAPI v1/v2, adulteracão, diff semântico,
timeout e cobertura parcial; PSL exact/wildcard/exception/private/IDN; XML
Sitemap com namespaces, extensões, CDATA, entidades, DTD/XXE, gzip, recursão,
ciclos, redirects, escopo, limites e timeout; CSP aplicada/Report-Only,
políticas múltiplas e headers duplicados; dispatcher/NDJSON, rota manual,
planner, OPSEC e engagement.

A execução hermética global desta revisão terminou em **184 de 188 arquivos**.
As quatro falhas restantes são as limitações de sandbox já reproduzidas:
dois casos de processo filho sem `stdout` observável
(`auth-principal-restart.test.js`, `auto-agent.test.js`) e dois casos em que
`listen(127.0.0.1)` é recusado com `EPERM`
(`tor-tunnel.test.js`, `vigolium-server-client.test.js`). O teste
`forge-security.test.js`, que oscilou na primeira execução concorrente, passou
isolado em 20 de 20 casos e passou na repetição global.

Os arquivos JavaScript alterados passaram em `node --check`, e a composição do
servidor importou com `GHOSTRECON_NO_HTTP_LISTEN=1`. Toda a validação foi local
com mocks/fixtures: nenhum alvo externo, navegador real, proxy real, scanner,
login ou write probe foi executado.

Passaram **42 de 42 arquivos de testes direcionados**. A bateria cobre os 30
módulos, o novo `ftp_anonymous_audit`, plano efetivo/OPSEC, Supabase sem writes
ou credencial privilegiada, escopo do IP pinado, parsers, limites, cancelamento,
outcomes, UI e redação de evidência. O recorte `evaluateAutoRun` de
`auto-agent.test.js` também passou separadamente, cobrindo falha fatal acima de
`partial` e status ausente em fail-closed.

Na suíte hermética global, **181 de 185 arquivos passaram**. As quatro falhas
restantes foram reproduzidas como limitações do sandbox desta sessão, não como
regressões do lote:

- `auth-principal-restart.test.js` e `auto-agent.test.js`: processos Node filhos
  encerram com código zero, mas o sandbox devolve `stdout`/`stderr` vazios;
- `tor-tunnel.test.js` e `vigolium-server-client.test.js`: o sandbox recusa
  `listen(127.0.0.1)` com `EPERM`.

As falhas anteriores de `finding-redaction`, assentamento do Codex App Server,
particionamento RAG e fixture HTML do XSS foram corrigidas e passaram. A
verificação estática também passou nos arquivos alterados com `node --check`,
no script inline da UI, em `git diff --check` e na importação do servidor com HTTP
desabilitado. `test:cli` passou em 2 de 2 arquivos e `test:mcp` em 1 de 1. O gate
Auto hermético passou em 39 de 41 arquivos; as duas falhas são os mesmos casos
de stdout de subprocesso já descritos acima. Toda a verificação foi local, com
fixtures/mocks; não houve scan externo,
login FTP real, Nmap/WPScan real, Tor real, write probe ou envio de segredo.

## Verificação desta rodada — 2026-09-06

Passaram **28 arquivos de testes Node direcionados** e **5 testes Python**.
A bateria cobre os 12 módulos, Firebase sem escrita, cancelamento, outcomes de
processos, transporte restrito de autenticação, catálogo, congelamento de
runtime, rotas manuais e contrato da UI. Os novos testes principais estão em
`server/tests/falta-muito-hardening.test.js`,
`server/tests/firebase-readonly-outcomes.test.js`,
`server/tests/kali-discovery-outcomes.test.js` e
`tools/info-disclosure/test_information_disclosure.py`.

Também passaram `node --check` em 29 arquivos JavaScript, a verificação
sintática do script inline da UI, o parse do playbook Firebase e `git diff --check`.

A suíte global não foi refeita nesta rodada. A execução adicional de
`finding-redaction.test.js` reproduziu uma falha (3 casos passaram, 1 falhou):
um hash estrutural é mascarado. Essa é uma pendência separada; o redator global
não foi alterado naquela rodada. A falha foi corrigida e revalidada em
2026-09-07, conforme a seção acima.

Não houve instalação, download, scan externo, execução de scanner real,
Temporal, build Go ou alteração em clones/artefatos históricos do usuário.

## Histórico de verificação — rodada de 2026-09-01

Após as correções, os 26 arquivos da bateria direcionada passaram. Ela cobre
os módulos antes classificados como Ruim, os módulos destrutivos já corrigidos,
proxy/Tor, escopo, OPSEC, plano efetivo, cancelamento, TruffleHog local e o
contrato da UI. Os 28 arquivos JavaScript alterados mais relevantes passaram
em `node --check`, e o servidor importou com
`GHOSTRECON_NO_HTTP_LISTEN=1`.

Na execução global registrada nessa rodada anterior, 174 de 181 arquivos
passaram. Os sete restantes estão fora das correções desta rodada:
subprocesso/EOF e cleanup do Auto, inicialização RAG, uma expectativa histórica
de redação e testes de socket local Tor/Vigolium bloqueados pelo sandbox
(`listen EPERM`).

Não foram executados scans contra alvos reais nem o write probe FTP real. Isso
exigiria alvo autorizado/laboratório definido; os testes usados são herméticos.
