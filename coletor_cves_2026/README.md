# Coletor de CVEs (multi-ano) + filtro web

Este pacote baixa registros públicos CVE e, opcionalmente, filtra **somente CVEs web**
para o módulo passivo `cve_correlation` do GHOSTRECON.

## Fontes

- **CVE List V5**: lista oficial do programa CVE.
- **NVD JSON 2.0**: feed anual enriquecido (CVSS, CWE, CPE, CISA KEV).

## Uso recomendado (GHOSTRECON)

Gera `web-cves.jsonl` (só web) e depois constrói o SQLite local:

```bash
# Na raiz do repositório:
npm run cve:collect
npm run cve:build
```

No `npm start`, o stack chama automaticamente `ensure-cve-web-db`
(collect+build se o DB faltar ou tiver mais de 24h). Para forçar em todo start:

```bash
# .env
GHOSTRECON_CVE_AUTO_UPDATE=always
```

Para desligar no start: `GHOSTRECON_CVE_AUTO_UPDATE=0` ou `GHOSTRECON_STACK_CVE=0`.

Ou diretamente:

```bash
python3 coletor_cves_2026/coletar_cves_2026.py \
  --fonte nvd \
  --anos 2018-2026 \
  --somente-web \
  --excluir-rejeitadas \
  --saida coletor_cves_2026/cves_web_saida

node scripts/build-cve-web-db.mjs \
  --input coletor_cves_2026/cves_web_saida/web-cves.jsonl \
  --output data/cve/web-cves.db
```

O dataset gerado fica em `data/cve/` (não versionado). Sem o arquivo, o módulo
`cve_correlation` degrada sem quebrar o pipeline.

## Flags novas

| Flag | Descrição |
|------|-----------|
| `--anos 2018-2026` | Ano único, lista (`2018,2020`) ou intervalo |
| `--somente-web` | Aplica o critério web e grava `web-cves.jsonl` |
| `--fonte nvd\|oficial\|ambas` | Fonte de dados (NVD é o mais útil para CPE) |

## Critério "somente web"

Entra se houver ao menos um sinal forte:

1. CPE de aplicação (`part = a`);
2. CWE web (79, 89, 78, 352, 918, …) **e** keyword web;
3. Keyword web em vendor/produto/descrição com produto textual.

Descarta explicitamente kernel, driver, firmware, bluetooth, wifi, etc. (quando
não houver sinal HTTP/web).

O critério vive em `cve_web_filter.py` (Python) e o espelho de testes em
`server/modules/cve-web-filter.mjs` (Node).

## Schema `web-cves.jsonl`

```json
{"id":"CVE-2021-41773","cvss":7.5,"sev":"HIGH","cwes":["CWE-22"],
 "kev":true,"desc":"...","refs":["..."],
 "affected":[{"vendor":"apache","product":"http_server",
   "cpe":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
   "introduced":"2.4.49","fixed":""}]}
```

## Tempo real (pipeline)

A coleta acima é **offline**. Para CVEs novas no dia a dia, o módulo
`cve_correlation` pode consultar a NVD API 2.0 sob demanda:

```bash
# .env
GHOSTRECON_CVE_REALTIME=1
GHOSTRECON_CVE_REALTIME_TTL_HOURS=24
NVD_API_KEY=           # opcional, melhora rate limit
```

## Windows / Linux (atalhos)

```powershell
# Windows — padrão agora: NVD multi-ano + somente-web
.\executar_windows.bat
```

```bash
chmod +x executar_linux.sh
./executar_linux.sh
```

## Requisitos

- Python 3.10+
- Internet durante a coleta
- Git apenas se `--fonte oficial` ou `ambas`
- Na raiz: Node 20+ e `better-sqlite3` para `npm run cve:build`

## Observação

O ano no ID CVE é o ano de **atribuição**, não necessariamente o dia da
publicação. Rode o coletor periodicamente e reconstrua o SQLite para manter o
dataset local atualizado.
