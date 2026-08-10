#!/usr/bin/env python3
"""
Coleta registros públicos CVE-YYYY-* (um ou mais anos).

Fontes suportadas:
  - oficial: CVE List V5 (CVEProject/cvelistV5), fonte oficial do programa CVE.
  - nvd: feed anual JSON 2.0 do NVD, com enriquecimentos como CVSS, CWE, CPE e KEV.
  - ambas: baixa as duas fontes e gera uma comparação.

Com --somente-web, filtra CVEs de aplicação web e emite web-cves.jsonl
(schema compacto para o módulo cve_correlation do GHOSTRECON).

Somente bibliotecas da instalação padrão do Python são usadas. Para a fonte
oficial, o executável `git` precisa estar instalado.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from cve_web_filter import WEB_FILTER_VERSION, to_web_record

DEFAULT_ANO = 2026
CVE_REPO = "https://github.com/CVEProject/cvelistV5.git"
NVD_ZIP_TMPL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{ano}.json.zip"
USER_AGENT = "Coletor-CVEs-GHOSTRECON/2.0 (+uso defensivo e pesquisa)"

COLUNAS = [
    "cve_id",
    "status",
    "publicada_em",
    "atualizada_em",
    "fonte_dados",
    "assigner_ou_source",
    "descricao",
    "cvss_versao",
    "cvss_score",
    "severidade",
    "vetor_cvss",
    "cwes",
    "fornecedores",
    "produtos",
    "versoes_afetadas",
    "cpes",
    "cisa_kev",
    "cisa_adicionada_em",
    "cisa_correcao_ate",
    "cisa_acao_requerida",
    "referencias",
    "url_registro",
]


def log(msg: str) -> None:
    print(f"[{dt.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def executar(cmd: list[str], cwd: Path | None = None) -> None:
    log("Executando: " + " ".join(cmd))
    try:
        subprocess.run(cmd, cwd=cwd, check=True)
    except FileNotFoundError as exc:
        raise RuntimeError(f"Comando não encontrado: {cmd[0]}") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Comando falhou com código {exc.returncode}: {' '.join(cmd)}") from exc


def texto_por_idioma(itens: Any, preferido: str = "en") -> str:
    if not isinstance(itens, list):
        return ""
    for item in itens:
        if isinstance(item, dict) and item.get("lang") == preferido and item.get("value"):
            return str(item["value"]).strip()
    for item in itens:
        if isinstance(item, dict) and item.get("value"):
            return str(item["value"]).strip()
    return ""


def uniq(valores: Iterable[Any]) -> list[str]:
    vistos: set[str] = set()
    saida: list[str] = []
    for valor in valores:
        if valor is None:
            continue
        s = str(valor).strip()
        if not s or s in vistos:
            continue
        vistos.add(s)
        saida.append(s)
    return saida


def juntar(valores: Iterable[Any]) -> str:
    return " | ".join(uniq(valores))


def chave_cve(cve_id: str) -> tuple[int, str]:
    try:
        return int(cve_id.rsplit("-", 1)[1]), cve_id
    except (ValueError, IndexError):
        return sys.maxsize, cve_id


def sanitizar_csv(valor: Any) -> Any:
    """Evita interpretação como fórmula ao abrir o CSV no Excel/LibreOffice."""
    if not isinstance(valor, str):
        return valor
    valor = valor.replace("\x00", "")
    if valor.startswith(("=", "+", "-", "@")):
        return "'" + valor
    return valor


def gravar_csv(caminho: Path, registros: list[dict[str, Any]]) -> None:
    caminho.parent.mkdir(parents=True, exist_ok=True)
    with caminho.open("w", encoding="utf-8-sig", newline="") as arq:
        writer = csv.DictWriter(arq, fieldnames=COLUNAS, extrasaction="ignore")
        writer.writeheader()
        for registro in registros:
            writer.writerow({k: sanitizar_csv(registro.get(k, "")) for k in COLUNAS})


def gravar_jsonl(caminho: Path, registros: list[dict[str, Any]]) -> None:
    caminho.parent.mkdir(parents=True, exist_ok=True)
    with caminho.open("w", encoding="utf-8") as arq:
        for registro in registros:
            arq.write(json.dumps(registro, ensure_ascii=False, separators=(",", ":")) + "\n")


def escolher_cvss_oficial(metricas: Any) -> tuple[str, str, str, str]:
    if not isinstance(metricas, list):
        return "", "", "", ""
    preferencia = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")
    for chave in preferencia:
        for item in metricas:
            if not isinstance(item, dict) or chave not in item:
                continue
            cvss = item.get(chave) or {}
            versao = str(cvss.get("version", ""))
            score = str(cvss.get("baseScore", ""))
            severidade = str(cvss.get("baseSeverity", ""))
            vetor = str(cvss.get("vectorString", ""))
            return versao, score, severidade, vetor
    return "", "", "", ""


def extrair_cwes_oficial(cna: dict[str, Any]) -> str:
    valores: list[str] = []
    for bloco in cna.get("problemTypes", []) or []:
        for item in bloco.get("descriptions", []) or []:
            if not isinstance(item, dict):
                continue
            cwe = item.get("cweId") or item.get("description")
            if cwe:
                valores.append(str(cwe))
    return juntar(valores)


def resumir_versoes(versoes: Any) -> list[str]:
    saida: list[str] = []
    if not isinstance(versoes, list):
        return saida
    for v in versoes:
        if not isinstance(v, dict):
            continue
        partes = []
        if v.get("version") is not None:
            partes.append(str(v["version"]))
        if v.get("lessThan") is not None:
            partes.append(f"< {v['lessThan']}")
        if v.get("lessThanOrEqual") is not None:
            partes.append(f"<= {v['lessThanOrEqual']}")
        if v.get("status"):
            partes.append(f"status={v['status']}")
        if v.get("versionType"):
            partes.append(f"tipo={v['versionType']}")
        if partes:
            saida.append(", ".join(partes))
    return saida


def parse_oficial(arquivo: Path, prefixo: str) -> dict[str, Any] | None:
    try:
        data = json.loads(arquivo.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log(f"Aviso: não foi possível ler {arquivo}: {exc}")
        return None

    meta = data.get("cveMetadata", {}) or {}
    cve_id = str(meta.get("cveId", ""))
    if not cve_id.startswith(prefixo):
        return None

    cna = ((data.get("containers") or {}).get("cna") or {})
    estado = str(meta.get("state", ""))
    descricao = texto_por_idioma(cna.get("descriptions"))
    if not descricao and estado.upper() == "REJECTED":
        descricao = texto_por_idioma(cna.get("rejectedReasons"))

    versao_cvss, score, severidade, vetor = escolher_cvss_oficial(cna.get("metrics"))

    fornecedores: list[str] = []
    produtos: list[str] = []
    versoes: list[str] = []
    for afetado in cna.get("affected", []) or []:
        if not isinstance(afetado, dict):
            continue
        vendor = afetado.get("vendor")
        product = afetado.get("product")
        if vendor:
            fornecedores.append(str(vendor))
        if product:
            produtos.append(str(product))
        prefixo_prod = " / ".join(x for x in (str(vendor or ""), str(product or "")) if x)
        for v in resumir_versoes(afetado.get("versions")):
            versoes.append(f"{prefixo_prod}: {v}" if prefixo_prod else v)

    referencias = [r.get("url") for r in cna.get("references", []) or [] if isinstance(r, dict)]

    return {
        "cve_id": cve_id,
        "status": estado,
        "publicada_em": meta.get("datePublished", ""),
        "atualizada_em": meta.get("dateUpdated", ""),
        "fonte_dados": "CVE List V5 (oficial)",
        "assigner_ou_source": meta.get("assignerShortName") or meta.get("assignerOrgId", ""),
        "descricao": descricao,
        "cvss_versao": versao_cvss,
        "cvss_score": score,
        "severidade": severidade,
        "vetor_cvss": vetor,
        "cwes": extrair_cwes_oficial(cna),
        "fornecedores": juntar(fornecedores),
        "produtos": juntar(produtos),
        "versoes_afetadas": juntar(versoes),
        "cpes": "",
        "cisa_kev": "",
        "cisa_adicionada_em": "",
        "cisa_correcao_ate": "",
        "cisa_acao_requerida": "",
        "referencias": juntar(referencias),
        "url_registro": f"https://www.cve.org/CVERecord?id={cve_id}",
    }


def coletar_oficial(destino: Path, anos: list[int], excluir_rejeitadas: bool) -> list[dict[str, Any]]:
    if shutil.which("git") is None:
        raise RuntimeError("Git não encontrado. Instale o Git ou use --fonte nvd.")

    registros: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="cvelistV5-") as tmp:
        repo = Path(tmp) / "cvelistV5"
        executar([
            "git", "clone", "--depth", "1", "--filter=blob:none", "--sparse",
            CVE_REPO, str(repo),
        ])
        sparse_paths = [f"cves/{ano}" for ano in anos]
        executar(["git", "-C", str(repo), "sparse-checkout", "set", *sparse_paths])

        for ano in anos:
            prefixo = f"CVE-{ano}-"
            arquivos = sorted((repo / "cves" / str(ano)).rglob(f"{prefixo}*.json"))
            log(f"Arquivos CVE oficiais {ano}: {len(arquivos)}")
            for i, arquivo in enumerate(arquivos, 1):
                registro = parse_oficial(arquivo, prefixo)
                if not registro:
                    continue
                if excluir_rejeitadas and registro["status"].upper() == "REJECTED":
                    continue
                registros.append(registro)
                if i % 5000 == 0:
                    log(f"Processados {i}/{len(arquivos)} arquivos oficiais {ano}")

    registros.sort(key=lambda r: chave_cve(str(r["cve_id"])))
    anos_tag = anos_tag_name(anos)
    gravar_csv(destino / f"cves_{anos_tag}_oficial.csv", registros)
    gravar_jsonl(destino / f"cves_{anos_tag}_oficial.jsonl", registros)
    return registros


def baixar(url: str, destino: Path, timeout: int) -> None:
    destino.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    log(f"Baixando {url}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resposta, destino.open("wb") as arq:
            total = resposta.headers.get("Content-Length")
            total_int = int(total) if total and total.isdigit() else None
            baixado = 0
            while True:
                bloco = resposta.read(1024 * 1024)
                if not bloco:
                    break
                arq.write(bloco)
                baixado += len(bloco)
                if total_int:
                    pct = baixado * 100 / total_int
                    print(f"\rBaixado: {baixado/1024/1024:.1f} MB ({pct:.1f}%)", end="", flush=True)
            if total_int:
                print()
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Falha ao baixar {url}: {exc}") from exc


def escolher_cvss_nvd(metricas: Any) -> tuple[str, str, str, str]:
    if not isinstance(metricas, dict):
        return "", "", "", ""
    for chave in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        lista = metricas.get(chave)
        if not isinstance(lista, list) or not lista:
            continue
        item = lista[0] if isinstance(lista[0], dict) else {}
        cvss = item.get("cvssData", {}) if isinstance(item, dict) else {}
        versao = str(cvss.get("version", ""))
        score = str(cvss.get("baseScore", ""))
        severidade = str(cvss.get("baseSeverity") or item.get("baseSeverity") or "")
        vetor = str(cvss.get("vectorString", ""))
        return versao, score, severidade, vetor
    return "", "", "", ""


def extrair_cwes_nvd(cve: dict[str, Any]) -> str:
    valores: list[str] = []
    for fraqueza in cve.get("weaknesses", []) or []:
        for item in fraqueza.get("description", []) or []:
            if isinstance(item, dict) and item.get("value"):
                valores.append(str(item["value"]))
    return juntar(valores)


def extrair_cpes(configuracoes: Any) -> list[str]:
    encontrados: list[str] = []

    def visitar(obj: Any) -> None:
        if isinstance(obj, dict):
            for match in obj.get("cpeMatch", []) or []:
                if isinstance(match, dict) and match.get("criteria"):
                    encontrados.append(str(match["criteria"]))
            for valor in obj.values():
                visitar(valor)
        elif isinstance(obj, list):
            for item in obj:
                visitar(item)

    visitar(configuracoes)
    return uniq(encontrados)


def cpe_vendor_produto(cpe: str) -> tuple[str, str]:
    # CPE 2.3: cpe:2.3:<part>:<vendor>:<product>:...
    partes = cpe.split(":")
    if len(partes) >= 5:
        vendor = partes[3].replace("\\_", "_").replace("\\-", "-")
        produto = partes[4].replace("\\_", "_").replace("\\-", "-")
        return vendor, produto
    return "", ""


def parse_nvd_item(item: dict[str, Any], prefixo: str) -> dict[str, Any] | None:
    cve = item.get("cve", {}) if isinstance(item, dict) else {}
    cve_id = str(cve.get("id", ""))
    if not cve_id.startswith(prefixo):
        return None

    versao_cvss, score, severidade, vetor = escolher_cvss_nvd(cve.get("metrics"))
    cpes = extrair_cpes(cve.get("configurations"))
    fornecedores: list[str] = []
    produtos: list[str] = []
    for cpe in cpes:
        vendor, produto = cpe_vendor_produto(cpe)
        fornecedores.append(vendor)
        produtos.append(produto)

    referencias = [r.get("url") for r in cve.get("references", []) or [] if isinstance(r, dict)]
    kev = bool(cve.get("cisaExploitAdd") or cve.get("cisaActionDue") or cve.get("cisaRequiredAction"))

    return {
        "cve_id": cve_id,
        "status": cve.get("vulnStatus", ""),
        "publicada_em": cve.get("published", ""),
        "atualizada_em": cve.get("lastModified", ""),
        "fonte_dados": "NVD JSON 2.0",
        "assigner_ou_source": cve.get("sourceIdentifier", ""),
        "descricao": texto_por_idioma(cve.get("descriptions")),
        "cvss_versao": versao_cvss,
        "cvss_score": score,
        "severidade": severidade,
        "vetor_cvss": vetor,
        "cwes": extrair_cwes_nvd(cve),
        "fornecedores": juntar(fornecedores),
        "produtos": juntar(produtos),
        "versoes_afetadas": "",
        "cpes": juntar(cpes),
        "cisa_kev": "SIM" if kev else "NÃO",
        "cisa_adicionada_em": cve.get("cisaExploitAdd", ""),
        "cisa_correcao_ate": cve.get("cisaActionDue", ""),
        "cisa_acao_requerida": cve.get("cisaRequiredAction", ""),
        "referencias": juntar(referencias),
        "url_registro": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def coletar_nvd(
    destino: Path,
    anos: list[int],
    excluir_rejeitadas: bool,
    timeout: int,
    manter_bruto: bool,
) -> list[dict[str, Any]]:
    registros: list[dict[str, Any]] = []
    for ano in anos:
        prefixo = f"CVE-{ano}-"
        zip_path = destino / f"nvdcve-2.0-{ano}.json.zip"
        baixar(NVD_ZIP_TMPL.format(ano=ano), zip_path, timeout)

        with zipfile.ZipFile(zip_path, "r") as zf:
            nomes = [n for n in zf.namelist() if n.endswith(".json")]
            if not nomes:
                raise RuntimeError(f"O ZIP do NVD {ano} não contém arquivo JSON.")
            nome_json = nomes[0]
            log(f"Lendo {nome_json} diretamente do ZIP ({ano})")
            with zf.open(nome_json) as arq:
                data = json.load(arq)
            if manter_bruto:
                zf.extract(nome_json, path=destino)

        vulnerabilidades = data.get("vulnerabilities", []) or []
        log(f"Itens no feed NVD {ano}: {len(vulnerabilidades)}")
        for i, item in enumerate(vulnerabilidades, 1):
            registro = parse_nvd_item(item, prefixo)
            if not registro:
                continue
            if excluir_rejeitadas and registro["status"].upper() in {"REJECT", "REJECTED"}:
                continue
            registros.append(registro)
            if i % 5000 == 0:
                log(f"Processados {i}/{len(vulnerabilidades)} itens NVD {ano}")

    registros.sort(key=lambda r: chave_cve(str(r["cve_id"])))
    anos_tag = anos_tag_name(anos)
    gravar_csv(destino / f"cves_{anos_tag}_nvd.csv", registros)
    gravar_jsonl(destino / f"cves_{anos_tag}_nvd.jsonl", registros)
    return registros


def contar(registros: list[dict[str, Any]], campo: str) -> dict[str, int]:
    contador = Counter(str(r.get(campo) or "SEM_VALOR") for r in registros)
    return dict(sorted(contador.items(), key=lambda x: (-x[1], x[0])))


def gerar_comparacao(
    destino: Path,
    anos: list[int],
    oficial: list[dict[str, Any]],
    nvd: list[dict[str, Any]],
) -> dict[str, int]:
    ids_oficial = {str(r["cve_id"]) for r in oficial}
    ids_nvd = {str(r["cve_id"]) for r in nvd}
    todos = sorted(ids_oficial | ids_nvd, key=chave_cve)

    caminho = destino / f"comparacao_fontes_{anos_tag_name(anos)}.csv"
    with caminho.open("w", encoding="utf-8-sig", newline="") as arq:
        campos = ["cve_id", "na_lista_oficial", "no_nvd", "situacao"]
        writer = csv.DictWriter(arq, fieldnames=campos)
        writer.writeheader()
        for cve_id in todos:
            no_oficial = cve_id in ids_oficial
            no_nvd = cve_id in ids_nvd
            if no_oficial and no_nvd:
                situacao = "NAS_DUAS_FONTES"
            elif no_oficial:
                situacao = "SOMENTE_OFICIAL"
            else:
                situacao = "SOMENTE_NVD"
            writer.writerow({
                "cve_id": cve_id,
                "na_lista_oficial": "SIM" if no_oficial else "NÃO",
                "no_nvd": "SIM" if no_nvd else "NÃO",
                "situacao": situacao,
            })

    return {
        "uniao": len(todos),
        "nas_duas": len(ids_oficial & ids_nvd),
        "somente_oficial": len(ids_oficial - ids_nvd),
        "somente_nvd": len(ids_nvd - ids_oficial),
    }


def anos_tag_name(anos: list[int]) -> str:
    if len(anos) == 1:
        return str(anos[0])
    return f"{anos[0]}-{anos[-1]}"


def parse_anos(raw: str) -> list[int]:
    text = str(raw or "").strip()
    if not text:
        return [DEFAULT_ANO]
    anos: set[int] = set()
    for parte in text.split(","):
        parte = parte.strip()
        if not parte:
            continue
        if "-" in parte:
            a, b = parte.split("-", 1)
            inicio, fim = int(a), int(b)
            if inicio > fim:
                inicio, fim = fim, inicio
            if fim - inicio > 40:
                raise ValueError(f"intervalo de anos muito largo: {parte}")
            anos.update(range(inicio, fim + 1))
        else:
            anos.add(int(parte))
    out = sorted(anos)
    if not out:
        raise ValueError("nenhum ano válido em --anos")
    for ano in out:
        if ano < 1999 or ano > 2100:
            raise ValueError(f"ano fora do intervalo suportado: {ano}")
    return out


def emitir_web_cves(destino: Path, registros: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filtra CVEs web e grava web-cves.jsonl (preferindo registros NVD quando houver CPE)."""
    by_id: dict[str, dict[str, Any]] = {}
    for registro in registros:
        web = to_web_record(registro)
        if not web:
            continue
        prev = by_id.get(web["id"])
        # Preferência: registro com mais affected/CPE, depois com CVSS.
        if not prev:
            by_id[web["id"]] = web
            continue
        prev_score = (len(prev.get("affected") or []), float(prev.get("cvss") or 0))
        next_score = (len(web.get("affected") or []), float(web.get("cvss") or 0))
        if next_score >= prev_score:
            by_id[web["id"]] = web

    web_list = sorted(by_id.values(), key=lambda r: chave_cve(str(r["id"])))
    caminho = destino / "web-cves.jsonl"
    gravar_jsonl(caminho, web_list)
    log(f"web-cves.jsonl: {len(web_list)} CVEs web (filtro v{WEB_FILTER_VERSION})")
    return web_list


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Baixa e exporta registros CVE públicos (um ou mais anos).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--fonte", choices=("oficial", "nvd", "ambas"), default="ambas")
    parser.add_argument(
        "--anos",
        default=str(DEFAULT_ANO),
        help="Ano único, lista (2018,2019) ou intervalo (2018-2026).",
    )
    parser.add_argument("--saida", type=Path, default=None)
    parser.add_argument("--excluir-rejeitadas", action="store_true")
    parser.add_argument(
        "--somente-web",
        action="store_true",
        help="Filtra CVEs web e gera web-cves.jsonl para o módulo cve_correlation.",
    )
    parser.add_argument("--manter-json-bruto", action="store_true", help="Extrai também o JSON bruto do NVD (~centenas de MB).")
    parser.add_argument("--timeout", type=int, default=180, help="Timeout de conexão em segundos.")
    args = parser.parse_args()

    try:
        anos = parse_anos(args.anos)
    except ValueError as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 2

    destino = (args.saida or Path(f"cves_{anos_tag_name(anos)}_saida")).resolve()
    destino.mkdir(parents=True, exist_ok=True)
    log(f"Saída: {destino}")
    log(f"Anos: {anos}")

    resumo: dict[str, Any] = {
        "anos_do_identificador": anos,
        "gerado_em_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "fonte_solicitada": args.fonte,
        "rejeitadas_excluidas": args.excluir_rejeitadas,
        "somente_web": args.somente_web,
        "web_filter_version": WEB_FILTER_VERSION if args.somente_web else None,
        "arquivos": {},
    }

    oficial: list[dict[str, Any]] = []
    nvd: list[dict[str, Any]] = []

    try:
        if args.fonte in {"oficial", "ambas"}:
            oficial = coletar_oficial(destino, anos, args.excluir_rejeitadas)
            resumo["oficial"] = {
                "total": len(oficial),
                "por_status": contar(oficial, "status"),
                "por_severidade": contar(oficial, "severidade"),
            }
            tag = anos_tag_name(anos)
            resumo["arquivos"]["oficial_csv"] = f"cves_{tag}_oficial.csv"
            resumo["arquivos"]["oficial_jsonl"] = f"cves_{tag}_oficial.jsonl"
            log(f"Total na lista oficial: {len(oficial)}")

        if args.fonte in {"nvd", "ambas"}:
            nvd = coletar_nvd(destino, anos, args.excluir_rejeitadas, args.timeout, args.manter_json_bruto)
            resumo["nvd"] = {
                "total": len(nvd),
                "por_status": contar(nvd, "status"),
                "por_severidade": contar(nvd, "severidade"),
                "cisa_kev": contar(nvd, "cisa_kev"),
            }
            tag = anos_tag_name(anos)
            resumo["arquivos"]["nvd_csv"] = f"cves_{tag}_nvd.csv"
            resumo["arquivos"]["nvd_jsonl"] = f"cves_{tag}_nvd.jsonl"
            resumo["arquivos"]["nvd_zip_original"] = [f"nvdcve-2.0-{ano}.json.zip" for ano in anos]
            log(f"Total no NVD: {len(nvd)}")

        if args.fonte == "ambas":
            resumo["comparacao"] = gerar_comparacao(destino, anos, oficial, nvd)
            resumo["arquivos"]["comparacao_csv"] = f"comparacao_fontes_{anos_tag_name(anos)}.csv"
            log("Comparação entre fontes concluída")

        if args.somente_web:
            # Preferir NVD (tem CPE) e complementar com oficial.
            merged = list(nvd) + list(oficial)
            web_list = emitir_web_cves(destino, merged)
            resumo["web"] = {
                "total": len(web_list),
                "filter_version": WEB_FILTER_VERSION,
                "por_severidade": contar(
                    [{"severidade": r.get("sev") or "SEM_VALOR"} for r in web_list],
                    "severidade",
                ),
            }
            resumo["arquivos"]["web_jsonl"] = "web-cves.jsonl"

        resumo_path = destino / f"resumo_{anos_tag_name(anos)}.json"
        resumo_path.write_text(json.dumps(resumo, ensure_ascii=False, indent=2), encoding="utf-8")
        log(f"Concluído. Resumo: {resumo_path}")
        return 0
    except KeyboardInterrupt:
        print("\nOperação cancelada.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
