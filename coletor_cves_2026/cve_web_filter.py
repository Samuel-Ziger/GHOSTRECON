#!/usr/bin/env python3
"""
Critério "somente web" para CVEs.

Uma CVE é considerada web quando passa em ao menos um sinal forte
(CPE de aplicação, CWE web ou palavra-chave web) e não é descartada
por exclusões explícitas (kernel, driver, firmware, etc.).
"""

from __future__ import annotations

import re
from typing import Any

WEB_FILTER_VERSION = "1"

# CWEs típicos de aplicações web / APIs HTTP.
WEB_CWES = frozenset({
    "CWE-22", "CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-95",
    "CWE-98", "CWE-287", "CWE-306", "CWE-352", "CWE-434", "CWE-502",
    "CWE-601", "CWE-611", "CWE-862", "CWE-863", "CWE-918", "CWE-1336",
})

WEB_KEYWORDS = (
    "http", "https", "web", "wordpress", "joomla", "drupal", "cms", "plugin",
    "apache", "nginx", "tomcat", "iis", "php", "laravel", "django", "express",
    "spring", "struts", "jenkins", "gitlab", "confluence", "graphql",
    "rest api", "restapi", "servlet", "jsp", "asp.net", "rails", "next.js",
    "nuxt", "magento", "shopify", "vbulletin", "mediawiki", "moodle",
)

NON_WEB_EXCLUSIONS = (
    "linux kernel", "windows kernel", "android kernel", "driver", "firmware",
    "bluetooth", "wifi", "wi-fi", "bios", "uefi", "hypervisor", "qemu",
    "virtualbox", "vmware esxi", "router firmware", "iot firmware",
)

_CPE_RE = re.compile(
    r"^cpe:2\.3:(?P<part>[aho]):(?P<vendor>[^:]+):(?P<product>[^:]+)"
    r":(?P<version>[^:]*)(?::.*)?$",
    re.IGNORECASE,
)


def _norm(text: Any) -> str:
    return str(text or "").strip().lower()


def parse_cpe(cpe: str) -> dict[str, str] | None:
    m = _CPE_RE.match(str(cpe or "").strip())
    if not m:
        return None
    return {
        "part": m.group("part").lower(),
        "vendor": m.group("vendor").replace("\\_", "_").replace("\\-", "-").lower(),
        "product": m.group("product").replace("\\_", "_").replace("\\-", "-").lower(),
        "version": m.group("version").replace("\\_", "_").replace("\\-", "-"),
        "cpe": str(cpe).strip(),
    }


def extract_cwes(value: Any) -> list[str]:
    raw = value if isinstance(value, (list, tuple, set)) else str(value or "").split("|")
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        s = str(item or "").strip().upper()
        if not s:
            continue
        m = re.search(r"CWE-(\d+)", s)
        if m:
            s = f"CWE-{m.group(1)}"
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def has_application_cpe(cpes: Any) -> bool:
    items = cpes if isinstance(cpes, (list, tuple)) else str(cpes or "").split("|")
    for item in items:
        parsed = parse_cpe(str(item))
        if parsed and parsed["part"] == "a":
            return True
    return False


def has_web_cwe(cwes: Any) -> bool:
    return any(cwe in WEB_CWES for cwe in extract_cwes(cwes))


def has_web_keyword(*texts: Any) -> bool:
    blob = " ".join(_norm(t) for t in texts if t)
    if not blob:
        return False
    return any(k in blob for k in WEB_KEYWORDS)


def is_explicitly_non_web(*texts: Any) -> bool:
    blob = " ".join(_norm(t) for t in texts if t)
    if not blob:
        return False
    # Exclusão só vale quando não há sinal HTTP/web explícito.
    if has_web_keyword(blob):
        return False
    return any(x in blob for x in NON_WEB_EXCLUSIONS)


def is_web_cve(
    *,
    cpes: Any = "",
    cwes: Any = "",
    vendors: Any = "",
    products: Any = "",
    description: Any = "",
) -> bool:
    """Retorna True se a CVE deve entrar no dataset web curado."""
    texts = (vendors, products, description)
    if is_explicitly_non_web(*texts):
        return False
    if has_application_cpe(cpes):
        return True
    if has_web_cwe(cwes) and has_web_keyword(*texts):
        return True
    if has_web_keyword(*texts) and (has_web_cwe(cwes) or bool(_norm(products))):
        return True
    return False


def normalize_affected_from_cpes(cpes: Any) -> list[dict[str, str]]:
    items = cpes if isinstance(cpes, (list, tuple)) else str(cpes or "").split("|")
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in items:
        parsed = parse_cpe(str(item))
        if not parsed or parsed["part"] != "a":
            continue
        version = parsed["version"]
        if version in {"*", "-", ""}:
            version = ""
        key = (parsed["vendor"], parsed["product"], parsed["cpe"])
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "vendor": parsed["vendor"],
            "product": parsed["product"],
            "cpe": parsed["cpe"],
            "introduced": version if version and version not in {"*", "-"} else "",
            "fixed": "",
        })
    return out


def to_web_record(registro: dict[str, Any]) -> dict[str, Any] | None:
    """Converte registro achatado (CSV/JSONL do coletor) em schema web-cves.jsonl."""
    if not isinstance(registro, dict):
        return None
    cve_id = str(registro.get("cve_id") or registro.get("id") or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return None

    cpes = registro.get("cpes") or ""
    cwes = registro.get("cwes") or ""
    vendors = registro.get("fornecedores") or registro.get("vendors") or ""
    products = registro.get("produtos") or registro.get("products") or ""
    description = registro.get("descricao") or registro.get("desc") or ""

    if not is_web_cve(
        cpes=cpes,
        cwes=cwes,
        vendors=vendors,
        products=products,
        description=description,
    ):
        return None

    score_raw = registro.get("cvss_score") or registro.get("cvss") or ""
    try:
        cvss = float(score_raw) if str(score_raw).strip() else None
    except (TypeError, ValueError):
        cvss = None

    kev_raw = str(registro.get("cisa_kev") or registro.get("kev") or "").strip().upper()
    kev = kev_raw in {"SIM", "YES", "TRUE", "1"}

    refs = registro.get("referencias") or registro.get("refs") or ""
    if isinstance(refs, str):
        ref_list = [r.strip() for r in refs.split("|") if r.strip()]
    elif isinstance(refs, list):
        ref_list = [str(r).strip() for r in refs if str(r).strip()]
    else:
        ref_list = []

    affected = normalize_affected_from_cpes(cpes)
    if not affected:
        # Sem CPE: ainda assim registra produto textual se houver.
        for product in str(products).split("|"):
            product = product.strip().lower()
            if not product or product in {"*", "-"}:
                continue
            vendor = str(vendors).split("|")[0].strip().lower() if vendors else ""
            affected.append({
                "vendor": vendor,
                "product": product.replace(" ", "_"),
                "cpe": "",
                "introduced": "",
                "fixed": "",
            })

    return {
        "id": cve_id,
        "cvss": cvss,
        "sev": str(registro.get("severidade") or registro.get("sev") or "").upper() or None,
        "cwes": extract_cwes(cwes),
        "kev": kev,
        "desc": str(description or "")[:2000],
        "refs": ref_list[:20],
        "affected": affected,
        "updated_at": str(registro.get("atualizada_em") or registro.get("updated_at") or ""),
        "filter_version": WEB_FILTER_VERSION,
    }
