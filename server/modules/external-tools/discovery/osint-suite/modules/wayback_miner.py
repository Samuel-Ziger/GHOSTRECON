"""
modules/wayback_miner.py — Extrai URLs históricas do Wayback Machine e Common Crawl
"""

import re
from urllib.parse import urlparse, parse_qs
from core.base import BaseModule

INTERESTING_EXTENSIONS = [
    ".php", ".asp", ".aspx", ".jsp", ".cgi",
    ".env", ".bak", ".sql", ".config", ".cfg", ".ini",
    ".log", ".xml", ".json", ".yaml", ".yml",
    ".zip", ".tar.gz", ".rar",
    ".key", ".pem", ".p12",
]

INTERESTING_PARAMS = [
    "id", "uid", "user", "admin", "debug", "test",
    "token", "key", "secret", "password", "passwd",
    "redirect", "url", "next", "return", "file", "path",
    "cmd", "exec", "query", "search",
]


class WaybackMiner(BaseModule):
    name        = "WaybackMiner"
    description = "Extrai URLs históricas via Wayback Machine e Common Crawl"

    def run(self, target: str) -> dict:
        self.info(f"Minerando histórico de: [bold]{target}[/bold]")

        urls = set()
        urls |= self._wayback_cdx(target)
        urls |= self._common_crawl(target)

        # Categoriza URLs
        categorized = self._categorize(urls)

        # Verifica se URLs antigas ainda estão ativas
        active = self._check_active(list(categorized["interesting"])[:20])

        self.success(f"{len(urls)} URLs | {len(categorized['interesting'])} interessantes | {len(active)} ativas")

        return {
            "target":         target,
            "total_urls":     len(urls),
            "categorized":    {k: list(v)[:50] for k, v in categorized.items()},
            "active_old":     active,
        }

    def _wayback_cdx(self, domain: str) -> set:
        url  = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
            f"&limit=5000&filter=statuscode:200"
        )
        resp = self.get(url)
        if resp:
            return set(resp.text.splitlines())
        return set()

    def _common_crawl(self, domain: str) -> set:
        # Usa o índice mais recente do Common Crawl
        url  = f"http://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{domain}/*&output=text&fl=url&limit=1000"
        resp = self.get(url)
        if resp:
            return {line.strip() for line in resp.text.splitlines() if line.strip()}
        return set()

    def _categorize(self, urls: set) -> dict:
        cats = {
            "interesting":  set(),
            "params":       set(),
            "static":       set(),
            "api":          set(),
            "admin":        set(),
            "other":        set(),
        }
        for url in urls:
            url_lower = url.lower()
            parsed    = urlparse(url)
            params    = parse_qs(parsed.query)

            if any(p in url_lower for p in ["/admin", "/panel", "/dashboard", "/manage", "/console"]):
                cats["admin"].add(url)
            elif any(p in url_lower for p in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]):
                cats["api"].add(url)
            elif any(url_lower.endswith(ext) for ext in INTERESTING_EXTENSIONS):
                cats["interesting"].add(url)
            elif params and any(k in INTERESTING_PARAMS for k in params):
                cats["params"].add(url)
                cats["interesting"].add(url)
            elif re.search(r"\.(js|css|png|jpg|gif|ico|woff)$", url_lower):
                cats["static"].add(url)
            else:
                cats["other"].add(url)

        return cats

    def _check_active(self, urls: list) -> list:
        active = []
        for url in urls:
            resp = self.get(url)
            if resp and resp.status_code == 200:
                active.append({"url": url, "status": 200, "size": len(resp.content)})
            elif resp:
                pass  # não ativa
        return active
