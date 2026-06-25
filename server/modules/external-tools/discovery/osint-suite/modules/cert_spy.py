"""
modules/cert_spy.py — Extrai subdomínios via Certificate Transparency logs
"""

import re
import dns.resolver
from core.base import BaseModule


class CertSpy(BaseModule):
    name        = "CertSpy"
    description = "Subdomínios via Certificate Transparency (crt.sh, Censys)"

    def run(self, target: str) -> dict:
        self.info(f"Consultando CT logs para: [bold]{target}[/bold]")

        subdomains = set()
        subdomains |= self._crtsh(target)
        subdomains |= self._certspotter(target)

        if self.config.get("censys_api_id"):
            subdomains |= self._censys(target)

        # Remove wildcards e o próprio domínio raiz
        subdomains = {s.lstrip("*.").lower() for s in subdomains if s}
        subdomains = {s for s in subdomains if s.endswith(target) and s != target}

        # Resolve DNS de cada subdomínio
        resolved = self._resolve_all(subdomains)

        self.success(f"{len(subdomains)} subdomínios encontrados, {len(resolved)} resolvidos")

        return {
            "target":     target,
            "subdomains": sorted(subdomains),
            "resolved":   resolved,
            "count":      len(subdomains),
        }

    def _crtsh(self, domain: str) -> set:
        url  = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = self.get(url)
        subs = set()
        if resp:
            try:
                for entry in resp.json():
                    for name in entry.get("name_value", "").split("\n"):
                        subs.add(name.strip())
            except Exception:
                pass
        self.log(f"crt.sh: {len(subs)} entradas")
        return subs

    def _certspotter(self, domain: str) -> set:
        url  = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        resp = self.get(url)
        subs = set()
        if resp:
            try:
                for entry in resp.json():
                    for name in entry.get("dns_names", []):
                        subs.add(name)
            except Exception:
                pass
        self.log(f"CertSpotter: {len(subs)} entradas")
        return subs

    def _censys(self, domain: str) -> set:
        url    = "https://search.censys.io/api/v2/certificates/search"
        params = {"q": f"parsed.names: {domain}", "per_page": 100}
        auth   = (self.config["censys_api_id"], self.config["censys_api_secret"])
        resp   = self.get(url, params=params, auth=auth)
        subs   = set()
        if resp:
            try:
                for hit in resp.json().get("result", {}).get("hits", []):
                    for name in hit.get("parsed", {}).get("names", []):
                        subs.add(name)
            except Exception:
                pass
        self.log(f"Censys: {len(subs)} entradas")
        return subs

    def _resolve_all(self, subdomains: set) -> list:
        resolved = []
        for sub in sorted(subdomains)[:200]:
            try:
                answers = dns.resolver.resolve(sub, "A", lifetime=3)
                ips = [str(r) for r in answers]
                resolved.append({"subdomain": sub, "ips": ips})
            except Exception:
                pass
        return resolved
