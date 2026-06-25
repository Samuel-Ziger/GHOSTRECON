"""
modules/email_harvester.py — Coleta e valida emails de um domínio
"""

import re
import dns.resolver
from urllib.parse import quote_plus
from core.base import BaseModule

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

GOOGLE_DORK_URLS = [
    "https://www.google.com/search?q=site:{d}+%22@{d}%22&num=100",
    "https://www.google.com/search?q=%22@{d}%22+filetype:pdf&num=50",
    "https://www.google.com/search?q=%22@{d}%22+filetype:xlsx+OR+filetype:csv&num=50",
]

BING_DORK_URL = "https://www.bing.com/search?q=site:{d}+%22@{d}%22&count=50"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    )
}


class EmailHarvester(BaseModule):
    name        = "EmailHarvester"
    description = "Coleta emails de um domínio via fontes passivas"

    def run(self, target: str) -> dict:
        domain = target.lower().strip()
        self.info(f"Coletando emails para: [bold]{domain}[/bold]")

        emails = set()

        # 1. Google Dorks (passivo, sem autenticação)
        emails |= self._google_dorks(domain)

        # 2. Bing
        emails |= self._bing_search(domain)

        # 3. crt.sh emails em certificados
        emails |= self._crtsh_emails(domain)

        # 4. Hunter.io (sem key retorna poucos resultados mas funciona)
        emails |= self._hunter_io(domain)

        # Filtra apenas emails do domínio alvo
        emails = {e for e in emails if domain in e.lower()}

        # 5. Valida MX records
        mx_records = self._check_mx(domain)

        # 6. Verifica HIBP para cada email (com delay)
        hibp_results = {}
        hibp_key = self.config.get("hibp_api_key", "")
        if hibp_key:
            for email in list(emails)[:20]:  # limita a 20 por rate-limit
                hibp_results[email] = self._check_hibp(email, hibp_key)

        self.success(f"{len(emails)} emails coletados")

        return {
            "target":       domain,
            "emails":       sorted(emails),
            "mx_records":   mx_records,
            "hibp_results": hibp_results,
            "count":        len(emails),
        }

    def _google_dorks(self, domain: str) -> set:
        emails = set()
        for url_tpl in GOOGLE_DORK_URLS:
            url  = url_tpl.format(d=domain)
            resp = self.get(url, headers=HEADERS)
            if resp:
                emails |= set(EMAIL_RE.findall(resp.text))
        self.log(f"Google Dorks: {len(emails)} emails")
        return emails

    def _bing_search(self, domain: str) -> set:
        url  = BING_DORK_URL.format(d=domain)
        resp = self.get(url, headers=HEADERS)
        emails = set(EMAIL_RE.findall(resp.text)) if resp else set()
        self.log(f"Bing: {len(emails)} emails")
        return emails

    def _crtsh_emails(self, domain: str) -> set:
        """Extrai emails de Subject Alternative Names em certificados."""
        url  = f"https://crt.sh/?q=%25@{domain}&output=json"
        resp = self.get(url)
        emails = set()
        if resp:
            try:
                for entry in resp.json():
                    name = entry.get("name_value", "")
                    emails |= set(EMAIL_RE.findall(name))
            except Exception:
                pass
        self.log(f"crt.sh: {len(emails)} emails")
        return emails

    def _hunter_io(self, domain: str) -> set:
        """Hunter.io público (sem key) — retorna amostra."""
        url  = f"https://hunter.io/try/v2/domain-search?domain={domain}&limit=10"
        resp = self.get(url)
        emails = set()
        if resp:
            try:
                data = resp.json()
                for item in data.get("data", {}).get("emails", []):
                    if "value" in item:
                        emails.add(item["value"])
            except Exception:
                pass
        self.log(f"Hunter.io: {len(emails)} emails")
        return emails

    def _check_mx(self, domain: str) -> list:
        try:
            answers = dns.resolver.resolve(domain, "MX")
            records = [str(r.exchange).rstrip(".") for r in answers]
            self.log(f"MX records: {records}")
            return records
        except Exception:
            return []

    def _check_hibp(self, email: str, api_key: str) -> dict:
        url  = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote_plus(email)}"
        resp = self.get(url, headers={
            "hibp-api-key": api_key,
            "User-Agent":   "OSINT-Suite/1.0",
        })
        if resp and resp.status_code == 200:
            try:
                breaches = [b.get("Name") for b in resp.json()]
                return {"breached": True, "breaches": breaches}
            except Exception:
                pass
        return {"breached": False, "breaches": []}
