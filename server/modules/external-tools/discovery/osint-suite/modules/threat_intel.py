"""
modules/threat_intel.py — Consulta IoC em múltiplos feeds de threat intel
"""

import asyncio
import aiohttp
from core.base import BaseModule


class ThreatIntelAggregator(BaseModule):
    name        = "ThreatIntelAggregator"
    description = "Consulta IP/domínio/hash em VirusTotal, AbuseIPDB, OTX, Shodan"

    def run(self, target: str) -> dict:
        self.info(f"Consultando threat intel para: [bold]{target}[/bold]")
        ioc_type = self._detect_type(target)
        self.log(f"Tipo detectado: {ioc_type}")

        results = {
            "target":   target,
            "ioc_type": ioc_type,
        }

        if self.config.get("virustotal_key"):
            results["virustotal"] = self._virustotal(target, ioc_type)

        if self.config.get("abuseipdb_key") and ioc_type == "ip":
            results["abuseipdb"] = self._abuseipdb(target)

        if self.config.get("otx_api_key"):
            results["otx"] = self._otx(target, ioc_type)

        if self.config.get("shodan_api_key") and ioc_type in ("ip", "domain"):
            results["shodan"] = self._shodan(target, ioc_type)

        # Sempre consulta ThreatFox (sem key)
        results["threatfox"] = self._threatfox(target)

        # Score de risco agregado
        results["risk_score"] = self._calc_risk(results)

        self.success(f"Risk score: {results['risk_score']}/100")
        return results

    # ------------------------------------------------------------------
    def _detect_type(self, target: str) -> str:
        import re
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return "ip"
        if re.match(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", target, re.I):
            return "hash"
        if re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", target):
            return "domain"
        return "unknown"

    def _virustotal(self, target: str, ioc_type: str) -> dict:
        endpoints = {
            "ip":     f"https://www.virustotal.com/api/v3/ip_addresses/{target}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{target}",
            "hash":   f"https://www.virustotal.com/api/v3/files/{target}",
        }
        url  = endpoints.get(ioc_type)
        if not url:
            return {}
        resp = self.get(url, headers={"x-apikey": self.config["virustotal_key"]})
        if resp:
            try:
                stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "malicious":  stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless":   stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                }
            except Exception:
                pass
        return {}

    def _abuseipdb(self, ip: str) -> dict:
        url  = "https://api.abuseipdb.com/api/v2/check"
        resp = self.get(url, params={"ipAddress": ip, "maxAgeInDays": 90},
                        headers={"Key": self.config["abuseipdb_key"], "Accept": "application/json"})
        if resp:
            try:
                d = resp.json().get("data", {})
                return {
                    "abuse_confidence": d.get("abuseConfidenceScore"),
                    "total_reports":    d.get("totalReports"),
                    "country":          d.get("countryCode"),
                    "isp":              d.get("isp"),
                    "is_tor":           d.get("isTor"),
                }
            except Exception:
                pass
        return {}

    def _otx(self, target: str, ioc_type: str) -> dict:
        section_map = {"ip": "general", "domain": "general", "hash": "general"}
        url  = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{target}/general"
        resp = self.get(url, headers={"X-OTX-API-KEY": self.config["otx_api_key"]})
        if resp:
            try:
                d = resp.json()
                return {
                    "pulse_count": d.get("pulse_info", {}).get("count", 0),
                    "reputation":  d.get("reputation", 0),
                    "country":     d.get("country_name"),
                }
            except Exception:
                pass
        return {}

    def _shodan(self, target: str, ioc_type: str) -> dict:
        key = self.config["shodan_api_key"]
        if ioc_type == "ip":
            url = f"https://api.shodan.io/shodan/host/{target}?key={key}"
        else:
            url = f"https://api.shodan.io/dns/resolve?hostnames={target}&key={key}"
        resp = self.get(url)
        if resp:
            try:
                d = resp.json()
                if ioc_type == "ip":
                    return {
                        "ports":   d.get("ports", []),
                        "os":      d.get("os"),
                        "org":     d.get("org"),
                        "country": d.get("country_name"),
                        "vulns":   list(d.get("vulns", {}).keys())[:10],
                    }
                return d
            except Exception:
                pass
        return {}

    def _threatfox(self, target: str) -> dict:
        url  = "https://threatfox-api.abuse.ch/api/v1/"
        body = {"query": "search_ioc", "search_term": target}
        resp = self.post(url, json=body)
        if resp:
            try:
                d = resp.json()
                if d.get("query_status") == "ok":
                    iocs = d.get("data", [])
                    return {
                        "found":     True,
                        "count":     len(iocs),
                        "malware":   [i.get("malware") for i in iocs[:5]],
                        "threat_type": iocs[0].get("threat_type") if iocs else None,
                    }
            except Exception:
                pass
        return {"found": False}

    def _calc_risk(self, results: dict) -> int:
        score = 0
        vt = results.get("virustotal", {})
        if vt.get("malicious", 0) > 5:    score += 40
        elif vt.get("malicious", 0) > 0:  score += 20
        if vt.get("suspicious", 0) > 3:   score += 10

        ab = results.get("abuseipdb", {})
        score += min(ab.get("abuse_confidence", 0) // 3, 30)

        otx = results.get("otx", {})
        if otx.get("pulse_count", 0) > 10: score += 20
        elif otx.get("pulse_count", 0) > 0: score += 10

        if results.get("threatfox", {}).get("found"): score += 15

        return min(score, 100)
