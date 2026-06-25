"""
modules/asn_mapper.py — Mapeia ASNs, ranges de IP e peers BGP
"""

import ipaddress
from core.base import BaseModule


class ASNMapper(BaseModule):
    name        = "ASNMapper"
    description = "Mapeia ASNs e blocos IP de uma organização"

    def run(self, target: str) -> dict:
        self.info(f"Mapeando ASN para: [bold]{target}[/bold]")

        # 1. Resolve domínio → IP
        ip = self._resolve_ip(target)

        # 2. Busca ASN do IP via ip-api
        asn_info = self._ip_api(ip) if ip else {}

        # 3. Detalhes do ASN via BGPView
        asn_num  = asn_info.get("asn", "").replace("AS", "").strip()
        bgp_info = self._bgpview_asn(asn_num) if asn_num else {}

        # 4. Prefixes do ASN
        prefixes = self._bgpview_prefixes(asn_num) if asn_num else []

        # 5. Peers
        peers = self._bgpview_peers(asn_num) if asn_num else []

        self.success(f"ASN: {asn_info.get('asn')} | Prefixes: {len(prefixes)}")

        return {
            "target":    target,
            "ip":        ip,
            "asn_info":  asn_info,
            "bgp_info":  bgp_info,
            "prefixes":  prefixes[:30],
            "peers":     peers[:20],
        }

    def _resolve_ip(self, domain: str) -> str | None:
        import socket
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return None

    def _ip_api(self, ip: str) -> dict:
        url  = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,asname,query"
        resp = self.get(url)
        if resp:
            try:
                return resp.json()
            except Exception:
                pass
        return {}

    def _bgpview_asn(self, asn: str) -> dict:
        url  = f"https://api.bgpview.io/asn/{asn}"
        resp = self.get(url)
        if resp:
            try:
                data = resp.json().get("data", {})
                return {
                    "name":          data.get("name"),
                    "description":   data.get("description_short"),
                    "country":       data.get("country_code"),
                    "website":       data.get("website"),
                    "email_contacts":data.get("email_contacts", []),
                    "rir_allocation":data.get("rir_allocation", {}).get("rir_name"),
                }
            except Exception:
                pass
        return {}

    def _bgpview_prefixes(self, asn: str) -> list:
        url  = f"https://api.bgpview.io/asn/{asn}/prefixes"
        resp = self.get(url)
        if resp:
            try:
                data = resp.json().get("data", {})
                return [
                    {"prefix": p.get("prefix"), "name": p.get("name"), "country": p.get("country_code")}
                    for p in data.get("ipv4_prefixes", []) + data.get("ipv6_prefixes", [])
                ]
            except Exception:
                pass
        return []

    def _bgpview_peers(self, asn: str) -> list:
        url  = f"https://api.bgpview.io/asn/{asn}/peers"
        resp = self.get(url)
        if resp:
            try:
                data = resp.json().get("data", {})
                peers = data.get("ipv4_peers", []) + data.get("ipv6_peers", [])
                return [{"asn": p.get("asn"), "name": p.get("name")} for p in peers]
            except Exception:
                pass
        return []
