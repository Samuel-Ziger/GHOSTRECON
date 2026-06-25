"""
modules/wigle_mapper.py — Localiza redes Wi-Fi por SSID/BSSID via WiGLE API
"""

from core.base import BaseModule


class WiGLEMapper(BaseModule):
    name        = "WiGLEMapper"
    description = "Localiza redes Wi-Fi por SSID/BSSID via WiGLE"

    BASE = "https://api.wigle.net/api/v2"

    def run(self, target: str) -> dict:
        self.info(f"Buscando rede Wi-Fi: [bold]{target}[/bold]")

        if not self.config.get("wigle_api_name"):
            self.warn("wigle_api_name/token não configurados — resultado vazio")
            return {"error": "WiGLE API key não configurada"}

        auth = (self.config["wigle_api_name"], self.config["wigle_api_token"])

        # Detecta se é BSSID (MAC) ou SSID
        is_bssid = ":" in target or "-" in target

        params = {
            "netid" if is_bssid else "ssid": target,
            "resultsPerPage": 50,
        }

        resp = self.get(f"{self.BASE}/network/search", params=params, auth=auth)
        networks = []
        if resp:
            try:
                data = resp.json()
                for net in data.get("results", []):
                    networks.append({
                        "ssid":      net.get("ssid"),
                        "bssid":     net.get("netid"),
                        "lat":       net.get("trilat"),
                        "lon":       net.get("trilong"),
                        "country":   net.get("country"),
                        "city":      net.get("city"),
                        "encryption":net.get("encryption"),
                        "last_seen": net.get("lastupdt"),
                        "first_seen":net.get("firsttime"),
                    })
            except Exception as e:
                return {"error": str(e)}

        # Gera mapa de calor
        if networks:
            self._generate_heatmap(networks)

        self.success(f"{len(networks)} redes encontradas")
        return {
            "target":   target,
            "type":     "bssid" if is_bssid else "ssid",
            "networks": networks,
            "count":    len(networks),
        }

    def _generate_heatmap(self, networks: list):
        try:
            import folium
            from folium.plugins import HeatMap
            coords = [[n["lat"], n["lon"]] for n in networks if n.get("lat") and n.get("lon")]
            if not coords:
                return
            center = [sum(c[0] for c in coords)/len(coords), sum(c[1] for c in coords)/len(coords)]
            m = folium.Map(location=center, zoom_start=12)
            HeatMap(coords).add_to(m)
            for n in networks[:50]:
                if n.get("lat"):
                    folium.CircleMarker(
                        [n["lat"], n["lon"]],
                        radius=5,
                        popup=f"{n['ssid']} ({n['bssid']})",
                        color="blue",
                    ).add_to(m)
            from pathlib import Path
            out = Path(self.config.get("output_dir","reports/")) / "wigle_map.html"
            m.save(str(out))
            self.success(f"Mapa salvo: {out}")
        except ImportError:
            self.warn("folium não instalado — mapa não gerado")


# ──────────────────────────────────────────────────────────────────────────────

"""
modules/phone_osint.py — Inteligência sobre números de telefone
"""


class PhoneOSINT(BaseModule):
    name        = "PhoneOSINT"
    description = "Inteligência sobre números de telefone (operadora, país, geoloc)"

    def run(self, target: str) -> dict:
        self.info(f"Analisando número: [bold]{target}[/bold]")

        basic  = self._phonenumbers_analysis(target)
        numverify = self._numverify(target)
        anatel = self._anatel_prefix(target)
        sources = self._search_open_sources(target)

        return {
            "target":   target,
            "basic":    basic,
            "numverify":numverify,
            "anatel":   anatel,
            "sources":  sources,
        }

    def _phonenumbers_analysis(self, number: str) -> dict:
        try:
            import phonenumbers
            from phonenumbers import geocoder, carrier, timezone

            # Tenta parse com e sem código do Brasil
            for region in (None, "BR"):
                try:
                    p = phonenumbers.parse(number, region)
                    if phonenumbers.is_valid_number(p):
                        break
                except Exception:
                    continue
            else:
                return {"error": "Número inválido"}

            return {
                "valid":         phonenumbers.is_valid_number(p),
                "possible":      phonenumbers.is_possible_number(p),
                "e164":          phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.E164),
                "international": phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "national":      phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.NATIONAL),
                "country_code":  p.country_code,
                "country":       geocoder.description_for_number(p, "pt"),
                "carrier":       carrier.name_for_number(p, "pt"),
                "line_type":     str(phonenumbers.number_type(p)),
                "timezones":     list(timezone.time_zones_for_number(p)),
            }
        except ImportError:
            return {"error": "phonenumbers não instalado"}
        except Exception as e:
            return {"error": str(e)}

    def _numverify(self, number: str) -> dict:
        """NumVerify tem tier gratuito."""
        clean = "".join(c for c in number if c.isdigit() or c == "+")
        url   = f"http://apilayer.net/api/validate?number={clean}&country_code=BR&format=1"
        resp  = self.get(url)
        if resp:
            try:
                d = resp.json()
                return {
                    "valid":    d.get("valid"),
                    "carrier":  d.get("carrier"),
                    "line_type":d.get("line_type"),
                    "location": d.get("location"),
                    "country":  d.get("country_name"),
                }
            except Exception:
                pass
        return {}

    def _anatel_prefix(self, number: str) -> dict:
        """Lookup de prefixo no banco da Anatel (código de área + prefixo)."""
        digits = "".join(c for c in number if c.isdigit())
        if len(digits) >= 11:
            ddd    = digits[-11:-9]
            prefix = digits[-9:-5]
            url    = f"https://sistemas.anatel.gov.br/areacodigoddd/SConsulta.asp?pnDDD={ddd}"
            resp   = self.get(url)
            return {
                "ddd":    ddd,
                "prefix": prefix,
                "source": "Anatel",
                "url":    url,
            }
        return {}

    def _search_open_sources(self, number: str) -> list:
        """Busca passiva em fontes abertas."""
        from bs4 import BeautifulSoup
        clean = "".join(c for c in number if c.isdigit())
        results = []

        # Quem Me Ligou
        url  = f"https://www.quemeligou.com.br/{clean}"
        resp = self.get(url)
        if resp:
            soup = BeautifulSoup(resp.text, "html.parser")
            title = soup.find("title")
            comments = [c.get_text(strip=True)[:100] for c in soup.select(".comment-body")[:3]]
            results.append({
                "source":   "Quem Me Ligou",
                "url":      url,
                "title":    title.get_text(strip=True) if title else "",
                "comments": comments,
            })

        return results
