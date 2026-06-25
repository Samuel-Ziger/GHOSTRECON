"""
modules/phone_osint.py — Inteligência sobre números de telefone
"""

from core.base import BaseModule


class PhoneOSINT(BaseModule):
    name        = "PhoneOSINT"
    description = "Inteligência sobre números de telefone (operadora, país, geoloc)"

    def run(self, target: str) -> dict:
        self.info(f"Analisando número: [bold]{target}[/bold]")
        basic    = self._phonenumbers_analysis(target)
        anatel   = self._anatel_prefix(target)
        sources  = self._search_open_sources(target)
        return {"target": target, "basic": basic, "anatel": anatel, "sources": sources}

    def _phonenumbers_analysis(self, number: str) -> dict:
        try:
            import phonenumbers
            from phonenumbers import geocoder, carrier, timezone
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
            return {"error": "phonenumbers não instalado — pip install phonenumbers"}
        except Exception as e:
            return {"error": str(e)}

    def _anatel_prefix(self, number: str) -> dict:
        digits = "".join(c for c in number if c.isdigit())
        if len(digits) >= 11:
            ddd = digits[-11:-9]
            return {"ddd": ddd, "source": "Anatel",
                    "url": f"https://sistemas.anatel.gov.br/areacodigoddd/SConsulta.asp?pnDDD={ddd}"}
        return {}

    def _search_open_sources(self, number: str) -> list:
        from bs4 import BeautifulSoup
        clean   = "".join(c for c in number if c.isdigit())
        results = []
        url     = f"https://www.quemeligou.com.br/{clean}"
        resp    = self.get(url)
        if resp:
            soup     = BeautifulSoup(resp.text, "html.parser")
            comments = [c.get_text(strip=True)[:100] for c in soup.select(".comment-body")[:3]]
            results.append({"source": "QuemMeLigou", "url": url, "comments": comments})
        return results
