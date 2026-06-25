"""
modules/geo_osint.py — Extrai metadados EXIF e geolocalização de imagens
"""

import json
from pathlib import Path
from core.base import BaseModule


class GeoOSINT(BaseModule):
    name        = "GeoOSINT"
    description = "Extrai coordenadas GPS de metadados EXIF de imagens"

    def run(self, target: str) -> dict:
        self.info(f"Extraindo metadados de: [bold]{target}[/bold]")

        path = Path(target)
        if not path.exists():
            return {"error": f"Arquivo não encontrado: {target}"}

        exif    = self._extract_exif(path)
        coords  = self._get_coords(exif)
        address = self._reverse_geocode(coords) if coords else None

        result = {
            "file":    str(path),
            "exif":    exif,
            "coords":  coords,
            "address": address,
        }

        if coords:
            result["map_url"] = (
                f"https://www.openstreetmap.org/?mlat={coords['lat']}"
                f"&mlon={coords['lon']}&zoom=15"
            )
            self.success(f"GPS: {coords['lat']}, {coords['lon']}")
            self._generate_map(coords, str(path), address)
        else:
            self.warn("Nenhuma coordenada GPS encontrada nos metadados")

        return result

    def _extract_exif(self, path: Path) -> dict:
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS
            img  = Image.open(path)
            raw  = img._getexif() or {}
            exif = {}
            for tag_id, value in raw.items():
                tag = TAGS.get(tag_id, tag_id)
                if tag == "GPSInfo":
                    gps = {}
                    for k, v in value.items():
                        gps[GPSTAGS.get(k, k)] = str(v)
                    exif["GPSInfo"] = gps
                elif isinstance(value, (str, int, float)):
                    exif[str(tag)] = value
            return exif
        except Exception as e:
            return {"error": str(e)}

    def _get_coords(self, exif: dict):
        gps = exif.get("GPSInfo", {})
        if not gps:
            return None
        try:
            def dms_to_dd(dms_str, ref):
                # Parse "(deg, min, sec)" format from str
                import re
                nums = [float(x) for x in re.findall(r"[\d.]+", dms_str)]
                dd = nums[0] + nums[1]/60 + nums[2]/3600
                if ref in ("S", "W"):
                    dd = -dd
                return round(dd, 7)

            lat = dms_to_dd(gps.get("GPSLatitude",""),  gps.get("GPSLatitudeRef","N"))
            lon = dms_to_dd(gps.get("GPSLongitude",""), gps.get("GPSLongitudeRef","E"))
            alt = gps.get("GPSAltitude", None)
            return {"lat": lat, "lon": lon, "alt": alt}
        except Exception:
            return None

    def _reverse_geocode(self, coords: dict) -> dict:
        url  = (
            f"https://nominatim.openstreetmap.org/reverse"
            f"?lat={coords['lat']}&lon={coords['lon']}&format=json"
        )
        resp = self.get(url, headers={"Accept-Language": "pt-BR"})
        if resp:
            try:
                d = resp.json()
                return {
                    "display_name": d.get("display_name"),
                    "city":         d.get("address", {}).get("city"),
                    "state":        d.get("address", {}).get("state"),
                    "country":      d.get("address", {}).get("country"),
                    "postcode":     d.get("address", {}).get("postcode"),
                }
            except Exception:
                pass
        return {}

    def _generate_map(self, coords: dict, title: str, address: dict):
        try:
            import folium
            m = folium.Map(location=[coords["lat"], coords["lon"]], zoom_start=15)
            popup_text = f"<b>{title}</b><br>{address.get('display_name','') if address else ''}"
            folium.Marker(
                [coords["lat"], coords["lon"]],
                popup=popup_text,
                icon=folium.Icon(color="red", icon="camera"),
            ).add_to(m)
            out = Path(self.config.get("output_dir","reports/")) / "geo_map.html"
            m.save(str(out))
            self.success(f"Mapa salvo: {out}")
        except ImportError:
            self.warn("folium não instalado — mapa não gerado")
