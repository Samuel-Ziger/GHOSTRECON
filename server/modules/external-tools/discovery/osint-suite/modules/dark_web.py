"""
modules/dark_web.py — Monitoramento passivo de menções em fóruns .onion via Tor
"""

import sqlite3
from datetime import datetime
from pathlib import Path
from core.base import BaseModule


class DarkWebMonitor(BaseModule):
    name        = "DarkWebMonitor"
    description = "Monitora menções em fontes .onion via Tor (requer --tor)"

    # Sites .onion indexados publicamente (via Ahmia — clearnet proxy)
    AHMIA_URL = "https://ahmia.fi/search/?q={q}"

    def run(self, target: str) -> dict:
        self.info(f"Buscando menções a [bold]{target}[/bold] na dark web")

        results = []

        # Ahmia é um mecanismo de busca .onion com proxy clearnet
        results += self._search_ahmia(target)

        # Salva em SQLite local
        db_path = Path(self.config.get("output_dir", "reports/")) / "darkweb_monitor.db"
        self._save_db(db_path, target, results)

        self.success(f"{len(results)} menções encontradas")

        return {
            "target":    target,
            "results":   results,
            "count":     len(results),
            "db_path":   str(db_path),
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _search_ahmia(self, query: str) -> list:
        from bs4 import BeautifulSoup
        url  = self.AHMIA_URL.format(q=query)
        resp = self.get(url)
        results = []
        if resp:
            soup = BeautifulSoup(resp.text, "html.parser")
            for item in soup.select("li.result")[:10]:
                title = item.select_one("h4")
                desc  = item.select_one("p")
                link  = item.select_one("a")
                if title:
                    results.append({
                        "source":  "Ahmia",
                        "title":   title.get_text(strip=True),
                        "excerpt": desc.get_text(strip=True)[:200] if desc else "",
                        "url":     link["href"] if link else "",
                        "ts":      datetime.utcnow().isoformat(),
                    })
        return results

    def _save_db(self, db_path: Path, target: str, results: list):
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mentions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT, source TEXT, title TEXT,
                excerpt TEXT, url TEXT, ts TEXT
            )
        """)
        for r in results:
            conn.execute(
                "INSERT INTO mentions (target,source,title,excerpt,url,ts) VALUES (?,?,?,?,?,?)",
                (target, r["source"], r["title"], r["excerpt"], r["url"], r["ts"])
            )
        conn.commit()
        conn.close()
