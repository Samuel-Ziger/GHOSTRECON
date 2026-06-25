"""
modules/brand_watcher.py — Monitora menções de marca em fontes abertas
"""

import sqlite3
from datetime import datetime
from pathlib import Path
from core.base import BaseModule


class BrandWatcher(BaseModule):
    name        = "BrandWatcher"
    description = "Monitora menções de marca em Pastebin, Reddit, GitHub Gists, RSS"

    def run(self, target: str) -> dict:
        self.info(f"Monitorando marca: [bold]{target}[/bold]")
        results = []
        results += self._search_reddit(target)
        results += self._search_github_gists(target)
        results += self._search_pastebin(target)
        results += self._search_rss(target)

        db_path = Path(self.config.get("output_dir", "reports/")) / "brand_monitor.db"
        self._save_db(db_path, target, results)

        if self.config.get("telegram_bot_token") and results:
            self._send_telegram_alert(target, results)

        self.success(f"{len(results)} menções encontradas")
        return {"target": target, "results": results, "count": len(results),
                "timestamp": datetime.utcnow().isoformat()}

    def _search_reddit(self, query: str) -> list:
        url  = f"https://www.reddit.com/search.json?q={query}&sort=new&limit=10"
        resp = self.get(url, headers={"User-Agent": "OSINT-Suite/1.0"})
        out  = []
        if resp:
            try:
                for post in resp.json().get("data", {}).get("children", []):
                    d = post.get("data", {})
                    out.append({"source": "Reddit", "title": d.get("title"),
                                "url": f"https://reddit.com{d.get('permalink')}",
                                "ts": datetime.utcfromtimestamp(d.get("created_utc", 0)).isoformat()})
            except Exception:
                pass
        return out

    def _search_github_gists(self, query: str) -> list:
        url  = f"https://api.github.com/gists/public?per_page=30"
        resp = self.get(url)
        out  = []
        if resp:
            try:
                for gist in resp.json():
                    desc = gist.get("description", "") or ""
                    if query.lower() in desc.lower():
                        out.append({"source": "GitHub Gist", "title": desc[:80],
                                    "url": gist.get("html_url"), "ts": gist.get("created_at")})
            except Exception:
                pass
        return out

    def _search_pastebin(self, query: str) -> list:
        url  = f"https://psbdmp.ws/api/search/{query}"
        resp = self.get(url)
        out  = []
        if resp:
            try:
                for item in resp.json().get("data", [])[:5]:
                    out.append({"source": "Pastebin", "title": item.get("id"),
                                "url": f"https://pastebin.com/{item.get('id')}",
                                "ts": item.get("time")})
            except Exception:
                pass
        return out

    def _search_rss(self, query: str) -> list:
        import xml.etree.ElementTree as ET
        url  = f"https://news.google.com/rss/search?q={query}&hl=pt-BR&gl=BR&ceid=BR:pt-419"
        resp = self.get(url)
        out  = []
        if resp:
            try:
                root = ET.fromstring(resp.text)
                for item in root.findall(".//item")[:5]:
                    title = item.findtext("title", "")
                    link  = item.findtext("link", "")
                    pubdate = item.findtext("pubDate", "")
                    out.append({"source": "Google News", "title": title,
                                "url": link, "ts": pubdate})
            except Exception:
                pass
        return out

    def _send_telegram_alert(self, brand: str, results: list):
        token   = self.config["telegram_bot_token"]
        chat_id = self.config.get("telegram_chat_id", "")
        if not chat_id:
            return
        msg = f"🔔 *BrandWatcher Alert*\nMarca: `{brand}`\n{len(results)} novas menções\n\n"
        for r in results[:3]:
            msg += f"• [{r['source']}] {r['title'][:60]}\n{r['url']}\n\n"
        self.post(f"https://api.telegram.org/bot{token}/sendMessage",
                  json={"chat_id": chat_id, "text": msg, "parse_mode": "Markdown"})

    def _save_db(self, db_path: Path, target: str, results: list):
        conn = sqlite3.connect(db_path)
        conn.execute("""CREATE TABLE IF NOT EXISTS mentions
            (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, source TEXT,
             title TEXT, url TEXT, ts TEXT)""")
        for r in results:
            conn.execute("INSERT INTO mentions (target,source,title,url,ts) VALUES (?,?,?,?,?)",
                         (target, r["source"], r.get("title",""), r.get("url",""), r.get("ts","")))
        conn.commit()
        conn.close()
