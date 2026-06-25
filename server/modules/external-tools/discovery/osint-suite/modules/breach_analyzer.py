"""
modules/breach_analyzer.py — Indexa e analisa dumps de credenciais localmente
"""

import re
import sqlite3
from pathlib import Path
from collections import Counter
from core.base import BaseModule

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


class BreachAnalyzer(BaseModule):
    name        = "BreachAnalyzer"
    description = "Indexa dumps de credenciais e busca por domínio"

    # target pode ser: caminho para arquivo dump, ou domínio para buscar no DB
    def run(self, target: str) -> dict:
        db_path = Path(self.config.get("output_dir", "reports/")) / "breaches.db"
        self._init_db(db_path)

        p = Path(target)
        if p.exists() and p.is_file():
            # Modo indexação
            return self._index_file(p, db_path)
        else:
            # Modo busca
            return self._search(target, db_path)

    # ------------------------------------------------------------------
    def _init_db(self, db_path: Path):
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT, password TEXT, domain TEXT,
                source_file TEXT, line_num INTEGER
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_domain ON credentials(domain)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_email  ON credentials(email)")
        conn.commit()
        conn.close()

    def _index_file(self, path: Path, db_path: Path) -> dict:
        self.info(f"Indexando: [bold]{path.name}[/bold]")
        conn    = sqlite3.connect(db_path)
        count   = 0
        errors  = 0
        batch   = []
        BATCH_SIZE = 5000

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    email, password = self._parse_line(line)
                    if email:
                        domain = email.split("@")[-1]
                        batch.append((email, password, domain, path.name, line_num))
                        count += 1
                        if len(batch) >= BATCH_SIZE:
                            conn.executemany(
                                "INSERT OR IGNORE INTO credentials "
                                "(email,password,domain,source_file,line_num) VALUES (?,?,?,?,?)",
                                batch
                            )
                            conn.commit()
                            batch.clear()
                except Exception:
                    errors += 1

        if batch:
            conn.executemany(
                "INSERT OR IGNORE INTO credentials "
                "(email,password,domain,source_file,line_num) VALUES (?,?,?,?,?)",
                batch
            )
            conn.commit()
        conn.close()

        self.success(f"{count:,} credenciais indexadas | {errors} erros")
        return {"indexed": count, "errors": errors, "file": str(path)}

    def _search(self, domain_or_email: str, db_path: Path) -> dict:
        self.info(f"Buscando: [bold]{domain_or_email}[/bold]")
        conn = sqlite3.connect(db_path)

        if "@" in domain_or_email:
            rows = conn.execute(
                "SELECT email, password, source_file FROM credentials WHERE email=?",
                (domain_or_email,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT email, password, source_file FROM credentials WHERE domain=? LIMIT 500",
                (domain_or_email,)
            ).fetchall()

        conn.close()

        creds = [{"email": r[0], "password": r[1], "source": r[2]} for r in rows]

        # Estatísticas de senhas
        passwords = [c["password"] for c in creds if c["password"]]
        stats = self._password_stats(passwords)

        self.success(f"{len(creds)} credenciais encontradas para {domain_or_email}")
        return {
            "target":     domain_or_email,
            "count":      len(creds),
            "credentials":creds[:100],  # limita output
            "stats":      stats,
        }

    def _parse_line(self, line: str):
        """Suporta formatos: email:senha, email;senha, email|senha"""
        for sep in (":", ";", "|", "\t"):
            if sep in line:
                parts = line.split(sep, 1)
                if len(parts) == 2 and EMAIL_RE.match(parts[0].strip()):
                    return parts[0].strip().lower(), parts[1].strip()
        return None, None

    def _password_stats(self, passwords: list) -> dict:
        if not passwords:
            return {}
        lengths = [len(p) for p in passwords]
        common  = Counter(passwords).most_common(10)
        return {
            "total":          len(passwords),
            "avg_length":     round(sum(lengths) / len(lengths), 1),
            "min_length":     min(lengths),
            "max_length":     max(lengths),
            "most_common":    [{"password": p, "count": c} for p, c in common],
            "unique":         len(set(passwords)),
        }
