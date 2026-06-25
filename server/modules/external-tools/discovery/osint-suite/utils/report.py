"""
utils/report.py — Geração de relatórios HTML, JSON e CSV
"""

import json
import csv
import html
from datetime import datetime
from pathlib import Path


class ReportGenerator:
    def __init__(self, target: str, results: dict):
        self.target    = target
        self.results   = results
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.out_dir   = Path("reports")
        self.out_dir.mkdir(exist_ok=True)

    # ------------------------------------------------------------------
    def generate_json(self) -> str:
        path = self.out_dir / f"osint_{self._safe(self.target)}_{self.timestamp}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"target": self.target, "timestamp": self.timestamp,
                       "results": self.results}, f, indent=2, ensure_ascii=False, default=str)
        return str(path)

    def generate_csv(self) -> str:
        path = self.out_dir / f"osint_{self._safe(self.target)}_{self.timestamp}.csv"
        rows = self._flatten(self.results)
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["module", "key", "value"])
            writer.writeheader()
            writer.writerows(rows)
        return str(path)

    def generate_html(self) -> str:
        path = self.out_dir / f"osint_{self._safe(self.target)}_{self.timestamp}.html"
        with open(path, "w", encoding="utf-8") as f:
            f.write(self._build_html())
        return str(path)

    # ------------------------------------------------------------------
    def _build_html(self) -> str:
        ts      = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        modules = self._render_modules()
        summary = self._render_summary()

        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSINT Suite — {html.escape(self.target)}</title>
<style>
  :root {{
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #e6edf3; --muted: #8b949e;
    --cyan: #58a6ff; --green: #3fb950; --red: #f85149;
    --yellow: #d29922; --purple: #bc8cff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg);
          color: var(--text); padding: 2rem; }}
  header {{ border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
  h1 {{ font-size: 1.6rem; color: var(--cyan); font-family: monospace; }}
  h1 span {{ color: var(--muted); font-weight: 400; }}
  .meta {{ font-size: .8rem; color: var(--muted); margin-top: .4rem; }}
  .summary {{ display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 2rem; }}
  .stat {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px;
           padding: .8rem 1.2rem; min-width: 130px; text-align: center; }}
  .stat .num {{ font-size: 1.8rem; font-weight: 700; color: var(--cyan); }}
  .stat .lbl {{ font-size: .75rem; color: var(--muted); margin-top: .2rem; }}
  .module {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 10px;
             margin-bottom: 1.5rem; overflow: hidden; }}
  .mod-header {{ display: flex; align-items: center; gap: .7rem; padding: .9rem 1.2rem;
                 background: var(--bg3); cursor: pointer; user-select: none; }}
  .mod-title {{ font-weight: 600; font-size: .95rem; }}
  .badge {{ font-size: .7rem; padding: 2px 8px; border-radius: 20px; font-weight: 600; }}
  .badge-ok  {{ background: #1a3a1a; color: var(--green); }}
  .badge-err {{ background: #3a1a1a; color: var(--red); }}
  .badge-warn{{ background: #3a2a0a; color: var(--yellow); }}
  .mod-body {{ padding: 1rem 1.2rem; }}
  pre {{ background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
         padding: .8rem; font-size: .78rem; overflow-x: auto;
         white-space: pre-wrap; word-break: break-all; color: var(--text); max-height: 400px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .82rem; }}
  th {{ text-align: left; padding: .5rem .7rem; background: var(--bg3);
        color: var(--muted); font-weight: 500; border-bottom: 1px solid var(--border); }}
  td {{ padding: .45rem .7rem; border-bottom: 1px solid var(--border); word-break: break-all; }}
  tr:last-child td {{ border-bottom: none; }}
  a {{ color: var(--cyan); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .tag-red  {{ color: var(--red); font-weight: 600; }}
  .tag-grn  {{ color: var(--green); }}
  .tag-ylw  {{ color: var(--yellow); }}
  .arrow {{ margin-left: auto; transition: transform .2s; }}
  .collapsed .arrow {{ transform: rotate(-90deg); }}
  .collapsed .mod-body {{ display: none; }}
  footer {{ margin-top: 3rem; text-align: center; font-size: .75rem; color: var(--muted);
            border-top: 1px solid var(--border); padding-top: 1rem; }}
</style>
</head>
<body>
<header>
  <h1>⚡ OSINT Suite <span>/ {html.escape(self.target)}</span></h1>
  <div class="meta">Gerado em {ts} &nbsp;|&nbsp; OSINT Suite v1.0.0 &nbsp;|&nbsp;
  ⚠ Uso exclusivo para fins legais e autorizados</div>
</header>

<div class="summary">{summary}</div>

{modules}

<footer>
  OSINT Suite v1.0.0 — Uso restrito a atividades legais e autorizadas.<br>
  Respeite a LGPD, o Marco Civil da Internet e os Termos de Serviço de cada plataforma.
</footer>

<script>
document.querySelectorAll('.mod-header').forEach(h => {{
  h.addEventListener('click', () => h.parentElement.classList.toggle('collapsed'));
}});
</script>
</body>
</html>"""

    def _render_summary(self) -> str:
        stats = [("Módulos", len(self.results))]

        # Conta findings notáveis
        if "git" in self.results:
            stats.append(("Segredos (Git)", self.results["git"].get("total_findings", 0)))
        if "cert" in self.results:
            stats.append(("Subdomínios", self.results["cert"].get("count", 0)))
        if "email" in self.results:
            stats.append(("Emails", self.results["email"].get("count", 0)))
        if "social" in self.results:
            found = len(self.results["social"].get("found", []))
            stats.append(("Perfis Sociais", found))
        if "threat" in self.results:
            stats.append(("Risk Score", f"{self.results['threat'].get('risk_score', 0)}/100"))

        html_parts = []
        for label, value in stats:
            html_parts.append(
                f'<div class="stat"><div class="num">{html.escape(str(value))}</div>'
                f'<div class="lbl">{html.escape(label)}</div></div>'
            )
        return "".join(html_parts)

    def _render_modules(self) -> str:
        parts = []
        for mod_key, data in self.results.items():
            if not data:
                continue
            has_error = isinstance(data, dict) and "error" in data
            badge_cls = "badge-err" if has_error else "badge-ok"
            badge_txt = "ERRO" if has_error else "OK"

            body = self._render_module_body(mod_key, data)
            parts.append(f"""
<div class="module">
  <div class="mod-header">
    <span class="badge {badge_cls}">{badge_txt}</span>
    <span class="mod-title">{html.escape(mod_key.upper())}</span>
    <span class="arrow">▼</span>
  </div>
  <div class="mod-body">{body}</div>
</div>""")
        return "\n".join(parts)

    def _render_module_body(self, key: str, data: dict) -> str:
        """Renderização especializada por módulo, fallback para JSON."""

        if key == "social" and isinstance(data, dict):
            found = data.get("found", [])
            rows  = "".join(
                f'<tr><td>{html.escape(f["platform"])}</td>'
                f'<td><a href="{html.escape(f["url"])}" target="_blank">{html.escape(f["url"])}</a></td></tr>'
                for f in found
            )
            return (f'<p style="margin-bottom:.6rem">Encontrado em <b>{len(found)}</b> plataformas</p>'
                    f'<table><thead><tr><th>Plataforma</th><th>URL</th></tr></thead>'
                    f'<tbody>{rows}</tbody></table>')

        if key == "git" and isinstance(data, dict):
            findings = data.get("findings", [])
            rows = "".join(
                f'<tr><td>{html.escape(f.get("repo",""))}</td>'
                f'<td>{html.escape(f.get("file",""))}</td>'
                f'<td class="tag-red">{html.escape(f.get("pattern",""))}</td>'
                f'<td><code>{html.escape(f.get("match",""))}</code></td>'
                f'<td><a href="{html.escape(f.get("url",""))}" target="_blank">link</a></td></tr>'
                for f in findings
            )
            return (f'<p style="margin-bottom:.6rem" class="tag-red">'
                    f'⚠ {len(findings)} segredos | {data.get("critical_count",0)} críticos</p>'
                    f'<table><thead><tr><th>Repo</th><th>Arquivo</th><th>Padrão</th>'
                    f'<th>Match</th><th>Link</th></tr></thead>'
                    f'<tbody>{rows}</tbody></table>')

        if key == "cert" and isinstance(data, dict):
            subs = data.get("resolved", [])
            rows = "".join(
                f'<tr><td>{html.escape(s["subdomain"])}</td>'
                f'<td>{html.escape(", ".join(s["ips"]))}</td></tr>'
                for s in subs
            )
            return (f'<p style="margin-bottom:.6rem">{data.get("count",0)} subdomínios '
                    f'| {len(subs)} resolvidos</p>'
                    f'<table><thead><tr><th>Subdomínio</th><th>IPs</th></tr></thead>'
                    f'<tbody>{rows}</tbody></table>')

        if key == "threat" and isinstance(data, dict):
            score = data.get("risk_score", 0)
            color = "tag-red" if score >= 60 else "tag-ylw" if score >= 30 else "tag-grn"
            return (f'<p class="{color}" style="font-size:1.1rem;margin-bottom:.8rem">'
                    f'Risk Score: <b>{score}/100</b></p>'
                    f'<pre>{html.escape(json.dumps(data, indent=2, ensure_ascii=False, default=str))}</pre>')

        # Fallback genérico
        return f'<pre>{html.escape(json.dumps(data, indent=2, ensure_ascii=False, default=str))}</pre>'

    def _flatten(self, data: dict, prefix: str = "") -> list:
        rows = []
        for k, v in data.items():
            full_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                rows += self._flatten(v, full_key)
            elif isinstance(v, list):
                rows.append({"module": prefix, "key": full_key, "value": json.dumps(v, ensure_ascii=False)})
            else:
                rows.append({"module": prefix, "key": full_key, "value": str(v)})
        return rows

    @staticmethod
    def _safe(s: str) -> str:
        import re
        return re.sub(r"[^\w\-]", "_", s)[:40]
