"""
exporter.py — Exportação de dorks e relatórios em múltiplos formatos.

Suporta exportação para:
    - TXT  : lista simples de dorks + URLs.
    - JSON : estruturado (categoria, título, dork, url, timestamp).
    - CSV  : colunas categoria, titulo, dork, url.
    - HTML : relatório responsivo (dark mode), agrupado por categoria, com links
             clicáveis e rodapé com aviso legal.

Todos os arquivos são salvos na pasta ``output/`` com um nome contendo timestamp,
evitando sobrescrever exportações anteriores.
"""

from __future__ import annotations

import csv
import html
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Reaproveita o gerador de URL para garantir consistência com o launcher.
from .operators import dork_para_url

# Aviso legal reutilizado no rodapé do relatório HTML.
DISCLAIMER = (
    "Esta ferramenta destina-se exclusivamente a fins educacionais, pesquisa de "
    "segurança, testes de invasão autorizados e programas de bug bounty. O uso de "
    "Google Dorking para acessar, coletar ou expor dados de terceiros sem "
    "autorização pode violar a Lei nº 12.737/2012 (Lei Carolina Dieckmann) e a "
    "LGPD (Lei nº 13.709/2018). O usuário é o único responsável pelo uso."
)


@dataclass
class ItemExportacao:
    """Representa uma linha exportável: categoria, dork e URL gerada."""

    categoria: str
    titulo: str
    dork: str
    url: str

    def como_dict(self) -> Dict[str, str]:
        """Retorna o item como dicionário."""
        return {
            "categoria": self.categoria,
            "titulo": self.titulo,
            "dork": self.dork,
            "url": self.url,
        }


@dataclass
class Exporter:
    """Gera arquivos de exportação a partir de uma lista de itens.

    :param diretorio_saida: pasta onde os arquivos serão gravados (padrão ``output``).
    :param alvo: alvo opcional (domínio) exibido nos relatórios.
    :param motor: mecanismo de busca usado para gerar URLs quando ausentes.
    """

    diretorio_saida: Path = field(default_factory=lambda: Path("output"))
    alvo: str = ""
    motor: str = "google"

    def __post_init__(self) -> None:
        """Garante que o diretório de saída exista."""
        self.diretorio_saida = Path(self.diretorio_saida)
        self.diretorio_saida.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Utilitários
    # ------------------------------------------------------------------ #
    def _timestamp(self) -> str:
        """Retorna um carimbo de data/hora (com milissegundos) para nomes de arquivo.

        A precisão de milissegundos evita colisões entre exportações disparadas
        no mesmo segundo (ex.: dois comandos em sequência rápida).
        """
        agora = datetime.now()
        return agora.strftime("%Y%m%d_%H%M%S_") + f"{agora.microsecond // 1000:03d}"

    def _caminho(self, extensao: str) -> Path:
        """Monta o caminho do arquivo de saída com timestamp."""
        nome = f"dorkforge_{self._timestamp()}.{extensao}"
        return self.diretorio_saida / nome

    @staticmethod
    def _garantir_url(item: ItemExportacao, motor: str) -> str:
        """Garante que o item tenha uma URL, gerando-a a partir do dork se preciso."""
        if item.url:
            return item.url
        try:
            return dork_para_url(item.dork, motor)
        except ValueError:
            return ""

    # ------------------------------------------------------------------ #
    # TXT
    # ------------------------------------------------------------------ #
    def exportar_txt(self, itens: List[ItemExportacao]) -> Path:
        """Exporta uma lista simples de dorks e URLs em texto."""
        caminho = self._caminho("txt")
        linhas: List[str] = [
            "DorkForge BR — Exportação de Dorks",
            f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
            f"Alvo: {self.alvo or '(não definido)'}",
            f"Motor de busca: {self.motor}",
            f"Total de dorks: {len(itens)}",
            "=" * 70,
            "",
        ]
        categoria_atual = None
        for item in itens:
            if item.categoria != categoria_atual:
                categoria_atual = item.categoria
                linhas.append(f"\n## {categoria_atual}")
                linhas.append("-" * 70)
            url = self._garantir_url(item, self.motor)
            linhas.append(f"[{item.titulo}]")
            linhas.append(f"  Dork: {item.dork}")
            linhas.append(f"  URL : {url}")
            linhas.append("")

        linhas.append("=" * 70)
        linhas.append(f"AVISO LEGAL: {DISCLAIMER}")
        caminho.write_text("\n".join(linhas), encoding="utf-8")
        return caminho

    # ------------------------------------------------------------------ #
    # JSON
    # ------------------------------------------------------------------ #
    def exportar_json(self, itens: List[ItemExportacao]) -> Path:
        """Exporta os dorks em JSON estruturado."""
        caminho = self._caminho("json")
        dados = {
            "ferramenta": "DorkForge BR",
            "gerado_em": datetime.now().isoformat(),
            "alvo": self.alvo,
            "motor": self.motor,
            "total": len(itens),
            "disclaimer": DISCLAIMER,
            "dorks": [
                {
                    "categoria": item.categoria,
                    "titulo": item.titulo,
                    "dork": item.dork,
                    "url": self._garantir_url(item, self.motor),
                }
                for item in itens
            ],
        }
        caminho.write_text(
            json.dumps(dados, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return caminho

    # ------------------------------------------------------------------ #
    # CSV
    # ------------------------------------------------------------------ #
    def exportar_csv(self, itens: List[ItemExportacao]) -> Path:
        """Exporta os dorks em CSV com colunas categoria, titulo, dork, url."""
        caminho = self._caminho("csv")
        # newline="" é necessário para o módulo csv não duplicar quebras de linha.
        with caminho.open("w", encoding="utf-8", newline="") as fp:
            escritor = csv.writer(fp)
            escritor.writerow(["categoria", "titulo", "dork", "url"])
            for item in itens:
                escritor.writerow(
                    [
                        item.categoria,
                        item.titulo,
                        item.dork,
                        self._garantir_url(item, self.motor),
                    ]
                )
        return caminho

    # ------------------------------------------------------------------ #
    # HTML
    # ------------------------------------------------------------------ #
    def exportar_html(self, itens: List[ItemExportacao]) -> Path:
        """Exporta um relatório HTML responsivo (dark mode) com links clicáveis."""
        caminho = self._caminho("html")

        # Agrupa os itens por categoria preservando a ordem de aparição.
        grupos: Dict[str, List[ItemExportacao]] = {}
        for item in itens:
            grupos.setdefault(item.categoria, []).append(item)

        gerado_em = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        alvo_exibido = html.escape(self.alvo or "(não definido)")

        # Monta as seções por categoria.
        secoes: List[str] = []
        for categoria, lista in grupos.items():
            linhas_tabela: List[str] = []
            for item in lista:
                url = self._garantir_url(item, self.motor)
                linhas_tabela.append(
                    "<tr>"
                    f"<td>{html.escape(item.titulo)}</td>"
                    f"<td><code>{html.escape(item.dork)}</code></td>"
                    f'<td><a href="{html.escape(url)}" target="_blank" '
                    f'rel="noopener noreferrer">🔍 Abrir busca</a></td>'
                    "</tr>"
                )
            secoes.append(
                f"""
        <section class="categoria">
            <h2>{html.escape(categoria)} <span class="contador">({len(lista)})</span></h2>
            <table>
                <thead>
                    <tr><th>Título</th><th>Dork</th><th>Ação</th></tr>
                </thead>
                <tbody>
                    {''.join(linhas_tabela)}
                </tbody>
            </table>
        </section>"""
            )

        documento = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DorkForge BR — Relatório de Dorks</title>
    <style>
        :root {{
            --bg: #0d1117; --card: #161b22; --border: #30363d;
            --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff;
            --green: #3fb950; --code-bg: #1f2630;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg); color: var(--text); margin: 0; padding: 0;
            line-height: 1.6;
        }}
        header {{
            background: linear-gradient(135deg, #161b22, #21262d);
            border-bottom: 2px solid var(--accent);
            padding: 32px 24px; text-align: center;
        }}
        header h1 {{ margin: 0; font-size: 2rem; color: var(--accent); }}
        header .meta {{ color: var(--muted); margin-top: 8px; font-size: 0.95rem; }}
        main {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
        .resumo {{
            background: var(--card); border: 1px solid var(--border);
            border-radius: 10px; padding: 16px 20px; margin-bottom: 24px;
            display: flex; flex-wrap: wrap; gap: 24px;
        }}
        .resumo div span {{ display: block; color: var(--muted); font-size: 0.8rem; }}
        .resumo div strong {{ font-size: 1.3rem; color: var(--green); }}
        .categoria {{
            background: var(--card); border: 1px solid var(--border);
            border-radius: 10px; padding: 16px 20px; margin-bottom: 20px;
        }}
        .categoria h2 {{
            margin: 0 0 12px; font-size: 1.2rem; color: var(--accent);
            border-bottom: 1px solid var(--border); padding-bottom: 8px;
        }}
        .contador {{ color: var(--muted); font-size: 0.9rem; font-weight: normal; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{
            text-align: left; padding: 10px 8px;
            border-bottom: 1px solid var(--border); vertical-align: top;
        }}
        th {{ color: var(--muted); font-size: 0.85rem; text-transform: uppercase; }}
        td code {{
            background: var(--code-bg); padding: 3px 6px; border-radius: 5px;
            font-size: 0.85rem; color: #e6edf3; word-break: break-word;
        }}
        a {{ color: var(--accent); text-decoration: none; white-space: nowrap; }}
        a:hover {{ text-decoration: underline; }}
        footer {{
            max-width: 1100px; margin: 0 auto; padding: 24px;
            color: var(--muted); font-size: 0.8rem; border-top: 1px solid var(--border);
        }}
        .disclaimer {{
            background: #2d1b1b; border: 1px solid #6e2727; border-radius: 8px;
            padding: 14px 18px; color: #f0b3b3;
        }}
    </style>
</head>
<body>
    <header>
        <h1>🔱 DorkForge BR</h1>
        <div class="meta">Relatório de Google Dorks &bull; Gerado em {gerado_em}</div>
    </header>
    <main>
        <div class="resumo">
            <div><span>Alvo</span><strong>{alvo_exibido}</strong></div>
            <div><span>Motor de busca</span><strong>{html.escape(self.motor)}</strong></div>
            <div><span>Total de dorks</span><strong>{len(itens)}</strong></div>
            <div><span>Categorias</span><strong>{len(grupos)}</strong></div>
        </div>
        {''.join(secoes)}
    </main>
    <footer>
        <div class="disclaimer">
            <strong>⚖️ AVISO LEGAL:</strong> {html.escape(DISCLAIMER)}
        </div>
        <p style="text-align:center; margin-top:16px;">
            Gerado por DorkForge BR — ferramenta de OSINT e reconhecimento autorizado.
        </p>
    </footer>
</body>
</html>"""
        caminho.write_text(documento, encoding="utf-8")
        return caminho

    # ------------------------------------------------------------------ #
    # Despacho por formato
    # ------------------------------------------------------------------ #
    def exportar(self, itens: List[ItemExportacao], formato: str) -> Path:
        """Exporta no formato indicado (``txt``/``json``/``csv``/``html``).

        :raises ValueError: se o formato não for suportado.
        """
        formato = formato.lower().strip()
        despacho = {
            "txt": self.exportar_txt,
            "json": self.exportar_json,
            "csv": self.exportar_csv,
            "html": self.exportar_html,
        }
        if formato not in despacho:
            raise ValueError(
                f"Formato '{formato}' inválido. Opções: {', '.join(despacho)}"
            )
        return despacho[formato](itens)
