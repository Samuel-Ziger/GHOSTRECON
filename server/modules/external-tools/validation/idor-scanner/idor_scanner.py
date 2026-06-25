

import argparse
import html
import ipaddress
import json
import socket
import sys
import time
from datetime import datetime
from urllib.parse import urlparse

# Garante UTF-8 na saída (consoles Windows usam cp1252 por padrão, o que
# quebraria os emojis/box-drawing da TUI). Seguro/no-op se já for UTF-8.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

try:
    import requests
except ImportError:
    sys.exit("ERRO: dependência 'requests' não instalada. Rode: pip install -r requirements.txt")

try:
    from rich.console import Console, Group
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.live import Live
    from rich.align import Align
    from rich.progress import (
        Progress, BarColumn, TextColumn, SpinnerColumn,
        TimeElapsedColumn, MofNCompleteColumn,
    )
    from rich import box
except ImportError:
    sys.exit("ERRO: dependência 'rich' não instalada. Rode: pip install -r requirements.txt")


# ------------------------------------------------------------------------------
# Tema visual (dark hacker: verde matrix / vermelho alerta)
# ------------------------------------------------------------------------------
COR_MATRIX = "bright_green"
COR_ALERTA = "bright_red"
COR_OK = "green"
COR_INFO = "cyan"
COR_AVISO = "yellow"
COR_DIM = "grey50"

console = Console()


# ------------------------------------------------------------------------------
# ASCII art / banners
# ------------------------------------------------------------------------------
ASCII_BANNER = r"""
 ___ ____   ___  ____    _        _    ____    ____   ____    _    _   _
|_ _|  _ \ / _ \|  _ \  | |      / \  | __ )  / ___| / ___|  / \  | \ | |
 | || | | | | | | |_) | | |     / _ \ |  _ \  \___ \| |     / _ \ |  \| |
 | || |_| | |_| |  _ <  | |___ / ___ \| |_) |  ___) | |___ / ___ \| |\  |
|___|____/ \___/|_| \_\ |_____/_/   \_\____/  |____/ \____/_/   \_\_| \_|
"""


def imprimir_banner():
    """Banner ASCII no topo, em verde matrix, dentro de um painel."""
    banner = Text(ASCII_BANNER, style=f"bold {COR_MATRIX}")
    subtitulo = Text(
        "IDOR Lab Scanner • Ferramenta Educacional • Cybersegurança na Prática",
        style=f"italic {COR_INFO}",
    )
    conteudo = Group(Align.center(banner), Align.center(subtitulo))
    console.print(Panel(conteudo, border_style=COR_MATRIX, box=box.DOUBLE))


def imprimir_aviso_legal():
    """
    Aviso legal exibido SEMPRE na inicialização.

    Menciona a Lei 12.737/2012 (Lei Carolina Dieckmann), que tipifica a invasão
    de dispositivo informático alheio. O objetivo é deixar explícito que a
    ferramenta só pode ser usada contra sistemas próprios ou com autorização.
    """
    texto = Text()
    texto.append("AVISO LEGAL — LEIA ANTES DE USAR\n\n", style=f"bold {COR_ALERTA}")
    texto.append(
        "Esta ferramenta é material EDUCACIONAL para demonstrar, em laboratório\n"
        "próprio, como funciona a vulnerabilidade IDOR. Ela NÃO é uma arma de\n"
        "ataque.\n\n",
        style="white",
    )
    texto.append(
        "Usar ferramentas de teste de intrusão contra sistemas de terceiros SEM\n"
        "autorização é CRIME no Brasil — Lei nº 12.737/2012 (Lei Carolina\n"
        "Dieckmann), que alterou o Código Penal (art. 154-A: invasão de\n"
        "dispositivo informático).\n\n",
        style=COR_AVISO,
    )
    texto.append(
        "Use SOMENTE em: localhost, redes privadas que você controla, ou alvos\n"
        "para os quais você tem permissão explícita e por escrito.",
        style=f"bold {COR_INFO}",
    )
    console.print(Panel(texto, title="[bold red]⚠️  RESPONSABILIDADE LEGAL[/]",
                        border_style=COR_ALERTA, box=box.HEAVY))


# ------------------------------------------------------------------------------
# Travas de escopo: só alvos locais/privados (salvo autorização explícita)
# ------------------------------------------------------------------------------
def _resolver_host(host: str):
    """Tenta resolver um hostname para IP. Retorna o IP (str) ou None se falhar."""
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, UnicodeError):
        return None


def alvo_eh_local_ou_privado(url: str) -> bool:
    """
    Decide se a URL aponta para um alvo SEGURO de testar (localhost ou rede
    privada). Faixas consideradas locais/privadas:
        - 127.0.0.0/8     (loopback)
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
        - ::1, fc00::/7   (IPv6 loopback e ULA)
        - hostnames 'localhost'
    Se o host for um nome (ex: 'meusite.com'), ele é resolvido para IP antes de
    avaliar.
    """
    host = urlparse(url).hostname
    if not host:
        return False

    if host.lower() in ("localhost", "localhost.localdomain"):
        return True

    # Se já for um IP literal, avalia direto; senão resolve o hostname.
    ip_str = host
    try:
        ipaddress.ip_address(host)
    except ValueError:
        ip_resolvido = _resolver_host(host)
        if ip_resolvido is None:
            return False  # não resolveu -> trata como não-confiável
        ip_str = ip_resolvido

    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    return ip.is_loopback or ip.is_private


def verificar_escopo(url: str, autorizado: bool):
    """
    Aplica a trava de escopo. Se o alvo NÃO for local/privado e o usuário não
    tiver passado --i-have-authorization, mostra um aviso grande e ABORTA.
    """
    if alvo_eh_local_ou_privado(url):
        return  # alvo seguro de laboratório — segue o jogo.

    # A partir daqui o alvo é público.
    aviso = Text()
    aviso.append("🚨  ALVO PÚBLICO DETECTADO  🚨\n\n", style=f"bold {COR_ALERTA}")
    aviso.append(
        f"O alvo informado ({urlparse(url).hostname}) NÃO está em localhost nem\n"
        "em uma faixa de rede privada.\n\n",
        style="white",
    )
    aviso.append(
        "Testar IDOR contra sistemas de terceiros sem autorização é CRIME\n"
        "(Lei 12.737/2012). Esta ferramenta foi feita para laboratório.\n\n",
        style=COR_AVISO,
    )

    if not autorizado:
        aviso.append(
            "Operação BLOQUEADA. Se — e somente se — você tem autorização\n"
            "explícita e por escrito para testar este alvo (ex.: contrato de\n"
            "pentest), execute novamente acrescentando a flag:\n\n",
            style="white",
        )
        aviso.append("    --i-have-authorization\n", style=f"bold {COR_INFO}")
        console.print(Panel(aviso, title="[bold red]ESCOPO NEGADO[/]",
                            border_style=COR_ALERTA, box=box.HEAVY))
        sys.exit(2)

    # Usuário afirmou ter autorização: deixamos seguir, mas registramos o aviso.
    aviso.append(
        "Você declarou possuir AUTORIZAÇÃO EXPLÍCITA (--i-have-authorization).\n"
        "A responsabilidade legal é inteiramente sua.",
        style=f"bold {COR_AVISO}",
    )
    console.print(Panel(aviso, title="[bold yellow]PROSSEGUINDO SOB SUA RESPONSABILIDADE[/]",
                        border_style=COR_AVISO, box=box.HEAVY))


# ------------------------------------------------------------------------------
# Utilidades de formatação
# ------------------------------------------------------------------------------
def formatar_brl(valor) -> str:
    """Formata um número como moeda brasileira: 47892.0 -> 'R$ 47.892,00'."""
    if valor is None:
        return "-"
    try:
        v = float(valor)
    except (TypeError, ValueError):
        return str(valor)
    inteiro, centavos = f"{v:,.2f}".split(".")
    inteiro = inteiro.replace(",", ".")  # separador de milhar -> ponto
    return f"R$ {inteiro},{centavos}"


def montar_url(base: str, id_: int) -> str:
    """
    Monta a URL final para um ID. Suporta dois formatos de --url:
      * Com placeholder:  http://host/api/usuario/{id}/perfil
      * Sem placeholder:  http://host/api/usuario/   (o ID é anexado no fim)
    """
    if "{id}" in base:
        return base.replace("{id}", str(id_))
    return base.rstrip("/") + "/" + str(id_)


# ------------------------------------------------------------------------------
# Núcleo da análise (o "diff inteligente")
# ------------------------------------------------------------------------------
# Campos considerados sensíveis. A presença deles numa resposta 200 indica que
# dados privados estão sendo expostos.
CAMPOS_SENSIVEIS = ("cpf", "saldo_conta", "senha_hash")


def analisar_resposta(resp, id_testado: int, meu_id):
    """
    Faz o 'diff inteligente' de uma resposta e decide se houve VAZAMENTO.

    Critério de vazamento (IDOR):
      1. status == 200 E
      2. corpo é JSON com pelo menos um campo sensível (cpf/saldo/senha_hash) E
      3. o registro NÃO é o do próprio usuário autenticado (--meu-id).
         (se --meu-id não foi informado, qualquer dado sensível conta.)

    Retorna um dicionário 'resultado' com tudo que a tabela e o relatório usam.
    """
    resultado = {
        "id": id_testado,
        "status": resp.status_code,
        "nome": "-",
        "cpf": "-",
        "saldo": None,
        "vulneravel": False,
        "motivo": "",
    }

    if resp.status_code == 200:
        try:
            dados = resp.json()
        except ValueError:
            dados = None

        if isinstance(dados, dict) and any(c in dados for c in CAMPOS_SENSIVEIS):
            resultado["nome"] = dados.get("nome", "-")
            resultado["cpf"] = dados.get("cpf", "-")
            resultado["saldo"] = dados.get("saldo_conta")

            eh_outro = (meu_id is None) or (id_testado != meu_id)
            if eh_outro:
                resultado["vulneravel"] = True
                resultado["motivo"] = "Dados sensíveis de OUTRO usuário expostos"
            else:
                resultado["motivo"] = "Seu próprio usuário (acesso esperado)"
        else:
            resultado["motivo"] = "200 sem dados sensíveis"

    elif resp.status_code in (401, 403):
        resultado["motivo"] = "Acesso negado (autorização funcionou ✓)"
    elif resp.status_code == 404:
        resultado["motivo"] = "Usuário não encontrado"
    else:
        resultado["motivo"] = f"HTTP {resp.status_code}"

    return resultado


# ------------------------------------------------------------------------------
# Construção da tabela em tempo real (rich)
# ------------------------------------------------------------------------------
def criar_tabela() -> Table:
    """Cria a tabela vazia com o cabeçalho do scanner."""
    tabela = Table(
        box=box.SIMPLE_HEAVY,
        border_style=COR_DIM,
        header_style=f"bold {COR_MATRIX}",
        expand=True,
    )
    tabela.add_column("ID", justify="right", style="bold", width=5)
    tabela.add_column("Status", justify="center", width=8)
    tabela.add_column("Nome", overflow="ellipsis", max_width=22)
    tabela.add_column("CPF", justify="center", width=16)
    tabela.add_column("Saldo", justify="right", width=15)
    tabela.add_column("Resultado", justify="center", width=16)
    return tabela


def adicionar_linha(tabela: Table, r: dict):
    """Adiciona uma linha à tabela, colorindo conforme o resultado."""
    if r["vulneravel"]:
        marcador = Text("VULNERÁVEL ⚠️", style=f"bold {COR_ALERTA}")
        estilo_linha = COR_ALERTA
    elif r["status"] in (401, 403):
        marcador = Text("BLOQUEADO 🛡️", style=f"bold {COR_OK}")
        estilo_linha = COR_OK
    elif r["status"] == 200:
        marcador = Text("OK ✓", style=COR_OK)
        estilo_linha = COR_DIM
    else:
        marcador = Text("—", style=COR_DIM)
        estilo_linha = COR_DIM

    tabela.add_row(
        str(r["id"]),
        str(r["status"]),
        r["nome"],
        r["cpf"],
        formatar_brl(r["saldo"]),
        marcador,
        style=estilo_linha if r["vulneravel"] else None,
    )


def painel_status(url: str, meu_id, testados: int, total: int, vazados: int) -> Panel:
    """Painel-cabeçalho com o contexto do scan, mostrado acima da tabela."""
    t = Text()
    t.append("Alvo: ", style="bold white")
    t.append(f"{url}\n", style=COR_INFO)
    t.append("Usuário autenticado: ", style="bold white")
    t.append(f"{meu_id if meu_id is not None else '(nenhum)'}", style=COR_INFO)
    t.append("   |   Progresso: ", style="bold white")
    t.append(f"{testados}/{total}", style=COR_INFO)
    t.append("   |   Vazamentos: ", style="bold white")
    cor_v = COR_ALERTA if vazados else COR_OK
    t.append(f"{vazados}", style=f"bold {cor_v}")
    return Panel(t, border_style=COR_MATRIX, box=box.ROUNDED, title="[bold]SCAN IDOR[/]")


# ------------------------------------------------------------------------------
# Loop principal de varredura
# ------------------------------------------------------------------------------
def executar_scan(args) -> dict:
    """
    Itera sobre o range de IDs, faz as requisições e atualiza a TUI em tempo
    real. Retorna um dicionário com os resultados e metadados para o relatório.
    """
    session = requests.Session()
    headers = {"User-Agent": "IDOR-Lab-Scanner/1.0 (educacional)"}
    if args.token:
        # Aceita tanto 'token-1' quanto 'Bearer token-1'.
        valor = args.token if args.token.lower().startswith("bearer ") else f"Bearer {args.token}"
        headers["Authorization"] = valor
    if args.cookie:
        headers["Cookie"] = args.cookie
    session.headers.update(headers)

    ids = list(range(args.inicio, args.fim + 1))
    total = len(ids)
    resultados = []

    tabela = criar_tabela()

    progress = Progress(
        SpinnerColumn(style=COR_MATRIX),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=40, complete_style=COR_MATRIX, finished_style=COR_OK),
        MofNCompleteColumn(),
        TextColumn("•"),
        TimeElapsedColumn(),
        expand=True,
    )
    task = progress.add_task("Extraindo dados", total=total)

    vazados = 0

    def render():
        return Group(
            painel_status(args.url, args.meu_id, len(resultados), total, vazados),
            tabela,
            progress,
        )

    with Live(render(), console=console, refresh_per_second=15, screen=False) as live:
        for id_ in ids:
            url = montar_url(args.url, id_)
            try:
                resp = session.get(url, timeout=args.timeout, allow_redirects=False)
                resultado = analisar_resposta(resp, id_, args.meu_id)
            except requests.exceptions.ConnectTimeout:
                resultado = _resultado_erro(id_, "TIMEOUT de conexão")
            except requests.exceptions.ReadTimeout:
                resultado = _resultado_erro(id_, "TIMEOUT de leitura")
            except requests.exceptions.ConnectionError:
                resultado = _resultado_erro(id_, "Conexão recusada (alvo no ar?)")
            except requests.exceptions.RequestException as e:
                resultado = _resultado_erro(id_, f"Erro: {type(e).__name__}")

            resultados.append(resultado)
            if resultado["vulneravel"]:
                vazados += 1

            adicionar_linha(tabela, resultado)
            progress.advance(task)
            live.update(render())

            # Modo cinematográfico: pequeno delay para a "extração" ficar visível.
            if args.dramatic:
                time.sleep(args.delay)

    return {
        "url": args.url,
        "meu_id": args.meu_id,
        "inicio": args.inicio,
        "fim": args.fim,
        "total_testado": total,
        "data": datetime.now().isoformat(timespec="seconds"),
        "resultados": resultados,
    }


def _resultado_erro(id_: int, motivo: str) -> dict:
    """Cria um 'resultado' padronizado para falhas de rede/requisição."""
    return {
        "id": id_,
        "status": 0,
        "nome": "-",
        "cpf": "-",
        "saldo": None,
        "vulneravel": False,
        "motivo": motivo,
    }


# ------------------------------------------------------------------------------
# Resumo final + estatísticas
# ------------------------------------------------------------------------------
def calcular_estatisticas(relatorio: dict) -> dict:
    """Calcula as estatísticas agregadas do scan (vazamentos, CPFs, saldos)."""
    resultados = relatorio["resultados"]
    vazados = [r for r in resultados if r["vulneravel"]]
    cpfs = [r["cpf"] for r in vazados if r["cpf"] not in (None, "-")]
    soma_saldos = sum(r["saldo"] for r in vazados if isinstance(r["saldo"], (int, float)))

    return {
        "total_testado": relatorio["total_testado"],
        "total_vazados": len(vazados),
        "cpfs_vazados": len(cpfs),
        "soma_saldos_expostos": soma_saldos,
        "registros_vazados": vazados,
    }


def imprimir_resumo(relatorio: dict, stats: dict):
    """Imprime o painel grande de resumo ao final do scan."""
    total = stats["total_testado"]
    vaz = stats["total_vazados"]

    if vaz > 0:
        titulo = "[bold red]💥  VULNERABILIDADE IDOR CONFIRMADA  💥[/]"
        borda = COR_ALERTA
        cabecalho = Text(
            f"\n  {vaz} de {total} usuários tiveram dados expostos\n",
            style=f"bold {COR_ALERTA}",
        )
    else:
        titulo = "[bold green]🛡️  NENHUM VAZAMENTO DETECTADO  🛡️[/]"
        borda = COR_OK
        cabecalho = Text(
            f"\n  0 de {total} usuários expostos — autorização funcionando\n",
            style=f"bold {COR_OK}",
        )

    corpo = Text()
    corpo.append("  • CPFs vazados ............... ", style="white")
    corpo.append(f"{stats['cpfs_vazados']}\n", style=f"bold {COR_ALERTA if vaz else COR_OK}")
    corpo.append("  • Saldo total exposto ........ ", style="white")
    corpo.append(f"{formatar_brl(stats['soma_saldos_expostos'])}\n",
                 style=f"bold {COR_ALERTA if vaz else COR_OK}")
    corpo.append("  • Requisições realizadas ..... ", style="white")
    corpo.append(f"{total}\n", style=COR_INFO)

    if vaz > 0:
        corpo.append("\n  Lição: o servidor entregou dados de outras contas só\n",
                     style=COR_AVISO)
        corpo.append("  trocando o número do ID na URL. Isso é IDOR.\n",
                     style=COR_AVISO)
        corpo.append("  Correção: validar a autorização a nível de objeto\n",
                     style=COR_INFO)
        corpo.append("  (veja o endpoint /api/usuario-seguro e --explicar).",
                     style=COR_INFO)

    console.print(Panel(Group(cabecalho, corpo), title=titulo,
                        border_style=borda, box=box.DOUBLE))


# ------------------------------------------------------------------------------
# Exportação: JSON + HTML
# ------------------------------------------------------------------------------
def exportar_json(relatorio: dict, stats: dict, caminho: str):
    """Salva o relatório completo em JSON."""
    saida = {
        "meta": {
            "ferramenta": "IDOR Lab Scanner",
            "gerado_em": relatorio["data"],
            "alvo": relatorio["url"],
            "usuario_autenticado": relatorio["meu_id"],
            "range_ids": [relatorio["inicio"], relatorio["fim"]],
        },
        "estatisticas": {
            "total_testado": stats["total_testado"],
            "total_vazados": stats["total_vazados"],
            "cpfs_vazados": stats["cpfs_vazados"],
            "soma_saldos_expostos": stats["soma_saldos_expostos"],
        },
        "resultados": relatorio["resultados"],
    }
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(saida, f, ensure_ascii=False, indent=2)


def exportar_html(relatorio: dict, stats: dict, caminho: str):
    """Gera um relatório HTML visual com tema dark hacker."""
    linhas = []
    for r in relatorio["resultados"]:
        if r["vulneravel"]:
            classe, tag = "vuln", "VULNERÁVEL ⚠️"
        elif r["status"] in (401, 403):
            classe, tag = "block", "BLOQUEADO 🛡️"
        elif r["status"] == 200:
            classe, tag = "ok", "OK ✓"
        else:
            classe, tag = "neutral", "—"

        linhas.append(
            "<tr class='{cls}'><td>{id}</td><td>{st}</td><td>{nm}</td>"
            "<td>{cpf}</td><td>{saldo}</td><td>{tag}</td></tr>".format(
                cls=classe,
                id=r["id"],
                st=r["status"],
                nm=html.escape(str(r["nome"])),
                cpf=html.escape(str(r["cpf"])),
                saldo=html.escape(formatar_brl(r["saldo"])),
                tag=tag,
            )
        )

    html_doc = _TEMPLATE_HTML.format(
        gerado_em=html.escape(relatorio["data"]),
        alvo=html.escape(relatorio["url"]),
        total=stats["total_testado"],
        vazados=stats["total_vazados"],
        cpfs=stats["cpfs_vazados"],
        saldos=html.escape(formatar_brl(stats["soma_saldos_expostos"])),
        linhas="\n".join(linhas),
    )
    with open(caminho, "w", encoding="utf-8") as f:
        f.write(html_doc)


_TEMPLATE_HTML = """<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="utf-8">
<title>Relatório IDOR Lab Scanner</title>
<style>
  body {{ background:#0b0f0b; color:#c8facc; font-family:'Consolas','Courier New',monospace; margin:0; padding:30px; }}
  h1 {{ color:#39ff14; text-shadow:0 0 8px #39ff14; }}
  .sub {{ color:#7fffd4; margin-bottom:24px; }}
  .cards {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:28px; }}
  .card {{ background:#111811; border:1px solid #1f3d1f; border-radius:10px; padding:18px 24px; min-width:160px; }}
  .card .num {{ font-size:32px; font-weight:bold; }}
  .card .lbl {{ color:#6fae6f; font-size:13px; text-transform:uppercase; letter-spacing:1px; }}
  .danger .num {{ color:#ff3b3b; text-shadow:0 0 8px #ff3b3b; }}
  .good .num {{ color:#39ff14; }}
  table {{ width:100%; border-collapse:collapse; background:#0d120d; }}
  th {{ background:#16241a; color:#39ff14; padding:10px; text-align:left; position:sticky; top:0; }}
  td {{ padding:8px 10px; border-bottom:1px solid #16241a; }}
  tr.vuln td {{ background:#2a0d0d; color:#ff7a7a; }}
  tr.vuln td:last-child {{ color:#ff3b3b; font-weight:bold; }}
  tr.ok td:last-child {{ color:#39ff14; }}
  tr.block td:last-child {{ color:#39ff14; }}
  tr.neutral td {{ color:#6fae6f; }}
  .legal {{ margin-top:30px; padding:16px; border:1px solid #4d1f1f; border-radius:8px; background:#1a0d0d; color:#ffb3b3; font-size:13px; }}
</style>
</head>
<body>
  <h1>&#9888;&#65039; IDOR Lab Scanner — Relatório</h1>
  <div class="sub">Gerado em {gerado_em} &nbsp;|&nbsp; Alvo: {alvo}</div>

  <div class="cards">
    <div class="card danger"><div class="num">{vazados}</div><div class="lbl">Usuários expostos</div></div>
    <div class="card"><div class="num">{total}</div><div class="lbl">IDs testados</div></div>
    <div class="card danger"><div class="num">{cpfs}</div><div class="lbl">CPFs vazados</div></div>
    <div class="card danger"><div class="num">{saldos}</div><div class="lbl">Saldo exposto</div></div>
  </div>

  <table>
    <thead>
      <tr><th>ID</th><th>Status</th><th>Nome</th><th>CPF</th><th>Saldo</th><th>Resultado</th></tr>
    </thead>
    <tbody>
      {linhas}
    </tbody>
  </table>

  <div class="legal">
    <b>Aviso legal:</b> relatório gerado por ferramenta educacional contra alvo de
    laboratório próprio. O uso contra sistemas de terceiros sem autorização é crime
    (Lei 12.737/2012). Dados exibidos são fictícios.
  </div>
</body>
</html>
"""


# ------------------------------------------------------------------------------
# Módulo educacional: --explicar
# ------------------------------------------------------------------------------
def explicar_idor():
    """Imprime uma explicação didática e visual sobre IDOR."""
    imprimir_banner()

    # O que é
    intro = Text()
    intro.append("O que é IDOR?\n\n", style=f"bold {COR_MATRIX}")
    intro.append(
        "IDOR (Insecure Direct Object Reference / Referência Insegura e Direta\n"
        "a Objeto) acontece quando uma aplicação usa um identificador fornecido\n"
        "pelo usuário (como o número de um ID na URL) para acessar um objeto\n"
        "interno — SEM verificar se aquele usuário tem permissão de acessá-lo.\n\n",
        style="white",
    )
    intro.append(
        "Exemplo clássico: você está logado e acessa\n"
        "    /api/usuario/1   (seus dados)\n"
        "Aí você troca o número para\n"
        "    /api/usuario/2   (dados de OUTRA pessoa)\n"
        "...e o servidor entrega. Isso é IDOR.",
        style=COR_INFO,
    )
    console.print(Panel(intro, title="[bold]📘 CONCEITO[/]", border_style=COR_INFO,
                        box=box.ROUNDED))

    # Por que acontece
    porque = Text()
    porque.append("Por que acontece?\n\n", style=f"bold {COR_MATRIX}")
    porque.append(
        "• O desenvolvedor confunde AUTENTICAÇÃO (saber quem você é) com\n"
        "  AUTORIZAÇÃO (saber o que você PODE acessar).\n"
        "• O código confere se você está logado, mas esquece de conferir se o\n"
        "  recurso pedido é SEU.\n"
        "• IDs sequenciais (1, 2, 3...) facilitam a enumeração pelo atacante.\n"
        "• Falta de controle de acesso a nível de objeto (OWASP A01:2021 —\n"
        "  Broken Access Control, o risco nº 1 do OWASP Top 10).",
        style="white",
    )
    console.print(Panel(porque, title="[bold]🤔 CAUSA RAIZ[/]", border_style=COR_AVISO,
                        box=box.ROUNDED))

    # Código vulnerável vs seguro
    vuln = Text()
    vuln.append("# ❌ VULNERÁVEL — não checa permissão\n", style=COR_ALERTA)
    vuln.append(
        '@app.route("/api/usuario/<int:id>")\n'
        "def usuario(id):\n"
        "    u = DB.get(id)          # pega QUALQUER id\n"
        "    return jsonify(u)       # e devolve, sem checar nada\n",
        style="white",
    )
    console.print(Panel(vuln, title="[bold red]CÓDIGO VULNERÁVEL[/]",
                        border_style=COR_ALERTA, box=box.ROUNDED))

    seguro = Text()
    seguro.append("# ✅ SEGURO — valida autorização a nível de objeto\n", style=COR_OK)
    seguro.append(
        '@app.route("/api/usuario-seguro/<int:id>")\n'
        "def usuario_seguro(id):\n"
        "    eu = id_do_token(request)          # quem está logado?\n"
        "    if eu is None:\n"
        "        return {'erro': 'não autenticado'}, 401\n"
        "    if eu != id:                       # o recurso é meu?\n"
        "        return {'erro': 'proibido'}, 403\n"
        "    return jsonify(DB.get(id))         # só então devolve\n",
        style="white",
    )
    console.print(Panel(seguro, title="[bold green]CÓDIGO SEGURO[/]",
                        border_style=COR_OK, box=box.ROUNDED))

    # Como prevenir
    prevenir = Text()
    prevenir.append("Como prevenir?\n\n", style=f"bold {COR_MATRIX}")
    prevenir.append(
        "1. Sempre validar autorização a nível de OBJETO (o recurso é deste\n"
        "   usuário?), não apenas se ele está logado.\n"
        "2. Preferir identificadores não previsíveis (UUID) a IDs sequenciais.\n"
        "3. Aplicar o princípio do menor privilégio.\n"
        "4. Centralizar a checagem de acesso (middleware/decorator), não\n"
        "   espalhar pela aplicação.\n"
        "5. Testar! (é exatamente o que este scanner faz em laboratório.)",
        style="white",
    )
    console.print(Panel(prevenir, title="[bold]🛡️ PREVENÇÃO[/]", border_style=COR_OK,
                        box=box.ROUNDED))


# ------------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------------
def parse_args(argv=None):
    """Define e processa os argumentos de linha de comando."""
    parser = argparse.ArgumentParser(
        prog="idor_scanner.py",
        description="IDOR Lab Scanner — ferramenta educacional de demonstração de IDOR.",
        epilog="Use SOMENTE em laboratório próprio ou com autorização explícita.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--url", help="URL base do endpoint, ex: "
                        "http://127.0.0.1:5000/api/usuario/  (ou use {id} como placeholder)")
    parser.add_argument("--inicio", type=int, default=1, help="Primeiro ID a testar (padrão: 1)")
    parser.add_argument("--fim", type=int, default=50, help="Último ID a testar (padrão: 50)")
    parser.add_argument("--meu-id", type=int, default=None, dest="meu_id",
                        help="ID do usuário autenticado (acessar OUTRO id = vazamento)")
    parser.add_argument("--token", default=None,
                        help="Token de sessão (ex: token-1). Enviado como Authorization: Bearer.")
    parser.add_argument("--cookie", default=None, help="Cookie de sessão bruto, ex: 'sessao=token-1'")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout por requisição (s)")

    parser.add_argument("--dramatic", action="store_true",
                        help="Modo cinematográfico: adiciona delays para a gravação do vídeo")
    parser.add_argument("--delay", type=float, default=0.12,
                        help="Delay (s) entre requisições no modo --dramatic (padrão: 0.12)")

    parser.add_argument("--export", action="store_true",
                        help="Exporta o resultado em JSON e HTML")
    parser.add_argument("--saida", default="relatorio_idor",
                        help="Prefixo dos arquivos de saída (padrão: relatorio_idor)")

    parser.add_argument("--explicar", action="store_true",
                        help="Mostra o módulo educacional sobre IDOR e sai")
    parser.add_argument("--i-have-authorization", action="store_true",
                        dest="autorizado",
                        help="Confirma que você tem autorização explícita para alvos públicos")

    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    # Modo educacional: explica e encerra.
    if args.explicar:
        explicar_idor()
        return 0

    # A partir daqui precisamos de uma URL.
    if not args.url:
        imprimir_banner()
        imprimir_aviso_legal()
        console.print("\n[bold yellow]Nada para escanear.[/] Informe um alvo com "
                      "[bold]--url[/], ou veja a explicação com [bold]--explicar[/].")
        console.print("Ex.: [cyan]python idor_scanner.py --url "
                      "http://127.0.0.1:5000/api/usuario/ --inicio 1 --fim 50 --meu-id 1[/]\n")
        return 1

    if args.inicio > args.fim:
        console.print("[bold red]Erro:[/] --inicio não pode ser maior que --fim.")
        return 1

    imprimir_banner()
    imprimir_aviso_legal()

    # Trava de escopo (pode abortar aqui se o alvo for público sem autorização).
    verificar_escopo(args.url, args.autorizado)

    console.print()  # respiro visual

    # Executa o scan (TUI ao vivo).
    relatorio = executar_scan(args)

    # Estatísticas + resumo.
    stats = calcular_estatisticas(relatorio)
    console.print()
    imprimir_resumo(relatorio, stats)

    # Exportação opcional.
    if args.export:
        json_path = f"{args.saida}.json"
        html_path = f"{args.saida}.html"
        try:
            exportar_json(relatorio, stats, json_path)
            exportar_html(relatorio, stats, html_path)
            console.print(f"\n[bold green]✓ Relatórios salvos:[/] "
                          f"[cyan]{json_path}[/] e [cyan]{html_path}[/]")
        except OSError as e:
            console.print(f"\n[bold red]Falha ao salvar relatório:[/] {e}")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Interrompido pelo usuário.[/]")
        sys.exit(130)
