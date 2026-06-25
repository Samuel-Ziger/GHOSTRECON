#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║              OSINT SUITE - Unified Intelligence Tool         ║
║          Coleta Passiva de Informações | v1.0.0              ║
║    USO EXCLUSIVO PARA FINS LEGAIS E AUTORIZADOS              ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys
import argparse
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

from modules.social_tracer    import SocialTracer
from modules.email_harvester  import EmailHarvester
from modules.br_people        import BRPeopleOSINT
from modules.asn_mapper       import ASNMapper
from modules.cloud_finder     import CloudFinder
from modules.cert_spy         import CertSpy
from modules.threat_intel     import ThreatIntelAggregator
from modules.dark_web         import DarkWebMonitor
from modules.breach_analyzer  import BreachAnalyzer
from modules.geo_osint        import GeoOSINT
from modules.wigle_mapper     import WiGLEMapper
from modules.phone_osint      import PhoneOSINT
from modules.git_leak         import GitLeakHunter
from modules.brand_watcher    import BrandWatcher
from modules.wayback_miner    import WaybackMiner
from utils.report             import ReportGenerator
from config.settings          import load_config

console = Console()

BANNER = """
[bold cyan]
 ██████╗ ███████╗██╗███╗   ██╗████████╗    ███████╗██╗   ██╗██╗████████╗███████╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ██╔════╝██║   ██║██║╚══██╔══╝██╔════╝
██║   ██║███████╗██║██╔██╗ ██║   ██║       ███████╗██║   ██║██║   ██║   █████╗  
██║   ██║╚════██║██║██║╚██╗██║   ██║       ╚════██║██║   ██║██║   ██║   ██╔══╝  
╚██████╔╝███████║██║██║ ╚████║   ██║       ███████║╚██████╔╝██║   ██║   ███████╗
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝       ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝
[/bold cyan]
[dim]          Passive Intelligence Collection Framework | v1.0.0[/dim]
[bold red]   ⚠  USE ONLY FOR LEGAL, AUTHORIZED PURPOSES | LGPD/Marco Civil Compliant[/bold red]
"""

MODULES = {
    # --- Pessoas & Identidade ---
    "social":   ("SocialTracer",          "Rastreia username em 100+ plataformas"),
    "email":    ("EmailHarvester",        "Coleta e verifica emails de um domínio"),
    "brpeople": ("BRPeopleOSINT",         "OSINT focado em fontes abertas brasileiras"),
    "phone":    ("PhoneOSINT",            "Inteligência sobre números de telefone"),
    # --- Infraestrutura & Redes ---
    "asn":      ("ASNMapper",             "Mapeia ASNs e blocos de IP de uma organização"),
    "cloud":    ("CloudFinder",           "Descobre buckets S3/Azure/GCS expostos"),
    "cert":     ("CertSpy",              "Extrai subdomínios via Certificate Transparency"),
    # --- Ameaças & Malware ---
    "threat":   ("ThreatIntelAggregator","Consulta IoC em múltiplos feeds de threat intel"),
    "darkweb":  ("DarkWebMonitor",        "Monitora menções em fóruns .onion via Tor"),
    "breach":   ("BreachAnalyzer",        "Analisa e indexa dumps de credenciais"),
    # --- Geolocalização ---
    "geo":      ("GeoOSINT",             "Extrai coordenadas GPS de metadados EXIF"),
    "wigle":    ("WiGLEMapper",           "Localiza redes Wi-Fi por SSID/BSSID"),
    # --- Monitoramento Passivo ---
    "git":      ("GitLeakHunter",         "Busca segredos expostos em repositórios GitHub"),
    "brand":    ("BrandWatcher",          "Monitora menções de marca em fontes abertas"),
    "wayback":  ("WaybackMiner",          "Extrai URLs históricas do Wayback Machine"),
}

def show_banner():
    console.print(BANNER)

def show_modules():
    table = Table(title="Módulos Disponíveis", box=box.ROUNDED, border_style="cyan")
    table.add_column("Flag",    style="bold yellow", width=12)
    table.add_column("Módulo",  style="bold white",  width=24)
    table.add_column("Descrição", style="dim white")

    categories = {
        "👤 Pessoas & Identidade":      ["social","email","brpeople","phone"],
        "🌐 Infraestrutura & Redes":    ["asn","cloud","cert"],
        "🛡  Ameaças & Malware":         ["threat","darkweb","breach"],
        "📍 Geolocalização":            ["geo","wigle"],
        "👁  Monitoramento Passivo":     ["git","brand","wayback"],
    }

    for cat, keys in categories.items():
        table.add_row(f"[bold cyan]{cat}[/bold cyan]", "", "")
        for k in keys:
            name, desc = MODULES[k]
            table.add_row(f"  --{k}", name, desc)

    console.print(table)

def run_all_modules(args, config):
    """Executa todos os módulos aplicáveis ao target."""
    results = {}
    target  = args.target

    console.print(Panel(f"[bold]Iniciando varredura completa em:[/bold] [cyan]{target}[/cyan]",
                        border_style="yellow"))

    runners = {
        "social":   lambda: SocialTracer(config).run(target),
        "email":    lambda: EmailHarvester(config).run(target),
        "cert":     lambda: CertSpy(config).run(target),
        "asn":      lambda: ASNMapper(config).run(target),
        "cloud":    lambda: CloudFinder(config).run(target),
        "git":      lambda: GitLeakHunter(config).run(target),
        "brand":    lambda: BrandWatcher(config).run(target),
        "wayback":  lambda: WaybackMiner(config).run(target),
        "threat":   lambda: ThreatIntelAggregator(config).run(target),
    }

    for key, fn in runners.items():
        name, _ = MODULES[key]
        with console.status(f"[cyan]Executando {name}...[/cyan]"):
            try:
                results[key] = fn()
                console.print(f"  [green]✓[/green] {name} concluído")
            except Exception as e:
                console.print(f"  [red]✗[/red] {name} falhou: {e}")
                results[key] = {"error": str(e)}

    return results

def dispatch(args, config):
    """Roteia para o módulo correto baseado nos flags."""
    module_map = {
        "social":   SocialTracer,
        "email":    EmailHarvester,
        "brpeople": BRPeopleOSINT,
        "phone":    PhoneOSINT,
        "asn":      ASNMapper,
        "cloud":    CloudFinder,
        "cert":     CertSpy,
        "threat":   ThreatIntelAggregator,
        "darkweb":  DarkWebMonitor,
        "breach":   BreachAnalyzer,
        "geo":      GeoOSINT,
        "wigle":    WiGLEMapper,
        "git":      GitLeakHunter,
        "brand":    BrandWatcher,
        "wayback":  WaybackMiner,
    }

    # Determina quais módulos rodar
    active = [k for k in module_map if getattr(args, k, False)]

    if not active and not args.all:
        console.print("[red]Nenhum módulo selecionado. Use --all ou escolha módulos com --<nome>.[/red]")
        console.print("Use [bold]--list[/bold] para ver os módulos disponíveis.")
        sys.exit(1)

    results = {}

    if args.all:
        results = run_all_modules(args, config)
    else:
        for key in active:
            cls  = module_map[key]
            name = MODULES[key][0]
            with console.status(f"[cyan]Executando {name}...[/cyan]"):
                try:
                    results[key] = cls(config).run(args.target)
                    console.print(f"  [green]✓[/green] {name} concluído")
                except Exception as e:
                    console.print(f"  [red]✗[/red] {name} falhou: {e}")
                    results[key] = {"error": str(e)}

    # Gera relatório
    if results:
        rg = ReportGenerator(args.target, results)
        if args.output == "html" or args.output == "all":
            path = rg.generate_html()
            console.print(f"\n[bold green]Relatório HTML:[/bold green] {path}")
        if args.output == "json" or args.output == "all":
            path = rg.generate_json()
            console.print(f"[bold green]Relatório JSON:[/bold green] {path}")
        if args.output == "csv" or args.output == "all":
            path = rg.generate_csv()
            console.print(f"[bold green]Relatório CSV:[/bold green]  {path}")

def build_parser():
    parser = argparse.ArgumentParser(
        prog="osint-suite",
        description="OSINT Suite — Coleta Passiva de Informações",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("target",         nargs="?", help="Alvo: domínio, email, username, IP, hash, etc.")
    parser.add_argument("--list",         action="store_true", help="Lista todos os módulos disponíveis")
    parser.add_argument("--all",          action="store_true", help="Executa todos os módulos aplicáveis")
    parser.add_argument("--output", "-o", choices=["html","json","csv","all"], default="html",
                        help="Formato do relatório (padrão: html)")
    parser.add_argument("--config", "-c", default="config/settings.yaml",
                        help="Caminho para o arquivo de configuração")
    parser.add_argument("--verbose", "-v", action="store_true", help="Output detalhado")
    parser.add_argument("--tor",          action="store_true", help="Roteia tráfego via Tor (requer Tor rodando)")

    # --- flags de módulos ---
    grp = parser.add_argument_group("Módulos")
    for key, (name, desc) in MODULES.items():
        grp.add_argument(f"--{key}", action="store_true", help=f"{name}: {desc}")

    return parser

def main():
    show_banner()
    parser = build_parser()
    args   = parser.parse_args()

    if args.list:
        show_modules()
        sys.exit(0)

    if not args.target:
        parser.print_help()
        sys.exit(1)

    config = load_config(args.config)
    config["verbose"] = args.verbose
    config["use_tor"] = args.tor

    console.print(f"\n[bold]Target:[/bold] [cyan]{args.target}[/cyan]")
    console.print(f"[bold]Output:[/bold] [yellow]{args.output}[/yellow]\n")

    dispatch(args, config)

if __name__ == "__main__":
    main()
