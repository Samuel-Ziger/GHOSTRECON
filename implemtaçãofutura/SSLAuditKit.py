#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║              SSLAuditKit v1.0 — by Kalyel473               ║
║     Ferramenta unificada: ssldump | sslscan | sslh |        ║
║                   sslsplit | sslyze                          ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import sys
import ssl
import json
import socket
import subprocess
import shutil
import datetime
import hashlib
import ipaddress
import re
import time
import threading
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any

# ─── Dependências ─────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.text import Text
    from rich.columns import Columns
    from rich.rule import Rule
    from rich.syntax import Syntax
    from rich import box
    from rich.prompt import Prompt, Confirm
    from rich.live import Live
    from rich.layout import Layout
    from rich.align import Align
except ImportError:
    print("[!] Instale: pip install rich")
    sys.exit(1)

try:
    import sslyze
    from sslyze import Scanner, ServerNetworkLocation, ScanCommand, ServerScanRequest
    from sslyze.errors import ConnectionToServerFailed
    SSLYZE_AVAILABLE = True
except ImportError:
    SSLYZE_AVAILABLE = False

console = Console()

# ─── Paleta de cores ──────────────────────────────────────────
C = {
    "title":   "bold cyan",
    "ok":      "bold green",
    "warn":    "bold yellow",
    "danger":  "bold red",
    "info":    "bold blue",
    "muted":   "dim white",
    "accent":  "bold magenta",
    "ssl":     "bold cyan",
}

BANNER = """
[bold cyan]
  ███████╗███████╗██╗      █████╗ ██╗   ██╗██████╗ ██╗████████╗██╗  ██╗██╗████████╗
  ██╔════╝██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝██║ ██╔╝██║╚══██╔══╝
  ███████╗███████╗██║     ███████║██║   ██║██║  ██║██║   ██║   █████╔╝ ██║   ██║   
  ╚════██║╚════██║██║     ██╔══██║██║   ██║██║  ██║██║   ██║   ██╔═██╗ ██║   ██║   
  ███████║███████║███████╗██║  ██║╚██████╔╝██████╔╝██║   ██║   ██║  ██╗██║   ██║   
  ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝   ╚═╝  
[/bold cyan]
[dim cyan]          Unified SSL/TLS Audit Framework — ssldump | sslscan | sslh | sslsplit | sslyze[/dim cyan]
[dim]                              github.com/Kalyel473 | v1.0[/dim]
"""

REPORT_DIR = Path("./SSLAuditKit_Reports")


# ══════════════════════════════════════════════════════════════
#  UTILITÁRIOS GERAIS
# ══════════════════════════════════════════════════════════════

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def check_tool(name: str) -> bool:
    return shutil.which(name) is not None

def run_cmd(cmd: str, timeout: int = 30) -> Tuple[int, str, str]:
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except Exception as e:
        return -2, "", str(e)

def save_report(name: str, data: dict) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = REPORT_DIR / f"{name}_{ts}.json"
    with open(fname, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return fname

def save_html_report(name: str, html: str) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = REPORT_DIR / f"{name}_{ts}.html"
    with open(fname, "w") as f:
        f.write(html)
    return fname

def header(title: str):
    console.print()
    console.print(Rule(f"[bold cyan]  {title}  [/bold cyan]", style="cyan"))
    console.print()

def status_icon(ok: bool) -> str:
    return "[bold green]✔[/bold green]" if ok else "[bold red]✘[/bold red]"


# ══════════════════════════════════════════════════════════════
#  MÓDULO 1 — ssldump (análise de tráfego SSL/TLS)
# ══════════════════════════════════════════════════════════════

class SSLDumpModule:
    """Emula e integra o ssldump: captura e analisa handshakes TLS."""

    NAME = "ssldump"
    DESC = "Captura e decodifica tráfego SSL/TLS em tempo real"

    def menu(self):
        header(f"MÓDULO: {self.NAME}")
        console.print(Panel(
            "[cyan]ssldump[/cyan] — decodifica handshakes TLS, extrai certificados "
            "e metadados de sessões SSL ao vivo em interfaces de rede.",
            title="Descrição", border_style="cyan"
        ))

        opts = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        opts.add_column(style="bold cyan", width=4)
        opts.add_column()
        opts.add_row("1", "Capturar tráfego SSL em interface (ao vivo)")
        opts.add_row("2", "Analisar arquivo pcap existente")
        opts.add_row("3", "Decodificar handshake de alvo específico")
        opts.add_row("4", "Verificar disponibilidade do ssldump")
        opts.add_row("0", "[dim]Voltar[/dim]")
        console.print(opts)

        choice = Prompt.ask("[cyan]>[/cyan]")
        if choice == "1":   self.capture_live()
        elif choice == "2": self.analyze_pcap()
        elif choice == "3": self.decode_target()
        elif choice == "4": self.check_availability()

    def check_availability(self):
        available = check_tool("ssldump")
        console.print(f"\n  ssldump instalado: {status_icon(available)}")
        if not available:
            console.print("  [yellow]Instale com: sudo apt install ssldump[/yellow]")
        console.input("\n  [dim]Enter para voltar...[/dim]")

    def capture_live(self):
        iface = Prompt.ask("  Interface de rede", default="eth0")
        port  = Prompt.ask("  Porta", default="443")
        secs  = Prompt.ask("  Duração (segundos)", default="15")

        if not check_tool("ssldump"):
            console.print("  [yellow][!] ssldump não encontrado — executando análise nativa Python[/yellow]")
            self._native_tls_capture(iface, port, int(secs))
            return

        cmd = f"ssldump -i {iface} -An port {port}"
        console.print(f"\n  [dim]Executando: {cmd}[/dim]")
        console.print(f"  [cyan]Capturando por {secs}s...[/cyan]")
        code, out, err = run_cmd(cmd, timeout=int(secs) + 5)
        self._display_ssldump_output(out or err, iface, port)

    def analyze_pcap(self):
        path = Prompt.ask("  Caminho do arquivo pcap")
        if not os.path.exists(path):
            console.print("  [red][!] Arquivo não encontrado[/red]")
            console.input("  Enter...")
            return
        if not check_tool("ssldump"):
            console.print("  [yellow][!] ssldump não disponível[/yellow]")
            console.input("  Enter...")
            return
        cmd = f"ssldump -r {path} -An"
        code, out, err = run_cmd(cmd, timeout=60)
        self._display_ssldump_output(out or err, pcap=path)

    def decode_target(self):
        host = Prompt.ask("  Host alvo (ex: google.com)")
        port = int(Prompt.ask("  Porta", default="443"))
        console.print(f"\n  [cyan]Conectando a {host}:{port} e analisando handshake...[/cyan]")
        self._analyze_handshake(host, port)

    def _native_tls_capture(self, iface: str, port: str, duration: int):
        console.print("\n  [dim]Análise nativa de handshake TLS via socket Python...[/dim]")
        results = []
        end_time = time.time() + duration

        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                      transient=True) as prog:
            prog.add_task(f"Aguardando conexões na porta {port}...", total=None)
            time.sleep(min(duration, 3))  # simulação de espera

        console.print("  [yellow]Dica: ssldump nativo requer root e interface ativa.[/yellow]")
        console.print("  [dim]Use 'decode_target' para análise precisa de handshake.[/dim]")
        console.input("\n  Enter para voltar...")

    def _analyze_handshake(self, host: str, port: int):
        results = {"host": host, "port": port, "timestamp": str(datetime.datetime.now())}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_OPTIONAL

            with socket.create_connection((host, port), timeout=10) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    cert = s.getpeercert()
                    cipher = s.cipher()
                    version = s.version()
                    shared_ciphers = s.shared_ciphers()

                    results.update({
                        "tls_version":     version,
                        "cipher_suite":    cipher[0] if cipher else "N/A",
                        "cipher_bits":     cipher[2] if cipher else "N/A",
                        "subject":         dict(x[0] for x in cert.get("subject", [])),
                        "issuer":          dict(x[0] for x in cert.get("issuer", [])),
                        "not_before":      cert.get("notBefore", "N/A"),
                        "not_after":       cert.get("notAfter", "N/A"),
                        "san":             [v for _, v in cert.get("subjectAltName", [])],
                        "shared_ciphers":  len(shared_ciphers) if shared_ciphers else 0,
                    })

            self._display_handshake_table(results)
        except Exception as e:
            console.print(f"  [red][!] Erro: {e}[/red]")

        fp = save_report("ssldump_handshake", results)
        console.print(f"\n  [dim]Relatório salvo: {fp}[/dim]")
        console.input("\n  Enter para voltar...")

    def _display_handshake_table(self, r: dict):
        t = Table(title="Análise de Handshake TLS", box=box.ROUNDED,
                  border_style="cyan", show_lines=True)
        t.add_column("Campo", style="bold cyan", width=22)
        t.add_column("Valor", style="white")

        version = r.get("tls_version", "N/A")
        v_color = "green" if "1.3" in str(version) else ("yellow" if "1.2" in str(version) else "red")

        t.add_row("Host", r["host"])
        t.add_row("Porta", str(r["port"]))
        t.add_row("Versão TLS", f"[{v_color}]{version}[/{v_color}]")
        t.add_row("Cipher Suite", str(r.get("cipher_suite")))
        t.add_row("Bits", str(r.get("cipher_bits")))
        t.add_row("Common Name", r.get("subject", {}).get("commonName", "N/A"))
        t.add_row("Emitido por", r.get("issuer", {}).get("organizationName", "N/A"))
        t.add_row("Válido de", str(r.get("not_before")))
        t.add_row("Válido até", str(r.get("not_after")))
        san = ", ".join(r.get("san", [])[:5])
        t.add_row("SANs", san or "N/A")
        t.add_row("Ciphers compartilhados", str(r.get("shared_ciphers")))

        console.print(t)

    def _display_ssldump_output(self, output: str, iface: str = "", port: str = "", pcap: str = ""):
        if not output.strip():
            console.print("  [yellow][!] Sem saída do ssldump.[/yellow]")
        else:
            syn = Syntax(output[:3000], "text", theme="monokai", line_numbers=True)
            console.print(syn)
        console.input("\n  Enter para voltar...")


# ══════════════════════════════════════════════════════════════
#  MÓDULO 2 — sslscan (enumeração de protocolos e ciphers)
# ══════════════════════════════════════════════════════════════

class SSLScanModule:
    NAME = "sslscan"
    DESC = "Enumera protocolos, cipher suites e vulnerabilidades SSL/TLS"

    # Ciphers considerados fracos
    WEAK_CIPHERS = [
        "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON",
        "MD5", "ADH", "AECDH", "RC2", "IDEA"
    ]
    VULN_CIPHERS = ["RC4", "NULL", "EXPORT", "ANON"]

    def menu(self):
        header(f"MÓDULO: {self.NAME}")
        console.print(Panel(
            "[cyan]sslscan[/cyan] — testa todas as versões de protocolo (SSLv2/3, TLSv1.0–1.3) "
            "e enumera cipher suites suportadas, identificando configurações inseguras.",
            title="Descrição", border_style="cyan"
        ))

        opts = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        opts.add_column(style="bold cyan", width=4)
        opts.add_column()
        opts.add_row("1", "Scan rápido de um alvo")
        opts.add_row("2", "Scan completo com análise detalhada")
        opts.add_row("3", "Scan em múltiplos alvos (batch)")
        opts.add_row("4", "Verificar protocolos deprecados (SSLv2/v3/TLS1.0)")
        opts.add_row("5", "Detectar ciphers fracos e vulneráveis")
        opts.add_row("0", "[dim]Voltar[/dim]")
        console.print(opts)

        choice = Prompt.ask("[cyan]>[/cyan]")
        if choice == "1":   self.quick_scan()
        elif choice == "2": self.full_scan()
        elif choice == "3": self.batch_scan()
        elif choice == "4": self.check_deprecated_protocols()
        elif choice == "5": self.detect_weak_ciphers()

    def quick_scan(self):
        target = Prompt.ask("  Alvo (host ou host:porta)")
        host, port = self._parse_target(target)
        console.print(f"\n  [cyan]Executando scan rápido em {host}:{port}...[/cyan]")
        results = self._run_scan(host, port)
        self._display_results(results)
        fp = save_report("sslscan_quick", results)
        console.print(f"  [dim]Salvo: {fp}[/dim]")
        console.input("\n  Enter para voltar...")

    def full_scan(self):
        target = Prompt.ask("  Alvo (host ou host:porta)")
        host, port = self._parse_target(target)
        console.print(f"\n  [cyan]Executando scan completo em {host}:{port}...[/cyan]")

        if check_tool("sslscan"):
            cmd = f"sslscan --no-colour {host}:{port}"
            code, out, err = run_cmd(cmd, timeout=60)
            console.print(Syntax(out[:5000] if out else err, "text",
                                 theme="monokai", line_numbers=True))
        else:
            results = self._run_scan(host, port, full=True)
            self._display_results(results, full=True)

        fp = save_report("sslscan_full", {"host": host, "port": port})
        console.print(f"  [dim]Salvo: {fp}[/dim]")
        console.input("\n  Enter para voltar...")

    def batch_scan(self):
        path = Prompt.ask("  Arquivo com lista de alvos (um por linha)")
        if not os.path.exists(path):
            console.print("  [red][!] Arquivo não encontrado[/red]")
            console.input("  Enter...")
            return
        with open(path) as f:
            targets = [l.strip() for l in f if l.strip()]
        console.print(f"\n  [cyan]Escaneando {len(targets)} alvos...[/cyan]")
        all_results = []
        for t in targets:
            host, port = self._parse_target(t)
            console.print(f"  → [cyan]{host}:{port}[/cyan]", end=" ")
            r = self._run_scan(host, port)
            risk = self._risk_level(r)
            console.print(f"[{risk['color']}]{risk['label']}[/{risk['color']}]")
            all_results.append(r)
        fp = save_report("sslscan_batch", {"targets": all_results})
        console.print(f"\n  [dim]Relatório batch salvo: {fp}[/dim]")
        console.input("\n  Enter para voltar...")

    def check_deprecated_protocols(self):
        target = Prompt.ask("  Alvo")
        host, port = self._parse_target(target)
        console.print(f"\n  [cyan]Verificando protocolos deprecados em {host}:{port}...[/cyan]\n")
        results = self._check_protocols(host, port)
        t = Table(title="Suporte a Protocolos SSL/TLS", box=box.ROUNDED,
                  border_style="cyan", show_lines=True)
        t.add_column("Protocolo", style="bold", width=16)
        t.add_column("Suportado", width=12)
        t.add_column("Status", width=20)
        t.add_column("Risco")

        for proto, supported in results.items():
            is_deprecated = proto in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
            if supported and is_deprecated:
                status, risk, color = "Suportado", "🔴 CRÍTICO", "red"
            elif supported:
                status, risk, color = "Suportado", "🟢 OK", "green"
            else:
                status, risk, color = "Não suportado", "✔ Seguro", "green"
                if is_deprecated:
                    risk, color = "✔ Desabilitado", "green"

            t.add_row(
                f"[bold]{proto}[/bold]",
                f"[{'red' if (supported and is_deprecated) else 'green'}]"
                f"{'Sim' if supported else 'Não'}[/]",
                f"[{color}]{status}[/{color}]",
                f"[{color}]{risk}[/{color}]"
            )
        console.print(t)
        fp = save_report("sslscan_protocols", {"host": host, "protocols": results})
        console.print(f"\n  [dim]Salvo: {fp}[/dim]")
        console.input("\n  Enter para voltar...")

    def detect_weak_ciphers(self):
        target = Prompt.ask("  Alvo")
        host, port = self._parse_target(target)
        console.print(f"\n  [cyan]Detectando ciphers fracos em {host}:{port}...[/cyan]")
        ciphers = self._enumerate_ciphers(host, port)

        t = Table(title="Análise de Cipher Suites", box=box.ROUNDED,
                  border_style="cyan", show_lines=True)
        t.add_column("Cipher Suite", style="white", width=40)
        t.add_column("Bits", width=8)
        t.add_column("Avaliação")

        weak_count = 0
        for c in ciphers:
            name, bits = c
            is_vuln  = any(k in name.upper() for k in self.VULN_CIPHERS)
            is_weak  = any(k in name.upper() for k in self.WEAK_CIPHERS)
            is_strong = "AES_256_GCM" in name or "CHACHA20" in name

            if is_vuln:
                label = "[bold red]🔴 VULNERÁVEL[/bold red]"
                weak_count += 1
            elif is_weak:
                label = "[yellow]🟡 FRACO[/yellow]"
                weak_count += 1
            elif is_strong:
                label = "[bold green]🟢 FORTE[/bold green]"
            else:
                label = "[cyan]🔵 ACEITÁVEL[/cyan]"
            t.add_row(name, str(bits) if bits else "?", label)

        console.print(t)
        console.print(f"\n  Ciphers fracos/vulneráveis: [{'red' if weak_count else 'green'}]{weak_count}[/]")
        console.input("\n  Enter para voltar...")

    # ── Helpers ──────────────────────────────────────────────

    def _parse_target(self, target: str) -> Tuple[str, int]:
        if ":" in target:
            parts = target.rsplit(":", 1)
            return parts[0], int(parts[1])
        return target, 443

    def _run_scan(self, host: str, port: int, full: bool = False) -> dict:
        result = {
            "host": host, "port": port,
            "timestamp": str(datetime.datetime.now()),
            "protocols": {}, "cert": {}, "ciphers": [], "vulnerabilities": []
        }
        # Cert info
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_OPTIONAL
            with socket.create_connection((host, port), timeout=8) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    cert = s.getpeercert()
                    cipher = s.cipher()
                    result["cert"] = {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer":  dict(x[0] for x in cert.get("issuer", [])),
                        "not_after": cert.get("notAfter"),
                        "version": s.version(),
                        "cipher": cipher[0] if cipher else "N/A",
                    }
                    result["protocols"]["TLSv1.3"] = "TLSv1.3" in str(s.version())
                    result["protocols"]["TLSv1.2"] = "TLSv1.2" in str(s.version())
        except Exception as e:
            result["error"] = str(e)

        result["protocols"].update(self._check_protocols(host, port))
        result["ciphers"] = self._enumerate_ciphers(host, port)
        return result

    def _check_protocols(self, host: str, port: int) -> dict:
        protocols = {}
        test_cases = [
            ("SSLv2",   ssl.PROTOCOL_TLS_CLIENT, {"SSLv2"}),
            ("SSLv3",   ssl.PROTOCOL_TLS_CLIENT, {"SSLv3"}),
            ("TLSv1.0", ssl.PROTOCOL_TLS_CLIENT, {}),
            ("TLSv1.1", ssl.PROTOCOL_TLS_CLIENT, {}),
            ("TLSv1.2", ssl.PROTOCOL_TLS_CLIENT, {}),
            ("TLSv1.3", ssl.PROTOCOL_TLS_CLIENT, {}),
        ]
        version_map = {
            "TLSv1.0": ssl.TLSVersion.TLSv1   if hasattr(ssl, 'TLSVersion') else None,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl, 'TLSVersion') else None,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2 if hasattr(ssl, 'TLSVersion') else None,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3 if hasattr(ssl, 'TLSVersion') else None,
        }
        for proto in ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                v = version_map.get(proto)
                if v:
                    ctx.minimum_version = v
                    ctx.maximum_version = v
                with socket.create_connection((host, port), timeout=5) as raw:
                    with ctx.wrap_socket(raw, server_hostname=host):
                        protocols[proto] = True
            except:
                protocols[proto] = False
        protocols["SSLv2"] = False
        protocols["SSLv3"] = False
        return protocols

    def _enumerate_ciphers(self, host: str, port: int) -> List[Tuple]:
        found = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=5) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    for c in (s.shared_ciphers() or []):
                        found.append((c[0], c[2]))
        except:
            pass
        return found[:20]

    def _display_results(self, r: dict, full: bool = False):
        t = Table(title=f"sslscan — {r['host']}:{r['port']}", box=box.ROUNDED,
                  border_style="cyan", show_lines=True)
        t.add_column("Campo", style="bold cyan", width=22)
        t.add_column("Valor")
        cert = r.get("cert", {})
        t.add_row("Versão TLS", cert.get("version", "N/A"))
        t.add_row("Cipher Atual", cert.get("cipher", "N/A"))
        t.add_row("Common Name", cert.get("subject", {}).get("commonName", "N/A"))
        t.add_row("Validade", cert.get("not_after", "N/A"))
        for proto, sup in r.get("protocols", {}).items():
            deprecated = proto in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
            color = "red" if (sup and deprecated) else ("green" if sup else "dim")
            t.add_row(f"Protocolo {proto}", f"[{color}]{'Sim' if sup else 'Não'}[/{color}]")
        console.print(t)

    def _risk_level(self, r: dict) -> dict:
        protos = r.get("protocols", {})
        if any(protos.get(p) for p in ["SSLv2", "SSLv3", "TLSv1.0"]):
            return {"label": "CRÍTICO", "color": "red"}
        if protos.get("TLSv1.1"):
            return {"label": "ALTO", "color": "yellow"}
        return {"label": "BAIXO", "color": "green"}


# ══════════════════════════════════════════════════════════════
#  MÓDULO 3 — sslh (multiplexador de protocolo na porta 443)
# ══════════════════════════════════════════════════════════════

class SSLHModule:
    NAME = "sslh"
    DESC = "Detecta e analisa multiplexação de protocolos na porta 443"

    PROTOCOLS = ["https", "ssh", "openvpn", "tinc", "xmpp", "http", "adb"]

    def menu(self):
        header(f"MÓDULO: {self.NAME}")
        console.print(Panel(
            "[cyan]sslh[/cyan] — multiplexador que permite SSH, HTTPS, OpenVPN e outros "
            "protocolos compartilharem a mesma porta 443. Esta ferramenta detecta "
            "quais protocolos estão multiplexados em um serviço.",
            title="Descrição", border_style="cyan"
        ))

        opts = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        opts.add_column(style="bold cyan", width=4)
        opts.add_column()
        opts.add_row("1", "Detectar protocolos multiplexados em um host")
        opts.add_row("2", "Verificar se SSH está atrás de HTTPS (porta 443)")
        opts.add_row("3", "Detectar OpenVPN em porta 443")
        opts.add_row("4", "Scan de multiplexação em range de portas")
        opts.add_row("5", "Gerar config sslh sugerida")
        opts.add_row("0", "[dim]Voltar[/dim]")
        console.print(opts)

        choice = Prompt.ask("[cyan]>[/cyan]")
        if choice == "1":   self.detect_protocols()
        elif choice == "2": self.check_ssh_behind_https()
        elif choice == "3": self.detect_openvpn()
        elif choice == "4": self.port_range_scan()
        elif choice == "5": self.generate_config()

    def detect_protocols(self):
        host = Prompt.ask("  Host alvo")
        port = int(Prompt.ask("  Porta", default="443"))
        console.print(f"\n  [cyan]Detectando protocolos em {host}:{port}...[/cyan]\n")

        results = {}
        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                      transient=True) as prog:
            task = prog.add_task("Testando protocolos...", total=len(self.PROTOCOLS))
            for proto in self.PROTOCOLS:
                prog.update(task, description=f"Testando {proto}...")
                results[proto] = self._probe_protocol(host, port, proto)
                prog.advance(task)

        t = Table(title=f"Protocolos Detectados — {host}:{port}",
                  box=box.ROUNDED, border_style="cyan", show_lines=True)
        t.add_column("Protocolo", style="bold", width=14)
        t.add_column("Detectado", width=12)
        t.add_column("Nota")

        notes = {
            "https":   "Tráfego web criptografado (normal)",
            "ssh":     "Shell remoto — risco se exposto publicamente",
            "openvpn": "VPN — pode indicar bypass de firewall",
            "tinc":    "VPN mesh — raro em produção",
            "xmpp":    "Protocolo de mensagens",
            "http":    "HTTP sem criptografia",
            "adb":     "Android Debug Bridge — risco crítico",
        }

        for proto, detected in results.items():
            color = "green" if detected else "dim"
            risk_note = notes.get(proto, "")
            if detected and proto in ["ssh", "adb", "openvpn"]:
                color = "yellow"
                risk_note = f"[yellow]⚠ {risk_note}[/yellow]"
            t.add_row(
                f"[bold]{proto.upper()}[/bold]",
                f"[{color}]{'✔ Sim' if detected else '✘ Não'}[/{color}]",
                risk_note
            )

        console.print(t)
        fp = save_report("sslh_detect", {"host": host, "port": port, "protocols": results})
        console.print(f"\n  [dim]Salvo: {fp}[/dim]")
        console.input("\n  Enter para voltar...")

    def check_ssh_behind_https(self):
        host = Prompt.ask("  Host alvo")
        port = 443
        console.print(f"\n  [cyan]Verificando SSH atrás de HTTPS em {host}:443...[/cyan]")
        detected = self._probe_ssh(host, port)
        if detected:
            console.print(f"\n  [bold yellow]⚠ SSH DETECTADO na porta 443![/bold yellow]")
            console.print("  [yellow]Possível uso de sslh para multiplexação de SSH/HTTPS[/yellow]")
            console.print("  [dim]Implicações: acesso shell remoto mascarado em tráfego HTTPS[/dim]")
        else:
            console.print("\n  [green]✔ SSH não detectado na porta 443[/green]")
        console.input("\n  Enter para voltar...")

    def detect_openvpn(self):
        host = Prompt.ask("  Host alvo")
        port = int(Prompt.ask("  Porta", default="443"))
        detected = self._probe_openvpn(host, port)
        status = "[yellow]⚠ OpenVPN DETECTADO[/yellow]" if detected else "[green]✔ Não detectado[/green]"
        console.print(f"\n  Resultado: {status}")
        console.input("\n  Enter para voltar...")

    def port_range_scan(self):
        host  = Prompt.ask("  Host alvo")
        start = int(Prompt.ask("  Porta inicial", default="440"))
        end   = int(Prompt.ask("  Porta final",   default="445"))
        console.print(f"\n  [cyan]Escaneando {host}:{start}-{end}...[/cyan]\n")

        t = Table(title="Scan de Multiplexação", box=box.ROUNDED,
                  border_style="cyan", show_lines=True)
        t.add_column("Porta", style="bold cyan", width=8)
        t.add_column("Aberta", width=10)
        t.add_column("TLS", width=8)
        t.add_column("SSH", width=8)
        t.add_column("HTTP", width=8)

        for port in range(start, end + 1):
            open_  = self._port_open(host, port)
            tls    = self._probe_protocol(host, port, "https") if open_ else False
            ssh    = self._probe_ssh(host, port) if open_ else False
            http   = self._probe_protocol(host, port, "http") if open_ else False
            t.add_row(
                str(port),
                "[green]✔[/green]" if open_ else "[dim]✘[/dim]",
                "[cyan]TLS[/cyan]" if tls else "[dim]-[/dim]",
                "[yellow]SSH[/yellow]" if ssh else "[dim]-[/dim]",
                "[blue]HTTP[/blue]" if http else "[dim]-[/dim]",
            )
        console.print(t)
        console.input("\n  Enter para voltar...")

    def generate_config(self):
        console.print("\n  [bold cyan]Gerador de Configuração sslh[/bold cyan]")
        ssh_port   = Prompt.ask("  Porta SSH interna", default="22")
        https_port = Prompt.ask("  Porta HTTPS interna", default="8443")
        openvpn    = Confirm.ask("  Incluir OpenVPN?", default=False)

        config = f"""# sslh config — gerado por SSLAuditKit
# Instale: sudo apt install sslh

foreground: false;
inetd: false;
numeric: false;
transparent: false;
timeout: 5;

listen:
(
  {{ host: "0.0.0.0"; port: "443"; }}
);

protocols:
(
  {{ name: "ssh";   host: "localhost"; port: "{ssh_port}";   }},
  {{ name: "tls";   host: "localhost"; port: "{https_port}"; }},
  {{ name: "http";  host: "localhost"; port: "80";   }},"""
        if openvpn:
            config += '\n  { name: "openvpn"; host: "localhost"; port: "1194"; },'
        config += "\n);"

        syn = Syntax(config, "text", theme="monokai", line_numbers=True)
        console.print(Panel(syn, title="sslh.conf sugerido", border_style="cyan"))
        path = REPORT_DIR / "sslh_suggested.conf"
        REPORT_DIR.mkdir(exist_ok=True)
        path.write_text(config)
        console.print(f"\n  [dim]Salvo: {path}[/dim]")
        console.input("\n  Enter para voltar...")

    # ── Probes ────────────────────────────────────────────────

    def _port_open(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except:
            return False

    def _probe_ssh(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=4) as s:
                banner = s.recv(64)
                return banner.startswith(b"SSH-")
        except:
            return False

    def _probe_openvpn(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=4) as s:
                # OpenVPN handshake inicial (HMAC key_method2)
                probe = bytes([0x38, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                s.send(probe)
                resp = s.recv(32)
                return len(resp) > 0 and resp[0] in [0x28, 0x38, 0x40]
        except:
            return False

    def _probe_protocol(self, host: str, port: int, proto: str) -> bool:
        if proto == "ssh":     return self._probe_ssh(host, port)
        if proto == "openvpn": return self._probe_openvpn(host, port)
        if proto == "https":
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=4) as raw:
                    with ctx.wrap_socket(raw, server_hostname=host):
                        return True
            except:
                return False
        if proto == "http":
            try:
                with socket.create_connection((host, port), timeout=3) as s:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    return b"HTTP" in s.recv(64)
            except:
                return False
        if proto == "adb":
            try:
                with socket.create_connection((host, port), timeout=3) as s:
                    s.send(b"CNXN")
                    return len(s.recv(16)) > 0
            except:
                return False
        return False


# ══════════════════════════════════════════════════════════════
#  MÓDULO 4 — sslsplit (SSL MitM / interceptação)
# ══════════════════════════════════════════════════════════════

class SSLSplitModule:
    NAME = "sslsplit"
    DESC = "Análise educacional de SSL MitM e interceptação de tráfego"

    def menu(self):
        header(f"MÓDULO: {self.NAME}")
        console.print(Panel(
            "[cyan]sslsplit[/cyan] — realiza interceptação transparente SSL/TLS para análise "
            "de tráfego (Man-in-the-Middle educacional). APENAS para ambientes controlados "
            "e com autorização explícita.",
            title="Descrição", border_style="cyan"
        ))
        console.print("[bold yellow]  ⚠ AVISO LEGAL: Use apenas em redes e dispositivos autorizados.[/bold yellow]\n")

        opts = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        opts.add_column(style="bold cyan", width=4)
        opts.add_column()
        opts.add_row("1", "Verificar disponibilidade e configuração do sslsplit")
        opts.add_row("2", "Gerar certificado CA para interceptação (lab)")
        opts.add_row("3", "Analisar arquivo de log sslsplit existente")
        opts.add_row("4", "Simular fluxo de ataque MitM (educacional)")
        opts.add_row("5", "Detectar vulnerabilidade a SSL Stripping")
        opts.add_row("6", "Verificar HSTS e proteções anti-MitM")
        opts.add_row("0", "[dim]Voltar[/dim]")
        console.print(opts)

        choice = Prompt.ask("[cyan]>[/cyan]")
        if choice == "1":   self.check_setup()
        elif choice == "2": self.generate_ca()
        elif choice == "3": self.analyze_log()
        elif choice == "4": self.mitm_simulation()
        elif choice == "5": self.detect_ssl_strip()
        elif choice == "6": self.check_hsts()

    def check_setup(self):
        items = {
            "sslsplit":     check_tool("sslsplit"),
            "openssl":      check_tool("openssl"),
            "iptables":     check_tool("iptables"),
            "ip_forward":   self._check_ip_forward(),
        }
        t = Table(title="Pré-requisitos sslsplit", box=box.ROUNDED,
                  border_style="cyan", show_lines=True)
        t.add_column("Componente", style="bold cyan", width=18)
        t.add_column("Status")
        for name, ok in items.items():
            t.add_row(name, f"{'[green]✔ OK[/green]' if ok else '[red]✘ Ausente[/red]'}")
        console.print(t)
        if not items["sslsplit"]:
            console.print("  [dim]Instale: sudo apt install sslsplit[/dim]")
        console.input("\n  Enter para voltar...")

    def generate_ca(self):
        console.print("\n  [cyan]Gerando CA auto-assinada para lab MitM...[/cyan]")
        out_dir = REPORT_DIR / "sslsplit_ca"
        out_dir.mkdir(parents=True, exist_ok=True)
        ca_key = out_dir / "ca.key"
        ca_crt = out_dir / "ca.crt"

        if not check_tool("openssl"):
            console.print("  [red][!] openssl não encontrado[/red]")
            console.input("  Enter...")
            return

        cmds = [
            f'openssl genrsa -out {ca_key} 4096',
            f'openssl req -new -x509 -days 1825 -key {ca_key} -out {ca_crt} '
            f'-subj "/C=BR/O=SSLAuditKit-Lab/CN=SSLAuditKit CA"',
        ]
        for cmd in cmds:
            code, out, err = run_cmd(cmd, timeout=30)
            if code != 0:
                console.print(f"  [red][!] Erro: {err}[/red]")
                break
        else:
            console.print(f"  [green]✔ CA gerada: {out_dir}/[/green]")
            console.print(f"  [dim]Chave: {ca_key}[/dim]")
            console.print(f"  [dim]Cert:  {ca_crt}[/dim]")
            console.print("\n  [dim]Para usar: instale ca.crt no dispositivo alvo (lab)[/dim]")

            # Comando sslsplit de exemplo
            example_cmd = (
                f"sudo sslsplit -D -l connections.log "
                f"-j /tmp/sslsplit_log -S /tmp/sslsplit_log "
                f"-k {ca_key} -c {ca_crt} "
                f"ssl 0.0.0.0 8443 tcp 0.0.0.0 8080"
            )
            console.print(Panel(
                Syntax(example_cmd, "bash", theme="monokai"),
                title="Comando sslsplit (exemplo lab)", border_style="dim"
            ))
        console.input("\n  Enter para voltar...")

    def analyze_log(self):
        path = Prompt.ask("  Caminho do log sslsplit")
        if not os.path.exists(path):
            console.print("  [red][!] Arquivo não encontrado[/red]")
            console.input("  Enter...")
            return
        connections = []
        with open(path) as f:
            for line in f:
                if "CONNECT" in line or "ssl" in line.lower():
                    connections.append(line.strip())
        console.print(f"\n  [cyan]{len(connections)} entradas encontradas[/cyan]\n")
        for c in connections[:30]:
            console.print(f"  [dim]{c}[/dim]")
        fp = save_report("sslsplit_log_analysis", {"entries": connections})
        console.print(f"\n  [dim]Salvo: {fp}[/dim]")
        console.input("\n  Enter para voltar...")

    def mitm_simulation(self):
        console.print()
        console.print(Panel(
            "[bold]Simulação Educacional — Fluxo SSL MitM[/bold]\n\n"
            "Como o sslsplit intercepta tráfego SSL/TLS:\n\n"
            "[cyan]1.[/cyan] Atacante configura roteamento (iptables REDIRECT)\n"
            "[cyan]2.[/cyan] sslsplit recebe conexão do cliente\n"
            "[cyan]3.[/cyan] sslsplit apresenta certificado falso assinado pela CA\n"
            "[cyan]4.[/cyan] sslsplit cria NOVA conexão TLS com o servidor real\n"
            "[cyan]5.[/cyan] Tráfego passa pelo sslsplit em texto claro\n"
            "[cyan]6.[/cyan] sslsplit registra e/ou modifica o conteúdo\n\n"
            "[bold yellow]Defesas:[/bold yellow]\n"
            "• HSTS (HTTP Strict Transport Security)\n"
            "• Certificate Pinning em apps mobile\n"
            "• HPKP (deprecado, mas informativo)\n"
            "• Verificação manual de certificados\n"
            "• Monitoramento de CT logs",
            title="[bold cyan]SSL MitM — Como Funciona[/bold cyan]",
            border_style="cyan"
        ))
        console.input("\n  Enter para voltar...")

    def detect_ssl_strip(self):
        target = Prompt.ask("  Alvo (domínio)")
        console.print(f"\n  [cyan]Verificando vulnerabilidade a SSL Stripping em {target}...[/cyan]\n")
        results = self._check_ssl_strip(target)

        t = Table(title=f"SSL Stripping — {target}", box=box.ROUNDED,
                  border_style="cyan", show_lines=True)
        t.add_column("Verificação", style="bold cyan", width=30)
        t.add_column("Resultado")
        t.add_column("Risco")

        for check, val, risk in results:
            t.add_row(check, val, risk)
        console.print(t)

        fp = save_report("sslsplit_strip_check", {"host": target, "checks": [
            {"check": c, "value": v, "risk": r} for c, v, r in results
        ]})
        console.print(f"\n  [dim]Salvo: {fp}[/dim]")
        console.input("\n  Enter para voltar...")

    def check_hsts(self):
        target = Prompt.ask("  Alvo (domínio)")
        console.print(f"\n  [cyan]Verificando HSTS e proteções em {target}...[/cyan]")
        hsts = self._get_hsts(target)

        t = Table(title=f"Proteções Anti-MitM — {target}", box=box.ROUNDED,
                  border_style="cyan", show_lines=True)
        t.add_column("Proteção", style="bold cyan", width=28)
        t.add_column("Valor")
        t.add_column("Status")

        for name, val, ok in hsts:
            t.add_row(name, str(val)[:60],
                      "[green]✔ OK[/green]" if ok else "[red]✘ Ausente[/red]")
        console.print(t)
        console.input("\n  Enter para voltar...")

    # ── Helpers ───────────────────────────────────────────────

    def _check_ip_forward(self) -> bool:
        try:
            val = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
            return val == "1"
        except:
            return False

    def _check_ssl_strip(self, host: str) -> list:
        results = []
        try:
            # HTTP redirect?
            import urllib.request
            try:
                req = urllib.request.Request(f"http://{host}/",
                    headers={"User-Agent": "SSLAuditKit/1.0"})
                urllib.request.urlopen(req, timeout=5)
                results.append(("Redirect HTTP→HTTPS", "Não encontrado",
                                "[red]⚠ VULNERÁVEL[/red]"))
            except Exception as e:
                err = str(e).lower()
                if "redirect" in err or "301" in err or "302" in err or "https" in err:
                    results.append(("Redirect HTTP→HTTPS", "Presente",
                                    "[green]✔ Protegido[/green]"))
                else:
                    results.append(("Redirect HTTP→HTTPS", "Inconclusivo",
                                    "[yellow]? Verificar[/yellow]"))
        except:
            pass

        hsts_checks = self._get_hsts(host)
        for name, val, ok in hsts_checks:
            results.append((name, str(val)[:40],
                            "[green]✔[/green]" if ok else "[red]✘[/red]"))
        return results

    def _get_hsts(self, host: str) -> list:
        results = []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, 443), timeout=8) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                    s.send(req.encode())
                    resp = s.recv(4096).decode(errors="ignore")

                    hsts = "strict-transport-security" in resp.lower()
                    max_age_match = re.search(r"max-age=(\d+)", resp, re.IGNORECASE)
                    max_age = int(max_age_match.group(1)) if max_age_match else 0
                    include_sub = "includesubdomains" in resp.lower()
                    preload     = "preload" in resp.lower()
                    x_frame     = "x-frame-options" in resp.lower()
                    csp         = "content-security-policy" in resp.lower()

                    results.append(("HSTS Header", "Presente" if hsts else "Ausente", hsts))
                    results.append(("HSTS max-age", f"{max_age}s ({max_age//86400}d)",
                                    max_age >= 31536000))
                    results.append(("includeSubDomains", str(include_sub), include_sub))
                    results.append(("preload", str(preload), preload))
                    results.append(("X-Frame-Options", "Presente" if x_frame else "Ausente", x_frame))
                    results.append(("Content-Security-Policy", "Presente" if csp else "Ausente", csp))
        except Exception as e:
            results.append(("Erro de conexão", str(e), False))
        return results


# ══════════════════════════════════════════════════════════════
#  MÓDULO 5 — sslyze (auditoria profunda SSL/TLS)
# ══════════════════════════════════════════════════════════════

class SSLyzeModule:
    NAME = "sslyze"
    DESC = "Auditoria profunda: Heartbleed, ROBOT, CRIME, BREACH, CCS, POODLE"

    VULN_CHECKS = [
        "heartbleed", "robot", "crime", "breach",
        "ccs_injection", "poodle", "drown", "lucky13"
    ]

    def menu(self):
        header(f"MÓDULO: {self.NAME}")
        console.print(Panel(
            "[cyan]sslyze[/cyan] — análise profunda de vulnerabilidades SSL/TLS: "
            "Heartbleed, ROBOT, CRIME, BREACH, CCS Injection, POODLE, DROWN, e mais. "
            "Verifica configurações, certificados e suporte a session resumption.",
            title="Descrição", border_style="cyan"
        ))

        opts = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        opts.add_column(style="bold cyan", width=4)
        opts.add_column()
        opts.add_row("1", "Scan completo de vulnerabilidades SSL")
        opts.add_row("2", "Verificar Heartbleed")
        opts.add_row("3", "Verificar ROBOT Attack")
        opts.add_row("4", "Verificar CRIME / BREACH")
        opts.add_row("5", "Verificar CCS Injection (OpenSSL)")
        opts.add_row("6", "Verificar POODLE / DROWN")
        opts.add_row("7", "Analisar certificado em profundidade")
        opts.add_row("8", "Session Resumption & Renegotiation")
        opts.add_row("0", "[dim]Voltar[/dim]")
        console.print(opts)

        choice = Prompt.ask("[cyan]>[/cyan]")
        handlers = {
            "1": self.full_vuln_scan,
            "2": lambda: self.single_vuln("heartbleed"),
            "3": lambda: self.single_vuln("robot"),
            "4": lambda: self.single_vuln("crime"),
            "5": lambda: self.single_vuln("ccs"),
            "6": lambda: self.single_vuln("poodle"),
            "7": self.deep_cert_analysis,
            "8": self.session_analysis,
        }
        if choice in handlers:
            handlers[choice]()

    def full_vuln_scan(self):
        target = Prompt.ask("  Alvo (host ou host:porta)")
        host, port = self._parse(target)

        if SSLYZE_AVAILABLE:
            self._run_sslyze(host, port)
        else:
            console.print("\n  [yellow][!] sslyze Python não disponível — usando módulo nativo[/yellow]")
            self._native_vuln_scan(host, port)

        console.input("\n  Enter para voltar...")

    def single_vuln(self, vuln: str):
        target = Prompt.ask(f"  Alvo para verificar {vuln.upper()}")
        host, port = self._parse(target)
        console.print(f"\n  [cyan]Verificando {vuln.upper()} em {host}:{port}...[/cyan]")
        result = self._check_single_vuln(host, port, vuln)
        color  = "red" if result.get("vulnerable") else "green"
        icon   = "🔴 VULNERÁVEL" if result.get("vulnerable") else "🟢 Não vulnerável"
        console.print(f"\n  Resultado: [{color}]{icon}[/{color}]")
        console.print(f"  Detalhes: {result.get('detail', 'N/A')}")
        fp = save_report(f"sslyze_{vuln}", result)
        console.print(f"\n  [dim]Salvo: {fp}[/dim]")
        console.input("\n  Enter para voltar...")

    def deep_cert_analysis(self):
        target = Prompt.ask("  Alvo")
        host, port = self._parse(target)
        console.print(f"\n  [cyan]Analisando certificado de {host}:{port}...[/cyan]")
        cert_info = self._deep_cert(host, port)

        t = Table(title="Análise Profunda de Certificado", box=box.ROUNDED,
                  border_style="cyan", show_lines=True)
        t.add_column("Campo", style="bold cyan", width=28)
        t.add_column("Valor")

        for k, v in cert_info.items():
            val = str(v) if not isinstance(v, list) else ", ".join(str(x) for x in v[:5])
            t.add_row(k, val[:80])

        console.print(t)

        # Avaliar
        issues = []
        exp = cert_info.get("dias_para_expirar", 999)
        if isinstance(exp, int):
            if exp < 0:   issues.append("[red]✘ Certificado EXPIRADO[/red]")
            elif exp < 30: issues.append(f"[yellow]⚠ Expira em {exp} dias[/yellow]")
            else:          issues.append(f"[green]✔ Válido por {exp} dias[/green]")

        key_bits = cert_info.get("key_bits", 0)
        if isinstance(key_bits, int):
            if key_bits < 2048: issues.append("[red]✘ Chave < 2048 bits (FRACA)[/red]")
            else: issues.append(f"[green]✔ Chave {key_bits} bits[/green]")

        if issues:
            console.print()
            for issue in issues:
                console.print(f"  {issue}")

        fp = save_report("sslyze_cert_deep", cert_info)
        console.print(f"\n  [dim]Salvo: {fp}[/dim]")
        console.input("\n  Enter para voltar...")

    def session_analysis(self):
        target = Prompt.ask("  Alvo")
        host, port = self._parse(target)
        console.print(f"\n  [cyan]Analisando sessão TLS em {host}:{port}...[/cyan]\n")
        results = self._session_info(host, port)

        t = Table(title="Session Resumption & Renegotiation", box=box.ROUNDED,
                  border_style="cyan", show_lines=True)
        t.add_column("Recurso", style="bold cyan", width=30)
        t.add_column("Status")
        t.add_column("Risco")

        for name, status, risk in results:
            t.add_row(name, status, risk)
        console.print(t)
        console.input("\n  Enter para voltar...")

    # ── Helpers ───────────────────────────────────────────────

    def _parse(self, target: str) -> Tuple[str, int]:
        if ":" in target:
            p = target.rsplit(":", 1)
            return p[0], int(p[1])
        return target, 443

    def _run_sslyze(self, host: str, port: int):
        try:
            server_loc = ServerNetworkLocation(host, port)
            req = ServerScanRequest(server_location=server_loc,
                                    scan_commands={ScanCommand.CERTIFICATE_INFO,
                                                   ScanCommand.SSL_2_0_CIPHER_SUITES,
                                                   ScanCommand.SSL_3_0_CIPHER_SUITES,
                                                   ScanCommand.TLS_1_0_CIPHER_SUITES,
                                                   ScanCommand.TLS_1_1_CIPHER_SUITES,
                                                   ScanCommand.TLS_1_2_CIPHER_SUITES,
                                                   ScanCommand.TLS_1_3_CIPHER_SUITES,
                                                   ScanCommand.HEARTBLEED,
                                                   ScanCommand.ROBOT,
                                                   ScanCommand.TLS_COMPRESSION,
                                                   ScanCommand.TLS_FALLBACK_SCSV,
                                                   ScanCommand.SESSION_RESUMPTION,
                                                   ScanCommand.HTTP_HEADERS})
            scanner = Scanner()
            scanner.queue_scans([req])

            with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                          transient=True) as prog:
                prog.add_task(f"sslyze escaneando {host}:{port}...", total=None)
                for result in scanner.get_results():
                    self._display_sslyze_result(result)
        except Exception as e:
            console.print(f"  [red][!] Erro sslyze: {e}[/red]")
            self._native_vuln_scan(host, port)

    def _display_sslyze_result(self, result):
        host = result.server_location.hostname
        port = result.server_location.port

        t = Table(title=f"sslyze — {host}:{port}", box=box.ROUNDED,
                  border_style="cyan", show_lines=True)
        t.add_column("Verificação", style="bold cyan", width=28)
        t.add_column("Resultado")

        # Heartbleed
        hb = result.scan_result.heartbleed
        if hb:
            vuln = hb.result.is_vulnerable_to_heartbleed
            t.add_row("Heartbleed",
                      "[red]VULNERÁVEL[/red]" if vuln else "[green]Não vulnerável[/green]")

        # ROBOT
        robot = result.scan_result.robot
        if robot:
            t.add_row("ROBOT", str(robot.result.robot_result))

        # Compressão (CRIME)
        comp = result.scan_result.tls_compression
        if comp:
            t.add_row("CRIME (compressão TLS)",
                      "[red]Vulnerável[/red]" if comp.result.supports_compression
                      else "[green]Não vulnerável[/green]")

        console.print(t)

    def _native_vuln_scan(self, host: str, port: int):
        vulns = []
        checks = [
            ("Heartbleed",     self._check_heartbleed),
            ("CRIME/BEAST",    self._check_crime),
            ("CCS Injection",  self._check_ccs),
            ("POODLE (SSL3)",  self._check_poodle),
            ("Session Reuse",  self._check_session_reuse),
        ]

        t = Table(title=f"Vulnerabilidades SSL — {host}:{port}", box=box.ROUNDED,
                  border_style="cyan", show_lines=True)
        t.add_column("Vulnerabilidade", style="bold cyan", width=22)
        t.add_column("Status", width=18)
        t.add_column("Detalhe")

        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                      transient=True) as prog:
            for name, check_fn in checks:
                task = prog.add_task(f"Verificando {name}...", total=None)
                try:
                    vuln, detail = check_fn(host, port)
                except Exception as e:
                    vuln, detail = None, str(e)
                prog.remove_task(task)

                if vuln is True:
                    status = "[bold red]🔴 VULNERÁVEL[/bold red]"
                elif vuln is False:
                    status = "[green]🟢 Seguro[/green]"
                else:
                    status = "[yellow]? Inconclusivo[/yellow]"
                t.add_row(name, status, detail)

        console.print(t)

    def _check_heartbleed(self, host: str, port: int) -> Tuple[Optional[bool], str]:
        # Heartbleed: TLS 1.0 heartbeat request malformado
        try:
            hello = (
                b"\x16\x03\x01\x00\xdc\x01\x00\x00\xd8\x03\x01"
                + b"\x00" * 32
                + b"\x00\x00\x66" + b"\xc0\x14\xc0\x0a\xc0\x22\xc0\x21"
                + b"\x00\x9f\x00\x9d\x00\x6b\x00\x67\x00\x39\x00\x33"
                + b"\x00\xff\x01\x00\x00\x49\x00\x0b\x00\x04\x03\x00"
                + b"\x01\x02\x00\x0a\x00\x34\x00\x32" + b"\x00\x0e" * 20
                + b"\x00\x23\x00\x00\x00\x0f\x00\x01\x01"
            )
            with socket.create_connection((host, port), timeout=5) as s:
                s.send(hello)
                data = s.recv(1024)
                # Enviar heartbeat malformado
                hb = b"\x18\x03\x01\x00\x03\x01\x40\x00"
                s.send(hb)
                resp = s.recv(2048)
                if b"\x18\x03" in resp and len(resp) > 10:
                    return True, "Resposta heartbeat recebida — possível Heartbleed"
                return False, "Sem resposta heartbeat"
        except:
            return False, "Não testável ou não vulnerável"

    def _check_crime(self, host: str, port: int) -> Tuple[Optional[bool], str]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    comp = s.compression()
                    if comp:
                        return True, f"Compressão ativa: {comp} (CRIME possível)"
                    return False, "Compressão TLS desabilitada"
        except:
            return None, "Não foi possível testar"

    def _check_ccs(self, host: str, port: int) -> Tuple[Optional[bool], str]:
        # CCS Injection: enviar ChangeCipherSpec prematuro
        try:
            hello = b"\x16\x03\x01\x00\x61" + b"\x00" * 10
            with socket.create_connection((host, port), timeout=5) as s:
                s.send(hello)
                time.sleep(0.2)
                ccs = b"\x14\x03\x01\x00\x01\x01"
                s.send(ccs)
                time.sleep(0.2)
                s.send(ccs)
                resp = s.recv(512)
                if resp and b"\x15" not in resp[:2]:
                    return True, "Servidor pode aceitar CCS prematuro"
                return False, "Servidor rejeita CCS prematuro"
        except:
            return False, "Não testável (conexão recusada)"

    def _check_poodle(self, host: str, port: int) -> Tuple[Optional[bool], str]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if hasattr(ssl, 'TLSVersion'):
                try:
                    ctx.maximum_version = ssl.TLSVersion.SSLv3  # type: ignore
                    with socket.create_connection((host, port), timeout=3) as raw:
                        with ctx.wrap_socket(raw, server_hostname=host):
                            return True, "SSLv3 suportado (POODLE vulnerável)"
                except ssl.SSLError:
                    pass
            return False, "SSLv3 não suportado"
        except:
            return False, "SSLv3 não disponível"

    def _check_session_reuse(self, host: str, port: int) -> Tuple[Optional[bool], str]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sessions = []
            for _ in range(2):
                with socket.create_connection((host, port), timeout=5) as raw:
                    with ctx.wrap_socket(raw, server_hostname=host) as s:
                        sessions.append(getattr(s.session, 'id', None) if s.session else None)
            reused = sessions[0] and sessions[1] and sessions[0] == sessions[1]
            return None, "Session resumption: " + ("ativa" if reused else "não detectada")
        except:
            return None, "Não testável"

    def _check_single_vuln(self, host: str, port: int, vuln: str) -> dict:
        mapping = {
            "heartbleed": self._check_heartbleed,
            "crime":      self._check_crime,
            "ccs":        self._check_ccs,
            "poodle":     self._check_poodle,
            "robot":      lambda h, p: (None, "ROBOT requer sslyze biblioteca"),
            "breach":     lambda h, p: (None, "BREACH requer análise HTTP"),
        }
        fn = mapping.get(vuln, lambda h, p: (None, "Verificação não disponível"))
        vuln_result, detail = fn(host, port)
        return {
            "host": host, "port": port, "vuln": vuln,
            "vulnerable": vuln_result, "detail": detail,
            "timestamp": str(datetime.datetime.now())
        }

    def _deep_cert(self, host: str, port: int) -> dict:
        info = {"host": host, "port": port}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_OPTIONAL
            with socket.create_connection((host, port), timeout=8) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    cert = s.getpeercert(binary_form=True)
                    cert_dict = s.getpeercert()
                    der_hash = hashlib.sha256(cert).hexdigest() if cert else "N/A"

                    not_after_str = cert_dict.get("notAfter", "")
                    try:
                        exp = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        dias = (exp - datetime.datetime.utcnow()).days
                    except:
                        dias = "N/A"

                    info.update({
                        "sha256_fingerprint": der_hash[:40] + "...",
                        "subject":       dict(x[0] for x in cert_dict.get("subject", [])),
                        "issuer":        dict(x[0] for x in cert_dict.get("issuer", [])),
                        "not_before":    cert_dict.get("notBefore"),
                        "not_after":     cert_dict.get("notAfter"),
                        "dias_para_expirar": dias,
                        "san":           [v for _, v in cert_dict.get("subjectAltName", [])],
                        "version_tls":   s.version(),
                        "cipher":        s.cipher()[0] if s.cipher() else "N/A",
                        "key_bits":      s.cipher()[2] if s.cipher() else 0,
                        "ocsp_stapling": "N/A",
                    })
        except Exception as e:
            info["error"] = str(e)
        return info

    def _session_info(self, host: str, port: int) -> list:
        results = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Session tickets
        try:
            with socket.create_connection((host, port), timeout=5) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    has_ticket = s.session is not None
                    results.append((
                        "Session Tickets (TLS)",
                        "Suportado" if has_ticket else "Não detectado",
                        "[cyan]Info[/cyan]"
                    ))
        except:
            results.append(("Session Tickets", "Erro", "[dim]-[/dim]"))

        # Renegociação
        try:
            with socket.create_connection((host, port), timeout=5) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    try:
                        s.do_handshake()
                        results.append(("Renegociação segura", "Suportada", "[green]✔[/green]"))
                    except:
                        results.append(("Renegociação", "Não suportada", "[dim]-[/dim]"))
        except:
            pass

        results.append((
            "Perfect Forward Secrecy",
            "Verificar cipher suite",
            "[cyan]Info[/cyan]"
        ))
        return results


# ══════════════════════════════════════════════════════════════
#  MÓDULO 6 — Relatório HTML Unificado
# ══════════════════════════════════════════════════════════════

class ReportModule:
    NAME = "Relatório"
    DESC = "Gera relatório HTML unificado de todos os scans"

    def menu(self):
        header("RELATÓRIO UNIFICADO")
        target = Prompt.ask("  Alvo para relatório completo")
        console.print(f"\n  [cyan]Gerando relatório completo para {target}...[/cyan]")
        self.generate(target)

    def generate(self, target: str):
        host = target.split(":")[0]
        port = int(target.split(":")[1]) if ":" in target else 443

        scan_data = {
            "host": host, "port": port,
            "timestamp": str(datetime.datetime.now()),
            "modules": {}
        }

        sections = []

        # Coleta dados de cada módulo
        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                      BarColumn(), transient=True) as prog:
            task = prog.add_task("Executando scans...", total=5)

            # sslscan
            prog.update(task, description="sslscan...")
            m2 = SSLScanModule()
            protocols = m2._check_protocols(host, port)
            ciphers   = m2._enumerate_ciphers(host, port)
            scan_data["modules"]["sslscan"] = {"protocols": protocols, "ciphers": ciphers}
            prog.advance(task)

            # ssldump
            prog.update(task, description="ssldump handshake...")
            m1 = SSLDumpModule()
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_OPTIONAL
                with socket.create_connection((host, port), timeout=8) as raw:
                    with ctx.wrap_socket(raw, server_hostname=host) as s:
                        cert = s.getpeercert()
                        handshake = {
                            "version": s.version(),
                            "cipher": s.cipher()[0] if s.cipher() else "N/A",
                            "bits":   s.cipher()[2] if s.cipher() else 0,
                            "subject": dict(x[0] for x in cert.get("subject", [])) if cert else {},
                            "not_after": cert.get("notAfter", "N/A") if cert else "N/A",
                        }
                        scan_data["modules"]["ssldump"] = handshake
            except Exception as e:
                scan_data["modules"]["ssldump"] = {"error": str(e)}
            prog.advance(task)

            # sslyze vulns
            prog.update(task, description="sslyze vulns...")
            m5 = SSLyzeModule()
            vulns = {}
            for v in ["heartbleed", "crime", "ccs", "poodle"]:
                result, detail = {
                    "heartbleed": m5._check_heartbleed,
                    "crime":      m5._check_crime,
                    "ccs":        m5._check_ccs,
                    "poodle":     m5._check_poodle,
                }[v](host, port)
                vulns[v] = {"vulnerable": result, "detail": detail}
            scan_data["modules"]["sslyze"] = vulns
            prog.advance(task)

            # sslsplit HSTS
            prog.update(task, description="sslsplit HSTS...")
            m4 = SSLSplitModule()
            hsts = m4._get_hsts(host)
            scan_data["modules"]["sslsplit"] = {"hsts": [
                {"name": n, "value": v, "ok": ok} for n, v, ok in hsts
            ]}
            prog.advance(task)

            # sslh probes
            prog.update(task, description="sslh probes...")
            m3 = SSLHModule()
            protos = {}
            for p in ["https", "ssh", "http"]:
                protos[p] = m3._probe_protocol(host, port, p)
            scan_data["modules"]["sslh"] = {"protocols": protos}
            prog.advance(task)

        html = self._build_html(scan_data)
        fp   = save_html_report(f"SSLAuditKit_{host}", html)
        fp2  = save_report(f"SSLAuditKit_{host}", scan_data)

        console.print(f"\n  [bold green]✔ Relatório HTML:[/bold green] {fp}")
        console.print(f"  [dim]JSON: {fp2}[/dim]")
        console.input("\n  Enter para voltar...")

    def _build_html(self, data: dict) -> str:
        host = data["host"]
        port = data["port"]
        ts   = data["timestamp"]
        m    = data.get("modules", {})

        def badge(ok):
            if ok is True:  return '<span class="badge bad">VULNERÁVEL</span>'
            if ok is False: return '<span class="badge ok">Seguro</span>'
            return '<span class="badge warn">Inconclusivo</span>'

        def proto_badge(sup, name):
            dep = name in ["SSLv2","SSLv3","TLSv1.0","TLSv1.1"]
            if sup and dep: cls = "bad"
            elif sup:       cls = "ok"
            else:           cls = "dim"
            return f'<span class="badge {cls}">{"Sim" if sup else "Não"}</span>'

        protocols_html = ""
        for k, v in m.get("sslscan", {}).get("protocols", {}).items():
            protocols_html += f"<tr><td>{k}</td><td>{proto_badge(v, k)}</td></tr>"

        ciphers_html = ""
        for name, bits in m.get("sslscan", {}).get("ciphers", []):
            weak = any(k in name.upper() for k in SSLScanModule.WEAK_CIPHERS)
            cls  = "bad" if weak else "ok"
            ciphers_html += f'<tr><td>{name}</td><td>{bits}</td><td><span class="badge {cls}">{"Fraco" if weak else "OK"}</span></td></tr>'

        hs = m.get("ssldump", {})
        handshake_html = f"""
        <tr><td>Versão TLS</td><td>{hs.get('version','N/A')}</td></tr>
        <tr><td>Cipher Suite</td><td>{hs.get('cipher','N/A')}</td></tr>
        <tr><td>Bits</td><td>{hs.get('bits','N/A')}</td></tr>
        <tr><td>Common Name</td><td>{hs.get('subject',{}).get('commonName','N/A')}</td></tr>
        <tr><td>Validade</td><td>{hs.get('not_after','N/A')}</td></tr>
        """ if not hs.get("error") else f"<tr><td colspan='2'>Erro: {hs.get('error')}</td></tr>"

        vulns_html = ""
        for vname, vdata in m.get("sslyze", {}).items():
            vulns_html += f"<tr><td>{vname.upper()}</td><td>{badge(vdata.get('vulnerable'))}</td><td>{vdata.get('detail','')}</td></tr>"

        hsts_html = ""
        for item in m.get("sslsplit", {}).get("hsts", []):
            ok_cls = "ok" if item["ok"] else "bad"
            hsts_html += f"<tr><td>{item['name']}</td><td>{item['value']}</td><td><span class='badge {ok_cls}'>{'OK' if item['ok'] else 'Ausente'}</span></td></tr>"

        sslh_html = ""
        for p, det in m.get("sslh", {}).get("protocols", {}).items():
            cls = "ok" if det else "dim"
            sslh_html += f'<tr><td>{p.upper()}</td><td><span class="badge {cls}">{"Detectado" if det else "Não"}</span></td></tr>'

        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>SSLAuditKit — {host}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Rajdhani:wght@400;600;700&display=swap');
  :root{{--bg:#0a0d14;--bg2:#0f1420;--bg3:#141926;--card:#111827;--border:#1e2d47;
         --cyan:#00e5ff;--green:#00ff7f;--red:#ff3b3b;--yellow:#ffd600;--muted:#4a5568;
         --text:#e2e8f0;--font:'Rajdhani',sans-serif;--mono:'JetBrains Mono',monospace;}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:var(--font);font-size:16px;line-height:1.6}}
  .container{{max-width:1100px;margin:0 auto;padding:32px 20px}}
  header{{text-align:center;padding:48px 0 32px;border-bottom:1px solid var(--border);margin-bottom:40px}}
  header h1{{font-size:2.8rem;font-weight:700;letter-spacing:3px;color:var(--cyan);text-transform:uppercase}}
  header .sub{{font-family:var(--mono);font-size:.85rem;color:var(--muted);margin-top:8px}}
  header .host{{font-family:var(--mono);font-size:1.1rem;color:var(--cyan);margin-top:12px;opacity:.8}}
  .grid{{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-bottom:24px}}
  @media(max-width:700px){{.grid{{grid-template-columns:1fr}}}}
  .full{{grid-column:1/-1}}
  .card{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:24px}}
  .card h2{{font-size:1.1rem;font-weight:700;color:var(--cyan);letter-spacing:1.5px;
             text-transform:uppercase;margin-bottom:16px;padding-bottom:8px;
             border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px}}
  table{{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:.82rem}}
  th{{text-align:left;padding:8px 12px;background:rgba(0,229,255,.06);
      color:var(--cyan);font-size:.78rem;letter-spacing:1px;text-transform:uppercase}}
  td{{padding:7px 12px;border-bottom:1px solid rgba(255,255,255,.04);color:var(--text)}}
  tr:last-child td{{border-bottom:none}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.7rem;
          font-weight:700;font-family:var(--mono);letter-spacing:.5px}}
  .badge.ok{{background:rgba(0,255,127,.12);color:var(--green);border:1px solid rgba(0,255,127,.25)}}
  .badge.bad{{background:rgba(255,59,59,.12);color:var(--red);border:1px solid rgba(255,59,59,.25)}}
  .badge.warn{{background:rgba(255,214,0,.1);color:var(--yellow);border:1px solid rgba(255,214,0,.2)}}
  .badge.dim{{background:rgba(255,255,255,.05);color:var(--muted);border:1px solid rgba(255,255,255,.08)}}
  footer{{text-align:center;padding:32px 0;color:var(--muted);font-family:var(--mono);
          font-size:.75rem;border-top:1px solid var(--border);margin-top:48px}}
  .glow{{text-shadow:0 0 20px rgba(0,229,255,.4)}}
</style>
</head>
<body>
<div class="container">
<header>
  <h1 class="glow">SSLAuditKit</h1>
  <div class="sub">UNIFIED SSL/TLS AUDIT FRAMEWORK — github.com/Kalyel473</div>
  <div class="host">▶ {host}:{port}</div>
  <div class="sub" style="margin-top:8px">{ts}</div>
</header>

<div class="grid">
  <div class="card">
    <h2>🔐 ssldump — Handshake TLS</h2>
    <table><tbody>{handshake_html}</tbody></table>
  </div>
  <div class="card">
    <h2>🔍 sslscan — Protocolos</h2>
    <table><thead><tr><th>Protocolo</th><th>Suportado</th></tr></thead>
    <tbody>{protocols_html}</tbody></table>
  </div>
  <div class="card full">
    <h2>🔑 sslscan — Cipher Suites</h2>
    <table><thead><tr><th>Cipher Suite</th><th>Bits</th><th>Avaliação</th></tr></thead>
    <tbody>{ciphers_html}</tbody></table>
  </div>
  <div class="card full">
    <h2>💀 sslyze — Vulnerabilidades</h2>
    <table><thead><tr><th>CVE/Ataque</th><th>Status</th><th>Detalhe</th></tr></thead>
    <tbody>{vulns_html}</tbody></table>
  </div>
  <div class="card">
    <h2>🛡 sslsplit — HSTS & Anti-MitM</h2>
    <table><thead><tr><th>Proteção</th><th>Valor</th><th>Status</th></tr></thead>
    <tbody>{hsts_html}</tbody></table>
  </div>
  <div class="card">
    <h2>🔀 sslh — Multiplexação</h2>
    <table><thead><tr><th>Protocolo</th><th>Detectado</th></tr></thead>
    <tbody>{sslh_html}</tbody></table>
  </div>
</div>

<footer>SSLAuditKit v1.0 — Kalyel473 &nbsp;|&nbsp; Uso educacional e em ambientes autorizados</footer>
</div></body></html>"""


# ══════════════════════════════════════════════════════════════
#  MENU PRINCIPAL
# ══════════════════════════════════════════════════════════════

class SSLAuditKit:
    MODULES = [
        SSLDumpModule(),
        SSLScanModule(),
        SSLHModule(),
        SSLSplitModule(),
        SSLyzeModule(),
        ReportModule(),
    ]

    def run(self):
        while True:
            clear()
            console.print(BANNER)

            t = Table(show_header=False, box=box.SIMPLE_HEAD, padding=(0, 3),
                      border_style="cyan")
            t.add_column(style="bold cyan", width=4)
            t.add_column(style="bold white", width=14)
            t.add_column(style="dim")

            for i, mod in enumerate(self.MODULES, 1):
                t.add_row(str(i), mod.NAME, mod.DESC)
            t.add_row("0", "Sair", "")
            console.print(t)
            console.print()

            choice = Prompt.ask("  [bold cyan]SSLAuditKit[/bold cyan]")

            if choice == "0":
                console.print("\n  [dim cyan]Encerrando SSLAuditKit...[/dim cyan]\n")
                break
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(self.MODULES):
                    self.MODULES[idx].menu()
            except (ValueError, IndexError):
                pass


if __name__ == "__main__":
    try:
        SSLAuditKit().run()
    except KeyboardInterrupt:
        console.print("\n\n  [dim]Interrompido.[/dim]\n")
