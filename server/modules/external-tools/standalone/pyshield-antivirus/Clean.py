#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════╗
║           ANTIVÍRUS COMPLETO - PyShield v1.0             ║
║     Varredura profunda, limpeza de disco e RAM           ║
╚══════════════════════════════════════════════════════════╝
Autor: PyShield
Requer: pip install psutil colorama requests
"""

import os
import sys
import re
import gc
import hashlib
import shutil
import tempfile
import platform
import datetime
import threading
import subprocess
import ctypes
import stat
import time
import json
import struct
import socket
import logging
from pathlib import Path
from collections import defaultdict

# ──────────────────────────────────────────────
# Dependências opcionais (instala se necessário)
# ──────────────────────────────────────────────
def instalar_dependencias():
    pkgs = ["psutil", "colorama"]
    for pkg in pkgs:
        try:
            __import__(pkg)
        except ImportError:
            print(f"[*] Instalando dependência: {pkg}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"])

instalar_dependencias()

import psutil
from colorama import Fore, Back, Style, init
init(autoreset=True)

# ──────────────────────────────────────────────
# CONFIGURAÇÕES GLOBAIS
# ──────────────────────────────────────────────
VERSAO = "1.0.0"
LOG_FILE = "pyshield_log.txt"
RELATORIO_FILE = "pyshield_relatorio.json"
QUARENTENA_DIR = os.path.join(os.path.expanduser("~"), "PyShield_Quarentena")

# Extensões suspeitas conhecidas de malware
EXTENSOES_SUSPEITAS = {
    ".exe", ".bat", ".cmd", ".scr", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".msi", ".com", ".pif", ".reg", ".inf",
    ".dll", ".sys", ".drv", ".cpl", ".ocx", ".bin",
    ".ps1", ".psm1", ".psd1", ".ps2", ".msc", ".hta",
    ".jar", ".class", ".sh", ".bash", ".ksh", ".zsh",
    ".lnk", ".url", ".tmp", ".temp"
}

# Padrões de nomes suspeitos
NOMES_SUSPEITOS = [
    r"(virus|malware|trojan|worm|spyware|ransomware|backdoor|rootkit|keylogger)",
    r"(crack|keygen|patch|serial|activat|hack)",
    r"(svchost\d+|csrss\d+|lsass\d+|winlogon\d+)",
    r"(\bsetup_[a-z0-9]{6,}\b)",
    r"(free.?download|download.?free)",
    r"(\binvoice_\d+\.exe\b|\bstatement\.exe\b)",
]

# Assinaturas de bytes maliciosos (hex) - simuladas para fins didáticos
ASSINATURAS_MALWARE = [
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR",  # EICAR test
    b"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAA",    # MZ header suspeito base64
    b"\x4d\x5a\x90\x00\x03\x00\x00\x00",      # MZ PE header
    bytes.fromhex("4d5a5000020000000400"),       # PE variant
]

# Processos suspeitos comuns
PROCESSOS_SUSPEITOS = [
    "miner", "cryptominer", "xmrig", "monero", "coinminer",
    "keylogger", "spyware", "backdoor", "netcat", "ncat",
    "mimikatz", "metasploit", "meterpreter", "cobaltstrike",
    "darkcomet", "njrat", "remcos", "asyncrat",
]

# Entradas de registro suspeitas (Windows)
REGISTRO_SUSPEITO = [
    r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
]

# Hashes MD5 conhecidos de malware (EICAR + exemplos fictícios para demo)
HASHES_MALWARE_CONHECIDOS = {
    "44d88612fea8a8f36de82e1278abb02f",  # EICAR MD5
    "cf8bd9dfddff007f75adf4c2be48005a",  # EICAR SHA1-like
    "131f95c51cc819465fa1797f6ccacf9d",  # fictício
    "d41d8cd98f00b204e9800998ecf8427e",  # MD5 vazio (arquivo zero bytes)
}

# ──────────────────────────────────────────────
# LOGGER
# ──────────────────────────────────────────────
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def log(msg, nivel="INFO"):
    if nivel == "INFO":
        logging.info(msg)
    elif nivel == "WARN":
        logging.warning(msg)
    elif nivel == "ERROR":
        logging.error(msg)

# ──────────────────────────────────────────────
# UTILITÁRIOS DE EXIBIÇÃO
# ──────────────────────────────────────────────
def banner():
    print(Fore.GREEN + r"""
  ██████╗ ██╗   ██╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ 
  ██╔══██╗╚██╗ ██╔╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
  ██████╔╝ ╚████╔╝ ███████╗███████║██║█████╗  ██║     ██║  ██║
  ██╔═══╝   ╚██╔╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
  ██║        ██║   ███████║██║  ██║██║███████╗███████╗██████╔╝
  ╚═╝        ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ 
    """ + Style.RESET_ALL)
    print(Fore.CYAN + f"  {'─'*55}")
    print(Fore.YELLOW + f"  Antivírus Python Completo  v{VERSAO}  |  PyShield")
    print(Fore.CYAN + f"  {'─'*55}\n")

def secao(titulo):
    print(Fore.CYAN + f"\n{'═'*60}")
    print(Fore.WHITE + Back.BLUE + f"  {titulo}  " + Style.RESET_ALL)
    print(Fore.CYAN + f"{'═'*60}")

def ok(msg):    print(Fore.GREEN  + f"  [✔] {msg}")
def info(msg):  print(Fore.CYAN   + f"  [i] {msg}")
def aviso(msg): print(Fore.YELLOW + f"  [!] {msg}")
def erro(msg):  print(Fore.RED    + f"  [✘] {msg}")
def ameaca(msg):print(Fore.RED + Back.BLACK + f"  [⚠ AMEAÇA] {msg}" + Style.RESET_ALL)

def barra_progresso(atual, total, largura=40):
    if total == 0:
        return
    pct = atual / total
    feito = int(largura * pct)
    barra = "█" * feito + "░" * (largura - feito)
    print(f"\r  {Fore.GREEN}[{barra}]{Style.RESET_ALL} {pct*100:5.1f}%  ({atual}/{total})", end="", flush=True)

# ──────────────────────────────────────────────
# CLASSE PRINCIPAL DO ANTIVÍRUS
# ──────────────────────────────────────────────
class PyShield:
    def __init__(self):
        self.ameacas_encontradas = []
        self.arquivos_limpos = 0
        self.arquivos_suspeitos = []
        self.processos_suspeitos = []
        self.conexoes_suspeitas = []
        self.inicio = datetime.datetime.now()
        self.sistema = platform.system()
        os.makedirs(QUARENTENA_DIR, exist_ok=True)
        log("PyShield iniciado")

    # ──────────────────────────────────────────
    # 1. VARREDURA DE ARQUIVOS
    # ──────────────────────────────────────────
    def calcular_hash(self, caminho, algoritmo="md5"):
        """Calcula hash MD5/SHA256 de um arquivo."""
        h = hashlib.new(algoritmo)
        try:
            with open(caminho, "rb") as f:
                for bloco in iter(lambda: f.read(65536), b""):
                    h.update(bloco)
            return h.hexdigest()
        except Exception:
            return None

    def verificar_assinaturas(self, caminho):
        """Verifica assinaturas de bytes de malware no arquivo."""
        try:
            with open(caminho, "rb") as f:
                conteudo = f.read(4096)  # primeiros 4KB
            for assinatura in ASSINATURAS_MALWARE:
                if assinatura in conteudo:
                    return True, f"Assinatura de malware detectada"
        except Exception:
            pass
        return False, None

    def verificar_hash_malware(self, caminho):
        """Verifica se o hash do arquivo está na base de dados de malware."""
        md5 = self.calcular_hash(caminho, "md5")
        if md5 and md5 in HASHES_MALWARE_CONHECIDOS:
            return True, f"Hash MD5 ({md5}) presente na base de ameaças"
        return False, None

    def verificar_nome_suspeito(self, nome_arquivo):
        """Verifica padrões suspeitos no nome do arquivo."""
        nome_lower = nome_arquivo.lower()
        for padrao in NOMES_SUSPEITOS:
            if re.search(padrao, nome_lower, re.IGNORECASE):
                return True, f"Nome suspeito: padrão '{padrao}'"
        return False, None

    def verificar_permissoes_suspeitas(self, caminho):
        """Verifica permissões incomuns no arquivo."""
        try:
            modo = os.stat(caminho).st_mode
            # Arquivo com SUID/SGID no Linux
            if self.sistema != "Windows":
                if modo & stat.S_ISUID or modo & stat.S_ISGID:
                    return True, "Bit SUID/SGID definido"
        except Exception:
            pass
        return False, None

    def verificar_conteudo_script(self, caminho):
        """Verifica scripts por padrões maliciosos."""
        ext = Path(caminho).suffix.lower()
        extensoes_script = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".sh"}
        if ext not in extensoes_script:
            return False, None

        padroes_maliciosos = [
            r"(IEX|Invoke-Expression)\s*\(",
            r"(New-Object\s+Net\.WebClient)",
            r"(DownloadString|DownloadFile)\s*\(",
            r"(Base64|FromBase64String)",
            r"(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe)",
            r"(reg\s+add|reg\s+delete)",
            r"(net\s+user\s+.*\s+/add)",
            r"(taskkill|shutdown\s+/[rs])",
            r"(certutil\s+-decode)",
            r"(mshta|rundll32|regsvr32)",
            r"(eval\s*\(|exec\s*\()",
            r"(__import__\s*\(\s*['\"]os['\"])",
            r"(subprocess\.call|os\.system)\s*\(\s*['\"]",
        ]
        try:
            with open(caminho, "r", encoding="utf-8", errors="ignore") as f:
                conteudo = f.read(8192)
            for padrao in padroes_maliciosos:
                if re.search(padrao, conteudo, re.IGNORECASE):
                    return True, f"Conteúdo suspeito: padrão '{padrao}'"
        except Exception:
            pass
        return False, None

    def analisar_arquivo(self, caminho):
        """Analisa um arquivo por múltiplos vetores de ameaça."""
        resultados = []
        nome = os.path.basename(caminho)
        ext = Path(caminho).suffix.lower()

        # Hash vs base de dados
        is_bad, motivo = self.verificar_hash_malware(caminho)
        if is_bad:
            resultados.append(motivo)

        # Assinaturas binárias
        is_bad, motivo = self.verificar_assinaturas(caminho)
        if is_bad:
            resultados.append(motivo)

        # Nome suspeito
        is_bad, motivo = self.verificar_nome_suspeito(nome)
        if is_bad:
            resultados.append(motivo)

        # Permissões
        is_bad, motivo = self.verificar_permissoes_suspeitas(caminho)
        if is_bad:
            resultados.append(motivo)

        # Conteúdo de script
        is_bad, motivo = self.verificar_conteudo_script(caminho)
        if is_bad:
            resultados.append(motivo)

        # Arquivo executável oculto (extensão dupla: foto.jpg.exe)
        if nome.count(".") > 1 and ext in EXTENSOES_SUSPEITAS:
            partes = nome.split(".")
            if partes[-2].lower() in ["jpg", "jpeg", "png", "pdf", "docx", "xlsx"]:
                resultados.append("Extensão dupla suspeita (possível engenharia social)")

        return resultados

    def varredura_diretorio(self, diretorio, profunda=True):
        """Varre um diretório recursivamente."""
        arquivos_total = 0
        arquivos_analisados = 0

        secao(f"VARREDURA: {diretorio}")

        # Conta total de arquivos primeiro
        info("Contando arquivos...")
        try:
            for raiz, dirs, arquivos in os.walk(diretorio, followlinks=False):
                # Ignora diretórios do sistema protegidos
                dirs[:] = [d for d in dirs if not d.startswith(".") or profunda]
                arquivos_total += len(arquivos)
        except PermissionError:
            pass

        info(f"Total de arquivos encontrados: {arquivos_total:,}")
        if arquivos_total == 0:
            ok("Nenhum arquivo para analisar.")
            return

        try:
            for raiz, dirs, arquivos in os.walk(diretorio, followlinks=False):
                dirs[:] = [d for d in dirs if not d.startswith(".") or profunda]

                for arquivo in arquivos:
                    caminho = os.path.join(raiz, arquivo)
                    arquivos_analisados += 1

                    if arquivos_analisados % 50 == 0 or arquivos_analisados == arquivos_total:
                        barra_progresso(arquivos_analisados, arquivos_total)

                    try:
                        if not os.path.isfile(caminho):
                            continue
                        if os.path.getsize(caminho) > 500 * 1024 * 1024:  # ignora >500MB
                            continue

                        ameacas = self.analisar_arquivo(caminho)
                        if ameacas:
                            self.arquivos_suspeitos.append({
                                "caminho": caminho,
                                "ameacas": ameacas,
                                "tamanho": os.path.getsize(caminho),
                                "modificado": datetime.datetime.fromtimestamp(
                                    os.path.getmtime(caminho)
                                ).strftime("%Y-%m-%d %H:%M:%S")
                            })
                            log(f"SUSPEITO: {caminho} | {'; '.join(ameacas)}", "WARN")
                        else:
                            self.arquivos_limpos += 1
                    except (PermissionError, OSError):
                        continue

        except KeyboardInterrupt:
            print()
            aviso("Varredura interrompida pelo usuário.")

        print()  # nova linha após barra
        ok(f"Analisados: {arquivos_analisados:,} arquivos")
        if self.arquivos_suspeitos:
            ameaca(f"{len(self.arquivos_suspeitos)} arquivo(s) suspeito(s) detectado(s)!")
        else:
            ok("Nenhuma ameaça encontrada neste diretório.")

    # ──────────────────────────────────────────
    # 2. VARREDURA DE PROCESSOS
    # ──────────────────────────────────────────
    def varredura_processos(self):
        secao("VARREDURA DE PROCESSOS EM EXECUÇÃO")

        processos = list(psutil.process_iter(["pid", "name", "exe", "cmdline", "username", "cpu_percent", "memory_percent"]))
        info(f"Total de processos ativos: {len(processos)}")

        for proc in processos:
            try:
                nome = (proc.info.get("name") or "").lower()
                exe = (proc.info.get("exe") or "").lower()
                cmdline = " ".join(proc.info.get("cmdline") or []).lower()

                suspeito = False
                motivos = []

                # Nome na lista negra
                for s in PROCESSOS_SUSPEITOS:
                    if s in nome or s in exe or s in cmdline:
                        suspeito = True
                        motivos.append(f"Nome na lista de processos maliciosos: '{s}'")

                # Processo sem executável mapeado (injetado)
                if not exe and nome not in ["system", "idle", "[system process]", ""]:
                    suspeito = True
                    motivos.append("Processo sem executável em disco (possível injeção)")

                # CPU muito alta (possível cryptominer)
                cpu = proc.info.get("cpu_percent") or 0
                if cpu > 90:
                    suspeito = True
                    motivos.append(f"CPU anormalmente alta: {cpu:.1f}%")

                # Executável em pasta temporária
                if exe and any(tmp in exe for tmp in ["/tmp/", "\\temp\\", "\\tmp\\", "appdata\\local\\temp"]):
                    suspeito = True
                    motivos.append("Executável rodando de pasta temporária")

                if suspeito:
                    self.processos_suspeitos.append({
                        "pid": proc.info["pid"],
                        "nome": proc.info["name"],
                        "exe": exe,
                        "motivos": motivos
                    })
                    ameaca(f"PID {proc.info['pid']} | {proc.info['name']} → {'; '.join(motivos)}")
                    log(f"PROCESSO SUSPEITO PID={proc.info['pid']} {proc.info['name']}: {'; '.join(motivos)}", "WARN")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not self.processos_suspeitos:
            ok("Nenhum processo suspeito encontrado.")
        else:
            aviso(f"{len(self.processos_suspeitos)} processo(s) suspeito(s) detectado(s).")

    # ──────────────────────────────────────────
    # 3. ANÁLISE DE RAM
    # ──────────────────────────────────────────
    def analisar_ram(self):
        secao("ANÁLISE DE MEMÓRIA RAM")

        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()

        info(f"RAM Total    : {mem.total / (1024**3):.2f} GB")
        info(f"RAM Usada    : {mem.used  / (1024**3):.2f} GB ({mem.percent}%)")
        info(f"RAM Livre    : {mem.available / (1024**3):.2f} GB")
        info(f"Swap Total   : {swap.total / (1024**3):.2f} GB")
        info(f"Swap Usada   : {swap.used  / (1024**3):.2f} GB ({swap.percent}%)")

        if mem.percent > 90:
            aviso("Uso de RAM crítico! Possível vazamento de memória ou processo malicioso.")
        elif mem.percent > 75:
            aviso("Uso de RAM elevado.")
        else:
            ok("Uso de RAM dentro do normal.")

        # Top 5 consumidores de RAM
        print()
        info("Top 5 processos consumidores de RAM:")
        procs_mem = []
        for p in psutil.process_iter(["pid", "name", "memory_percent"]):
            try:
                procs_mem.append(p.info)
            except psutil.AccessDenied:
                continue
        procs_mem.sort(key=lambda x: x.get("memory_percent") or 0, reverse=True)
        for p in procs_mem[:5]:
            print(f"    PID {p['pid']:6d}  {p.get('memory_percent', 0):5.1f}%  {p['name']}")

        # Liberar memória Python
        gc.collect()
        ok("Coleta de lixo Python executada (gc.collect).")

    # ──────────────────────────────────────────
    # 4. VARREDURA DE CONEXÕES DE REDE
    # ──────────────────────────────────────────
    def varredura_rede(self):
        secao("VARREDURA DE CONEXÕES DE REDE")

        # Portas suspeitas conhecidas
        portas_suspeitas = {
            1337: "Backdoor/Leet", 31337: "Back Orifice", 4444: "Metasploit",
            6666: "Trojan IRC", 6667: "IRC Botnet", 6668: "IRC Botnet",
            9001: "Tor", 9050: "Tor SOCKS", 9150: "Tor Browser",
            12345: "NetBus", 54321: "NetBus reverse", 2222: "SSH alt",
            3333: "CryptoMiner", 14444: "CryptoMiner", 45000: "CryptoMiner",
            7777: "Backdoor", 8888: "Backdoor alt",
        }

        try:
            conexoes = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            aviso("Acesso negado para listar conexões. Execute como administrador.")
            return

        info(f"Total de conexões de rede: {len(conexoes)}")

        for conn in conexoes:
            motivos = []
            try:
                porta_local  = conn.laddr.port if conn.laddr else 0
                porta_remota = conn.raddr.port if conn.raddr else 0
                ip_remoto    = conn.raddr.ip   if conn.raddr else ""

                if porta_remota in portas_suspeitas:
                    motivos.append(f"Porta suspeita {porta_remota} ({portas_suspeitas[porta_remota]})")
                if porta_local in portas_suspeitas:
                    motivos.append(f"Escutando porta suspeita {porta_local}")

                # IPs de faixas privadas conectados externamente com portas bizarras
                if ip_remoto and porta_remota > 49151:
                    pass  # efêmero normal, ignora

                if motivos:
                    pid_info = f"PID {conn.pid}" if conn.pid else "PID desconhecido"
                    self.conexoes_suspeitas.append({
                        "pid": conn.pid,
                        "local": str(conn.laddr),
                        "remoto": str(conn.raddr),
                        "status": conn.status,
                        "motivos": motivos
                    })
                    ameaca(f"{pid_info} | {conn.laddr} → {conn.raddr} | {'; '.join(motivos)}")

            except Exception:
                continue

        if not self.conexoes_suspeitas:
            ok("Nenhuma conexão de rede suspeita encontrada.")
        else:
            aviso(f"{len(self.conexoes_suspeitas)} conexão(ões) suspeita(s) encontrada(s).")

    # ──────────────────────────────────────────
    # 5. VARREDURA DE INICIALIZAÇÃO (STARTUP)
    # ──────────────────────────────────────────
    def varredura_inicializacao(self):
        secao("VARREDURA DE PROGRAMAS DE INICIALIZAÇÃO")

        # Linux: systemd, cron, rc.local, ~/.bashrc, /etc/init.d
        if self.sistema == "Linux":
            locais_startup = [
                os.path.expanduser("~/.bashrc"),
                os.path.expanduser("~/.bash_profile"),
                os.path.expanduser("~/.profile"),
                os.path.expanduser("~/.config/autostart"),
                "/etc/crontab",
                "/etc/rc.local",
                "/etc/init.d",
                "/etc/profile.d",
                "/tmp",
                "/var/tmp",
            ]
            for local in locais_startup:
                if os.path.exists(local):
                    if os.path.isfile(local):
                        ameacas = self.analisar_arquivo(local)
                        if ameacas:
                            ameaca(f"Startup suspeito: {local}")
                            for a in ameacas:
                                aviso(f"  → {a}")
                        else:
                            ok(f"OK: {local}")
                    elif os.path.isdir(local):
                        for f in os.listdir(local):
                            fp = os.path.join(local, f)
                            if os.path.isfile(fp):
                                ameacas = self.analisar_arquivo(fp)
                                if ameacas:
                                    ameaca(f"Startup suspeito: {fp}")

        # macOS: LaunchAgents / LaunchDaemons
        elif self.sistema == "Darwin":
            dirs = [
                os.path.expanduser("~/Library/LaunchAgents"),
                "/Library/LaunchAgents",
                "/Library/LaunchDaemons",
                "/System/Library/LaunchDaemons",
            ]
            for d in dirs:
                if os.path.isdir(d):
                    for f in os.listdir(d):
                        fp = os.path.join(d, f)
                        ameacas = self.analisar_arquivo(fp)
                        if ameacas:
                            ameaca(f"LaunchAgent suspeito: {fp}")
                        else:
                            info(f"LaunchAgent verificado: {f}")

        # Windows: Registro
        elif self.sistema == "Windows":
            try:
                import winreg
                chaves = [
                    (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                ]
                for hive, subkey in chaves:
                    try:
                        key = winreg.OpenKey(hive, subkey)
                        i = 0
                        while True:
                            try:
                                nome, valor, _ = winreg.EnumValue(key, i)
                                suspeito = any(p in valor.lower() for p in
                                               ["temp", "tmp", "appdata\\local\\temp",
                                                "powershell", "cmd.exe /c", "wscript"])
                                if suspeito:
                                    ameaca(f"Registro startup suspeito: {nome} = {valor}")
                                else:
                                    ok(f"Registro OK: {nome}")
                                i += 1
                            except OSError:
                                break
                        winreg.CloseKey(key)
                    except PermissionError:
                        aviso(f"Sem permissão para acessar: {subkey}")
            except ImportError:
                aviso("winreg não disponível (não é Windows).")

        ok("Varredura de inicialização concluída.")

    # ──────────────────────────────────────────
    # 6. LIMPEZA DE DISCO
    # ──────────────────────────────────────────
    def limpeza_disco(self):
        secao("LIMPEZA DE DISCO")

        total_liberado = 0

        # Pastas temporárias do sistema
        dirs_temp = []

        if self.sistema == "Windows":
            dirs_temp = [
                os.environ.get("TEMP", ""),
                os.environ.get("TMP", ""),
                os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Temp"),
                os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp"),
                os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "SoftwareDistribution", "Download"),
            ]
        elif self.sistema == "Linux":
            dirs_temp = [
                "/tmp",
                "/var/tmp",
                os.path.expanduser("~/.cache"),
                "/var/cache/apt/archives",
            ]
        elif self.sistema == "Darwin":
            dirs_temp = [
                "/tmp",
                "/var/tmp",
                os.path.expanduser("~/Library/Caches"),
            ]

        for pasta in dirs_temp:
            if not pasta or not os.path.isdir(pasta):
                continue
            liberado = 0
            removidos = 0
            erros = 0
            try:
                for item in os.listdir(pasta):
                    caminho = os.path.join(pasta, item)
                    try:
                        if os.path.isfile(caminho):
                            tamanho = os.path.getsize(caminho)
                            # Não remove arquivos recentes (<1h) para segurança
                            if time.time() - os.path.getmtime(caminho) > 3600:
                                os.remove(caminho)
                                liberado += tamanho
                                removidos += 1
                        elif os.path.isdir(caminho):
                            tamanho = sum(
                                os.path.getsize(os.path.join(dp, fn))
                                for dp, dn, fns in os.walk(caminho)
                                for fn in fns
                                if os.path.isfile(os.path.join(dp, fn))
                            )
                            shutil.rmtree(caminho, ignore_errors=True)
                            liberado += tamanho
                            removidos += 1
                    except (PermissionError, OSError):
                        erros += 1
                        continue
            except PermissionError:
                aviso(f"Sem permissão: {pasta}")
                continue

            total_liberado += liberado
            ok(f"{pasta}: {removidos} itens removidos ({liberado / (1024**2):.2f} MB liberados), {erros} sem permissão")

        # Arquivos de log antigos (>30 dias) na pasta home
        home = os.path.expanduser("~")
        log_liberado = 0
        for raiz, dirs, arquivos in os.walk(home):
            # Não entra em pastas ocultas profundas
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for arq in arquivos:
                if arq.endswith(".log") or arq.endswith(".old"):
                    caminho = os.path.join(raiz, arq)
                    try:
                        if time.time() - os.path.getmtime(caminho) > 30 * 86400:
                            sz = os.path.getsize(caminho)
                            os.remove(caminho)
                            log_liberado += sz
                    except (PermissionError, OSError):
                        pass
        if log_liberado:
            ok(f"Logs antigos removidos: {log_liberado / (1024**2):.2f} MB")
            total_liberado += log_liberado

        print()
        ok(f"Total liberado em disco: {total_liberado / (1024**2):.2f} MB")
        log(f"Limpeza de disco: {total_liberado / (1024**2):.2f} MB liberados")

    # ──────────────────────────────────────────
    # 7. VERIFICAÇÃO DE INTEGRIDADE DO SISTEMA
    # ──────────────────────────────────────────
    def verificar_integridade_sistema(self):
        secao("VERIFICAÇÃO DE INTEGRIDADE DO SISTEMA")

        # Verifica arquivos críticos do sistema
        if self.sistema == "Linux":
            arquivos_criticos = [
                "/etc/passwd", "/etc/shadow", "/etc/sudoers",
                "/etc/hosts", "/etc/resolv.conf", "/etc/crontab",
                "/bin/bash", "/bin/sh", "/usr/bin/python3",
            ]
        elif self.sistema == "Darwin":
            arquivos_criticos = [
                "/etc/passwd", "/etc/hosts", "/etc/resolv.conf",
                "/bin/bash", "/bin/sh",
            ]
        elif self.sistema == "Windows":
            win = os.environ.get("SYSTEMROOT", "C:\\Windows")
            arquivos_criticos = [
                os.path.join(win, "System32", "cmd.exe"),
                os.path.join(win, "System32", "notepad.exe"),
                os.path.join(win, "System32", "calc.exe"),
                os.path.join(win, "System32", "drivers", "etc", "hosts"),
            ]
        else:
            arquivos_criticos = []

        for arq in arquivos_criticos:
            if os.path.exists(arq):
                ameacas = self.analisar_arquivo(arq)
                if ameacas:
                    ameaca(f"Arquivo crítico comprometido: {arq}")
                    for a in ameacas:
                        aviso(f"  → {a}")
                else:
                    ok(f"Íntegro: {arq}")
            else:
                aviso(f"Arquivo crítico não encontrado: {arq}")

        # Informações do sistema
        print()
        info(f"Sistema Operacional : {platform.system()} {platform.release()}")
        info(f"Versão              : {platform.version()}")
        info(f"Arquitetura         : {platform.machine()}")
        info(f"Hostname            : {socket.gethostname()}")
        info(f"Usuário atual       : {os.environ.get('USER') or os.environ.get('USERNAME', 'N/A')}")
        try:
            info(f"IP local            : {socket.gethostbyname(socket.gethostname())}")
        except Exception:
            pass

        # Uptime
        boot = psutil.boot_time()
        uptime = datetime.datetime.now() - datetime.datetime.fromtimestamp(boot)
        info(f"Uptime              : {str(uptime).split('.')[0]}")

        # Uso de disco
        print()
        info("Uso de disco por partição:")
        for part in psutil.disk_partitions(all=False):
            try:
                uso = psutil.disk_usage(part.mountpoint)
                pct = uso.percent
                cor = Fore.RED if pct > 90 else (Fore.YELLOW if pct > 75 else Fore.GREEN)
                print(f"    {cor}{part.mountpoint:20s}  {uso.total/(1024**3):6.1f} GB total  "
                      f"{uso.used/(1024**3):6.1f} GB usado  {pct:5.1f}%{Style.RESET_ALL}")
            except PermissionError:
                continue

    # ──────────────────────────────────────────
    # 8. QUARENTENA
    # ──────────────────────────────────────────
    def colocar_quarentena(self):
        if not self.arquivos_suspeitos:
            return

        secao("QUARENTENA DE ARQUIVOS SUSPEITOS")
        aviso(f"{len(self.arquivos_suspeitos)} arquivo(s) serão movidos para quarentena.")
        info(f"Diretório de quarentena: {QUARENTENA_DIR}")

        resposta = input(f"\n  {Fore.YELLOW}Mover arquivos suspeitos para quarentena? [s/N]: {Style.RESET_ALL}").strip().lower()
        if resposta != "s":
            aviso("Quarentena cancelada pelo usuário.")
            return

        for item in self.arquivos_suspeitos:
            try:
                src = item["caminho"]
                nome_q = hashlib.md5(src.encode()).hexdigest()[:8] + "_" + os.path.basename(src) + ".quarantine"
                dst = os.path.join(QUARENTENA_DIR, nome_q)
                shutil.move(src, dst)
                ok(f"Quarentena: {os.path.basename(src)} → {nome_q}")
                log(f"QUARENTENA: {src} → {dst}")
            except Exception as e:
                erro(f"Falha ao mover {item['caminho']}: {e}")

    # ──────────────────────────────────────────
    # 9. RELATÓRIO FINAL
    # ──────────────────────────────────────────
    def gerar_relatorio(self):
        secao("RELATÓRIO FINAL")

        fim = datetime.datetime.now()
        duracao = fim - self.inicio

        relatorio = {
            "versao": VERSAO,
            "inicio": self.inicio.strftime("%Y-%m-%d %H:%M:%S"),
            "fim": fim.strftime("%Y-%m-%d %H:%M:%S"),
            "duracao_segundos": duracao.total_seconds(),
            "sistema": {
                "os": platform.system(),
                "release": platform.release(),
                "hostname": socket.gethostname(),
            },
            "resumo": {
                "arquivos_limpos": self.arquivos_limpos,
                "arquivos_suspeitos": len(self.arquivos_suspeitos),
                "processos_suspeitos": len(self.processos_suspeitos),
                "conexoes_suspeitas": len(self.conexoes_suspeitas),
            },
            "arquivos_suspeitos": self.arquivos_suspeitos,
            "processos_suspeitos": self.processos_suspeitos,
            "conexoes_suspeitas": self.conexoes_suspeitas,
        }

        with open(RELATORIO_FILE, "w", encoding="utf-8") as f:
            json.dump(relatorio, f, ensure_ascii=False, indent=2)

        print()
        print(Fore.CYAN + f"  {'─'*55}")
        print(Fore.WHITE + f"  {'RESUMO DA VARREDURA':^55}")
        print(Fore.CYAN + f"  {'─'*55}")
        print(Fore.GREEN  + f"  Arquivos limpos      : {self.arquivos_limpos:,}")
        print(Fore.RED    + f"  Arquivos suspeitos   : {len(self.arquivos_suspeitos):,}")
        print(Fore.YELLOW + f"  Processos suspeitos  : {len(self.processos_suspeitos):,}")
        print(Fore.YELLOW + f"  Conexões suspeitas   : {len(self.conexoes_suspeitas):,}")
        print(Fore.CYAN   + f"  Duração total        : {str(duracao).split('.')[0]}")
        print(Fore.CYAN + f"  {'─'*55}")
        print()
        ok(f"Relatório salvo em: {RELATORIO_FILE}")
        ok(f"Log detalhado em:   {LOG_FILE}")

        if len(self.arquivos_suspeitos) == 0 and len(self.processos_suspeitos) == 0:
            print(Fore.GREEN + Back.BLACK + "\n  ✔  SISTEMA LIMPO - Nenhuma ameaça confirmada detectada.\n" + Style.RESET_ALL)
        else:
            print(Fore.RED + Back.BLACK + f"\n  ⚠  ATENÇÃO: {len(self.arquivos_suspeitos) + len(self.processos_suspeitos)} possível(is) ameaça(s) detectada(s)!\n" + Style.RESET_ALL)

    # ──────────────────────────────────────────
    # EXECUÇÃO PRINCIPAL
    # ──────────────────────────────────────────
    def executar_varredura_completa(self):
        banner()

        # Determina o diretório raiz de varredura
        if self.sistema == "Windows":
            raiz = os.environ.get("SYSTEMDRIVE", "C:\\")
        else:
            raiz = os.path.expanduser("~")  # Home do usuário por padrão

        print(Fore.YELLOW + "  Escolha o escopo da varredura:")
        print("  [1] Pasta pessoal (mais rápido)")
        print("  [2] Sistema completo (lento, requer root/admin)")
        print("  [3] Pasta personalizada")
        print("  [4] Apenas processos, RAM e rede (sem arquivos)")
        escolha = input(f"\n  {Fore.CYAN}Opção [1-4] (padrão=1): {Style.RESET_ALL}").strip() or "1"

        if escolha == "1":
            dirs_scan = [os.path.expanduser("~")]
        elif escolha == "2":
            dirs_scan = ["/" if self.sistema != "Windows" else "C:\\"]
        elif escolha == "3":
            caminho = input("  Caminho da pasta: ").strip()
            dirs_scan = [caminho] if os.path.isdir(caminho) else [os.path.expanduser("~")]
        else:
            dirs_scan = []

        print()
        info("Iniciando varredura completa do sistema...")
        log("Varredura completa iniciada")

        # Varredura de arquivos
        for d in dirs_scan:
            self.varredura_diretorio(d, profunda=True)

        # Varredura de processos
        self.varredura_processos()

        # Análise de RAM
        self.analisar_ram()

        # Varredura de rede
        self.varredura_rede()

        # Inicialização
        self.varredura_inicializacao()

        # Integridade do sistema
        self.verificar_integridade_sistema()

        # Limpeza de disco
        resp = input(f"\n  {Fore.YELLOW}Executar limpeza de disco? [s/N]: {Style.RESET_ALL}").strip().lower()
        if resp == "s":
            self.limpeza_disco()

        # Quarentena
        self.colocar_quarentena()

        # Relatório final
        self.gerar_relatorio()


# ──────────────────────────────────────────────
# PONTO DE ENTRADA
# ──────────────────────────────────────────────
if __name__ == "__main__":
    # Verifica se está rodando como root/admin para funcionalidades avançadas
    if platform.system() != "Windows":
        if os.geteuid() != 0:
            print(Fore.YELLOW + "\n  [!] Dica: Execute com 'sudo python3 antivirus_completo.py' para varredura completa do sistema.\n")
    
    av = PyShield()
    try:
        av.executar_varredura_completa()
    except KeyboardInterrupt:
        print()
        aviso("Programa encerrado pelo usuário.")
        av.gerar_relatorio()