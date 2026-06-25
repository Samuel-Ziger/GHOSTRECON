#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════════════════
 WPHunter BR v1.0 — Scanner Automatizado de Vulnerabilidades WordPress
═══════════════════════════════════════════════════════════════════════════════

 Ferramenta de segurança ofensiva voltada ao público brasileiro. Identifica
 falhas críticas em instalações WordPress em menos de 60 segundos, gerando
 relatórios completos em HTML (dark theme), JSON e CSV.

 ⚠️  AVISO LEGAL:
 Use APENAS em sites próprios ou com autorização EXPRESSA e por escrito.
 O uso não autorizado é crime no Brasil:
   • Lei 12.737/2012 (Lei Carolina Dieckmann)
   • LGPD 13.709/2018
   • Marco Civil da Internet 12.965/2014

 Autor   : WPHunter BR Team
 Licença : Uso educacional e profissional autorizado
 Versão  : 1.0
═══════════════════════════════════════════════════════════════════════════════
"""

import os
import re
import sys
import csv
import ssl
import json
import time
import socket
import logging
import argparse
import datetime
import threading
from urllib.parse import urljoin, urlparse, quote

# ──────────────────────────────────────────────────────────────────────────────
# Garante saída UTF-8 no terminal (Windows usa cp1252 por padrão e quebra com
# emojis/acentos). Reconfigura stdout/stderr antes de qualquer impressão.
# ──────────────────────────────────────────────────────────────────────────────
def _forcar_utf8():
    for fluxo in (sys.stdout, sys.stderr):
        try:
            fluxo.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if os.name == "nt":
        try:
            os.system("")  # habilita sequências ANSI no Windows Terminal/cmd
        except Exception:
            pass


_forcar_utf8()

# ──────────────────────────────────────────────────────────────────────────────
# Importação de dependências externas com tratamento amigável
# ──────────────────────────────────────────────────────────────────────────────
try:
    import requests
    import urllib3
    from urllib3.exceptions import InsecureRequestWarning
    urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[ERRO] Dependência ausente: requests/urllib3")
    print("       Instale com: pip install requests urllib3")
    sys.exit(1)

try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    print("[ERRO] Dependência ausente: colorama")
    print("       Instale com: pip install colorama")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[ERRO] Dependência ausente: beautifulsoup4")
    print("       Instale com: pip install beautifulsoup4")
    sys.exit(1)

# Dependências opcionais — degradação graciosa se ausentes
try:
    from fake_useragent import UserAgent
    _FAKE_UA = UserAgent()
except Exception:
    _FAKE_UA = None

try:
    import whois as whois_lib
except Exception:
    whois_lib = None

try:
    import dns.resolver
except Exception:
    dns = None

try:
    from jinja2 import Template
except Exception:
    Template = None


# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTES GLOBAIS
# ══════════════════════════════════════════════════════════════════════════════

VERSAO = "1.0"
NOME = "WPHunter BR"
TIMEOUT_REQUEST = 10          # Timeout de 10s por request
TIMEOUT_MODULO = 25           # Timeout máximo por módulo (segundos)
MAX_RETRY = 2                 # Tentativas de retry em falha de rede

# User-Agents de fallback caso fake-useragent não esteja disponível
USER_AGENTS_FALLBACK = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
    "Gecko/20100101 Firefox/121.0",
]

# Níveis de criticidade padronizados
CRITICO = "CRITICO"
ALTO = "ALTO"
MEDIO = "MEDIO"
BAIXO = "BAIXO"
INFO = "INFO"

# Ícones por criticidade
ICONES = {
    CRITICO: "🔴",
    ALTO: "🟠",
    MEDIO: "🟡",
    BAIXO: "🟢",
    INFO: "ℹ️",
}

# Peso de cada criticidade para cálculo do score de segurança
PESO_CRITICIDADE = {
    CRITICO: 25,
    ALTO: 12,
    MEDIO: 6,
    BAIXO: 2,
    INFO: 0,
}


# ══════════════════════════════════════════════════════════════════════════════
# BASE DE CONHECIMENTO — CVEs DE PLUGINS, TEMAS E VERSÕES DO WORDPRESS
# ══════════════════════════════════════════════════════════════════════════════

# Versões do WordPress consideradas desatualizadas/vulneráveis (simplificado).
# Qualquer versão abaixo da última estável conhecida é marcada como desatualizada.
WP_VERSAO_SEGURA = (6, 4, 0)

# Plugins críticos verificados e seus CVEs conhecidos.
# Estrutura: slug -> {nome, cves:[{id, versao_max, cvss, tipo, exploit, ref}]}
PLUGINS_CVE = {
    "contact-form-7": {
        "nome": "Contact Form 7",
        "cves": [
            {"id": "CVE-2020-35489", "versao_max": "5.3.1", "cvss": 9.8,
             "tipo": "Upload irrestrito de arquivos (RCE)", "exploit": True,
             "ref": "https://wpscan.com/vulnerability/CVE-2020-35489"},
        ],
    },
    "wordpress-seo": {
        "nome": "Yoast SEO",
        "cves": [
            {"id": "CVE-2021-25118", "versao_max": "17.2", "cvss": 5.3,
             "tipo": "Exposição de informações via REST API", "exploit": False,
             "ref": "https://wpscan.com/vulnerability/CVE-2021-25118"},
            {"id": "CVE-2018-19370", "versao_max": "9.1", "cvss": 6.1,
             "tipo": "XSS refletido", "exploit": False,
             "ref": "https://wpscan.com/vulnerability/9008"},
        ],
    },
    "woocommerce": {
        "nome": "WooCommerce",
        "cves": [
            {"id": "CVE-2021-32789", "versao_max": "5.5.0", "cvss": 9.8,
             "tipo": "SQL Injection (REST API)", "exploit": True,
             "ref": "https://wpscan.com/vulnerability/CVE-2021-32789"},
        ],
    },
    "elementor": {
        "nome": "Elementor",
        "cves": [
            {"id": "CVE-2022-1329", "versao_max": "3.6.2", "cvss": 8.8,
             "tipo": "RCE via upload (usuário autenticado)", "exploit": True,
             "ref": "https://wpscan.com/vulnerability/CVE-2022-1329"},
        ],
    },
    "sitepress-multilingual-cms": {
        "nome": "WPML",
        "cves": [
            {"id": "CVE-2015-5468", "versao_max": "3.1.9", "cvss": 7.5,
             "tipo": "SQL Injection / divulgação de informações", "exploit": False,
             "ref": "https://wpscan.com/vulnerability/8141"},
        ],
    },
    "revslider": {
        "nome": "Revolution Slider",
        "cves": [
            {"id": "CVE-2014-9734", "versao_max": "4.1.5", "cvss": 9.8,
             "tipo": "LFI / arquivo arbitrário (RCE)", "exploit": True,
             "ref": "https://wpscan.com/vulnerability/cve-2014-9734"},
        ],
    },
    "nextgen-gallery": {
        "nome": "NextGEN Gallery",
        "cves": [
            {"id": "CVE-2020-35942", "versao_max": "3.5.0", "cvss": 9.8,
             "tipo": "Upload arbitrário de arquivos", "exploit": True,
             "ref": "https://wpscan.com/vulnerability/CVE-2020-35942"},
        ],
    },
    "all-in-one-seo-pack": {
        "nome": "All in One SEO",
        "cves": [
            {"id": "CVE-2021-25036", "versao_max": "4.1.5.2", "cvss": 9.9,
             "tipo": "Escalada de privilégios (REST API)", "exploit": True,
             "ref": "https://wpscan.com/vulnerability/CVE-2021-25036"},
        ],
    },
    "duplicator": {
        "nome": "Duplicator",
        "cves": [
            {"id": "CVE-2020-11738", "versao_max": "1.3.26", "cvss": 7.5,
             "tipo": "Directory Traversal (download arbitrário)", "exploit": True,
             "ref": "https://wpscan.com/vulnerability/CVE-2020-11738"},
        ],
    },
    "backupbuddy": {
        "nome": "BackupBuddy",
        "cves": [
            {"id": "CVE-2022-31474", "versao_max": "8.7.4.1", "cvss": 7.5,
             "tipo": "Download arbitrário de arquivos", "exploit": True,
             "ref": "https://wpscan.com/vulnerability/CVE-2022-31474"},
        ],
    },
    "wp-file-manager": {
        "nome": "WP File Manager",
        "cves": [
            {"id": "CVE-2020-25213", "versao_max": "6.8", "cvss": 9.8,
             "tipo": "RCE via upload irrestrito", "exploit": True,
             "ref": "https://wpscan.com/vulnerability/CVE-2020-25213"},
        ],
    },
    "w3-total-cache": {
        "nome": "W3 Total Cache",
        "cves": [
            {"id": "CVE-2019-6715", "versao_max": "0.9.7.4", "cvss": 7.5,
             "tipo": "Exposição de dados (leitura arbitrária)", "exploit": False,
             "ref": "https://wpscan.com/vulnerability/CVE-2019-6715"},
        ],
    },
    "ml-slider": {
        "nome": "MetaSlider",
        "cves": [],
    },
    "akismet": {"nome": "Akismet", "cves": []},
    "jetpack": {"nome": "Jetpack", "cves": []},
    "wpforms-lite": {"nome": "WPForms Lite", "cves": []},
    "wordfence": {"nome": "Wordfence Security", "cves": []},
    "really-simple-ssl": {"nome": "Really Simple SSL", "cves": []},
    "classic-editor": {"nome": "Classic Editor", "cves": []},
    "redirection": {"nome": "Redirection", "cves": []},
}

# Lista expandida de slugs de plugins populares para detecção ativa.
PLUGINS_POPULARES = list(PLUGINS_CVE.keys()) + [
    "wp-super-cache", "google-sitemap-generator", "tinymce-advanced",
    "wp-optimize", "updraftplus", "loginizer", "limit-login-attempts-reloaded",
    "wps-hide-login", "advanced-custom-fields", "regenerate-thumbnails",
    "mailchimp-for-wp", "wp-mail-smtp", "smush", "autoptimize", "litespeed-cache",
    "google-analytics-for-wordpress", "seo-by-rank-math", "elementor-pro",
    "woocommerce-gateway-stripe", "woocommerce-pdf-invoices-packing-slips",
    "ti-woocommerce-wishlist", "contact-form-cfdb7", "ninja-forms",
    "wpforms", "gravityforms", "the-events-calendar", "wordpress-importer",
    "duplicate-post", "broken-link-checker", "table-of-contents-plus",
    "imsanity", "wp-fastest-cache", "wp-rocket", "header-footer-elementor",
    "essential-addons-for-elementor-lite", "premium-addons-for-elementor",
    "instagram-feed", "custom-facebook-feed", "tablepress", "wordpress-popular-posts",
    "popup-maker", "ultimate-member", "buddypress", "bbpress", "polylang",
    "loco-translate", "wpdiscuz", "disqus-comment-system", "wp-statistics",
    "cookie-law-info", "complianz-gdpr", "gdpr-cookie-consent",
]

# Temas verificados e seus CVEs conhecidos.
TEMAS_CVE = {
    "Avada": [
        {"id": "CVE-2021-24284", "versao_max": "7.4.1", "cvss": 9.8,
         "tipo": "Upload arbitrário de arquivos", "exploit": True,
         "ref": "https://wpscan.com/vulnerability/CVE-2021-24284"},
    ],
    "Divi": [
        {"id": "CVE-2023-3460", "versao_max": "4.21.0", "cvss": 8.8,
         "tipo": "Escalada de privilégios", "exploit": False,
         "ref": "https://wpscan.com/vulnerability/CVE-2023-3460"},
    ],
    "Newspaper": [
        {"id": "CVE-2016-10973", "versao_max": "6.7.1", "cvss": 8.8,
         "tipo": "Inclusão de arquivos / XSS", "exploit": True,
         "ref": "https://wpscan.com/vulnerability/8966"},
    ],
    "OceanWP": [],
    "Astra": [],
    "GeneratePress": [],
    "Flatsome": [],
}

# Endpoints sensíveis verificados pelo módulo 5.
ENDPOINTS_CRITICOS = [
    ("/wp-login.php", "Página de login", MEDIO),
    ("/wp-admin/", "Painel administrativo", BAIXO),
    ("/xmlrpc.php", "Interface XML-RPC", ALTO),
    ("/wp-json/", "REST API exposta", MEDIO),
    ("/wp-config.php", "Configuração principal", CRITICO),
    ("/wp-config.php.bak", "Backup de configuração", CRITICO),
    ("/wp-config.php.old", "Backup de configuração", CRITICO),
    ("/wp-config.php~", "Backup de configuração (editor)", CRITICO),
    ("/.htaccess", "Controle de acesso Apache", ALTO),
    ("/readme.html", "Versão do WordPress exposta", MEDIO),
    ("/license.txt", "Versão do WordPress exposta", BAIXO),
    ("/wp-cron.php", "Agendador de tarefas", BAIXO),
    ("/wp-includes/", "Listagem de diretório", MEDIO),
    ("/wp-content/uploads/", "Listagem de uploads", MEDIO),
    ("/wp-content/debug.log", "Log de depuração exposto", ALTO),
    ("/wp-content/", "Listagem de conteúdo", BAIXO),
]

# Arquivos de backup e sensíveis verificados pelo módulo 9.
ARQUIVOS_BACKUP = [
    ("/backup.zip", CRITICO), ("/backup.sql", CRITICO),
    ("/wp-backup.zip", CRITICO), ("/database.sql", CRITICO),
    ("/site.zip", CRITICO), ("/wordpress.zip", CRITICO),
    ("/db-backup.sql", CRITICO), ("/dump.sql", CRITICO),
    ("/backup.tar.gz", CRITICO), ("/www.zip", CRITICO),
    ("/public_html.zip", CRITICO), ("/wp-content/backup.zip", CRITICO),
    ("/.env", CRITICO), ("/.git/config", ALTO),
    ("/.git/HEAD", ALTO), ("/wp-config.php.bak", CRITICO),
    ("/wp-config.php.old", CRITICO), ("/wp-config.php.save", CRITICO),
    ("/wp-config.php.txt", CRITICO), ("/error_log", MEDIO),
    ("/debug.log", MEDIO), ("/phpinfo.php", ALTO),
    ("/info.php", ALTO), ("/test.php", MEDIO),
    ("/.DS_Store", BAIXO), ("/.svn/entries", MEDIO),
    ("/wp-content/uploads/backup.zip", CRITICO),
    ("/adminer.php", ALTO), ("/.user.ini", MEDIO),
]

# Wordlist brasileira embutida para teste de credenciais (módulo 6).
SENHAS_COMUNS_BR = [
    "admin", "password", "123456", "12345678", "wordpress", "senha123",
    "minhasenha", "brasil123", "admin123", "123456789", "qwerty",
    "abc123", "senha", "mudar123", "senha@123", "Brasil@2024",
    "Brasil@2025", "admin@123", "P@ssw0rd", "root", "toor",
]


# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURAÇÃO DE LOGGING
# ══════════════════════════════════════════════════════════════════════════════

def configurar_logging():
    """Configura logging completo em arquivo .log com timestamp."""
    logger = logging.getLogger("wphunter")
    logger.setLevel(logging.DEBUG)
    if logger.handlers:
        return logger
    nome_log = f"wphunter_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    try:
        fh = logging.FileHandler(nome_log, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except Exception:
        pass  # Se não puder escrever log, continua sem ele
    return logger


LOG = configurar_logging()


# ══════════════════════════════════════════════════════════════════════════════
# UTILITÁRIOS DE INTERFACE (CORES,BANNER, PROGRESSO)
# ══════════════════════════════════════════════════════════════════════════════

class UI:
    """Centraliza saída colorida no terminal em português brasileiro."""

    GRAY = Style.DIM + Fore.WHITE

    @staticmethod
    def limpar_terminal():
        """Limpa a tela do terminal (Windows e Linux)."""
        os.system("cls" if os.name == "nt" else "clear")

    @staticmethod
    def banner():
        """Exibe o banner ASCII principal com aviso legal."""
        b = Fore.CYAN + Style.BRIGHT
        r = Style.RESET_ALL
        y = Fore.YELLOW + Style.BRIGHT
        print(b + r"""
 ██╗    ██╗██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
 ██║    ██║██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ██║ █╗ ██║██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ██║███╗██║██╔═══╝ ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ╚███╔███╔╝██║     ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚══╝╚══╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
""" + r)
        print(b + "╔══════════════════════════════════════════════════════════╗" + r)
        print(b + "║" + r + f"   {NOME} v{VERSAO}".ljust(58) + b + "║" + r)
        print(b + "║" + r + "   Scanner de Vulnerabilidades WordPress".ljust(58) + b + "║" + r)
        print(b + "║" + r + y + "   ⚠️  Use apenas com autorização expressa".ljust(57) + r + b + "║" + r)
        print(b + "╚══════════════════════════════════════════════════════════╝" + r)
        print()
        print(y + "⚠️  USE APENAS EM SITES PRÓPRIOS OU COM AUTORIZAÇÃO EXPRESSA.")
        print(UI.GRAY + "    Lei 12.737/2012  |  LGPD 13.709/2018  |  Marco Civil 12.965/2014" + r)
        print()

    @staticmethod
    def modulo(num, total, nome):
        """Cabeçalho amarelo de módulo ativo."""
        print()
        print(Fore.YELLOW + Style.BRIGHT +
              f"┌─[ Módulo {num}/{total} ]─ {nome} " + "─" * max(0, 30 - len(nome)))

    @staticmethod
    def progresso(num, total, nome, pct, eta):
        """Barra de progresso em tempo real."""
        cheios = int(pct / 10)
        barra = "█" * cheios + "░" * (10 - cheios)
        eta_str = time.strftime("%M:%S", time.gmtime(max(0, eta)))
        sys.stdout.write(
            "\r" + Fore.YELLOW +
            f"[Módulo {num}/{total}] {nome[:24]:<24} " +
            Fore.CYAN + f"[{barra}] {pct:3.0f}%" +
            UI.GRAY + f" | ETA: {eta_str}   ")
        sys.stdout.flush()

    @staticmethod
    def critico(msg):
        print(Fore.RED + Style.BRIGHT + f"   🔴 {msg}")

    @staticmethod
    def alto(msg):
        print(Fore.LIGHTRED_EX + f"   🟠 {msg}")

    @staticmethod
    def medio(msg):
        print(Fore.YELLOW + f"   🟡 {msg}")

    @staticmethod
    def baixo(msg):
        print(Fore.GREEN + f"   🟢 {msg}")

    @staticmethod
    def sucesso(msg):
        print(Fore.GREEN + Style.BRIGHT + f"   ✅ {msg}")

    @staticmethod
    def info(msg):
        print(Fore.WHITE + f"   ℹ️  {msg}")

    @staticmethod
    def aviso(msg):
        print(Fore.YELLOW + Style.BRIGHT + f"   ⚠️  {msg}")

    @staticmethod
    def erro(msg):
        print(Fore.RED + Style.BRIGHT + f"   ❌ {msg}")

    @staticmethod
    def comentario(msg):
        print(UI.GRAY + f"   {msg}")

    @staticmethod
    def por_criticidade(nivel, msg):
        """Imprime mensagem com a cor adequada ao nível de criticidade."""
        if nivel == CRITICO:
            UI.critico(msg)
        elif nivel == ALTO:
            UI.alto(msg)
        elif nivel == MEDIO:
            UI.medio(msg)
        elif nivel == BAIXO:
            UI.baixo(msg)
        else:
            UI.info(msg)


# ══════════════════════════════════════════════════════════════════════════════
# CLASSE DE RESULTADO / VULNERABILIDADE
# ══════════════════════════════════════════════════════════════════════════════

class Vulnerabilidade:
    """Representa uma vulnerabilidade ou achado de segurança."""

    def __init__(self, titulo, criticidade, descricao="", como_explorar="",
                 como_corrigir="", referencia="", detalhe="", modulo=""):
        self.titulo = titulo
        self.criticidade = criticidade
        self.descricao = descricao
        self.como_explorar = como_explorar
        self.como_corrigir = como_corrigir
        self.referencia = referencia
        self.detalhe = detalhe
        self.modulo = modulo

    def to_dict(self):
        return {
            "titulo": self.titulo,
            "criticidade": self.criticidade,
            "descricao": self.descricao,
            "como_explorar": self.como_explorar,
            "como_corrigir": self.como_corrigir,
            "referencia": self.referencia,
            "detalhe": self.detalhe,
            "modulo": self.modulo,
        }


# ══════════════════════════════════════════════════════════════════════════════
# GERENCIADOR DE SESSÃO HTTP (reutilizada, retry, headers aleatórios)
# ══════════════════════════════════════════════════════════════════════════════

class SessaoHTTP:
    """Encapsula uma sessão requests reutilizável com retry e UA aleatório."""

    def __init__(self, stealth=False, aggressive=False, verify_ssl=True):
        self.stealth = stealth
        self.aggressive = aggressive
        self.verify_ssl = verify_ssl
        self.waf_detectado = False
        self.rate_limit_detectado = False
        self.session = requests.Session()
        self.session.headers.update(self._headers_base())
        # Atraso entre requisições conforme modo de operação
        if stealth:
            self.delay = 1.5
        elif aggressive:
            self.delay = 0.0
        else:
            self.delay = 0.2

    def _ua_aleatorio(self):
        """Retorna um User-Agent aleatório (fake-useragent ou fallback)."""
        if _FAKE_UA is not None:
            try:
                return _FAKE_UA.random
            except Exception:
                pass
        import random
        return random.choice(USER_AGENTS_FALLBACK)

    def _headers_base(self):
        return {
            "User-Agent": self._ua_aleatorio(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
            "Connection": "keep-alive",
        }

    def get(self, url, **kwargs):
        return self._request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self._request("POST", url, **kwargs)

    def head(self, url, **kwargs):
        return self._request("HEAD", url, **kwargs)

    def _request(self, metodo, url, **kwargs):
        """Executa request com retry, rotação de UA e detecção de WAF/rate-limit."""
        kwargs.setdefault("timeout", TIMEOUT_REQUEST)
        kwargs.setdefault("verify", self.verify_ssl)
        kwargs.setdefault("allow_redirects", True)
        # Rotaciona User-Agent a cada requisição (ruído reduzido)
        self.session.headers["User-Agent"] = self._ua_aleatorio()

        if self.delay > 0:
            time.sleep(self.delay)

        ultima_exc = None
        for tentativa in range(MAX_RETRY + 1):
            try:
                resp = self.session.request(metodo, url, **kwargs)
                self._analisar_protecoes(resp)
                LOG.debug(f"{metodo} {url} -> {resp.status_code}")
                return resp
            except requests.exceptions.SSLError as e:
                # SSL inválido: tenta novamente sem verificação
                LOG.warning(f"SSL inválido em {url}: {e}")
                kwargs["verify"] = False
                ultima_exc = e
            except requests.exceptions.RequestException as e:
                ultima_exc = e
                LOG.warning(f"Falha {metodo} {url} (tentativa {tentativa+1}): {e}")
                time.sleep(0.5 * (tentativa + 1))
        LOG.error(f"Request falhou definitivamente: {url} -> {ultima_exc}")
        return None

    def _analisar_protecoes(self, resp):
        """Detecta WAF (Cloudflare) e rate limiting nas respostas."""
        if resp is None:
            return
        server = resp.headers.get("Server", "").lower()
        if "cloudflare" in server or "cf-ray" in {k.lower() for k in resp.headers}:
            self.waf_detectado = True
        if resp.status_code == 429:
            self.rate_limit_detectado = True
            # Ativa modo stealth automaticamente
            if self.delay < 1.5:
                self.delay = 1.5


# ══════════════════════════════════════════════════════════════════════════════
# CLASSE BASE PARA MÓDULOS
# ══════════════════════════════════════════════════════════════════════════════

class ModuloBase:
    """Classe base com utilitários compartilhados entre os módulos."""

    def __init__(self, contexto):
        self.ctx = contexto              # Referência ao WPHunter (contexto global)
        self.http = contexto.http
        self.base_url = contexto.base_url
        self.vulnerabilidades = []

    def url(self, caminho):
        """Constrói URL absoluta a partir do caminho relativo."""
        return urljoin(self.base_url + "/", caminho.lstrip("/"))

    def add_vuln(self, vuln):
        """Adiciona vulnerabilidade ao módulo e ao contexto global."""
        self.vulnerabilidades.append(vuln)
        self.ctx.vulnerabilidades.append(vuln)

    @staticmethod
    def comparar_versoes(v1, v2):
        """Compara duas versões. Retorna -1, 0 ou 1 (v1 <, ==, > v2)."""
        def normalizar(v):
            partes = re.findall(r"\d+", str(v))
            return [int(p) for p in partes] if partes else [0]
        a, b = normalizar(v1), normalizar(v2)
        tam = max(len(a), len(b))
        a += [0] * (tam - len(a))
        b += [0] * (tam - len(b))
        for x, y in zip(a, b):
            if x < y:
                return -1
            if x > y:
                return 1
        return 0


# ══════════════════════════════════════════════════════════════════════════════
# MÓDULO 1 — DETECTOR WORDPRESS
# ══════════════════════════════════════════════════════════════════════════════

class DetectorWordPress(ModuloBase):
    """Confirma se o alvo é WordPress, extrai versão, tecnologias e WHOIS."""

    def executar(self):
        info = self.ctx.info_alvo
        confirmacoes = 0

        # 1) Página inicial — meta generator, wp-content, headers
        resp_home = self.http.get(self.base_url)
        if resp_home is not None:
            html = resp_home.text or ""
            self._analisar_headers(resp_home, info)

            if "/wp-content/" in html:
                confirmacoes += 1
            if "/wp-includes/" in html:
                confirmacoes += 1

            # Meta generator
            m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']'
                          r'WordPress\s*([\d.]+)?', html, re.I)
            if m:
                confirmacoes += 2
                if m.group(1):
                    info["wp_versao"] = m.group(1)

        # 2) Caminhos típicos do WordPress
        for caminho in ("/wp-login.php", "/wp-admin/", "/wp-content/"):
            r = self.http.get(self.url(caminho))
            if r is not None and r.status_code in (200, 301, 302, 401, 403):
                confirmacoes += 1

        # 3) wp-json
        r = self.http.get(self.url("/wp-json/"))
        if r is not None and r.status_code == 200 and "application/json" in \
                r.headers.get("Content-Type", ""):
            confirmacoes += 2
            try:
                data = r.json()
                if "name" in data:
                    info["site_nome"] = data.get("name")
                    info["site_descricao"] = data.get("description", "")
            except Exception:
                pass

        info["is_wordpress"] = confirmacoes >= 2
        self.ctx.is_wordpress = info["is_wordpress"]

        # Extração de versão por múltiplas fontes
        if not info.get("wp_versao"):
            info["wp_versao"] = self._extrair_versao()

        # Avaliação da versão
        if info.get("wp_versao"):
            ver = info["wp_versao"]
            if self.comparar_versoes(ver,
                                     ".".join(map(str, WP_VERSAO_SEGURA))) < 0:
                self.add_vuln(Vulnerabilidade(
                    titulo=f"WordPress desatualizado (v{ver})",
                    criticidade=ALTO,
                    descricao=f"A versão {ver} do WordPress está abaixo da "
                              f"versão estável recomendada. Versões antigas "
                              f"acumulam vulnerabilidades conhecidas.",
                    como_explorar="Atacantes consultam bancos de CVEs para a "
                                  "versão exata e aplicam exploits públicos.",
                    como_corrigir="Atualize o WordPress para a última versão "
                                  "estável em Painel > Atualizações. Ative "
                                  "atualizações automáticas de segurança.",
                    referencia="https://wordpress.org/download/releases/",
                    modulo="Detector WordPress"))

        # WHOIS
        self._whois(info)

        # Saída no terminal
        self._exibir(info)

    def _analisar_headers(self, resp, info):
        """Extrai PHP, servidor web, CDN e cabeçalhos relevantes."""
        h = resp.headers
        server = h.get("Server", "")
        powered = h.get("X-Powered-By", "")
        info["servidor"] = server or "Desconhecido"
        info["x_powered_by"] = powered

        m = re.search(r"PHP/([\d.]+)", powered)
        if m:
            info["php_versao"] = m.group(1)

        if "cloudflare" in server.lower() or "CF-RAY" in h:
            info["cdn"] = "Cloudflare"
        elif "x-cache" in {k.lower() for k in h}:
            info["cdn"] = "CDN/Cache ativo"
        else:
            info["cdn"] = "Não detectado"

        info["ssl_valido"] = self.base_url.startswith("https")

    def _extrair_versao(self):
        """Tenta extrair a versão do WP via readme.html e feed RSS."""
        # readme.html
        r = self.http.get(self.url("/readme.html"))
        if r is not None and r.status_code == 200:
            m = re.search(r"Version\s*([\d.]+)", r.text)
            if m:
                return m.group(1)
        # Feed RSS
        r = self.http.get(self.url("/feed/"))
        if r is not None and r.status_code == 200:
            m = re.search(r"<generator>https?://wordpress\.org/\?v=([\d.]+)",
                          r.text)
            if m:
                return m.group(1)
        return None

    def _whois(self, info):
        """Consulta WHOIS do domínio (proprietário, país, datas)."""
        dominio = urlparse(self.base_url).hostname or ""
        info["dominio"] = dominio
        if whois_lib is None:
            info["whois"] = "Módulo python-whois indisponível"
            return
        try:
            w = whois_lib.whois(dominio)
            criar = w.creation_date
            expirar = w.expiration_date
            if isinstance(criar, list):
                criar = criar[0]
            if isinstance(expirar, list):
                expirar = expirar[0]
            info["whois"] = {
                "registrar": str(w.registrar) if w.registrar else "N/D",
                "pais": str(w.country) if getattr(w, "country", None) else "N/D",
                "criacao": str(criar) if criar else "N/D",
                "expiracao": str(expirar) if expirar else "N/D",
            }
        except Exception as e:
            LOG.warning(f"WHOIS falhou: {e}")
            info["whois"] = "Consulta WHOIS indisponível"

    def _exibir(self, info):
        print()
        if info.get("is_wordpress"):
            UI.sucesso(f"WordPress detectado" +
                       (f" — versão {info['wp_versao']}" if info.get("wp_versao") else ""))
        else:
            UI.erro("WordPress NÃO detectado neste endereço.")
            return

        if info.get("php_versao"):
            php = info["php_versao"]
            vuln_php = self.comparar_versoes(php, "8.0.0") < 0
            tag = " (VULNERÁVEL/EOL)" if vuln_php else ""
            UI.por_criticidade(ALTO if vuln_php else INFO,
                               f"PHP {php}{tag}")
            if vuln_php:
                self.add_vuln(Vulnerabilidade(
                    titulo=f"PHP desatualizado/EOL ({php})",
                    criticidade=ALTO,
                    descricao="Versões de PHP abaixo da 8.0 não recebem mais "
                              "atualizações de segurança (fim de vida).",
                    como_explorar="Exploits específicos da versão do PHP podem "
                                  "ser aplicados; falhas conhecidas ficam abertas.",
                    como_corrigir="Solicite ao provedor de hospedagem a "
                                  "atualização do PHP para 8.1+.",
                    referencia="https://www.php.net/supported-versions.php",
                    modulo="Detector WordPress"))
        if info.get("servidor"):
            UI.info(f"Servidor: {info['servidor']}")
        if info.get("cdn") and info["cdn"] != "Não detectado":
            UI.info(f"CDN/WAF: {info['cdn']}")
        if info.get("ssl_valido"):
            UI.baixo("SSL/TLS: conexão HTTPS ativa")
        else:
            UI.medio("SSL/TLS: site sem HTTPS")
        if isinstance(info.get("whois"), dict):
            w = info["whois"]
            UI.comentario(f"WHOIS: {w['registrar']} | {w['pais']} | "
                          f"criado {w['criacao'][:10]}")


# ══════════════════════════════════════════════════════════════════════════════
# MÓDULO 2 — ENUMERAÇÃO DE USUÁRIOS
# ══════════════════════════════════════════════════════════════════════════════

class EnumeradorUsuarios(ModuloBase):
    """Enumera usuários por REST API, author archive, oEmbed e sitemap."""

    def executar(self):
        usuarios = {}

        self._tecnica_rest_api(usuarios)
        self._tecnica_author_archive(usuarios)
        self._tecnica_oembed(usuarios)
        self._tecnica_sitemap(usuarios)

        lista = list(usuarios.values())
        self.ctx.usuarios = lista

        if lista:
            self.add_vuln(Vulnerabilidade(
                titulo=f"Enumeração de usuários possível ({len(lista)} encontrados)",
                criticidade=MEDIO,
                descricao="Os nomes de login dos usuários foram expostos. "
                          "Isso facilita ataques de força bruta direcionados.",
                como_explorar="Com o login conhecido, basta descobrir a senha "
                              "via brute force (módulo 6) ou phishing.",
                como_corrigir="Bloqueie /wp-json/wp/v2/users, desabilite a "
                              "enumeração por author archive e use plugins como "
                              "'Stop User Enumeration'. Evite logins óbvios "
                              "como 'admin'.",
                referencia="https://owasp.org/www-community/attacks/"
                           "Username_enumeration",
                detalhe="; ".join(u["login"] for u in lista),
                modulo="Enumeração de Usuários"))

        # Saída
        print()
        UI.info(f"Usuários encontrados: {len(lista)}")
        for u in lista:
            risco = "RISCO ALTO" if u["login"].lower() in (
                "admin", "administrator", "root") else ""
            cor = UI.alto if risco else UI.baixo
            cor(f"ID:{u.get('id','?')} → {u['login']}" +
                (f" ({risco})" if risco else "") +
                (f"  [{u['nome']}]" if u.get("nome") else ""))
            if risco:
                self.add_vuln(Vulnerabilidade(
                    titulo=f"Usuário administrador previsível: '{u['login']}'",
                    criticidade=ALTO,
                    descricao="Existe um usuário com login administrativo "
                              "previsível, alvo prioritário de força bruta.",
                    como_explorar="Ataques de dicionário focam diretamente "
                                  "neste login conhecido.",
                    como_corrigir="Renomeie o usuário 'admin' para algo único "
                                  "e crie uma conta administrativa nova.",
                    referencia="https://wpscan.com",
                    modulo="Enumeração de Usuários"))

    def _registrar(self, usuarios, login, nome=None, uid=None, slug=None,
                   avatar=None):
        if not login:
            return
        chave = (slug or login).lower()
        if chave not in usuarios:
            usuarios[chave] = {"login": login, "nome": nome or "",
                               "id": uid, "slug": slug or login,
                               "avatar": avatar or ""}
        else:
            u = usuarios[chave]
            u["nome"] = u["nome"] or (nome or "")
            u["id"] = u["id"] or uid

    def _tecnica_rest_api(self, usuarios):
        """GET /wp-json/wp/v2/users."""
        r = self.http.get(self.url("/wp-json/wp/v2/users"))
        if r is None or r.status_code != 200:
            return
        try:
            for item in r.json():
                self._registrar(
                    usuarios,
                    login=item.get("slug"),
                    nome=item.get("name"),
                    uid=item.get("id"),
                    slug=item.get("slug"),
                    avatar=(item.get("avatar_urls") or {}).get("96", ""))
        except Exception as e:
            LOG.debug(f"REST API users parse: {e}")

    def _tecnica_author_archive(self, usuarios):
        """GET /?author=N detectando redirecionamento com slug."""
        for uid in range(1, 11):
            r = self.http.get(self.base_url + f"/?author={uid}",
                              allow_redirects=False)
            if r is None:
                continue
            slug = None
            if r.status_code in (301, 302):
                loc = r.headers.get("Location", "")
                m = re.search(r"/author/([^/]+)/?", loc)
                if m:
                    slug = m.group(1)
            elif r.status_code == 200:
                m = re.search(r'/author/([^/"\']+)', r.text)
                if m:
                    slug = m.group(1)
            if slug:
                self._registrar(usuarios, login=slug, uid=uid, slug=slug)

    def _tecnica_oembed(self, usuarios):
        """GET /wp-json/oembed/1.0/embed extraindo author_name."""
        alvo = quote(self.base_url, safe="")
        r = self.http.get(self.url(f"/wp-json/oembed/1.0/embed?url={alvo}"))
        if r is None or r.status_code != 200:
            return
        try:
            data = r.json()
            nome = data.get("author_name")
            if nome:
                self._registrar(usuarios, login=nome.lower().replace(" ", "_"),
                                nome=nome)
        except Exception:
            pass

    def _tecnica_sitemap(self, usuarios):
        """Busca autores em sitemaps XML."""
        for sm in ("/wp-sitemap-users-1.xml", "/author-sitemap.xml",
                   "/sitemap_index.xml"):
            r = self.http.get(self.url(sm))
            if r is None or r.status_code != 200:
                continue
            for m in re.finditer(r"/author/([^/<]+)/?", r.text):
                slug = m.group(1)
                self._registrar(usuarios, login=slug, slug=slug)


# ══════════════════════════════════════════════════════════════════════════════
# MÓDULO 3 — SCANNER DE PLUGINS
# ══════════════════════════════════════════════════════════════════════════════

class ScannerPlugins(ModuloBase):
    """Detecta plugins (passiva e ativa) e correlaciona CVEs."""

    def executar(self):
        plugins = {}

        # Detecção passiva — analisa código-fonte da home
        self._deteccao_passiva(plugins)

        # Detecção ativa — verifica readme.txt dos plugins populares
        limite = PLUGINS_POPULARES if self.ctx.aggressive else PLUGINS_POPULARES[:40]
        self._deteccao_ativa(plugins, limite)

        lista = list(plugins.values())
        self.ctx.plugins = lista

        # Correlaciona CVEs e gera vulnerabilidades
        for p in lista:
            self._avaliar_cve(p)

        # Saída
        print()
        UI.info(f"Plugins detectados: {len(lista)}")
        for p in sorted(lista, key=lambda x: x.get("pior_criticidade_idx", 99)):
            ver = f" v{p['versao']}" if p.get("versao") else ""
            if p.get("cve"):
                cve = p["cve"]
                UI.por_criticidade(
                    p["criticidade"],
                    f"{p['nome']}{ver} — {cve['id']} "
                    f"(CVSS {cve['cvss']}, {cve['tipo']})")
            else:
                UI.baixo(f"{p['nome']}{ver} — sem CVE conhecido")

    def _registrar(self, plugins, slug, nome=None, versao=None):
        if slug not in plugins:
            plugins[slug] = {"slug": slug,
                             "nome": nome or PLUGINS_CVE.get(slug, {}).get(
                                 "nome", slug),
                             "versao": versao}
        else:
            if versao and not plugins[slug].get("versao"):
                plugins[slug]["versao"] = versao

    def _deteccao_passiva(self, plugins):
        """Procura /wp-content/plugins/ no HTML da página."""
        r = self.http.get(self.base_url)
        if r is None:
            return
        for m in re.finditer(
                r"/wp-content/plugins/([a-z0-9\-_]+)/[^\"']*?"
                r"(?:[?&]ver=([\d.]+))?", r.text, re.I):
            self._registrar(plugins, m.group(1).lower(), versao=m.group(2))

    def _deteccao_ativa(self, plugins, slugs):
        """Verifica readme.txt de cada plugin para confirmar presença/versão."""
        for slug in slugs:
            caminho = f"/wp-content/plugins/{slug}/readme.txt"
            r = self.http.get(self.url(caminho))
            if r is None or r.status_code != 200:
                continue
            texto = r.text[:4000]
            if "stable tag" not in texto.lower() and "=== " not in texto:
                continue
            m = re.search(r"Stable tag:\s*([\d.]+)", texto, re.I)
            versao = m.group(1) if m else None
            mn = re.search(r"===\s*(.+?)\s*===", texto)
            nome = mn.group(1).strip() if mn else None
            self._registrar(plugins, slug, nome=nome, versao=versao)

    def _avaliar_cve(self, plugin):
        """Correlaciona a versão do plugin com CVEs conhecidos."""
        slug = plugin["slug"]
        dados = PLUGINS_CVE.get(slug)
        plugin["pior_criticidade_idx"] = 99
        if not dados or not dados.get("cves"):
            return
        versao = plugin.get("versao")
        for cve in dados["cves"]:
            vulneravel = True
            if versao:
                vulneravel = self.comparar_versoes(versao, cve["versao_max"]) <= 0
            if vulneravel:
                crit = CRITICO if cve["cvss"] >= 9.0 else (
                    ALTO if cve["cvss"] >= 7.0 else MEDIO)
                plugin["cve"] = cve
                plugin["criticidade"] = crit
                plugin["pior_criticidade_idx"] = list(PESO_CRITICIDADE).index(crit)
                exploit = " — EXPLOIT PÚBLICO DISPONÍVEL" if cve["exploit"] else ""
                self.add_vuln(Vulnerabilidade(
                    titulo=f"{plugin['nome']} vulnerável — {cve['id']}",
                    criticidade=crit,
                    descricao=f"O plugin {plugin['nome']} "
                              f"(v{versao or '?'}) é afetado por {cve['id']}: "
                              f"{cve['tipo']}. CVSS {cve['cvss']}.{exploit}",
                    como_explorar=f"Consulte o exploit público referente a "
                                  f"{cve['id']} ({cve['tipo']}). "
                                  f"Ferramentas como Metasploit/WPScan podem "
                                  f"automatizar a exploração.",
                    como_corrigir=f"Atualize o plugin {plugin['nome']} para a "
                                  f"versão mais recente imediatamente, ou "
                                  f"desative-o se não for essencial.",
                    referencia=cve["ref"],
                    detalhe=f"Versão instalada: {versao or 'desconhecida'} | "
                            f"Afeta até: {cve['versao_max']}",
                    modulo="Scanner de Plugins"))
                break  # registra apenas o CVE mais grave


# ══════════════════════════════════════════════════════════════════════════════
# MÓDULO 4 — SCANNER DE TEMAS
# ══════════════════════════════════════════════════════════════════════════════

class ScannerTemas(ModuloBase):
    """Detecta tema ativo e versão, correlacionando CVEs conhecidos."""

    def executar(self):
        temas = {}

        # Detecção passiva via HTML
        r = self.http.get(self.base_url)
        if r is not None:
            for m in re.finditer(
                    r"/wp-content/themes/([a-z0-9\-_]+)/[^\"']*?"
                    r"(?:[?&]ver=([\d.]+))?", r.text, re.I):
                slug = m.group(1).lower()
                if slug not in temas:
                    temas[slug] = {"slug": slug, "versao": m.group(2),
                                   "nome": slug, "ativo": True}

        # Para cada tema, lê style.css para extrair metadados
        for slug, tema in list(temas.items()):
            self._ler_style(slug, tema)

        lista = list(temas.values())
        self.ctx.temas = lista

        for tema in lista:
            self._avaliar_cve(tema)

        # Saída
        print()
        if not lista:
            UI.info("Nenhum tema detectado passivamente.")
            return
        for tema in lista:
            ver = f" v{tema['versao']}" if tema.get("versao") else ""
            estado = "ativo" if tema.get("ativo") else "instalado"
            if tema.get("cve"):
                cve = tema["cve"]
                UI.por_criticidade(
                    tema["criticidade"],
                    f"Tema {estado}: {tema['nome']}{ver} — {cve['id']} "
                    f"({cve['tipo']})")
            else:
                UI.sucesso(f"Tema {estado}: {tema['nome']}{ver}")

    def _ler_style(self, slug, tema):
        """Lê style.css do tema para extrair nome, versão, autor e URI."""
        r = self.http.get(self.url(f"/wp-content/themes/{slug}/style.css"))
        if r is None or r.status_code != 200:
            return
        cab = r.text[:2000]
        for campo, chave in (("Theme Name", "nome"), ("Version", "versao"),
                             ("Author", "autor"), ("Theme URI", "uri")):
            m = re.search(rf"{campo}:\s*(.+)", cab)
            if m:
                val = m.group(1).strip()
                if chave == "versao":
                    mv = re.search(r"[\d.]+", val)
                    val = mv.group(0) if mv else val
                tema[chave] = val

    def _avaliar_cve(self, tema):
        """Correlaciona o nome do tema com CVEs conhecidos."""
        nome = tema.get("nome", "")
        for tnome, cves in TEMAS_CVE.items():
            if tnome.lower() in nome.lower() or tnome.lower() == tema["slug"]:
                for cve in cves:
                    versao = tema.get("versao")
                    vulneravel = True
                    if versao:
                        vulneravel = self.comparar_versoes(
                            versao, cve["versao_max"]) <= 0
                    if vulneravel:
                        crit = CRITICO if cve["cvss"] >= 9.0 else (
                            ALTO if cve["cvss"] >= 7.0 else MEDIO)
                        tema["cve"] = cve
                        tema["criticidade"] = crit
                        self.add_vuln(Vulnerabilidade(
                            titulo=f"Tema {nome} vulnerável — {cve['id']}",
                            criticidade=crit,
                            descricao=f"O tema {nome} (v{versao or '?'}) é "
                                      f"afetado por {cve['id']}: {cve['tipo']}.",
                            como_explorar=f"Exploit público para {cve['id']} "
                                          f"pode permitir {cve['tipo']}.",
                            como_corrigir=f"Atualize o tema {nome} para a versão "
                                          f"mais recente ou substitua-o.",
                            referencia=cve["ref"],
                            modulo="Scanner de Temas"))
                        break


# ══════════════════════════════════════════════════════════════════════════════
# MÓDULO 5 — VERIFICAÇÃO DE ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

class VerificadorEndpoints(ModuloBase):
    """Verifica endpoints críticos, xmlrpc e proteções de login."""

    def executar(self):
        print()
        for caminho, descricao, crit_base in ENDPOINTS_CRITICOS:
            r = self.http.get(self.url(caminho), allow_redirects=False)
            if r is None:
                continue
            self._avaliar_endpoint(caminho, descricao, crit_base, r)

        self._analisar_xmlrpc()
        self._analisar_login()

    def _avaliar_endpoint(self, caminho, descricao, crit_base, r):
        codigo = r.status_code
        # wp-config.php acessível com conteúdo PHP = catastrófico
        if caminho.startswith("/wp-config") and codigo == 200 and \
                "DB_PASSWORD" in (r.text or ""):
            UI.critico(f"{caminho} ACESSÍVEL com credenciais expostas!")
            self.add_vuln(Vulnerabilidade(
                titulo=f"{caminho} expõe credenciais do banco",
                criticidade=CRITICO,
                descricao="O arquivo de configuração principal está acessível "
                          "e revela usuário/senha do banco de dados.",
                como_explorar="Atacante lê DB_USER/DB_PASSWORD e acessa o banco "
                              "diretamente, comprometendo todo o site.",
                como_corrigir="Mova wp-config.php para fora do webroot ou "
                              "bloqueie via .htaccess/Nginx. Troque as senhas.",
                referencia="https://wordpress.org/documentation/article/"
                           "hardening-wordpress/",
                modulo="Verificação de Endpoints"))
            return

        # Listagem de diretório
        if caminho.endswith("/") and codigo == 200 and \
                ("Index of" in (r.text or "") or "Parent Directory" in (r.text or "")):
            UI.por_criticidade(MEDIO, f"{caminho} com LISTAGEM DE DIRETÓRIO ativa")
            self.add_vuln(Vulnerabilidade(
                titulo=f"Listagem de diretório em {caminho}",
                criticidade=MEDIO,
                descricao="O diretório expõe a listagem de seus arquivos, "
                          "revelando estrutura interna e arquivos sensíveis.",
                como_explorar="Navegação direta revela plugins, uploads, "
                              "backups e arquivos não públicos.",
                como_corrigir="Adicione 'Options -Indexes' no .htaccess ou "
                              "'autoindex off' no Nginx.",
                referencia="https://owasp.org/www-community/vulnerabilities/"
                           "Directory_listing",
                modulo="Verificação de Endpoints"))
            return

        # Arquivos de versão expostos
        if caminho in ("/readme.html", "/license.txt") and codigo == 200:
            UI.por_criticidade(crit_base, f"{caminho} EXPOSTO (versão visível)")
            self.add_vuln(Vulnerabilidade(
                titulo=f"{caminho} exposto",
                criticidade=crit_base,
                descricao="Arquivo padrão do WordPress acessível revela a "
                          "versão exata, facilitando ataques direcionados.",
                como_explorar="A versão exposta é usada para selecionar "
                              "exploits compatíveis.",
                como_corrigir=f"Remova ou bloqueie o acesso a {caminho}.",
                referencia="https://wpscan.com",
                modulo="Verificação de Endpoints"))
            return

        if caminho == "/wp-content/debug.log" and codigo == 200:
            UI.critico("debug.log EXPOSTO (pode conter dados sensíveis)")
            self.add_vuln(Vulnerabilidade(
                titulo="Log de depuração exposto",
                criticidade=ALTO,
                descricao="O arquivo debug.log está acessível e pode conter "
                          "caminhos internos, queries SQL e erros sensíveis.",
                como_explorar="Leitura do log revela informações para outros "
                              "ataques (caminhos, plugins, erros).",
                como_corrigir="Desative WP_DEBUG_LOG em produção e bloqueie o "
                              "acesso ao arquivo.",
                referencia="https://wordpress.org/documentation/article/debugging-in-wordpress/",
                modulo="Verificação de Endpoints"))
            return

        # Estado geral
        if codigo in (200, 301, 302):
            UI.comentario(f"{caminho} → HTTP {codigo} ({descricao})")
        elif codigo in (401, 403):
            UI.baixo(f"{caminho} protegido (HTTP {codigo})")

    def _analisar_xmlrpc(self):
        """Testa xmlrpc.php: habilitado, listMethods, amplificação."""
        url = self.url("/xmlrpc.php")
        r = self.http.get(url)
        if r is None:
            return
        if r.status_code == 405 or "XML-RPC server accepts POST requests only" \
                in (r.text or ""):
            self.ctx.info_alvo["xmlrpc"] = "habilitado"
            # Confirma via system.listMethods
            payload = ("<?xml version='1.0'?><methodCall>"
                       "<methodName>system.listMethods</methodName>"
                       "<params></params></methodCall>")
            rp = self.http.post(url, data=payload,
                                headers={"Content-Type": "text/xml"})
            metodos = []
            if rp is not None and "<methodResponse>" in (rp.text or ""):
                metodos = re.findall(r"<string>([\w.]+)</string>", rp.text)
            amplifica = "pingback.ping" in metodos
            multicall = "system.multicall" in metodos
            UI.critico("xmlrpc.php HABILITADO")
            extras = []
            if amplifica:
                extras.append("pingback (amplificação DDoS)")
            if multicall:
                extras.append("multicall (brute force acelerado)")
            if extras:
                UI.alto("XML-RPC permite: " + ", ".join(extras))
            self.add_vuln(Vulnerabilidade(
                titulo="XML-RPC habilitado",
                criticidade=ALTO if (amplifica or multicall) else MEDIO,
                descricao="O endpoint xmlrpc.php está ativo. Pode ser abusado "
                          "para força bruta acelerada (system.multicall) e "
                          "ataques de amplificação DDoS (pingback.ping).",
                como_explorar="system.multicall permite testar centenas de "
                              "senhas numa única requisição; pingback.ping "
                              "permite usar o site como refletor de DDoS.",
                como_corrigir="Desative o XML-RPC se não for necessário "
                              "(plugin 'Disable XML-RPC') ou bloqueie o acesso "
                              "ao arquivo via servidor web.",
                referencia="https://www.wordfence.com/learn/"
                           "wordpress-xml-rpc/",
                detalhe=f"Métodos detectados: {len(metodos)}",
                modulo="Verificação de Endpoints"))
        else:
            self.ctx.info_alvo["xmlrpc"] = "desabilitado"
            UI.baixo("xmlrpc.php desabilitado/protegido")

    def _analisar_login(self):
        """Verifica proteções na página de login (rate limit, captcha, 2FA)."""
        url = self.url("/wp-login.php")
        r = self.http.get(url)
        if r is None or r.status_code not in (200, 503):
            return
        html = (r.text or "").lower()
        protecoes = []
        if "captcha" in html or "g-recaptcha" in html or "h-captcha" in html:
            protecoes.append("CAPTCHA")
        if "two-factor" in html or "2fa" in html or "authenticator" in html:
            protecoes.append("2FA")
        if "wordfence" in html:
            protecoes.append("Wordfence")
        if "limit" in html and "login" in html:
            protecoes.append("Limit Login")
        if protecoes:
            UI.baixo(f"Login protegido por: {', '.join(protecoes)}")
            self.ctx.info_alvo["protecao_login"] = protecoes
        else:
            UI.medio("wp-login.php sem proteções visíveis (CAPTCHA/2FA)")
            self.ctx.info_alvo["protecao_login"] = []
            self.add_vuln(Vulnerabilidade(
                titulo="Login sem proteção visível contra força bruta",
                criticidade=MEDIO,
                descricao="A página de login não apresenta CAPTCHA, 2FA ou "
                          "limitação de tentativas detectável.",
                como_explorar="Permite ataques de dicionário/força bruta de "
                              "forma contínua.",
                como_corrigir="Instale 'Limit Login Attempts Reloaded' ou "
                              "Wordfence, habilite 2FA e CAPTCHA no login.",
                referencia="https://owasp.org/www-community/attacks/"
                           "Brute_force_attack",
                modulo="Verificação de Endpoints"))


# ══════════════════════════════════════════════════════════════════════════════
# MÓDULO 6 — TESTE DE CREDENCIAIS
# ══════════════════════════════════════════════════════════════════════════════

class TestadorCredenciais(ModuloBase):
    """Testa combinações de credenciais padrão de forma controlada e segura."""

    # Limite conservador de tentativas para evitar lockout/abuso
    MAX_TENTATIVAS = 12

    def executar(self):
        print()
        protecao = self.ctx.info_alvo.get("protecao_login")
        if protecao:
            UI.aviso(f"Proteção de login detectada ({', '.join(protecao)}). "
                     f"Teste limitado para evitar lockout.")
            UI.comentario("Pulando força bruta para não disparar bloqueios.")
            return

        url = self.url("/wp-login.php")
        # Monta lista de combinações a partir dos usuários encontrados
        combinacoes = self._montar_combinacoes()

        UI.info(f"Testando até {min(len(combinacoes), self.MAX_TENTATIVAS)} "
                f"credenciais padrão (modo seguro)...")

        encontrou = False
        for i, (usuario, senha) in enumerate(combinacoes[:self.MAX_TENTATIVAS]):
            sucesso = self._testar_login(url, usuario, senha)
            UI.comentario(f"[{i+1}] {usuario}:{senha} → "
                          f"{'✔ válido' if sucesso else '✘'}")
            if sucesso:
                encontrou = True
                UI.critico(f"ACESSO OBTIDO: {usuario}/{senha}")
                self.add_vuln(Vulnerabilidade(
                    titulo=f"Credencial padrão válida: {usuario}",
                    criticidade=CRITICO,
                    descricao=f"O par usuário/senha '{usuario}/{senha}' concede "
                              f"acesso ao painel administrativo.",
                    como_explorar="Login direto em /wp-admin/ com controle total "
                                  "do site (instalar plugins maliciosos, etc).",
                    como_corrigir="Troque a senha imediatamente por uma senha "
                                  "forte e única; habilite 2FA.",
                    referencia="https://owasp.org/www-community/attacks/"
                               "Brute_force_attack",
                    modulo="Teste de Credenciais"))
                break
            if self.http.rate_limit_detectado:
                UI.aviso("Rate limit detectado — interrompendo teste.")
                break

        if not encontrou:
            UI.baixo("Nenhuma credencial padrão válida encontrada.")

    def _montar_combinacoes(self):
        """Gera combinações usuário/senha a partir de padrões + usuários reais."""
        combos = [
            ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
            ("admin", "wordpress"), ("admin", "admin123"),
        ]
        for u in self.ctx.usuarios[:3]:
            login = u["login"]
            combos.append((login, login))
            combos.append((login, "123456"))
            combos.append((login, "senha123"))
        return combos

    def _testar_login(self, url, usuario, senha):
        """POST seguro no wp-login.php; detecta sucesso sem causar lockout."""
        dados = {
            "log": usuario, "pwd": senha,
            "wp-submit": "Acessar", "redirect_to": self.url("/wp-admin/"),
            "testcookie": "1",
        }
        cookies = {"wordpress_test_cookie": "WP Cookie check"}
        r = self.http.post(url, data=dados, cookies=cookies,
                           allow_redirects=False)
        if r is None:
            return False
        # Sucesso típico: redireciona para wp-admin e seta cookie de auth
        if r.status_code in (302, 301):
            loc = r.headers.get("Location", "")
            set_cookie = r.headers.get("Set-Cookie", "")
            if "wp-admin" in loc and "wordpress_logged_in" in set_cookie:
                return True
        return False


# ══════════════════════════════════════════════════════════════════════════════
# MÓDULO 7 — SCANNER DE INJEÇÕES
# ══════════════════════════════════════════════════════════════════════════════

class ScannerInjecoes(ModuloBase):
    """Testes não destrutivos de SQLi, XSS refletido, LFI e Open Redirect."""

    ERROS_SQL = [
        "you have an error in your sql syntax", "warning: mysql",
        "unclosed quotation mark", "quoted string not properly terminated",
        "pg_query()", "sql syntax", "mysql_fetch", "mysqli_",
        "syntax error", "odbc", "sqlite3::",
    ]

    def executar(self):
        print()
        self._testar_sqli()
        self._testar_xss()
        self._testar_lfi()
        self._testar_open_redirect()

    def _testar_sqli(self):
        """Injeta payloads em parâmetro de busca e procura erros de SQL."""
        payloads = ["' OR 1=1-- -", "'\"", "1' AND '1'='2"]
        detectou = False
        for p in payloads:
            url = self.base_url + "/?s=" + quote(p)
            r = self.http.get(url)
            if r is None:
                continue
            texto = (r.text or "").lower()
            if any(e in texto for e in self.ERROS_SQL):
                detectou = True
                UI.critico(f"SQL Injection: erro de banco exposto com payload {p}")
                self.add_vuln(Vulnerabilidade(
                    titulo="Possível SQL Injection (erro exposto)",
                    criticidade=CRITICO,
                    descricao="A aplicação retornou mensagens de erro de banco "
                              "de dados ao receber payloads de injeção SQL.",
                    como_explorar="Refine o payload para extrair dados via "
                                  "UNION/blind SQLi (ex.: sqlmap).",
                    como_corrigir="Use prepared statements/$wpdb->prepare(), "
                                  "valide entradas e oculte mensagens de erro.",
                    referencia="https://owasp.org/www-community/attacks/"
                               "SQL_Injection",
                    detalhe=f"Payload: {p}",
                    modulo="Scanner de Injeções"))
                break
        if not detectou:
            UI.baixo("SQL Injection: não detectado nos testes básicos")

    def _testar_xss(self):
        """Verifica reflexão de payload XSS no parâmetro de busca."""
        marcador = "wphunterXSS9173"
        payload = f"<script>{marcador}</script>"
        url = self.base_url + "/?s=" + quote(payload)
        r = self.http.get(url)
        if r is not None and payload in (r.text or ""):
            UI.alto("XSS Refletido DETECTADO no parâmetro ?s= (campo de busca)")
            self.add_vuln(Vulnerabilidade(
                titulo="XSS Refletido no parâmetro de busca (?s=)",
                criticidade=ALTO,
                descricao="O parâmetro de busca reflete tags <script> sem "
                          "sanitização adequada, permitindo XSS refletido.",
                como_explorar="Envie à vítima uma URL com payload JS para roubar "
                              "cookies de sessão ou executar ações no navegador.",
                como_corrigir="Aplique escaping de saída (esc_html), use CSP e "
                              "valide/sanitize parâmetros de busca.",
                referencia="https://owasp.org/www-community/attacks/xss/",
                detalhe="Parâmetro: ?s=",
                modulo="Scanner de Injeções"))
        else:
            UI.baixo("XSS Refletido: não detectado no campo de busca")

    def _testar_lfi(self):
        """Testa LFI em parâmetro genérico de arquivo (não destrutivo)."""
        payloads = ["../../../../etc/passwd", "....//....//etc/passwd"]
        detectou = False
        for p in payloads:
            url = self.base_url + "/?page=" + quote(p)
            r = self.http.get(url)
            if r is not None and re.search(r"root:.*:0:0:", r.text or ""):
                detectou = True
                UI.critico("LFI DETECTADO — conteúdo de /etc/passwd retornado")
                self.add_vuln(Vulnerabilidade(
                    titulo="Local File Inclusion (LFI)",
                    criticidade=CRITICO,
                    descricao="Foi possível incluir/ler arquivos locais do "
                              "servidor (/etc/passwd retornado).",
                    como_explorar="Leia arquivos sensíveis (wp-config.php, logs) "
                                  "e, com log poisoning, alcance RCE.",
                    como_corrigir="Nunca inclua arquivos com base em entrada do "
                                  "usuário; use allowlist de caminhos.",
                    referencia="https://owasp.org/www-community/attacks/"
                               "Path_Traversal",
                    detalhe=f"Payload: {p}",
                    modulo="Scanner de Injeções"))
                break
        if not detectou:
            UI.baixo("LFI: não detectado nos testes básicos")

    def _testar_open_redirect(self):
        """Testa open redirect via redirect_to do wp-login."""
        externo = "https://exemplo-malicioso.com/"
        url = self.url("/wp-login.php?redirect_to=" + quote(externo))
        r = self.http.get(url, allow_redirects=False)
        if r is not None and r.status_code in (301, 302):
            loc = r.headers.get("Location", "")
            if "exemplo-malicioso.com" in loc:
                UI.alto("Open Redirect DETECTADO em redirect_to")
                self.add_vuln(Vulnerabilidade(
                    titulo="Open Redirect em wp-login (redirect_to)",
                    criticidade=MEDIO,
                    descricao="O parâmetro redirect_to permite redirecionar "
                              "para domínios externos arbitrários.",
                    como_explorar="Use em campanhas de phishing aproveitando a "
                                  "confiança no domínio legítimo.",
                    como_corrigir="Valide o destino do redirecionamento contra "
                                  "uma allowlist do próprio domínio.",
                    referencia="https://owasp.org/www-community/attacks/"
                               "Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
                    modulo="Scanner de Injeções"))
                return
        UI.baixo("Open Redirect: não detectado")


# ══════════════════════════════════════════════════════════════════════════════
# MÓDULO 8 — VERIFICAÇÃO SSL / HEADERS DE SEGURANÇA
# ══════════════════════════════════════════════════════════════════════════════

class VerificadorSSL(ModuloBase):
    """Avalia certificado SSL/TLS e cabeçalhos de segurança HTTP."""

    HEADERS_SEGURANCA = {
        "X-Frame-Options": ("Proteção contra clickjacking", MEDIO),
        "Content-Security-Policy": ("Política de segurança de conteúdo", MEDIO),
        "Strict-Transport-Security": ("HSTS — força HTTPS", MEDIO),
        "X-Content-Type-Options": ("Anti MIME-sniffing", BAIXO),
        "Referrer-Policy": ("Controle de referrer", BAIXO),
        "Permissions-Policy": ("Controle de permissões do navegador", BAIXO),
    }

    def executar(self):
        print()
        self._verificar_ssl()
        self._verificar_headers()

    def _verificar_ssl(self):
        """Inspeciona o certificado TLS e protocolos."""
        parsed = urlparse(self.base_url)
        if parsed.scheme != "https":
            UI.alto("Site não usa HTTPS — tráfego trafega em texto puro")
            self.add_vuln(Vulnerabilidade(
                titulo="Ausência de HTTPS",
                criticidade=ALTO,
                descricao="O site não força conexões HTTPS, expondo dados em "
                          "trânsito (incluindo credenciais de login).",
                como_explorar="Interceptação de tráfego (MITM) em redes "
                              "compartilhadas captura senhas e cookies.",
                como_corrigir="Instale um certificado SSL (Let's Encrypt) e "
                              "force HTTPS via redirecionamento e HSTS.",
                referencia="https://owasp.org/www-community/controls/"
                           "SecureCookieAttribute",
                modulo="Verificação SSL/Headers"))
            return

        host = parsed.hostname
        porta = parsed.port or 443
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, porta), timeout=TIMEOUT_REQUEST) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    versao_tls = ssock.version()
                    self.ctx.info_alvo["tls_versao"] = versao_tls

                    # Protocolos antigos = risco
                    if versao_tls in ("TLSv1", "TLSv1.1", "SSLv3"):
                        UI.alto(f"Protocolo TLS obsoleto: {versao_tls}")
                        self.add_vuln(Vulnerabilidade(
                            titulo=f"Protocolo TLS obsoleto ({versao_tls})",
                            criticidade=ALTO,
                            descricao="O servidor aceita versões antigas de "
                                      "TLS/SSL, vulneráveis a ataques conhecidos.",
                            como_explorar="Downgrade/POODLE/BEAST podem ser "
                                          "explorados em conexões antigas.",
                            como_corrigir="Desabilite TLS 1.0/1.1 e exija "
                                          "TLS 1.2+ no servidor web.",
                            referencia="https://owasp.org/www-project-"
                                       "transport-layer-protection/",
                            modulo="Verificação SSL/Headers"))
                    else:
                        UI.baixo(f"Protocolo TLS: {versao_tls}")

                    # Validade do certificado (quando disponível)
                    if cert and cert.get("notAfter"):
                        UI.baixo(f"Certificado válido até: {cert['notAfter']}")
                        self.ctx.info_alvo["ssl_expira"] = cert["notAfter"]
                    else:
                        UI.comentario("Certificado presente (detalhes limitados)")
        except Exception as e:
            LOG.warning(f"Verificação SSL falhou: {e}")
            UI.aviso(f"Não foi possível inspecionar o certificado: {e}")

    def _verificar_headers(self):
        """Verifica presença de headers de segurança e exposição de versões."""
        r = self.http.get(self.base_url)
        if r is None:
            UI.aviso("Sem resposta para análise de headers.")
            return
        h = r.headers
        ausentes = []
        for header, (desc, crit) in self.HEADERS_SEGURANCA.items():
            if header not in h:
                ausentes.append((header, desc, crit))
                UI.por_criticidade(crit, f"{header}: AUSENTE ({desc})")
            else:
                UI.baixo(f"{header}: presente")

        if ausentes:
            piores = [c for _, _, c in ausentes]
            crit_geral = MEDIO if MEDIO in piores else BAIXO
            self.add_vuln(Vulnerabilidade(
                titulo=f"Headers de segurança ausentes ({len(ausentes)})",
                criticidade=crit_geral,
                descricao="Cabeçalhos HTTP de segurança importantes não estão "
                          "configurados: " +
                          ", ".join(a[0] for a in ausentes) + ".",
                como_explorar="A ausência facilita clickjacking, injeção de "
                              "conteúdo e MIME-sniffing.",
                como_corrigir="Adicione os cabeçalhos no servidor web ou via "
                              "plugin de segurança (ex.: 'Headers Security "
                              "Advanced & HSTS WP').",
                referencia="https://owasp.org/www-project-secure-headers/",
                modulo="Verificação SSL/Headers"))

        # Exposição de versões nos headers
        exposicoes = []
        if "Server" in h and re.search(r"\d", h["Server"]):
            exposicoes.append(f"Server: {h['Server']}")
        if "X-Powered-By" in h:
            exposicoes.append(f"X-Powered-By: {h['X-Powered-By']}")
        for e in exposicoes:
            UI.medio(f"Exposição de versão no header → {e}")
        if exposicoes:
            self.add_vuln(Vulnerabilidade(
                titulo="Versões de software expostas nos headers",
                criticidade=BAIXO,
                descricao="Os cabeçalhos revelam versões de servidor/PHP, "
                          "facilitando a seleção de exploits.",
                como_explorar="Atacante mapeia CVEs conforme as versões "
                              "expostas.",
                como_corrigir="Oculte tokens de versão (ServerTokens Prod, "
                              "expose_php = Off).",
                referencia="https://owasp.org/www-project-secure-headers/",
                detalhe="; ".join(exposicoes),
                modulo="Verificação SSL/Headers"))


# ══════════════════════════════════════════════════════════════════════════════
# MÓDULO 9 — DETECTOR DE BACKUPS E ARQUIVOS SENSÍVEIS EXPOSTOS
# ══════════════════════════════════════════════════════════════════════════════

class DetectorBackups(ModuloBase):
    """Procura backups e arquivos sensíveis acessíveis publicamente."""

    def executar(self):
        print()
        encontrados = 0
        # Inclui backups com data dos últimos anos
        lista = list(ARQUIVOS_BACKUP) + self._backups_com_data()

        for caminho, crit in lista:
            r = self.http.get(self.url(caminho), allow_redirects=False, stream=True)
            if r is None:
                continue
            if r.status_code == 200 and self._conteudo_relevante(r, caminho):
                encontrados += 1
                tamanho = self._formatar_tamanho(
                    r.headers.get("Content-Length"))
                UI.por_criticidade(crit, f"{caminho} ENCONTRADO "
                                         f"({tamanho}) → {self.url(caminho)}")
                self._registrar_vuln(caminho, crit, r)
            try:
                r.close()
            except Exception:
                pass

        if encontrados == 0:
            UI.baixo("Nenhum backup ou arquivo sensível exposto encontrado.")
        else:
            UI.aviso(f"{encontrados} arquivo(s) sensível(is) exposto(s)!")

    def _backups_com_data(self):
        """Gera nomes de backup com datas recentes (padrão comum)."""
        nomes = []
        ano = datetime.date.today().year
        for a in (ano, ano - 1):
            nomes.append((f"/backup-{a}.zip", CRITICO))
            nomes.append((f"/backup_{a}.sql", CRITICO))
            nomes.append((f"/wp-content/backup-{a}.zip", CRITICO))
        return nomes

    def _conteudo_relevante(self, r, caminho):
        """Evita falsos positivos (páginas 200 customizadas)."""
        ctype = r.headers.get("Content-Type", "").lower()
        # Arquivos de texto sensíveis
        if caminho.endswith((".env", ".log", "config", "HEAD", "entries",
                             ".ini", ".DS_Store")):
            try:
                amostra = r.raw.read(512, decode_content=True) or b""
            except Exception:
                amostra = b""
            amostra = amostra.decode("utf-8", "ignore")
            if caminho.endswith(".env"):
                return any(k in amostra for k in
                           ("DB_", "APP_KEY", "SECRET", "PASSWORD", "="))
            if "git" in caminho:
                return "ref:" in amostra or "[core]" in amostra
            return len(amostra.strip()) > 0 and "<html" not in amostra.lower()
        # Arquivos binários (zip/sql/tar)
        if any(caminho.endswith(ext) for ext in (".zip", ".sql", ".gz", ".tar")):
            if "text/html" in ctype:
                return False  # provavelmente página de erro 200
            return True
        if caminho.endswith((".php",)):
            # phpinfo exposto
            try:
                amostra = r.raw.read(512, decode_content=True) or b""
            except Exception:
                amostra = b""
            return b"phpinfo" in amostra.lower() or b"PHP Version" in amostra
        return "text/html" not in ctype

    def _registrar_vuln(self, caminho, crit, r):
        sensivel = ""
        if caminho.endswith(".env"):
            sensivel = "Pode conter DB_PASSWORD, chaves de API e segredos."
        elif "git" in caminho:
            sensivel = "Repositório Git exposto — código-fonte pode ser baixado."
        elif caminho.endswith((".sql",)):
            sensivel = "Dump de banco de dados — pode conter todos os dados."
        elif caminho.endswith((".zip", ".tar", ".gz")):
            sensivel = "Backup completo do site — credenciais e código incluídos."
        self.add_vuln(Vulnerabilidade(
            titulo=f"Arquivo sensível exposto: {caminho}",
            criticidade=crit,
            descricao=f"O arquivo {caminho} está publicamente acessível. "
                      f"{sensivel}",
            como_explorar="Baixe o arquivo diretamente pela URL e extraia "
                          "credenciais/código/dados.",
            como_corrigir=f"Remova {caminho} do servidor público e bloqueie o "
                          f"acesso via .htaccess/Nginx. Rotacione segredos "
                          f"expostos.",
            referencia="https://owasp.org/www-community/vulnerabilities/"
                       "Information_exposure_through_query_strings_in_url",
            detalhe=f"URL: {self.url(caminho)}",
            modulo="Detector de Backups"))

    @staticmethod
    def _formatar_tamanho(content_length):
        if not content_length:
            return "tamanho desconhecido"
        try:
            n = int(content_length)
        except (ValueError, TypeError):
            return "tamanho desconhecido"
        for unidade in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.0f} {unidade}"
            n /= 1024
        return f"{n:.0f} TB"


# ══════════════════════════════════════════════════════════════════════════════
# MÓDULO 10 — GERADOR DE RELATÓRIO (HTML / JSON / CSV)
# ══════════════════════════════════════════════════════════════════════════════

class GeradorRelatorio:
    """Gera relatórios em HTML (dark theme), JSON e CSV."""

    def __init__(self, contexto):
        self.ctx = contexto

    def gerar_todos(self):
        self.gerar_json()
        self.gerar_csv()
        self.gerar_html()

    def _contagem(self):
        c = {CRITICO: 0, ALTO: 0, MEDIO: 0, BAIXO: 0, INFO: 0}
        for v in self.ctx.vulnerabilidades:
            c[v.criticidade] = c.get(v.criticidade, 0) + 1
        return c

    def calcular_score(self):
        """Score de segurança 0-100 (100 = seguro)."""
        score = 100
        for v in self.ctx.vulnerabilidades:
            score -= PESO_CRITICIDADE.get(v.criticidade, 0)
        return max(0, min(100, score))

    def classificacao(self, score):
        if score >= 85:
            return "🟢 SEGURO", "#2ecc71"
        if score >= 60:
            return "🟡 ATENÇÃO", "#f1c40f"
        if score >= 35:
            return "🟠 VULNERÁVEL", "#e67e22"
        return "🔴 CRÍTICO", "#e74c3c"

    # ── JSON ──────────────────────────────────────────────────────────────────
    def gerar_json(self):
        dados = {
            "ferramenta": f"{NOME} v{VERSAO}",
            "data": datetime.datetime.now().isoformat(),
            "alvo": self.ctx.base_url,
            "info_alvo": self.ctx.info_alvo,
            "score_seguranca": self.calcular_score(),
            "contagem": self._contagem(),
            "usuarios": self.ctx.usuarios,
            "plugins": [{k: v for k, v in p.items()
                         if k != "pior_criticidade_idx"}
                        for p in self.ctx.plugins],
            "temas": self.ctx.temas,
            "vulnerabilidades": [v.to_dict() for v in self.ctx.vulnerabilidades],
        }
        try:
            with open("wphunter_resultado.json", "w", encoding="utf-8") as f:
                json.dump(dados, f, ensure_ascii=False, indent=2, default=str)
            LOG.info("JSON gerado: wphunter_resultado.json")
        except Exception as e:
            LOG.error(f"Falha ao gerar JSON: {e}")

    # ── CSV ───────────────────────────────────────────────────────────────────
    def gerar_csv(self):
        try:
            with open("wphunter_vulnerabilidades.csv", "w", newline="",
                      encoding="utf-8-sig") as f:
                w = csv.writer(f, delimiter=";")
                w.writerow(["Criticidade", "Titulo", "Modulo", "Descricao",
                            "Como Corrigir", "Referencia", "Detalhe"])
                for v in sorted(self.ctx.vulnerabilidades,
                                key=lambda x: list(PESO_CRITICIDADE).index(
                                    x.criticidade)):
                    w.writerow([v.criticidade, v.titulo, v.modulo,
                                v.descricao, v.como_corrigir, v.referencia,
                                v.detalhe])
            LOG.info("CSV gerado: wphunter_vulnerabilidades.csv")
        except Exception as e:
            LOG.error(f"Falha ao gerar CSV: {e}")

    # ── HTML ──────────────────────────────────────────────────────────────────
    def gerar_html(self):
        score = self.calcular_score()
        classe, cor = self.classificacao(score)
        contagem = self._contagem()
        info = self.ctx.info_alvo

        # Ordena vulnerabilidades por criticidade
        vulns = sorted(self.ctx.vulnerabilidades,
                       key=lambda x: list(PESO_CRITICIDADE).index(x.criticidade))

        cores_crit = {CRITICO: "#e74c3c", ALTO: "#e67e22",
                      MEDIO: "#f1c40f", BAIXO: "#2ecc71", INFO: "#3498db"}

        # Resumo executivo em PT-BR
        resumo = self._resumo_executivo(contagem, score)

        # Constrói blocos de vulnerabilidades
        blocos = []
        for v in vulns:
            cor_v = cores_crit.get(v.criticidade, "#888")
            icone = ICONES.get(v.criticidade, "•")
            blocos.append(f"""
            <div class="vuln" style="border-left-color:{cor_v}">
              <div class="vuln-head">
                <span class="badge" style="background:{cor_v}">{icone} {v.criticidade}</span>
                <h3>{self._esc(v.titulo)}</h3>
              </div>
              <p class="modulo">📦 {self._esc(v.modulo)}</p>
              <p><b>Descrição:</b> {self._esc(v.descricao)}</p>
              {f'<p><b>Como explorar (educacional):</b> {self._esc(v.como_explorar)}</p>' if v.como_explorar else ''}
              <p class="fix"><b>✅ Como corrigir:</b> {self._esc(v.como_corrigir)}</p>
              {f'<p class="detalhe">{self._esc(v.detalhe)}</p>' if v.detalhe else ''}
              {f'<p class="ref">🔗 <a href="{self._esc(v.referencia)}" target="_blank">{self._esc(v.referencia)}</a></p>' if v.referencia else ''}
            </div>""")

        # Tabela de plugins
        linhas_plugins = ""
        for p in self.ctx.plugins:
            cve = p.get("cve")
            status = (f"<span style='color:#e74c3c'>{cve['id']} (CVSS {cve['cvss']})</span>"
                      if cve else "<span style='color:#2ecc71'>Sem CVE conhecido</span>")
            linhas_plugins += (f"<tr><td>{self._esc(p['nome'])}</td>"
                               f"<td>{self._esc(str(p.get('versao') or '?'))}</td>"
                               f"<td>{status}</td></tr>")
        if not linhas_plugins:
            linhas_plugins = "<tr><td colspan='3'>Nenhum plugin detectado</td></tr>"

        # Tabela de usuários
        linhas_users = ""
        for u in self.ctx.usuarios:
            risco = ("RISCO ALTO" if u["login"].lower() in
                     ("admin", "administrator", "root") else "normal")
            linhas_users += (f"<tr><td>{u.get('id','?')}</td>"
                             f"<td>{self._esc(u['login'])}</td>"
                             f"<td>{self._esc(u.get('nome',''))}</td>"
                             f"<td>{risco}</td></tr>")
        if not linhas_users:
            linhas_users = "<tr><td colspan='4'>Nenhum usuário enumerado</td></tr>"

        # Recomendações prioritárias
        recomendacoes = self._recomendacoes(vulns)

        html = self._template_html().format(
            nome=NOME, versao=VERSAO,
            data=datetime.datetime.now().strftime("%d/%m/%Y %H:%M"),
            alvo=self._esc(self.ctx.base_url),
            wp_versao=self._esc(str(info.get("wp_versao") or "Desconhecida")),
            php_versao=self._esc(str(info.get("php_versao") or "N/D")),
            servidor=self._esc(str(info.get("servidor") or "N/D")),
            score=score, classe=classe, cor=cor,
            n_critico=contagem[CRITICO], n_alto=contagem[ALTO],
            n_medio=contagem[MEDIO], n_baixo=contagem[BAIXO],
            resumo=resumo,
            blocos="".join(blocos) or "<p>Nenhuma vulnerabilidade registrada. 🎉</p>",
            linhas_plugins=linhas_plugins,
            linhas_users=linhas_users,
            recomendacoes=recomendacoes,
            duracao=self.ctx.duracao_str,
        )
        try:
            with open("wphunter_relatorio.html", "w", encoding="utf-8") as f:
                f.write(html)
            LOG.info("HTML gerado: wphunter_relatorio.html")
        except Exception as e:
            LOG.error(f"Falha ao gerar HTML: {e}")

    def _resumo_executivo(self, contagem, score):
        total = sum(v for k, v in contagem.items() if k != INFO)
        if score >= 85:
            base = ("O site apresenta uma boa postura de segurança. Poucas ou "
                    "nenhuma falha relevante foi identificada.")
        elif score >= 60:
            base = ("O site possui falhas de segurança que merecem atenção. "
                    "Recomenda-se correção em prazo razoável.")
        elif score >= 35:
            base = ("O site está vulnerável. Foram encontradas falhas que podem "
                    "ser exploradas por atacantes. Ação corretiva é necessária.")
        else:
            base = ("⚠️ Situação crítica. O site possui falhas graves que "
                    "permitem comprometimento total. Correção urgente!")
        return (f"{base} Foram identificadas <b>{total}</b> questões de "
                f"segurança, sendo <b>{contagem[CRITICO]} crítica(s)</b> e "
                f"<b>{contagem[ALTO]} de alto risco</b>.")

    def _recomendacoes(self, vulns):
        criticas = [v for v in vulns if v.criticidade in (CRITICO, ALTO)]
        if not criticas:
            return "<li>Manter o WordPress, plugins e temas sempre atualizados.</li>"
        itens = ""
        vistos = set()
        for v in criticas[:8]:
            chave = v.titulo
            if chave in vistos:
                continue
            vistos.add(chave)
            itens += f"<li><b>{self._esc(v.titulo)}</b> — {self._esc(v.como_corrigir)}</li>"
        return itens

    @staticmethod
    def _esc(texto):
        if texto is None:
            return ""
        return (str(texto).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))

    def _template_html(self):
        # Dark theme com barra de score animada
        return """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{nome} — Relatório de Segurança</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:'Segoe UI',Roboto,sans-serif; background:#0d1117;
         color:#c9d1d9; line-height:1.6; }}
  .container {{ max-width:1000px; margin:0 auto; padding:30px 20px; }}
  header {{ text-align:center; padding:40px 20px; background:linear-gradient(135deg,#161b22,#0d1117);
           border-bottom:2px solid #30363d; border-radius:12px; margin-bottom:30px; }}
  header h1 {{ font-size:2.4em; color:#58a6ff; letter-spacing:1px; }}
  header .sub {{ color:#8b949e; margin-top:6px; }}
  .badge-risco {{ display:inline-block; padding:10px 26px; border-radius:30px;
                 font-size:1.4em; font-weight:bold; color:#fff; margin-top:18px;
                 background:{cor}; box-shadow:0 0 25px {cor}; }}
  .meta {{ display:flex; flex-wrap:wrap; gap:14px; justify-content:center; margin-top:22px; }}
  .meta div {{ background:#161b22; padding:10px 18px; border-radius:8px;
              border:1px solid #30363d; font-size:.9em; }}
  .meta b {{ color:#58a6ff; }}
  section {{ background:#161b22; border:1px solid #30363d; border-radius:12px;
            padding:26px; margin-bottom:26px; }}
  section h2 {{ color:#58a6ff; margin-bottom:16px; border-bottom:1px solid #30363d;
               padding-bottom:10px; font-size:1.4em; }}
  .score-wrap {{ text-align:center; }}
  .score-num {{ font-size:3.5em; font-weight:bold; color:{cor}; }}
  .barra {{ background:#21262d; border-radius:20px; height:28px; overflow:hidden;
           margin:18px 0; border:1px solid #30363d; }}
  .barra-fill {{ height:100%; width:0; background:{cor};
                border-radius:20px; transition:width 2s ease;
                animation:enche 2s forwards; text-align:right; color:#0d1117;
                font-weight:bold; padding-right:10px; line-height:28px; }}
  @keyframes enche {{ from {{ width:0; }} to {{ width:{score}%; }} }}
  .cards {{ display:flex; flex-wrap:wrap; gap:14px; justify-content:center; margin-top:10px; }}
  .card {{ flex:1; min-width:130px; text-align:center; padding:18px;
          border-radius:10px; background:#0d1117; border:1px solid #30363d; }}
  .card .n {{ font-size:2.2em; font-weight:bold; }}
  .c-crit .n {{ color:#e74c3c; }} .c-alto .n {{ color:#e67e22; }}
  .c-medio .n {{ color:#f1c40f; }} .c-baixo .n {{ color:#2ecc71; }}
  .vuln {{ background:#0d1117; border-left:5px solid #888; border-radius:8px;
          padding:18px; margin-bottom:16px; }}
  .vuln-head {{ display:flex; align-items:center; gap:12px; margin-bottom:8px; flex-wrap:wrap; }}
  .vuln-head h3 {{ color:#e6edf3; font-size:1.15em; }}
  .badge {{ color:#fff; padding:4px 12px; border-radius:6px; font-size:.8em;
           font-weight:bold; white-space:nowrap; }}
  .vuln p {{ margin:6px 0; font-size:.95em; }}
  .vuln .modulo {{ color:#8b949e; font-size:.85em; }}
  .vuln .fix {{ background:#11271b; border:1px solid #1f6f43; padding:8px 12px;
               border-radius:6px; }}
  .vuln .detalhe {{ font-family:monospace; background:#161b22; padding:6px;
                   border-radius:4px; color:#8b949e; font-size:.85em; }}
  .vuln .ref a {{ color:#58a6ff; text-decoration:none; }}
  table {{ width:100%; border-collapse:collapse; margin-top:10px; }}
  th, td {{ padding:10px; text-align:left; border-bottom:1px solid #30363d; font-size:.9em; }}
  th {{ color:#58a6ff; background:#0d1117; }}
  ul {{ padding-left:22px; }} li {{ margin:8px 0; }}
  .disclaimer {{ background:#1a1207; border:1px solid #6b4d1a; color:#d4a13a;
                font-size:.85em; padding:18px; border-radius:8px; }}
  footer {{ text-align:center; color:#8b949e; font-size:.8em; padding:20px; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>🛡️ {nome} v{versao}</h1>
    <div class="sub">Relatório de Vulnerabilidades WordPress</div>
    <div class="badge-risco">{classe}</div>
    <div class="meta">
      <div><b>Alvo:</b> {alvo}</div>
      <div><b>WordPress:</b> {wp_versao}</div>
      <div><b>PHP:</b> {php_versao}</div>
      <div><b>Servidor:</b> {servidor}</div>
      <div><b>Data:</b> {data}</div>
      <div><b>Duração:</b> {duracao}</div>
    </div>
  </header>

  <section class="score-wrap">
    <h2>📊 Score de Segurança</h2>
    <div class="score-num">{score}/100</div>
    <div class="barra"><div class="barra-fill">{score}%</div></div>
    <div class="cards">
      <div class="card c-crit"><div class="n">{n_critico}</div>🔴 Crítico</div>
      <div class="card c-alto"><div class="n">{n_alto}</div>🟠 Alto</div>
      <div class="card c-medio"><div class="n">{n_medio}</div>🟡 Médio</div>
      <div class="card c-baixo"><div class="n">{n_baixo}</div>🟢 Baixo</div>
    </div>
  </section>

  <section>
    <h2>📝 Resumo Executivo</h2>
    <p>{resumo}</p>
  </section>

  <section>
    <h2>🚨 Vulnerabilidades Detalhadas</h2>
    {blocos}
  </section>

  <section>
    <h2>🔌 Plugins Detectados</h2>
    <table>
      <tr><th>Plugin</th><th>Versão</th><th>Status</th></tr>
      {linhas_plugins}
    </table>
  </section>

  <section>
    <h2>👤 Usuários Expostos</h2>
    <table>
      <tr><th>ID</th><th>Login</th><th>Nome</th><th>Risco</th></tr>
      {linhas_users}
    </table>
  </section>

  <section>
    <h2>⭐ Recomendações Prioritárias</h2>
    <ul>{recomendacoes}</ul>
  </section>

  <section>
    <h2>⚖️ Aviso Legal</h2>
    <div class="disclaimer">
      Este relatório foi gerado pela ferramenta {nome} exclusivamente para fins
      de auditoria autorizada. O uso desta ferramenta e das informações aqui
      contidas é de inteira responsabilidade do operador. Testes de segurança
      só podem ser realizados em sistemas próprios ou com <b>autorização
      expressa e por escrito</b> do proprietário. O acesso não autorizado a
      sistemas é crime no Brasil — Lei nº 12.737/2012 (Lei Carolina Dieckmann),
      LGPD nº 13.709/2018 e Marco Civil da Internet nº 12.965/2014.
    </div>
  </section>

  <footer>
    Gerado por {nome} v{versao} — Scanner de Vulnerabilidades WordPress<br>
    🤖 Use com responsabilidade e ética.
  </footer>
</div>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
# CLASSE PRINCIPAL — ORQUESTRADOR WPHUNTER
# ══════════════════════════════════════════════════════════════════════════════

class WPHunter:
    """Orquestra todos os módulos e mantém o estado global da auditoria."""

    def __init__(self, url, args):
        self.base_url = self._normalizar_url(url)
        self.args = args
        self.stealth = args.stealth
        self.aggressive = args.aggressive
        self.is_wordpress = False

        # Estado compartilhado
        self.info_alvo = {}
        self.vulnerabilidades = []
        self.usuarios = []
        self.plugins = []
        self.temas = []
        self.inicio = None
        self.duracao_str = "—"

        # Sessão HTTP
        self.http = SessaoHTTP(stealth=self.stealth, aggressive=self.aggressive,
                               verify_ssl=False)

        # Definição dos módulos (ordem de execução)
        self.modulos = [
            ("Detector WordPress", DetectorWordPress),
            ("Enumeração de Usuários", EnumeradorUsuarios),
            ("Scanner de Plugins", ScannerPlugins),
            ("Scanner de Temas", ScannerTemas),
            ("Verificação de Endpoints", VerificadorEndpoints),
            ("Teste de Credenciais", TestadorCredenciais),
            ("Scanner de Injeções", ScannerInjecoes),
            ("Verificação SSL/Headers", VerificadorSSL),
            ("Detector de Backups", DetectorBackups),
            ("Geração de Relatório", None),  # tratado à parte
        ]

    @staticmethod
    def _normalizar_url(url):
        """Garante esquema http(s) e remove barra final."""
        url = url.strip()
        if not re.match(r"^https?://", url):
            url = "https://" + url
        return url.rstrip("/")

    def validar_alvo(self):
        """Valida URL, conectividade e confirma se é WordPress."""
        parsed = urlparse(self.base_url)
        if not parsed.hostname or "." not in parsed.hostname:
            UI.erro("URL inválida. Use: https://site.com")
            return False

        UI.info(f"Verificando conectividade com {self.base_url} ...")
        r = self.http.get(self.base_url)
        if r is None:
            # Tenta HTTP se HTTPS falhar
            if self.base_url.startswith("https://"):
                self.base_url = self.base_url.replace("https://", "http://", 1)
                self.http.base_url = self.base_url
                r = self.http.get(self.base_url)
            if r is None:
                UI.erro("Site não responde. Verifique a conectividade.")
                return False

        if self.http.waf_detectado:
            UI.aviso("WAF detectado (Cloudflare). Alguns módulos podem ser limitados.")
        return True

    def confirmar_autorizacao(self):
        """Solicita confirmação obrigatória de autorização (PASSO 1)."""
        if self.args.yes:
            UI.aviso("Autorização confirmada via --yes (modo não-interativo).")
            return True
        print()
        print(Fore.YELLOW + Style.BRIGHT +
              "Confirmo que tenho autorização para testar este site? (s/n): ",
              end="")
        try:
            resp = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        if resp not in ("s", "sim", "y", "yes"):
            UI.erro("Autorização não confirmada. Encerrando.")
            return False
        return True

    def executar(self):
        """Fluxo completo de execução."""
        self.inicio = time.time()

        # PASSO 1 — Detector WordPress primeiro (confirma alvo)
        total = len(self.modulos)
        self._rodar_modulo(1, total, "Detector WordPress", DetectorWordPress)

        if not self.is_wordpress:
            UI.erro("WordPress não detectado nesse endereço. Encerrando.")
            return

        # Determina quais módulos rodar conforme flags seletivas
        seletivo = self.args.plugins or self.args.users or self.args.endpoints

        mapa_seletivo = {
            "Scanner de Plugins": self.args.plugins,
            "Enumeração de Usuários": self.args.users,
            "Verificação de Endpoints": self.args.endpoints,
        }

        # PASSO 2 — Demais módulos
        for idx, (nome, classe) in enumerate(self.modulos[1:-1], start=2):
            if seletivo and nome in mapa_seletivo and not mapa_seletivo[nome]:
                continue
            if seletivo and nome not in mapa_seletivo:
                # Em modo seletivo, pula módulos não solicitados
                continue
            self._rodar_modulo(idx, total, nome, classe)

        # PASSO 3 — Relatório
        self.duracao_str = self._duracao()
        self._gerar_relatorios()

    def _rodar_modulo(self, idx, total, nome, classe):
        """Executa um módulo com barra de progresso e timeout protegido."""
        UI.modulo(idx, total, nome)
        decorrido = time.time() - self.inicio
        eta = max(0, (TIMEOUT_MODULO * (total - idx)) - decorrido)
        UI.progresso(idx, total, nome, (idx / total) * 100, eta)
        print()

        resultado = {"erro": None}

        def alvo():
            try:
                instancia = classe(self)
                instancia.executar()
            except Exception as e:
                resultado["erro"] = e
                LOG.exception(f"Erro no módulo {nome}: {e}")

        t = threading.Thread(target=alvo, daemon=True)
        t.start()
        t.join(timeout=TIMEOUT_MODULO)

        if t.is_alive():
            UI.aviso(f"Timeout no módulo '{nome}'. Continuando próximo módulo...")
            LOG.warning(f"Timeout no módulo {nome}")
        elif resultado["erro"]:
            UI.aviso(f"Erro no módulo '{nome}': {resultado['erro']}. Continuando...")

    def _gerar_relatorios(self):
        UI.modulo(len(self.modulos), len(self.modulos), "Geração de Relatório")
        try:
            gerador = GeradorRelatorio(self)
            gerador.gerar_todos()
            print()
            UI.sucesso("Relatórios gerados com sucesso.")
        except Exception as e:
            UI.erro(f"Falha ao gerar relatórios: {e}")
            LOG.exception(e)

    def _duracao(self):
        seg = int(time.time() - self.inicio)
        return f"{seg} segundos" if seg < 60 else f"{seg // 60}m {seg % 60}s"

    def resumo_final(self):
        """Exibe o resumo final no terminal (PASSO 3)."""
        gerador = GeradorRelatorio(self)
        score = gerador.calcular_score()
        classe, _ = gerador.classificacao(score)
        c = gerador._contagem()

        cheios = int(score / 10)
        barra = "█" * cheios + "░" * (10 - cheios)

        print()
        print(Fore.CYAN + Style.BRIGHT +
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(Fore.GREEN + Style.BRIGHT + "✅ WPHUNTER BR CONCLUÍDO")
        print(Fore.CYAN + Style.BRIGHT +
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(Fore.WHITE + f"Alvo          : {self.base_url}")
        print(Fore.WHITE + f"WordPress     : {self.info_alvo.get('wp_versao', 'N/D')}")
        print(Fore.WHITE + f"Duração total : {self.duracao_str}")
        print(Fore.WHITE + f"Plugins       : {len(self.plugins)} encontrados")
        print(Fore.WHITE + f"Usuários      : {len(self.usuarios)} expostos")
        backups = sum(1 for v in self.vulnerabilidades
                      if v.modulo == "Detector de Backups")
        print(Fore.WHITE + f"Backups       : {backups} encontrados")
        print()
        print(Fore.RED + Style.BRIGHT + f"🔴 Crítico : {c[CRITICO]}")
        print(Fore.LIGHTRED_EX + f"🟠 Alto    : {c[ALTO]}")
        print(Fore.YELLOW + f"🟡 Médio   : {c[MEDIO]}")
        print(Fore.GREEN + f"🟢 Baixo   : {c[BAIXO]}")
        print()
        cor_score = (Fore.GREEN if score >= 60 else
                     Fore.YELLOW if score >= 35 else Fore.RED)
        print(cor_score + Style.BRIGHT +
              f"Score de Segurança: [{barra}] {score}/100")
        print(cor_score + Style.BRIGHT + f"Classificação: {classe}")
        print()
        if self.args.report or not (self.args.plugins or self.args.users or
                                    self.args.endpoints):
            print(Fore.WHITE + "Arquivos gerados:")
            print(Fore.CYAN + "→ wphunter_relatorio.html")
            print(Fore.CYAN + "→ wphunter_resultado.json")
            print(Fore.CYAN + "→ wphunter_vulnerabilidades.csv")
        print(Fore.CYAN + Style.BRIGHT +
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")


# ══════════════════════════════════════════════════════════════════════════════
# FUNÇÃO PRINCIPAL / CLI
# ══════════════════════════════════════════════════════════════════════════════

def construir_parser():
    p = argparse.ArgumentParser(
        prog="wphunter.py",
        description=f"{NOME} v{VERSAO} — Scanner de Vulnerabilidades WordPress",
        epilog="Exemplo: python wphunter.py --url https://site.com --report",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", "-u", required=False,
                   help="URL do alvo WordPress (ex.: https://site.com)")
    p.add_argument("--plugins", action="store_true",
                   help="Executa apenas o scanner de plugins")
    p.add_argument("--users", action="store_true",
                   help="Executa apenas a enumeração de usuários")
    p.add_argument("--endpoints", action="store_true",
                   help="Executa apenas a verificação de endpoints")
    p.add_argument("--report", action="store_true",
                   help="Garante a geração do relatório HTML/JSON/CSV")
    p.add_argument("--stealth", action="store_true",
                   help="Modo stealth (mais lento, menos ruído)")
    p.add_argument("--aggressive", action="store_true",
                   help="Modo agressivo (mais rápido, mais requisições)")
    p.add_argument("--output", "-o", metavar="ARQUIVO",
                   help="Salva o output do terminal em arquivo .txt")
    p.add_argument("--yes", "-y", action="store_true",
                   help="Confirma autorização automaticamente (não-interativo)")
    return p


class TeeOutput:
    """Duplica stdout para um arquivo (suporte ao --output)."""

    def __init__(self, arquivo):
        self.terminal = sys.stdout
        self.log = open(arquivo, "w", encoding="utf-8")
        # Regex para remover códigos ANSI ao salvar em arquivo
        self.ansi = re.compile(r"\x1b\[[0-9;]*m")

    def write(self, msg):
        self.terminal.write(msg)
        try:
            self.log.write(self.ansi.sub("", msg))
        except Exception:
            pass

    def flush(self):
        self.terminal.flush()
        try:
            self.log.flush()
        except Exception:
            pass

    def fechar(self):
        try:
            self.log.close()
        except Exception:
            pass


def main():
    parser = construir_parser()
    args = parser.parse_args()

    # Output para arquivo, se solicitado
    tee = None
    if args.output:
        try:
            tee = TeeOutput(args.output)
            sys.stdout = tee
        except Exception as e:
            print(f"[AVISO] Não foi possível abrir {args.output}: {e}")

    UI.limpar_terminal()
    UI.banner()

    if not args.url:
        UI.erro("URL não informada. Use: python wphunter.py --url https://site.com")
        UI.comentario("Veja todas as opções com: python wphunter.py --help")
        return 1

    hunter = WPHunter(args.url, args)

    try:
        # PASSO 1 — validação
        if not hunter.validar_alvo():
            return 1

        # Confirmação de autorização obrigatória
        if not hunter.confirmar_autorizacao():
            return 1

        print()
        UI.sucesso("Autorização confirmada! Iniciando análise...")

        # PASSO 2 e 3
        hunter.executar()

        # Resumo final
        hunter.resumo_final()
        return 0

    except KeyboardInterrupt:
        print()
        UI.aviso("Interrompido pelo usuário. Salvando resultados parciais...")
        try:
            hunter.duracao_str = hunter._duracao() if hunter.inicio else "—"
            GeradorRelatorio(hunter).gerar_todos()
            UI.sucesso("Resultados parciais salvos.")
        except Exception as e:
            LOG.error(f"Falha ao salvar parcial: {e}")
        return 130
    except Exception as e:
        UI.erro(f"Erro inesperado: {e}")
        LOG.exception(e)
        return 1
    finally:
        if tee is not None:
            sys.stdout = tee.terminal
            tee.fechar()


if __name__ == "__main__":
    sys.exit(main())
