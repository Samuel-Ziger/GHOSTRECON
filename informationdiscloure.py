#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import argparse
import concurrent.futures as futures
import io
import json
import csv
import os
import random
import re
import string
import sys
import threading
import time
import zipfile
from datetime import datetime
from difflib import SequenceMatcher
from urllib.parse import urljoin, urlparse, urlsplit

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] Falta a lib 'requests'. Instale com:  pip install requests")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    print("[!] Falta a lib 'colorama'. Instale com:  pip install colorama")
    sys.exit(1)


# ======================================================================
#  CORES / TEMA "TERMINAL VERDE"
# ======================================================================
class C:
    G  = Fore.GREEN + Style.BRIGHT     # verde neon
    g  = Fore.GREEN                     # verde
    R  = Fore.RED + Style.BRIGHT        # vermelho
    Y  = Fore.YELLOW + Style.BRIGHT     # âmbar
    B  = Fore.CYAN + Style.BRIGHT       # ciano
    W  = Fore.WHITE + Style.BRIGHT
    D  = Style.DIM
    X  = Style.RESET_ALL

    @staticmethod
    def off():
        for k in ("G", "g", "R", "Y", "B", "W", "D", "X"):
            setattr(C, k, "")


# Severidades e o "peso" pra ordenação/relatório
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = lambda s: {"CRITICAL": C.R, "HIGH": C.R, "MEDIUM": C.Y,
                       "LOW": C.B, "INFO": C.D}.get(s, C.W)


# ======================================================================
#  BASE DE CONHECIMENTO
# ======================================================================

# Caminhos sensíveis agrupados por categoria. Cada item: (path, severidade base)
SENSITIVE_PATHS = {
    "VCS / Código-fonte": [
        (".git/HEAD", "CRITICAL"), (".git/config", "CRITICAL"),
        (".git/index", "CRITICAL"), (".gitignore", "LOW"),
        (".svn/entries", "HIGH"), (".svn/wc.db", "HIGH"),
        (".hg/store", "HIGH"), (".bzr/README", "MEDIUM"),
    ],
    "Config / Segredos": [
        (".env", "CRITICAL"), (".env.bak", "CRITICAL"), (".env.local", "CRITICAL"),
        (".env.production", "CRITICAL"), ("config.php.bak", "HIGH"),
        ("wp-config.php.bak", "CRITICAL"), ("wp-config.php~", "CRITICAL"),
        ("configuration.php.bak", "HIGH"), ("settings.py.bak", "HIGH"),
        ("application.yml", "HIGH"), ("appsettings.json", "HIGH"),
        ("docker-compose.yml", "MEDIUM"), (".npmrc", "MEDIUM"),
        (".aws/credentials", "CRITICAL"), ("credentials.json", "HIGH"),
    ],
    "Backups / Dumps": [
        ("backup.zip", "HIGH"), ("backup.tar.gz", "HIGH"), ("backup.sql", "HIGH"),
        ("database.sql", "HIGH"), ("db.sql", "HIGH"), ("dump.sql", "HIGH"),
        ("site.zip", "MEDIUM"), ("www.zip", "MEDIUM"), ("backup.rar", "MEDIUM"),
        ("backup.bak", "MEDIUM"), ("old.zip", "MEDIUM"), ("data.tar", "MEDIUM"),
    ],
    "Info do Servidor": [
        ("server-status", "MEDIUM"), ("server-info", "MEDIUM"),
        ("phpinfo.php", "HIGH"), ("info.php", "HIGH"), ("test.php", "LOW"),
        ("web.config", "MEDIUM"), (".htaccess", "MEDIUM"), (".htpasswd", "CRITICAL"),
        ("crossdomain.xml", "LOW"), (".DS_Store", "MEDIUM"),
    ],
    "Framework / Debug / API": [
        ("actuator", "MEDIUM"), ("actuator/env", "HIGH"), ("actuator/heapdump", "CRITICAL"),
        ("debug", "LOW"), ("_profiler", "MEDIUM"), ("telescope", "MEDIUM"),
        ("swagger-ui.html", "LOW"), ("api-docs", "LOW"), ("openapi.json", "LOW"),
        ("graphql", "LOW"), (".well-known/security.txt", "INFO"),
        ("composer.json", "LOW"), ("package.json", "LOW"), ("composer.lock", "LOW"),
    ],
}

# Validadores de conteúdo: confirmam que o arquivo é REAL (mata falso-positivo).
# path-substring -> função(body_text, raw_bytes) -> bool
def _git_head(t, b):     return t.lstrip().startswith("ref:") or re.match(r"^[0-9a-f]{40}", t.strip())
def _git_config(t, b):   return "[core]" in t or "repositoryformatversion" in t
def _env(t, b):          return bool(re.search(r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=", t))
def _dsstore(t, b):      return b[:8] == b"\x00\x00\x00\x01Bud1"
def _phpinfo(t, b):      return "phpinfo()" in t or "PHP Version" in t
def _serverstatus(t, b): return "Apache Server Status" in t or "Server uptime" in t
def _webconfig(t, b):    return "<configuration" in t.lower()
def _htpasswd(t, b):     return bool(re.search(r"(?m)^[\w.\-]+:\$?\w", t))
def _actuator(t, b):     return "propertySources" in t or '"activeProfiles"' in t
def _swagger(t, b):      return "swagger" in t.lower() or "openapi" in t.lower()
def _sql(t, b):          return bool(re.search(r"(?i)(INSERT INTO|CREATE TABLE|DROP TABLE|-- MySQL dump)", t))
def _archive(t, b):      return b[:2] in (b"PK", b"\x1f\x8b", b"Ra") or b[:4] == b"Rar!"

VALIDATORS = {
    ".git/HEAD": _git_head, ".git/config": _git_config,
    ".env": _env, ".DS_Store": _dsstore,
    "phpinfo.php": _phpinfo, "info.php": _phpinfo,
    "server-status": _serverstatus, "web.config": _webconfig,
    ".htpasswd": _htpasswd, "actuator/env": _actuator,
    "swagger-ui.html": _swagger, "api-docs": _swagger, "openapi.json": _swagger,
    ".sql": _sql, ".zip": _archive, ".tar.gz": _archive,
    ".rar": _archive, ".bak": _archive,
}

# Assinaturas de erro verboso: (regex, rótulo da tecnologia, severidade)
ERROR_SIGNATURES = [
    (r"PDOException|SQLSTATE\[|You have an error in your SQL syntax|mysqli?_query|"
     r"ORA-\d{4,}|PostgreSQL.*ERROR|Unclosed quotation mark|SQLServer", "Erro de Banco/SQL", "HIGH"),
    (r"Fatal error|Parse error|Warning: \w+\(\)|Notice: Undefined|Call Stack|"
     r"Stack trace:\s*#0", "Erro PHP", "MEDIUM"),
    (r"Traceback \(most recent call last\)|Werkzeug Debugger|"
     r'File &quot;.*&quot;, line \d+|File ".*", line \d+', "Stack trace Python", "HIGH"),
    (r"java\.lang\.[A-Za-z]+Exception|javax\.servlet|org\.springframework|"
     r"at [\w$.]+\([\w]+\.java:\d+\)", "Stack trace Java", "HIGH"),
    (r"System\.Web|Server Error in '.*' Application|Microsoft .NET Framework|"
     r"\[\w*Exception:.*\]|StackTrace:", "Erro ASP.NET", "HIGH"),
    (r"ActionController|app/controllers/|gems/[\w.\-]+/lib|RAILS_ENV", "Erro Ruby on Rails", "HIGH"),
    (r"/var/www/|/home/[\w.\-]+/public_html|/usr/local/\w+|"
     r"[A-Z]:\\(inetpub|xampp|wamp|laragon|Users)\\", "Vazamento de caminho do servidor", "MEDIUM"),
    (r"(?i)debug\s*=\s*true|APP_DEBUG.*true|display_errors\s*=\s*On", "Modo DEBUG ativo", "MEDIUM"),
]

# Versões a extrair quando aparecem em erros/respostas
VERSION_REGEX = re.compile(
    r"(PHP|MySQL|MariaDB|Apache|nginx|OpenSSL|Python|Java|ASP\.NET|"
    r"WordPress|Laravel|Django|Rails|Tomcat|IIS|Express)[/ ]?v?(\d+\.\d+[\d.]*)",
    re.IGNORECASE)

# Headers que entregam tecnologia/versão (severidade)
VERSION_HEADERS = {
    "server": "LOW", "x-powered-by": "MEDIUM", "x-aspnet-version": "MEDIUM",
    "x-aspnetmvc-version": "MEDIUM", "x-generator": "MEDIUM", "x-runtime": "LOW",
    "x-drupal-cache": "LOW", "x-redirect-by": "LOW", "via": "LOW",
    "x-served-by": "LOW", "x-backend-server": "MEDIUM", "x-debug-token": "MEDIUM",
    "x-debug-token-link": "HIGH",
}

# Assinaturas de Directory Listing
LISTING_SIGNATURES = [
    r"<title>Index of /", r"<h1>Index of /", r"Directory listing for /",
    r"\[To Parent Directory\]", r"<title>Directory Listing", r"autoindex",
]

# Padrões de segredos no corpo/JS: (nome, regex, severidade)
SECRET_PATTERNS = [
    ("Chave privada", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", "CRITICAL"),
    ("AWS Access Key", r"\bAKIA[0-9A-Z]{16}\b", "HIGH"),
    ("Google API Key", r"\bAIza[0-9A-Za-z\-_]{35}\b", "HIGH"),
    ("Slack Token", r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b", "HIGH"),
    ("JWT", r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b", "MEDIUM"),
    ("Credencial em URL", r"https?://[^/\s:@\"']{1,40}:[^/\s:@\"']{1,40}@", "MEDIUM"),
    ("API key atribuída", r"(?i)(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key|"
                          r"client[_-]?secret)\s*[:=]\s*[\"'][0-9A-Za-z\-_./+]{16,}[\"']", "MEDIUM"),
    ("Senha atribuída", r"(?i)(?:password|passwd|pwd|senha)\s*[:=]\s*[\"'][^\"'\s]{4,40}[\"']", "MEDIUM"),
]

# Palavras sensíveis dentro de comentários
COMMENT_KEYWORDS = [
    "senha", "password", "passwd", "pwd", "todo", "fixme", "hack", "admin",
    "root", "login", "api", "apikey", "api_key", "token", "secret", "internal",
    "debug", "backup", "deprecat", "remov", "temporar", "staging", "endpoint",
    "database", "db_", "credential", "credencial", "chave", "oculto", "hidden",
]
COMMENT_RE = re.compile(r"<!--(.*?)-->|/\*(.*?)\*/|//[^\n\r]{0,200}", re.DOTALL)


# ======================================================================
#  VALIDAÇÃO DE PII BRASILEIRA (o toque BR)
# ======================================================================
CPF_RE = re.compile(r"\b(\d{3})\.?(\d{3})\.?(\d{3})-?(\d{2})\b")
CNPJ_RE = re.compile(r"\b(\d{2})\.?(\d{3})\.?(\d{3})/?(\d{4})-?(\d{2})\b")


def valida_cpf(num):
    n = re.sub(r"\D", "", num)
    if len(n) != 11 or n == n[0] * 11:
        return False
    for i in (9, 10):
        s = sum(int(n[j]) * ((i + 1) - j) for j in range(i))
        d = (s * 10) % 11
        d = 0 if d == 10 else d
        if d != int(n[i]):
            return False
    return True


def valida_cnpj(num):
    n = re.sub(r"\D", "", num)
    if len(n) != 14 or n == n[0] * 14:
        return False
    pesos1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    pesos2 = [6] + pesos1
    for pesos, pos in ((pesos1, 12), (pesos2, 13)):
        s = sum(int(n[i]) * pesos[i] for i in range(pos))
        d = s % 11
        d = 0 if d < 2 else 11 - d
        if d != int(n[pos]):
            return False
    return True


def mascara(doc):
    n = re.sub(r"\D", "", doc)
    return n[:3] + "*" * (len(n) - 5) + n[-2:] if len(n) > 5 else "***"


# ======================================================================
#  SCANNER
# ======================================================================
class InfoHunter:
    def __init__(self, target, args):
        self.args = args
        self.base = self._normaliza(target)
        self.host = urlparse(self.base).netloc
        self.findings = []
        self.lock = threading.Lock()
        self.baseline = None      # (status, len, body) p/ detectar soft-404
        self.downloadables = []   # URLs de arquivos achados (p/ módulo metadados)

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": args.user_agent,
            "Accept": "*/*",
            "Connection": "close",
        })
        self.proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
        self.verify = not args.insecure
        self.timeout = args.timeout

    # ---- infra ----
    def _normaliza(self, t):
        if not re.match(r"^https?://", t):
            # tenta HTTPS, cai pra HTTP
            for scheme in ("https://", "http://"):
                try:
                    requests.head(scheme + t, timeout=5, verify=False)
                    return (scheme + t).rstrip("/")
                except Exception:
                    continue
            return ("http://" + t).rstrip("/")
        return t.rstrip("/")

    def _req(self, path="", method="GET", **kw):
        url = path if re.match(r"^https?://", path) else urljoin(self.base + "/", path)
        try:
            if self.args.delay:
                time.sleep(self.args.delay)
            r = self.session.request(method, url, timeout=self.timeout,
                                     allow_redirects=False, verify=self.verify,
                                     proxies=self.proxies, **kw)
            return r
        except requests.RequestException:
            return None

    def add(self, module, severity, title, url, evidence=""):
        ev = (evidence or "").strip().replace("\n", " ")[:240]
        with self.lock:
            self.findings.append({
                "modulo": module, "severidade": severity, "titulo": title,
                "url": url, "evidencia": ev,
            })
            tag = SEV_COLOR(severity) + f"[{severity:^8}]" + C.X
            print(f"  {tag} {C.W}{title}{C.X}")
            if url:
                print(f"            {C.D}{url}{C.X}")
            if ev:
                print(f"            {C.g}↳ {ev}{C.X}")

    def _bar(self, title):
        print(f"\n{C.G}┌─[ {title} ]{'─' * max(2, 58 - len(title))}{C.X}")

    # ---- baseline p/ soft-404 ----
    def _build_baseline(self):
        rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
        r = self._req(rnd + ".html")
        if r is not None:
            self.baseline = (r.status_code, len(r.content), r.text[:3000])

    def _is_soft404(self, r):
        if not self.baseline:
            return False
        bstatus, blen, bbody = self.baseline
        # Só existe "soft-404" se o servidor responde 200 a caminhos inexistentes.
        # Se ele responde 404 corretamente, qualquer 200 é um achado real.
        if bstatus != 200:
            return False
        if r.status_code != 200:
            return False
        if abs(len(r.content) - blen) <= 64:
            return True
        ratio = SequenceMatcher(None, bbody, r.text[:3000]).quick_ratio()
        return ratio > 0.92

    # =============================================================
    #  MÓDULO 1 — HEADERS
    # =============================================================
    def scan_headers(self):
        self._bar("MÓDULO 1 · Headers HTTP / Fingerprint")
        r = self._req("")
        if r is None:
            print(f"  {C.R}[!] Alvo não respondeu.{C.X}")
            return
        achou = False
        for h, sev in VERSION_HEADERS.items():
            if h in (k.lower() for k in r.headers):
                val = r.headers.get(h, "") or next(
                    (v for k, v in r.headers.items() if k.lower() == h), "")
                # eleva severidade se houver número de versão
                s = sev
                if re.search(r"\d+\.\d+", val) and sev == "LOW":
                    s = "MEDIUM"
                self.add("headers", s, f"Header expõe tecnologia: {h}", self.base,
                         f"{h}: {val}")
                achou = True
                for m in VERSION_REGEX.finditer(val):
                    self.add("headers", "MEDIUM", "Versão exata divulgada",
                             self.base, f"{m.group(1)} {m.group(2)}")
        # cookies sem flags (info)
        for ck in r.headers.get("set-cookie", "").split(","):
            if ck and "httponly" not in ck.lower():
                self.add("headers", "INFO", "Cookie sem flag HttpOnly", self.base,
                         ck.split("=")[0].strip()[:40])
                break
        if not achou:
            print(f"  {C.g}[ok] Nenhum header de versão óbvio.{C.X}")

    # =============================================================
    #  MÓDULO 2 — ARQUIVOS SENSÍVEIS
    # =============================================================
    def _check_path(self, path, base_sev):
        r = self._req(path)
        if r is None:
            return
        if r.status_code in (200, 206):
            if self._is_soft404(r):
                return
            raw = r.content
            txt = r.text
            confirmado = None
            for key, fn in VALIDATORS.items():
                if path.endswith(key) or key in path:
                    try:
                        confirmado = fn(txt, raw)
                    except Exception:
                        confirmado = None
                    break
            if confirmado is True:
                self.add("files", base_sev, f"EXPOSTO e confirmado: /{path}",
                         urljoin(self.base + "/", path),
                         f"HTTP 200 · {len(raw)} bytes · conteúdo validado")
                self._maybe_downloadable(path)
            elif confirmado is False:
                pass  # validador reprovou -> provável falso positivo
            else:
                sev = base_sev if base_sev in ("LOW", "INFO") else "MEDIUM"
                self.add("files", sev, f"Acessível (verificar): /{path}",
                         urljoin(self.base + "/", path),
                         f"HTTP 200 · {len(raw)} bytes")
                self._maybe_downloadable(path)
        elif r.status_code in (401, 403):
            # 403 em .git/.env muitas vezes confirma a existência
            if any(k in path for k in (".git", ".env", ".svn", ".htpasswd")):
                self.add("files", "LOW", f"Protegido mas presente: /{path}",
                         urljoin(self.base + "/", path),
                         f"HTTP {r.status_code} (existe, mas bloqueado)")

    def _maybe_downloadable(self, path):
        if re.search(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|tiff?)$", path, re.I):
            self.downloadables.append(urljoin(self.base + "/", path))

    def scan_files(self):
        self._bar("MÓDULO 2 · Arquivos & Caminhos Sensíveis")
        self._build_baseline()
        if self.baseline and self.baseline[0] == 200:
            print(f"  {C.Y}[i] Alvo responde 200 a caminhos aleatórios "
                  f"(soft-404). Filtro ativo.{C.X}")
        jobs = []
        for cat, items in SENSITIVE_PATHS.items():
            for path, sev in items:
                jobs.append((path, sev))
        # adiciona wordlist extra
        if self.args.wordlist and os.path.isfile(self.args.wordlist):
            with open(self.args.wordlist, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    p = line.strip().lstrip("/")
                    if p and not p.startswith("#"):
                        jobs.append((p, "MEDIUM"))
        print(f"  {C.D}Testando {len(jobs)} caminhos com {self.args.threads} threads...{C.X}")
        with futures.ThreadPoolExecutor(max_workers=self.args.threads) as ex:
            list(ex.map(lambda j: self._check_path(*j), jobs))

    # =============================================================
    #  MÓDULO 3 — DIRECTORY LISTING
    # =============================================================
    def scan_listing(self):
        self._bar("MÓDULO 3 · Directory Listing")
        dirs = ["", "uploads/", "files/", "backup/", "backups/", "img/", "images/",
                "assets/", "static/", "media/", "tmp/", "temp/", "old/", "data/",
                "docs/", "download/", "downloads/", "includes/", "logs/", "private/"]
        sig = re.compile("|".join(LISTING_SIGNATURES), re.IGNORECASE)
        achou = False
        for d in dirs:
            r = self._req(d)
            if r is None or r.status_code != 200:
                continue
            if sig.search(r.text):
                # extrai alguns nomes de arquivo listados
                nomes = re.findall(r'href="([^"?]+)"', r.text)
                nomes = [n for n in nomes if n not in ("../", "/")][:5]
                sev = "MEDIUM"
                if any(re.search(r"\.(sql|zip|env|bak|txt|key|pem)$", n, re.I) for n in nomes):
                    sev = "HIGH"
                self.add("listing", sev, f"Directory listing aberto: /{d}",
                         urljoin(self.base + "/", d),
                         "arquivos: " + ", ".join(nomes) if nomes else "índice exposto")
                achou = True
        if not achou:
            print(f"  {C.g}[ok] Nenhum diretório listável encontrado.{C.X}")

    # =============================================================
    #  MÓDULO 4 — ERROS VERBOSOS
    # =============================================================
    def _harvest_endpoints(self):
        r = self._req("")
        eps = set()
        if r is not None:
            for m in re.finditer(r'(?:href|action|src)="([^"#]+)"', r.text):
                u = m.group(1)
                full = urljoin(self.base + "/", u)
                if urlparse(full).netloc == self.host and (
                        "?" in full or re.search(r"\.(php|asp|aspx|jsp|do|cgi)(\?|$)", full, re.I)):
                    eps.add(full.split("#")[0])
        return list(eps)[:12]

    def _probe_errors(self, url):
        payloads = ["'", "%27", "\"'><", "[]", "%00",
                    "../../../../etc/passwd", "1%20AND%201=2"]
        sig = [(re.compile(rx, re.IGNORECASE), lbl, sv) for rx, lbl, sv in ERROR_SIGNATURES]
        sep = "&" if "?" in url else "?"
        targets = [url] + [f"{url}{sep}infohunter={p}" for p in payloads]
        for t in targets:
            r = self._req(t)
            if r is None:
                continue
            body = r.text
            for rx, label, sev in sig:
                m = rx.search(body)
                if m:
                    versoes = {f"{a} {b}" for a, b in VERSION_REGEX.findall(body)}
                    extra = (" · " + ", ".join(list(versoes)[:3])) if versoes else ""
                    self.add("errors", sev, f"Erro verboso: {label}", t,
                             m.group(0)[:120] + extra)
                    return  # 1 achado por endpoint já basta

    def scan_errors(self):
        self._bar("MÓDULO 4 · Indução de Erros Verbosos")
        urls = [self.base + "/"] + self._harvest_endpoints()
        urls += [self.base + "/" + "%ff", self.base + "/index.php?id='"]
        print(f"  {C.D}Sondando {len(urls)} alvos com payloads de erro...{C.X}")
        before = len(self.findings)
        for u in urls:
            self._probe_errors(u)
        if len(self.findings) == before:
            print(f"  {C.g}[ok] Nenhum stack trace / erro verboso disparado.{C.X}")

    # =============================================================
    #  MÓDULO 5 — COMENTÁRIOS, SEGREDOS & PII
    # =============================================================
    def _scan_blob(self, texto, origem):
        # comentários
        for m in COMMENT_RE.finditer(texto):
            comentario = next((g for g in m.groups() if g), "") or m.group(0)
            low = comentario.lower()
            achados = [kw for kw in COMMENT_KEYWORDS if kw in low]
            if achados and len(comentario.strip()) > 3:
                self.add("comments", "MEDIUM", "Comentário sensível no código",
                         origem, f"[{','.join(sorted(set(achados))[:4])}] "
                                 + comentario.strip()[:120])
        # segredos
        for nome, rx, sev in SECRET_PATTERNS:
            for m in re.finditer(rx, texto):
                trecho = m.group(0)
                if len(trecho) > 60:
                    trecho = trecho[:30] + "…" + trecho[-12:]
                self.add("comments", sev, f"Segredo exposto: {nome}", origem, trecho)
                break  # 1 por tipo por arquivo
        # PII brasileira
        cpfs = {mascara("".join(g)) for g in CPF_RE.findall(texto)
                if valida_cpf("".join(g))}
        cnpjs = {mascara("".join(g)) for g in CNPJ_RE.findall(texto)
                 if valida_cnpj("".join(g))}
        if cpfs:
            self.add("comments", "HIGH", f"Vazamento de CPF válido ({len(cpfs)})",
                     origem, "ex: " + ", ".join(list(cpfs)[:3]))
        if cnpjs:
            self.add("comments", "MEDIUM", f"Vazamento de CNPJ válido ({len(cnpjs)})",
                     origem, "ex: " + ", ".join(list(cnpjs)[:3]))

    def scan_comments(self):
        self._bar("MÓDULO 5 · Comentários, Segredos & PII")
        r = self._req("")
        if r is None:
            print(f"  {C.R}[!] Sem resposta da página inicial.{C.X}")
            return
        before = len(self.findings)
        self._scan_blob(r.text, self.base)
        # coleta arquivos JS same-origin
        js = []
        for m in re.finditer(r'<script[^>]+src="([^"]+)"', r.text):
            full = urljoin(self.base + "/", m.group(1))
            if urlparse(full).netloc == self.host:
                js.append(full)
        js = list(dict.fromkeys(js))[: self.args.max_js]
        if js:
            print(f"  {C.D}Analisando {len(js)} arquivo(s) JS same-origin...{C.X}")
        for j in js:
            rj = self._req(j)
            if rj is not None and rj.status_code == 200:
                self._scan_blob(rj.text, j)
        if len(self.findings) == before:
            print(f"  {C.g}[ok] Nada sensível em comentários/JS.{C.X}")

    # =============================================================
    #  MÓDULO 6 — METADADOS
    # =============================================================
    def _meta_pdf(self, raw, origem):
        t = raw.decode("latin-1", "ignore")
        campos = {}
        for f in ("Author", "Creator", "Producer", "Title", "CreationDate", "ModDate"):
            m = re.search(r"/%s\s*\(([^)]{1,200})\)" % f, t)
            if m and m.group(1).strip():
                campos[f] = m.group(1).strip()
        if campos:
            ev = " · ".join(f"{k}={v}" for k, v in campos.items())
            self.add("metadata", "LOW", "Metadados em PDF", origem, ev[:220])

    def _meta_office(self, raw, origem):
        try:
            z = zipfile.ZipFile(io.BytesIO(raw))
        except Exception:
            return
        if "docProps/core.xml" in z.namelist():
            core = z.read("docProps/core.xml").decode("utf-8", "ignore")
            campos = {}
            for tag in ("dc:creator", "cp:lastModifiedBy", "dc:title", "cp:company"):
                m = re.search(r"<%s>([^<]+)</%s>" % (tag, tag), core)
                if m:
                    campos[tag.split(":")[-1]] = m.group(1)
            if campos:
                ev = " · ".join(f"{k}={v}" for k, v in campos.items())
                self.add("metadata", "LOW", "Metadados em documento Office", origem, ev[:220])

    def _meta_image(self, raw, origem):
        if raw[:2] == b"\xff\xd8":  # JPEG
            head = raw[:20000]
            if b"Exif\x00\x00" in head:
                gps = b"GPSLatitude" in head or b"\x88\x25" in head
                self.add("metadata", "MEDIUM" if gps else "LOW",
                         "Imagem com EXIF" + (" (possível GPS!)" if gps else ""),
                         origem, "marcador Exif presente")

    def scan_metadata(self):
        self._bar("MÓDULO 6 · Metadados de Arquivos")
        alvos = list(dict.fromkeys(self.downloadables))
        if self.args.meta_url:
            alvos.append(self.args.meta_url)
        if not alvos:
            print(f"  {C.D}[i] Nenhum arquivo baixável detectado. "
                  f"Use --meta-url <arquivo> para apontar manualmente.{C.X}")
            return
        for u in alvos[:20]:
            r = self._req(u)
            if r is None or r.status_code != 200:
                continue
            raw = r.content
            low = u.lower()
            if low.endswith(".pdf") or raw[:5] == b"%PDF-":
                self._meta_pdf(raw, u)
            elif re.search(r"\.(docx|xlsx|pptx)$", low) or raw[:2] == b"PK":
                self._meta_office(raw, u)
            elif re.search(r"\.(jpe?g|png|tiff?)$", low) or raw[:2] == b"\xff\xd8":
                self._meta_image(raw, u)

    # =============================================================
    #  EXECUÇÃO + RELATÓRIO
    # =============================================================
    def run(self, modules):
        m = {
            "headers": self.scan_headers, "files": self.scan_files,
            "listing": self.scan_listing, "errors": self.scan_errors,
            "comments": self.scan_comments, "metadata": self.scan_metadata,
        }
        t0 = time.time()
        for name in modules:
            if name in m:
                try:
                    m[name]()
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    print(f"  {C.R}[!] Erro no módulo {name}: {e}{C.X}")
        self.elapsed = time.time() - t0

    def resumo(self):
        print(f"\n{C.G}╔{'═' * 58}╗{C.X}")
        print(f"{C.G}║{C.W}{'RESUMO DA VARREDURA':^58}{C.G}║{C.X}")
        print(f"{C.G}╚{'═' * 58}╝{C.X}")
        cont = {k: 0 for k in SEV_ORDER}
        for f in self.findings:
            cont[f["severidade"]] = cont.get(f["severidade"], 0) + 1
        for sev in sorted(cont, key=lambda s: SEV_ORDER[s]):
            if cont[sev]:
                print(f"  {SEV_COLOR(sev)}{sev:<9}{C.X} : {cont[sev]}")
        total = len(self.findings)
        cor = C.R if (cont["CRITICAL"] or cont["HIGH"]) else (C.Y if total else C.g)
        print(f"  {C.W}{'─'*20}{C.X}")
        print(f"  {cor}TOTAL     : {total} achado(s){C.X}")
        print(f"  {C.D}Tempo: {self.elapsed:.1f}s · Alvo: {self.base}{C.X}")
        if not total:
            print(f"\n  {C.g}Nenhuma exposição óbvia detectada. "
                  f"(ausência de achado ≠ ausência de falha){C.X}")

    def salvar(self, base_out, fmt):
        if not base_out:
            return
        ordenado = sorted(self.findings, key=lambda f: SEV_ORDER[f["severidade"]])
        meta = {
            "alvo": self.base, "data": datetime.now().isoformat(timespec="seconds"),
            "total": len(ordenado), "ferramenta": "InfoHunter BR",
        }
        saidas = []
        if fmt in ("json", "all"):
            fn = base_out + ".json"
            with open(fn, "w", encoding="utf-8") as f:
                json.dump({"meta": meta, "achados": ordenado}, f,
                          ensure_ascii=False, indent=2)
            saidas.append(fn)
        if fmt in ("csv", "all"):
            fn = base_out + ".csv"
            with open(fn, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["severidade", "modulo", "titulo",
                                                  "url", "evidencia"])
                w.writeheader()
                for row in ordenado:
                    w.writerow({k: row[k] for k in w.fieldnames})
            saidas.append(fn)
        if fmt in ("txt", "all"):
            fn = base_out + ".txt"
            with open(fn, "w", encoding="utf-8") as f:
                f.write(f"InfoHunter BR — Relatório\nAlvo: {self.base}\n"
                        f"Data: {meta['data']}\nTotal: {meta['total']}\n"
                        + "=" * 60 + "\n")
                for r in ordenado:
                    f.write(f"\n[{r['severidade']}] {r['titulo']}\n"
                            f"  URL: {r['url']}\n  Evidência: {r['evidencia']}\n")
            saidas.append(fn)
        for s in saidas:
            print(f"  {C.B}[+] Relatório salvo: {s}{C.X}")


# ======================================================================
#  CLI
# ======================================================================
BANNER = r"""
 ___        __     _   _             _            ____  ____
|_ _|_ __  / _| __| | | |_   _ _ __ | |_ ___ _ __| __ )|  _ \
 | || '_ \| |_ / _` |_| | | | | '_ \| __/ _ \ '__|  _ \| |_) |
 | || | | |  _| (_) |  _  | |_| | | | | ||  __/ |  | |_) |  _ <
|___|_| |_|_|  \___/|_| |_|\__,_|_| |_|\__\___|_|  |____/|_| \_\
"""

ALL_MODULES = ["headers", "files", "listing", "errors", "comments", "metadata"]


def banner():
    print(C.G + BANNER + C.X)
    print(f"   {C.W}Scanner de Information Disclosure{C.X} "
          f"{C.D}v1.0{C.X}")
    print(f"   {C.g}Cybersegurança na Prática{C.X}\n")
    print(f"   {C.Y}⚠ Use SOMENTE com autorização por escrito. "
          f"Lei 12.737/2012 + LGPD.{C.X}")
    print(f"   {C.D}Você assume total responsabilidade pelo uso desta ferramenta.{C.X}\n")


def main():
    p = argparse.ArgumentParser(
        description="InfoHunter BR — detecta Information Disclosure em alvos web.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""exemplos:
  python infohunter_br.py https://alvo.com.br
  python infohunter_br.py alvo.com.br -m files,listing -t 30
  python infohunter_br.py https://alvo.com.br -o relatorio --format all
  python infohunter_br.py https://alvo.com.br --proxy http://127.0.0.1:8080
""")
    p.add_argument("target", nargs="?", help="URL ou host alvo")
    p.add_argument("-m", "--modules", default="all",
                   help="módulos: " + ",".join(ALL_MODULES) + " (padrão: all)")
    p.add_argument("-t", "--threads", type=int, default=15, help="threads (padrão 15)")
    p.add_argument("--timeout", type=int, default=8, help="timeout por request (s)")
    p.add_argument("--delay", type=float, default=0, help="delay entre requests (s)")
    p.add_argument("-w", "--wordlist", help="wordlist extra de caminhos (módulo files)")
    p.add_argument("--proxy", help="proxy, ex: http://127.0.0.1:8080 (Burp)")
    p.add_argument("-A", "--user-agent",
                   default="Mozilla/5.0 (InfoHunterBR/1.0; +CyberSegPratica)",
                   help="User-Agent customizado")
    p.add_argument("-k", "--insecure", action="store_true", help="ignora erro de SSL")
    p.add_argument("--max-js", type=int, default=15, help="máx. arquivos JS a analisar")
    p.add_argument("--meta-url", help="URL de arquivo p/ extrair metadados (módulo metadata)")
    p.add_argument("-o", "--output", help="nome base do relatório (sem extensão)")
    p.add_argument("--format", choices=["txt", "json", "csv", "all"], default="json",
                   help="formato do relatório (padrão json)")
    p.add_argument("--no-color", action="store_true", help="desativa cores")
    p.add_argument("--list-paths", action="store_true", help="lista a wordlist embutida e sai")
    args = p.parse_args()

    if args.no_color:
        C.off()

    if args.list_paths:
        for cat, items in SENSITIVE_PATHS.items():
            print(f"\n# {cat}")
            for path, sev in items:
                print(f"{path}")
        return

    banner()

    if not args.target:
        p.print_help()
        sys.exit(0)

    modules = ALL_MODULES if args.modules == "all" else [
        x.strip() for x in args.modules.split(",") if x.strip() in ALL_MODULES]
    if not modules:
        print(f"{C.R}[!] Nenhum módulo válido. Opções: {','.join(ALL_MODULES)}{C.X}")
        sys.exit(1)

    print(f"{C.B}[*] Alvo:{C.X} {args.target}")
    print(f"{C.B}[*] Módulos:{C.X} {', '.join(modules)}")

    scanner = InfoHunter(args.target, args)
    print(f"{C.B}[*] URL base resolvida:{C.X} {scanner.base}\n")
    try:
        scanner.run(modules)
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] Interrompido pelo usuário.{C.X}")
    scanner.resumo()
    if args.output:
        print()
        scanner.salvar(args.output, args.format)


if __name__ == "__main__":
    main()