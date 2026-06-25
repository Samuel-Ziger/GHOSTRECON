"""
modules/git_leak.py — Busca segredos expostos em repositórios GitHub/GitLab públicos
"""

import re
import base64
from core.base import BaseModule

# Padrões de segredos — regex compilados
SECRET_PATTERNS = {
    "AWS Access Key":       re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key":       re.compile(r"(?i)aws[_\-\s]?secret[_\-\s]?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"),
    "GitHub Token":         re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "GitHub Fine-grained":  re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
    "GitLab Token":         re.compile(r"glpat-[A-Za-z0-9\-_]{20}"),
    "Google API Key":       re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Google OAuth":         re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    "Stripe Secret Key":    re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "Stripe Publishable":   re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
    "Twilio Account SID":   re.compile(r"AC[a-zA-Z0-9]{32}"),
    "Twilio Auth Token":    re.compile(r"(?i)twilio[^0-9a-z].*[0-9a-f]{32}"),
    "SendGrid API Key":     re.compile(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"),
    "Mailgun API Key":      re.compile(r"key-[0-9a-zA-Z]{32}"),
    "Slack Token":          re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    "Slack Webhook":        re.compile(r"https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+"),
    "Discord Token":        re.compile(r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"),
    "Telegram Bot Token":   re.compile(r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}"),
    "JWT Token":            re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "RSA Private Key":      re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
    "Private Key":          re.compile(r"-----BEGIN (?:EC|DSA|OPENSSH) PRIVATE KEY-----"),
    "Password in Config":   re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,})"),
    "DB Connection String": re.compile(r"(?i)(?:mysql|postgres|mongodb|redis|mssql)://[^:]+:[^@]+@[^\s\"']+"),
    "Generic Secret":       re.compile(r"(?i)(?:secret|api_key|apikey|access_token|auth_token)\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{16,})"),
    "SSH Private Key":      re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    "Azure Connection":     re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"),
    "Heroku API Key":       re.compile(r"(?i)heroku[^0-9a-z].*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    "MailChimp API Key":    re.compile(r"[0-9a-f]{32}-us[0-9]{1,2}"),
    "PayPal BrainTree":     re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    "NPM Token":            re.compile(r"npm_[A-Za-z0-9]{36}"),
    "Hugging Face Token":   re.compile(r"hf_[A-Za-z0-9]{32,}"),
    "OpenAI API Key":       re.compile(r"sk-[A-Za-z0-9]{48}"),
    "Anthropic API Key":    re.compile(r"sk-ant-[A-Za-z0-9\-_]{40,}"),
}

# Extensões de arquivo para priorizar na busca
RISKY_EXTENSIONS = [
    ".env", ".config", ".cfg", ".conf", ".ini", ".yaml", ".yml",
    ".json", ".properties", ".xml", ".toml", ".py", ".js", ".ts",
    ".sh", ".bash", ".zsh", ".dockerfile", "docker-compose",
    ".tf", ".tfvars",  # Terraform
]


class GitLeakHunter(BaseModule):
    name        = "GitLeakHunter"
    description = "Busca segredos expostos em repos GitHub públicos"

    GH_API = "https://api.github.com"

    def run(self, target: str) -> dict:
        self.info(f"Buscando segredos em: [bold]{target}[/bold]")

        headers = {"Accept": "application/vnd.github+json"}
        if self.config.get("github_token"):
            headers["Authorization"] = f"Bearer {self.config['github_token']}"
        self.session.headers.update(headers)

        findings   = []
        repos_scanned = 0

        # 1. Lista repos da org/usuário
        repos = self._list_repos(target)
        self.info(f"{len(repos)} repositórios encontrados")

        # 2. Para cada repo, busca via GitHub Code Search + análise de arquivos
        for repo in repos[:30]:  # limita a 30 repos
            repo_name = repo.get("full_name", "")
            findings += self._search_repo(repo_name)
            repos_scanned += 1

        # 3. GitHub Code Search direto (busca global de secrets)
        findings += self._github_code_search(target)

        # Deduplica por (repo, arquivo, padrão)
        seen = set()
        unique = []
        for f in findings:
            key = (f.get("repo"), f.get("file"), f.get("pattern"))
            if key not in seen:
                seen.add(key)
                unique.append(f)

        # Categoriza por criticidade
        critical = [f for f in unique if f.get("pattern") in (
            "AWS Access Key", "AWS Secret Key", "GitHub Token", "RSA Private Key",
            "Private Key", "SSH Private Key", "OpenAI API Key", "Anthropic API Key",
        )]

        self.success(f"{len(unique)} segredos | {len(critical)} críticos | {repos_scanned} repos")

        return {
            "target":        target,
            "repos_scanned": repos_scanned,
            "total_findings":len(unique),
            "critical_count":len(critical),
            "findings":      unique,
            "critical":      critical,
        }

    # ------------------------------------------------------------------
    def _list_repos(self, org_or_user: str) -> list:
        repos = []
        for endpoint in (f"/orgs/{org_or_user}/repos", f"/users/{org_or_user}/repos"):
            resp = self.get(f"{self.GH_API}{endpoint}",
                            params={"per_page": 100, "type": "public", "sort": "updated"})
            if resp and resp.status_code == 200:
                repos = resp.json()
                break
        return repos if isinstance(repos, list) else []

    def _search_repo(self, full_name: str) -> list:
        """Analisa arquivos sensíveis diretamente no repositório."""
        findings = []

        # Busca arquivos por nome risky
        for ext in [".env", ".yaml", ".yml", ".json", ".config"]:
            resp = self.get(
                f"{self.GH_API}/search/code",
                params={"q": f"repo:{full_name} filename:{ext}", "per_page": 10}
            )
            if resp and resp.status_code == 200:
                for item in resp.json().get("items", []):
                    findings += self._analyze_file(
                        full_name,
                        item.get("path", ""),
                        item.get("sha", ""),
                    )

        return findings

    def _analyze_file(self, repo: str, path: str, sha: str) -> list:
        """Baixa conteúdo do arquivo e aplica regex patterns."""
        findings = []
        resp = self.get(f"{self.GH_API}/repos/{repo}/git/blobs/{sha}")
        if not resp or resp.status_code != 200:
            return findings

        try:
            blob = resp.json()
            if blob.get("encoding") == "base64":
                content = base64.b64decode(blob["content"]).decode("utf-8", errors="ignore")
            else:
                content = blob.get("content", "")

            for pattern_name, regex in SECRET_PATTERNS.items():
                matches = regex.findall(content)
                for match in matches:
                    # Trunca o match para não expor o segredo completo no relatório
                    match_str = match if isinstance(match, str) else str(match)
                    masked    = match_str[:6] + "***" + match_str[-4:] if len(match_str) > 10 else "***"

                    # Contexto: linha onde foi encontrado
                    line_num  = self._find_line(content, match_str)
                    findings.append({
                        "repo":    repo,
                        "file":    path,
                        "pattern": pattern_name,
                        "match":   masked,
                        "line":    line_num,
                        "url":     f"https://github.com/{repo}/blob/main/{path}",
                    })
        except Exception as e:
            self.log(f"Erro ao analisar {repo}/{path}: {e}")

        return findings

    def _github_code_search(self, org: str) -> list:
        """GitHub Code Search API — busca global por padrões."""
        findings = []
        queries  = [
            f"org:{org} password",
            f"org:{org} secret_key",
            f"org:{org} api_key",
            f"org:{org} AKIA",
            f"org:{org} BEGIN RSA PRIVATE",
            f"org:{org} .env",
        ]
        for q in queries:
            resp = self.get(
                f"{self.GH_API}/search/code",
                params={"q": q, "per_page": 10}
            )
            if resp and resp.status_code == 200:
                for item in resp.json().get("items", []):
                    findings.append({
                        "repo":    item.get("repository", {}).get("full_name"),
                        "file":    item.get("path"),
                        "pattern": "Code Search Hit",
                        "match":   q.split()[-1],
                        "line":    None,
                        "url":     item.get("html_url"),
                    })
        return findings

    def _find_line(self, content: str, match: str) -> int | None:
        for i, line in enumerate(content.splitlines(), 1):
            if match[:10] in line:
                return i
        return None
