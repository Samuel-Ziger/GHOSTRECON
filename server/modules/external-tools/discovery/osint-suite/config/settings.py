"""
config/settings.py — Carrega configurações de settings.yaml
"""

import os
import yaml
from pathlib import Path

DEFAULT_CONFIG = {
    "github_token":      "",
    "shodan_api_key":    "",
    "virustotal_key":    "",
    "abuseipdb_key":     "",
    "otx_api_key":       "",
    "wigle_api_name":    "",
    "wigle_api_token":   "",
    "hibp_api_key":      "",
    "censys_api_id":     "",
    "censys_api_secret": "",
    "telegram_bot_token":"",
    "telegram_chat_id":  "",
    "tor_proxy":         "socks5h://127.0.0.1:9050",
    "request_delay":     1.5,   # segundos entre requests
    "max_retries":       3,
    "timeout":           15,
    "output_dir":        "reports/",
    "verbose":           False,
    "use_tor":           False,
}

YAML_TEMPLATE = """\
# OSINT Suite — Configurações
# Preencha as API keys que você possui; módulos sem key funcionam de forma degradada.

github_token:       ""          # https://github.com/settings/tokens
shodan_api_key:     ""          # https://account.shodan.io/
virustotal_key:     ""          # https://www.virustotal.com/gui/my-apikey
abuseipdb_key:      ""          # https://www.abuseipdb.com/account/api
otx_api_key:        ""          # https://otx.alienvault.com/api
wigle_api_name:     ""          # https://wigle.net/account
wigle_api_token:    ""
hibp_api_key:       ""          # https://haveibeenpwned.com/API/Key
censys_api_id:      ""          # https://search.censys.io/account/api
censys_api_secret:  ""
telegram_bot_token: ""          # Alertas via Telegram (opcional)
telegram_chat_id:   ""

# Comportamento
request_delay:  1.5             # segundos entre requisições (evita rate-limit)
max_retries:    3
timeout:        15
output_dir:     "reports/"
"""

def load_config(path: str = "config/settings.yaml") -> dict:
    """Carrega configuração do YAML + variáveis de ambiente."""
    config = DEFAULT_CONFIG.copy()

    # Cria arquivo de exemplo se não existir
    cfg_path = Path(path)
    if not cfg_path.exists():
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(YAML_TEMPLATE)
        print(f"[config] Arquivo criado em {path} — preencha suas API keys.")
    else:
        with open(cfg_path) as f:
            loaded = yaml.safe_load(f) or {}
        config.update({k: v for k, v in loaded.items() if v})

    # Variáveis de ambiente têm prioridade (ex: OSINT_GITHUB_TOKEN)
    env_map = {
        "OSINT_GITHUB_TOKEN":      "github_token",
        "OSINT_SHODAN_KEY":        "shodan_api_key",
        "OSINT_VT_KEY":            "virustotal_key",
        "OSINT_ABUSEIPDB_KEY":     "abuseipdb_key",
        "OSINT_OTX_KEY":           "otx_api_key",
        "OSINT_WIGLE_NAME":        "wigle_api_name",
        "OSINT_WIGLE_TOKEN":       "wigle_api_token",
        "OSINT_HIBP_KEY":          "hibp_api_key",
        "OSINT_CENSYS_ID":         "censys_api_id",
        "OSINT_CENSYS_SECRET":     "censys_api_secret",
        "OSINT_TG_TOKEN":          "telegram_bot_token",
        "OSINT_TG_CHAT":           "telegram_chat_id",
    }
    for env_var, cfg_key in env_map.items():
        val = os.getenv(env_var)
        if val:
            config[cfg_key] = val

    # Garante diretório de output
    Path(config["output_dir"]).mkdir(parents=True, exist_ok=True)

    return config
