"""
core/base.py — Classe base para todos os módulos OSINT
"""

import time
import requests
from abc import ABC, abstractmethod
from rich.console import Console

console = Console()


class BaseModule(ABC):
    """
    Classe base herdada por todos os módulos.
    Provê: session HTTP (com/sem Tor), rate limiting, retries e logging.
    """

    def __init__(self, config: dict):
        self.config  = config
        self.verbose = config.get("verbose", False)
        self.delay   = config.get("request_delay", 1.5)
        self.timeout = config.get("timeout", 15)
        self.retries = config.get("max_retries", 3)
        self.session = self._build_session()

    # ------------------------------------------------------------------
    # Session
    # ------------------------------------------------------------------
    def _build_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            )
        })
        if self.config.get("use_tor"):
            proxy = self.config.get("tor_proxy", "socks5h://127.0.0.1:9050")
            session.proxies = {"http": proxy, "https": proxy}
            self.log("[yellow]Roteando via Tor[/yellow]")
        return session

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------
    def get(self, url: str, **kwargs) -> requests.Response | None:
        kwargs.setdefault("timeout", self.timeout)
        for attempt in range(1, self.retries + 1):
            try:
                time.sleep(self.delay)
                resp = self.session.get(url, **kwargs)
                resp.raise_for_status()
                return resp
            except requests.exceptions.HTTPError as e:
                if e.response is not None and e.response.status_code == 429:
                    wait = 10 * attempt
                    self.log(f"[yellow]Rate-limit — aguardando {wait}s...[/yellow]")
                    time.sleep(wait)
                else:
                    self.log(f"[red]HTTP {e}[/red] (tentativa {attempt}/{self.retries})")
                    break
            except requests.exceptions.RequestException as e:
                self.log(f"[red]Erro de rede:[/red] {e} (tentativa {attempt}/{self.retries})")
                time.sleep(2 * attempt)
        return None

    def post(self, url: str, **kwargs) -> requests.Response | None:
        kwargs.setdefault("timeout", self.timeout)
        try:
            time.sleep(self.delay)
            resp = self.session.post(url, **kwargs)
            resp.raise_for_status()
            return resp
        except requests.exceptions.RequestException as e:
            self.log(f"[red]POST falhou:[/red] {e}")
            return None

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    def log(self, msg: str):
        if self.verbose:
            console.print(f"  [dim][{self.__class__.__name__}][/dim] {msg}")

    def info(self, msg: str):
        console.print(f"  [cyan]→[/cyan] {msg}")

    def success(self, msg: str):
        console.print(f"  [green]✓[/green] {msg}")

    def warn(self, msg: str):
        console.print(f"  [yellow]⚠[/yellow] {msg}")

    def error(self, msg: str):
        console.print(f"  [red]✗[/red] {msg}")

    # ------------------------------------------------------------------
    # Interface obrigatória
    # ------------------------------------------------------------------
    @abstractmethod
    def run(self, target: str) -> dict:
        """
        Executa o módulo para o target informado.
        Retorna um dict com os resultados estruturados.
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Nome legível do módulo."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Descrição curta do módulo."""
        ...
