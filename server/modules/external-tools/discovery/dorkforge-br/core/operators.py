"""
operators.py — Construtor fluente de Google Dorks (DorkBuilder).

Este módulo implementa a classe :class:`DorkBuilder`, responsável por montar
consultas de busca avançada (Google Dorks) de forma programática e encadeável
(fluent interface). Cada operador é um método que retorna ``self``, permitindo
combinar várias chamadas em sequência.

Exemplo de uso::

    from core.operators import DorkBuilder

    dork = (DorkBuilder()
            .site("*.gov.br")
            .filetype("xls")
            .intext("CPF")
            .build())
    # -> 'site:*.gov.br filetype:xls intext:"CPF"'

IMPORTANTE (arquitetura ética): esta classe apenas CONSTRÓI a string da consulta
e gera a URL de busca. Ela NÃO realiza scraping de resultados do Google — isso
violaria os Termos de Serviço do Google. Para coleta automatizada de resultados,
o caminho correto seria a Google Custom Search JSON API (que exige chave de API),
o que está fora do escopo desta ferramenta por decisão de projeto.
"""

from __future__ import annotations

from typing import List
from urllib.parse import quote_plus

# Mecanismos de busca suportados e seus endpoints base.
# A query (já codificada) é anexada ao final de cada URL.
MOTORES_BUSCA = {
    "google": "https://www.google.com/search?q=",
    "bing": "https://www.bing.com/search?q=",
    "duckduckgo": "https://duckduckgo.com/?q=",
}


class DorkBuilder:
    """Construtor encadeável (fluent) de Google Dorks.

    Acumula partes da consulta em uma lista interna e as une com espaços ao
    chamar :meth:`build`. Cada método de operador retorna ``self`` para permitir
    o encadeamento de chamadas.
    """

    def __init__(self) -> None:
        """Inicializa um construtor vazio."""
        self._partes: List[str] = []

    # ------------------------------------------------------------------ #
    # Utilitários internos de formatação
    # ------------------------------------------------------------------ #
    @staticmethod
    def _aspas_se_preciso(valor: str) -> str:
        """Envolve ``valor`` em aspas duplas apenas se contiver espaços.

        Mantém o valor intacto caso já esteja entre aspas.
        """
        valor = valor.strip()
        if not valor:
            return valor
        if valor.startswith('"') and valor.endswith('"'):
            return valor
        if " " in valor:
            return f'"{valor}"'
        return valor

    @staticmethod
    def _aspas_sempre(valor: str) -> str:
        """Envolve ``valor`` em aspas duplas (correspondência exata).

        Não duplica aspas caso o valor já esteja entre aspas.
        """
        valor = valor.strip()
        if not valor:
            return valor
        if valor.startswith('"') and valor.endswith('"'):
            return valor
        return f'"{valor}"'

    # ------------------------------------------------------------------ #
    # Operadores de domínio / URL
    # ------------------------------------------------------------------ #
    def site(self, dominio: str) -> "DorkBuilder":
        """Restringe a busca a um domínio (``site:``).

        Ex.: ``site:gov.br`` ou ``site:*.gov.br``.
        """
        self._partes.append(f"site:{dominio.strip()}")
        return self

    def inurl(self, termo: str) -> "DorkBuilder":
        """Procura um termo na URL (``inurl:``). Ex.: ``inurl:admin``."""
        self._partes.append(f"inurl:{self._aspas_se_preciso(termo)}")
        return self

    def allinurl(self, *termos: str) -> "DorkBuilder":
        """Procura vários termos na URL (``allinurl:``).

        Ex.: ``allinurl:admin login``.
        """
        unidos = " ".join(t.strip() for t in termos if t.strip())
        if unidos:
            self._partes.append(f"allinurl:{unidos}")
        return self

    # ------------------------------------------------------------------ #
    # Operadores de título
    # ------------------------------------------------------------------ #
    def intitle(self, termo: str) -> "DorkBuilder":
        """Procura um termo no título da página (``intitle:``).

        Ex.: ``intitle:"index of"``.
        """
        self._partes.append(f"intitle:{self._aspas_se_preciso(termo)}")
        return self

    def allintitle(self, *termos: str) -> "DorkBuilder":
        """Procura vários termos no título (``allintitle:``).

        Ex.: ``allintitle:painel admin``.
        """
        unidos = " ".join(t.strip() for t in termos if t.strip())
        if unidos:
            self._partes.append(f"allintitle:{unidos}")
        return self

    # ------------------------------------------------------------------ #
    # Operadores de corpo de texto
    # ------------------------------------------------------------------ #
    def intext(self, termo: str) -> "DorkBuilder":
        """Procura um termo no corpo da página (``intext:``).

        O termo é sempre colocado entre aspas para correspondência exata.
        Ex.: ``intext:"senha"``.
        """
        self._partes.append(f"intext:{self._aspas_sempre(termo)}")
        return self

    def allintext(self, *termos: str) -> "DorkBuilder":
        """Procura vários termos no corpo (``allintext:``).

        Ex.: ``allintext:usuario senha``.
        """
        unidos = " ".join(t.strip() for t in termos if t.strip())
        if unidos:
            self._partes.append(f"allintext:{unidos}")
        return self

    # ------------------------------------------------------------------ #
    # Operadores de tipo de arquivo
    # ------------------------------------------------------------------ #
    def filetype(self, extensao: str) -> "DorkBuilder":
        """Restringe a um tipo de arquivo (``filetype:``). Ex.: ``filetype:pdf``."""
        self._partes.append(f"filetype:{extensao.strip().lstrip('.')}")
        return self

    def ext(self, extensao: str) -> "DorkBuilder":
        """Alias de ``filetype`` usando o operador ``ext:``. Ex.: ``ext:bak``."""
        self._partes.append(f"ext:{extensao.strip().lstrip('.')}")
        return self

    # ------------------------------------------------------------------ #
    # Operadores de relação entre páginas
    # ------------------------------------------------------------------ #
    def cache(self, url: str) -> "DorkBuilder":
        """Mostra a versão em cache do Google (``cache:``)."""
        self._partes.append(f"cache:{url.strip()}")
        return self

    def related(self, url: str) -> "DorkBuilder":
        """Encontra sites relacionados (``related:``)."""
        self._partes.append(f"related:{url.strip()}")
        return self

    # ------------------------------------------------------------------ #
    # Operadores de data
    # ------------------------------------------------------------------ #
    def before(self, data: str) -> "DorkBuilder":
        """Filtra resultados anteriores à data (``before:AAAA-MM-DD``)."""
        self._partes.append(f"before:{data.strip()}")
        return self

    def after(self, data: str) -> "DorkBuilder":
        """Filtra resultados posteriores à data (``after:AAAA-MM-DD``)."""
        self._partes.append(f"after:{data.strip()}")
        return self

    # ------------------------------------------------------------------ #
    # Operadores avançados
    # ------------------------------------------------------------------ #
    def around(self, termo1: str, n: int, termo2: str) -> "DorkBuilder":
        """Proximidade entre dois termos (``AROUND(n)``).

        Ex.: ``senha AROUND(3) admin`` — os termos devem aparecer a até ``n``
        palavras de distância um do outro.
        """
        self._partes.append(f"{termo1.strip()} AROUND({int(n)}) {termo2.strip()}")
        return self

    def exact(self, frase: str) -> "DorkBuilder":
        """Correspondência exata de uma frase (``"..."``).

        Ex.: ``"acesso restrito"``.
        """
        self._partes.append(self._aspas_sempre(frase))
        return self

    def any_of(self, *termos: str) -> "DorkBuilder":
        """Alternância entre termos usando ``OR`` (agrupado em parênteses).

        Ex.: ``any_of("pdf", "doc")`` -> ``(pdf OR doc)``.
        """
        validos = [t.strip() for t in termos if t.strip()]
        if validos:
            self._partes.append("(" + " OR ".join(validos) + ")")
        return self

    def exclude(self, termo: str) -> "DorkBuilder":
        """Exclui um termo dos resultados (``-termo``). Ex.: ``-www``."""
        termo = termo.strip().lstrip("-")
        if termo:
            self._partes.append(f"-{self._aspas_se_preciso(termo)}")
        return self

    def group(self, *partes: str) -> "DorkBuilder":
        """Agrupa expressões entre parênteses ``( )``.

        Ex.: ``group('intext:cpf', 'OR', 'intext:cnpj')``
        -> ``(intext:cpf OR intext:cnpj)``.
        """
        unidos = " ".join(p.strip() for p in partes if p.strip())
        if unidos:
            self._partes.append(f"({unidos})")
        return self

    def raw(self, texto: str) -> "DorkBuilder":
        """Adiciona texto bruto à consulta, sem qualquer formatação.

        Útil para operadores não cobertos pelos métodos acima ou para curingas
        como ``*``.
        """
        if texto and texto.strip():
            self._partes.append(texto.strip())
        return self

    # ------------------------------------------------------------------ #
    # Saída
    # ------------------------------------------------------------------ #
    def build(self) -> str:
        """Monta e retorna a string final do dork (partes unidas por espaço)."""
        return " ".join(self._partes).strip()

    def to_url(self, motor: str = "google") -> str:
        """Gera a URL de busca pronta para o ``motor`` informado.

        :param motor: ``"google"``, ``"bing"`` ou ``"duckduckgo"``.
        :raises ValueError: se o motor não for suportado.
        """
        motor = motor.lower().strip()
        if motor not in MOTORES_BUSCA:
            raise ValueError(
                f"Motor de busca '{motor}' não suportado. "
                f"Opções: {', '.join(MOTORES_BUSCA)}"
            )
        consulta = self.build()
        return MOTORES_BUSCA[motor] + quote_plus(consulta)

    def reset(self) -> "DorkBuilder":
        """Limpa todas as partes acumuladas, reutilizando o mesmo objeto."""
        self._partes.clear()
        return self

    def __str__(self) -> str:  # pragma: no cover - conveniência
        return self.build()

    def __repr__(self) -> str:  # pragma: no cover - conveniência
        return f"DorkBuilder({self.build()!r})"


def dork_para_url(dork: str, motor: str = "google") -> str:
    """Converte uma string de dork pronta em URL de busca.

    Função utilitária para quando já se tem a string do dork (ex.: vinda do
    banco de dados) e se deseja apenas a URL, sem usar o :class:`DorkBuilder`.

    :param dork: a consulta de busca já montada.
    :param motor: mecanismo de busca alvo.
    :raises ValueError: se o motor não for suportado.
    """
    motor = motor.lower().strip()
    if motor not in MOTORES_BUSCA:
        raise ValueError(
            f"Motor de busca '{motor}' não suportado. "
            f"Opções: {', '.join(MOTORES_BUSCA)}"
        )
    return MOTORES_BUSCA[motor] + quote_plus(dork.strip())
