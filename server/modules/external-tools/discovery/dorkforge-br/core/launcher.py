"""
launcher.py — Geração de URLs e abertura de buscas no navegador.

Este módulo é o coração da arquitetura ética da ferramenta. Ele NÃO faz scraping
dos resultados do Google. Em vez disso, ele:

    1. Constrói a URL de busca a partir de uma string de dork.
    2. Abre essa URL no NAVEGADOR PADRÃO do usuário (módulo ``webbrowser`` da
       biblioteca padrão), respeitando integralmente os Termos de Serviço.

Para abertura em lote, há controle de rate limiting (delay entre abas), limite
máximo de abas e confirmação explícita — evitando travar o sistema e abrir um
número abusivo de abas.

NOTA TÉCNICA: caso o usuário deseje coleta automatizada de resultados, o caminho
correto e legal é a Google Custom Search JSON API (que exige chave de API). Isso
está FORA do escopo desta ferramenta por decisão de projeto.
"""

from __future__ import annotations

import time
import webbrowser
from dataclasses import dataclass
from typing import Callable, List, Optional

from .operators import MOTORES_BUSCA, dork_para_url


@dataclass
class ResultadoAbertura:
    """Resumo de uma operação de abertura em lote no navegador."""

    abertos: int
    total: int
    cancelado: bool = False


class DorkLauncher:
    """Gera URLs de busca e abre dorks no navegador padrão com rate limiting.

    :param motor: mecanismo de busca padrão (``google``/``bing``/``duckduckgo``).
    :param delay: segundos de espera entre a abertura de abas (padrão 2.5s).
    :param max_abas: limite de abas abertas sem confirmação extra (padrão 10).
    """

    def __init__(
        self,
        motor: str = "google",
        delay: float = 2.5,
        max_abas: int = 10,
    ) -> None:
        """Inicializa o lançador validando o motor de busca informado."""
        self.definir_motor(motor)
        self.delay = max(0.0, float(delay))
        self.max_abas = max(1, int(max_abas))

    # ------------------------------------------------------------------ #
    # Configuração
    # ------------------------------------------------------------------ #
    def definir_motor(self, motor: str) -> None:
        """Define o mecanismo de busca, validando-o.

        :raises ValueError: se o motor não for suportado.
        """
        motor = motor.lower().strip()
        if motor not in MOTORES_BUSCA:
            raise ValueError(
                f"Motor '{motor}' inválido. Opções: {', '.join(MOTORES_BUSCA)}"
            )
        self.motor = motor

    # ------------------------------------------------------------------ #
    # Geração de URL
    # ------------------------------------------------------------------ #
    def gerar_url(self, dork: str, motor: Optional[str] = None) -> str:
        """Gera a URL de busca para um dork, sem abri-lo.

        :param dork: a string da consulta já montada.
        :param motor: sobrescreve o motor padrão, se informado.
        """
        return dork_para_url(dork, motor or self.motor)

    # ------------------------------------------------------------------ #
    # Abertura no navegador
    # ------------------------------------------------------------------ #
    def abrir_dork(self, dork: str, motor: Optional[str] = None) -> str:
        """Abre um único dork no navegador padrão e retorna a URL aberta.

        :raises RuntimeError: se o navegador não puder ser aberto.
        """
        url = self.gerar_url(dork, motor)
        try:
            aberto = webbrowser.open(url, new=2)  # new=2 -> nova aba, se possível
        except Exception as exc:  # noqa: BLE001 - queremos uma mensagem amigável
            raise RuntimeError(f"Falha ao abrir o navegador: {exc}") from exc
        if not aberto:
            raise RuntimeError(
                "Não foi possível abrir o navegador padrão. "
                "Verifique se há um navegador configurado no sistema."
            )
        return url

    def abrir_varios(
        self,
        dorks: List[str],
        motor: Optional[str] = None,
        confirmador: Optional[Callable[[int], bool]] = None,
        ao_abrir: Optional[Callable[[int, int, str], None]] = None,
    ) -> ResultadoAbertura:
        """Abre uma lista de dorks no navegador, com delay entre cada um.

        Aplica rate limiting (``self.delay``) entre as aberturas e, se a lista
        exceder ``self.max_abas``, solicita confirmação por meio de
        ``confirmador``.

        :param dorks: lista de strings de dorks a abrir.
        :param motor: sobrescreve o motor padrão, se informado.
        :param confirmador: função que recebe a quantidade e retorna ``True``
            para prosseguir. Se ``None`` e a quantidade exceder o limite, a
            operação é cancelada por segurança.
        :param ao_abrir: callback opcional ``(indice, total, url)`` chamado a
            cada abertura — útil para feedback visual na CLI.
        :returns: :class:`ResultadoAbertura` com o resumo da operação.
        """
        dorks_validos = [d for d in dorks if d and d.strip()]
        total = len(dorks_validos)
        if total == 0:
            return ResultadoAbertura(abertos=0, total=0)

        # Confirmação obrigatória quando a quantidade ultrapassa o limite seguro.
        if total > self.max_abas:
            permitido = confirmador(total) if confirmador else False
            if not permitido:
                return ResultadoAbertura(abertos=0, total=total, cancelado=True)

        abertos = 0
        for i, dork in enumerate(dorks_validos, start=1):
            try:
                url = self.abrir_dork(dork, motor)
                abertos += 1
                if ao_abrir:
                    ao_abrir(i, total, url)
            except RuntimeError:
                # Falha em uma aba não deve interromper o restante do lote.
                if ao_abrir:
                    ao_abrir(i, total, "")
            # Aplica o delay entre aberturas, exceto após a última.
            if i < total and self.delay > 0:
                time.sleep(self.delay)

        return ResultadoAbertura(abertos=abertos, total=total)
