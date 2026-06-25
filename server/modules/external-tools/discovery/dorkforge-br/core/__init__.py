"""
Pacote ``core`` do DorkForge BR.

Expõe as classes e funções principais para uso pelo ponto de entrada
(``dorkforge.py``) e por scripts de terceiros que queiram reaproveitar a lógica.
"""

from .database import Categoria, Dork, DorkDatabase
from .exporter import DISCLAIMER, Exporter, ItemExportacao
from .launcher import DorkLauncher, ResultadoAbertura
from .operators import MOTORES_BUSCA, DorkBuilder, dork_para_url

__all__ = [
    "Categoria",
    "Dork",
    "DorkDatabase",
    "DISCLAIMER",
    "Exporter",
    "ItemExportacao",
    "DorkLauncher",
    "ResultadoAbertura",
    "MOTORES_BUSCA",
    "DorkBuilder",
    "dork_para_url",
]

__version__ = "1.0.0"
