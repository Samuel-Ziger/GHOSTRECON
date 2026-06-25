#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DorkForge BR — Ferramenta de Google Hacking / Google Dorking para OSINT.

Ponto de entrada da aplicação. Reúne:
    - Banner ASCII art colorido + aviso legal.
    - Menu interativo numerado (modo padrão).
    - Modo de linha de comando via argparse (para automação).
    - Construção, geração de URL, abertura no navegador e exportação de dorks.

ARQUITETURA ÉTICA: esta ferramenta NÃO faz scraping dos resultados do Google.
Ela apenas CONSTRÓI consultas, GERA URLs e as ABRE no navegador padrão do usuário
(módulo ``webbrowser`` da stdlib), respeitando os Termos de Serviço do Google.
Para coleta automatizada de resultados, o caminho correto é a Google Custom
Search JSON API (que exige chave) — algo fora do escopo desta ferramenta.

Uso interativo:
    python dorkforge.py

Exemplos de modo CLI:
    python dorkforge.py --listar
    python dorkforge.py --categoria arquivos --alvo exemplo.com.br --abrir --delay 3
    python dorkforge.py --custom --site "*.gov.br" --filetype xls --intext "CPF" --export html
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

# --------------------------------------------------------------------------- #
# Força a saída em UTF-8 (especialmente no Windows, cujo console usa cp1252 por
# padrão e quebraria ao imprimir acentos/emojis). Deve ocorrer ANTES do colorama
# embrulhar os streams. errors='replace' evita qualquer UnicodeEncodeError.
# --------------------------------------------------------------------------- #
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        # Streams sem reconfigure (Python < 3.7 ou já redirecionados) seguem como estão.
        pass

# --------------------------------------------------------------------------- #
# Importação resiliente do colorama: se não estiver instalado, a ferramenta
# continua funcionando, apenas sem cores (degradação graciosa).
# --------------------------------------------------------------------------- #
try:
    from colorama import Fore, Style
    from colorama import init as _colorama_init

    _colorama_init(autoreset=True)
    _CORES_ATIVAS = True
except ImportError:  # pragma: no cover - caminho de fallback
    class _SemCor:
        """Substituto de Fore/Style quando o colorama não está disponível."""

        def __getattr__(self, _nome: str) -> str:
            return ""

    Fore = Style = _SemCor()  # type: ignore[assignment]
    _CORES_ATIVAS = False

# Importa o núcleo da ferramenta.
from core.database import Categoria, DorkDatabase
from core.exporter import DISCLAIMER, Exporter, ItemExportacao
from core.launcher import DorkLauncher
from core.operators import MOTORES_BUSCA, DorkBuilder

# --------------------------------------------------------------------------- #
# Constantes e caminhos (resolvidos relativamente a este arquivo, para que a
# ferramenta funcione independentemente do diretório de trabalho atual).
# --------------------------------------------------------------------------- #
VERSAO = "1.0.0"
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DORKS_BR = DATA_DIR / "dorks_br.json"
OUTPUT_DIR = BASE_DIR / "output"
CONFIG_PATH = BASE_DIR / "config.json"
LOG_PATH = BASE_DIR / "dorkforge.log"

CONFIG_PADRAO = {
    "delay": 2.5,
    "motor": "google",
    "max_abas": 10,
    "disclaimer_aceito": False,
}

BANNER = r"""
    ____             _    ______                       ____  ____
   / __ \____  _____| | _/ ____/___  _________ ____   / __ )/ __ \
  / / / / __ \/ ___/| |/ / /_  / __ \/ ___/ __ `/ _ \ / __  / /_/ /
 / /_/ / /_/ / /    |   / __/ / /_/ / /  / /_/ /  __// /_/ / _, _/
/_____/\____/_/     |_|_/_/    \____/_/   \__, /\___//_____/_/ |_|
                                         /____/
"""


# --------------------------------------------------------------------------- #
# Utilitários de saída colorida
# --------------------------------------------------------------------------- #
def c_titulo(texto: str) -> str:
    """Formata um título em destaque (ciano/negrito)."""
    return f"{Style.BRIGHT}{Fore.CYAN}{texto}{Style.RESET_ALL}"


def c_ok(texto: str) -> str:
    """Mensagem de sucesso (verde)."""
    return f"{Fore.GREEN}{texto}{Style.RESET_ALL}"


def c_erro(texto: str) -> str:
    """Mensagem de erro (vermelho)."""
    return f"{Fore.RED}{texto}{Style.RESET_ALL}"


def c_aviso(texto: str) -> str:
    """Mensagem de aviso (amarelo)."""
    return f"{Fore.YELLOW}{texto}{Style.RESET_ALL}"


def c_info(texto: str) -> str:
    """Mensagem informativa (ciano)."""
    return f"{Fore.CYAN}{texto}{Style.RESET_ALL}"


def c_destaque(texto: str) -> str:
    """Texto em negrito branco."""
    return f"{Style.BRIGHT}{texto}{Style.RESET_ALL}"


# --------------------------------------------------------------------------- #
# Configuração de logging
# --------------------------------------------------------------------------- #
def configurar_logging() -> logging.Logger:
    """Configura o logger que grava as operações em ``dorkforge.log``."""
    logger = logging.getLogger("dorkforge")
    if logger.handlers:  # evita handlers duplicados em reentradas
        return logger
    logger.setLevel(logging.INFO)
    try:
        handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        )
        logger.addHandler(handler)
    except OSError:
        # Se não for possível escrever o log (ex.: sistema só-leitura), seguimos
        # sem logging em arquivo em vez de quebrar a ferramenta.
        logger.addHandler(logging.NullHandler())
    return logger


# --------------------------------------------------------------------------- #
# Aplicação principal
# --------------------------------------------------------------------------- #
class DorkForgeApp:
    """Orquestra a aplicação: estado, menu interativo e ações."""

    def __init__(self) -> None:
        """Inicializa o banco de dorks, o lançador, a config e o logger."""
        self.logger = configurar_logging()
        self.config = self._carregar_config()
        self.db = self._inicializar_banco()
        self.launcher = DorkLauncher(
            motor=self.config["motor"],
            delay=self.config["delay"],
            max_abas=self.config["max_abas"],
        )
        self.alvo: str = ""
        # Conjunto de trabalho: dorks selecionados na sessão atual.
        self.itens: List[ItemExportacao] = []

    # ------------------------------------------------------------------ #
    # Inicialização auxiliar
    # ------------------------------------------------------------------ #
    def _inicializar_banco(self) -> DorkDatabase:
        """Cria o banco de dorks, carregando o módulo BR se o JSON existir."""
        if DORKS_BR.exists():
            try:
                return DorkDatabase(caminho_dados=DORKS_BR)
            except (FileNotFoundError, ValueError) as exc:
                print(c_aviso(f"Aviso: falha ao carregar dorks BR ({exc})."))
                self.logger.warning("Falha ao carregar dorks BR: %s", exc)
        else:
            print(c_aviso(f"Aviso: {DORKS_BR} não encontrado. Módulo BR desativado."))
        return DorkDatabase()

    def _carregar_config(self) -> dict:
        """Carrega a configuração persistida ou retorna os padrões."""
        config = dict(CONFIG_PADRAO)
        if CONFIG_PATH.exists():
            try:
                salvo = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
                config.update({k: salvo[k] for k in CONFIG_PADRAO if k in salvo})
            except (json.JSONDecodeError, OSError):
                pass  # configuração corrompida -> usa padrões
        return config

    def _salvar_config(self) -> None:
        """Persiste a configuração atual em ``config.json``."""
        try:
            CONFIG_PATH.write_text(
                json.dumps(self.config, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            self.logger.warning("Não foi possível salvar config: %s", exc)

    # ------------------------------------------------------------------ #
    # Alvo e geração de itens
    # ------------------------------------------------------------------ #
    def _aplicar_alvo(self, dork: str) -> str:
        """Combina o alvo definido (se houver) com a string do dork.

        - Se o dork contém o placeholder ``exemplo.com.br``, substitui pelo alvo.
        - Senão, se o dork não tem operador ``site:``, acrescenta ``site:<alvo>``.
        """
        if not self.alvo:
            return dork
        alvo = self.alvo.strip()
        if "exemplo.com.br" in dork:
            return dork.replace("exemplo.com.br", alvo)
        if "site:" not in dork:
            return f"site:{alvo} {dork}"
        return dork

    def _novo_item(self, categoria: str, titulo: str, dork: str) -> ItemExportacao:
        """Cria um :class:`ItemExportacao` com a URL já gerada e o alvo aplicado."""
        dork_final = self._aplicar_alvo(dork)
        url = self.launcher.gerar_url(dork_final)
        return ItemExportacao(
            categoria=categoria, titulo=titulo, dork=dork_final, url=url
        )

    def adicionar_categoria(self, categoria: Categoria) -> int:
        """Adiciona todos os dorks de uma categoria ao conjunto de trabalho.

        :returns: quantidade de dorks adicionados.
        """
        for dork in categoria.dorks:
            self.itens.append(
                self._novo_item(categoria.nome, dork.titulo, dork.dork)
            )
        self.logger.info(
            "Categoria '%s' adicionada (%d dorks).", categoria.nome, len(categoria)
        )
        return len(categoria)

    # ------------------------------------------------------------------ #
    # Disclaimer
    # ------------------------------------------------------------------ #
    def exibir_banner(self) -> None:
        """Imprime o banner ASCII e o resumo do aviso legal."""
        print(f"{Fore.RED}{Style.BRIGHT}{BANNER}{Style.RESET_ALL}")
        print(c_info(f"  DorkForge BR v{VERSAO} — Google Hacking para OSINT autorizado"))
        print(c_aviso("  Uso exclusivo para fins educacionais e testes AUTORIZADOS.\n"))

    def exibir_disclaimer_completo(self) -> None:
        """Imprime o aviso legal completo."""
        print(c_erro("=" * 72))
        print(c_erro("  ⚖️  AVISO LEGAL"))
        print(c_erro("=" * 72))
        print(c_aviso(f"  {DISCLAIMER}"))
        print(c_aviso(
            "\n  Use APENAS em alvos que você possui ou tem permissão expressa "
            "para testar."
        ))
        print(c_erro("=" * 72))

    def garantir_aceite(self, modo_cli: bool, aceito_flag: bool) -> bool:
        """Garante que o usuário tenha aceitado o aviso legal ao menos uma vez.

        :param modo_cli: ``True`` se a chamada veio do modo de linha de comando.
        :param aceito_flag: ``True`` se ``--aceito-termos`` foi passado.
        :returns: ``True`` se o uso pode prosseguir.
        """
        if self.config.get("disclaimer_aceito"):
            return True

        self.exibir_disclaimer_completo()

        if aceito_flag:
            self.config["disclaimer_aceito"] = True
            self._salvar_config()
            return True

        if modo_cli:
            # No modo automatizado não há prompt: orienta o usuário.
            print(c_aviso(
                "\n  Para usar o modo CLI, confirme a leitura do aviso passando "
                "a flag --aceito-termos\n  (ou rode 'python dorkforge.py' uma vez "
                "no modo interativo para aceitar)."
            ))
            return False

        # Modo interativo: solicita aceite explícito.
        try:
            resposta = input(
                c_destaque("\n  Você leu e concorda em usar de forma autorizada? "
                           "(digite 'aceito'): ")
            ).strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            return False
        if resposta in ("aceito", "sim", "s", "yes", "y"):
            self.config["disclaimer_aceito"] = True
            self._salvar_config()
            print(c_ok("\n  Termos aceitos. Bom reconhecimento — e seja ético!\n"))
            return True
        print(c_erro("\n  Termos não aceitos. Encerrando."))
        return False

    # ================================================================== #
    # MODO INTERATIVO
    # ================================================================== #
    def _ler(self, prompt: str) -> str:
        """Lê entrada do usuário tratando Ctrl+C / EOF de forma graciosa."""
        try:
            return input(prompt).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return ""

    def loop_interativo(self) -> None:
        """Executa o laço principal do menu interativo."""
        while True:
            self._imprimir_menu()
            opcao = self._ler(c_destaque("\n  Escolha uma opção: "))
            print()
            try:
                if opcao == "1":
                    self._acao_listar_categorias()
                elif opcao == "2":
                    self._acao_gerar_categoria()
                elif opcao == "3":
                    self._acao_construir_custom()
                elif opcao == "4":
                    self._acao_definir_alvo()
                elif opcao == "5":
                    self._acao_abrir_navegador()
                elif opcao == "6":
                    self._acao_exportar()
                elif opcao == "7":
                    self._acao_carregar_lista()
                elif opcao == "8":
                    self._acao_configuracoes()
                elif opcao == "9":
                    self._acao_buscar()
                elif opcao == "10":
                    self._acao_ver_selecao()
                elif opcao == "0":
                    self._acao_sair()
                    break
                else:
                    print(c_aviso("  Opção inválida. Tente novamente."))
            except Exception as exc:  # noqa: BLE001 - blindagem do menu
                print(c_erro(f"  Erro inesperado: {exc}"))
                self.logger.exception("Erro na opção %s", opcao)
            self._ler(c_info("\n  [Enter] para continuar..."))

    def _imprimir_menu(self) -> None:
        """Imprime o cabeçalho de estado e o menu numerado."""
        alvo = self.alvo or "(nenhum)"
        print(c_titulo("\n" + "─" * 50))
        print(c_titulo("  MENU PRINCIPAL"))
        print(c_titulo("─" * 50))
        print(
            f"  Alvo: {c_ok(alvo)}  |  Motor: {c_ok(self.config['motor'])}  |  "
            f"Selecionados: {c_ok(str(len(self.itens)))}"
        )
        print()
        print("  [1] Listar categorias de dorks")
        print("  [2] Gerar dorks de uma categoria")
        print("  [3] Construir dork customizado")
        print("  [4] Definir alvo (site/domínio)")
        print("  [5] Abrir dorks no navegador")
        print("  [6] Exportar resultados (TXT/JSON/CSV/HTML)")
        print("  [7] Carregar lista customizada (JSON)")
        print("  [8] Configurações (delay, motor de busca)")
        print("  [9] Buscar dorks por palavra-chave")
        print("  [10] Ver / limpar seleção atual")
        print("  [0] Sair")

    # --- Ações do menu ------------------------------------------------- #
    def _acao_listar_categorias(self) -> None:
        """Opção [1]: lista todas as categorias com índice e contagem."""
        print(c_titulo(f"  CATEGORIAS DISPONÍVEIS ({len(self.db.categorias)})\n"))
        for i, cat in enumerate(self.db.categorias, start=1):
            print(f"  {c_destaque(f'[{i:>2}]')} {c_info(cat.nome)} "
                  f"{c_aviso(f'({len(cat)} dorks)')}")
            print(f"       {cat.descricao}")
        print(c_ok(f"\n  Total de dorks no banco: {self.db.total_dorks()}"))

    def _acao_gerar_categoria(self) -> None:
        """Opção [2]: adiciona os dorks de uma categoria ao conjunto de trabalho."""
        self._acao_listar_categorias()
        escolha = self._ler(c_destaque("\n  Número (ou nome) da categoria: "))
        if not escolha:
            return
        categoria = None
        if escolha.isdigit():
            categoria = self.db.obter_categoria_por_indice(int(escolha))
        if categoria is None:
            categoria = self.db.obter_categoria(escolha)
        if categoria is None:
            print(c_erro("  Categoria não encontrada."))
            return
        qtd = self.adicionar_categoria(categoria)
        print(c_ok(f"  {qtd} dorks de '{categoria.nome}' adicionados à seleção."))
        if self.alvo:
            print(c_info(f"  (alvo '{self.alvo}' aplicado aos dorks)"))

    def _acao_construir_custom(self) -> None:
        """Opção [3]: monta um dork customizado interativamente via DorkBuilder."""
        print(c_titulo("  CONSTRUTOR DE DORK CUSTOMIZADO"))
        print(c_info("  Deixe em branco para pular cada operador.\n"))
        b = DorkBuilder()

        campos = [
            ("site (ex.: *.gov.br)", b.site),
            ("inurl (ex.: admin)", b.inurl),
            ("intitle (ex.: index of)", b.intitle),
            ("intext (ex.: senha)", b.intext),
            ("filetype (ex.: pdf)", b.filetype),
            ('frase exata (entre o texto, ex.: acesso restrito)', b.exact),
            ("excluir termo (-) (ex.: www)", b.exclude),
        ]
        for rotulo, metodo in campos:
            valor = self._ler(f"  {rotulo}: ")
            if valor:
                metodo(valor)

        # Operador livre, para casos avançados (AROUND, OR, curingas etc.).
        livre = self._ler("  operador/termo livre (opcional): ")
        if livre:
            b.raw(livre)

        dork = b.build()
        if not dork:
            print(c_aviso("  Nenhum operador informado. Dork vazio descartado."))
            return

        item = self._novo_item("Customizado", "Dork customizado", dork)
        self.itens.append(item)
        print(c_ok(f"\n  Dork criado: {c_destaque(item.dork)}"))
        print(c_info(f"  URL: {item.url}"))
        self.logger.info("Dork customizado criado: %s", item.dork)

    def _acao_definir_alvo(self) -> None:
        """Opção [4]: define (ou limpa) o alvo aplicado aos dorks."""
        print(c_info(f"  Alvo atual: {self.alvo or '(nenhum)'}"))
        novo = self._ler(c_destaque("  Novo alvo (domínio) ou Enter p/ limpar: "))
        self.alvo = novo
        if novo:
            print(c_ok(f"  Alvo definido: {novo}"))
        else:
            print(c_aviso("  Alvo removido."))
        self.logger.info("Alvo definido: %s", self.alvo or "(nenhum)")

    def _acao_abrir_navegador(self) -> None:
        """Opção [5]: abre os dorks selecionados no navegador padrão."""
        if not self.itens:
            print(c_aviso("  Nenhum dork selecionado. Use [2] ou [3] primeiro."))
            return
        total = len(self.itens)
        print(c_info(f"  {total} dork(s) serão abertos no navegador "
                     f"({self.config['motor']}), com {self.config['delay']}s de "
                     f"intervalo entre cada um."))
        confirma = self._ler(c_aviso(f"  Confirmar abertura de {total} aba(s)? (s/N): "))
        if confirma.lower() not in ("s", "sim", "y", "yes"):
            print(c_aviso("  Operação cancelada."))
            return

        def _confirmador(qtd: int) -> bool:
            r = self._ler(c_aviso(
                f"  ATENÇÃO: {qtd} abas excede o limite de "
                f"{self.config['max_abas']}. Continuar mesmo assim? (s/N): "
            ))
            return r.lower() in ("s", "sim", "y", "yes")

        def _ao_abrir(i: int, tot: int, url: str) -> None:
            status = c_ok("OK ") if url else c_erro("FALHA")
            print(f"  [{i}/{tot}] {status} {url}")

        dorks = [it.dork for it in self.itens]
        resultado = self.launcher.abrir_varios(
            dorks, confirmador=_confirmador, ao_abrir=_ao_abrir
        )
        if resultado.cancelado:
            print(c_aviso("  Abertura cancelada (limite de abas)."))
        else:
            print(c_ok(f"\n  {resultado.abertos}/{resultado.total} dorks abertos."))
        self.logger.info(
            "Abertura no navegador: %d/%d", resultado.abertos, resultado.total
        )

    def _acao_exportar(self) -> None:
        """Opção [6]: exporta a seleção em um ou mais formatos."""
        if not self.itens:
            print(c_aviso("  Nenhum dork selecionado para exportar."))
            return
        print(c_info("  Formatos: txt, json, csv, html, todos"))
        escolha = self._ler(c_destaque("  Formato(s) (separe por vírgula): ")).lower()
        if not escolha:
            return
        if "todos" in escolha:
            formatos = ["txt", "json", "csv", "html"]
        else:
            formatos = [f.strip() for f in escolha.split(",") if f.strip()]
        self._exportar_formatos(formatos)

    def _exportar_formatos(self, formatos: List[str]) -> None:
        """Executa a exportação para a lista de formatos informada."""
        exporter = Exporter(
            diretorio_saida=OUTPUT_DIR, alvo=self.alvo, motor=self.config["motor"]
        )
        for fmt in formatos:
            try:
                caminho = exporter.exportar(self.itens, fmt)
                print(c_ok(f"  [{fmt.upper()}] salvo em: {caminho}"))
                self.logger.info("Exportado %s: %s", fmt, caminho)
            except ValueError as exc:
                print(c_erro(f"  {exc}"))
            except OSError as exc:
                print(c_erro(f"  Erro ao gravar {fmt}: {exc}"))

    def _acao_carregar_lista(self) -> None:
        """Opção [7]: carrega uma lista customizada de dorks (JSON)."""
        caminho = self._ler(c_destaque("  Caminho do arquivo JSON: "))
        if not caminho:
            return
        try:
            qtd = self.db.carregar_lista_customizada(Path(caminho))
            print(c_ok(f"  {qtd} categoria(s) carregada(s) de {caminho}."))
            self.logger.info("Lista customizada carregada: %s (%d cat.)", caminho, qtd)
        except FileNotFoundError:
            print(c_erro("  Arquivo não encontrado."))
        except ValueError as exc:
            print(c_erro(f"  {exc}"))

    def _acao_configuracoes(self) -> None:
        """Opção [8]: ajusta delay, motor de busca e limite de abas."""
        print(c_titulo("  CONFIGURAÇÕES"))
        print(f"  Delay atual: {c_ok(str(self.config['delay']))}s")
        print(f"  Motor atual: {c_ok(self.config['motor'])}")
        print(f"  Máx. de abas: {c_ok(str(self.config['max_abas']))}")
        print(c_info(f"  Motores disponíveis: {', '.join(MOTORES_BUSCA)}\n"))

        novo_delay = self._ler("  Novo delay em segundos (Enter p/ manter): ")
        if novo_delay:
            try:
                self.config["delay"] = max(0.0, float(novo_delay.replace(",", ".")))
                self.launcher.delay = self.config["delay"]
            except ValueError:
                print(c_erro("  Valor de delay inválido."))

        novo_motor = self._ler("  Novo motor (Enter p/ manter): ").lower()
        if novo_motor:
            if novo_motor in MOTORES_BUSCA:
                self.config["motor"] = novo_motor
                self.launcher.definir_motor(novo_motor)
            else:
                print(c_erro(f"  Motor inválido. Opções: {', '.join(MOTORES_BUSCA)}"))

        nova_max = self._ler("  Novo limite de abas (Enter p/ manter): ")
        if nova_max:
            try:
                self.config["max_abas"] = max(1, int(nova_max))
                self.launcher.max_abas = self.config["max_abas"]
            except ValueError:
                print(c_erro("  Valor inválido."))

        self._salvar_config()
        print(c_ok("  Configurações salvas."))

    def _acao_buscar(self) -> None:
        """Opção [9]: busca dorks por palavra-chave em todo o banco."""
        termo = self._ler(c_destaque("  Palavra-chave: "))
        if not termo:
            return
        encontrados = self.db.buscar(termo)
        if not encontrados:
            print(c_aviso(f"  Nenhum dork encontrado para '{termo}'."))
            return
        print(c_ok(f"  {len(encontrados)} dork(s) encontrado(s):\n"))
        for i, d in enumerate(encontrados, start=1):
            print(f"  [{i:>2}] {c_info(d.titulo)}: {c_destaque(d.dork)}")
        add = self._ler(c_aviso(
            "\n  Adicionar à seleção? Informe números (ex.: 1,3) ou 'todos': "
        )).lower()
        if not add:
            return
        if "todos" in add:
            selecionados = encontrados
        else:
            indices = [int(x) for x in add.replace(" ", "").split(",") if x.isdigit()]
            selecionados = [encontrados[i - 1] for i in indices
                            if 1 <= i <= len(encontrados)]
        for d in selecionados:
            self.itens.append(self._novo_item("Busca", d.titulo, d.dork))
        print(c_ok(f"  {len(selecionados)} dork(s) adicionado(s) à seleção."))

    def _acao_ver_selecao(self) -> None:
        """Opção [10]: exibe e (opcionalmente) limpa a seleção atual."""
        if not self.itens:
            print(c_aviso("  Seleção vazia."))
            return
        print(c_titulo(f"  SELEÇÃO ATUAL ({len(self.itens)} dorks)\n"))
        for i, it in enumerate(self.itens, start=1):
            print(f"  [{i:>2}] {c_info(it.categoria)} — {it.titulo}")
            print(f"       {c_destaque(it.dork)}")
        limpar = self._ler(c_aviso("\n  Limpar toda a seleção? (s/N): "))
        if limpar.lower() in ("s", "sim", "y", "yes"):
            self.itens.clear()
            print(c_ok("  Seleção limpa."))

    def _acao_sair(self) -> None:
        """Opção [0]: encerra a aplicação exibindo estatísticas da sessão."""
        print(c_titulo("  ESTATÍSTICAS DA SESSÃO"))
        print(f"  Dorks selecionados: {c_ok(str(len(self.itens)))}")
        # Conta por categoria selecionada.
        por_cat: dict = {}
        for it in self.itens:
            por_cat[it.categoria] = por_cat.get(it.categoria, 0) + 1
        for cat, qtd in por_cat.items():
            print(f"    - {cat}: {qtd}")
        print(c_ok("\n  Até a próxima! Use com responsabilidade. 🔱"))
        self.logger.info("Sessão encerrada. %d dorks na seleção.", len(self.itens))


# --------------------------------------------------------------------------- #
# MODO CLI (argparse)
# --------------------------------------------------------------------------- #
def construir_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos de linha de comando."""
    parser = argparse.ArgumentParser(
        prog="dorkforge.py",
        description="DorkForge BR — gerador e lançador de Google Dorks para OSINT "
                    "autorizado.",
        epilog="Exemplos:\n"
               "  python dorkforge.py --listar\n"
               "  python dorkforge.py --categoria arquivos --alvo exemplo.com.br "
               "--abrir --delay 3\n"
               "  python dorkforge.py --custom --site \"*.gov.br\" --filetype xls "
               "--intext CPF --export html",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--versao", action="version",
                        version=f"DorkForge BR v{VERSAO}")
    parser.add_argument("--aceito-termos", action="store_true",
                        help="confirma a leitura do aviso legal (necessário no modo CLI)")

    # Ações de consulta
    parser.add_argument("--listar", action="store_true",
                        help="lista as categorias de dorks e sai")
    parser.add_argument("--buscar", metavar="TERMO",
                        help="busca dorks por palavra-chave e os adiciona à seleção")
    parser.add_argument("--categoria", metavar="NOME/Nº",
                        help="seleciona uma categoria (por nome ou índice)")

    # Construtor customizado
    parser.add_argument("--custom", action="store_true",
                        help="monta um dork customizado com as flags abaixo")
    parser.add_argument("--site", help="operador site:")
    parser.add_argument("--inurl", help="operador inurl:")
    parser.add_argument("--intitle", help="operador intitle:")
    parser.add_argument("--intext", help="operador intext:")
    parser.add_argument("--filetype", help="operador filetype:")
    parser.add_argument("--exact", metavar="FRASE", help='correspondência exata "..."')
    parser.add_argument("--exclude", metavar="TERMO", help="exclui termo (-)")

    # Alvo e execução
    parser.add_argument("--alvo", metavar="DOMINIO",
                        help="define o alvo aplicado aos dorks")
    parser.add_argument("--abrir", action="store_true",
                        help="abre os dorks gerados no navegador")
    parser.add_argument("--motor", choices=list(MOTORES_BUSCA), default=None,
                        help="mecanismo de busca (google/bing/duckduckgo)")
    parser.add_argument("--delay", type=float, default=None,
                        help="segundos entre abrir abas no navegador")
    parser.add_argument("--max-abas", type=int, default=None, dest="max_abas",
                        help="limite de abas antes de pedir confirmação")
    parser.add_argument("--export", nargs="+", metavar="FORMATO",
                        choices=["txt", "json", "csv", "html"],
                        help="exporta nos formatos indicados (txt/json/csv/html)")
    return parser


def executar_cli(app: DorkForgeApp, args: argparse.Namespace) -> int:
    """Executa as ações solicitadas no modo de linha de comando.

    :returns: código de saída (0 = sucesso).
    """
    # Aplica overrides de configuração vindos da linha de comando.
    if args.motor:
        app.config["motor"] = args.motor
        app.launcher.definir_motor(args.motor)
    if args.delay is not None:
        app.config["delay"] = max(0.0, args.delay)
        app.launcher.delay = app.config["delay"]
    if args.max_abas is not None:
        app.config["max_abas"] = max(1, args.max_abas)
        app.launcher.max_abas = app.config["max_abas"]
    if args.alvo:
        app.alvo = args.alvo

    # --listar: apenas lista e sai.
    if args.listar:
        app._acao_listar_categorias()
        return 0

    # --buscar: adiciona resultados da busca à seleção.
    if args.buscar:
        encontrados = app.db.buscar(args.buscar)
        if not encontrados:
            print(c_aviso(f"Nenhum dork encontrado para '{args.buscar}'."))
        else:
            for d in encontrados:
                app.itens.append(app._novo_item("Busca", d.titulo, d.dork))
            print(c_ok(f"{len(encontrados)} dork(s) adicionados da busca."))

    # --categoria: adiciona os dorks da categoria.
    if args.categoria:
        categoria = None
        if args.categoria.isdigit():
            categoria = app.db.obter_categoria_por_indice(int(args.categoria))
        if categoria is None:
            categoria = app.db.obter_categoria(args.categoria)
        if categoria is None:
            print(c_erro(f"Categoria '{args.categoria}' não encontrada."))
            return 1
        qtd = app.adicionar_categoria(categoria)
        print(c_ok(f"{qtd} dorks de '{categoria.nome}' adicionados."))

    # --custom: monta um dork a partir das flags.
    if args.custom:
        b = DorkBuilder()
        if args.site:
            b.site(args.site)
        if args.inurl:
            b.inurl(args.inurl)
        if args.intitle:
            b.intitle(args.intitle)
        if args.intext:
            b.intext(args.intext)
        if args.filetype:
            b.filetype(args.filetype)
        if args.exact:
            b.exact(args.exact)
        if args.exclude:
            b.exclude(args.exclude)
        dork = b.build()
        if dork:
            app.itens.append(app._novo_item("Customizado", "Dork customizado", dork))
            print(c_ok(f"Dork customizado: {dork}"))
        else:
            print(c_aviso("Nenhum operador informado para --custom."))

    # Se nada foi selecionado, não há o que abrir/exportar.
    if not app.itens:
        print(c_aviso("Nenhum dork na seleção. Use --categoria, --buscar ou --custom."))
        return 0

    # Mostra a seleção resultante.
    print(c_info(f"\nSeleção: {len(app.itens)} dork(s)."))
    for it in app.itens:
        print(f"  - {it.dork}")

    # --abrir: abre no navegador.
    if args.abrir:
        def _ao_abrir(i: int, tot: int, url: str) -> None:
            print(c_ok(f"  [{i}/{tot}] aberto: {url}") if url
                  else c_erro(f"  [{i}/{tot}] falha"))

        def _confirmador(qtd: int) -> bool:
            print(c_aviso(f"  {qtd} abas excedem o limite de {app.config['max_abas']}; "
                          "abrindo mesmo assim (modo CLI)."))
            return True

        dorks = [it.dork for it in app.itens]
        resultado = app.launcher.abrir_varios(
            dorks, confirmador=_confirmador, ao_abrir=_ao_abrir
        )
        print(c_ok(f"{resultado.abertos}/{resultado.total} dorks abertos."))

    # --export: exporta nos formatos pedidos.
    if args.export:
        app._exportar_formatos(args.export)

    return 0


# --------------------------------------------------------------------------- #
# Ponto de entrada
# --------------------------------------------------------------------------- #
def main(argv: Optional[List[str]] = None) -> int:
    """Função principal: decide entre modo interativo e modo CLI."""
    parser = construir_parser()
    args = parser.parse_args(argv)

    app = DorkForgeApp()
    app.exibir_banner()

    # Detecta se alguma ação de CLI foi solicitada.
    acao_cli = any([
        args.listar, args.buscar, args.categoria, args.custom,
        args.abrir, args.export,
    ])

    # Garante o aceite do aviso legal antes de qualquer ação.
    if not app.garantir_aceite(modo_cli=acao_cli, aceito_flag=args.aceito_termos):
        return 1

    try:
        if acao_cli:
            return executar_cli(app, args)
        # Sem ação de CLI -> modo interativo.
        app.loop_interativo()
        return 0
    except KeyboardInterrupt:
        print(c_aviso("\n\n  Interrompido pelo usuário. Saindo..."))
        return 130


if __name__ == "__main__":
    sys.exit(main())
