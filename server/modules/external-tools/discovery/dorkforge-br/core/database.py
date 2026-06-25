"""
database.py — Banco de Google Dorks pré-definidos, organizado por categoria.

Este módulo concentra um catálogo curado de dorks úteis para reconhecimento
autorizado e OSINT, dividido em categorias temáticas. Também é capaz de carregar
o módulo de dorks brasileiros a partir de ``data/dorks_br.json``.

Estruturas de dados:
    - :class:`Dork`      -> um único dork (título, descrição e a string da consulta).
    - :class:`Categoria` -> um grupo nomeado de dorks.
    - :class:`DorkDatabase` -> agregador com métodos de listagem, busca e carga.

AVISO: os dorks aqui catalogados destinam-se a testes AUTORIZADOS, pesquisa de
segurança e fins educacionais. O usuário é o único responsável pelo uso.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class Dork:
    """Representa um único Google Dork catalogado."""

    titulo: str
    dork: str
    descricao: str = ""

    def como_dict(self) -> Dict[str, str]:
        """Retorna o dork como dicionário serializável."""
        return {"titulo": self.titulo, "dork": self.dork, "descricao": self.descricao}


@dataclass
class Categoria:
    """Agrupa um conjunto de dorks sob um nome e uma descrição."""

    nome: str
    descricao: str
    dorks: List[Dork] = field(default_factory=list)

    def __len__(self) -> int:  # pragma: no cover - conveniência
        return len(self.dorks)


# --------------------------------------------------------------------------- #
# Catálogo embutido de categorias e dorks (contexto geral).
# Cada categoria traz de 5 a 10 dorks representativos e reais.
# --------------------------------------------------------------------------- #
_CATALOGO: List[Categoria] = [
    Categoria(
        nome="Arquivos confidenciais expostos",
        descricao="Arquivos sensíveis (planilhas, configs, logs, dumps) indexados pelo Google.",
        dorks=[
            Dork("SQL em index of", 'intitle:"index of" "*.sql"',
                 "Listagens de diretório contendo arquivos .sql."),
            Dork("Variáveis .env com senha", 'filetype:env "DB_PASSWORD"',
                 "Arquivos .env vazando credenciais de banco de dados."),
            Dork("Logs com senha", "filetype:log intext:senha",
                 "Arquivos de log que mencionam a palavra 'senha'."),
            Dork("Backups .bak", 'filetype:bak inurl:"php"',
                 "Backups de scripts PHP com extensão .bak."),
            Dork("Configurações expostas", 'filetype:conf intext:"password"',
                 "Arquivos de configuração com senhas em texto."),
            Dork("Planilhas CSV sensíveis", 'filetype:csv intext:"senha"',
                 "Arquivos CSV contendo a palavra 'senha'."),
            Dork("Arquivos INI de configuração", 'filetype:ini intext:"password"',
                 "Arquivos .ini com credenciais."),
            Dork("Dumps JSON de configuração", 'filetype:json intext:"api_key"',
                 "Arquivos JSON expondo chaves de API."),
        ],
    ),
    Categoria(
        nome="Painéis de login e administração",
        descricao="Páginas de autenticação e painéis administrativos expostos.",
        dorks=[
            Dork("Admin + login", "inurl:admin intitle:login",
                 "Páginas de login em caminhos /admin."),
            Dork("WordPress wp-admin", "inurl:/wp-admin/",
                 "Painéis administrativos do WordPress."),
            Dork("Painel de controle PT-BR", 'intitle:"painel de controle"',
                 "Páginas com título 'painel de controle'."),
            Dork("phpMyAdmin", 'intitle:phpMyAdmin "Welcome to phpMyAdmin"',
                 "Instâncias do phpMyAdmin expostas."),
            Dork("cPanel login", "inurl:cpanel intitle:login",
                 "Páginas de login do cPanel."),
            Dork("Webmail", "inurl:webmail intitle:login",
                 "Portais de webmail expostos."),
            Dork("Painel genérico", 'inurl:painel intitle:"login"',
                 "Painéis administrativos com termo 'painel'."),
        ],
    ),
    Categoria(
        nome="Diretórios listados (directory listing)",
        descricao="Listagens de diretório abertas que expõem arquivos do servidor.",
        dorks=[
            Dork("Index of backup", 'intitle:"index of" "backup"',
                 "Diretórios de backup abertos."),
            Dork("Index of /private", 'intitle:"index of" "/private"',
                 "Pastas privadas listadas publicamente."),
            Dork("Index of /admin", 'intitle:"index of" "admin"',
                 "Diretórios administrativos expostos."),
            Dork("Index of parent directory", 'intitle:"index of" "parent directory"',
                 "Listagens clássicas do Apache."),
            Dork("Index of senhas", 'intitle:"index of" "password"',
                 "Diretórios contendo arquivos de senha."),
            Dork("Index of /uploads", 'intitle:"index of" "/uploads"',
                 "Pastas de upload listadas."),
        ],
    ),
    Categoria(
        nome="Mensagens de erro e debug",
        descricao="Páginas que vazam stack traces, erros de SQL e informações de debug.",
        dorks=[
            Dork("Erro mysql_connect", 'intext:"Warning: mysql_connect()"',
                 "Vazamento de erros de conexão MySQL em PHP."),
            Dork("Fatal error PHP", 'intext:"Fatal error" inurl:php',
                 "Páginas PHP exibindo erros fatais."),
            Dork("phpinfo()", 'intitle:"phpinfo()"',
                 "Páginas phpinfo() expostas com config do servidor."),
            Dork("SQL syntax error", 'intext:"You have an error in your SQL syntax"',
                 "Erros de sintaxe SQL revelando a estrutura do banco."),
            Dork("Stack trace", 'intext:"Stack trace:" intext:"on line"',
                 "Stack traces de exceções expostos."),
            Dork("Warning include()", 'intext:"Warning: include()"',
                 "Avisos de inclusão de arquivos em PHP."),
        ],
    ),
    Categoria(
        nome="Bancos de dados e backups expostos",
        descricao="Dumps SQL, backups e exportações de banco de dados indexados.",
        dorks=[
            Dork("Dump SQL INSERT", "filetype:sql intext:INSERT INTO",
                 "Dumps SQL contendo comandos INSERT."),
            Dork("Backup PHP .bak", 'ext:bak inurl:"php"',
                 "Arquivos PHP com backup .bak."),
            Dork("db_backup .sql", "db_backup filetype:sql",
                 "Backups de banco nomeados db_backup."),
            Dork("Dump com CREATE TABLE", 'filetype:sql "CREATE TABLE"',
                 "Esquemas de banco em arquivos .sql."),
            Dork("Backup .tar.gz", 'intitle:"index of" "backup.tar.gz"',
                 "Arquivos compactados de backup expostos."),
            Dork("MongoDB dump", 'filetype:json "mongodb" intext:"password"',
                 "Exportações de configuração do MongoDB."),
        ],
    ),
    Categoria(
        nome="Dispositivos IoT / câmeras / impressoras",
        descricao="Interfaces web de dispositivos conectados expostas à internet.",
        dorks=[
            Dork("Câmera AXIS/IP", 'inurl:"/view/index.shtml"',
                 "Câmeras IP com interface de visualização."),
            Dork("webcamXP", 'intitle:"webcamXP 5"',
                 "Servidores de câmera webcamXP."),
            Dork("Impressora HP", "inurl:hp/device/this.LCDispatcher",
                 "Interfaces web de impressoras HP."),
            Dork("Câmeras Live View", 'intitle:"Live View / - AXIS"',
                 "Câmeras AXIS com visualização ao vivo."),
            Dork("Roteador login", 'intitle:"router" intitle:"login"',
                 "Painéis de login de roteadores."),
            Dork("NAS exposto", 'intitle:"Synology" inurl:5000',
                 "Interfaces de NAS Synology."),
        ],
    ),
    Categoria(
        nome="Credenciais e senhas em texto",
        descricao="Arquivos contendo usuários e senhas em texto claro.",
        dorks=[
            Dork("TXT com password", 'filetype:txt intext:"password"',
                 "Arquivos de texto contendo senhas."),
            Dork("Planilha de e-mails", 'filetype:xls inurl:"email.xls"',
                 "Planilhas chamadas email.xls."),
            Dork("CSV com senha", 'intext:"senha" filetype:csv',
                 "Arquivos CSV com a coluna senha."),
            Dork("Credenciais em log", 'filetype:log intext:"username" intext:"password"',
                 "Logs com pares de usuário/senha."),
            Dork("Arquivo de senhas", 'filetype:txt intext:"usuario" intext:"senha"',
                 "Listas de usuários e senhas em texto."),
            Dork("Config com credenciais", 'filetype:env "API_KEY" OR "SECRET"',
                 "Arquivos .env com chaves secretas."),
        ],
    ),
    Categoria(
        nome="Documentos sensíveis / dados pessoais",
        descricao="Documentos confidenciais e arquivos com dados pessoais.",
        dorks=[
            Dork("PDF confidencial", 'filetype:pdf intext:"confidencial"',
                 "Documentos PDF marcados como confidenciais."),
            Dork("Planilha de dados pessoais", 'intext:"dados pessoais" filetype:xlsx',
                 "Planilhas contendo dados pessoais."),
            Dork("Documento interno", 'filetype:doc intext:"uso interno"',
                 "Documentos Word de uso interno."),
            Dork("Contrato em PDF", 'filetype:pdf intext:"contrato" intext:"assinatura"',
                 "Contratos assinados em PDF."),
            Dork("Relatório restrito", 'filetype:pdf intext:"acesso restrito"',
                 "Relatórios de acesso restrito."),
        ],
    ),
    Categoria(
        nome="Subdomínios e tecnologias",
        descricao="Enumeração de subdomínios e identificação de tecnologias.",
        dorks=[
            Dork("Subdomínios -www", "site:*.exemplo.com.br -www",
                 "Subdomínios de um alvo, excluindo www."),
            Dork("WordPress em alvo", "inurl:wp-content site:exemplo.com.br",
                 "Páginas WordPress de um domínio específico."),
            Dork("Ambientes de teste", 'site:*.exemplo.com.br (inurl:dev OR inurl:test OR inurl:staging)',
                 "Subdomínios de desenvolvimento/homologação."),
            Dork("Painéis em subdomínios", "site:*.exemplo.com.br inurl:admin",
                 "Painéis administrativos em subdomínios."),
            Dork("APIs expostas", "site:*.exemplo.com.br inurl:api",
                 "Endpoints de API de um alvo."),
        ],
    ),
    Categoria(
        nome="Parâmetros e paths potencialmente vulneráveis",
        descricao="URLs com parâmetros que costumam indicar pontos de injeção.",
        dorks=[
            Dork("Parâmetro id em PHP", 'inurl:"id=" inurl:".php"',
                 "Páginas PHP com parâmetro id (possível SQLi)."),
            Dork("Open redirect", 'inurl:"redirect="',
                 "Parâmetros de redirecionamento (possível open redirect)."),
            Dork("Inclusão de página", 'inurl:"?page="',
                 "Parâmetro page (possível LFI/RFI)."),
            Dork("Parâmetro file", 'inurl:"file=" inurl:".php"',
                 "Parâmetro file (possível path traversal)."),
            Dork("Parâmetro cat", 'inurl:"cat=" inurl:".php"',
                 "Parâmetro cat (possível SQLi)."),
            Dork("Parâmetro url", 'inurl:"url=" inurl:"http"',
                 "Parâmetro url (possível SSRF/open redirect)."),
        ],
    ),
]


class DorkDatabase:
    """Agrega o catálogo embutido e (opcionalmente) o módulo de dorks brasileiros.

    :param caminho_dados: caminho para o arquivo ``dorks_br.json``. Se omitido,
        o módulo BR não é carregado automaticamente.
    """

    def __init__(self, caminho_dados: Optional[Path] = None) -> None:
        """Inicializa o banco com o catálogo embutido e, se possível, o BR."""
        # Copia rasa da lista para não mutar o catálogo global.
        self._categorias: List[Categoria] = list(_CATALOGO)
        self.caminho_dados = caminho_dados
        if caminho_dados is not None:
            self.carregar_dorks_br(caminho_dados)

    # ------------------------------------------------------------------ #
    # Carga de dados externos
    # ------------------------------------------------------------------ #
    def carregar_dorks_br(self, caminho: Path) -> int:
        """Carrega as categorias brasileiras de um arquivo JSON.

        :param caminho: caminho para ``data/dorks_br.json``.
        :returns: quantidade de categorias carregadas.
        :raises FileNotFoundError: se o arquivo não existir.
        :raises ValueError: se o JSON estiver malformado.
        """
        caminho = Path(caminho)
        if not caminho.exists():
            raise FileNotFoundError(f"Arquivo de dorks BR não encontrado: {caminho}")

        try:
            dados = json.loads(caminho.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSON inválido em {caminho}: {exc}") from exc

        carregadas = 0
        for cat in dados.get("categorias", []):
            categoria = Categoria(
                nome=cat.get("nome", "Sem nome"),
                descricao=cat.get("descricao", ""),
                dorks=[
                    Dork(
                        titulo=d.get("titulo", ""),
                        dork=d.get("dork", ""),
                        descricao=d.get("descricao", ""),
                    )
                    for d in cat.get("dorks", [])
                ],
            )
            self._categorias.append(categoria)
            carregadas += 1
        return carregadas

    def carregar_lista_customizada(self, caminho: Path) -> int:
        """Carrega uma lista customizada do usuário (mesmo formato do BR).

        Permite ao usuário manter seus próprios bancos de dorks.

        :returns: quantidade de categorias adicionadas.
        """
        return self.carregar_dorks_br(caminho)

    # ------------------------------------------------------------------ #
    # Consulta
    # ------------------------------------------------------------------ #
    @property
    def categorias(self) -> List[Categoria]:
        """Lista todas as categorias disponíveis."""
        return self._categorias

    def listar_nomes_categorias(self) -> List[str]:
        """Retorna apenas os nomes das categorias."""
        return [c.nome for c in self._categorias]

    def obter_categoria(self, nome: str) -> Optional[Categoria]:
        """Busca uma categoria por nome (correspondência parcial, sem caso).

        :param nome: nome ou parte do nome da categoria.
        :returns: a primeira categoria correspondente ou ``None``.
        """
        nome_norm = nome.strip().lower()
        # Primeiro tenta correspondência exata, depois parcial.
        for cat in self._categorias:
            if cat.nome.lower() == nome_norm:
                return cat
        for cat in self._categorias:
            if nome_norm in cat.nome.lower():
                return cat
        return None

    def obter_categoria_por_indice(self, indice: int) -> Optional[Categoria]:
        """Busca uma categoria pelo índice (base 1, como exibido no menu)."""
        if 1 <= indice <= len(self._categorias):
            return self._categorias[indice - 1]
        return None

    def buscar(self, termo: str) -> List[Dork]:
        """Procura dorks cujo título, descrição ou consulta contenham ``termo``.

        :param termo: texto a procurar (sem distinção de maiúsculas/minúsculas).
        :returns: lista de dorks correspondentes.
        """
        termo_norm = termo.strip().lower()
        encontrados: List[Dork] = []
        for cat in self._categorias:
            for dork in cat.dorks:
                alvo = f"{dork.titulo} {dork.descricao} {dork.dork}".lower()
                if termo_norm in alvo:
                    encontrados.append(dork)
        return encontrados

    def todos_os_dorks(self) -> List[Dork]:
        """Retorna a lista completa de dorks de todas as categorias."""
        return [d for c in self._categorias for d in c.dorks]

    def total_dorks(self) -> int:
        """Conta o total de dorks no banco."""
        return sum(len(c.dorks) for c in self._categorias)
