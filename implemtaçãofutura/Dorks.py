#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GERADOR DE DORKS PARA SQL INJECTION - ULTRA MAX
================================================
Script educacional para geração de dorks de busca do Google
com foco em parâmetros e mensagens de erro típicas de SQL Injection.
Utilize apenas em sistemas com autorização explícita do proprietário.
"""

import argparse
import random
import sys
from itertools import product

# ============================================================
# LISTAS DE ERROS, PARÂMETROS E PADRÕES
# ============================================================

# Mensagens genéricas de erro SQL
GENERIC_SQL_ERRORS = [
    '"You have an error in your SQL syntax"',
    '"Warning: mysql_query()"',
    '"Warning: mysql_fetch_assoc()"',
    '"Warning: mysql_num_rows()"',
    '"supplied argument is not a valid MySQL result"',
    '"SQL syntax" "MySQL"',
    '"MySQL server" "error"',
    '"Microsoft OLE DB Provider for ODBC Drivers"',
    '"Unclosed quotation mark"',
    '"SQL query failed"',
    '"PostgreSQL query failed"',
    '"Invalid query" "ODBC"',
    '"DB2 SQL error"',
    '"Oracle error"',
    '"SQLITE_ERROR"',
    '"syntax error" "in your SQL"',
    '"Call to a member function" "on a non-object"',
    '"Fatal error: Uncaught Error: Call to a member function"',
    '"Division by zero" "in" ".php"',  # as vezes erro de SQL mal tratado
    '"Warning: pg_query()"',
    '"Warning: mssql_query()"',
    '"Warning: odbc_exec()"',
    '"SQL command not properly ended"',
    '"PLS-00306"',  # Oracle
    '"ORA-00933"',   # Oracle
    '"Incorrect syntax near"',
    '"[SQL Server]" "error"',
    '"mysql_fetch_array()"',
    '"mysql_result()"',
    '"mysql_db_query()"',
    '"mysql_query()" "Resource id"',
    '"supplied argument is not a valid MySQL-Link"',
    '"mysql_connect()" "Access denied"',  # pode indicar credenciais expostas
]

# Erros específicos por SGBD
DB_SPECIFIC_ERRORS = {
    'MySQL': [
        '"You have an error in your SQL syntax"',
        '"mysql_fetch"',
        '"mysql_query" "error"',
        '"The MySQL server is running with the --secure-file-priv"',
    ],
    'MSSQL': [
        '"Microsoft OLE DB Provider for ODBC Drivers error"',
        '"[Microsoft][ODBC SQL Server Driver]"',
        '"Unclosed quotation mark before the character string"',
        '"Incorrect syntax near"',
        '"Procedure or function" "expects parameter"',
    ],
    'PostgreSQL': [
        '"PostgreSQL query failed:"',
        '"Warning: pg_connect()"',
        '"pg_query()" "Warning"',
        '"ERROR:  syntax error at or near"',
    ],
    'Oracle': [
        '"ORA-00933: SQL command not properly ended"',
        '"ORA-01756: quoted string not properly terminated"',
        '"PLS-00306: wrong number or types of arguments"',
        '"ORA-01722: invalid number"',
    ],
    'SQLite': [
        '"SQLITE_ERROR"',
        '"Warning: sqlite_query()"',
        '"near \"*\": syntax error"',
    ],
}

# Parâmetros comuns em URLs suscetíveis
VULN_PARAMETERS = [
    'id', 'page', 'cat', 'category', 'product', 'prod', 'news', 'article',
    'content', 'view', 'file', 'download', 'redirect', 'url', 'link',
    'user', 'login', 'admin', 'profile', 'member', 'search', 'keyword',
    'query', 'sort', 'order', 'type', 'mode', 'lang', 'session',
    'pid', 'cid', 'uid', 'nid', 'tid', 'iid', 'id2', 'id_product',
    'id_cat', 'id_news', 'num', 'code', 'ref', 'item', 'detail',
]

# Extensões de arquivos dinâmicos
DYNAMIC_EXTENSIONS = ['php', 'asp', 'aspx', 'jsp', 'cfm', 'cgi', 'pl']

# Padrões de URL e título
URL_PATTERNS = [
    'inurl:"/index.php?id="',
    'inurl:"/product.php?pid="',
    'inurl:"/news.php?id="',
    'inurl:"/article.php?id="',
    'inurl:"/view.php?id="',
    'inurl:"/download.php?file="',
    'inurl:"/login.php?user="',
    'inurl:"/admin/login.php?username="',
    'inurl:"/shop.php?cat="',
    'inurl:"/category.php?cid="',
    'inurl:"/page.php?page="',
    'inurl:"/detail.php?id="',
    'inurl:"/profile.php?uid="',
    'inurl:"/modules.php?name="',
    'inurl:"/search.php?query="',
    'intitle:"Admin Login" inurl:".php?login="',
    'intitle:"phpMyAdmin" intext:"Welcome to"',  # não é SQLi, mas painel exposto
    'inurl:"/wp-content/plugins/" "id="',  # WordPress comum
    'inurl:"/index.php?option=com_"',  # Joomla
    'inurl:"/showthread.php?t="',      # vBulletin
    'inurl:"/modules.php?name=Forums&file=viewtopic&t="',
    'inurl:"/index.php?route=product/product&product_id="',  # OpenCart
]

# ============================================================
# FUNÇÕES DE GERAÇÃO
# ============================================================

def generate_error_dorks():
    """Gera dorks apenas com mensagens de erro."""
    dorks = []
    for err in GENERIC_SQL_ERRORS:
        dorks.append(err)
    for db, errors in DB_SPECIFIC_ERRORS.items():
        for err in errors:
            dorks.append(err)
    return dorks

def generate_parameter_dorks():
    """Combina extensões dinâmicas com parâmetros vulneráveis."""
    dorks = []
    for ext in DYNAMIC_EXTENSIONS:
        for param in VULN_PARAMETERS:
            # Formato: inurl:".php?id="
            dorks.append(f'inurl:".{ext}?{param}="')
            # Versão com dois parâmetros (ex: .php?cat= &id=)
            if param != VULN_PARAMETERS[0]:
                dorks.append(f'inurl:".{ext}?{VULN_PARAMETERS[0]}=&{param}="')
    return dorks

def generate_combined_dorks(limit=None):
    """Gera dorks complexos combinando múltiplos fatores."""
    dorks = set()
    # Combina erro com parâmetro
    for err in random.sample(GENERIC_SQL_ERRORS, min(15, len(GENERIC_SQL_ERRORS))):
        for param in random.sample(VULN_PARAMETERS, 5):
            dorks.add(f'inurl:"{param}=" {err}')
    # Combina extensão, parâmetro e erro
    for ext in random.sample(DYNAMIC_EXTENSIONS, 3):
        for param in random.sample(VULN_PARAMETERS, 4):
            dorks.add(f'inurl:".{ext}?{param}=" "{GENERIC_SQL_ERRORS[0]}"')
    # Adiciona padrões fixos de URL
    for pat in URL_PATTERNS:
        dorks.add(pat)
    # Combina site: com erros (exemplo de domínio genérico)
    # Apenas demonstração – não é ético fazer em massa sem autorização
    # dorks.add('site:gov.br "You have an error in your SQL syntax"')
    
    dorks = list(dorks)
    if limit and limit < len(dorks):
        dorks = random.sample(dorks, limit)
    return sorted(dorks)

def generate_all(limit=None, categories='all'):
    """Retorna todos os dorks conforme categoria, com limite opcional."""
    all_dorks = []
    if categories in ('all', 'errors'):
        all_dorks.extend(generate_error_dorks())
    if categories in ('all', 'parameters'):
        all_dorks.extend(generate_parameter_dorks())
    if categories in ('all', 'combined'):
        all_dorks.extend(generate_combined_dorks())
    
    # Remove duplicatas mantendo ordem
    unique = list(dict.fromkeys(all_dorks))
    if limit and limit < len(unique):
        unique = random.sample(unique, limit)
    return unique

# ============================================================
# INTERFACE DE LINHA DE COMANDO
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='Gerador Ultra Max de Dorks para SQL Injection no Google.',
        epilog='Use apenas em ambientes autorizados. O autor não se responsabiliza por uso indevido.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-o', '--output', metavar='ARQUIVO',
                        help='Salva os dorks em um arquivo de texto')
    parser.add_argument('-c', '--category', choices=['all', 'errors', 'parameters', 'combined'],
                        default='all', help='Categoria de dorks (padrão: all)')
    parser.add_argument('-n', '--number', type=int, default=0,
                        help='Número máximo de dorks a gerar (0 = todos)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Exibe estatísticas da geração')
    
    args = parser.parse_args()
    
    limit = args.number if args.number > 0 else None
    dorks = generate_all(limit=limit, categories=args.category)
    
    output_lines = []
    header = f"# GERADOR ULTRA MAX - DORKS SQL INJECTION\n# Categoria: {args.category}\n# Total: {len(dorks)}\n\n"
    output_lines.append(header)
    
    for i, dork in enumerate(dorks, 1):
        output_lines.append(dork)
    
    full_output = '\n'.join(output_lines)
    
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(full_output)
        print(f"[+] {len(dorks)} dorks salvos em '{args.output}'")
    else:
        print(full_output)
    
    if args.verbose:
        print(f"\n[INFO] Total de dorks gerados: {len(dorks)}")
        cat_counts = {}
        if args.category == 'all':
            cat_counts = {
                'errors': len(generate_error_dorks()),
                'parameters': len(generate_parameter_dorks()),
                'combined': len(generate_combined_dorks())
            }
            print(f"[INFO] Por categoria: {cat_counts}")

if __name__ == '__main__':
    main()