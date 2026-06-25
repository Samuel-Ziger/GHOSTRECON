
import hashlib
import random
import sys

# Garante UTF-8 na saída do terminal (consoles Windows usam cp1252 por padrão,
# o que quebraria os emojis do banner). Seguro/no-op em terminais já UTF-8.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

from flask import Flask, jsonify, request

# ------------------------------------------------------------------------------
# Configuração do app
# ------------------------------------------------------------------------------
app = Flask(__name__)

HOST = "127.0.0.1"   # SEMPRE localhost — é um laboratório, não exponha isso.
PORT = 5000

# Quantidade de usuários falsos que vamos gerar para o laboratório.
TOTAL_USUARIOS = 50

# ------------------------------------------------------------------------------
# Geração de dados FALSOS (fictícios) e chamativos para o vídeo
# ------------------------------------------------------------------------------
# Tudo aqui é inventado de forma determinística (seed fixa) — nenhum dado real
# de pessoa real é usado. CPFs têm formato válido (dígitos verificadores certos)
# só para ficarem realistas na tela, mas pertencem a usuários FICTÍCIOS.

_PRIMEIROS_NOMES = [
    "Ana", "Bruno", "Carla", "Diego", "Eduarda", "Felipe", "Gabriela", "Heitor",
    "Isabela", "João", "Karina", "Lucas", "Mariana", "Nicolas", "Olivia", "Pedro",
    "Queila", "Rafael", "Sofia", "Thiago", "Ursula", "Vitor", "Wanessa", "Xavier",
    "Yasmin", "Zeca", "Beatriz", "Caio", "Daniela", "Enzo", "Fernanda", "Gustavo",
    "Helena", "Igor", "Júlia", "Kauã", "Larissa", "Marcelo", "Natália", "Otávio",
]

_SOBRENOMES = [
    "Silva", "Souza", "Oliveira", "Santos", "Pereira", "Lima", "Carvalho",
    "Ferreira", "Rodrigues", "Almeida", "Costa", "Gomes", "Martins", "Araújo",
    "Melo", "Barbosa", "Ribeiro", "Nascimento", "Cardoso", "Rocha", "Dias",
    "Teixeira", "Moreira", "Cavalcanti", "Monteiro",
]

_DDDS = ["11", "21", "31", "41", "47", "51", "61", "71", "81", "85"]


def _gerar_cpf_valido(rng: random.Random) -> str:
    """
    Gera um CPF FICTÍCIO com formato e dígitos verificadores válidos.

    Usa o algoritmo oficial de cálculo dos dígitos verificadores, apenas para
    que o número pareça real na tela do vídeo. NÃO corresponde a nenhuma pessoa.
    """
    n = [rng.randint(0, 9) for _ in range(9)]

    # Primeiro dígito verificador
    soma = sum((10 - i) * n[i] for i in range(9))
    d1 = (soma * 10) % 11
    d1 = 0 if d1 == 10 else d1
    n.append(d1)

    # Segundo dígito verificador
    soma = sum((11 - i) * n[i] for i in range(10))
    d2 = (soma * 10) % 11
    d2 = 0 if d2 == 10 else d2
    n.append(d2)

    return f"{n[0]}{n[1]}{n[2]}.{n[3]}{n[4]}{n[5]}.{n[6]}{n[7]}{n[8]}-{n[9]}{n[10]}"


def _gerar_usuarios(quantidade: int) -> dict:
    """
    Cria um 'banco de dados' (dicionário em memória) com usuários falsos.

    Retorna um dict no formato {id: {dados...}}. Como usamos seed fixa, os
    dados são sempre os mesmos a cada execução — ótimo para gravar e regravar
    o vídeo sem que os números mudem.
    """
    rng = random.Random(42)  # seed fixa -> dados determinísticos
    usuarios = {}

    for uid in range(1, quantidade + 1):
        nome = f"{rng.choice(_PRIMEIROS_NOMES)} {rng.choice(_SOBRENOMES)}"
        primeiro = nome.split()[0].lower()

        # Telefone fake no formato (DD) 9XXXX-XXXX
        ddd = rng.choice(_DDDS)
        telefone = f"({ddd}) 9{rng.randint(1000, 9999)}-{rng.randint(1000, 9999)}"

        # Saldos altos e chamativos para a tela (entre R$ 5 mil e R$ 250 mil)
        saldo = round(rng.uniform(5_000, 250_000), 2)

        # "Senha" fictícia + hash SHA-256 (simula um banco que guarda hash)
        senha_fake = f"{primeiro}@{rng.randint(1000, 9999)}"
        senha_hash = hashlib.sha256(senha_fake.encode("utf-8")).hexdigest()

        usuarios[uid] = {
            "id": uid,
            "nome": nome,
            "cpf": _gerar_cpf_valido(rng),
            "email": f"{primeiro}.{uid}@email-ficticio.com.br",
            "telefone": telefone,
            "saldo_conta": saldo,
            "senha_hash": senha_hash,
        }

    return usuarios


# Banco de dados em memória (não persiste nada em disco).
DB_USUARIOS = _gerar_usuarios(TOTAL_USUARIOS)

# ------------------------------------------------------------------------------
# "Sistema de login" simplificado
# ------------------------------------------------------------------------------
# Para manter o lab simples, o login apenas devolve um token associado a um ID.
# Token = "token-<id>". Em um sistema real isto seria um JWT/sessão assinada.

def _token_para_id(token: str):
    """Extrai o ID de usuário a partir de um token 'token-<id>'. None se inválido."""
    if not token:
        return None
    token = token.strip()
    if token.lower().startswith("bearer "):  # aceita 'Bearer token-1'
        token = token[7:].strip()
    if token.startswith("token-"):
        try:
            return int(token.split("-", 1)[1])
        except (ValueError, IndexError):
            return None
    return None


def _id_autenticado_da_requisicao():
    """Lê o token do header Authorization OU do cookie 'sessao' e retorna o ID."""
    auth = request.headers.get("Authorization", "")
    uid = _token_para_id(auth)
    if uid is None:
        uid = _token_para_id(request.cookies.get("sessao", ""))
    return uid


# ------------------------------------------------------------------------------
# ROTAS
# ------------------------------------------------------------------------------

@app.route("/")
def index():
    """Página inicial com instruções rápidas do laboratório."""
    return jsonify({
        "app": "IDOR Lab — Alvo Vulnerável (uso educacional)",
        "aviso": "Aplicativo PROPOSITALMENTE vulnerável. Apenas para laboratório local.",
        "total_usuarios": TOTAL_USUARIOS,
        "endpoints": {
            "login (POST)": "/api/login   body: {\"id\": 1}",
            "VULNERAVEL (GET)": "/api/usuario/<id>   <- falha IDOR proposital",
            "SEGURO (GET)": "/api/usuario-seguro/<id>   <- versão corrigida",
        },
        "dica": "Faça login como id=1 e tente ler /api/usuario/2, /api/usuario/3 ...",
    })


@app.route("/api/login", methods=["POST"])
def login():
    """
    Login simplificado de laboratório.

    Recebe JSON {"id": <n>} e devolve um token de sessão 'token-<n>'.
    Em um sistema real você enviaria usuário/senha; aqui só pegamos o ID
    para focar exclusivamente na demonstração do IDOR.
    """
    dados = request.get_json(silent=True) or {}
    uid = dados.get("id", 1)

    if uid not in DB_USUARIOS:
        return jsonify({"erro": "Usuário inexistente"}), 404

    token = f"token-{uid}"
    return jsonify({
        "mensagem": f"Login efetuado como usuário {uid}",
        "token": token,
        "como_usar": "Envie no header  Authorization: Bearer " + token,
    })


@app.route("/api/usuario/<int:id>", methods=["GET"])
def usuario_vulneravel(id: int):
    """
    >>> ENDPOINT VULNERÁVEL A IDOR (proposital) <<<

    A FALHA: este endpoint pega o <id> direto da URL e devolve os dados
    correspondentes SEM verificar se quem está pedindo é o dono daquele
    registro (ou se tem permissão). Qualquer um, logado como qualquer ID,
    consegue ler os dados de TODOS os usuários só trocando o número.

    É exatamente isso que o scanner explora.
    """
    usuario = DB_USUARIOS.get(id)
    if usuario is None:
        return jsonify({"erro": "Usuário não encontrado"}), 404

    # Devolvemos TUDO, inclusive dados sensíveis (CPF, saldo, hash de senha).
    # Nenhuma checagem de autorização -> esta é a vulnerabilidade.
    return jsonify(usuario)


@app.route("/api/usuario-seguro/<int:id>", methods=["GET"])
def usuario_seguro(id: int):
    """
    >>> ENDPOINT CORRIGIDO (a forma certa de fazer) <<<

    A CORREÇÃO: antes de devolver qualquer dado, validamos o token de sessão
    e conferimos se o usuário autenticado é o DONO do registro pedido
    (controle de autorização a nível de objeto). Se ele tentar acessar o ID
    de outra pessoa, recebe 403 Forbidden.

    Compare no vídeo: mesmo ataque, mas aqui o scanner só consegue ver o
    próprio usuário — o vazamento desaparece.
    """
    id_autenticado = _id_autenticado_da_requisicao()

    # 1) Sem token válido => não autenticado.
    if id_autenticado is None:
        return jsonify({"erro": "Não autenticado. Faça login em /api/login."}), 401

    # 2) Token válido, mas pedindo o registro de OUTRO usuário => proibido.
    if id_autenticado != id:
        return jsonify({
            "erro": "Acesso negado.",
            "motivo": "Você não tem permissão para acessar os dados deste usuário.",
        }), 403

    # 3) Tudo certo: é o próprio dono pedindo seus dados.
    usuario = DB_USUARIOS.get(id)
    if usuario is None:
        return jsonify({"erro": "Usuário não encontrado"}), 404

    # Boa prática extra: não devolver o hash de senha para o cliente.
    dados = {k: v for k, v in usuario.items() if k != "senha_hash"}
    return jsonify(dados)


# ------------------------------------------------------------------------------
# Inicialização
# ------------------------------------------------------------------------------
def _banner():
    """Imprime um pequeno banner no terminal ao subir o servidor."""
    print("=" * 70)
    print("  IDOR LAB  —  APP-ALVO VULNERÁVEL (uso EXCLUSIVO em laboratório)")
    print("=" * 70)
    print(f"  Servindo em   : http://{HOST}:{PORT}")
    print(f"  Usuários fake : {TOTAL_USUARIOS}")
    print("  Endpoint VULN : GET /api/usuario/<id>")
    print("  Endpoint OK   : GET /api/usuario-seguro/<id>")
    print("  Login         : POST /api/login   body {\"id\": 1}")
    print("-" * 70)
    print("  ⚠️  Vulnerabilidade proposital. NÃO use em produção.")
    print("=" * 70)


if __name__ == "__main__":
    _banner()
    # debug=False para não vazar stack traces e ficar mais "limpo" no vídeo.
    app.run(host=HOST, port=PORT, debug=False)
