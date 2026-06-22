#!/usr/bin/env bash
# PoC — criar usuário Auth + Firestore users/{uid} com role ADMIN (uso interno)
# Uso: ./poc-criar-admin.sh "seu+poc@email.com" 'SenhaForte!2026'
set -euo pipefail

API_KEY="AIzaSyBlEgFftjgHDznfDiLGxTup9otxIxE6B4U"
EMAIL="${1:?Uso: $0 seu-email-de-teste@dominio.com}"
SENHA="${2:?Uso: $0 email 'SenhaForte!123'}"
NOME="PoC Admin Teste"

echo "=== PoC criar ADMIN — $(date -Iseconds) ==="
echo "Email de teste: ${EMAIL}"

echo -e "\n[1] SignUp Firebase Auth..."
HTTP=$(curl -s -o /tmp/poc-signup.json -w "%{http_code}" -X POST \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${API_KEY}" \
  -H "Content-Type: application/json" \
  -H "Referer: https://admin.photonow.com.br/" \
  -H "Origin: https://admin.photonow.com.br" \
  -d "{\"email\":\"${EMAIL}\",\"password\":\"${SENHA}\",\"returnSecureToken\":true}")

echo "HTTP: ${HTTP}"
if ! python3 -c "import json; d=json.load(open('/tmp/poc-signup.json')); assert 'localId' in d, d" 2>/dev/null; then
  echo "Falha no cadastro Auth. Resposta:"
  cat /tmp/poc-signup.json | python3 -m json.tool 2>/dev/null || cat /tmp/poc-signup.json
  echo ""
  echo "Alternativa: crie o usuário no Console Firebase (Authentication), copie o UID e execute o Passo 2 da seção 10.4 do relatório."
  exit 1
fi

# Não usar variável UID — no zsh é o uid numérico do Linux (ex.: 1000)
FB_UID=$(python3 -c "import json; print(json.load(open('/tmp/poc-signup.json'))['localId'])")
echo "FB_UID: ${FB_UID}"

echo -e "\n[2] Firestore users/${FB_UID} com role ADMIN..."
curl -s -X PATCH \
  "https://firestore.googleapis.com/v1/projects/photonow-app/databases/(default)/documents/users/${FB_UID}?updateMask.fieldPaths=nome&updateMask.fieldPaths=email&updateMask.fieldPaths=status&updateMask.fieldPaths=role" \
  -H "X-Goog-Api-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"fields\":{\"nome\":{\"stringValue\":\"${NOME}\"},\"email\":{\"stringValue\":\"${EMAIL}\"},\"status\":{\"stringValue\":\"ATIVO\"},\"role\":{\"arrayValue\":{\"values\":[{\"stringValue\":\"ADMIN\"}]}}}}" \
  -o /tmp/poc-firestore.json

echo -e "\n[3] Conferir documento..."
curl -s "https://firestore.googleapis.com/v1/projects/photonow-app/databases/(default)/documents/users/${FB_UID}" \
  -H "X-Goog-Api-Key: ${API_KEY}" \
| python3 -c "
import json,sys
d=json.load(sys.stdin)
if 'error' in d:
    print('ERRO:', d['error']); sys.exit(1)
roles=[v['stringValue'] for v in d['fields']['role']['arrayValue']['values']]
print('roles:', roles)
print('ADMIN presente:', 'ADMIN' in roles)
"

echo -e "\n=== Próximo passo ==="
echo "Login: https://admin.photonow.com.br/login"
echo "  Email: ${EMAIL}"
echo "  Senha: (a que você passou no argumento)"
echo ""
echo "Limpeza (após o teste):"
echo "  curl -s -X DELETE \"https://firestore.googleapis.com/v1/projects/photonow-app/databases/(default)/documents/users/${FB_UID}\" -H \"X-Goog-Api-Key: ${API_KEY}\""
echo "  Console Firebase → Authentication → apagar usuário ${EMAIL}"
