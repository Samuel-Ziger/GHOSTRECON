# Low-Code Hunt — Checklist rápido

Checklist operacional para apps construídos com plataformas low-code/no-code (Bubble, Webflow, OutSystems, Mendix, Appsmith e similares).

Use junto com:

```bash
ghostrecon run --target alvo.tld --playbook lowcode-hunt --output lowcode.json
```

## 1) Broken Access Control / IDOR (prioridade máxima)

- Comparar respostas com e sem autenticação em endpoints de API.
- Tentar troca de IDs em rotas e parâmetros (`/user/123` -> `/user/124`).
- Verificar métodos mutáveis (`PUT`, `PATCH`, `DELETE`) em recursos sensíveis.

Sinais fortes:

- `200/2xx` sem auth em endpoint privado.
- Mudança de status/body ao variar ID de outro usuário.
- Resposta mutável bem-sucedida fora de escopo da conta.

## 2) Exposição de APIs e endpoints internos

- Procurar OpenAPI/Swagger/GraphQL expostos.
- Revisar endpoints históricos (`wayback`, `common_crawl`).
- Conferir over-fetching (resposta com campos sensíveis não necessários).

## 3) Credenciais no frontend

- Buscar tokens/chaves no JS bundle, HTML e assets.
- Correlacionar com endpoints onde o token concede acesso real.
- Confirmar se segredo é de produção ou apenas chave pública.

## 4) Auth/sessão frágil

- Testar rotas sem `Authorization`.
- Verificar token/JWT sem expiração razoável ou claims suspeitas.
- Observar mudanças de sessão/cookie após payloads de login anômalos.

## 5) CORS e misconfig

- Testar `Origin` arbitrária e observar `Access-Control-Allow-Origin` + `Allow-Credentials`.
- Checar headers de segurança e arquivos expostos (`.env`, source maps, configs).

## 6) Injection em conectores/workflows

- Aplicar payloads controlados em campos que alimentam integrações.
- Medir diff de resposta baseline vs payload mutado.
- Escalar para `sqlmap` apenas quando houver indício técnico consistente.

## Mapeamento rápido de risco

- **Critical**: auth bypass, IDOR com dados de terceiros, escrita sem autorização, segredo sensível ativo.
- **High**: leitura de dados privados, método mutável aberto, CORS perigoso com credenciais.
- **Medium**: exposição de superfície interna sem impacto direto confirmado.
- **Low/Info**: hardening ausente sem exploração concreta.

## Nota operacional

Para melhorar cobertura real em low-code, rode com sessão autenticada quando permitido:

- CLI: `--auth-cookie` e/ou `--auth-header K=V`
- UI: preencha cookie/headers no painel de autenticação

Uso somente em alvos autorizados.

