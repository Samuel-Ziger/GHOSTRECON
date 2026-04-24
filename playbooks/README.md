# Playbooks — perfis nomeados para GHOSTRECON

Playbooks são ficheiros JSON (ou YAML minimalista) que pré-selecionam módulos e
configuração de pipeline para cenários comuns de bug bounty / red team. Evitam
que você tenha de lembrar qual combinação de módulos faz sentido em cada caso.

## Uso

```bash
# Listar
ghostrecon playbooks

# Ver detalhes
ghostrecon playbooks --show api-first

# Usar num recon
ghostrecon run --target api.example.com --playbook api-first --output api.json

# Combinar playbook com módulos extra (união)
ghostrecon run --target example.com --playbook api-first --modules kali_scan

# Usar no scheduler com alerta new-only
ghostrecon schedule --target api.example.com --playbook api-first \
  --interval 6h --webhook https://discord.com/api/webhooks/... \
  --only-new --min-severity high
```

## Playbooks incluídos

| Nome | Uso típico |
|------|------------|
| `api-first` | Aplicações com superfície de API (REST/GraphQL/OpenAPI) |
| `wordpress` | Alvos WordPress — wpscan, themes, plugins |
| `cloud-takeover` | Caça takeover via CNAMEs órfãos |
| `subdomain-hunt` | Enumeração agressiva de subdomínios |
| `secrets-leak` | Leak hunting — GitHub, wayback, dorks |
| `quick-triage` | First-pass rápido para reconhecimento inicial |

## Formato

```json
{
  "name": "my-playbook",
  "description": "O que este playbook faz.",
  "profile": "standard",
  "tags": ["rest", "api"],
  "modules": ["crtsh", "http", "openapi_harvest"],
  "limits": {},
  "targetHint": "api.*"
}
```

Campos:

- **name** (obrigatório): identificador único, usado pelo `--playbook`.
- **description**: frase curta descrevendo o caso de uso.
- **profile**: `standard` | `stealth` | `aggressive`. Usado para ajustar rate-limits.
- **tags**: livre, apenas documental.
- **modules**: lista de módulos (mesmos nomes que a API `/api/recon/stream` aceita).
- **limits**: reservado para overrides futuros de `server/config.js` por playbook.
- **targetHint**: sugestão documental de padrão de alvo — não é enforced.

## Custom playbooks

Coloque ficheiros `.json` (ou `.yaml` minimalista) em `playbooks/` ou aponte
`GHOSTRECON_PLAYBOOKS_DIR` para um diretório extra (suporta múltiplos caminhos
separados por `:` em POSIX ou `;` em Windows). O primeiro playbook com cada nome
vence.

Para YAML, apenas o subset abaixo é suportado (parser mínimo, zero deps):

```yaml
name: my-pb
description: Exemplo
profile: standard
modules:
  - crtsh
  - http
tags: [a, b]
```
