# Vigolium PATH/Kali Mode

Este modo faz o GhostRecon usar o `vigolium` instalado no `PATH` quando estiver em Kali/Linux. Se o binario nao existir no `PATH`, o pipeline volta para o fallback local atual (`engines/vigolium`, `vigolium/bin/vigolium`, etc.).

## Instalar

```bash
bash scripts/install-vigolium-engine.sh
```

Se o script nao encontrar `vigolium`, ele oferece instalar com:

```bash
curl -fsSL https://vigolium.com/install.sh | bash
```

Para instalacao nao interativa:

```bash
GHOSTRECON_INSTALL_VIGOLIUM_PATH=1 bash scripts/install-vigolium-engine.sh
```

## Usar no GhostRecon

Na UI:

- marque `Modo Vigolium PATH (Kali)`;
- selecione `both` ou `go`;
- marque `Vigolium DAST`;
- escolha `deep` quando quiser o equivalente a `--strategy deep`;
- marque `Gerar report HTML Vigolium` se quiser tambem o HTML do Vigolium.

Pelo CLI:

```bash
node bin/ghostrecon.mjs scan \
  --target https://example.com \
  --kali \
  --engine both \
  --modules vigolium_dast \
  --strategy deep \
  --vigolium-prefer-path
```

O comando delegado fica equivalente a:

```bash
vigolium scan -t https://example.com --strategy deep
```

## OpenAPI / arquivo de entrada

Na UI, preencha:

- `Entrada Vigolium -T`: `openapi.yaml`
- `Tipo -I`: `openapi`

Pelo CLI:

```bash
node bin/ghostrecon.mjs scan \
  --target api.example.com \
  --engine both \
  --modules vigolium_dast \
  --vigolium-input-file openapi.yaml \
  --vigolium-input-type openapi
```

Equivalente:

```bash
vigolium scan -T openapi.yaml -I openapi
```

## Login / sessoes

Na UI, use `Logins / auth inline Vigolium`, um por linha:

```text
admin:Cookie:session_id=abc123
user:Cookie:session_id=xyz789
```

Pelo CLI:

```bash
node bin/ghostrecon.mjs scan \
  --target https://example.com \
  --engine both \
  --modules vigolium_dast \
  --vigolium-auth "admin:Cookie:session_id=abc123" \
  --vigolium-auth "user:Cookie:session_id=xyz789"
```

## Report HTML

Na UI, marque `Gerar report HTML Vigolium`. Por padrao o report usa:

```bash
vigolium scan -t https://example.com --only discovery --format html -o report.html
```

Os arquivos ficam em:

```text
.runtime/vigolium-reports/
```

O run tambem recebe um finding `intel` com:

- `reportPath`: caminho local do HTML;
- `reportUrl`: rota autenticada para abrir no navegador.

## Codex

O instalador pergunta se voce quer preparar Codex para os agents IA do Vigolium. Ele clona:

```text
https://github.com/ilysenko/codex-desktop-linux.git
```

Importante:

- esse wrapper Linux e nao oficial;
- ele nao libera acesso ao Codex por conta propria;
- ainda e necessario ter login/plano/acesso Codex habilitado pela OpenAI;
- valide antes com:

```bash
codex login
codex exec 'hello'
```

Para ativar no GhostRecon:

```bash
export GHOSTRECON_VIGOLIUM_USE_CODEX=1
export VIGOLIUM_PROVIDER=openai-codex-oauth
```

Ou marque `Usar Vigolium com Codex` na UI.
