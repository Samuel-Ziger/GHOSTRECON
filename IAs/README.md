# IAs locais

## Shannon Lite (white-box)

O código do Shannon **não** está neste repositório. Para o GHOSTRECON o encontrar em `IAs/shannon/`:

```bash
mkdir -p IAs && cd IAs
git clone https://github.com/keygraph/shannon.git shannon
cd shannon
# Seguir o README do Shannon: pnpm install, pnpm build, ./shannon build, credenciais, Docker
```

Variável opcional: `GHOSTRECON_SHANNON_HOME` (path absoluto) se instalares fora de `IAs/shannon`.

Ver `PLANO_IAS_LOCAIS_GHOSTRECON.md` no repositório GHOSTRECON.

---

## PentestGPT (GreyDGL)

O código do PentestGPT **não** está no Git do GHOSTRECON. Coloca o clone em `IAs/PentestGPT/`:

```bash
mkdir -p IAs && cd IAs
git clone --recurse-submodules https://github.com/GreyDGL/PentestGPT.git PentestGPT
cd PentestGPT
# Requer Docker + Python 3.12+; fluxo oficial:
make install
make config
make connect
```

Se não precisares de `git pull` dentro do clone, podes apagar **`IAs/PentestGPT/.git`** (remove o Git aninhado; o GHOSTRECON continua a ignorar a pasta inteira no seu próprio repositório).

Isto sobe o **agente autónomo** (TUI / CTF / pentest no `--target`). Para o **módulo da UI** «Validação PentestGPT» do Ghost (revisão leve dos achados após o recon), não é obrigatório ter este clone: basta `GHOSTRECON_PENTESTGPT_URL` apontando para um serviço que aceite `ghostPayload` — incluindo o script **`server/scripts/pentestgpt-ghost-bridge.mjs`** (OpenRouter) na raiz do GHOSTRECON.

Variável opcional: `GHOSTRECON_PENTESTGPT_HOME` se instalares o GreyDGL fora de `IAs/PentestGPT`.
