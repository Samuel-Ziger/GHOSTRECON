# GHOSTRECON — Motor Vigolium (runtime)

Esta pasta contém **apenas o binário compilado** do motor DAST Go. O código-fonte
completo do Vigolium **não** deve permanecer no monorepo após o build.

## Instalar o binário

### Opção A — já tens `vigolium` no PATH (recomendado)

```bash
bash scripts/install-vigolium-engine.sh
```

Copia `vigolium` de `~/.local/bin`, PATH ou `npm install -g @vigolium/vigolium`.

### Opção B — compilar a partir de `vigolium/` (temporário)

```bash
# clone só para build (não versionar a pasta)
git clone https://github.com/vigolium/vigolium.git vigolium
bash scripts/build-vigolium-engine.sh
rm -rf vigolium   # libertar ~150MB+ de fontes Go
```

Requisitos: Go 1.26+, Bun 1.3.11+ (ver `vigolium/HACKING.md` durante o build).

### Opção C — curl upstream

```bash
curl -fsSL https://vigolium.com/install.sh | bash
bash scripts/install-vigolium-engine.sh
```

## Verificar

```bash
./engines/vigolium version
# ou
GHOSTRECON_VIGOLIUM_BIN=./engines/vigolium ghostrecon scan -t example.com --modules vigolium_dast --strategy lite --confirm-active
```

## Licença

O binário deriva do projeto [Vigolium](https://github.com/vigolium/vigolium) (AGPL-3.0).
Ver `engines/LICENSE.AGPL` e `NOTICE` na raiz do GHOSTRECON.

## O que fica aqui vs. o que sai

| Mantém em `engines/` | Remove `vigolium/` após build |
|----------------------|-------------------------------|
| `vigolium` (binário) | ~2700 ficheiros `.go` |
| `LICENSE.AGPL` | `platform/`, testes, docs upstream |
| `.gitkeep` | `.git` nested, `node_modules` bun |

O binário já embute `vigolium-audit`, módulos DAST, OAST e agent runtime — não precisas
da pasta fonte para correr scans.
