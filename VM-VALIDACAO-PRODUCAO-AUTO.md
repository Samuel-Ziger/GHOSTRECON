# VM — Validação para liberar o Modo Auto em produção

Este arquivo é um **runbook**. Rode cada bloco na VM (Linux recomendado) e **cole a
saída** dentro do bloco `RESULTADO` correspondente. Não apague os comandos: preciso
ver exatamente o que foi executado e o que saiu para poder implementar/comprovar o
que hoje não é verificável na máquina Windows atual (sem toolchain Go, sem Docker,
sem Bubblewrap).

Regras:

- Preencha primeiro a **Seção 0** (ambiente). Sem isso o resto perde contexto.
- Se um comando falhar, cole o erro **inteiro** (não resuma).
- Marque cada seção no fim: `STATUS: ok | falhou | pulado (motivo)`.
- Autorização: os builds/testes de `vigolium/` e `FrameSeven/` podem **baixar
  dependências** (Go modules, `gotestsum`, `bun`, Chromium, imagens Docker). Rode
  apenas em VM descartável/autorizada. Nada de segredo real nos alvos.

---

## Seção 0 — Ambiente da VM

```bash
uname -a
cat /etc/os-release 2>/dev/null | head -n 5
node --version
npm --version
go version
bun --version 2>/dev/null || echo "bun ausente"
docker --version 2>/dev/null || echo "docker ausente"
bwrap --version 2>/dev/null || echo "bubblewrap ausente"
```

RESULTADO:

```text
(cole aqui)
```

STATUS: _______

Requisitos mínimos esperados: Node >=20 <27, **Go 1.26+** (exigência do
`vigolium/CLAUDE.md`), Docker (para e2e/canary), Bubblewrap (para o runner forte do
Forge). Se algo faltar, anote e siga o que der.

---

## Seção 1 — Raiz Node (paridade com o que já passa no Windows)

O objetivo é confirmar que na VM o mesmo verde se mantém e que as suites que eu não
consigo exercitar aqui (rede/import completo) continuam sãs.

```bash
cd <raiz-do-repo>
node --version

# 1a. Gate consolidado do Auto (Auto hermético + CLI + MCP + smoke de import)
npm run test:auto:gate

# 1b. Suite hermética da raiz inteira
npm test

# 1c. CLI e MCP isolados (redundante com o gate, mas confirma os scripts)
npm run test:cli
npm run test:mcp
```

RESULTADO:

```text
(cole aqui a linha final de resumo de cada comando: "tests / pass / fail / skipped")
```

STATUS: _______

> Nota: no Windows 2 testes ficam `skipped` por dependerem de process groups POSIX.
> Na VM Linux eles **devem rodar** — se aparecerem como pass, ótimo (é justamente o
> sinal que falta aqui). Cole o resumo com o número de skipped.

---

## Seção 2 — Suites de rede opt-in (precisa de rede autorizada)

```bash
# Só rode se a VM tem rede e você autoriza o smoke de pipeline.
npm run test:network
```

RESULTADO:

```text
(cole aqui)
```

STATUS: _______

---

## Seção 3 — Vigolium: build + testes nativos

Fonte já clonada em `vigolium/`. Siga o Makefile local (NUNCA `go build` ad-hoc — o
`CLAUDE.md` proíbe; use `make build`). Estes passos podem instalar `gotestsum` e
dependências `bun`/jstangle.

```bash
cd vigolium

make fmt
make lint
make build            # -> bin/vigolium (também instala em $GOPATH/bin)
./bin/vigolium version
make test-unit        # testes rápidos, sem Docker
```

RESULTADO (fmt/lint/build/version):

```text
(cole aqui)
```

RESULTADO (test-unit — cole o resumo final e QUALQUER pacote que falhou):

```text
(cole aqui)
```

STATUS: _______

### 3b — Scope nativo do Vigolium (o que preciso descobrir)

Preciso saber **como o CLI do Vigolium expressa e impõe escopo hoje**, para wirar a
`scopePolicy` selada do GHOSTRECON de forma nativa. Rode e cole a ajuda:

```bash
cd vigolium
./bin/vigolium scope --help 2>&1 | head -n 60
./bin/vigolium scan --help 2>&1 | grep -iE "scope|ignore-scope|out-of-scope|include|exclude" || true
./bin/vigolium --help 2>&1 | head -n 40
```

RESULTADO:

```text
(cole aqui)
```

STATUS: _______

---

## Seção 4 — FrameSeven: build + testes nativos

```bash
cd FrameSeven

go fmt ./...
go vet ./...
go test ./... 2>&1 | tail -n 60
go build -o bin/frameseven/cli/v1 cmd/cli/v1/main.go
./bin/frameseven/cli/v1 --help 2>&1 | head -n 40
```

RESULTADO (fmt/vet):

```text
(cole aqui)
```

RESULTADO (go test — resumo + falhas):

```text
(cole aqui)
```

RESULTADO (build + help):

```text
(cole aqui)
```

STATUS: _______

### 4b — Confirmar suporte a scopePolicy selada / Tor no binário

O adapter GHOSTRECON já transporta `GHOSTRECON_SCOPE_POLICY_*` (env/arquivo 0600) e
falha fechado sob Tor estrito no lado Node. Preciso confirmar o que o binário Go já
reconhece:

```bash
cd FrameSeven
grep -rInE "GHOSTRECON_SCOPE_POLICY|scopePolicy|ScopePolicy|SOCKS|socks5|tor" \
  --include=*.go internal cmd 2>/dev/null | head -n 60
```

RESULTADO:

```text
(cole aqui)
```

STATUS: _______

---

## Seção 5 — Build integrado da engine (ponte GHOSTRECON→Vigolium)

```bash
cd <raiz-do-repo>
npm run engine:build   # bash scripts/build-vigolium-engine.sh
ls -la engines/ 2>/dev/null || true
```

RESULTADO:

```text
(cole aqui — inclua erros do script se houver)
```

STATUS: _______

---

## Seção 6 — E2E de lab (Docker, alvo vulnerável autorizado)

Precisa de Docker. Sobe alvos deliberadamente vulneráveis do próprio Vigolium e roda
os testes canary. **Só em VM autorizada.**

```bash
cd vigolium
make apps-up          # sobe Juice Shop / VAmPI / crAPI etc. (Docker)
make test-e2e         # e2e sem Docker externo (tags e2e)
make test-canary      # canary contra os alvos vulneráveis (lento, ~30-60m)
make apps-down
```

RESULTADO (apps-up):

```text
(cole aqui)
```

RESULTADO (test-e2e):

```text
(cole aqui)
```

RESULTADO (test-canary — resumo + falhas):

```text
(cole aqui)
```

STATUS: _______

---

## Seção 7 — Forge Bubblewrap (runner forte, só Linux)

O Forge exige o runner forte Bubblewrap e falha fechado sem ele. No Windows só há
mock. Na VM Linux, confirme que o `bwrap` está presente e funcional:

```bash
which bwrap && bwrap --version
# sandbox mínimo (deve imprimir "ok" e sair 0):
bwrap --ro-bind / / --dev /dev --proc /proc --unshare-all /bin/sh -c 'echo ok'
```

RESULTADO:

```text
(cole aqui)
```

STATUS: _______

---

## Seção 8 — E2E controlado do Modo Auto (o grande item aberto do DoD)

Este é o teste que hoje não existe fora de fixture. Requer alvo autorizado + rede +
os binários acima construídos. Se você tiver um alvo de laboratório, descreva-o e
rode um ciclo Auto real de ponta a ponta. Se ainda não tiver, marque `pulado` e
seguimos com o resto.

Cheklist a exercitar (marque cada um):

- [ ] `observation` passivo completa e grava relatório/RAG.
- [ ] `assisted` aprovado executa o pipeline; recusado não executa.
- [ ] Cancelamento em cada estágio (planner, aprovação, pipeline, subprocesso).
- [ ] Timeout por turno e por módulo encerra de fato.
- [ ] Restart/resume perto do deadline não renova tetos.
- [ ] Redirect / subdomínio / IP fora da allowlist são bloqueados.
- [ ] Contexto autenticado single-use é consumido e limpo.
- [ ] Zero processo, browser ou temporário residual ao final.
- [ ] Nenhum segredo em NDJSON, RAG, snapshot, SQLite ou relatório.

Alvo de laboratório usado (URL/descrição/autorização):

```text
(descreva aqui)
```

RESULTADO / observações:

```text
(cole aqui logs relevantes, saídas de comando, e o que falhou)
```

STATUS: _______

---

## Seção 9 — Resíduos e segredos (higiene pós-execução)

```bash
# processos/temporários que sobraram após um ciclo Auto:
ps aux | grep -iE "frameseven|vigolium|chrome|chromium" | grep -v grep || echo "sem residuos"
ls -la .runtime 2>/dev/null || true
ls -la .ghostrecon-* 2>/dev/null || true
```

RESULTADO:

```text
(cole aqui)
```

STATUS: _______

---

## Resumo final (preencha por último)

| Seção | Item | STATUS |
|------|------|--------|
| 1 | Node raiz (gate + npm test + cli + mcp) | |
| 2 | Suites de rede opt-in | |
| 3 | Vigolium build + test-unit + scope help | |
| 4 | FrameSeven build + test + scope/Tor grep | |
| 5 | engine:build integrado | |
| 6 | E2E de lab (Docker/canary) | |
| 7 | Bubblewrap funcional | |
| 8 | E2E controlado do Auto | |
| 9 | Resíduos/segredos | |

Observações gerais / bloqueios encontrados:

```text
(cole aqui)
```

---

### O que eu faço com isso

Com os resultados das Seções 3b, 4b (como Vigolium/FrameSeven expressam escopo e
Tor) eu implemento o **enforcement nativo de `scopePolicy`** e o **fail-closed de Tor
no Go**, com testes. Com as Seções 1, 6 e 8 verdes eu tenho a evidência de E2E que o
DoD exige. Só então faz sentido a **decisão de política** de habilitar
`authorized`/`authorized_opsec`, Vigolium no Auto e FrameSeven ofensivo — que é sua,
não minha.
