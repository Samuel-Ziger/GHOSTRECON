# FrameSeven — integração futura

Criado em: 2026-07-20

## Decisão atual

O FrameSeven foi incorporado ao workspace apenas como código-fonte de referência. O repositório Git interno foi removido para evitar um repositório aninhado dentro do GHOSTRECON.

A integração operacional foi concluída para o RUN comum e também está disponível no Modo Auto. O controle de autenticação fica na seção principal de Auth opcional.

## Estado validado

- fonte localizada em `FrameSeven/`;
- CLI e Framework API versionados como `v1`;
- 21 ferramentas de recon e verificação;
- servidor MCP via stdio ou HTTP;
- relatório JSON estruturado e versionado;
- suporte a cookies, headers e endpoints autenticados;
- `go test ./...` aprovado em 2026-07-20;
- `go vet ./...` aprovado em 2026-07-20;
- build da CLI aprovado com Go 1.26.5.

## Decisão de linguagem

O FrameSeven deve permanecer em Go. Não há benefício atual que justifique reescrever o scanner em Python. A integração recomendada é por binário versionado e relatório JSON. Python pode continuar sendo usado apenas onde o próprio projeto já o utiliza, como renderização PDF.

## Bloqueio conhecido

O timeout de ferramenta em `FrameSeven/internal/tools/v1/scanner/scanner.go` deixa de esperar pela goroutine, mas não cancela necessariamente as requisições em andamento. O `context.Context` recebido pelos handlers MCP também não é propagado por todo o scanner.

Antes da integração devem ser implementados:

1. contexto cancelável no scanner e nas ferramentas;
2. cancelamento de requisições HTTP e subprocessos;
3. classificação explícita entre passivo, ativo e destrutivo;
4. adaptador GHOSTRECON para executar o binário;
5. normalizador do `report.json` para findings do GHOSTRECON;
6. deduplicação conjunta dos três motores e regravação do `report.html` original;
6. testes de timeout, cancelamento, OPSEC e processo órfão;
7. liberação inicial somente de `recon`, `crawler`, `content` e `misconfig`;
8. confirmação humana antes de qualquer ferramenta ativa.

## Integração implementada

```text
RUN comum ou Modo Auto
  -> gate de OPSEC
  -> adaptador frameseven_v1
  -> binário Go isolado e cancelável
  -> report.json v1
  -> normalizador de findings
  -> dedupe GHOSTRECON + Vigolium + FrameSeven
  -> report.html original do FrameSeven
  -> nova aba na UI
```

## Critério para retomar

A integração está liberada para testes autorizados. Permanecem como melhorias futuras a propagação completa de cancelamento para todas as goroutines internas do FrameSeven e testes reais ponta a ponta com navegador.
