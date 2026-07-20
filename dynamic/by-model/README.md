# GHOSTRECON AI Module Forge

Armazenamento segregado dos módulos propostos por IAs do Modo AUTO.

```text
<provider>/<model opcional>/
  pending/<forgeId>/
  active/<moduleId>/<forgeId>/
  rejected/<moduleId>/<version>/
```

Regras:

- `pending` preserva propostas ainda não aprovadas.
- `rejected` preserva código, testes, evidências e o motivo da rejeição.
- Somente `active` com `pipelineEnabled=true` pode ser considerado pelo loader do pipeline.
- A aprovação humana move o pacote para `active` e inicia imediatamente uma execução no alvo gravado em `provenance.json`.
- `provenance.json` identifica autor original, modelo, contribuidores e run de origem.
- `verdict.json` registra conselho, policy, testes e aprovação humana.

Gates atuais antes da aprovação humana:

1. manifesto conservador e não intrusivo;
2. bloqueio de imports, rede, filesystem, subprocessos e código dinâmico;
3. `node --check` no módulo e no teste;
4. teste com Node permission model, sem rede/escrita/subprocessos;
5. review estruturado das IAs selecionadas;
6. quórum do conselho;
7. decisão explícita do operador via API.

Quando o conselho retornar `request_changes`, o autor recebe o código atual e os pareceres,
gera uma revisão e repete validação, testes e votação. Cada versão anterior é preservada em
`revisions/revision-NN`. O limite padrão é duas correções e pode ser ajustado entre zero e cinco
com `GHOSTRECON_AUTO_FORGE_MAX_CORRECTIONS`.

Após a primeira execução, o veredito fica `active` quando o módulo conclui; se falhar, fica `activation_failed`, o estado vira `disabled` e `pipelineEnabled=false`.

O loader dinâmico roda no final das fases de coleta do pipeline, exige `export async function run(ctx)`, impõe o `timeoutMs` do manifesto e normaliza os findings antes de adicioná-los à execução.
