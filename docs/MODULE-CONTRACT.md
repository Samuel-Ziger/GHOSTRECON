# Contrato para modulos GHOSTRECON

Este documento define o formato minimo para novos modulos do pipeline. A regra e simples: modulo novo precisa ser previsivel para executar, limitar recursos, emitir findings normalizados e ser testavel sem rede real quando possivel.

## Manifesto

Cada modulo novo deve declarar estes campos perto do topo do arquivo ou em um registry futuro:

```js
export const moduleManifest = {
  id: 'cookie_session_audit',
  name: 'Cookie / Session Audit',
  category: 'surface',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 60_000,
  concurrency: 4,
  outputs: ['finding'],
};
```

Campos obrigatorios:

- `id`: slug estavel usado em UI, playbook, testes e logs.
- `name`: nome humano.
- `category`: `discovery`, `surface`, `validation`, `aggressive`, `ai`, `persistence` ou `reporting`.
- `intrusive`: `true` se faz escrita, brute force, fuzzing pesado, spray, exploit ou alteracao de estado.
- `requiresAuth`: `true` se precisa de cookies/tokens do operador.
- `requiresKali`: `true` se depende de ferramenta externa do Kali.
- `timeoutMs`: limite padrao do modulo.
- `concurrency`: limite interno padrao.
- `outputs`: tipos emitidos, normalmente `finding`, `intel`, `artifact` ou `metric`.

## Assinatura de execucao

Modulo novo deve expor uma funcao pura o suficiente para teste:

```js
export async function runCookieSessionAudit(ctx) {
  const {
    target,
    findings = [],
    auth = null,
    modules = [],
    emit = () => {},
    log = () => {},
    fetchImpl = fetch,
    executor = null,
  } = ctx;

  return { findings: [], metrics: {}, artifacts: [] };
}
```

Regras:

- Aceitar `fetchImpl` ou `executor` injetavel para testes.
- Nao ler `req`/`res` diretamente.
- Nao gravar arquivo sem passar por um store/helper existente.
- Nao chamar processo externo diretamente; usar `runProcess` de `server/modules/module-runner.mjs`.
- Nao implementar pool proprio; usar `mapPool` de `server/modules/module-runner.mjs`.
- Nao ler body HTTP inteiro; usar `readResponseSnippet`.

## Findings

Finding minimo:

```js
{
  type: 'cookie_session',
  prio: 'low',
  score: 35,
  value: 'Cookie sem SameSite',
  meta: 'cookie=sessionid; host=app.example.com',
  url: 'https://app.example.com/'
}
```

Regras:

- `type` deve ser estavel e especifico.
- `prio`: `info`, `low`, `med`, `high` ou `critical`.
- `score`: numero entre 0 e 100.
- `value`: frase curta.
- `meta`: detalhe compacto, sem segredos em claro.
- `url`: quando houver origem verificavel.

## OPSEC

Modulo `intrusive: true` deve respeitar:

- engagement/ROE
- janela operacional
- confirmacao explicita
- escopo e exclusoes
- perfil OPSEC

Se houver duvida, o modulo deve gerar plano ou finding informativo, nao executar acao ativa.

## Testes

Cada modulo novo deve ter teste em `server/tests/<id>.test.js` cobrindo:

- parsing/normalizacao
- caso positivo
- caso negativo
- timeout/erro controlado
- ausencia de rede real via `fetchImpl` ou `executor`

Antes de merge:

```bash
npm test
npm audit --omit=dev
```
