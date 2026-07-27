import vm from 'node:vm';
import { readFileSync, writeFileSync } from 'node:fs';

const MAX_INPUT_BYTES = 512 * 1024;
const MAX_SOURCE_BYTES = 256 * 1024;
const MAX_RESULT_CHARS = 750_000;

function writeResult(value) {
  const text = JSON.stringify(value);
  const output = text.length > MAX_RESULT_CHARS
    ? JSON.stringify({ ok: false, error: 'resultado excede o limite do runtime Forge' })
    : text;
  writeFileSync(1, output);
}

function readInput() {
  const input = readFileSync(0);
  if (input.length > MAX_INPUT_BYTES) throw new Error('entrada excede o limite do runtime Forge');
  return JSON.parse(input.toString('utf8'));
}

function validateSource(source) {
  if (!source || Buffer.byteLength(source) > MAX_SOURCE_BYTES) throw new Error('código Forge ausente ou acima do limite');
  if (!/export\s+(?:default\s+)?(?:async\s+)?function\s+run\s*\(|export\s+(?:const|let)\s+run\s*=/.test(source)) {
    throw new Error('módulo Forge não exporta run(ctx)');
  }
  const forbidden = [
    [/\bimport\s*(?:\(|[\s{*"'])/, 'imports'],
    [/\brequire\s*\(/, 'require'],
    [/\bprocess\b/, 'process'],
    [/\b(?:Deno|Bun|WebAssembly|SharedArrayBuffer)\b/, 'runtime privilegiado'],
    [/\b(?:eval|Function)\s*\(/, 'código dinâmico'],
    [/\bfetch\s*\(/, 'fetch global'],
    [/\b(?:globalThis|global)\b|\bself\s*(?:\.|\[)/, 'objeto global'],
    [/\b(?:child_process|worker_threads|cluster)\b|node:(?:vm|fs|net|http|https|tls|dgram|dns)/, 'capacidade privilegiada'],
  ];
  for (const [pattern, label] of forbidden) {
    if (pattern.test(source)) throw new Error(`código Forge contém ${label} não permitido`);
  }
}

async function main() {
  const input = readInput();
  const source = String(input?.source || '');
  validateSource(source);
  const timeoutMs = Math.max(100, Math.min(120_000, Number(input?.timeoutMs) || 30_000));
  const sandbox = Object.create(null);
  sandbox.__payloadJson = JSON.stringify({
    target: String(input?.context?.target || '').slice(0, 2048),
    domain: String(input?.context?.domain || input?.context?.target || '').slice(0, 2048),
    requestRunId: String(input?.context?.requestRunId || '').slice(0, 300),
    runId: String(input?.context?.runId || '').slice(0, 300),
    engagementId: String(input?.context?.engagementId || '').slice(0, 120),
    engagementVersion: String(input?.context?.engagementVersion || '').slice(0, 200),
    authorizationBindingSha256: String(
      input?.context?.authorizationBindingSha256 || '',
    ).slice(0, 64),
    artifactSha256: String(input?.context?.artifactSha256 || '').slice(0, 64),
  });
  const context = vm.createContext(sandbox, {
    name: 'ghostrecon-forge-runtime',
    codeGeneration: { strings: false, wasm: false },
  });
  const mod = new vm.SourceTextModule(source, {
    context,
    identifier: `forge:${String(input?.moduleId || 'dynamic').slice(0, 120)}`,
    initializeImportMeta(meta) {
      Object.defineProperty(meta, 'url', { value: 'forge:isolated', enumerable: true });
      Object.freeze(meta);
    },
    importModuleDynamically() {
      throw new Error('import dinâmico bloqueado no runtime Forge');
    },
  });
  await mod.link(() => {
    throw new Error('imports bloqueados no runtime Forge');
  });
  await mod.evaluate({ timeout: timeoutMs, breakOnSigint: true });
  if (typeof mod.namespace.run !== 'function') throw new Error('módulo Forge não exporta run(ctx)');
  sandbox.__forgeRun = mod.namespace.run;
  const resultJson = await vm.runInContext(`(async () => {
    const input = JSON.parse(__payloadJson);
    Object.defineProperties(input, {
      fetchImpl: {
        enumerable: true,
        value: async () => { throw new Error('rede desabilitada no runtime Forge isolado'); },
      },
      signal: {
        enumerable: true,
        value: Object.freeze({
          aborted: false,
          reason: null,
          addEventListener() {},
          removeEventListener() {},
          throwIfAborted() {},
        }),
      },
    });
    Object.freeze(input);
    const output = await __forgeRun(input);
    return JSON.stringify(output ?? null);
  })()`, context, { timeout: timeoutMs, breakOnSigint: true });
  writeResult({ ok: true, result: JSON.parse(resultJson) });
}

try {
  await main();
} catch (error) {
  writeResult({ ok: false, error: String(error?.message || error).slice(0, 2000) });
}
