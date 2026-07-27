import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { protectSecretFinding } from '../modules/secret-safety.js';
import { captureTokenFinding } from '../modules/token-capture.js';
import {
  shouldValidateSecretFindings,
  validateSecretFindings,
} from '../modules/secret-validation.js';
import { createPipelineContext } from '../pipeline/finding-context.mjs';
import { isIntrusive } from '../modules/opsec.mjs';
import { reconBodyIsIntrusive } from '../modules/auth.js';
import { fingerprintLovable } from '../modules/lovable-fingerprint.js';
import { scanSecrets } from '../modules/secrets.js';
import { autoCapabilityClass } from '../auto-agent/pipeline-capabilities.mjs';
import { buildAutoToolCatalog } from '../auto-agent/tool-catalog.mjs';

const RAW_PAT = `ghp_${'A1b2C3d4'.repeat(4)}`;

function jwt(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${header}.${body}.signature123`;
}

test('finding secret emitido contém apenas máscara e fingerprint', () => {
  const events = [];
  const ctx = createPipelineContext({
    domain: 'example.test',
    emit: (event) => events.push(event),
  });
  const finding = {
    type: 'secret',
    prio: 'high',
    value: `[GitHub PAT] ${RAW_PAT}`,
    url: `https://example.test/app.js?token=${RAW_PAT}`,
    meta: `token=${RAW_PAT}`,
  };

  ctx.addFinding(finding, 'secrets');

  const serialized = JSON.stringify({ events, findings: ctx.findings });
  assert.equal(serialized.includes(RAW_PAT), false);
  assert.match(finding.value, /^\[GitHub PAT\] .+…/);
  assert.match(String(finding.meta), /value_fp=[a-f0-9]{64}/);
  assert.equal(finding.url.includes(RAW_PAT), false);
});

test('scanner preserva material só em memória não enumerável', () => {
  const [candidate] = scanSecrets(`const token = "${RAW_PAT}"`);
  assert.ok(candidate);
  assert.equal(candidate.rawMaterial, RAW_PAT);
  assert.equal(JSON.stringify(candidate).includes(RAW_PAT), false);
});

test('captura fica desligada por padrão e evidência opt-in é 0600/redigida', async () => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-secret-'));
  const finding = protectSecretFinding({
    type: 'secret',
    prio: 'high',
    value: `[GitHub PAT] ${RAW_PAT}`,
    url: 'https://example.test/app.js',
    meta: `raw=${RAW_PAT}`,
  });
  const events = [];

  try {
    const skipped = await captureTokenFinding(finding, 'example.test', () => {}, {
      outputDir: temp,
    });
    assert.equal(skipped.skipped, 'disabled');
    assert.deepEqual(await fs.readdir(temp), []);

    await captureTokenFinding(finding, 'example.test', (event) => events.push(event), {
      enabled: true,
      fetchSource: true,
      networkValidation: false,
      outputDir: temp,
      fetchImpl: async () => ({
        status: 200,
        headers: {},
        body: `<script>const token="${RAW_PAT}"</script>`,
        finalUrl: `https://example.test/app.js?token=${RAW_PAT}`,
      }),
      probeImpl: async () => {
        throw new Error('probe de rede não deveria executar');
      },
    });

    const domainDir = path.join(temp, 'example.test');
    const dirStat = await fs.stat(domainDir);
    assert.equal(dirStat.mode & 0o777, 0o700);
    const files = await fs.readdir(domainDir);
    assert.ok(files.some((name) => name.endsWith('.json')));
    assert.ok(files.some((name) => name.endsWith('.curl.sh')));
    assert.ok(files.some((name) => name.endsWith('.html')));

    for (const file of files) {
      const fullPath = path.join(domainDir, file);
      const stat = await fs.stat(fullPath);
      const body = await fs.readFile(fullPath, 'utf8');
      assert.equal(stat.mode & 0o777, 0o600, file);
      assert.equal(body.includes(RAW_PAT), false, file);
    }
    assert.equal(JSON.stringify(events).includes(RAW_PAT), false);
  } finally {
    await fs.rm(temp, { recursive: true, force: true });
  }
});

test('validação de segredo é offline por padrão e nunca retorna token cru', async () => {
  const rawJwt = jwt({
    sub: 'user-fixture',
    role: 'user',
    exp: Math.floor(Date.now() / 1000) + 3600,
  });
  const finding = protectSecretFinding({
    type: 'secret',
    value: `[JWT] ${rawJwt}`,
    url: 'https://example.test/api/me',
  });
  let probes = 0;

  const offline = await validateSecretFindings([finding], null, {
    probeImpl: async () => {
      probes += 1;
      return { status: 403, body: '' };
    },
  });
  assert.equal(probes, 0);
  assert.equal(JSON.stringify(offline).includes(rawJwt), false);
  assert.equal(offline[0].tokenStatus, 'probable');

  const online = await validateSecretFindings([finding], null, {
    network: true,
    probeImpl: async () => {
      probes += 1;
      return { status: 403, body: '' };
    },
  });
  assert.ok(probes > 0);
  assert.equal(online[0].tokenStatus, 'valid');
  assert.equal(JSON.stringify(online).includes(rawJwt), false);
});

test('validação ativa não cruza escopo e propaga cancelamento', async () => {
  const externalJwt = jwt({
    role: 'anon',
    iss: 'https://outside-project.supabase.co/auth/v1',
    exp: Math.floor(Date.now() / 1000) + 3600,
  });
  const externalFinding = protectSecretFinding({
    type: 'secret',
    value: `[JWT] ${externalJwt}`,
    url: 'https://app.example.test/app.js',
  });
  let probes = 0;
  const scoped = await validateSecretFindings([externalFinding], null, {
    network: true,
    urlAllowed: (url) => new URL(url).hostname.endsWith('.example.test'),
    probeImpl: async () => {
      probes += 1;
      return { status: 200, body: '' };
    },
  });
  assert.equal(probes, 0);
  assert.equal(scoped[0].tokenStatus, 'probable');
  assert.match(scoped[0].reason, /fora do escopo/);

  const controller = new AbortController();
  const inScopeFinding = protectSecretFinding({
    type: 'secret',
    value: `[JWT] ${jwt({
      sub: 'fixture',
      exp: Math.floor(Date.now() / 1000) + 3600,
    })}`,
    url: 'https://app.example.test/api/me',
  });
  const running = validateSecretFindings([inScopeFinding], null, {
    network: true,
    signal: controller.signal,
    urlAllowed: () => true,
    probeImpl: async (_url, _headers, _method, { signal }) => new Promise((resolve, reject) => {
      const onAbort = () => reject(signal.reason);
      signal.addEventListener('abort', onAbort, { once: true });
      if (signal.aborted) onAbort();
    }),
  });
  controller.abort(new DOMException('stop fixture', 'AbortError'));
  await assert.rejects(running, /stop fixture/);
});

test('PoC Lovable ignora storeRawSecrets e grava somente evidência 0600', async () => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-lovable-'));
  const supabaseJwt = jwt({
    role: 'anon',
    ref: 'abcdefghijklmnop',
    iss: 'https://abcdefghijklmnop.supabase.co/auth/v1',
  });
  const html = `<html><meta name="lovable"><script>
    const supabaseUrl="https://abcdefghijklmnop.supabase.co";
    const anonKey="${supabaseJwt}";
  </script></html>`;

  try {
    const result = await fingerprintLovable('https://app.example.test/', {
      fetch: async () => new Response(html, {
        status: 200,
        headers: { 'content-type': 'text/html' },
      }),
      probeRls: false,
      probeMisconfig: false,
      pocDir: temp,
      storeRawSecrets: true,
    });
    assert.ok(result.context.pocPath);
    const stat = await fs.stat(result.context.pocPath);
    const body = await fs.readFile(result.context.pocPath, 'utf8');
    assert.equal(stat.mode & 0o777, 0o600);
    assert.equal(body.includes(supabaseJwt), false);
    assert.match(body, /storesRawSecrets(?:&quot;|"):\s*false/);
  } finally {
    await fs.rm(temp, { recursive: true, force: true });
  }
});

test('secret_validation só roda quando o módulo foi selecionado explicitamente', () => {
  assert.equal(shouldValidateSecretFindings([]), false);
  assert.equal(shouldValidateSecretFindings(['secrets_context_ranker']), false);
  assert.equal(shouldValidateSecretFindings(['secret_validation']), true);
  assert.equal(isIntrusive('secret_validation'), true);
  assert.equal(reconBodyIsIntrusive({ modules: ['secret_validation'] }), true);
  assert.equal(autoCapabilityClass('secret_validation'), 'intrusive');
});

test('catálogo Auto só expõe secret_validation quando intrusivos foram autorizados', async () => {
  const conservative = await buildAutoToolCatalog({
    includeDeepPassive: false,
    includeIntrusive: false,
  });
  assert.equal(conservative.modules.some((item) => item.id === 'secret_validation'), false);

  const authorized = await buildAutoToolCatalog({
    includeDeepPassive: false,
    includeIntrusive: true,
  });
  const module = authorized.modules.find((item) => item.id === 'secret_validation');
  assert.equal(module?.class, 'intrusive');
  assert.equal(module?.available, true);
});
