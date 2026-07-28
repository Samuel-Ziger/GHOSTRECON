/**
 * Cobertura hermética da identidade owner-bound de API keys entre restarts.
 *
 * Cada chamada abaixo inicia um processo Node novo, portanto não reutiliza o
 * STATE nem a chave aleatória de boot de server/modules/auth.js.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const execFileAsync = promisify(execFile);
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const AUTH_MODULE_URL = pathToFileURL(
  path.resolve(TEST_DIR, '../modules/auth.js'),
).href;
const API_KEY = 'fixture-api-key-owner-binding-0001';
const RESULT_PREFIX = '__GHOSTRECON_AUTH_RESULT__';

const CHILD_SOURCE = `
const { initAuth, requireAuth, _authStateForTests } = await import(process.env.TEST_AUTH_MODULE_URL);
initAuth();

const req = {
  headers: { 'x-api-key': process.env.TEST_API_KEY },
  socket: { remoteAddress: '127.0.0.1' },
  method: 'GET',
  url: '/api/test',
  originalUrl: '/api/test',
};
const res = {
  statusCode: 200,
  status(code) { this.statusCode = code; return this; },
  json(body) { this.body = body; return this; },
};

let nextCalled = false;
requireAuth()(req, res, () => { nextCalled = true; });

if (!nextCalled || !req.principal?.sub) {
  throw new Error(\`API key fixture não autenticou: HTTP \${res.statusCode}\`);
}
process.stdout.write(
  ${JSON.stringify(RESULT_PREFIX)}
  + JSON.stringify({
    sub: req.principal.sub,
    principalBinding: _authStateForTests().principalBinding,
  })
  + '\\n',
);
`;

async function principalFromFreshProcess({
  principalBindingSecret = '',
  jwtSecret = '',
} = {}) {
  // O runner node:test injeta este marcador nos workers. Removê-lo garante que
  // o filho simula um boot normal e escreve no stdout convencional.
  const { NODE_TEST_CONTEXT: _testContext, ...baseEnv } = process.env;
  const { stdout } = await execFileAsync(
    process.execPath,
    ['--input-type=module', '--eval', CHILD_SOURCE],
    {
      env: {
        ...baseEnv,
        AUTH_MODE: 'apikey',
        AUTH_DISABLE: '0',
        AUTH_API_KEYS: `${API_KEY}:operator:restart-fixture`,
        AUTH_API_KEYS_FILE: '',
        AUTH_AUDIT_DISABLE: '1',
        AUTH_PRINCIPAL_BINDING_SECRET: principalBindingSecret,
        AUTH_JWT_SECRET: jwtSecret,
        TEST_API_KEY: API_KEY,
        TEST_AUTH_MODULE_URL: AUTH_MODULE_URL,
      },
      timeout: 5_000,
      maxBuffer: 256 * 1024,
      windowsHide: true,
    },
  );
  const line = stdout
    .split(/\r?\n/)
    .find((entry) => entry.startsWith(RESULT_PREFIX));
  assert.ok(line, `processo filho não retornou marcador de resultado: ${stdout}`);
  return JSON.parse(line.slice(RESULT_PREFIX.length));
}

test('AUTH_PRINCIPAL_BINDING_SECRET mantém principal.sub estável entre processos', async () => {
  const secret = 'dedicated-principal-binding-secret-fixture-0001';
  const firstBoot = await principalFromFreshProcess({ principalBindingSecret: secret });
  const secondBoot = await principalFromFreshProcess({ principalBindingSecret: secret });
  const otherSecret = await principalFromFreshProcess({
    principalBindingSecret: 'dedicated-principal-binding-secret-fixture-0002',
  });

  assert.equal(firstBoot.sub, secondBoot.sub);
  assert.notEqual(firstBoot.sub, otherSecret.sub);
  assert.deepEqual(firstBoot.principalBinding, {
    persistent: true,
    source: 'dedicated',
  });
});

test('AUTH_JWT_SECRET mantém o fallback de principal.sub estável entre processos', async () => {
  const secret = 'jwt-hs256-principal-binding-secret-fixture-0001';
  const firstBoot = await principalFromFreshProcess({ jwtSecret: secret });
  const secondBoot = await principalFromFreshProcess({ jwtSecret: secret });
  const otherSecret = await principalFromFreshProcess({
    jwtSecret: 'jwt-hs256-principal-binding-secret-fixture-0002',
  });

  assert.equal(firstBoot.sub, secondBoot.sub);
  assert.notEqual(firstBoot.sub, otherSecret.sub);
  assert.deepEqual(firstBoot.principalBinding, {
    persistent: true,
    source: 'jwt_hs256',
  });
});
