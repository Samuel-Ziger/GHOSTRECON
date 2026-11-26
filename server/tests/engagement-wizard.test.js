import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const ROOT = path.resolve(import.meta.dirname, '../..');
const SCRIPT = path.join(ROOT, 'criar-engagement-autorizado.sh');

function runWizard(storeDir, answers) {
  return spawnSync('bash', [SCRIPT], {
    cwd: ROOT,
    encoding: 'utf8',
    input: `${answers.join('\n')}\n`,
    env: {
      ...process.env,
      GHOSTRECON_ENGAGEMENT_ALLOW_PIPE: '1',
      GHOSTRECON_ENGAGEMENT_DIR: storeDir,
      GITHUB_TOKEN: '',
    },
    timeout: 20_000,
  });
}

function fixtureAnswers({ id = 'ENG-WIZARD-TEST', confirmation = 'AUTORIZO' } = {}) {
  return [
    id,
    'Programa autorizado de teste',
    'Operador Teste',
    'example.test,*.api.example.test',
    '',
    '',
    'admin.example.test',
    '192.0.2.10',
    '',
    '',
    '',
    'https://example.test/roe',
    's',
    'SOC Teste',
    'soc@example.test',
    '+55 11 0000-0000',
    'Fixture hermética, sem rede.',
    confirmation,
  ];
}

test('assistente cria engagement autorizado pelo store nativo e imprime JSON final', async (t) => {
  const storeDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-engagement-wizard-'));
  t.after(() => fs.rm(storeDir, { recursive: true, force: true }));

  const result = runWizard(storeDir, fixtureAnswers());
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /Engagement autorizado criado com sucesso/);
  assert.match(result.stdout, /"id": "ENG-WIZARD-TEST"/);
  assert.match(result.stdout, /\[checklist] ok=true/);

  const store = JSON.parse(await fs.readFile(path.join(storeDir, 'engagements.json'), 'utf8'));
  const engagement = store.engagements.find((item) => item.id === 'ENG-WIZARD-TEST');
  assert.ok(engagement);
  assert.equal(engagement.status, 'active');
  assert.equal(engagement.roeSigned, true);
  assert.deepEqual(engagement.scopeDomains, ['example.test', '*.api.example.test']);
  assert.deepEqual(engagement.sourceIps, ['192.0.2.10']);
  assert.equal(engagement.escalationContact.email, 'soc@example.test');
});

test('assistente não grava antes da confirmação literal AUTORIZO', async (t) => {
  const storeDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-engagement-cancel-'));
  t.after(() => fs.rm(storeDir, { recursive: true, force: true }));

  const result = runWizard(storeDir, fixtureAnswers({ id: 'ENG-CANCEL', confirmation: 'CANCELAR' }));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /nenhuma alteração foi gravada/);
  await assert.rejects(fs.access(path.join(storeDir, 'engagements.json')));
});

test('script de engagement permanece executável e sintaticamente válido', async () => {
  const stat = await fs.stat(SCRIPT);
  assert.notEqual(stat.mode & 0o111, 0);
  const syntax = spawnSync('bash', ['-n', SCRIPT], { cwd: ROOT, encoding: 'utf8' });
  assert.equal(syntax.status, 0, syntax.stderr);
});
