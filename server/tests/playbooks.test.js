import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  listPlaybooks,
  resolvePlaybook,
  parseMinimalYaml,
  validatePlaybookModules,
} from '../modules/playbooks/loader.mjs';

test('listPlaybooks: carrega os bundled', async () => {
  const list = await listPlaybooks();
  const names = list.map((p) => p.name);
  assert.ok(names.includes('api-first'), `esperava api-first, vi ${names.join(',')}`);
  assert.ok(names.includes('wordpress'));
  assert.ok(names.includes('cloud-takeover'));
  assert.ok(names.includes('subdomain-hunt'));
  assert.deepEqual(
    list.filter((playbook) => !playbook.validation.ok).map((playbook) => ({
      name: playbook.name,
      unknown: playbook.validation.unknownModules,
    })),
    [],
    'todos os playbooks bundled devem resolver apenas para capacidades executáveis',
  );
});

test('resolvePlaybook: api-first tem modules', async () => {
  const pb = await resolvePlaybook('api-first');
  assert.equal(pb.name, 'api-first');
  assert.ok(Array.isArray(pb.modules));
  assert.ok(pb.modules.length > 3);
  assert.ok(pb.modules.includes('openapi_specs'));
  assert.ok(pb.modules.includes('http_probe'));
  assert.ok(pb.modules.includes('active_param_discovery'));
  assert.equal(pb.validation.ok, true);
  assert.deepEqual(pb.validation.unknownModules, []);
  assert.deepEqual(pb.validation.retiredModules, []);
});

test('resolvePlaybook: case-insensitive', async () => {
  const pb = await resolvePlaybook('API-FIRST');
  assert.equal(pb.name, 'api-first');
});

test('resolvePlaybook: playbook inexistente falha', async () => {
  await assert.rejects(() => resolvePlaybook('xxx-does-not-exist'));
});

test('validatePlaybookModules: migra aliases 1:1 e 1:N antes dos gates', () => {
  const result = validatePlaybookModules([
    'crtsh',
    'http',
    'graphql',
    'param_discovery',
    'well_known',
    'html_surface',
    'takeover',
    'secrets',
  ]);
  assert.equal(result.ok, true);
  assert.deepEqual(result.modules, [
    'subdomains',
    'http_probe',
    'graphql_probe',
    'graphql_recon',
    'active_param_discovery',
    'wellknown_security_txt',
    'wellknown_openid',
    'client_surface_audit',
    'asset_discovery',
    'js_intel',
    'secrets_context_ranker',
  ]);
  assert.equal(result.migrations.length, 8);
});

test('resolvePlaybook: full-recon não morre por IDs históricos', async () => {
  const pb = await resolvePlaybook('full-recon');
  assert.equal(pb.validation.ok, true);
  assert.ok(pb.modules.includes('http_probe'));
  assert.ok(pb.modules.includes('client_surface_audit'));
  assert.ok(pb.modules.includes('asset_discovery'));
  assert.ok(pb.modules.includes('secrets_context_ranker'));
  assert.ok(pb.modules.includes('github'));
  assert.equal(pb.modules.includes('dorks'), false);
  assert.equal(pb.modules.includes('encoding_sniff'), false);
});

test('validatePlaybookModules: ID desconhecido não desaparece silenciosamente', () => {
  const result = validatePlaybookModules(['http_probe', 'does_not_exist']);
  assert.equal(result.ok, false);
  assert.deepEqual(result.modules, ['http_probe']);
  assert.deepEqual(result.unknownModules, ['does_not_exist']);
});

test('validatePlaybookModules: IDs removidos são tombstones, não unknown/no-op', () => {
  const result = validatePlaybookModules([
    'http_probe',
    'shannon-whitebox',
    'pentestgpt_validate',
  ]);
  assert.equal(result.ok, false);
  assert.deepEqual(result.modules, ['http_probe']);
  assert.deepEqual(result.unknownModules, []);
  assert.deepEqual(result.retiredModules, ['shannon_whitebox', 'pentestgpt_validate']);
});

test('resolvePlaybook: fallback por nome interno também falha fechado para ID desconhecido', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-playbook-'));
  const previous = process.env.GHOSTRECON_PLAYBOOKS_DIR;
  await fs.writeFile(path.join(dir, 'arquivo-com-outro-nome.json'), JSON.stringify({
    name: 'internal-invalid-playbook',
    modules: ['http_probe', 'does_not_exist'],
  }));
  process.env.GHOSTRECON_PLAYBOOKS_DIR = dir;
  try {
    await assert.rejects(
      () => resolvePlaybook('internal-invalid-playbook'),
      (error) => error?.code === 'PLAYBOOK_MODULES_INVALID'
        && error?.unknownModules?.includes('does_not_exist'),
    );
  } finally {
    if (previous == null) delete process.env.GHOSTRECON_PLAYBOOKS_DIR;
    else process.env.GHOSTRECON_PLAYBOOKS_DIR = previous;
  }
});

test('resolvePlaybook: arquivo legado com módulo removido retorna MODULE_RETIRED', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-playbook-retired-'));
  const previous = process.env.GHOSTRECON_PLAYBOOKS_DIR;
  await fs.writeFile(path.join(dir, 'legacy-retired.json'), JSON.stringify({
    name: 'legacy-retired',
    modules: ['http_probe', 'shannon_whitebox'],
  }));
  process.env.GHOSTRECON_PLAYBOOKS_DIR = dir;
  try {
    await assert.rejects(
      () => resolvePlaybook('legacy-retired'),
      (error) => error?.code === 'MODULE_RETIRED'
        && error?.statusCode === 410
        && error?.retiredModules?.includes('shannon_whitebox'),
    );
  } finally {
    if (previous == null) delete process.env.GHOSTRECON_PLAYBOOKS_DIR;
    else process.env.GHOSTRECON_PLAYBOOKS_DIR = previous;
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('parseMinimalYaml: basic key/list/scalar', () => {
  const txt = `
name: foo
description: test
profile: standard
modules:
  - a
  - b
tags: [x, y]
num: 42
bool: true
`;
  const parsed = parseMinimalYaml(txt);
  assert.equal(parsed.name, 'foo');
  assert.equal(parsed.profile, 'standard');
  assert.deepEqual(parsed.modules, ['a', 'b']);
  assert.deepEqual(parsed.tags, ['x', 'y']);
  assert.equal(parsed.num, 42);
  assert.equal(parsed.bool, true);
});

test('parseMinimalYaml: ignora comentários', () => {
  const parsed = parseMinimalYaml('name: foo # comment\n# full line\n');
  assert.equal(parsed.name, 'foo');
});
