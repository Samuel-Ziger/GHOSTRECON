import fs from 'node:fs/promises';
import path from 'node:path';
import { computeForgeArtifactIntegrity } from './artifact-integrity.mjs';

const ALLOWED_CATEGORIES = new Set(['discovery', 'surface', 'validation', 'ai', 'persistence', 'reporting']);
const ALLOWED_OUTPUTS = new Set(['finding', 'intel', 'artifact', 'metric']);
const TEST_IMPORTS = new Set(['node:test', 'node:assert', 'node:assert/strict', './module.mjs']);

function importsOf(code) {
  const imports = [];
  const re = /(?:import\s+(?:[^'";]+?\s+from\s+)?|export\s+[^'";]+?\s+from\s+|import\s*\()(['"])([^'"]+)\1/g;
  for (const match of String(code || '').matchAll(re)) imports.push(match[2]);
  return imports;
}

function scanForbidden(code, kind) {
  const rules = [
    ['dynamic_code', /\b(?:eval|Function)\s*\(/],
    ['process_execution', /\b(?:child_process|spawn|execFile|execSync|fork)\b/],
    ['filesystem', /(?:node:)?fs(?:\/promises)?|\bDeno\.|\bBun\./],
    ['raw_network', /(?:node:)?(?:net|http|https|tls|dgram|dns)(?:\/promises)?/],
    ['worker_or_vm', /(?:node:)?(?:worker_threads|vm)\b|\bWebAssembly\b/],
    ['runtime_process_access', /\bprocess\b/],
    ['global_fetch', /(?<![\w.])fetch\s*\(/],
    ['global_object_access', /\b(?:globalThis|global)\b|\bself\s*(?:\.|\[)/],
    ['module_loader', /\brequire\s*\(|\bimport\s*\(/],
    ['prototype_mutation', /__(?:proto)__|prototype\s*\[/],
  ];
  const findings = [];
  for (const [id, pattern] of rules) if (pattern.test(String(code || ''))) findings.push({ id, kind, severity: 'block' });
  return findings;
}

function validateManifest(manifest, expectedId) {
  const errors = [];
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) return ['manifest inválido'];
  if (manifest.id !== expectedId) errors.push('manifest.id difere do forge request');
  if (!/^[a-z][a-z0-9_]{2,127}$/.test(String(manifest.id || ''))) errors.push('manifest.id inválido');
  if (!String(manifest.name || '').trim()) errors.push('manifest.name obrigatório');
  if (!ALLOWED_CATEGORIES.has(manifest.category)) errors.push('manifest.category inválida');
  if (manifest.intrusive !== false) errors.push('manifest.intrusive deve ser false');
  if (manifest.requiresKali !== false) errors.push('manifest.requiresKali deve ser false');
  if (manifest.requiresAuth !== false) errors.push('manifest.requiresAuth deve ser false');
  if (!Number.isInteger(manifest.timeoutMs) || manifest.timeoutMs < 1000 || manifest.timeoutMs > 120000) errors.push('manifest.timeoutMs fora do limite');
  if (!Number.isInteger(manifest.concurrency) || manifest.concurrency < 1 || manifest.concurrency > 8) errors.push('manifest.concurrency fora do limite');
  if (!Array.isArray(manifest.outputs) || !manifest.outputs.length || manifest.outputs.some((x) => !ALLOWED_OUTPUTS.has(x))) errors.push('manifest.outputs inválido');
  return errors;
}

export async function validateForgePackage(pendingDir) {
  const [request, manifest, moduleCode, testCode] = await Promise.all([
    fs.readFile(path.join(pendingDir, 'forge-request.json'), 'utf8').then(JSON.parse),
    fs.readFile(path.join(pendingDir, 'manifest.json'), 'utf8').then(JSON.parse),
    fs.readFile(path.join(pendingDir, 'module.mjs'), 'utf8'),
    fs.readFile(path.join(pendingDir, 'module.test.js'), 'utf8'),
  ]);
  const errors = validateManifest(manifest, request.proposedId);
  const moduleImports = importsOf(moduleCode);
  if (moduleImports.length) errors.push(`module imports não permitidos nesta fase: ${moduleImports.join(', ')}`);
  const testImports = importsOf(testCode);
  const invalidTestImports = testImports.filter((x) => !TEST_IMPORTS.has(x));
  if (invalidTestImports.length) errors.push(`test imports não permitidos: ${invalidTestImports.join(', ')}`);
  if (!testImports.includes('node:test')) errors.push('teste deve importar node:test');
  if (!testImports.includes('./module.mjs')) errors.push('teste deve importar ./module.mjs');
  if (!/export\s+(?:default\s+)?(?:async\s+)?function\s+run\s*\(|export\s+(?:const|let)\s+run\s*=/.test(moduleCode)) {
    errors.push('módulo deve exportar run(ctx)');
  }
  if (/\bwhile\s*\(\s*(?:true|1)\s*\)|\bfor\s*\(\s*;\s*;\s*\)/.test(moduleCode)) errors.push('loop potencialmente infinito bloqueado');
  const forbidden = [...scanForbidden(moduleCode, 'module'), ...scanForbidden(testCode, 'test')];
  errors.push(...forbidden.map((x) => `${x.kind}: ${x.id}`));
  if (!/\bfetchImpl\b/.test(moduleCode) && /https?:|request|endpoint|url/i.test(`${request.gap || ''} ${moduleCode}`)) {
    errors.push('módulo de rede deve aceitar fetchImpl injetável');
  }
  const artifactIntegrity = await computeForgeArtifactIntegrity(pendingDir);
  const result = {
    schemaVersion: 1,
    ok: errors.length === 0,
    checkedAt: new Date().toISOString(),
    errors,
    imports: { module: moduleImports, test: testImports },
    forbidden,
    manifest,
    artifactIntegrity,
  };
  await fs.writeFile(path.join(pendingDir, 'validation-results.json'), JSON.stringify(result, null, 2), 'utf8');
  return result;
}
