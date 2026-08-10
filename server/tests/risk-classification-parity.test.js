import test from 'node:test';
import assert from 'node:assert/strict';

import { isIntrusive } from '../modules/opsec.mjs';
import { autoCapabilityClass } from '../auto-agent/pipeline-capabilities.mjs';
import { classifyAutoModule } from '../auto-agent/tool-catalog.mjs';
import { listModuleManifests } from '../modules/module-registry.mjs';

test('paridade de classificação: manifest intrusive ↔ catálogo ↔ OPSEC', async () => {
  const manifests = (() => {
    try {
      return listModuleManifests() || [];
    } catch {
      return [];
    }
  })();
  const divergences = [];
  for (const manifest of manifests) {
    const id = String(manifest?.id || '').trim();
    if (!id) continue;
    const catalogClass = classifyAutoModule(id, manifest);
    const legacyClass = autoCapabilityClass(id);
    const opsecIntrusive = isIntrusive(id);
    const manifestIntrusive = manifest.intrusive === true || manifest.class === 'intrusive';

    if (manifestIntrusive && catalogClass !== 'intrusive' && catalogClass !== 'destructive') {
      divergences.push(`${id}: manifest intrusive but catalog=${catalogClass}`);
    }
    if (opsecIntrusive && catalogClass !== 'intrusive' && catalogClass !== 'destructive') {
      divergences.push(`${id}: OPSEC intrusive but catalog=${catalogClass}`);
    }
    if (catalogClass === 'intrusive' && !manifestIntrusive && !opsecIntrusive && legacyClass !== 'intrusive') {
      divergences.push(`${id}: catalog intrusive without manifest/OPSEC/legacy`);
    }
  }

  // Capacidade engine FrameSeven ofensiva deve ser intrusive no catálogo.
  assert.equal(classifyAutoModule('frameseven_active', { class: 'intrusive', intrusive: true }), 'intrusive');
  assert.equal(classifyAutoModule('frameseven_recon', { class: 'active' }), 'active');
  assert.equal(isIntrusive('sqlmap'), true);

  assert.deepEqual(divergences, [], divergences.join('\n'));
});
