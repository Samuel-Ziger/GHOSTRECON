import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

const ROOT = new URL('../', import.meta.url);
const read = (path) => fs.readFile(new URL(path, ROOT), 'utf8');

test('MITRE Live usa reducer e efeitos React sem controller público', async () => {
  const [page, hook, model] = await Promise.all([
    read('src/features/ghostrecon/MitreLivePage.tsx'),
    read('src/features/ghostrecon/useMitreLiveRuntime.ts'),
    read('src/features/ghostrecon/mitreLiveModel.ts'),
  ]);

  assert.doesNotMatch(hook, /mitre-live-runtime\.js/);
  assert.doesNotMatch(page, /dangerouslySetInnerHTML|\.innerHTML\s*=/);
  assert.match(hook, /new BroadcastChannel\(`ghostrecon-mitre-\$\{state\.sessionId\}`\)/);
  assert.match(hook, /ghostrecon_mitre_live_session_id/);
  assert.match(model, /MAX_EVENTS = 200/);
  assert.match(model, /MAX_SEGMENTS = 80/);
  assert.match(hook, /slice\(0, 600\)/);
});

test('componentes React preservam anchors e controles operacionais', async () => {
  const page = await read('src/features/ghostrecon/MitreLivePage.tsx');
  for (const id of [
    'statePill', 'targetLine', 'pipeMilestonesH', 'feedRoot', 'tacticsRoot',
    'branchImportJson', 'branchExportJsonBtn', 'matrixFilterBar', 'jsonLive',
    'projectSecretPeersBar', 'modalBackdrop',
  ]) assert.match(page, new RegExp(`id="${id}"`), id);
  assert.match(page, /<JsonDock/);
  assert.match(page, /<Branches/);
  assert.match(page, /<Matrix/);
  assert.match(page, /<FindingModal/);
});
