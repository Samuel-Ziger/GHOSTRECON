import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

test('dispatcher evita done após AbortError/erro (contrato no fonte)', async () => {
  const src = await fs.readFile(new URL('../pipeline/dispatcher.mjs', import.meta.url), 'utf8');
  assert.match(src, /isAbortLikeError/);
  assert.match(src, /isTimeoutError/);
  assert.match(src, /emitTerminalOutcome\(s, id, 'cancelled'/);
  assert.match(src, /emitTerminalOutcome\(s, id, 'timeout'/);
  assert.match(src, /emitTerminalOutcome\(s, id, 'failed'/);
  assert.match(src, /emitTerminalOutcome\(s, id, 'done'/);
  assert.match(src, /type: 'module_outcome'/);
  const doneIdx = src.indexOf("emitTerminalOutcome(s, id, 'done')");
  const catchIdx = src.indexOf('} catch (e) {');
  assert.ok(doneIdx > 0 && catchIdx > doneIdx, 'done fica no try; catch trata abort/timeout/falha');
  assert.match(src.slice(catchIdx, catchIdx + 500), /throw e/);
  assert.doesNotMatch(src.slice(catchIdx, catchIdx + 500), /emitTerminalOutcome\(s, id, 'done'/);
});
