import test from 'node:test';
import assert from 'node:assert/strict';

import {
  evaluateRestrictedFunctionSource,
  extractRestrictedFunctions,
} from '../modules/restricted-js-evaluator.mjs';
import {
  analyzeDeterministicVoucherSource,
  runDeterministicVoucherAudit,
} from '../modules/deterministic-voucher-audit.mjs';

const FIXTURE = `
<form><input name="voucher"><button>Redeem Gift Card</button></form>
<script>
function generateGiftCode() {
  const table = {
    "v": "3", "u": "1", "l": "2", "n": "a",
    "c": "9", "a": "7", "r": "5", "t": "a"
  };
  const seed = "vulncart";
  let out = "";
  for (let c of seed) out += table[c];
  out += "994e";
  return "GIFT-" + out;
}
fetch("/api/v1/payments/giftcard", { method: "POST" });
</script>`;

test('interpretador restrito deriva a função constante da fixture sem executar JS', () => {
  const functions = extractRestrictedFunctions(FIXTURE);
  assert.equal(functions.length, 1);
  const result = evaluateRestrictedFunctionSource(functions[0].source);
  assert.equal(result.ok, true);
  assert.equal(result.value, 'GIFT-312a975a994e');
  assert.ok(result.steps > 0);
});

test('módulo confirma voucher, mas finding nunca contém o valor bruto', async () => {
  const result = await runDeterministicVoucherAudit({
    sources: [{ url: 'https://shop.test/payment', source: FIXTURE }],
  });
  assert.equal(result.metrics.confirmed, 1);
  assert.equal(result.findings.length, 1);
  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes('GIFT-312a975a994e'), false);
  assert.match(serialized, /sha256:/);
  assert.match(result.findings[0].meta, /raw_value_stored=false/);
});

test('aleatoriedade/chamada não suportada fica candidate e nunca é executada', () => {
  globalThis.__voucherAuditCanary = 0;
  const source = `
    <div>Gift Card voucher</div>
    function generateGiftCode() {
      globalThis.__voucherAuditCanary += 1;
      return "GIFT-" + crypto.getRandomValues(new Uint32Array(1))[0];
    }
  `;
  const analyses = analyzeDeterministicVoucherSource({ source, url: 'https://shop.test/' });
  assert.equal(analyses.length, 1);
  assert.equal(analyses[0].classification, 'candidate');
  assert.equal(globalThis.__voucherAuditCanary, 0);
  delete globalThis.__voucherAuditCanary;
});

test('placeholder não é confirmado e função sem contexto de negócio permanece candidate', () => {
  const placeholder = analyzeDeterministicVoucherSource({
    source: 'function giftCode(){ return "GIFT-XXXX"; }',
    url: 'https://shop.test/example.js',
  });
  assert.equal(placeholder[0].classification, 'candidate');

  const dead = analyzeDeterministicVoucherSource({
    source: 'function generateCode(){ return "GIFT-12345678"; }',
    url: 'https://shop.test/example.js',
  });
  assert.equal(dead[0].classification, 'candidate');
});

test('limite de iteração falha fechado', () => {
  const longSeed = 'a'.repeat(1_001);
  const result = evaluateRestrictedFunctionSource(`
    function giftCode(){
      const table = {"a":"b"};
      const seed = "${longSeed}";
      let out = "";
      for (let c of seed) out += table[c];
      return "GIFT-" + out;
    }
  `);
  assert.equal(result.ok, false);
  assert.match(result.reason, /limit/i);
});
