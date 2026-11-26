import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeSensitivePaymentData } from '../modules/sensitive-payment-data.mjs';

const accessFinding = { type: 'bola_fixed_object', state: 'confirmed', value: 'cross object' };

test('classifica PAN Luhn e CVV somente após acesso indevido confirmado, sem raw', () => {
  const result = analyzeSensitivePaymentData({
    url: 'https://lab.invalid/orders/a', accessFinding,
    data: { payment: { card_number: '4111 1111 1111 1111', cvv: '123' } },
  });
  assert.equal(result.findings[0].prio, 'critical');
  assert.equal(result.findings[0].paymentEvidence.pans[0].last4, '1111');
  assert.equal(result.findings[0].paymentEvidence.cvvPresent, true);
  assert.doesNotMatch(JSON.stringify(result), /4111 1111|111111111111|"123"/);
});

test('sem BOLA confirmada, Luhn inválido ou número em order_id não vira impacto', () => {
  assert.equal(analyzeSensitivePaymentData({ data: { card_number: '4111111111111111' } }).findings.length, 0);
  assert.equal(analyzeSensitivePaymentData({ accessFinding, data: { card_number: '4111111111111112' } }).findings.length, 0);
  assert.equal(analyzeSensitivePaymentData({ accessFinding, data: { order_id: '4111111111111111' } }).findings.length, 0);
});
