import { createHash } from 'node:crypto';

export const moduleManifest = {
  id: 'sensitive_payment_data',
  name: 'Sensitive Payment Data Impact Classifier',
  category: 'validation',
  intrusive: false,
  requiresAuth: true,
  requiresKali: false,
  timeoutMs: 5_000,
  concurrency: 1,
  outputs: ['finding', 'metric'],
};

const PAN_KEYS = new Set([
  'pan', 'cardnumber', 'creditcardnumber', 'paymentcardnumber', 'primaryaccountnumber',
]);
const CVV_KEYS = new Set([
  'cvv', 'cvc', 'cvv2', 'cvc2', 'cardverificationvalue', 'cardsecuritycode',
]);

function canonical(value) {
  return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function fingerprint(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

function safeUrl(value) {
  try {
    const parsed = new URL(String(value || ''));
    parsed.username = '';
    parsed.password = '';
    parsed.search = '';
    parsed.hash = '';
    return parsed.href;
  } catch {
    return '';
  }
}

function luhn(value) {
  const digits = String(value ?? '').replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19 || /^(\d)\1+$/.test(digits)) return false;
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let digit = Number(digits[i]);
    if (alternate) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

function confirmedUnauthorizedAccess(accessFinding) {
  if (!accessFinding || accessFinding.state !== 'confirmed') return false;
  return /(?:bola|idor|broken_object|unauthori[sz]ed|object_auth)/i.test(
    `${accessFinding.type || ''} ${accessFinding.value || ''}`,
  );
}

function collectPaymentIndicators(value, state, depth = 0) {
  if (depth > 12 || value == null || state.fieldsVisited >= 10_000) return;
  if (Array.isArray(value)) {
    for (const child of value.slice(0, 1_000)) collectPaymentIndicators(child, state, depth + 1);
    return;
  }
  if (typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    state.fieldsVisited += 1;
    if (state.fieldsVisited > 10_000) return;
    const normalized = canonical(key);
    if (PAN_KEYS.has(normalized)) {
      const digits = String(child ?? '').replace(/\D/g, '');
      if (luhn(digits)) {
        const id = fingerprint(digits);
        if (!state.panFingerprints.has(id)) {
          state.panFingerprints.add(id);
          state.pans.push({ fingerprint: id, last4: digits.slice(-4), length: digits.length });
        }
      }
      continue;
    }
    if (CVV_KEYS.has(normalized) && /^\d{3,4}$/.test(String(child ?? '').trim())) {
      state.cvvPresent = true;
      state.cvvCount += 1;
      continue;
    }
    collectPaymentIndicators(child, state, depth + 1);
  }
}

export function analyzeSensitivePaymentData({
  url = '',
  data = null,
  accessFinding = null,
} = {}) {
  if (!confirmedUnauthorizedAccess(accessFinding)) {
    return { state: 'skipped_ineligible', reason: 'unauthorized_access_not_confirmed', findings: [] };
  }
  const state = {
    pans: [], panFingerprints: new Set(), cvvPresent: false, cvvCount: 0, fieldsVisited: 0,
  };
  collectPaymentIndicators(data, state);
  if (!state.pans.length && !state.cvvPresent) {
    return { state: 'executed_no_finding', reason: 'no_valid_payment_data', findings: [] };
  }
  const finding = {
    type: 'sensitive_payment_data_exposed',
    prio: state.cvvPresent ? 'critical' : 'high',
    score: state.cvvPresent ? 98 : 91,
    value: 'Dados sensíveis de pagamento acessíveis após quebra de autorização confirmada',
    meta: [
      'source=sensitive_payment_data',
      'classification=confirmed_impact',
      `pan_count=${state.pans.length}`,
      `cvv_present=${state.cvvPresent}`,
      'cvv_stored=false',
      'raw_pan_stored=false',
    ].join(' • '),
    url: safeUrl(url) || undefined,
    state: 'confirmed',
    paymentEvidence: {
      pans: state.pans,
      cvvPresent: state.cvvPresent,
      cvvCount: state.cvvCount,
    },
  };
  return { state: 'confirmed', reason: 'payment_data_after_confirmed_unauthorized_access', findings: [finding] };
}

export async function runSensitivePaymentData({ observations = [] } = {}) {
  const findings = [];
  const outcomes = [];
  for (const observation of (Array.isArray(observations) ? observations : []).slice(0, 128)) {
    const result = analyzeSensitivePaymentData(observation);
    findings.push(...result.findings);
    outcomes.push({ state: result.state, reason: result.reason, url: safeUrl(observation?.url) });
  }
  return { findings, outcomes, status: 'done', metrics: { observations: outcomes.length, confirmed: findings.length } };
}
