import { createHash } from 'node:crypto';

import {
  evaluateRestrictedFunctionSource,
  extractRestrictedFunctions,
} from './restricted-js-evaluator.mjs';

export const moduleManifest = {
  id: 'deterministic_voucher_audit',
  name: 'Deterministic Voucher Generator Audit',
  category: 'validation',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 15_000,
  concurrency: 1,
  outputs: ['finding', 'intel', 'metric'],
};

const SEMANTIC_NAME_RE = /(?:gift|voucher|coupon|promo|redeem|token|code)/i;
const BUSINESS_CONTEXT_RE = /(?:gift[ -]?card|voucher|coupon|promo|redeem|payments?\/giftcard|name=["']?voucher)/i;
const PLACEHOLDER_RE = /(?:X{3,}|TODO|PLACEHOLDER|EXAMPLE|CHANGEME)/i;
const TOKEN_SHAPE_RE = /^(?:GIFT|VOUCHER|COUPON|PROMO)-[A-Za-z0-9_-]{6,128}$/i;

function fingerprint(value) {
  return `sha256:${createHash('sha256').update(String(value)).digest('hex')}`;
}

function preview(value) {
  const text = String(value);
  const prefix = text.includes('-') ? `${text.slice(0, text.indexOf('-') + 1)}` : '';
  return `${prefix}…[redacted,length=${text.length}]`;
}

function sourceCallCount(source, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return (String(source).match(new RegExp(`\\b${escaped}\\s*\\(`, 'g')) || []).length;
}

export function analyzeDeterministicVoucherSource({ source = '', url = '' } = {}) {
  const text = String(source || '');
  const hasBusinessContext = BUSINESS_CONTEXT_RE.test(text);
  const analyses = [];

  for (const fn of extractRestrictedFunctions(text)) {
    const semantic = SEMANTIC_NAME_RE.test(fn.name) || /(?:GIFT|VOUCHER|COUPON|PROMO)-/i.test(fn.source);
    if (!semantic) continue;
    const evaluated = evaluateRestrictedFunctionSource(fn.source);
    if (!evaluated.ok) {
      analyses.push({
        classification: 'candidate',
        functionName: fn.name,
        url,
        reason: evaluated.reason,
      });
      continue;
    }
    const value = String(evaluated.value);
    const called = sourceCallCount(text, fn.name) > 1;
    const placeholder = PLACEHOLDER_RE.test(value);
    const validShape = TOKEN_SHAPE_RE.test(value);
    const confirmed = validShape && !placeholder && (hasBusinessContext || called);
    analyses.push({
      classification: confirmed ? 'confirmed' : 'candidate',
      functionName: fn.name,
      url,
      reason: confirmed ? 'constant_only_function_evaluated' : placeholder ? 'placeholder_value' : 'business_context_not_confirmed',
      fingerprint: fingerprint(value),
      preview: preview(value),
      length: value.length,
      steps: evaluated.steps,
    });
  }
  return analyses;
}

export async function runDeterministicVoucherAudit({ sources = [], probeResults = [] } = {}) {
  const normalizedSources = [
    ...(Array.isArray(sources) ? sources : []),
    ...(Array.isArray(probeResults) ? probeResults : []).flatMap((item) => {
      const result = item?.r || item;
      const source = result?.htmlSample || result?.body || '';
      return source ? [{ url: result?.url || item?.url || '', source }] : [];
    }),
  ].slice(0, 128);

  const analyses = normalizedSources.flatMap((item) => analyzeDeterministicVoucherSource({
    source: item?.source ?? item?.body ?? item?.text ?? '',
    url: item?.url || '',
  }));
  const seen = new Set();
  const unique = analyses.filter((analysis) => {
    const key = `${analysis.url}|${analysis.functionName}|${analysis.fingerprint || analysis.reason}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const findings = unique.map((analysis) => {
    const confirmed = analysis.classification === 'confirmed';
    return {
      type: 'deterministic_client_secret',
      prio: confirmed ? 'high' : 'info',
      score: confirmed ? 78 : 22,
      value: confirmed
        ? 'Voucher/token de negócio gerado deterministicamente no cliente'
        : 'Possível gerador determinístico de voucher no cliente',
      meta: [
        'source=deterministic_voucher_audit',
        `classification=${analysis.classification}`,
        `function=${analysis.functionName}`,
        `reason=${analysis.reason}`,
        analysis.fingerprint ? `secret_ref=${analysis.fingerprint}` : '',
        analysis.preview ? `preview=${analysis.preview}` : '',
        'raw_value_stored=false',
      ].filter(Boolean).join(' • '),
      url: analysis.url || undefined,
      secretRef: analysis.fingerprint,
      functionName: analysis.functionName,
    };
  });

  return {
    findings,
    analyses: unique,
    status: normalizedSources.length ? 'done' : 'skipped',
    reason: normalizedSources.length ? undefined : 'no_sources',
    metrics: {
      sources: normalizedSources.length,
      candidates: unique.filter((row) => row.classification === 'candidate').length,
      confirmed: unique.filter((row) => row.classification === 'confirmed').length,
    },
  };
}
