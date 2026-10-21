/**
 * Achados de configuração de cabeçalhos (orientação a hardening / superfície).
 * A análise descreve somente a resposta observada; não comprova comportamento
 * efetivo do navegador, impacto ou explorabilidade.
 */

const MAX_POLICY_CHARS = 32_768;
const MAX_HEADER_CHARS = 8_192;
const MAX_TOTAL_HEADER_CHARS = 131_072;
const MAX_HEADER_VALUES = 16;
const MAX_CSP_POLICIES = 16;
const MAX_CSP_DIRECTIVES = 256;
const MAX_CSP_TOKENS = 512;
const INVALID_CONTROLS = /[\0\r\n]/;

const CSP_CONFIG = Object.freeze({
  enforce: {
    header: 'Content-Security-Policy',
    keys: ['contentSecurityPolicies', 'contentSecurityPolicy', 'content-security-policy'],
  },
  'report-only': {
    header: 'Content-Security-Policy-Report-Only',
    keys: [
      'contentSecurityPolicyReportOnlyPolicies',
      'contentSecurityPoliciesReportOnly',
      'contentSecurityPolicyReportOnly',
      'content-security-policy-report-only',
    ],
  },
});

const REFERRER_POLICIES = new Set([
  'no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin',
  'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url',
]);

const CSP_FETCH_DIRECTIVES = new Set([
  'default-src', 'child-src', 'connect-src', 'font-src', 'frame-src', 'img-src',
  'manifest-src', 'media-src', 'object-src', 'prefetch-src', 'script-src',
  'script-src-elem', 'style-src', 'style-src-elem', 'worker-src',
]);

function hasOwn(value, key) {
  return Boolean(value && Object.prototype.hasOwnProperty.call(value, key));
}

function selectInput(snap, keys) {
  if (!snap || typeof snap !== 'object' || Array.isArray(snap)) return { input: undefined, key: keys[0] };
  for (const key of keys) {
    if (!hasOwn(snap, key) || snap[key] == null) continue;
    if (Array.isArray(snap[key]) && snap[key].length === 0) continue;
    return { input: snap[key], key };
  }
  return { input: undefined, key: keys[0] };
}

function normalizeValues(input, { maxChars = MAX_HEADER_CHARS, sourceKey = '' } = {}) {
  if (input == null) {
    return { observed: false, values: [], rejected: [], incomplete: false, sourceKey };
  }
  const source = Array.isArray(input) ? input : [input];
  const values = [];
  const rejected = [];
  let observed = false;
  let incomplete = source.length > MAX_HEADER_VALUES;
  let total = 0;
  if (incomplete) rejected.push({ code: 'too_many_header_values', count: source.length });

  for (let index = 0; index < Math.min(source.length, MAX_HEADER_VALUES); index += 1) {
    const raw = source[index];
    if (typeof raw !== 'string') {
      observed = true;
      incomplete = true;
      rejected.push({ code: 'invalid_header_value_type', index });
      continue;
    }
    const text = raw.trim();
    if (!text) continue;
    observed = true;
    if (text.length > maxChars || INVALID_CONTROLS.test(text)) {
      incomplete = true;
      rejected.push({ code: text.length > maxChars ? 'header_value_too_large' : 'invalid_control_character', index });
      continue;
    }
    total += text.length;
    if (total > MAX_TOTAL_HEADER_CHARS) {
      incomplete = true;
      rejected.push({ code: 'header_values_total_too_large', index });
      break;
    }
    values.push(text);
  }
  return { observed, values, rejected, incomplete, sourceKey };
}

function field(snap, keys, maxChars = MAX_HEADER_CHARS) {
  const selected = selectInput(snap, keys);
  return normalizeValues(selected.input, { maxChars, sourceKey: selected.key });
}

function parseCspPolicy(raw, context) {
  const directives = new Map();
  const duplicates = [];
  const malformed = [];
  const parts = raw.split(';');
  let incomplete = parts.length > MAX_CSP_DIRECTIVES;

  for (let index = 0; index < Math.min(parts.length, MAX_CSP_DIRECTIVES); index += 1) {
    const part = parts[index].trim();
    if (!part) continue;
    const match = part.match(/^([a-zA-Z0-9-]+)(?:[\t ]+([\s\S]*))?$/);
    if (!match) {
      malformed.push({ index, code: 'malformed_directive' });
      continue;
    }
    const name = match[1].toLowerCase();
    if (directives.has(name)) {
      duplicates.push(name);
      continue;
    }
    const valueText = String(match[2] || '').trim();
    const values = valueText ? valueText.split(/[\t ]+/).filter(Boolean) : [];
    if (values.length > MAX_CSP_TOKENS) {
      malformed.push({ index, name, code: 'too_many_directive_tokens' });
      incomplete = true;
      continue;
    }
    directives.set(name, {
      name,
      values,
      // Preserva nonces/hashes no valor original; minúsculas só para checks exatos.
      normalizedValues: values.map((value) => value.toLowerCase()),
    });
  }
  return {
    ...context,
    directives,
    duplicates: [...new Set(duplicates)],
    malformed,
    incomplete,
  };
}

function collectCsp(input, disposition, sourceKey = '') {
  const normalized = normalizeValues(input, { maxChars: MAX_POLICY_CHARS, sourceKey });
  const policies = [];
  const rejected = [...normalized.rejected];
  let incomplete = normalized.incomplete;
  let policyIndex = 0;

  for (let headerValueIndex = 0; headerValueIndex < normalized.values.length; headerValueIndex += 1) {
    // CSP usa uma lista serializada; vírgula literal não pertence ao valor
    // ABNF de diretiva e separa camadas cumulativas.
    for (const serialized of normalized.values[headerValueIndex].split(',')) {
      const raw = serialized.trim();
      if (!raw) {
        rejected.push({ code: 'empty_serialized_policy', headerValueIndex });
        continue;
      }
      if (policyIndex >= MAX_CSP_POLICIES) {
        rejected.push({ code: 'too_many_csp_policies' });
        incomplete = true;
        break;
      }
      const policy = parseCspPolicy(raw, {
        disposition,
        policyIndex,
        headerValueIndex,
        sourceKey: normalized.sourceKey,
      });
      policies.push(policy);
      if (policy.incomplete) incomplete = true;
      policyIndex += 1;
    }
    if (policyIndex >= MAX_CSP_POLICIES) break;
  }

  return {
    disposition,
    header: CSP_CONFIG[disposition].header,
    observed: normalized.observed,
    policies,
    usablePolicies: policies.filter((policy) => policy.directives.size > 0),
    rejected,
    incomplete,
  };
}

function cspSnapshot(snap) {
  const enforced = selectInput(snap, CSP_CONFIG.enforce.keys);
  const reportOnly = selectInput(snap, CSP_CONFIG['report-only'].keys);
  return {
    enforce: collectCsp(enforced.input, 'enforce', enforced.key),
    reportOnly: collectCsp(reportOnly.input, 'report-only', reportOnly.key),
  };
}

function getDirective(policy, names) {
  for (const name of names) {
    if (policy.directives.has(name)) return policy.directives.get(name);
  }
  return null;
}

function validFrameSource(source) {
  const value = source.toLowerCase();
  if (value === "'self'" || value === '*') return true;
  if (value.startsWith("'") || value.endsWith("'")) return false;
  if (/^[a-z][a-z0-9+.-]*:$/.test(value)) return true;
  return /^(?:[a-z][a-z0-9+.-]*:\/\/)?(?:\*\.)?(?:\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::(?:\*|\d+))?(?:\/[^\s]*)?$/i.test(source);
}

function hasUsableFrameAncestors(policy) {
  const value = policy.directives.get('frame-ancestors');
  if (!value || value.values.length === 0) return false;
  if (value.normalizedValues.includes("'none'")) return value.values.length === 1;
  // `frame-ancestors *` e fontes apenas por esquema não restringem um site
  // atacante HTTPS de forma útil; são declarações válidas, mas não uma
  // proteção anti-framing que possamos afirmar a partir do header.
  if (value.normalizedValues.includes('*')) return false;
  if (value.normalizedValues.some((source) => /^[a-z][a-z0-9+.-]*:$/.test(source))) return false;
  return value.values.every(validFrameSource);
}

function inspectSingleton(snap, keys, validate) {
  const observed = field(snap, keys);
  if (!observed.observed) return { state: 'absent', field: observed };
  if (observed.incomplete || observed.values.length !== 1 || observed.values[0].includes(',')) {
    return { state: 'unknown', field: observed };
  }
  return { state: validate(observed.values[0]) ? 'declared' : 'invalid', field: observed };
}

function inspectHsts(snap) {
  const observed = field(snap, [
    'strictTransportSecurityValues', 'strictTransportSecurity', 'strict-transport-security',
  ]);
  if (!observed.observed) return { state: 'absent' };
  if (observed.incomplete || observed.values.length !== 1 || observed.values[0].includes(',')) {
    return { state: 'unknown' };
  }
  const maxAges = observed.values[0].split(';')
    .map((part) => part.trim().match(/^max-age\s*=\s*(\d+)$/i))
    .filter(Boolean)
    .map((match) => match[1]);
  if (maxAges.length !== 1 || !/[1-9]/.test(maxAges[0])) return { state: 'ineffective' };
  return { state: 'declared' };
}

function inspectFrame(snap, csp) {
  if (csp.enforce.usablePolicies.some(hasUsableFrameAncestors)) {
    return { state: 'declared', source: 'content-security-policy' };
  }
  const xfo = inspectSingleton(
    snap,
    ['xFrameOptionsValues', 'xFrameOptions', 'x-frame-options'],
    (value) => /^(?:DENY|SAMEORIGIN)$/i.test(value),
  );
  if (xfo.state === 'declared') return { state: 'declared', source: 'x-frame-options' };
  if (csp.enforce.incomplete || xfo.state === 'unknown') return { state: 'unknown', source: null };
  return { state: 'absent', source: null };
}

function inspectNosniff(snap) {
  return inspectSingleton(
    snap,
    ['xContentTypeOptionsValues', 'xContentTypeOptions', 'x-content-type-options'],
    (value) => value.toLowerCase() === 'nosniff',
  );
}

function inspectReferrer(snap) {
  const observed = field(snap, ['referrerPolicyValues', 'referrerPolicy', 'referrer-policy']);
  if (!observed.observed) return { state: 'absent', selected: null };
  if (observed.incomplete) return { state: 'unknown', selected: null };
  const tokens = observed.values.flatMap((value) => value.split(','))
    .map((value) => value.trim().toLowerCase()).filter(Boolean);
  if (tokens.length > MAX_HEADER_VALUES * 4) return { state: 'unknown', selected: null };
  let selected = null;
  // O navegador escolhe o último token reconhecido da lista observada.
  for (const token of tokens) if (REFERRER_POLICIES.has(token)) selected = token;
  return { state: selected ? 'declared' : 'invalid', selected };
}

function provenance(header, disposition = undefined) {
  return {
    source: 'http_response_header_snapshot',
    scope: 'single_observed_response',
    header,
    ...(disposition ? { disposition } : {}),
    browserBehaviorVerified: false,
  };
}

function observation(text, score, {
  code,
  header,
  disposition,
  analysisStatus = 'complete',
  details,
} = {}) {
  return {
    text,
    prio: score >= 30 ? 'low' : 'info',
    score,
    diagnosticCode: code,
    header,
    ...(disposition ? { disposition } : {}),
    analysisStatus,
    ...(details ? { details } : {}),
    evidenceStatus: 'configuration_observation',
    impactTested: false,
    provenance: provenance(header, disposition),
  };
}

function isHttpsUrl(url) {
  if (typeof url !== 'string' || url.length > 4_096) return false;
  try { return new URL(url).protocol.toLowerCase() === 'https:'; } catch { return false; }
}

function parserDiagnostics(collection) {
  const out = [];
  if (collection.incomplete) {
    out.push(observation(`${collection.header} observada, mas a análise ficou incompleta por limite ou formato`, 16, {
      code: 'csp_analysis_incomplete',
      header: collection.header,
      disposition: collection.disposition,
      analysisStatus: 'partial',
    }));
  }
  const duplicates = [...new Set(collection.policies.flatMap((policy) => policy.duplicates))].slice(0, 16);
  if (duplicates.length) {
    out.push(observation(`${collection.header} contém diretiva duplicada; somente a primeira ocorrência foi considerada`, 18, {
      code: 'csp_duplicate_directive',
      header: collection.header,
      disposition: collection.disposition,
      details: { directives: duplicates },
    }));
  }
  const malformed = collection.policies.reduce((count, policy) => count + policy.malformed.length, 0);
  if (malformed) {
    out.push(observation(`${collection.header} contém diretiva com sintaxe não reconhecida`, 18, {
      code: 'csp_malformed_directive',
      header: collection.header,
      disposition: collection.disposition,
      details: { count: Math.min(malformed, MAX_CSP_DIRECTIVES) },
    }));
  }
  return out;
}

/** Analisa headers observados na resposta final. */
export function analyzeSecurityHeaders(pageUrl, snap) {
  if (!snap || typeof snap !== 'object' || Array.isArray(snap)) return [];
  const out = [];
  const csp = cspSnapshot(snap);

  if (isHttpsUrl(pageUrl)) {
    const hsts = inspectHsts(snap);
    if (hsts.state === 'absent' || hsts.state === 'ineffective') {
      out.push(observation('Strict-Transport-Security (HSTS) ausente ou inefetivo', 28, {
        code: 'hsts_absent_or_ineffective', header: 'Strict-Transport-Security',
      }));
    } else if (hsts.state === 'unknown') {
      out.push(observation('Strict-Transport-Security (HSTS) observada, mas ambígua ou não analisável', 16, {
        code: 'hsts_analysis_incomplete', header: 'Strict-Transport-Security', analysisStatus: 'partial',
      }));
    }
  }

  if (!csp.enforce.observed) {
    const onlyReport = csp.reportOnly.usablePolicies.length > 0;
    out.push(observation(
      onlyReport
        ? 'Nenhuma Content-Security-Policy aplicada foi observada; somente Report-Only foi declarada'
        : 'Sem Content-Security-Policy aplicada observada',
      24,
      {
        code: onlyReport ? 'csp_report_only_without_enforced_policy' : 'csp_enforced_policy_not_observed',
        header: 'Content-Security-Policy',
        disposition: 'enforce',
        ...(onlyReport ? { details: { reportOnlyPolicyCount: csp.reportOnly.usablePolicies.length } } : {}),
      },
    ));
  } else if (!csp.enforce.usablePolicies.length && !csp.enforce.incomplete) {
    out.push(observation('Content-Security-Policy aplicada observada, mas sem diretiva analisável', 20, {
      code: 'csp_without_analyzable_directive', header: 'Content-Security-Policy', disposition: 'enforce',
    }));
  }
  out.push(...parserDiagnostics(csp.enforce), ...parserDiagnostics(csp.reportOnly));

  const frame = inspectFrame(snap, csp);
  if (frame.state === 'absent') {
    out.push(observation('Sem proteção aplicada declarada por X-Frame-Options ou CSP frame-ancestors', 26, {
      code: 'frame_protection_not_observed',
      header: 'X-Frame-Options / Content-Security-Policy',
      disposition: 'enforce',
    }));
  } else if (frame.state === 'unknown') {
    out.push(observation('Proteção de frame não pôde ser determinada nos headers observados', 16, {
      code: 'frame_protection_analysis_incomplete',
      header: 'X-Frame-Options / Content-Security-Policy',
      disposition: 'enforce',
      analysisStatus: 'partial',
    }));
  }

  const nosniff = inspectNosniff(snap);
  if (nosniff.state === 'absent' || nosniff.state === 'invalid') {
    out.push(observation('X-Content-Type-Options: nosniff ausente ou inefetivo', 22, {
      code: 'nosniff_absent_or_ineffective', header: 'X-Content-Type-Options',
    }));
  } else if (nosniff.state === 'unknown') {
    out.push(observation('X-Content-Type-Options observada, mas ambígua ou não analisável', 14, {
      code: 'nosniff_analysis_incomplete', header: 'X-Content-Type-Options', analysisStatus: 'partial',
    }));
  }

  const referrer = inspectReferrer(snap);
  if (referrer.state === 'absent' || referrer.state === 'invalid') {
    out.push(observation('Referrer-Policy reconhecida não observada', 18, {
      code: 'referrer_policy_not_observed', header: 'Referrer-Policy',
    }));
  } else if (referrer.state === 'unknown') {
    out.push(observation('Referrer-Policy observada, mas não analisável dentro dos limites', 14, {
      code: 'referrer_policy_analysis_incomplete', header: 'Referrer-Policy', analysisStatus: 'partial',
    }));
  }

  return out.slice(0, 24);
}

function weakness(text, score, issue, collection, options = {}) {
  const reportOnly = collection.disposition === 'report-only';
  const finalScore = reportOnly ? Math.min(score, 18) : score;
  return {
    text,
    prio: finalScore >= 30 ? 'low' : 'info',
    score: finalScore,
    issue,
    disposition: collection.disposition,
    enforced: !reportOnly,
    ...(options.policy ? { policyIndex: options.policy.policyIndex } : {}),
    ...(options.sourceDirective ? { sourceDirective: options.sourceDirective } : {}),
    analysisStatus: options.analysisStatus || 'complete',
    effectAssessment: 'not_inferred_from_header_observation',
    ...(options.details ? { details: options.details } : {}),
    evidenceStatus: 'configuration_observation',
    impactTested: false,
    provenance: provenance(collection.header, collection.disposition),
  };
}

function analyzeCollection(collection) {
  if (!collection.observed) return [];
  const out = [];
  if (collection.incomplete) {
    out.push(weakness(`${collection.header} observada, mas não analisada integralmente por limite ou formato`, 16,
      'analysis-incomplete', collection, { analysisStatus: 'partial' }));
  }
  for (const policy of collection.policies) {
    const label = `${collection.disposition === 'report-only' ? 'CSP Report-Only' : 'CSP aplicada'} #${policy.policyIndex + 1}`;
    const script = getDirective(policy, ['script-src', 'default-src']);
    const element = getDirective(policy, ['script-src-elem', 'script-src', 'default-src']);
    const attribute = getDirective(policy, ['script-src-attr', 'script-src', 'default-src']);
    const inline = [...new Map([element, attribute].filter(Boolean).map((entry) => [entry.name, entry])).values()];
    const unsafeInline = inline.find((entry) => entry.normalizedValues.includes("'unsafe-inline'"));
    if (unsafeInline) out.push(weakness(`${label} declara 'unsafe-inline' para scripts`, 32, 'unsafe-inline', collection,
      { policy, sourceDirective: unsafeInline.name }));
    if (script?.normalizedValues.includes("'unsafe-eval'")) {
      out.push(weakness(`${label} declara 'unsafe-eval' para scripts`, 34, 'unsafe-eval', collection,
        { policy, sourceDirective: script.name }));
    }
    if (element?.normalizedValues.includes('*')) {
      out.push(weakness(`${label} declara wildcard (*) para carregamento de scripts`, 32, 'wildcard-src', collection,
        { policy, sourceDirective: element.name }));
    }
    if (element?.normalizedValues.includes('data:')) {
      out.push(weakness(`${label} declara data: para carregamento de scripts`, 30, 'data-script', collection,
        { policy, sourceDirective: element.name }));
    }
    const httpSource = [...policy.directives.values()].some((entry) => CSP_FETCH_DIRECTIVES.has(entry.name)
      && entry.normalizedValues.some((value) => /^http:(?:$|\/\/)/.test(value)));
    if (httpSource && !policy.directives.has('upgrade-insecure-requests')) {
      out.push(weakness(`${label} referencia fonte http: sem upgrade-insecure-requests na mesma camada`, 28,
        'mixed-in-csp', collection, { policy }));
    }
    if (policy.duplicates.length) {
      out.push(weakness(`${label} possui diretiva duplicada; ocorrências posteriores não foram usadas`, 18,
        'duplicate-directive', collection, { policy, details: { directives: policy.duplicates.slice(0, 16) } }));
    }
    if (policy.malformed.length) {
      out.push(weakness(`${label} possui diretiva com sintaxe não reconhecida`, 18,
        'malformed-directive', collection, { policy, details: { count: policy.malformed.length } }));
    }
  }
  if (collection.usablePolicies.length && !collection.usablePolicies.some(hasUsableFrameAncestors)) {
    out.push(weakness(`${collection.header} não declara frame-ancestors utilizável nas camadas observadas`, 24,
      'no-frame-ancestors', collection));
  }
  return out.slice(0, 48);
}

/**
 * Analisa CSP aplicada (string/array) ou snapshot completo, distinguindo
 * Content-Security-Policy de Content-Security-Policy-Report-Only.
 */
export function analyzeCspWeaknesses(cspInput, options = {}) {
  if (cspInput && typeof cspInput === 'object' && !Array.isArray(cspInput)) {
    const csp = cspSnapshot(cspInput);
    return [...analyzeCollection(csp.enforce), ...analyzeCollection(csp.reportOnly)].slice(0, 64);
  }
  const disposition = options.disposition === 'report-only' ? 'report-only' : 'enforce';
  return analyzeCollection(collectCsp(cspInput, disposition, 'direct_input'));
}

const PERMISSIONS_POLICY_SENSITIVE = [
  'camera', 'microphone', 'geolocation', 'payment', 'usb', 'interest-cohort',
];

export function analyzePermissionsPolicyGaps(snap) {
  const pp = field(snap, ['permissionsPolicyValues', 'permissionsPolicy', 'permissions-policy'], MAX_POLICY_CHARS);
  if (pp.observed && !pp.incomplete && pp.values.length) return [];
  if (pp.observed) {
    return [observation('Permissions-Policy observada, mas não analisável dentro dos limites', 14, {
      code: 'permissions_policy_analysis_incomplete', header: 'Permissions-Policy', analysisStatus: 'partial',
    })];
  }
  return [{
    ...observation('Permissions-Policy não observada — restrições explícitas não puderam ser inventariadas', 18, {
      code: 'permissions_policy_not_observed', header: 'Permissions-Policy',
    }),
    missing: PERMISSIONS_POLICY_SENSITIVE,
  }];
}

function controlStates(snap) {
  const csp = cspSnapshot(snap);
  const cspState = csp.enforce.usablePolicies.length ? 'present' : csp.enforce.observed ? 'unknown' : 'missing';
  const frame = inspectFrame(snap, csp);
  const nosniff = inspectNosniff(snap);
  const referrer = inspectReferrer(snap);
  const state = (item) => item.state === 'declared' ? 'present' : item.state === 'unknown' ? 'unknown' : 'missing';
  return [
    { label: 'Content-Security-Policy aplicada', state: cspState },
    { label: 'X-Frame-Options / frame-ancestors aplicado', state: state(frame) },
    { label: 'X-Content-Type-Options', state: state(nosniff) },
    { label: 'Referrer-Policy', state: state(referrer) },
  ];
}

function observedHost(url) {
  if (typeof url !== 'string' || url.length > 4_096) return 'unknown';
  try { return new URL(url).hostname.slice(0, 253) || 'unknown'; } catch {
    const value = url.trim();
    return value && value.length <= 253 && !INVALID_CONTROLS.test(value) ? value : 'unknown';
  }
}

export function summarizeSecurityHeaderGaps(pageUrl, snap) {
  if (!snap || typeof snap !== 'object' || Array.isArray(snap)) return null;
  const controls = controlStates(snap);
  const missing = controls.filter((item) => item.state === 'missing').map((item) => item.label);
  const unknown = controls.filter((item) => item.state === 'unknown').map((item) => item.label);
  if (missing.length < 3) return null;
  const clickjackingProtectionGap = controls[0].state === 'missing' && controls[1].state === 'missing';
  return {
    text: `${missing.length} controles de headers não observados (${missing.join(', ')})`,
    prio: missing.length >= 4 ? 'low' : 'info',
    score: missing.length >= 4 ? 32 : 26,
    missing,
    unknown,
    analysisStatus: unknown.length ? 'partial' : 'complete',
    clickjackingRisk: false,
    clickjackingProtectionGap,
    clickjackingValidation: 'not_performed',
    evidenceStatus: 'configuration_observation',
    impactTested: false,
    host: observedHost(pageUrl),
    provenance: provenance('HTTP response security headers'),
  };
}
