/**
 * Inbound webhooks — endpoint HTTP que recebe eventos de ferramentas externas
 * (subfinder, amass, nuclei, dnsx, custom cron scripts) e funde no próximo run.
 *
 * Registrar no server/index.js:
 *   import { registerInboundWebhooks } from './modules/inbound-webhooks.js';
 *   registerInboundWebhooks(app);
 *
 * Segurança:
 *   - HMAC-SHA256: header `x-ghostrecon-signature: sha256=<hex>` (opcional, mas
 *     recomendado). Chaves em GHOSTRECON_INBOUND_KEYS="source1:key1,source2:key2".
 *     Se não houver key configurada para a source, o endpoint rejeita.
 *   - Rate-limit por IP (re-uso do reconRateLimitConfig se disponível — senão 60/min).
 *
 * Storage:
 *   - Eventos persistidos em `.ghostrecon-inbound/<source>/<target>.ndjson`.
 *   - Função `consumeInboundForTarget(target, { clear })` devolve eventos
 *     acumulados para merge no próximo run.
 *
 * Formatos suportados (auto-detectados):
 *   - Subfinder JSON: [{ host: "x.example.com" }]
 *   - Amass: { "name": "x.example.com", ... }
 *   - Nuclei: { "template-id": "...", "matched-at": "https://...", "severity": "high" }
 *   - Custom: { subdomain?, url?, finding?, severity?, source?, target? }
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

const STORAGE_DIR = () =>
  path.resolve(process.cwd(), process.env.GHOSTRECON_INBOUND_DIR || '.ghostrecon-inbound');

function loadInboundKeys() {
  const raw = String(process.env.GHOSTRECON_INBOUND_KEYS || '').trim();
  const out = new Map();
  if (!raw) return out;
  for (const part of raw.split(',')) {
    const s = part.trim();
    if (!s) continue;
    const i = s.indexOf(':');
    if (i <= 0) continue;
    out.set(s.slice(0, i).trim().toLowerCase(), s.slice(i + 1).trim());
  }
  return out;
}

function verifySignature(rawBody, secret, headerValue) {
  if (!secret || !headerValue) return false;
  const hmac = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  const expected = `sha256=${hmac}`;
  const provided = String(headerValue).trim();
  const a = Buffer.from(expected);
  const b = Buffer.from(provided);
  if (a.length !== b.length) return false;
  try { return crypto.timingSafeEqual(a, b); } catch { return false; }
}

/**
 * Normaliza um evento externo para formato interno.
 * Retorna { kind, target, host, url, severity, raw, source, at } ou null.
 */
export function normalizeInboundEvent(source, body) {
  if (!body || typeof body !== 'object') return null;
  const src = String(source || '').toLowerCase();
  const at = new Date().toISOString();

  // Nuclei
  if (body['template-id'] || body.template || body['matched-at']) {
    const url = body['matched-at'] || body.matched || body.host || '';
    return {
      kind: 'finding',
      source: src || 'nuclei',
      target: body.target || extractHost(url) || '',
      host: extractHost(url),
      url,
      severity: (body.info?.severity || body.severity || 'info').toLowerCase(),
      title: body.info?.name || body['template-id'] || 'nuclei match',
      raw: body,
      at,
    };
  }

  // Subfinder (string or array)
  if (typeof body.host === 'string' && !body['template-id']) {
    return { kind: 'subdomain', source: src || 'subfinder', target: body.root || apex(body.host), host: body.host.toLowerCase(), url: null, severity: null, raw: body, at };
  }
  // Amass
  if (typeof body.name === 'string' && typeof body.addresses !== 'undefined') {
    return { kind: 'subdomain', source: src || 'amass', target: body.root || apex(body.name), host: body.name.toLowerCase(), url: null, severity: null, raw: body, at };
  }
  // Custom generic
  if (body.subdomain) {
    return { kind: 'subdomain', source: src || 'custom', target: body.target || apex(body.subdomain), host: String(body.subdomain).toLowerCase(), url: null, severity: null, raw: body, at };
  }
  if (body.url || body.finding) {
    return {
      kind: 'finding',
      source: src || 'custom',
      target: body.target || extractHost(body.url) || '',
      host: extractHost(body.url),
      url: body.url || null,
      severity: String(body.severity || 'info').toLowerCase(),
      title: body.title || body.finding || 'inbound finding',
      raw: body,
      at,
    };
  }
  return null;
}

function extractHost(u) {
  if (!u) return null;
  try {
    if (String(u).includes('://')) return new URL(String(u)).hostname.toLowerCase();
    return String(u).split('/')[0].split(':')[0].toLowerCase();
  } catch { return null; }
}
function apex(host) {
  const parts = String(host || '').toLowerCase().split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  return parts.slice(-2).join('.');
}

async function appendEvent(evt) {
  if (!evt?.target) return;
  const dir = path.join(STORAGE_DIR(), slug(evt.source));
  await fs.mkdir(dir, { recursive: true });
  const file = path.join(dir, `${slug(evt.target)}.ndjson`);
  await fs.appendFile(file, `${JSON.stringify(evt)}\n`, 'utf8');
}
function slug(s) {
  return String(s || '')
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '_')
    .slice(0, 120);
}

/**
 * Retorna todos os eventos acumulados para um target (de todas as sources).
 * Se `clear=true`, trunca os ficheiros após leitura.
 */
export async function consumeInboundForTarget(target, { clear = false } = {}) {
  const events = [];
  const root = STORAGE_DIR();
  let sources;
  try { sources = await fs.readdir(root, { withFileTypes: true }); } catch { return events; }
  for (const e of sources) {
    if (!e.isDirectory()) continue;
    const file = path.join(root, e.name, `${slug(target)}.ndjson`);
    try {
      const raw = await fs.readFile(file, 'utf8');
      for (const line of raw.split(/\r?\n/)) {
        if (!line.trim()) continue;
        try { events.push(JSON.parse(line)); } catch { /* skip */ }
      }
      if (clear) await fs.writeFile(file, '', 'utf8');
    } catch { /* sem eventos para este source */ }
  }
  events.sort((a, b) => String(a.at).localeCompare(String(b.at)));
  return events;
}

/**
 * Express middleware factory. Monta POST /api/inbound/:source e
 * GET /api/inbound/:source/:target (lista eventos).
 */
export function registerInboundWebhooks(app, { pathPrefix = '/api/inbound' } = {}) {
  const keys = loadInboundKeys();

  // raw body parser necessário para HMAC — só para esta rota
  const rawBodyMiddleware = (req, res, next) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      req._rawBody = Buffer.concat(chunks);
      try { req.body = req._rawBody.length ? JSON.parse(req._rawBody.toString('utf8')) : {}; }
      catch { req.body = {}; }
      next();
    });
    req.on('error', next);
  };

  app.post(`${pathPrefix}/:source`, rawBodyMiddleware, async (req, res) => {
    const source = String(req.params.source || '').toLowerCase();
    if (!source || source.length > 40) return res.status(400).json({ ok: false, error: 'source inválida' });

    const secret = keys.get(source);
    if (!secret) return res.status(401).json({ ok: false, error: 'source não configurada' });

    const sig = req.headers['x-ghostrecon-signature'];
    if (!verifySignature(req._rawBody, secret, sig)) {
      return res.status(403).json({ ok: false, error: 'assinatura inválida' });
    }

    // Aceita objeto único ou array
    const payload = Array.isArray(req.body) ? req.body : [req.body];
    const accepted = [];
    for (const item of payload) {
      const evt = normalizeInboundEvent(source, item);
      if (!evt) continue;
      await appendEvent(evt);
      accepted.push({ kind: evt.kind, target: evt.target, host: evt.host, url: evt.url });
    }
    return res.json({ ok: true, accepted: accepted.length, events: accepted.slice(0, 50) });
  });

  app.get(`${pathPrefix}/:source/:target`, async (req, res) => {
    // leitura não requer HMAC (não expõe nada sensível além do que a ferramenta já enviou)
    // mas exigimos header Authorization: Bearer <key da source>
    const source = String(req.params.source || '').toLowerCase();
    const target = String(req.params.target || '').toLowerCase();
    const secret = keys.get(source);
    if (!secret) return res.status(401).json({ ok: false, error: 'source não configurada' });
    const bearer = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
    if (bearer !== secret) return res.status(403).json({ ok: false, error: 'token inválido' });
    const events = await consumeInboundForTarget(target);
    res.json({ ok: true, count: events.length, events });
  });
}
