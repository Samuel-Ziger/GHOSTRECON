import fs from 'fs';
import path from 'path';
import { DATA_DIR, resolveLocalProjectDbDir, sanitizePathSegment } from './db-sqlite.js';

/** Limites de caracteres por campo (prompt + truncagem no servidor). Config: GHOSTRECON_AI_RELATORIO_MAX_CHARS, GHOSTRECON_AI_PROXIMOS_MAX_CHARS */
export function getAiMarkdownCharLimits() {
  const rel = Number(process.env.GHOSTRECON_AI_RELATORIO_MAX_CHARS);
  const prox = Number(process.env.GHOSTRECON_AI_PROXIMOS_MAX_CHARS);
  const maxRel = Number.isFinite(rel) ? Math.min(8000, Math.max(400, rel)) : 2400;
  const maxProx = Number.isFinite(prox) ? Math.min(4000, Math.max(200, prox)) : 1600;
  return { maxRelatorio: maxRel, maxProximos: maxProx };
}

function clampMarkdown(text, max) {
  const s = String(text ?? '');
  if (s.length <= max) return s;
  const cut = Math.max(0, max - 40);
  return `${s.slice(0, cut)}\n\n*(truncado no servidor — limite ${max} caracteres)*`;
}

/** Prompt idêntico para Gemini, OpenRouter e Anthropic direct (system + instrução sobre o JSON). */
export function buildAiSystemPrompt() {
  const { maxRelatorio, maxProximos } = getAiMarkdownCharLimits();
  return `És analista de segurança (bug bounty / pentest defensivo). Recebes UM objeto JSON exportado do framework GHOSTRECON (recon passivo, OSINT, heurísticas).

Regras obrigatórias:
- Baseia-te APENAS no conteúdo do JSON. Não inventes CVEs, versões exactas, URLs que não apareçam, nem explorações "confirmadas" se o dado for só heurística ou passivo.
- Indica claramente quando algo for hipótese ou requer verificação manual.
- Não descrevas passos de exploit automatizado; foca em priorização, verificação e documentação.

Estilo e extensão (obrigatório):
- Sê extremamente conciso e directo ao ponto: prioriza falhas, riscos e superfície de ataque evidenciados no JSON; evita introduções longas e repetição.
- Conta caracteres mentalmente antes de responder.

Formato de resposta (OBRIGATÓRIO):
Responde APENAS com um único objeto JSON válido (sem texto antes ou depois, sem blocos markdown), com exactamente estas chaves:
- "relatorio": string em Markdown — no máximo ${maxRelatorio} caracteres. Síntese seca: achados relevantes por severidade/tipo, notas de risco.
- "proximos_passos": string em Markdown — no máximo ${maxProximos} caracteres. Lista curta e priorizada de verificações manuais seguras.

Idioma: português (Portugal ou Brasil, consistente).`;
}

function buildAiSystemPromptCompact() {
  const { maxRelatorio, maxProximos } = getAiMarkdownCharLimits();
  return `Analisa o JSON do GHOSTRECON e responde APENAS com JSON válido:
{"relatorio":"...","proximos_passos":"..."}.
Regras: usar só dados do JSON, sem inventar, português, conciso.
Limites: relatorio <= ${maxRelatorio} chars; proximos_passos <= ${maxProximos} chars.`;
}

function lmStudioMaxOutputTokensForCtx(nCtx) {
  const req = Number(
    process.env.GHOSTRECON_LMSTUDIO_MAX_OUTPUT_TOKENS ?? process.env.GHOSTRECON_LMSTUDIO_MAX_TOKENS ?? 1024,
  );
  const cap = Math.max(256, nCtx - 1536);
  return Math.max(128, Math.min(req, cap));
}

/**
 * Orçamento conservador de caracteres (JSON + instrução user) para caber no n_ctx do LM Studio.
 * Tokens reais variam; usa margem para system + reasoning.
 */
function lmStudioSafeMaxChars() {
  const nCtx = Math.max(2048, Math.min(262144, Number(process.env.GHOSTRECON_LMSTUDIO_N_CTX || 4096)));
  const maxOut = lmStudioMaxOutputTokensForCtx(nCtx);
  const promptTokBudget = Math.max(256, nCtx - maxOut - 400);
  const est = Math.floor(promptTokBudget * Number(process.env.GHOSTRECON_LMSTUDIO_CHARS_PER_TOKEN || 1.45));
  return Math.max(1200, Math.min(200000, est));
}

const MAX_PAYLOAD_CHARS = 900_000;

function shrinkPayload(obj) {
  let o = JSON.parse(JSON.stringify(obj));
  if (!Array.isArray(o.findings)) o.findings = [];
  let s = JSON.stringify(o);
  while (s.length > MAX_PAYLOAD_CHARS && o.findings.length > 50) {
    const cut = Math.max(50, Math.floor(o.findings.length * 0.85));
    o.findings = o.findings.slice(0, cut);
    o._truncated = { note: 'findings cortados para caber no limite da API', kept: o.findings.length };
    s = JSON.stringify(o);
  }
  if (s.length > MAX_PAYLOAD_CHARS) {
    o.findings = (o.findings || []).slice(0, 100);
    o._truncated = { note: 'truncagem agressiva', kept: o.findings.length };
    s = JSON.stringify(o);
  }
  return { payload: o, json: s };
}

function buildUserContent(jsonString) {
  return `${buildAiSystemPrompt()}

---

Segue o JSON completo do pipeline GHOSTRECON (é o único contexto). Depois da análise, responde só com o objeto JSON com "relatorio" e "proximos_passos".

JSON:
${jsonString}`;
}

function extractJsonObject(text) {
  if (!text || typeof text !== 'string') throw new Error('Resposta vazia');
  let s = text.trim();
  const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) s = fence[1].trim();
  const start = s.indexOf('{');
  const end = s.lastIndexOf('}');
  if (start === -1 || end <= start) throw new Error('JSON não encontrado na resposta');
  s = s.slice(start, end + 1);
  return JSON.parse(s);
}

function parseRetryAfterSeconds(retryAfterHeader) {
  const raw = String(retryAfterHeader ?? '').trim();
  if (!raw) return null;
  const asNumber = Number(raw);
  if (Number.isFinite(asNumber) && asNumber >= 0) {
    return Math.min(180, Math.max(1, Math.ceil(asNumber)));
  }
  const asDate = new Date(raw).getTime();
  if (!Number.isFinite(asDate)) return null;
  const deltaSec = Math.ceil((asDate - Date.now()) / 1000);
  if (!Number.isFinite(deltaSec)) return null;
  return Math.min(180, Math.max(1, deltaSec));
}

function isTransientHttpStatus(status) {
  return [429, 500, 502, 503, 504].includes(Number(status));
}

function isRetryableNetworkError(err) {
  if (!err) return false;
  if (err.name === 'AbortError') return true;
  const msg = String(err.message || err).toLowerCase();
  return (
    msg.includes('etimedout')
    || msg.includes('timed out')
    || msg.includes('econnreset')
    || msg.includes('eai_again')
    || msg.includes('enotfound')
    || msg.includes('socket hang up')
    || msg.includes('network')
    || msg.includes('fetch failed')
  );
}

function computeRetryDelaySec(attempt, { fromApiSec = null, baseSec = 4, maxSec = 90 } = {}) {
  if (Number.isFinite(fromApiSec) && fromApiSec > 0) return Math.min(maxSec, Math.ceil(fromApiSec));
  const exp = baseSec * 2 ** Math.max(0, attempt - 1);
  const jitter = Math.floor(Math.random() * 4);
  return Math.min(maxSec, exp + jitter);
}

/** Extrai segundos sugeridos pela mensagem Gemini ("Please retry in 35.2s"). */
function parseGeminiRetrySeconds(message) {
  const m = String(message).match(/retry in ([\d.]+)\s*s/i);
  if (!m) return null;
  const sec = Math.ceil(parseFloat(m[1], 10));
  if (!Number.isFinite(sec)) return null;
  return Math.min(120, Math.max(3, sec));
}

function formatGeminiHttpError(status, data, model) {
  const raw = String(data?.error?.message || JSON.stringify(data)).trim();
  if (status === 429) {
    if (/limit:\s*0/i.test(raw) || /free_tier.*limit:\s*0/i.test(raw)) {
      return `Quota/cota: o modelo «${model}» não tem pedidos disponíveis no plano grátis da tua conta (limite 0). Define outro modelo em GHOSTRECON_GEMINI_MODEL (ex.: gemini-2.5-flash ou gemini-1.5-flash) ou activa faturação em Google AI Studio. Docs: https://ai.google.dev/gemini-api/docs/rate-limits`;
    }
    return `Rate limit 429 — aguarda e tenta de novo, ou reduz uso / muda de modelo. ${raw.length > 200 ? `${raw.slice(0, 200)}…` : raw}`;
  }
  if (status === 400 && /API key/i.test(raw)) {
    return `Pedido inválido (400): verifica a chave e o nome do modelo «${model}».`;
  }
  return raw.length > 320 ? `${raw.slice(0, 320)}…` : raw;
}

async function callGeminiOnce(userText, apiKey, model) {
  const u = new URL(
    `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
  );
  u.searchParams.set('key', apiKey);
  const res = await fetch(u.toString(), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ role: 'user', parts: [{ text: userText }] }],
      generationConfig: {
        temperature: 0.25,
        maxOutputTokens: 8192,
      },
    }),
    signal: AbortSignal.timeout(180000),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = formatGeminiHttpError(res.status, data, model);
    const err = new Error(`Gemini HTTP ${res.status}: ${detail}`);
    err.geminiStatus = res.status;
    err.geminiRetryAfterSec =
      parseRetryAfterSeconds(res.headers?.get('retry-after'))
      ?? (isTransientHttpStatus(res.status) ? parseGeminiRetrySeconds(data?.error?.message || '') : null);
    throw err;
  }
  const parts = data?.candidates?.[0]?.content?.parts;
  const t = Array.isArray(parts) ? parts.map((p) => p.text || '').join('') : '';
  if (!t) throw new Error('Gemini sem texto na resposta');
  return t;
}

export async function callGemini(userText, apiKey, model) {
  const maxAttempts = Math.max(1, Math.min(6, Number(process.env.GHOSTRECON_GEMINI_MAX_RETRIES || 4)));
  let lastErr;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await callGeminiOnce(userText, apiKey, model);
    } catch (e) {
      lastErr = e;
      const status = e?.geminiStatus;
      const transient = isTransientHttpStatus(status) || isRetryableNetworkError(e);
      if (!transient || attempt >= maxAttempts) throw e;
      const backoff = computeRetryDelaySec(attempt, {
        fromApiSec: e?.geminiRetryAfterSec,
        baseSec: 6,
        maxSec: 120,
      });
      await new Promise((r) => setTimeout(r, backoff * 1000));
    }
  }
  throw lastErr;
}

/** Chat Completions (OpenAI-compatible) na OpenRouter — substitui o segundo relatório que antes usava Anthropic direct. */
async function callOpenRouterOnce(userText, apiKey, model, opts = {}) {
  const system = opts.systemPrompt != null ? opts.systemPrompt : buildAiSystemPrompt();
  const referer = process.env.GHOSTRECON_OPENROUTER_HTTP_REFERER?.trim();
  const title = process.env.GHOSTRECON_OPENROUTER_APP_TITLE?.trim() || 'GHOSTRECON';
  const headers = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${apiKey}`,
  };
  if (referer) headers['HTTP-Referer'] = referer;
  if (title) headers['X-Title'] = title;
  const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model,
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: userText },
      ],
      temperature: 0.25,
      max_tokens: 16384,
    }),
    signal: AbortSignal.timeout(180000),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const raw = String(data?.error?.message || data?.message || JSON.stringify(data));
    const msg = raw.length > 360 ? `${raw.slice(0, 360)}…` : raw;
    const err = new Error(`OpenRouter HTTP ${res.status}: ${msg}`);
    err.openrouterStatus = res.status;
    err.openrouterRetryAfterSec = parseRetryAfterSeconds(res.headers?.get('retry-after'));
    throw err;
  }
  const content = data?.choices?.[0]?.message?.content;
  let t = '';
  if (typeof content === 'string') t = content;
  else if (Array.isArray(content)) {
    t = content.map((p) => (typeof p === 'string' ? p : p?.text || '')).join('');
  }
  if (!t) throw new Error('OpenRouter sem texto na resposta');
  return t;
}

export async function callOpenRouter(userText, apiKey, model, opts = {}) {
  const maxAttempts = Math.max(1, Math.min(6, Number(process.env.GHOSTRECON_OPENROUTER_MAX_RETRIES || 4)));
  let lastErr;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await callOpenRouterOnce(userText, apiKey, model, opts);
    } catch (e) {
      lastErr = e;
      const status = e?.openrouterStatus;
      const transient = isTransientHttpStatus(status) || isRetryableNetworkError(e);
      if (!transient || attempt >= maxAttempts) throw e;
      const backoff = computeRetryDelaySec(attempt, {
        fromApiSec: e?.openrouterRetryAfterSec,
        baseSec: 5,
        maxSec: 120,
      });
      await new Promise((r) => setTimeout(r, backoff * 1000));
    }
  }
  throw lastErr;
}

export async function callClaude(userText, apiKey, model) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model,
      max_tokens: 16384,
      system: buildAiSystemPrompt(),
      messages: [{ role: 'user', content: userText }],
    }),
    signal: AbortSignal.timeout(180000),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const raw = String(data?.error?.message || JSON.stringify(data));
    if (res.status === 400 && /balance|credit|billing|too low/i.test(raw)) {
      throw new Error(
        `Claude HTTP 400: saldo de créditos insuficiente na Anthropic — abre Plans & Billing para comprar créditos ou subscrever plano. https://console.anthropic.com/`,
      );
    }
    const msg = raw.length > 360 ? `${raw.slice(0, 360)}…` : raw;
    throw new Error(`Claude HTTP ${res.status}: ${msg}`);
  }
  const blocks = data?.content;
  const t = Array.isArray(blocks) ? blocks.map((b) => (b.type === 'text' ? b.text : '')).join('') : '';
  if (!t) throw new Error('Claude sem texto na resposta');
  return t;
}

/** OpenAI-compatible local endpoint (LM Studio). */
export async function callLmStudio(userText, model, opts = {}) {
  const system =
    opts.systemPrompt != null ? opts.systemPrompt : buildAiSystemPromptCompact();
  const baseUrl = String(process.env.GHOSTRECON_LMSTUDIO_BASE_URL || 'http://127.0.0.1:1234/v1').trim();
  const apiKey = String(process.env.GHOSTRECON_LMSTUDIO_API_KEY || '').trim();
  const nCtx = Math.max(2048, Math.min(262144, Number(process.env.GHOSTRECON_LMSTUDIO_N_CTX || 4096)));
  const maxTokens = lmStudioMaxOutputTokensForCtx(nCtx);
  const timeoutMs = Math.max(
    30000,
    Math.min(3600000, Number(process.env.GHOSTRECON_LMSTUDIO_TIMEOUT_MS || 900000)),
  );
  const temperature = Number.isFinite(Number(process.env.GHOSTRECON_LMSTUDIO_TEMPERATURE))
    ? Math.max(0, Math.min(2, Number(process.env.GHOSTRECON_LMSTUDIO_TEMPERATURE)))
    : 0.25;
  const headers = { 'Content-Type': 'application/json' };
  if (apiKey) headers.Authorization = `Bearer ${apiKey}`;
  const url = `${baseUrl.replace(/\/$/, '')}/chat/completions`;
  const res = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model,
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: userText },
      ],
      temperature,
      max_tokens: maxTokens,
    }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const raw = String(data?.error?.message || data?.message || JSON.stringify(data));
    const msg = raw.length > 360 ? `${raw.slice(0, 360)}…` : raw;
    throw new Error(`LM Studio HTTP ${res.status}: ${msg}`);
  }
  const content = data?.choices?.[0]?.message?.content;
  let t = '';
  if (typeof content === 'string') t = content;
  else if (Array.isArray(content)) {
    t = content.map((p) => (typeof p === 'string' ? p : p?.text || '')).join('');
  }
  if (!t) {
    const err = new Error(
      'LM Studio sem texto na resposta (content vazio; modelo pode estar em reasoning longo ou pedido foi cancelado por timeout).',
    );
    err.lmStudioEmptyResponse = true;
    throw err;
  }
  return t;
}

export async function probeLmStudioConnection() {
  const model = process.env.GHOSTRECON_LMSTUDIO_MODEL?.trim() || 'local-model';
  const pong = await callLmStudio(
    'Responde apenas com PONG.',
    model,
    { systemPrompt: 'Responde de forma mínima.' },
  );
  return {
    ok: true,
    model,
    preview: String(pong || '').replace(/\s+/g, ' ').slice(0, 80),
  };
}

function isLmStudioContextError(err) {
  const msg = String(err?.message || err || '').toLowerCase();
  return (
    msg.includes('n_keep')
    || msg.includes('n_ctx')
    || msg.includes('context length')
    || msg.includes('exceeds the available context')
    || msg.includes('available context size')
    || msg.includes('channel error')
  );
}

function isLmStudioRetryablePayloadError(err) {
  if (!err) return false;
  if (err.name === 'AbortError') return true;
  if (err.lmStudioEmptyResponse) return true;
  const msg = String(err.message || err || '').toLowerCase();
  return (
    isLmStudioContextError(err)
    || msg.includes('timeout')
    || msg.includes('sem texto na resposta')
    || msg.includes('disconnected')
    || msg.includes('abort')
  );
}

/** Conteúdo user só com o JSON (system já leva as regras no Claude). */
function buildClaudeUserPayloadJsonOnly(jsonString) {
  const { maxRelatorio, maxProximos } = getAiMarkdownCharLimits();
  return `Analisa o seguinte JSON do GHOSTRECON. Responde APENAS com o objeto JSON pedido (chaves "relatorio" e "proximos_passos", valores Markdown). Cumpre os limites: relatorio ≤ ${maxRelatorio} caracteres, proximos_passos ≤ ${maxProximos} caracteres.

JSON:
${jsonString}`;
}

function clampText(s, max = 240) {
  const t = String(s ?? '');
  return t.length > max ? `${t.slice(0, Math.max(0, max - 1))}…` : t;
}

function shrinkPayloadForLmStudio(obj, maxChars) {
  const cap = lmStudioSafeMaxChars();
  const requested = Number.isFinite(Number(maxChars)) ? Number(maxChars) : cap;
  const max = Math.max(800, Math.min(120000, Math.min(requested, cap)));
  let o = JSON.parse(JSON.stringify(obj));
  if (!Array.isArray(o.findings)) o.findings = [];
  let s = JSON.stringify(o);

  // Primeiro corte: reduzir quantidade de findings
  while (s.length > max && o.findings.length > 20) {
    const cut = Math.max(20, Math.floor(o.findings.length * 0.7));
    o.findings = o.findings.slice(0, cut);
    o._truncated = { note: 'findings reduzidos para LM Studio', kept: o.findings.length };
    s = JSON.stringify(o);
  }

  // Segundo corte: simplificar campos textuais longos
  if (s.length > max) {
    o.findings = (o.findings || []).slice(0, 30).map((f) => ({
      type: f?.type,
      priority: f?.priority,
      score: f?.score,
      value: clampText(f?.value, 180),
      meta: clampText(f?.meta, 180),
      url: clampText(f?.url, 140),
    }));
    o._truncated = { note: 'payload simplificado para LM Studio', kept: o.findings.length };
    s = JSON.stringify(o);
  }

  // Terceiro corte: removendo blocos pesados opcionais
  if (s.length > max) {
    delete o.reportTemplates;
    delete o.correlation;
    delete o.intelMerge;
    o._truncated = { note: 'blocos auxiliares removidos para LM Studio', kept: o.findings.length };
    s = JSON.stringify(o);
  }

  if (s.length > max) {
    o.findings = (o.findings || []).slice(0, 12);
    o._truncated = { note: 'truncagem agressiva para caber no contexto do modelo local', kept: o.findings.length };
    s = JSON.stringify(o);
  }

  if (s.length > max) {
    s = s.slice(0, max);
  }
  return s;
}

function resolveOutputDir(projectName, targetDomain) {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const scoped = resolveLocalProjectDbDir(projectName, targetDomain);
  if (scoped) return path.join(scoped, 'ia', stamp);
  const safe = sanitizePathSegment(targetDomain, 'alvo');
  return path.join(DATA_DIR, 'ai_reports', safe, stamp);
}

/**
 * @param {object} payload — export completo do pipeline (UI)
 * @param {string} [aiProviderMode] — reservado; `lmstudio_only` na UI só activa pré-check (ordem no servidor: cloud → LM no fim).
 * @returns {{ outputDir: string, gemini: object, openrouter: object, claude: object, lmstudio: object, pipelineJsonPath: string }}
 */
export async function runDualAiReports(payload, { projectName, targetDomain, onStatus, aiProviderMode } = {}) {
  const geminiKey = process.env.GEMINI_API_KEY?.trim() || process.env.GOOGLE_AI_API_KEY?.trim();
  const openrouterKey = process.env.OPENROUTER_API_KEY?.trim();
  const claudeKey = process.env.ANTHROPIC_API_KEY?.trim();
  const lmStudioEnabled =
    ['1', 'true', 'yes', 'on'].includes(String(process.env.GHOSTRECON_LMSTUDIO_ENABLED || '').trim().toLowerCase())
    || Boolean(process.env.GHOSTRECON_LMSTUDIO_MODEL?.trim());
  /** Modelo por defeito: 2.5-flash costuma ter cota free distinta de 2.0; sobrescreve com GHOSTRECON_GEMINI_MODEL. */
  const geminiModel = process.env.GHOSTRECON_GEMINI_MODEL?.trim() || 'gemini-2.5-flash';
  const openrouterModel =
    process.env.GHOSTRECON_OPENROUTER_MODEL?.trim() || 'anthropic/claude-3.5-sonnet';
  const claudeModel = process.env.GHOSTRECON_CLAUDE_MODEL?.trim() || 'claude-3-5-sonnet-20241022';
  const lmStudioModel = process.env.GHOSTRECON_LMSTUDIO_MODEL?.trim() || 'local-model';
  void aiProviderMode;

  const { payload: p, json: jsonStr } = shrinkPayload(payload);
  const outputDir = resolveOutputDir(projectName, targetDomain);
  fs.mkdirSync(outputDir, { recursive: true });
  const pipelineJsonPath = path.join(outputDir, 'pipeline_snapshot.json');
  fs.writeFileSync(pipelineJsonPath, JSON.stringify(p, null, 2), 'utf8');

  const userBlockGemini = buildUserContent(jsonStr);
  const secondUser = buildClaudeUserPayloadJsonOnly(jsonStr);
  const lmCap = lmStudioSafeMaxChars();
  const lmStudioInputCharsRaw = Number(process.env.GHOSTRECON_LMSTUDIO_MAX_INPUT_CHARS);
  const lmStudioInputChars = Number.isFinite(lmStudioInputCharsRaw)
    ? Math.min(lmCap, lmStudioInputCharsRaw)
    : lmCap;
  const secondUserLmStudio = buildClaudeUserPayloadJsonOnly(
    shrinkPayloadForLmStudio(p, lmStudioInputChars),
  );
  const fallbackWaitSec = Math.max(
    1,
    Math.min(300, Number(process.env.GHOSTRECON_AI_FALLBACK_WAIT_SEC || 60)),
  );
  const sleepSec = (sec) => new Promise((r) => setTimeout(r, sec * 1000));
  const status = (msg, level = 'info') => {
    if (typeof onStatus === 'function') onStatus(String(msg), level);
  };

  const result = {
    outputDir,
    pipelineJsonPath,
    gemini: {
      ok: false,
      error: null,
      relatorio: null,
      proximos_passos: null,
      relatorioPath: null,
      proximosPath: null,
    },
    openrouter: {
      ok: false,
      error: null,
      relatorio: null,
      proximos_passos: null,
      relatorioPath: null,
      proximosPath: null,
    },
    claude: {
      ok: false,
      error: null,
      relatorio: null,
      proximos_passos: null,
      relatorioPath: null,
      proximosPath: null,
    },
    lmstudio: {
      ok: false,
      error: null,
      relatorio: null,
      proximos_passos: null,
      relatorioPath: null,
      proximosPath: null,
    },
  };

  const { maxRelatorio, maxProximos } = getAiMarkdownCharLimits();

  const writePair = (prefix, parsed) => {
    const rel = clampMarkdown(parsed?.relatorio ?? '', maxRelatorio);
    const prox = clampMarkdown(parsed?.proximos_passos ?? '', maxProximos);
    const rp = path.join(outputDir, `${prefix}_relatorio.md`);
    const pp = path.join(outputDir, `${prefix}_proximos_passos.md`);
    fs.writeFileSync(rp, rel, 'utf8');
    fs.writeFileSync(pp, prox, 'utf8');
    return { relatorio: rel, proximos_passos: prox, relatorioPath: rp, proximosPath: pp };
  };

  const lmTryChars = [
    lmStudioInputChars,
    Math.floor(lmStudioInputChars * 0.55),
    Math.floor(lmStudioInputChars * 0.32),
    Math.min(2200, lmCap),
  ].filter((v, i, arr) => v >= 800 && arr.indexOf(v) === i);

  const tryLmStudioReport = async () => {
    let lastErr = null;
    for (let i = 0; i < lmTryChars.length; i++) {
      const maxChars = lmTryChars[i];
      const userText =
        i === 0 ? secondUserLmStudio : buildClaudeUserPayloadJsonOnly(shrinkPayloadForLmStudio(p, maxChars));
      const systemPrompt = buildAiSystemPromptCompact();
      try {
        const raw = await callLmStudio(userText, lmStudioModel, { systemPrompt });
        fs.writeFileSync(path.join(outputDir, 'lmstudio_raw.txt'), raw, 'utf8');
        const parsed = extractJsonObject(raw);
        const paths = writePair('lmstudio', parsed);
        result.lmstudio = { ok: true, error: null, ...paths };
        return true;
      } catch (e) {
        lastErr = e;
        if (!isLmStudioRetryablePayloadError(e)) break;
        if (i < lmTryChars.length - 1) {
          const reason = isLmStudioContextError(e)
            ? 'contexto excedido'
            : e?.name === 'AbortError' || String(e?.message || '').toLowerCase().includes('timeout')
              ? 'timeout'
              : 'resposta inválida ou vazia';
          status(
            `IA LM Studio: ${reason} (tentativa ${i + 1}/${lmTryChars.length}). A reduzir payload ou aguardar nova tentativa…`,
            'warn',
          );
        }
      }
    }
    result.lmstudio = {
      ok: false,
      error: lastErr?.message || 'Falha no LM Studio',
      relatorio: null,
      proximos_passos: null,
      relatorioPath: null,
      proximosPath: null,
    };
    return false;
  };

  const cloudOk = () =>
    result.gemini.ok === true || result.openrouter.ok === true || result.claude.ok === true;

  // Cascata: 1) Gemini (3×)  2) OpenRouter  3) Claude  4) LM Studio (lento — só se clouds falharem)
  // Modo UI `lmstudio_only`: obriga pré-check no cliente; no servidor LM fica sempre no fim.

  // 1) Gemini
  if (geminiKey) {
    let geminiLastErr = null;
    for (let attempt = 1; attempt <= 3; attempt++) {
      status(`IA Gemini: tentativa ${attempt}/3…`, 'info');
      try {
        const raw = await callGeminiOnce(userBlockGemini, geminiKey, geminiModel);
        fs.writeFileSync(path.join(outputDir, 'gemini_raw.txt'), raw, 'utf8');
        const parsed = extractJsonObject(raw);
        const paths = writePair('gemini', parsed);
        result.gemini = { ok: true, error: null, ...paths };
        geminiLastErr = null;
        break;
      } catch (e) {
        geminiLastErr = e;
        if (attempt < 3) {
          status(
            `IA Gemini: falhou na tentativa ${attempt}/3 (${e?.message || e}). A aguardar ${fallbackWaitSec}s para nova tentativa…`,
            'warn',
          );
          await sleepSec(fallbackWaitSec);
        }
      }
    }
    if (geminiLastErr) {
      result.gemini = {
        ok: false,
        error: geminiLastErr.message,
        relatorio: null,
        proximos_passos: null,
        relatorioPath: null,
        proximosPath: null,
      };
    }
  } else {
    result.gemini = {
      ok: false,
      error: 'GEMINI_API_KEY ou GOOGLE_AI_API_KEY não definido',
      relatorio: null,
      proximos_passos: null,
      relatorioPath: null,
      proximosPath: null,
    };
  }

  // 2) OpenRouter
  if (openrouterKey) {
    if (result.gemini.ok) {
      result.openrouter = {
        ok: false,
        error: 'Não executado (Gemini já respondeu com sucesso).',
        relatorio: null,
        proximos_passos: null,
        relatorioPath: null,
        proximosPath: null,
      };
    } else {
      status('IA OpenRouter: tentativa 1/1…', 'info');
      try {
        const raw = await callOpenRouterOnce(secondUser, openrouterKey, openrouterModel);
        fs.writeFileSync(path.join(outputDir, 'openrouter_raw.txt'), raw, 'utf8');
        const parsed = extractJsonObject(raw);
        const paths = writePair('openrouter', parsed);
        result.openrouter = { ok: true, error: null, ...paths };
      } catch (e) {
        result.openrouter = {
          ok: false,
          error: e.message,
          relatorio: null,
          proximos_passos: null,
          relatorioPath: null,
          proximosPath: null,
        };
      }
    }
  } else {
    result.openrouter = {
      ok: false,
      error: 'OPENROUTER_API_KEY não definido',
      relatorio: null,
      proximos_passos: null,
      relatorioPath: null,
      proximosPath: null,
    };
  }

  // 3) Claude (Anthropic direct)
  if (claudeKey) {
    if (result.gemini.ok || result.openrouter.ok) {
      result.claude = {
        ok: false,
        error: 'Não executado (provider cloud anterior já respondeu com sucesso).',
        relatorio: null,
        proximos_passos: null,
        relatorioPath: null,
        proximosPath: null,
      };
    } else {
      status('IA Claude: tentativa 1/1…', 'info');
      try {
        const raw = await callClaude(secondUser, claudeKey, claudeModel);
        fs.writeFileSync(path.join(outputDir, 'claude_raw.txt'), raw, 'utf8');
        const parsed = extractJsonObject(raw);
        const paths = writePair('claude', parsed);
        result.claude = { ok: true, error: null, ...paths };
      } catch (e) {
        result.claude = {
          ok: false,
          error: e.message,
          relatorio: null,
          proximos_passos: null,
          relatorioPath: null,
          proximosPath: null,
        };
      }
    }
  } else {
    result.claude = {
      ok: false,
      error: 'ANTHROPIC_API_KEY não definido',
      relatorio: null,
      proximos_passos: null,
      relatorioPath: null,
      proximosPath: null,
    };
  }

  // 4) LM Studio (último recurso — modelos locais podem demorar muito em "reasoning")
  const shouldTryLmStudio = !cloudOk();
  if (shouldTryLmStudio && lmStudioEnabled) {
    status('IA LM Studio: fallback local (último passo)…', 'info');
    await tryLmStudioReport();
  } else if (!shouldTryLmStudio && lmStudioEnabled) {
    result.lmstudio = {
      ok: false,
      error: 'Não executado (um provider cloud já respondeu com sucesso).',
      relatorio: null,
      proximos_passos: null,
      relatorioPath: null,
      proximosPath: null,
    };
  } else if (shouldTryLmStudio && !lmStudioEnabled) {
    result.lmstudio = {
      ok: false,
      error: 'LM Studio desativado (define GHOSTRECON_LMSTUDIO_ENABLED=1 e GHOSTRECON_LMSTUDIO_MODEL).',
      relatorio: null,
      proximos_passos: null,
      relatorioPath: null,
      proximosPath: null,
    };
  }

  return result;
}

/** Escolhe o primeiro relatório bem-sucedido (Gemini → OpenRouter → Claude → LM Studio). */
export function pickAiReportForWebhook(aiOut) {
  if (!aiOut || typeof aiOut !== 'object') return null;
  const order = ['gemini', 'openrouter', 'claude', 'lmstudio'];
  for (const key of order) {
    const b = aiOut[key];
    if (b?.ok && typeof b.relatorio === 'string' && typeof b.proximos_passos === 'string') {
      return { provider: key, relatorio: b.relatorio, proximos_passos: b.proximos_passos };
    }
  }
  return null;
}

export function aiKeysConfigured() {
  const g = Boolean(process.env.GEMINI_API_KEY?.trim() || process.env.GOOGLE_AI_API_KEY?.trim());
  const o = Boolean(process.env.OPENROUTER_API_KEY?.trim());
  const c = Boolean(process.env.ANTHROPIC_API_KEY?.trim());
  const l =
    ['1', 'true', 'yes', 'on'].includes(String(process.env.GHOSTRECON_LMSTUDIO_ENABLED || '').trim().toLowerCase())
    || Boolean(process.env.GHOSTRECON_LMSTUDIO_MODEL?.trim());
  return {
    gemini: g,
    openrouter: o,
    claude: Boolean(c),
    lmstudio: l,
    any: g || o || c || l,
    both: [g, o, c].filter(Boolean).length >= 2,
  };
}
