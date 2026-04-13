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
    err.geminiRetryAfterSec = res.status === 429 ? parseGeminiRetrySeconds(data?.error?.message || '') : null;
    throw err;
  }
  const parts = data?.candidates?.[0]?.content?.parts;
  const t = Array.isArray(parts) ? parts.map((p) => p.text || '').join('') : '';
  if (!t) throw new Error('Gemini sem texto na resposta');
  return t;
}

export async function callGemini(userText, apiKey, model) {
  const maxAttempts = Math.max(1, Math.min(5, Number(process.env.GHOSTRECON_GEMINI_MAX_RETRIES || 3)));
  let lastErr;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await callGeminiOnce(userText, apiKey, model);
    } catch (e) {
      lastErr = e;
      const status = e?.geminiStatus;
      const is429 = status === 429 || /HTTP 429/.test(String(e.message));
      if (!is429 || attempt >= maxAttempts) throw e;
      const fromApi = e?.geminiRetryAfterSec;
      const backoff = fromApi ?? Math.min(90, 12 * attempt);
      await new Promise((r) => setTimeout(r, backoff * 1000));
    }
  }
  throw lastErr;
}

/** Chat Completions (OpenAI-compatible) na OpenRouter — substitui o segundo relatório que antes usava Anthropic direct. */
export async function callOpenRouter(userText, apiKey, model, opts = {}) {
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
    throw new Error(`OpenRouter HTTP ${res.status}: ${msg}`);
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

/** Conteúdo user só com o JSON (system já leva as regras no Claude). */
function buildClaudeUserPayloadJsonOnly(jsonString) {
  const { maxRelatorio, maxProximos } = getAiMarkdownCharLimits();
  return `Analisa o seguinte JSON do GHOSTRECON. Responde APENAS com o objeto JSON pedido (chaves "relatorio" e "proximos_passos", valores Markdown). Cumpre os limites: relatorio ≤ ${maxRelatorio} caracteres, proximos_passos ≤ ${maxProximos} caracteres.

JSON:
${jsonString}`;
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
 * @returns {{ outputDir: string, gemini: object, openrouter: object, claude: object, pipelineJsonPath: string }}
 */
export async function runDualAiReports(payload, { projectName, targetDomain } = {}) {
  const geminiKey = process.env.GEMINI_API_KEY?.trim() || process.env.GOOGLE_AI_API_KEY?.trim();
  const openrouterKey = process.env.OPENROUTER_API_KEY?.trim();
  const claudeKey = process.env.ANTHROPIC_API_KEY?.trim();
  /** Modelo por defeito: 2.5-flash costuma ter cota free distinta de 2.0; sobrescreve com GHOSTRECON_GEMINI_MODEL. */
  const geminiModel = process.env.GHOSTRECON_GEMINI_MODEL?.trim() || 'gemini-2.5-flash';
  const openrouterModel =
    process.env.GHOSTRECON_OPENROUTER_MODEL?.trim() || 'anthropic/claude-3.5-sonnet';
  const claudeModel = process.env.GHOSTRECON_CLAUDE_MODEL?.trim() || 'claude-3-5-sonnet-20241022';

  const { payload: p, json: jsonStr } = shrinkPayload(payload);
  const outputDir = resolveOutputDir(projectName, targetDomain);
  fs.mkdirSync(outputDir, { recursive: true });
  const pipelineJsonPath = path.join(outputDir, 'pipeline_snapshot.json');
  fs.writeFileSync(pipelineJsonPath, JSON.stringify(p, null, 2), 'utf8');

  const userBlockGemini = buildUserContent(jsonStr);
  const secondUser = buildClaudeUserPayloadJsonOnly(jsonStr);

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

  if (geminiKey) {
    try {
      const raw = await callGemini(userBlockGemini, geminiKey, geminiModel);
      fs.writeFileSync(path.join(outputDir, 'gemini_raw.txt'), raw, 'utf8');
      const parsed = extractJsonObject(raw);
      const paths = writePair('gemini', parsed);
      result.gemini = { ok: true, error: null, ...paths };
    } catch (e) {
      result.gemini = {
        ok: false,
        error: e.message,
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

  if (openrouterKey) {
    try {
      const raw = await callOpenRouter(secondUser, openrouterKey, openrouterModel);
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
  } else if (claudeKey) {
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
  } else {
    result.openrouter = {
      ok: false,
      error: 'OPENROUTER_API_KEY ou ANTHROPIC_API_KEY não definido',
      relatorio: null,
      proximos_passos: null,
      relatorioPath: null,
      proximosPath: null,
    };
  }

  return result;
}

/** Escolhe o primeiro relatório bem-sucedido (Gemini → OpenRouter → Claude) para webhook/UI. */
export function pickAiReportForWebhook(aiOut) {
  if (!aiOut || typeof aiOut !== 'object') return null;
  const order = ['gemini', 'openrouter', 'claude'];
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
  return {
    gemini: g,
    openrouter: o,
    claude: !o && c,
    any: g || o || c,
    both: g && (o || c),
  };
}
