/**
 * Resumo dos achados novos para o webhook: Gemini primeiro, depois OpenRouter (mesmo .env do GHOSTRECON).
 */

const DEFAULT_MODEL = () => process.env.WORKFLOW_GEMINI_MODEL || 'gemini-2.0-flash';

export function geminiApiKey() {
  return String(process.env.GEMINI_API_KEY || process.env.GOOGLE_AI_KEY || process.env.GOOGLE_AI_API_KEY || '').trim();
}

export function openRouterApiKey() {
  return String(process.env.OPENROUTER_API_KEY || '').trim();
}

function buildUserPrompt(items, { targets } = {}) {
  const lines = items.slice(0, 400).map((f) => ({
    tipo: f.type || f.kind,
    prio: f.prio,
    valor: typeof f.value === 'string' ? f.value.slice(0, 500) : f.value,
    url: typeof f.url === 'string' ? f.url.slice(0, 500) : f.url,
    alvo: f.targetBucket || '',
  }));

  return (
    `Você é analista de segurança bug bounty.\n\n` +
    `Alvos tocados neste ciclo (${targets?.length ?? 0}): ${JSON.stringify(targets ?? [])}\n\n` +
    `Lista apenas de achados NOVOS (dedupe já feito antes):\n${JSON.stringify(lines, null, 2)}\n\n` +
    `Responda em português: (1) 3–8 bullets objetivos do que mudou desde o ciclo anterior, ` +
    `(2) o que vale priorizar agora por severidade, (3) riscos de falso positivo onde aplicável. ` +
    `Seja compacto (< 1200 caracteres total).`
  );
}

async function summarizeWithGemini(userText) {
  const key = geminiApiKey();
  if (!key) throw new Error('GEMINI_API_KEY não definido');

  const model = encodeURIComponent(DEFAULT_MODEL());
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${encodeURIComponent(key)}`;

  const body = JSON.stringify({
    contents: [{ role: 'user', parts: [{ text: userText }] }],
    generationConfig: {
      temperature: 0.2,
      maxOutputTokens: 1024,
    },
  });

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
  });

  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Gemini HTTP ${res.status}: ${t.slice(0, 300)}`);
  }

  const data = await res.json();
  const text =
    data?.candidates?.[0]?.content?.parts?.map((p) => p.text).join('\n').trim()
    ?? data?.candidates?.[0]?.output_text
    ?? null;

  if (!text?.trim()) throw new Error('Gemini não devolveu texto');
  return text;
}

async function summarizeWithOpenRouter(userText) {
  const key = openRouterApiKey();
  if (!key) throw new Error('OPENROUTER_API_KEY não definido');

  const model = String(process.env.GHOSTRECON_OPENROUTER_MODEL || '').trim() || 'google/gemma-2-9b-it';
  const referer = String(process.env.GHOSTRECON_OPENROUTER_HTTP_REFERER || '').trim();
  const title =
    String(process.env.GHOSTRECON_OPENROUTER_APP_TITLE || '').trim() || 'ghostrecon-vps-workflow';

  /** @type {Record<string, string>} */
  const headers = {
    'content-type': 'application/json',
    authorization: `Bearer ${key}`,
    'x-title': title,
  };
  if (referer) headers['http-referer'] = referer;

  const body = JSON.stringify({
    model,
    messages: [{ role: 'user', content: userText }],
    temperature: 0.2,
    max_tokens: 1024,
  });

  const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers,
    body,
  });

  if (!res.ok) {
    const t = await res.text();
    throw new Error(`OpenRouter HTTP ${res.status}: ${t.slice(0, 400)}`);
  }

  const data = await res.json();
  const text = data?.choices?.[0]?.message?.content ?? null;
  if (!text || !String(text).trim()) throw new Error('OpenRouter não devolveu texto');
  return String(text).trim();
}

/**
 * @returns {Promise<{ text: string | null, provider: 'gemini' | 'openrouter' | null, errorNotes: string[] }>}
 */
export async function summarizeFindingsPortugueseWithMeta(items, ctx) {
  const userText = buildUserPrompt(items, ctx);
  /** @type {string[]} */
  const notes = [];

  if (geminiApiKey()) {
    try {
      const text = await summarizeWithGemini(userText);
      return { text, provider: 'gemini', errorNotes: notes };
    } catch (e) {
      notes.push(`Gemini: ${e.message || e}`);
    }
  }

  if (openRouterApiKey()) {
    try {
      const text = await summarizeWithOpenRouter(userText);
      return { text, provider: 'openrouter', errorNotes: notes };
    } catch (e) {
      notes.push(`OpenRouter: ${e.message || e}`);
    }
  }

  if (!notes.length) {
    notes.push('Sem GEMINI_API_KEY / GOOGLE_AI_API_KEY nem OPENROUTER_API_KEY');
  }

  return { text: `(${notes.join('; ')})`, provider: null, errorNotes: notes };
}

export async function summarizeFindingsPortuguese(items, ctx) {
  const { text } = await summarizeFindingsPortugueseWithMeta(items, ctx);
  return text;
}
