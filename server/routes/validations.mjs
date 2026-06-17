import {
  listManualValidationsForTarget,
  upsertManualValidation,
  deleteManualValidation,
  storageLabel,
} from '../modules/db.js';
import { isSha256FingerprintHex } from '../modules/db-common.js';
import {
  runDualAiReports,
  callOpenRouter,
  normalizeOpenrouterOnlyFlag,
} from '../modules/ai-dual-report.js';
import { requireScope } from '../modules/auth.js';

function isValidManualValidationTarget(t) {
  const s = String(t || '')
    .trim()
    .toLowerCase();
  return s && /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(s);
}

const ANNOTATIONS_AI_SYSTEM_PT = [
  'És um redactor técnico de relatórios de segurança ofensiva (pentest / red team).',
  'Recebes anotações de campo em Markdown (português). Gera um relatório formal em Markdown, em português de Portugal, com:',
  '- Título e metadados (alvo, data se existir na entrada).',
  '- Resumo executivo (2–5 frases).',
  '- Achados e riscos (tabela ou lista) com severidade estimada quando possível a partir do texto.',
  '- Detalhe técnico por tema (portas/serviços, web, vetores, testes, exploração, impacto).',
  '- Recomendações de mitigação concretas.',
  '- Secção «Referências» só com OWASP/MITRE que apareçam nas anotações (não inventes códigos).',
  'Regras: não inventes factos, URLs, portas, CVEs ou resultados de testes que não estejam nas anotações; se algo for incerto, indica-o explicitamente como hipótese ou «não documentado nas notas».',
  'Responde apenas com o corpo Markdown do relatório (sem JSON).',
].join(' ');

export function registerValidationsRoutes(app, { validateCsrfToken }) {
  app.get('/api/manual-validations/:target', async (req, res) => {
  const t = String(req.params.target || '')
    .trim()
    .toLowerCase();
  if (!isValidManualValidationTarget(t)) {
    res.status(400).json({ error: 'domínio inválido' });
    return;
  }
  try {
    const items = await listManualValidationsForTarget(t);
    res.json({ target: t, items });
  } catch (e) {
    res.status(500).json({ error: e?.message || String(e) });
  }
});

/** Marca ou desmarca validação manual (persistência por fingerprint = mesmo achado em recons futuros). */
  app.post('/api/manual-validations', requireScope('validation.write'), async (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF token inválido ou ausente' });
    return;
  }
  const target = String(req.body?.target || '')
    .trim()
    .toLowerCase();
  const fp = String(req.body?.fingerprint || '').trim().toLowerCase();
  const validated = req.body?.validated !== false && req.body?.validated !== 0 && req.body?.validated !== 'false';
  if (!isValidManualValidationTarget(target)) {
    res.status(400).json({ ok: false, error: 'domínio inválido' });
    return;
  }
  if (!isSha256FingerprintHex(fp)) {
    res.status(400).json({ ok: false, error: 'fingerprint inválido' });
    return;
  }
  try {
    if (validated) {
      const snap = req.body?.snapshot && typeof req.body.snapshot === 'object' ? req.body.snapshot : null;
      const notes = req.body?.notes != null ? String(req.body.notes) : '';
      await upsertManualValidation({ target, fingerprint: fp, snapshot: snap, notes });
      res.json({ ok: true, target, fingerprint: fp, validated: true });
    } else {
      await deleteManualValidation(target, fp);
      res.json({ ok: true, target, fingerprint: fp, validated: false });
    }
  } catch (e) {
    res.status(400).json({ ok: false, error: e?.message || String(e) });
  }
});

/** Gera relatório por IA só com achados já validados manualmente (subset do recon). */
  app.post('/api/manual-validations/ai-report', requireScope('ai.run'), async (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF token inválido ou ausente' });
    return;
  }
  const target = String(req.body?.target || '')
    .trim()
    .toLowerCase();
  const findingsIn = Array.isArray(req.body?.findings) ? req.body.findings : null;
  if (!isValidManualValidationTarget(target)) {
    res.status(400).json({ ok: false, error: 'domínio inválido' });
    return;
  }
  if (!findingsIn || !findingsIn.length) {
    res.status(400).json({ ok: false, error: 'Indica pelo menos um achado validado (array findings).' });
    return;
  }
  const known = new Set(
    (await listManualValidationsForTarget(target)).map((x) => String(x.fingerprint || '').toLowerCase()),
  );
  const findings = [];
  for (const f of findingsIn) {
    if (!f || typeof f !== 'object') continue;
    const fp = String(f.fingerprint || '').trim().toLowerCase();
    if (!isSha256FingerprintHex(fp) || !known.has(fp)) continue;
    findings.push({
      type: f.type,
      prio: f.prio,
      score: f.score,
      value: f.value,
      meta: f.meta,
      url: f.url,
      fingerprint: fp,
    });
  }
  if (!findings.length) {
    res.status(400).json({
      ok: false,
      error: 'Nenhum achado coincide com validações manuais gravadas na base para este alvo.',
    });
    return;
  }
  const projectName = String(req.body?.projectName ?? '').trim();
  const stats =
    req.body?.stats && typeof req.body.stats === 'object'
      ? req.body.stats
      : { subs: 0, endpoints: 0, params: 0, secrets: 0, dorks: 0, high: 0 };
  const payload = {
    schemaVersion: 1,
    source: 'ghostrecon-manual-validation-report',
    exportedAt: new Date().toISOString(),
    target,
    projectName: projectName || undefined,
    stats,
    findings,
    correlation: null,
    reportTemplates: {},
    runId: null,
    storage: storageLabel(),
    modules: ['manual_validation'],
    bountyContext: {
      note: 'Relatório pedido a partir de achados já confirmados manualmente no checklist Reporte.',
    },
  };
  const aiPrimaryRaw =
    typeof req.body?.aiPrimaryCloud === 'string'
      ? req.body.aiPrimaryCloud
      : typeof req.body?.aiPrimaryReport === 'string'
        ? req.body.aiPrimaryReport
        : null;
  try {
    const out = await runDualAiReports(payload, {
      projectName,
      targetDomain: target,
      aiProviderMode: 'auto',
      aiUseOpenrouter: req.body?.aiUseOpenrouter !== false,
      aiOpenrouterOnly: normalizeOpenrouterOnlyFlag(req.body?.aiOpenrouterOnly),
      aiPrimaryCloud: aiPrimaryRaw,
      onStatus: () => {},
      /** Reporte: OpenRouter → Gemini → LM Studio (não LM entre as duas clouds). */
      aiOpenrouterThenGeminiBeforeLm: true,
    });
    res.json({ ok: true, ...out });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

const ANNOTATIONS_AI_SYSTEM_PT = [
  'És um redactor técnico de relatórios de segurança ofensiva (pentest / red team).',
  'Recebes anotações de campo em Markdown (português). Gera um relatório formal em Markdown, em português de Portugal, com:',
  '- Título e metadados (alvo, data se existir na entrada).',
  '- Resumo executivo (2–5 frases).',
  '- Achados e riscos (tabela ou lista) com severidade estimada quando possível a partir do texto.',
  '- Detalhe técnico por tema (portas/serviços, web, vetores, testes, exploração, impacto).',
  '- Recomendações de mitigação concretas.',
  '- Secção «Referências» só com OWASP/MITRE que apareçam nas anotações (não inventes códigos).',
  'Regras: não inventes factos, URLs, portas, CVEs ou resultados de testes que não estejam nas anotações; se algo for incerto, indica-o explicitamente como hipótese ou «não documentado nas notas».',
  'Responde apenas com o corpo Markdown do relatório (sem JSON).',
].join(' ');

/** Relatório Markdown só via OpenRouter a partir do texto das anotações do Reporte. */
  app.post('/api/manual-validations/annotations-ai', requireScope('ai.run'), async (req, res) => {
  if (!validateCsrfToken(req)) {
    res.status(403).json({ ok: false, error: 'CSRF token inválido ou ausente' });
    return;
  }
  const markdown = String(req.body?.markdown || '').trim();
  if (!markdown) {
    res.status(400).json({ ok: false, error: 'Indica o campo markdown com as anotações.' });
    return;
  }
  const targetOpt = String(req.body?.target || '')
    .trim()
    .toLowerCase();
  if (targetOpt && !isValidManualValidationTarget(targetOpt)) {
    res.status(400).json({ ok: false, error: 'domínio inválido' });
    return;
  }
  const openrouterKey = process.env.OPENROUTER_API_KEY?.trim();
  if (!openrouterKey) {
    res.status(503).json({ ok: false, error: 'OPENROUTER_API_KEY não configurada no servidor.' });
    return;
  }
  const openrouterModel =
    process.env.GHOSTRECON_OPENROUTER_MODEL?.trim() || 'google/gemma-4-31b-it';
  const maxIn = Math.max(4000, Math.min(200000, Number(process.env.GHOSTRECON_ANNOTATIONS_AI_MAX_CHARS || 120000)));
  const slice = markdown.length > maxIn ? `${markdown.slice(0, maxIn)}\n\n[… texto truncado …]` : markdown;
  const userBlock = [
    targetOpt ? `Alvo (referência): ${targetOpt}` : '',
    '',
    '---',
    '',
    'Anotações do analista:',
    '',
    slice,
  ]
    .filter(Boolean)
    .join('\n');
  try {
    const out = await callOpenRouter(userBlock, openrouterKey, openrouterModel, {
      systemPrompt: ANNOTATIONS_AI_SYSTEM_PT,
      jsonObject: false,
    });
    res.json({ ok: true, markdown: String(out || '').trim() });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});
}
