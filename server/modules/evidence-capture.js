/**
 * Evidence capture — anexa evidências ricas a findings.
 *
 * Para cada URL/target interessante (severity ≥ threshold), abre uma página
 * com Playwright e captura:
 *   - screenshot PNG (full page opcional)
 *   - DOM snippet (primeiros N kB do HTML pós-render)
 *   - request/response principal (HTTP status, headers, timing)
 *   - console logs (stdout/stderr do runtime JS)
 *
 * As evidências são persistidas em `evidence/<runId>/<findingIdx>.{png,txt,json}`
 * e referenciadas no finding por campo `evidence.captures = { screenshot, dom, har }`.
 *
 * Uso:
 *   import { captureEvidenceForRun } from './modules/evidence-capture.js';
 *   const updatedFindings = await captureEvidenceForRun(run, { outputDir, minSeverity: 'medium' });
 *
 * Este módulo é opt-in — não é chamado por runPipeline por padrão.
 * CLI, scheduler e API podem invocá-lo após o run ser gravado.
 */

import fs from 'node:fs/promises';
import path from 'node:path';

const SEV_ORDER = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
function sev(s) { return SEV_ORDER[String(s || '').toLowerCase()] ?? 0; }

/**
 * Decide qual URL/target capturar para um dado finding.
 * Retorna null se não houver alvo HTTP útil.
 */
function pickCaptureTarget(finding) {
  const ev = finding.evidence || {};
  const candidates = [ev.url, ev.endpoint, ev.target, ev.host, finding.url, finding.host];
  for (const c of candidates) {
    if (!c) continue;
    const s = String(c).trim();
    if (!s) continue;
    if (/^https?:\/\//i.test(s)) return s;
    if (/^[\w.-]+\.[\w.-]+/.test(s)) return `https://${s.replace(/^\/*/, '')}`;
  }
  return null;
}

/**
 * Captura evidências para UMA URL. Retorna objeto descritivo ou null.
 * Totalmente envolto em try/catch — nunca propaga exceção para o caller.
 */
export async function captureUrl(url, { outputBase, label, fullPage = false, timeoutMs = 15_000 } = {}) {
  let browser = null;
  let playwright;
  try {
    playwright = await import('playwright');
  } catch {
    return { error: 'playwright não instalado' };
  }
  try {
    browser = await playwright.chromium.launch({ headless: true });
    const context = await browser.newContext({
      userAgent: 'GHOSTRECON/1.0 evidence-capture',
      ignoreHTTPSErrors: true,
      viewport: { width: 1280, height: 900 },
    });
    const page = await context.newPage();

    const consoleLogs = [];
    page.on('console', (msg) => {
      try {
        consoleLogs.push({ type: msg.type(), text: msg.text().slice(0, 500) });
      } catch { /* ignore */ }
      if (consoleLogs.length > 200) consoleLogs.length = 200;
    });

    const netEvents = [];
    page.on('response', async (res) => {
      if (netEvents.length > 40) return;
      try {
        netEvents.push({
          url: res.url(),
          status: res.status(),
          headers: Object.fromEntries(Object.entries(res.headers()).slice(0, 30)),
        });
      } catch { /* ignore */ }
    });

    let mainResponse = null;
    try {
      mainResponse = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
    } catch (e) {
      return { error: `navegação falhou: ${e.message}`, url };
    }

    const screenshotPath = path.join(outputBase, `${label}.png`);
    const domPath = path.join(outputBase, `${label}.html`);
    const metaPath = path.join(outputBase, `${label}.json`);

    await fs.mkdir(outputBase, { recursive: true });
    try {
      await page.screenshot({ path: screenshotPath, fullPage, type: 'png' });
    } catch (e) {
      return { error: `screenshot falhou: ${e.message}`, url };
    }

    let html = '';
    try {
      html = await page.content();
    } catch { /* ignore */ }
    if (html) await fs.writeFile(domPath, html.slice(0, 256 * 1024), 'utf8');

    const meta = {
      url,
      capturedAt: new Date().toISOString(),
      mainStatus: mainResponse?.status?.() ?? null,
      mainHeaders: mainResponse ? await safeHeaders(mainResponse) : null,
      title: await safeTitle(page),
      consoleLogs: consoleLogs.slice(-60),
      netEvents: netEvents.slice(0, 40),
      screenshot: path.relative(process.cwd(), screenshotPath),
      dom: html ? path.relative(process.cwd(), domPath) : null,
    };
    await fs.writeFile(metaPath, JSON.stringify(meta, null, 2), 'utf8');

    return {
      url,
      screenshot: meta.screenshot,
      dom: meta.dom,
      meta: path.relative(process.cwd(), metaPath),
      title: meta.title,
      mainStatus: meta.mainStatus,
    };
  } catch (e) {
    return { error: e.message || String(e), url };
  } finally {
    try { await browser?.close(); } catch { /* ignore */ }
  }
}

async function safeHeaders(response) {
  try {
    const all = await response.allHeaders();
    return Object.fromEntries(Object.entries(all).slice(0, 40));
  } catch {
    return null;
  }
}
async function safeTitle(page) {
  try { return (await page.title()).slice(0, 200); } catch { return ''; }
}

/**
 * Captura evidências para findings de um run.
 * Itera sobre findings ≥ minSeverity, ignora duplicados (mesmo host/URL).
 * Retorna o run com `findings` atualizados (evidence.captures adicionado).
 */
export async function captureEvidenceForRun(run, {
  outputDir = '.ghostrecon-evidence',
  minSeverity = 'medium',
  maxCaptures = 25,
  fullPage = false,
  timeoutMs = 15_000,
} = {}) {
  const floor = sev(minSeverity);
  const base = path.resolve(process.cwd(), outputDir, String(run.id ?? 'run'));
  const seen = new Set();
  const captured = [];
  const findings = Array.isArray(run.findings) ? [...run.findings] : [];

  let count = 0;
  for (let i = 0; i < findings.length && count < maxCaptures; i++) {
    const f = findings[i];
    if (sev(f.severity) < floor) continue;
    const url = pickCaptureTarget(f);
    if (!url || seen.has(url)) continue;
    seen.add(url);

    const label = `f${i}_${slugForFilename(url)}`;
    const cap = await captureUrl(url, { outputBase: base, label, fullPage, timeoutMs });
    count++;
    if (cap && !cap.error) {
      const ev = { ...(f.evidence || {}) };
      ev.captures = {
        screenshot: cap.screenshot,
        dom: cap.dom,
        meta: cap.meta,
        title: cap.title,
        mainStatus: cap.mainStatus,
        capturedAt: new Date().toISOString(),
      };
      findings[i] = { ...f, evidence: ev };
      captured.push({ findingIndex: i, ...cap });
    } else {
      captured.push({ findingIndex: i, error: cap?.error, url });
    }
  }

  return {
    run: { ...run, findings, evidenceCaptureCount: captured.filter((c) => !c.error).length },
    captures: captured,
    outputDir: base,
  };
}

function slugForFilename(s) {
  return String(s || '')
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/[^a-z0-9._-]+/g, '_')
    .slice(0, 80);
}
