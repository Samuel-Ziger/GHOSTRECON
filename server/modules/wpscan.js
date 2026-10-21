import { readFile, mkdtemp, rm, stat } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';
import { runProcess } from './module-runner.mjs';

/**
 * Token da WordPress Vulnerability Database (wpscan.com).
 * WPScan CLI lê `WPSCAN_API_TOKEN` no ambiente (v3.7.10+); também aceitamos `GHOSTRECON_WPSCAN_API_TOKEN`.
 */
export function resolveWpscanApiToken() {
  const a = String(process.env.WPSCAN_API_TOKEN || '').trim();
  const b = String(process.env.GHOSTRECON_WPSCAN_API_TOKEN || '').trim();
  return a || b || '';
}

export function isWpscanApiTokenConfigured() {
  return Boolean(resolveWpscanApiToken());
}

/**
 * Por defeito o WPScan só corre com token (WPVulnDB).
 * `GHOSTRECON_WPSCAN_REQUIRE_API=0` permite executar wpscan sem API (só enumeração).
 */
export function isWpscanApiRequired() {
  return String(process.env.GHOSTRECON_WPSCAN_REQUIRE_API ?? '1').trim() !== '0';
}

function runProc(cmd, args, timeoutMs, spawnOpts = {}, { signal = null } = {}) {
  return runProcess(cmd, args, { timeoutMs, spawnOpts, signal, label: cmd });
}

function safeConfidence(n) {
  const x = Number(n);
  return Number.isFinite(x) ? x : null;
}

function prioScoreFromVersionConfidence({ hasVersion, confidence }) {
  const c = safeConfidence(confidence);
  if (!hasVersion) return { prio: 'info', score: 14 };
  if (c != null && c >= 80) return { prio: 'info', score: 24 };
  return { prio: 'info', score: 18 };
}

function extractMainThemeFindings(targetUrl, wps) {
  const out = [];
  const mt = wps?.main_theme;
  if (!mt?.slug) return out;

  const location = mt.location || null;
  const version = mt?.version?.number || null;
  const confidence = mt?.version?.confidence ?? null;

  const { prio, score } = prioScoreFromVersionConfidence({ hasVersion: Boolean(version), confidence });
  out.push({
    type: 'wpscan',
    prio,
    score,
    value: version ? `Main theme: ${mt.slug} v${version}` : `Main theme: ${mt.slug}`,
    meta: {
      source: 'kali_wpscan',
      evidenceStatus: 'component_inventory',
      foundBy: mt?.version?.found_by || mt?.found_by || 'unknown',
      confidence,
      note: 'Tema/versão observados não provam vulnerabilidade',
    },
    url: location || targetUrl,
  });

  return out;
}

function extractPluginsFindings(targetUrl, wps) {
  const out = [];
  const plugins = wps?.plugins;
  if (!plugins || typeof plugins !== 'object') return out;

  for (const [slug, p] of Object.entries(plugins).slice(0, 1_000)) {
    if (slug === '*') continue; // placeholder entry
    if (!p || typeof p !== 'object') continue;

    const location = p.location || null;
    const version = p?.version?.number || null;
    const confidence = p?.version?.confidence ?? p?.confidence ?? null;

    const { prio, score } = prioScoreFromVersionConfidence({ hasVersion: Boolean(version), confidence });
    out.push({
      type: 'wpscan',
      prio,
      score,
      value: version ? `Plugin: ${slug} v${version}` : `Plugin: ${slug}`,
      meta: {
        source: 'kali_wpscan',
        evidenceStatus: 'component_inventory',
        foundBy: p?.version?.found_by || p?.found_by || 'unknown',
        confidence,
        note: 'Plugin/versão observados não provam vulnerabilidade',
      },
      url: location || targetUrl,
    });
  }

  return out;
}

function cvesFromReferences(refs) {
  if (!refs || typeof refs !== 'object') return [];
  const raw = refs.cve ?? refs.CVE ?? refs.cves;
  if (Array.isArray(raw)) return raw.map((x) => String(x).trim()).filter(Boolean);
  if (typeof raw === 'string') return [raw.trim()].filter(Boolean);
  return [];
}

function normalizeVulnArray(v) {
  if (!Array.isArray(v)) return [];
  return v.filter((x) => x && typeof x === 'object');
}

/**
 * Vulnerabilidades da WPVulnDB (só aparecem no JSON com `--api-token` / WPSCAN_API_TOKEN).
 */
function extractVulnerabilityFindings(targetUrl, wps) {
  const out = [];
  const seen = new Set();

  function pushVuln(contextLabel, vuln, pageUrl) {
    const title = String(vuln.title || vuln.Title || 'Vulnerability').trim() || 'Vulnerability';
    const refs = vuln.references;
    const cves = cvesFromReferences(refs);
    const key = `${contextLabel}|${title}|${cves.join(',')}`;
    if (seen.has(key)) return;
    seen.add(key);

    const cveStr = cves.length ? cves.join(', ') : '';
    const value = cveStr
      ? `WPVulnDB: ${contextLabel} — ${cveStr}`
      : `WPVulnDB: ${contextLabel} — ${title}`;
    out.push({
      type: 'wpscan',
      prio: 'low',
      score: cveStr ? 45 : 38,
      value,
      meta: {
        source: 'kali_wpscan',
        evidenceStatus: 'candidate_by_vulnerability_database',
        title,
        cves: cves.slice(0, 20),
        fixedIn: vuln.fixed_in || null,
        applicabilityVerified: false,
        note: 'Correlação de base; versão afetada e impacto no alvo ainda não foram validados',
      },
      url: pageUrl || targetUrl,
    });
  }

  const vCore = normalizeVulnArray(wps?.version?.vulnerabilities);
  for (const vuln of vCore) pushVuln('WordPress core', vuln, targetUrl);

  const mt = wps?.main_theme;
  if (mt?.slug) {
    const label = `Theme ${mt.slug}`;
    for (const vuln of normalizeVulnArray(mt.vulnerabilities)) pushVuln(label, vuln, mt.location || targetUrl);
    for (const vuln of normalizeVulnArray(mt.version?.vulnerabilities)) pushVuln(label, vuln, mt.location || targetUrl);
  }

  const plugins = wps?.plugins;
  if (plugins && typeof plugins === 'object') {
    for (const [slug, p] of Object.entries(plugins).slice(0, 1_000)) {
      if (slug === '*' || !p || typeof p !== 'object') continue;
      const label = `Plugin ${slug}`;
      const loc = p.location || targetUrl;
      for (const vuln of normalizeVulnArray(p.vulnerabilities)) pushVuln(label, vuln, loc);
      for (const vuln of normalizeVulnArray(p.version?.vulnerabilities)) pushVuln(label, vuln, loc);
    }
  }

  return out;
}

/** Número de vulnerabilidades reportadas no JSON (campos alimentados pela WPVulnDB com token). */
export function countWpvulndbFindings(wpscanJson) {
  if (!wpscanJson || typeof wpscanJson !== 'object') return 0;
  return extractVulnerabilityFindings('https://example.invalid/', wpscanJson).length;
}

function extractCoreVersionFindings(targetUrl, wps) {
  const out = [];
  const v = wps?.version;
  if (!v || typeof v !== 'object') return out;

  const number = v?.number;
  if (!number) return out;

  const confidence = v?.confidence ?? null;
  const { prio, score } = prioScoreFromVersionConfidence({ hasVersion: true, confidence });
  out.push({
    type: 'wpscan',
    prio,
    score,
    value: `WordPress version: ${number}`,
    meta: {
      source: 'kali_wpscan',
      evidenceStatus: 'component_inventory',
      foundBy: v?.found_by || 'unknown',
      confidence,
      note: 'Versão observada não prova vulnerabilidade',
    },
    url: targetUrl,
  });
  return out;
}

export function extractWpscanFindings({ targetUrl, wpscanJson }) {
  if (!wpscanJson || typeof wpscanJson !== 'object') return [];
  const vulns = extractVulnerabilityFindings(targetUrl, wpscanJson);
  const rest = [
    ...extractCoreVersionFindings(targetUrl, wpscanJson),
    ...extractMainThemeFindings(targetUrl, wpscanJson),
    ...extractPluginsFindings(targetUrl, wpscanJson),
  ];

  // Vulnerabilidades (API) primeiro; depois enumeração de versões.
  const merged = [...vulns, ...rest];
  const maxFindings = 100;
  return merged.slice(0, maxFindings);
}

export function classifyWpscanProcessResult(result) {
  if (result?.aborted) return { status: 'cancelled', reason: 'process_aborted' };
  if (result?.timedOut) return { status: 'timeout', reason: 'process_timeout' };
  if (!Number.isInteger(result?.code) || result.code !== 0) {
    return { status: 'failed', reason: 'process_exit', exitCode: Number.isInteger(result?.code) ? result.code : null };
  }
  return { status: 'done', reason: 'completed', exitCode: 0 };
}

export function isWpscanJsonDocument(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  if (value.scan_aborted === true) return false;
  return ['target_url', 'interesting_findings', 'version', 'main_theme', 'plugins', 'vulnerabilities']
    .some((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function wpscanSpawnEnv(apiToken) {
  const names = ['PATH', 'HOME', 'LANG', 'LC_ALL', 'GEM_HOME', 'GEM_PATH', 'RUBYLIB', 'TMPDIR'];
  const env = Object.create(null);
  for (const name of names) {
    if (process.env[name] != null) env[name] = process.env[name];
  }
  if (apiToken) env.WPSCAN_API_TOKEN = apiToken;
  return env;
}

async function readBoundedJsonFile(file, maxBytes = 4 * 1024 * 1024) {
  const info = await stat(file);
  if (!info.isFile()) throw new Error('saída WPScan não é arquivo regular');
  if (info.size > maxBytes) {
    const error = new Error(`saída WPScan excede ${maxBytes} bytes`);
    error.code = 'WPSCAN_OUTPUT_TOO_LARGE';
    throw error;
  }
  return readFile(file, 'utf8');
}

/**
 * Rodar wpscan e retornar JSON parseado.
 * @returns {Promise<{ json: any|null, error?: string, stderr?: string, vulnDbCount?: number }>}
 */
export async function runWpscanJson({
  targetUrl,
  detectionMode,
  timeoutMs,
  log,
  signal = null,
}) {
  let parsedTarget;
  try {
    parsedTarget = new URL(targetUrl);
  } catch {
    return { json: null, error: 'invalid_target_url', status: 'failed' };
  }
  if (!['http:', 'https:'].includes(parsedTarget.protocol) || parsedTarget.username || parsedTarget.password) {
    return { json: null, error: 'invalid_target_url', status: 'failed' };
  }
  parsedTarget.search = '';
  parsedTarget.hash = '';
  targetUrl = parsedTarget.href;
  const dir = await mkdtemp(join(tmpdir(), 'ghwp-'));
  const outJson = join(dir, 'wpscan.json');

  const mode = detectionMode || 'mixed';
  const timeout = Number(timeoutMs) > 0 ? Number(timeoutMs) : 240000;
  const apiToken = resolveWpscanApiToken();

  try {
    const args = [
      '--url',
      targetUrl,
      '--detection-mode',
      mode,
      '--format',
      'json',
      '-o',
      outJson,
      '--no-banner',
    ];

    const spawnEnv = wpscanSpawnEnv(apiToken);

    const label = `wpscan ${mode} ${targetUrl}${apiToken ? ' (API WPVulnDB)' : ''}`;
    if (typeof log === 'function') {
      log(`[WPScan] A executar ferramenta: wpscan --url ${targetUrl} --detection-mode ${mode} --format json …`, 'info');
      log(
        `[WPScan] WPVulnDB (API CVEs): ${apiToken ? 'ligado — token definido' : 'desligado — sem WPSCAN_API_TOKEN'}`,
        apiToken ? 'success' : 'warn',
      );
      log(`[WPScan] Timeout: ${timeout}ms (JSON escrito em ficheiro temporário, depois parseado)`, 'info');
      log(`Executando ${label}...`, 'info');
    }

    const proc = await runProc('wpscan', args, timeout, { env: spawnEnv }, { signal });
    const processState = classifyWpscanProcessResult(proc);
    if (processState.status === 'cancelled') {
      const error = new Error('WPScan cancelado');
      error.name = 'AbortError';
      error.code = 'PROCESS_ABORTED';
      throw error;
    }
    if (processState.status !== 'done') {
      return {
        json: null,
        error: processState.reason,
        status: processState.status,
        exitCode: processState.exitCode ?? null,
      };
    }

    const raw = await readBoundedJsonFile(outJson);
    try {
      const json = JSON.parse(raw);
      if (!isWpscanJsonDocument(json)) {
        return { json: null, error: 'invalid_json_schema', status: 'failed' };
      }
      const vulnDbCount = countWpvulndbFindings(json);
      if (typeof log === 'function') {
        log(`[WPScan] JSON analisado — entradas WPVulnDB (CVEs) no relatório: ${vulnDbCount}`, vulnDbCount ? 'success' : 'info');
        const va = json?.vuln_api;
        if (va && typeof va === 'object' && va.error) {
          log(`[WPScan] Aviso API WPVulnDB: ${String(va.error)}`, 'warn');
        }
      }
      return { json, vulnDbCount, status: 'done' };
    } catch (e) {
      return { json: null, error: 'invalid_json_output', status: 'failed' };
    }
  } catch (e) {
    if (e?.name === 'AbortError' || e?.code === 'PROCESS_ABORTED' || e?.code === 'PROCESS_UNTERMINATED' || e?.fatal) throw e;
    return { json: null, error: String(e?.code || 'execution_or_output_invalid'), status: e?.code === 'PROCESS_TIMEOUT' ? 'timeout' : 'failed' };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
