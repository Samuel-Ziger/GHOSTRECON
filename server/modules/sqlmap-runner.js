import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { SQLI_PARAM_RE, responseLooksLikeSqlError, evidenceHash } from './verify.js';
import { isStrict, wrapCommand as torStrictWrap } from './tor-strict.js';

function runProc(cmd, args, timeoutMs) {
  // Quando strict, qualquer spawn de tool externa passa por proxychains4.
  if (isStrict()) {
    const w = torStrictWrap(cmd, args);
    if (w.refuse) return Promise.reject(new Error(`tor-strict: ${w.reason}`));
    cmd = w.cmd;
    args = w.args;
  }
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    let killed = false;
    const t = setTimeout(() => {
      killed = true;
      try {
        child.kill('SIGKILL');
      } catch {
        /* ignore */
      }
      reject(new Error(`${cmd} timeout (${timeoutMs}ms)`));
    }, timeoutMs);
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.on('error', (e) => {
      clearTimeout(t);
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(t);
      if (killed) return;
      resolve({
        code,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8'),
      });
    });
  });
}

/** Heurísticas para `--dbms` e `-D` a partir do corpo HTML/JSON (curl). */
export function sniffSqlmapHints(text) {
  const t = String(text || '');
  let dbms = null;
  if (/ORA-\d{4,5}/i.test(t)) dbms = 'Oracle';
  else if (/Microsoft SQL|ODBC SQL Server|SqlException|SQL Server/i.test(t)) dbms = 'Microsoft SQL Server';
  else if (/PostgreSQL|syntax error at or near|PG::[A-Za-z]+Error/i.test(t)) dbms = 'PostgreSQL';
  else if (/SQLite|sqlite3?_/i.test(t)) dbms = 'SQLite';
  else if (/MariaDB/i.test(t)) dbms = 'MySQL';
  else if (/MySQL|mysqli|You have an error in your SQL syntax|SQLSTATE\[HY000\]/i.test(t)) dbms = 'MySQL';

  let database = null;
  const patterns = [
    /Unknown database ['"]([^'"]+)['"]/i,
    /database ['"]([^'"]+)['"] doesn't exist/i,
    /no database ['"]([^'"]+)['"]/i,
    /Unknown column ['"][^'"]+['"] in ['"]([^'"]+)['"]/i,
  ];
  for (const re of patterns) {
    const m = t.match(re);
    if (m?.[1] && /^[a-zA-Z0-9_$-]{1,64}$/.test(m[1])) {
      database = m[1];
      break;
    }
  }
  if (!dbms && /Unknown database/i.test(t)) dbms = 'MySQL';
  return { dbms, database };
}

function resolveCurlProfile(profile = 'standard') {
  const p = String(profile || 'standard').toLowerCase();
  if (p === 'stealth') return { timeoutSec: 18, retry: 1, retryDelaySec: 2, useHttp2: false };
  if (p === 'aggressive') return { timeoutSec: 24, retry: 3, retryDelaySec: 1, useHttp2: true };
  if (p === 'quick') return { timeoutSec: 10, retry: 1, retryDelaySec: 1, useHttp2: true };
  return { timeoutSec: 14, retry: 2, retryDelaySec: 1, useHttp2: true };
}

function buildCurlArgs({ url, auth, profile = 'standard', proxy = null, headerFile, bodyFile }) {
  const cfg = resolveCurlProfile(profile);
  const args = [
    '-sS',
    '--fail-with-body',
    '-g',
    '-L',
    '--max-redirs',
    '2',
    '--tlsv1.2',
    '--compressed',
    '-A',
    'GhostRecon-sqlmap-preflight/1.1',
    '-m',
    String(cfg.timeoutSec),
    '--retry',
    String(cfg.retry),
    '--retry-delay',
    String(cfg.retryDelaySec),
    '--retry-connrefused',
    '-D',
    headerFile,
    '-o',
    bodyFile,
    '-w',
    '{"http_code":"%{http_code}","time_total":"%{time_total}","redirect_url":"%{redirect_url}","size_download":"%{size_download}","remote_ip":"%{remote_ip}","url_effective":"%{url_effective}"}',
  ];
  if (cfg.useHttp2) args.push('--http2');
  // Em strict, não passamos --proxy ao curl: o proxychains4 já intercepta o
  // connect e direciona para o Tor SOCKS — duplicar leva a SOCKS-over-SOCKS.
  if (proxy && !isStrict()) args.push('--proxy', String(proxy));
  if (auth?.cookie) args.push('-H', `Cookie: ${String(auth.cookie)}`);
  if (auth?.headers && typeof auth.headers === 'object') {
    for (const [k, v] of Object.entries(auth.headers)) {
      if (!k || v == null) continue;
      args.push('-H', `${k}: ${String(v)}`);
    }
  }
  args.push(url);
  return args;
}

function resolveCurlProxy(identityCtrl = null) {
  const fromCtrl = identityCtrl?.getCurrentProxy?.();
  if (fromCtrl) return fromCtrl;
  const envPool = String(process.env.GHOSTRECON_PROXY_POOL || '')
    .split(/[,;\n]/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (envPool[0]) return envPool[0];
  // Em strict, default explícito para Tor SOCKS5h.
  if (isStrict()) return 'socks5h://127.0.0.1:9050';
  return null;
}

async function curlGet(url, auth, { timeoutMs = 16000, profile = 'standard', identityCtrl = null } = {}) {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghostrecon-curl-sqlmap-'));
  const headerFile = path.join(tmpDir, 'headers.txt');
  const bodyFile = path.join(tmpDir, 'body.txt');
  const proxy = resolveCurlProxy(identityCtrl);
  try {
    const r = await runProc(
      'curl',
      buildCurlArgs({ url, auth, profile, proxy, headerFile, bodyFile }),
      timeoutMs,
    );
    const body = await fs.readFile(bodyFile, 'utf8').catch(() => '');
    const headersRaw = await fs.readFile(headerFile, 'utf8').catch(() => '');
    let metrics = {};
    try {
      metrics = JSON.parse(String(r.stdout || '{}').trim() || '{}');
    } catch {
      metrics = {};
    }
    const httpCode = Number(metrics.http_code || 0);
    return {
      ok: true,
      body,
      headersRaw,
      stderr: r.stderr,
      code: Number.isFinite(httpCode) ? httpCode : 0,
      metrics,
      proxyUsed: proxy || null,
    };
  } catch (e) {
    return { ok: false, error: e?.message || String(e), body: '', stderr: '', code: -1, metrics: {}, proxyUsed: proxy || null };
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}

function collectSqliTargets(findings, maxTargets) {
  const cap = Math.max(1, Math.min(12, maxTargets));
  const out = [];
  const seen = new Set();

  const tryAdd = (urlStr, paramName, baseVal) => {
    if (!urlStr || !paramName || !SQLI_PARAM_RE.test(String(paramName).toLowerCase())) return;
    try {
      const u = new URL(urlStr);
      if (!u.searchParams.has(paramName)) return;
      const key = `${u.origin}${u.pathname}?${paramName}`;
      if (seen.has(key)) return;
      seen.add(key);
      const bv =
        u.searchParams.get(paramName) != null && String(u.searchParams.get(paramName)).length > 0
          ? String(u.searchParams.get(paramName))
          : '1';
      out.push({ url: u.href, param: paramName, baseVal: baseVal != null ? String(baseVal) : bv });
    } catch {
      /* ignore */
    }
  };

  for (const f of findings || []) {
    if (out.length >= cap) break;
    if (f?.type === 'param' && typeof f.url === 'string' && /^https?:\/\//i.test(f.url)) {
      const m = String(f.value || '').match(/^\?([a-zA-Z_][a-zA-Z0-9_]{0,64})=\s*$/);
      if (m?.[1]) tryAdd(f.url, m[1]);
    }
  }

  for (const f of findings || []) {
    if (out.length >= cap) break;
    if (f?.type !== 'endpoint' || typeof f.value !== 'string' || !/^https?:\/\//i.test(f.value)) continue;
    if (!f.value.includes('?')) continue;
    try {
      const u = new URL(f.value);
      for (const k of u.searchParams.keys()) {
        if (out.length >= cap) break;
        tryAdd(f.value, k);
      }
    } catch {
      /* ignore */
    }
  }

  return out.slice(0, cap);
}

function setSearchParam(urlStr, param, value) {
  const u = new URL(urlStr);
  u.searchParams.set(param, value);
  return u.href;
}

function buildSqlmapArgs(targetUrl, param, auth, hints, runDbsEnumeration) {
  const args = [
    '-u',
    targetUrl,
    '-p',
    param,
    '--batch',
    '--risk=2',
    '--level=3',
    '--timeout=25',
    '--threads=1',
  ];
  if (hints?.dbms) args.push(`--dbms=${hints.dbms}`);
  if (hints?.database) args.push('-D', hints.database);
  if (runDbsEnumeration) args.push('--dbs');
  if (auth?.cookie) args.push('--cookie', String(auth.cookie));
  if (auth?.headers && typeof auth.headers === 'object') {
    for (const [k, v] of Object.entries(auth.headers)) {
      if (!k || v == null) continue;
      args.push('--header', `${k}: ${String(v)}`);
    }
  }
  return args;
}

function sqlmapOutputSuggestsInjection(combined) {
  const s = String(combined || '').toLowerCase();
  return (
    /parameter ['"][^'"]+['"] is vulnerable/i.test(s) ||
    /might be injectable/i.test(s) ||
    /sql injection/i.test(s) ||
    /payload:\s*and/i.test(s) ||
    /back-end dbms/i.test(s)
  );
}

/**
 * Pré-flight com curl (baseline vs ') e sqlmap --batch --risk=2 --level=3 quando há sinal SQL.
 * @param {object} opts
 * @param {object[]} opts.findings
 * @param {object} opts.auth
 * @param {function} opts.log
 * @param {number} [opts.maxTargets]
 */
export async function runSqlmapModule({ findings, auth, log, maxTargets = 2, profile = 'standard', identityCtrl = null }) {
  const outFindings = [];
  const logFn = typeof log === 'function' ? log : () => {};

  let hasSqlmap = false;
  try {
    const chk = await runProc('which', ['sqlmap'], 4000);
    hasSqlmap = chk.code === 0 && /sqlmap/.test(chk.stdout);
  } catch {
    hasSqlmap = false;
  }
  if (!hasSqlmap) {
    try {
      await runProc('sqlmap', ['--version'], 6000);
      hasSqlmap = true;
    } catch {
      hasSqlmap = false;
    }
  }

  if (!hasSqlmap) {
    logFn('sqlmap: executável não encontrado (PATH). Instala no Kali ou exporta o PATH.', 'warn');
    return outFindings;
  }

  const timeoutMs = Math.max(60000, Number(process.env.GHOSTRECON_SQLMAP_TIMEOUT_MS) || 180000);
  const targets = collectSqliTargets(findings, maxTargets);
  if (!targets.length) {
    logFn('sqlmap: sem URLs com parâmetros candidatos a SQLi no corpus.', 'info');
    return outFindings;
  }

  logFn(
    'sqlmap: só em alvos autorizados — módulo invoca ferramenta ofensiva; pré-check com curl antes de sqlmap.',
    'warn',
  );

  for (const t of targets) {
    const baseUrl = setSearchParam(t.url, t.param, t.baseVal);
    const tickUrl = setSearchParam(t.url, t.param, `${t.baseVal}'`);

    logFn(`sqlmap: curl baseline → ${baseUrl.slice(0, 120)}${baseUrl.length > 120 ? '…' : ''}`, 'info');
    const c0 = await curlGet(baseUrl, auth, { profile, identityCtrl });
    if (!c0.ok) logFn(`sqlmap: curl baseline falhou: ${c0.error || c0.stderr}`, 'warn');

    logFn(`sqlmap: curl com aspas → ?${t.param}=…'`, 'info');
    const c1 = await curlGet(tickUrl, auth, { profile, identityCtrl });
    if (!c1.ok) logFn(`sqlmap: curl (') falhou: ${c1.error || c1.stderr}`, 'warn');

    const errBase = responseLooksLikeSqlError(c0.body);
    const errTick = responseLooksLikeSqlError(c1.body);
    const hintsTick = sniffSqlmapHints(c1.body);
    const hintsBase = sniffSqlmapHints(c0.body);

    logFn(
      `sqlmap: pré-flight ?${t.param}= • sql_err_baseline=${errBase ? 'yes' : 'no'} • sql_err_tick=${errTick ? 'yes' : 'no'} • status_curl=${c1.code} • t=${c1.metrics?.time_total || '?'}s • ip=${c1.metrics?.remote_ip || '?'}${c1.proxyUsed ? ` • proxy=${c1.proxyUsed}` : ''}`,
      'info',
    );
    if (hintsTick.dbms || hintsBase.dbms) {
      logFn(`sqlmap: indício SGBD na resposta → ${hintsTick.dbms || hintsBase.dbms || 'n/a'}`, 'info');
    }
    if (hintsTick.database) {
      logFn(`sqlmap: nome de BD/schema na resposta → ${hintsTick.database}`, 'info');
    }

    const interesting = (errTick && !errBase) || (hintsTick.dbms && errTick) || (hintsTick.database && errTick);
    if (!interesting) {
      logFn(`sqlmap: sem sinal forte (erro SQL com ' vs baseline) — sqlmap não invocado para este alvo.`, 'info');
      continue;
    }

    const hints = {
      dbms: hintsTick.dbms || hintsBase.dbms || null,
      database: hintsTick.database || hintsBase.database || null,
    };

    const runDbs = Boolean(hints.database || hints.dbms);
    const argsProbe = buildSqlmapArgs(baseUrl, t.param, auth, hints, false);
    logFn(`sqlmap: a correr (timeout ${timeoutMs}ms): sqlmap ${argsProbe.map((a) => (/\s/.test(a) ? JSON.stringify(a) : a)).join(' ')}`, 'info');

    let combined = '';
    try {
      const run = await runProc('sqlmap', argsProbe, timeoutMs);
      combined = `${run.stdout}\n${run.stderr}`;
      const inj = sqlmapOutputSuggestsInjection(combined);
      logFn(
        inj
          ? 'sqlmap: saída sugere ponto de injeção ou fingerprint — rever output completo no terminal.'
          : 'sqlmap: terminou sem confirmação clara na saída truncada; rever manualmente.',
        inj ? 'success' : 'info',
      );
      const snippet = combined.replace(/\s+/g, ' ').trim().slice(0, 420);
      const evidence = {
        source: 'sqlmap-runner',
        url: tickUrl,
        method: 'GET',
        status: 0,
        requestSnippet: `curl+sqlmap • ${t.param}`,
        responseSnippet: snippet,
        timestamp: new Date().toISOString(),
      };

      outFindings.push({
        type: 'sqli',
        prio: inj ? 'high' : 'med',
        score: inj ? 99 : 78,
        value: `SQLmap (${inj ? 'possível injeção' : 'inconclusivo'}) @ ?${t.param}=`,
        meta: `tool=sqlmap • param=${t.param} • dbms=${hints.dbms || 'n/a'} • D=${hints.database || 'n/a'} • curl_sql_tick=${errTick ? 'yes' : 'no'}`,
        url: tickUrl,
        verification: {
          classification: inj ? 'confirmed' : 'probable',
          evidence: {
            ...evidence,
            curl: {
              baseline: c0.metrics,
              tick: c1.metrics,
              baselineStatus: c0.code,
              tickStatus: c1.code,
              proxy: c1.proxyUsed || null,
            },
            evidenceHash: evidenceHash(evidence),
          },
          verifiedAt: new Date().toISOString(),
        },
      });

      if (runDbs && process.env.GHOSTRECON_SQLMAP_AUTO_DBS === '1') {
        const argsDbs = buildSqlmapArgs(baseUrl, t.param, auth, { dbms: hints.dbms, database: null }, true);
        logFn(`sqlmap: GHOSTRECON_SQLMAP_AUTO_DBS=1 — segunda fase --dbs…`, 'warn');
        try {
          const run2 = await runProc('sqlmap', argsDbs, timeoutMs);
          const c2 = `${run2.stdout}\n${run2.stderr}`;
          logFn(`sqlmap --dbs: ${c2.replace(/\s+/g, ' ').trim().slice(0, 360)}`, 'info');
        } catch (e2) {
          logFn(`sqlmap --dbs: ${e2.message}`, 'warn');
        }
      } else if (hints.database || hints.dbms) {
        const suggest = buildSqlmapArgs(baseUrl, t.param, auth, { dbms: hints.dbms, database: null }, true)
          .map((a) => (/\s/.test(a) ? JSON.stringify(a) : a))
          .join(' ');
        logFn(`sqlmap: para listar bases manualmente: sqlmap ${suggest}`, 'info');
      }
    } catch (e) {
      logFn(`sqlmap: erro ou timeout: ${e.message}`, 'warn');
    }
  }

  return outFindings;
}
