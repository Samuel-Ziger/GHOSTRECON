import { runProcess } from './module-runner.mjs';

function runProc(cmd, args, timeoutMs = 90000) {
  return runProcess(cmd, args, { timeoutMs, label: cmd });
}

async function commandExists(cmd) {
  const finder = process.platform === 'win32' ? 'where' : 'which';
  try {
    const r = await runProc(finder, [cmd], 8000);
    return r.code === 0;
  } catch {
    return false;
  }
}

function normalizeUrls(lines, domain) {
  const out = new Set();
  const d = String(domain || '').toLowerCase();
  for (const line of lines) {
    const u = String(line || '').trim();
    if (!/^https?:\/\//i.test(u)) continue;
    try {
      const x = new URL(u);
      const h = x.hostname.toLowerCase();
      if (h === d || h.endsWith(`.${d}`)) out.add(x.href);
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

export async function fetchArchiveToolUrls(domain, log) {
  const urls = new Set();

  if (await commandExists('gau')) {
    try {
      const r = await runProc('gau', [domain], 120000);
      const got = normalizeUrls(r.stdout.split('\n'), domain);
      for (const u of got) urls.add(u);
      if (typeof log === 'function') log(`gau: ${got.length} URL(s)`, 'info');
    } catch (e) {
      if (typeof log === 'function') log(`gau: ${e.message}`, 'warn');
    }
  }

  if (await commandExists('waybackurls')) {
    try {
      const r = await runProc('waybackurls', [domain], 120000);
      const got = normalizeUrls(r.stdout.split('\n'), domain);
      for (const u of got) urls.add(u);
      if (typeof log === 'function') log(`waybackurls: ${got.length} URL(s)`, 'info');
    } catch (e) {
      if (typeof log === 'function') log(`waybackurls: ${e.message}`, 'warn');
    }
  }

  return [...urls];
}
