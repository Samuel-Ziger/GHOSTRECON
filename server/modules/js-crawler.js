import { runProcess } from './module-runner.mjs';

function runProc(cmd, args, timeoutMs = 120000) {
  return runProcess(cmd, args, { timeoutMs, label: cmd });
}

async function which(cmd) {
  try {
    const finder = process.platform === 'win32' ? 'where' : 'which';
    const r = await runProc(finder, [cmd], 6000);
    return r.code === 0;
  } catch {
    return false;
  }
}

export async function crawlWithKatana(seedUrl, { depth = 2 } = {}) {
  if (!(await which('katana'))) return { ok: false, reason: 'katana_not_found', urls: [] };
  try {
    const r = await runProc('katana', ['-u', seedUrl, '-d', String(depth), '-silent'], 150000);
    const urls = [...new Set(
      String(r.stdout || '')
        .split('\n')
        .map((x) => x.trim())
        .filter((x) => /^https?:\/\//i.test(x)),
    )];
    return { ok: true, urls };
  } catch (e) {
    return { ok: false, reason: e.message, urls: [] };
  }
}
