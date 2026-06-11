import { runProcess } from './module-runner.mjs';

function runProc(cmd, args, timeoutMs = 25000) {
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

export async function wafw00fFingerprint(host) {
  if (!(await which('wafw00f'))) return null;
  try {
    const r = await runProc('wafw00f', ['-a', host], 28000);
    const text = [r.stdout, r.stderr].join('\n').toLowerCase();
    const m = text.match(/is behind (.+?)\./i) || text.match(/detected.*waf(?:.*):\s*(.+)/i);
    const waf = m ? m[1].trim() : '';
    return waf ? { tool: 'wafw00f', waf } : { tool: 'wafw00f', waf: '' };
  } catch (e) {
    return { tool: 'wafw00f', error: e.message };
  }
}
