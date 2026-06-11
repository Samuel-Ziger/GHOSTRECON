import { runProcess } from './module-runner.mjs';

function runProc(cmd, args, timeoutMs = 60000) {
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

function parseParamsFromArjunOutput(text) {
  const out = new Set();
  for (const line of String(text || '').split('\n')) {
    const m = line.match(/(\w+)\s*=/) || line.match(/param:\s*([a-z0-9_]+)/i);
    if (m?.[1]) out.add(m[1]);
  }
  return [...out];
}

function parseParamsFromX8Output(text) {
  const out = new Set();
  for (const line of String(text || '').split('\n')) {
    const m = line.match(/param(?:eter)?:\s*([a-z0-9_]+)/i) || line.match(/([a-z0-9_]+)=X8/i);
    if (m?.[1]) out.add(m[1]);
  }
  return [...out];
}

export async function discoverParamsActive(url, { timeoutMs = 60000 } = {}) {
  if (await which('arjun')) {
    try {
      const r = await runProc('arjun', ['-u', url, '-m', 'GET', '-t', '20', '--stable'], timeoutMs);
      const params = parseParamsFromArjunOutput(r.stdout);
      return { tool: 'arjun', params };
    } catch (e) {
      return { tool: 'arjun', params: [], error: e.message };
    }
  }
  if (await which('x8')) {
    try {
      const r = await runProc('x8', ['-u', url], timeoutMs);
      const params = parseParamsFromX8Output(r.stdout);
      return { tool: 'x8', params };
    } catch (e) {
      return { tool: 'x8', params: [], error: e.message };
    }
  }
  return { tool: 'none', params: [] };
}
