import { runProcess } from './module-runner.mjs';
import { getKaliCapabilities } from './kali-scan.js';

const ALFA_USB_IDS = new Set(['0e8d:7612']);
const ALFA_NAME_RE = /AWUS036ACM|MT7612U|MT7612/i;
const BSSID_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;

export const KALI_WIFI_MODULE_ID = 'kali_wifi';

export function parseWifiTargets(raw) {
  const text = String(raw || '').trim();
  if (!text) return { bssids: [], ssids: [] };
  const bssids = new Set();
  const ssids = new Set();
  for (const line of text.split(/[\r\n,;]+/)) {
    const item = String(line || '').trim();
    if (!item || item.startsWith('#')) continue;
    if (BSSID_RE.test(item)) bssids.add(item.toLowerCase());
    else ssids.add(item);
  }
  return { bssids: [...bssids], ssids: [...ssids] };
}

export function wifiTargetsFromEnv(env = process.env) {
  return parseWifiTargets(env.GHOSTRECON_WIFI_TARGETS || '');
}

export function resolveWifiTimeoutMs(env = process.env) {
  const n = Number(env.GHOSTRECON_WIFI_TIMEOUT_MS ?? 900_000);
  if (!Number.isFinite(n) || n < 30_000) return 900_000;
  return Math.min(Math.floor(n), 3_600_000);
}

export function resolveWifiWordlist(env = process.env) {
  const fromEnv = String(env.GHOSTRECON_WIFI_WORDLIST || '').trim();
  if (fromEnv) return fromEnv;
  return '/usr/share/wordlists/rockyou.txt';
}

/**
 * Parse linhas de stdout Wifite/aircrack em findings tipados.
 */
export function parseWifiToolLine(line) {
  const text = String(line || '').trim();
  if (!text) return null;

  const handshake =
    text.match(/handshake\s+(?:captured|saved|found).*?([0-9a-f:]{17})/i)
    || text.match(/saved\s+handshake.*?([0-9a-f:]{17})/i)
    || (/\.cap\b/i.test(text) && /handshake|saved|written/i.test(text) ? [text] : null);
  if (handshake) {
    const bssid = typeof handshake[1] === 'string' && BSSID_RE.test(handshake[1])
      ? handshake[1].toLowerCase()
      : null;
    return {
      type: 'wifi_handshake',
      prio: 'high',
      score: 78,
      value: bssid ? `Handshake capturado ${bssid}` : 'Handshake / captura .cap detetada',
      meta: text.slice(0, 240),
    };
  }

  const cracked = text.match(/(?:key\s+found|psk\s*[:=]|password\s*[:=])\s*['"]?([^\s'"]+)/i);
  if (cracked) {
    return {
      type: 'wifi_crack',
      prio: 'critical',
      score: 92,
      value: 'Credencial WiFi recuperada (lab)',
      meta: `resultado: ${cracked[1]} · ${text.slice(0, 160)}`,
    };
  }

  const ap = text.match(/(?:essid|ssid)\s*[:=]\s*['"]?([^'"\n]+)/i);
  const bssidHit = text.match(/\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b/i);
  if (ap || (bssidHit && /(?:ap|access\s*point|beacon)/i.test(text))) {
    return {
      type: 'wifi_ap',
      prio: 'med',
      score: 45,
      value: ap ? `AP ${String(ap[1]).trim()}` : `AP ${bssidHit[1].toLowerCase()}`,
      meta: text.slice(0, 240),
    };
  }

  return null;
}

async function whichTool(name, { runProcessImpl = runProcess, signal } = {}) {
  try {
    const finder = process.platform === 'win32' ? 'where' : 'which';
    const r = await runProcessImpl(finder, [name], {
      timeoutMs: 8_000,
      signal,
      rejectOnError: false,
      rejectOnTimeout: false,
      stdoutMaxBytes: 8 * 1024,
      stderrMaxBytes: 2 * 1024,
      label: `which:${name}`,
    });
    const pathLine = String(r.stdout || '')
      .split(/\r?\n/)
      .map((l) => l.trim())
      .find(Boolean);
    return Boolean(pathLine);
  } catch {
    return false;
  }
}

export function detectAlfaFromLsusb(stdout) {
  const text = String(stdout || '');
  const matches = [];
  for (const line of text.split(/\r?\n/)) {
    const idMatch = line.match(/\b([0-9a-f]{4}:[0-9a-f]{4})\b/i);
    const id = idMatch ? idMatch[1].toLowerCase() : '';
    const byId = id && ALFA_USB_IDS.has(id);
    const byName = ALFA_NAME_RE.test(line);
    if (byId || byName) {
      matches.push({
        id: id || null,
        line: line.trim().slice(0, 200),
        byId,
        byName,
      });
    }
  }
  return { found: matches.length > 0, matches };
}

export function parseIwInterfaces(stdout) {
  const text = String(stdout || '');
  const ifaces = [];
  let current = null;
  for (const line of text.split(/\r?\n/)) {
    const iface = line.match(/^\s*Interface\s+(\S+)/i);
    if (iface) {
      current = { name: iface[1], type: '', addr: '' };
      ifaces.push(current);
      continue;
    }
    if (!current) continue;
    const type = line.match(/^\s*type\s+(\S+)/i);
    if (type) current.type = type[1].toLowerCase();
    const addr = line.match(/^\s*addr\s+([0-9a-f:]+)/i);
    if (addr) current.addr = addr[1].toLowerCase();
  }
  return ifaces;
}

/**
 * Inventário passivo: Kali tools + ALFA + interfaces.
 */
export async function probeWifiEnvironment({
  runProcessImpl = runProcess,
  signal = null,
} = {}) {
  const toolNames = ['lsusb', 'iw', 'airmon-ng', 'airodump-ng', 'aircrack-ng', 'wifite'];
  const tools = {};
  for (const name of toolNames) {
    tools[name] = await whichTool(name, { runProcessImpl, signal });
  }

  let lsusbOut = '';
  if (tools.lsusb) {
    try {
      const r = await runProcessImpl('lsusb', [], {
        timeoutMs: 12_000,
        signal,
        rejectOnError: false,
        rejectOnTimeout: false,
        stdoutMaxBytes: 256 * 1024,
        stderrMaxBytes: 16 * 1024,
        label: 'lsusb',
      });
      lsusbOut = r.stdout || '';
    } catch {
      lsusbOut = '';
    }
  }

  const adapter = detectAlfaFromLsusb(lsusbOut);

  let interfaces = [];
  if (tools.iw) {
    try {
      const r = await runProcessImpl('iw', ['dev'], {
        timeoutMs: 12_000,
        signal,
        rejectOnError: false,
        rejectOnTimeout: false,
        stdoutMaxBytes: 128 * 1024,
        stderrMaxBytes: 16 * 1024,
        label: 'iw-dev',
      });
      interfaces = parseIwInterfaces(r.stdout || '');
    } catch {
      interfaces = [];
    }
  }

  const wlan = interfaces.find((i) => /^wlan/i.test(i.name)) || interfaces[0] || null;
  return {
    tools,
    adapter,
    interfaces,
    preferredIface: wlan?.name || null,
    readyForAttack: Boolean(
      adapter.found
      && tools.wifite
      && tools['airmon-ng']
      && tools['aircrack-ng'],
    ),
  };
}

function emitFinding(emit, finding) {
  if (typeof emit !== 'function' || !finding) return;
  emit({ type: 'finding', finding });
}

function emitLog(emit, message, level = 'info') {
  if (typeof emit !== 'function') return;
  emit({ type: 'log', level, message: String(message) });
}

function emitPipe(emit, state, detail = null) {
  if (typeof emit !== 'function') return;
  emit({ type: 'pipe', name: KALI_WIFI_MODULE_ID, state, ...(detail ? { detail } : {}) });
}

async function cleanupMonitor(iface, { runProcessImpl, signal, emit }) {
  if (!iface) return;
  try {
    emitLog(emit, `Cleanup: airmon-ng stop ${iface}`, 'info');
    await runProcessImpl('airmon-ng', ['stop', iface], {
      timeoutMs: 20_000,
      signal,
      rejectOnError: false,
      rejectOnTimeout: false,
      stdoutMaxBytes: 64 * 1024,
      stderrMaxBytes: 32 * 1024,
      label: 'airmon-stop',
    });
  } catch (e) {
    emitLog(emit, `Cleanup airmon: ${e.message}`, 'warn');
  }
}

/**
 * Orquestra readiness (+ Wifite se labConfirm + alvos).
 */
export async function runWifiPentest({
  targetsText = '',
  labConfirm = false,
  wordlist = null,
  iface = null,
  emit = () => {},
  signal = null,
  runProcessImpl = runProcess,
  getKaliCapabilitiesImpl = getKaliCapabilities,
  env = process.env,
} = {}) {
  emitPipe(emit, 'active');
  const findings = [];
  const pushFinding = (f) => {
    findings.push(f);
    emitFinding(emit, f);
  };

  let kaliCap;
  try {
    kaliCap = await getKaliCapabilitiesImpl({ signal });
  } catch (e) {
    emitLog(emit, `Kali capabilities: ${e.message}`, 'warn');
    kaliCap = { kali: false, message: e.message, tools: {} };
  }

  if (!kaliCap?.kali) {
    emitLog(emit, `Ambiente não Kali pronto: ${kaliCap?.message || 'indisponível'}`, 'warn');
    pushFinding({
      type: 'intel',
      prio: 'low',
      score: 20,
      value: 'Pentest WiFi: Kali não disponível',
      meta: kaliCap?.message || 'Requer Kali Linux (ou GHOSTRECON_FORCE_KALI=1) com tools no PATH',
    });
    emitPipe(emit, 'skipped', { reason: 'not_kali' });
    return { ok: false, reason: 'not_kali', findings, env: null };
  }

  const probe = await probeWifiEnvironment({ runProcessImpl, signal });
  const missingTools = Object.entries(probe.tools)
    .filter(([, ok]) => !ok)
    .map(([name]) => name);

  pushFinding({
    type: 'intel',
    prio: probe.adapter.found ? 'med' : 'high',
    score: probe.adapter.found ? 55 : 35,
    value: probe.adapter.found
      ? 'ALFA AWUS036ACM / MT7612U detetada'
      : 'ALFA AWUS036ACM (MT7612U) não encontrada',
    meta: probe.adapter.found
      ? probe.adapter.matches.map((m) => m.line).join(' · ').slice(0, 300)
      : 'Procure USB 0e8d:7612 / AWUS036ACM no lsusb (passthrough USB na VM)',
  });

  if (missingTools.length) {
    pushFinding({
      type: 'intel',
      prio: 'med',
      score: 40,
      value: 'Ferramentas WiFi em falta no PATH',
      meta: missingTools.join(', '),
    });
  }

  emitLog(
    emit,
    `Readiness: adapter=${probe.adapter.found ? 'yes' : 'no'} iface=${probe.preferredIface || '—'} tools_ok=${!missingTools.length}`,
    'info',
  );

  const fromBody = parseWifiTargets(targetsText);
  const fromEnv = wifiTargetsFromEnv(env);
  const targets = {
    bssids: [...new Set([...fromBody.bssids, ...fromEnv.bssids])],
    ssids: [...new Set([...fromBody.ssids, ...fromEnv.ssids])],
  };
  const hasTargets = targets.bssids.length > 0 || targets.ssids.length > 0;
  const confirm = labConfirm === true;
  const attackIface = String(iface || probe.preferredIface || '').trim() || null;
  const dict = String(wordlist || resolveWifiWordlist(env)).trim();
  const timeoutMs = resolveWifiTimeoutMs(env);

  if (!confirm || !hasTargets) {
    const why = !confirm
      ? 'confirmação de lab/rede própria em falta'
      : 'sem BSSID/SSID autorizados';
    emitLog(emit, `Ataque omitido (${why}) — só readiness.`, 'info');
    emitPipe(emit, 'done', { mode: 'readiness' });
    return {
      ok: true,
      reason: 'readiness_only',
      findings,
      env: probe,
      targets,
    };
  }

  if (!probe.adapter.found) {
    emitLog(emit, 'ALFA ausente — não inicia Wifite.', 'warn');
    emitPipe(emit, 'skipped', { reason: 'no_adapter' });
    return { ok: false, reason: 'no_adapter', findings, env: probe, targets };
  }

  if (!probe.tools.wifite) {
    emitLog(emit, 'wifite não está no PATH.', 'warn');
    emitPipe(emit, 'skipped', { reason: 'no_wifite' });
    return { ok: false, reason: 'no_wifite', findings, env: probe, targets };
  }

  if (!attackIface) {
    emitLog(emit, 'Nenhuma interface wlan* encontrada.', 'warn');
    emitPipe(emit, 'skipped', { reason: 'no_iface' });
    return { ok: false, reason: 'no_iface', findings, env: probe, targets };
  }

  const jobs = [];
  for (const bssid of targets.bssids) jobs.push({ kind: 'bssid', value: bssid });
  for (const ssid of targets.ssids) jobs.push({ kind: 'essid', value: ssid });

  let monitorIface = attackIface;
  try {
    if (probe.tools['airmon-ng']) {
      emitLog(emit, `airmon-ng start ${attackIface}`, 'info');
      const mon = await runProcessImpl('airmon-ng', ['start', attackIface], {
        timeoutMs: 45_000,
        signal,
        rejectOnError: false,
        rejectOnTimeout: false,
        stdoutMaxBytes: 128 * 1024,
        stderrMaxBytes: 64 * 1024,
        label: 'airmon-start',
        onStdout: (buf) => {
          for (const line of String(buf).split(/\r?\n/)) {
            if (line.trim()) emitLog(emit, line.trim(), 'info');
          }
        },
      });
      const monHit = String(mon.stdout || '').match(/\b(wlan\d+mon|mon\d+)\b/i);
      if (monHit) monitorIface = monHit[1];
      else if (!/mon$/i.test(monitorIface)) monitorIface = `${attackIface}mon`;
    }

    for (const job of jobs) {
      if (signal?.aborted) throw Object.assign(new Error('cancelado'), { name: 'AbortError' });

      const args = ['--kill', '-i', monitorIface, '--no-wps'];
      if (job.kind === 'bssid') args.push('--bssid', job.value);
      else args.push('--essid', job.value);
      if (dict) args.push('--dict', dict);

      emitLog(emit, `wifite ${args.join(' ')}`, 'info');
      const lineBuf = { rest: '' };
      const onChunk = (buf, stream) => {
        const chunk = String(buf);
        const mixed = lineBuf.rest + chunk;
        const parts = mixed.split(/\r?\n/);
        lineBuf.rest = parts.pop() || '';
        for (const line of parts) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          emitLog(emit, `[${stream}] ${trimmed}`, 'info');
          const parsed = parseWifiToolLine(trimmed);
          if (parsed) pushFinding(parsed);
        }
      };

      try {
        await runProcessImpl('wifite', args, {
          timeoutMs,
          signal,
          rejectOnError: false,
          rejectOnTimeout: true,
          stdoutMaxBytes: 8 * 1024 * 1024,
          stderrMaxBytes: 2 * 1024 * 1024,
          label: `wifite:${job.value}`,
          onStdout: (b) => onChunk(b, 'out'),
          onStderr: (b) => onChunk(b, 'err'),
        });
      } catch (e) {
        if (e?.name === 'AbortError' || e?.code === 'PROCESS_ABORTED') throw e;
        emitLog(emit, `wifite ${job.value}: ${e.message}`, 'warn');
        pushFinding({
          type: 'intel',
          prio: 'med',
          score: 40,
          value: `Wifite falhou para ${job.value}`,
          meta: e.message,
        });
      }
      if (lineBuf.rest.trim()) {
        const parsed = parseWifiToolLine(lineBuf.rest.trim());
        if (parsed) pushFinding(parsed);
      }
    }

    emitPipe(emit, 'done', { mode: 'attack', jobs: jobs.length });
    return { ok: true, reason: 'completed', findings, env: probe, targets, monitorIface };
  } catch (e) {
    if (e?.name === 'AbortError' || e?.code === 'PROCESS_ABORTED') {
      emitLog(emit, 'Pentest WiFi cancelado', 'warn');
      emitPipe(emit, 'cancelled');
      return { ok: false, reason: 'cancelled', findings, env: probe, targets };
    }
    emitLog(emit, `Pentest WiFi: ${e.message}`, 'error');
    emitPipe(emit, 'failed', { error: e.message });
    return { ok: false, reason: 'failed', findings, env: probe, targets, error: e.message };
  } finally {
    await cleanupMonitor(monitorIface, { runProcessImpl, signal: null, emit });
  }
}

/**
 * Snapshot leve para /api/capabilities (sem Wifite).
 */
export async function getWifiCapabilities({
  runProcessImpl = runProcess,
  getKaliCapabilitiesImpl = getKaliCapabilities,
  signal = null,
} = {}) {
  let kali = false;
  let kaliMessage = '';
  try {
    const cap = await getKaliCapabilitiesImpl({ signal });
    kali = Boolean(cap?.kali);
    kaliMessage = cap?.message || '';
  } catch (e) {
    kaliMessage = e.message;
  }
  if (!kali) {
    return {
      ok: false,
      kali: false,
      message: kaliMessage || 'Kali indisponível',
      adapter: { found: false, matches: [] },
      tools: {},
      preferredIface: null,
      readyForAttack: false,
    };
  }
  const probe = await probeWifiEnvironment({ runProcessImpl, signal });
  return {
    ok: probe.adapter.found && probe.tools.wifite,
    kali: true,
    message: probe.adapter.found
      ? 'ALFA detetada — confirme lab e alvos para atacar'
      : 'Kali OK; ALFA AWUS036ACM/MT7612U não detetada',
    adapter: probe.adapter,
    tools: probe.tools,
    preferredIface: probe.preferredIface,
    readyForAttack: probe.readyForAttack,
  };
}
