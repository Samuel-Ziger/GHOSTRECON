import fs from 'fs';
import { readFile, writeFile, mkdtemp, rm, stat } from 'fs/promises';
import { join, delimiter } from 'path';
import { tmpdir } from 'os';
import net from 'node:net';
import { limits } from '../config.js';
import { sevToPrio, sevToScore } from '../lib/severity.mjs';
import { enrichFromTechStrings } from './cve-enrichment.js';
import {
  runWpscanJson,
  extractWpscanFindings,
  isWpscanApiTokenConfigured,
  isWpscanApiRequired,
  countWpvulndbFindings,
} from './wpscan.js';
import { hostLiteralForUrl } from './recon-target.js';
import { buildMysql3306IntelFindings } from './mysql-nmap-intel.js';
import { probeFtpAnonymousWritable } from './ftp-anon-write-probe.js';
import {
  ftpAnonymousLoginFinding,
  isFtpServiceRow,
  probeFtpAnonymousLogin,
} from './ftp-anonymous-login.mjs';
import { postFtpAnonymousWritableCriticalWebhook } from './webhook-notify.js';
import { positiveIntEnv, runProcess } from './module-runner.mjs';
import { throwIfAborted } from './http-utils.js';

const WORDLISTS = [
  '/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt',
  '/usr/share/seclists/Discovery/Web-Content/common.txt',
  '/usr/share/wordlists/dirb/common.txt',
];

const INFO_DISCLOSURE_SCRIPT = join(process.cwd(), 'tools/info-disclosure/information_disclosure.py');
const INFO_DISCLOSURE_SAFE_MODULES = ['headers', 'files', 'listing', 'comments', 'metadata'];
const INFO_DISCLOSURE_ERROR_MODULE = 'errors';
const TOOL_STDOUT_MAX_BYTES = positiveIntEnv('GHOSTRECON_TOOL_STDOUT_MAX_BYTES', 16 * 1024 * 1024, {
  max: 128 * 1024 * 1024,
});
const TOOL_STDERR_MAX_BYTES = positiveIntEnv('GHOSTRECON_TOOL_STDERR_MAX_BYTES', 2 * 1024 * 1024, {
  max: 32 * 1024 * 1024,
});

function sanitizeHost(h) {
  if (typeof h !== 'string' || h.length < 3) return null;
  const s = h.trim();
  if (net.isIPv4(s)) return s;
  if (net.isIPv6(s)) return s.toLowerCase();
  if (s.length > 253) return null;
  const t = s.toLowerCase();
  if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(t)) return null;
  return t;
}

async function pathWhich(cmd, { signal = null } = {}) {
  const finder = process.platform === 'win32' ? 'where' : 'which';
  try {
    const result = await runProcess(finder, [cmd], {
      timeoutMs: 6_000,
      signal,
      rejectOnError: false,
      rejectOnTimeout: false,
      label: `${finder} ${cmd}`,
      stdoutMaxBytes: 64 * 1024,
      stderrMaxBytes: 64 * 1024,
    });
    return result.code === 0;
  } catch (error) {
    if (error?.name === 'AbortError' || error?.code === 'PROCESS_ABORTED') throw error;
    // A detecção de ferramentas é opcional; falha local equivale a ausente.
    return false;
  }
}

/** `which` + caminhos absolutos (IDE/systemd por vezes não herdam PATH completo com ~/go/bin). */
function fileExecutableExists(absPath) {
  if (!absPath || typeof absPath !== 'string') return false;
  try {
    const st = fs.statSync(absPath);
    return st.isFile() || st.isSymbolicLink();
  } catch {
    return false;
  }
}

async function pathWhichOrPaths(cmd, absoluteCandidates = [], opts = {}) {
  if (await pathWhich(cmd, opts)) return true;
  for (const p of absoluteCandidates) {
    if (fileExecutableExists(p)) return true;
  }
  return false;
}

/** Onde o dalfox costuma estar (PATH incomum no processo Node). */
function dalfoxCandidatePaths() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const set = new Set();
  const push = (p) => {
    if (p && typeof p === 'string') set.add(p);
  };
  push('/usr/local/bin/dalfox');
  push('/usr/bin/dalfox');
  push('/snap/bin/dalfox');
  if (home) {
    push(join(home, 'go', 'bin', 'dalfox'));
    push(join(home, '.local', 'bin', 'dalfox'));
    push(join(home, 'bin', 'dalfox'));
  }
  const goPath = process.env.GOPATH || '';
  for (const root of goPath.split(delimiter)) {
    const t = root?.trim();
    if (t) push(join(t, 'bin', 'dalfox'));
  }
  return [...set];
}

/** Caminho absoluto quando o ficheiro existe; senão `dalfox` no PATH. */
function resolveDalfoxExecutableForSpawn() {
  for (const p of dalfoxCandidatePaths()) {
    if (fileExecutableExists(p)) return p;
  }
  return 'dalfox';
}

export async function getKaliCapabilities({ signal = null } = {}) {
  const force = process.env.GHOSTRECON_FORCE_KALI === '1';
  let distroKali = false;
  try {
    const rel = fs.readFileSync('/etc/os-release', 'utf8');
    if (/\bID=kali\b/i.test(rel)) distroKali = true;
    else if (/PRETTY_NAME=.*[Kk]ali/i.test(rel)) distroKali = true;
  } catch {
    /* não-Linux ou sem os-release */
  }

  const qualifyDistro = distroKali || force;
  const python3 = await pathWhich('python3', { signal });
  const python = python3 ? false : await pathWhich('python', { signal });
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const sqlmapAbs = ['/usr/bin/sqlmap', '/usr/local/bin/sqlmap', ...(home ? [join(home, '.local/bin/sqlmap')] : [])];
  const tools = {
    nmap: await pathWhich('nmap', { signal }),
    nuclei: await pathWhich('nuclei', { signal }),
    ffuf: await pathWhich('ffuf', { signal }),
    dirsearch: await pathWhich('dirsearch', { signal }),
    searchsploit: await pathWhich('searchsploit', { signal }),
    wpscan: await pathWhich('wpscan', { signal }),
    whois: await pathWhich('whois', { signal }),
    dalfox: await pathWhichOrPaths('dalfox', dalfoxCandidatePaths(), { signal }),
    sqlmap: await pathWhichOrPaths('sqlmap', sqlmapAbs, { signal }),
    smbclient: await pathWhich('smbclient', { signal }),
    rpcclient: await pathWhich('rpcclient', { signal }),
    proxychains: await pathWhichOrPaths(
      'proxychains4',
      ['/usr/bin/proxychains4', '/usr/local/bin/proxychains4'],
      { signal },
    ),
    tor: await pathWhich('tor', { signal }),
    python3,
    python,
    info_disclosure_hunter: (python3 || python) && fs.existsSync(INFO_DISCLOSURE_SCRIPT),
    // Implementação interna segura; não depende do scanner Python legado.
    xss_vibes: true,
  };

  const ready = qualifyDistro && tools.nmap;
  let message = 'Modo agressivo disponível.';
  if (!qualifyDistro) {
    message = 'Não é Kali Linux. Usa Kali ou define GHOSTRECON_FORCE_KALI=1 (apenas testes).';
  } else if (!tools.nmap) {
    message = 'nmap não encontrado no PATH.';
  }

  return {
    kali: ready,
    kaliDistro: distroKali,
    forced: force,
    qualifyDistro,
    tools,
    message,
  };
}

function runProc(cmd, args, timeoutMs, spawnOpts = {}, execOpts = {}) {
  const withProxy = buildProxychainsCommand(cmd, args, execOpts);
  return runProcess(withProxy.cmd, withProxy.args, {
    timeoutMs,
    spawnOpts,
    signal: execOpts.signal ?? null,
    stdoutMaxBytes: TOOL_STDOUT_MAX_BYTES,
    stderrMaxBytes: TOOL_STDERR_MAX_BYTES,
    label: cmd,
  });
}

function isProcessAbort(error) {
  return error?.name === 'AbortError'
    || error?.code === 'PROCESS_ABORTED'
    || error?.code === 'PROCESS_UNTERMINATED'
    || error?.fatal === true;
}

const AUTO_TCP_NMAP_CAPABILITIES = new Set([
  'ftp_anonymous_audit',
  'kali_nmap',
  'kali_nmap_aggressive',
  'kali_nmap_udp',
  'nmap_cve_match',
  'nmap_backport_review',
  'mysql_3306_intel',
  'nmap_service_followups',
]);

/**
 * Em qualquer entrada, `kaliMode` é apenas uma dependência de ambiente: o
 * scan só pode ocorrer quando o plano contém uma capacidade que depende dele.
 */
export function shouldRunKaliTcpBase({ autoModeExecution = false, modules = [] } = {}) {
  void autoModeExecution;
  return (Array.isArray(modules) ? modules : []).some((id) =>
    AUTO_TCP_NMAP_CAPABILITIES.has(String(id || '').trim().toLowerCase()),
  );
}

export function resolveKaliExecutionPolicy({ autoModeExecution = false, modules = [] } = {}) {
  const selected = new Set(
    (Array.isArray(modules) ? modules : [])
      .map((id) => String(id || '').trim().toLowerCase())
      .filter(Boolean),
  );
  const manual = autoModeExecution !== true;
  return Object.freeze({
    runNmapBase: [...AUTO_TCP_NMAP_CAPABILITIES].some((id) => selected.has(id))
      || (manual && selected.has('ftp_write_probe')),
    runWhois: selected.has('kali_whois'),
    runWpscan: selected.has('kali_wpscan'),
    runDalfox: selected.has('kali_dalfox'),
    allowNmapServiceFollowups: selected.has('nmap_service_followups'),
    // Caminho FTP para programas autorizados: apenas USER/PASS anonymous e
    // QUIT. Não habilita os follow-ups SMB/RPC/searchsploit nem qualquer write.
    allowFtpAnonymousAudit: selected.has('ftp_anonymous_audit')
      || (manual && selected.has('ftp_write_probe')),
    // Escrita remota permanece separada dos follow-ups de leitura.
    // O Auto nunca recebe esta capacidade, mesmo se um override escapar ao catálogo.
    allowFtpWriteProbe: manual && selected.has('ftp_write_probe'),
  });
}

export function classifyFtpAnonymousAuditOutcome(
  summary = {},
  { enabled = true, nmapState = 'done' } = {},
) {
  if (!enabled) return { status: 'skipped', reason: 'not_selected', partial: false };
  if (nmapState === 'timeout') return { status: 'timeout', reason: 'nmap_timeout', partial: false };
  if (nmapState === 'failed') return { status: 'failed', reason: 'nmap_failed', partial: false };
  if (nmapState === 'cancelled') return { status: 'cancelled', reason: 'operation_cancelled', partial: false };
  if (nmapState === 'skipped') return { status: 'skipped', reason: 'nmap_unavailable_or_no_scoped_hosts', partial: false };

  const confirmed = Number(summary.confirmed) || 0;
  const denied = Number(summary.denied) || 0;
  const timeouts = Number(summary.timeouts) || 0;
  const failed = Number(summary.failed) || 0;
  const skipped = Number(summary.skipped) || 0;
  const cleanupUnconfirmed = Number(summary.cleanupUnconfirmed) || 0;
  const hostsTruncated = Number(summary.hostsTruncated) || 0;
  const incomplete = timeouts + failed + skipped + cleanupUnconfirmed + hostsTruncated;
  if (!Number(summary.servicesDetected)) {
    return {
      status: 'done',
      reason: hostsTruncated > 0
        ? 'no_ftp_control_service_in_scanned_sample'
        : 'no_ftp_control_service',
      partial: hostsTruncated > 0,
    };
  }
  if (confirmed > 0) {
    return { status: 'done', reason: 'anonymous_login_confirmed', partial: incomplete > 0 };
  }
  if (denied > 0) {
    return { status: 'done', reason: 'anonymous_login_not_accepted', partial: incomplete > 0 };
  }
  if (timeouts > 0) {
    return {
      status: 'timeout',
      reason: incomplete === timeouts ? 'ftp_login_timeout' : 'ftp_login_incomplete_mixed',
      partial: failed + skipped + hostsTruncated > 0,
    };
  }
  if (failed > 0) {
    return { status: 'failed', reason: 'ftp_probe_failed', partial: skipped + hostsTruncated > 0 };
  }
  return { status: 'skipped', reason: 'ftp_probe_blocked', partial: hostsTruncated > 0 };
}

export function classifyFtpWriteProbeOutcome(
  summary = {},
  {
    enabled = true,
    nmapState = 'done',
    ftpAuditSummary = {},
  } = {},
) {
  if (!enabled) return { status: 'skipped', reason: 'not_selected', partial: false };
  if (nmapState === 'timeout') return { status: 'timeout', reason: 'nmap_timeout', partial: false };
  if (nmapState === 'failed') return { status: 'failed', reason: 'nmap_failed', partial: false };
  if (nmapState === 'cancelled') return { status: 'cancelled', reason: 'operation_cancelled', partial: false };
  if (nmapState === 'skipped') return { status: 'skipped', reason: 'nmap_unavailable_or_no_scoped_hosts', partial: false };

  const attempted = Number(summary.attempted) || 0;
  const confirmed = Number(summary.writeConfirmed) || 0;
  const denied = Number(summary.denied) || 0;
  const timeouts = Number(summary.timeouts) || 0;
  const failed = Number(summary.failed) || 0;
  const skipped = Number(summary.skipped) || 0;
  const cleanupUnconfirmed = Number(summary.cleanupUnconfirmed) || 0;
  const hostsTruncated = Number(ftpAuditSummary.hostsTruncated) || 0;
  if (cleanupUnconfirmed > 0) {
    return { status: 'failed', reason: 'remote_cleanup_unconfirmed', partial: true };
  }
  if (confirmed > 0) {
    return {
      status: 'done',
      reason: 'write_and_cleanup_confirmed',
      partial: denied + timeouts + failed + skipped + hostsTruncated > 0,
    };
  }
  if (timeouts > 0) {
    return {
      status: 'timeout',
      reason: 'write_probe_timeout',
      partial: failed + skipped + denied + hostsTruncated > 0,
    };
  }
  if (failed > 0) {
    return { status: 'failed', reason: 'write_probe_failed', partial: skipped + denied + hostsTruncated > 0 };
  }
  if (attempted > 0 && denied > 0) {
    return { status: 'done', reason: 'anonymous_write_not_accepted', partial: skipped + hostsTruncated > 0 };
  }
  if (!Number(ftpAuditSummary.servicesDetected)) {
    return { status: 'skipped', reason: 'no_ftp_control_service', partial: hostsTruncated > 0 };
  }
  if (!Number(ftpAuditSummary.confirmed)) {
    return { status: 'skipped', reason: 'anonymous_login_not_confirmed', partial: hostsTruncated > 0 };
  }
  return { status: 'skipped', reason: 'write_gate_or_prerequisite_blocked', partial: hostsTruncated > 0 };
}

// Quando GHOSTRECON_TOR_STRICT=1, delegamos a decisão de wrap para
// `tor-strict.js` — único ponto da verdade. O modo legacy (GHOSTRECON_PROXYCHAINS=1
// sem strict) continua a funcionar para retrocompatibilidade.
import { isStrict, wrapCommand as torStrictWrap } from './tor-strict.js';

function shouldUseProxychainsForCommand(cmd, execOpts = {}) {
  if (isStrict()) return true; // strict → wrap todos os defaults
  const enabled = String(process.env.GHOSTRECON_PROXYCHAINS || '0') === '1' || Boolean(execOpts.useProxychains);
  if (!enabled) return false;
  const normalized = String(cmd || '').trim().toLowerCase().split(/[\\/]/).pop();
  if (!normalized) return false;
  const skip = String(process.env.GHOSTRECON_PROXYCHAINS_SKIP || '')
    .split(/[,\s]+/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  if (skip.includes(normalized)) return false;
  const defaults = new Set(['nmap', 'ffuf', 'nuclei', 'dirsearch', 'dalfox', 'whois', 'sqlmap', 'wpscan', 'smbclient', 'rpcclient']);
  return defaults.has(normalized);
}

export function normalizeProxychainsInvocation(cmd, args = []) {
  const normalized = String(cmd || '').trim().toLowerCase().split(/[\\/]/).pop();
  const safeArgs = Array.isArray(args) ? [...args] : [];
  if (normalized !== 'nmap') return { cmd, args: safeArgs };
  const unsupported = safeArgs.find((arg) => (
    arg === '-sS'
    || arg === '-sU'
    || arg === '-O'
    || arg === '-A'
    || arg === '--traceroute'
    || /^-s(?:S|U|A|F|N|X|O|Y|Z|I)/i.test(String(arg))
  ));
  if (unsupported) {
    const error = new Error(`proxychains: modo Nmap incompatível (${unsupported}); somente TCP connect (-sT) é permitido`);
    error.code = 'PROXYCHAINS_NMAP_MODE_UNSUPPORTED';
    throw error;
  }
  if (!safeArgs.includes('-sT')) safeArgs.unshift('-sT');
  return { cmd, args: safeArgs };
}

export function buildProxychainsCommand(cmd, args, execOpts = {}) {
  const shouldWrap = isStrict() || shouldUseProxychainsForCommand(cmd, execOpts);
  const invocation = shouldWrap
    ? normalizeProxychainsInvocation(cmd, args)
    : { cmd, args: Array.isArray(args) ? [...args] : [] };
  // Caminho strict: tor-strict.wrapCommand decide e devolve { cmd, args, refuse?, reason? }
  if (isStrict()) {
    const r = torStrictWrap(invocation.cmd, invocation.args);
    if (r.refuse) {
      // Sinalizamos um pseudo-comando que forçará erro — o caller (runProc/spawn)
      // deve capturar. Em prática queremos abortar antes de chegar aqui.
      throw new Error(`tor-strict: comando ${cmd} recusado — ${r.reason}`);
    }
    return { cmd: r.cmd, args: r.args };
  }
  if (!shouldUseProxychainsForCommand(cmd, execOpts)) return invocation;
  const proxychainsBin = process.env.GHOSTRECON_PROXYCHAINS_BIN || 'proxychains4';
  const conf = String(process.env.GHOSTRECON_PROXYCHAINS_CONF || '').trim();
  const quiet = String(process.env.GHOSTRECON_PROXYCHAINS_QUIET || '1') === '1';
  const wrappedArgs = [];
  if (quiet) wrappedArgs.push('-q');
  if (conf) wrappedArgs.push('-f', conf);
  wrappedArgs.push(invocation.cmd, ...invocation.args);
  return { cmd: proxychainsBin, args: wrappedArgs };
}

function getAttr(attrStr, key) {
  const m = attrStr.match(new RegExp(`${key}="([^"]*)"`));
  return m ? m[1] : '';
}

function serviceAttrsFromPortBlock(block) {
  const selfClosing = block.match(/<service\s+([^/]*?)\s*\/>/);
  if (selfClosing) return selfClosing[1];
  const openTag = block.match(/<service\s+([^>]+)>/);
  return openTag ? openTag[1] : '';
}

function portBlockIsOpen(block) {
  const m = block.match(/<state\b[^>]*\bstate=["']([^"']+)["']/);
  return Boolean(m && m[1] === 'open');
}

/**
 * Extrai portas TCP/UDP abertas do XML do nmap (`-oX`).
 * O formato real com `-sV` quase sempre usa `<service …><cpe>…</cpe></service>`;
 * o regex antigo só aceitava `<service …/>` e descartava todas as linhas.
 */
export function parseNmapXml(xml) {
  if (typeof xml !== 'string') return [];
  if (Buffer.byteLength(xml, 'utf8') > 16 * 1024 * 1024) {
    const error = new Error('XML Nmap excede o limite de 16 MiB');
    error.code = 'NMAP_XML_TOO_LARGE';
    throw error;
  }
  const rows = [];
  const parts = xml.split(/<host[\s>]/);
  for (let i = 1; i < parts.length; i++) {
    const hc = parts[i];
    const hostnameTags = [...hc.matchAll(/<hostname\s+([^>]+?)\s*\/?\s*>/g)];
    const hostname = hostnameTags
      .map((match) => ({ name: getAttr(match[1], 'name'), type: getAttr(match[1], 'type') }))
      .find((item) => item.name && item.type === 'user')?.name || '';
    const address =
      (hc.match(/<address addr="([^"]+)" addrtype="ipv4"/) || [])[1]
      || (hc.match(/<address addr="([^"]+)" addrtype="ipv6"/) || [])[1]
      || '';
    const hostLabel = hostname || address || 'unknown';

    const portBlockRe = /<port protocol="(\w+)" portid="(\d+)">[\s\S]*?<\/port>/g;
    let m;
    while ((m = portBlockRe.exec(hc)) !== null) {
      const block = m[0];
      if (!portBlockIsOpen(block)) continue;
      const attrs = serviceAttrsFromPortBlock(block);
      const name = getAttr(attrs, 'name');
      const product = getAttr(attrs, 'product');
      const version = getAttr(attrs, 'version');
      const extrainfo = getAttr(attrs, 'extrainfo');
      const tunnel = getAttr(attrs, 'tunnel').toLowerCase();
      const cpes = [...block.matchAll(/<cpe>([^<]+)<\/cpe>/g)]
        .map((x) => String(x[1] || '').trim())
        .filter(Boolean);
      const searchBlob = [product, version, name, extrainfo].filter(Boolean).join(' ').trim();
      rows.push({
        host: hostLabel,
        address: address || null,
        port: m[2],
        proto: m[1],
        name,
        product,
        version,
        extrainfo,
        tunnel,
        cpes,
        searchBlob,
      });
      if (rows.length >= 10_000) return rows;
    }
  }
  return rows;
}

export function classifyNmapProcessResult(result) {
  if (result?.aborted) return { status: 'cancelled', reason: 'process_aborted', exitCode: null };
  if (result?.timedOut) return { status: 'timeout', reason: 'process_timeout', exitCode: null };
  if (!Number.isInteger(result?.code) || result.code !== 0) {
    return {
      status: 'failed',
      reason: 'process_exit',
      exitCode: Number.isInteger(result?.code) ? result.code : null,
    };
  }
  return { status: 'done', reason: 'completed', exitCode: 0 };
}

const NMAP_FLAG_WITH_VALUE = Object.freeze({
  '--top-ports': (value) => /^\d{1,5}$/.test(value) && Number(value) > 0 && Number(value) <= 65_535,
  '--host-timeout': (value) => /^\d+(?:ms|s|m|h)?$/i.test(value),
  '--max-retries': (value) => /^\d{1,3}$/.test(value),
  '--scan-delay': (value) => /^\d+(?:ms|s|m|h)?$/i.test(value),
  '--max-scan-delay': (value) => /^\d+(?:ms|s|m|h)?$/i.test(value),
  '--min-rate': (value) => /^\d{1,7}$/.test(value),
  '--max-rate': (value) => /^\d{1,7}$/.test(value),
  '--version-intensity': (value) => /^[0-9]$/.test(value),
});

function nmapPortSpecAllowed(value, { aggressive = false } = {}) {
  let spec = String(value || '');
  if (/^[TUSP]:/i.test(spec)) spec = spec.slice(2);
  if (spec === '-') return aggressive;
  if (!/^[0-9,-]+$/.test(spec)) return false;
  let count = 0;
  for (const item of spec.split(',')) {
    if (!item) return false;
    const range = item.match(/^(\d{1,5})(?:-(\d{1,5}))?$/);
    if (!range) return false;
    const start = Number(range[1]);
    const end = Number(range[2] || range[1]);
    if (start < 1 || end > 65_535 || end < start) return false;
    count += end - start + 1;
    if (!aggressive && count > 1_024) return false;
  }
  return true;
}

function throwNmapArgsNotAllowed(message) {
  const error = new Error(message);
  error.code = 'NMAP_ARGS_NOT_ALLOWED';
  throw error;
}

/**
 * Não permite que um override de ambiente injete scripts, novos alvos,
 * spoofing ou arquivos de saída fora do plano aprovado.
 */
export function normalizeNmapConfiguredArgs(raw, {
  aggressive = false,
  forceSafeProfile = false,
  udp = false,
  fixedPorts = false,
} = {}) {
  if (forceSafeProfile) {
    return ['-sV', '-Pn', '-T3', '--host-timeout', '180s'];
  }
  const fallback = udp
    ? '-sU -A -Pn -T4'
    : aggressive
      ? '-A -sV -p- -Pn'
      : '-sV -Pn -T4 --host-timeout 180s';
  const tokens = String(raw || fallback).split(/\s+/).filter(Boolean);
  const allowedSwitches = new Set([
    '-sV', ...(udp ? [] : ['-sT']), '-Pn', '-n', '-4', '-6', '--open', '--reason',
    '--version-light', '--version-all', '--version-trace',
    ...(aggressive ? ['-A', udp ? '-sU' : '-sS', '-O', '--traceroute'] : []),
  ]);
  const normalized = [];
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (allowedSwitches.has(token)) {
      normalized.push(token);
      continue;
    }
    if (/^-T[0-5]$/.test(token)) {
      if (!aggressive && token === '-T5') {
        throwNmapArgsNotAllowed('Argumento Nmap -T5 exige capability agressiva');
      }
      normalized.push(token);
      continue;
    }
    if (/^-p(?:-|(?:[TUSP]:)?[0-9][0-9,:-]*)$/i.test(token)) {
      const spec = token.slice(2);
      if (fixedPorts || !nmapPortSpecAllowed(spec, { aggressive })) {
        throwNmapArgsNotAllowed('Portas Nmap fora do perfil aprovado');
      }
      normalized.push(token);
      continue;
    }
    const assignment = token.match(/^(--[a-z-]+)=(.+)$/i);
    if (assignment && NMAP_FLAG_WITH_VALUE[assignment[1]]?.(assignment[2])) {
      if (fixedPorts && assignment[1] === '--top-ports') {
        throwNmapArgsNotAllowed('Portas Nmap UDP são fixadas pela capability');
      }
      if (!aggressive && assignment[1] === '--min-rate') {
        throwNmapArgsNotAllowed('Nmap --min-rate exige capability agressiva');
      }
      if (!aggressive && assignment[1] === '--top-ports' && Number(assignment[2]) > 1_024) {
        throwNmapArgsNotAllowed('Nmap base limita --top-ports a 1024');
      }
      normalized.push(token);
      continue;
    }
    if (token === '-p') {
      const value = tokens[i + 1];
      if (fixedPorts || !nmapPortSpecAllowed(value, { aggressive })) {
        throwNmapArgsNotAllowed('Portas Nmap fora do perfil aprovado');
      }
      normalized.push(token, value);
      i += 1;
      continue;
    }
    const validateValue = NMAP_FLAG_WITH_VALUE[token];
    if (validateValue) {
      const value = tokens[i + 1];
      if (!value || !validateValue(value)) {
        throwNmapArgsNotAllowed(`Valor recusado para argumento Nmap ${token}`);
      }
      if (fixedPorts && token === '--top-ports') {
        throwNmapArgsNotAllowed('Portas Nmap UDP são fixadas pela capability');
      }
      if (!aggressive && token === '--min-rate') {
        throwNmapArgsNotAllowed('Nmap --min-rate exige capability agressiva');
      }
      if (!aggressive && token === '--top-ports' && Number(value) > 1_024) {
        throwNmapArgsNotAllowed('Nmap base limita --top-ports a 1024');
      }
      normalized.push(token, value);
      i += 1;
      continue;
    }
    throwNmapArgsNotAllowed(`Argumento Nmap fora da allowlist: ${String(token).slice(0, 80)}`);
  }
  if (udp && !normalized.includes('-sU')) {
    throwNmapArgsNotAllowed('Capability Nmap UDP exige -sU');
  }
  return normalized;
}

async function runNmapOnHosts(hosts, log, opts = {}) {
  const aggressive = Boolean(opts.aggressive);
  const extra = normalizeNmapConfiguredArgs(
    aggressive ? process.env.GHOSTRECON_NMAP_AGGRESSIVE_ARGS : process.env.GHOSTRECON_NMAP_ARGS,
    { aggressive, forceSafeProfile: opts.forceSafeProfile === true },
  );
  const dir = await mkdtemp(join(tmpdir(), 'ghnr-'));
  const xmlPath = join(dir, 'nmap.xml');
  const args = [...extra, '-oX', xmlPath, ...hosts];
  log(`nmap ${args.slice(0, -hosts.length).join(' ')} [${hosts.length} hosts]`, 'info');
  const timeoutMs = aggressive
    ? Math.max(300_000, Number(process.env.GHOSTRECON_NMAP_AGGRESSIVE_TIMEOUT_MS || 7_200_000))
    : 660_000;
  try {
    const proc = await runProc('nmap', args, timeoutMs, {}, opts.execOpts || {});
    const processState = classifyNmapProcessResult(proc);
    if (processState.status !== 'done') {
      const error = new Error(`nmap não concluiu (${processState.reason})`);
      error.code = processState.status === 'timeout' ? 'PROCESS_TIMEOUT' : 'NMAP_PROCESS_FAILED';
      error.exitCode = processState.exitCode;
      throw error;
    }
    const xml = await readBoundedToolOutput(xmlPath, 16 * 1024 * 1024);
    return parseNmapXml(xml);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/** Portas UDP frequentemente relevantes (DNS, DHCP, TFTP, NTP, SNMP, IKE, SIP, SSDP, …). */
const DEFAULT_SENSITIVE_UDP_PORTS = Object.freeze([
  53, 67, 68, 69, 111, 123, 135, 137, 138, 161, 162, 500, 514, 520, 631, 1434, 1900, 2049, 3478, 4500, 5060,
  5061, 5353, 11211, 1812, 1813, 3391,
]);

export function normalizeNmapUdpPortsSpec(raw, { maxPorts = 128 } = {}) {
  const source = String(raw || '').trim();
  const tokens = source ? source.split(/[\s,]+/) : DEFAULT_SENSITIVE_UDP_PORTS.map(String);
  if (!tokens.length || tokens.some((port) => (
    !/^\d{1,5}$/.test(port) || Number(port) < 1 || Number(port) > 65_535
  ))) {
    const error = new Error('Lista GHOSTRECON_NMAP_UDP_PORTS inválida');
    error.code = 'NMAP_UDP_PORTS_NOT_ALLOWED';
    throw error;
  }
  const unique = [...new Set(tokens.map((port) => String(Number(port))))];
  const boundedMax = Math.max(1, Math.min(1_024, Number(maxPorts) || 128));
  if (unique.length > boundedMax) {
    const error = new Error(`Nmap UDP limitado a ${boundedMax} portas por execução`);
    error.code = 'NMAP_UDP_PORTS_NOT_ALLOWED';
    throw error;
  }
  return unique.join(',');
}

function sensitiveUdpPortsSpec() {
  return normalizeNmapUdpPortsSpec(process.env.GHOSTRECON_NMAP_UDP_PORTS);
}

async function runNmapUdpOnHosts(hosts, log, opts = {}) {
  const portCsv = sensitiveUdpPortsSpec();
  if (!portCsv) {
    log('nmap UDP: lista de portas vazia — skip', 'warn');
    return [];
  }
  // Validar antes de criar arquivos temporários ou iniciar o processo.
  const extra = normalizeNmapConfiguredArgs(process.env.GHOSTRECON_NMAP_UDP_ARGS, {
    aggressive: true,
    udp: true,
    fixedPorts: true,
  });
  const dir = await mkdtemp(join(tmpdir(), 'ghnrudp-'));
  const xmlPath = join(dir, 'nmap-udp.xml');
  const pArg = `U:${portCsv}`;
  const args = [...extra, '-p', pArg, '-oX', xmlPath, ...hosts];
  log(`nmap ${args.slice(0, -hosts.length).join(' ')} [${hosts.length} hosts]`, 'info');
  const timeoutMs = Math.max(120_000, Number(process.env.GHOSTRECON_NMAP_UDP_TIMEOUT_MS || 2_700_000));
  try {
    const proc = await runProc('nmap', args, timeoutMs, {}, opts.execOpts || {});
    const processState = classifyNmapProcessResult(proc);
    if (processState.status !== 'done') {
      const error = new Error(`nmap UDP não concluiu (${processState.reason})`);
      error.code = processState.status === 'timeout' ? 'PROCESS_TIMEOUT' : 'NMAP_PROCESS_FAILED';
      error.exitCode = processState.exitCode;
      throw error;
    }
    const xml = await readBoundedToolOutput(xmlPath, 16 * 1024 * 1024);
    return parseNmapXml(xml);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function searchExploitDbOne(query, log, execOpts = {}) {
  const q = query.slice(0, 100).trim();
  if (q.length < 2) return [];
  const tryJson = async (args) => {
    const r = await runProc('searchsploit', args, 40000, {}, execOpts);
    if (!r.stdout.trim()) return [];
    try {
      const j = JSON.parse(r.stdout);
      if (Array.isArray(j)) return j.slice(0, 8);
      if (j.RESULTS_EXPLOIT && Array.isArray(j.RESULTS_EXPLOIT)) return j.RESULTS_EXPLOIT.slice(0, 8);
      if (j.RESULTS_SHELLCODE && Array.isArray(j.RESULTS_SHELLCODE)) return j.RESULTS_SHELLCODE.slice(0, 8);
      if (j.results && Array.isArray(j.results)) return j.results.slice(0, 8);
    } catch {
      /* texto */
    }
    return [];
  };
  try {
    let rows = await tryJson(['--json', q]);
    if (rows.length) return rows;
    rows = await tryJson(['-j', q]);
    return rows;
  } catch (e) {
    if (isProcessAbort(e)) throw e;
    log(`searchsploit "${q.slice(0, 40)}…": ${e.message}`, 'warn');
    return [];
  }
}

function cleanExploitDbQuery(value) {
  return String(value || '')
    .replace(/["'`]/g, ' ')
    .replace(/[^\w.+:/ -]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 100);
}

function normalizeNmapVersion(version) {
  const raw = String(version || '').trim();
  if (!raw || !/\d/.test(raw)) return '';
  const m = raw.match(/^v?(\d+(?:\.\d+){0,4}(?:p\d+)?(?:[a-z]\d*)?)/i);
  return cleanExploitDbQuery((m && m[1]) || raw.split(/\s+/)[0]);
}

function majorMinorVersion(version) {
  const v = normalizeNmapVersion(version);
  const m = v.match(/^(\d+\.\d+)/);
  return m ? m[1] : '';
}

function cpeToken(value) {
  const s = String(value || '').replace(/\\:/g, ':').replace(/_/g, ' ').replace(/\+/g, ' ');
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function parseCpe(cpe) {
  const raw = String(cpe || '').trim();
  if (raw.startsWith('cpe:/')) {
    const parts = raw.slice(5).split(':');
    return {
      part: parts[0] || '',
      vendor: cpeToken(parts[1] || ''),
      product: cpeToken(parts[2] || ''),
      version: cpeToken(parts[3] || ''),
    };
  }
  if (raw.startsWith('cpe:2.3:')) {
    const parts = raw.split(':');
    return {
      part: parts[2] || '',
      vendor: cpeToken(parts[3] || ''),
      product: cpeToken(parts[4] || ''),
      version: cpeToken(parts[5] || ''),
    };
  }
  return null;
}

function addUniqueQuery(out, query) {
  const q = cleanExploitDbQuery(query);
  if (q.length < 3 || !/\d/.test(q)) return;
  const key = q.toLowerCase();
  if (!out.some((x) => x.toLowerCase() === key)) out.push(q);
}

export function buildExploitDbQueries(row, { max = 5 } = {}) {
  const out = [];
  const product = cleanExploitDbQuery(row?.product || '');
  const service = cleanExploitDbQuery(row?.name || '');
  const ver = normalizeNmapVersion(row?.version);
  const majorMinor = majorMinorVersion(row?.version);
  const products = [];
  const cpeRows = [];
  if (product) products.push(product);

  for (const cpe of row?.cpes || []) {
    const p = parseCpe(cpe);
    if (!p) continue;
    const cpeProduct = cleanExploitDbQuery(p.product);
    const cpeVendor = cleanExploitDbQuery(p.vendor);
    const cpeVersion = normalizeNmapVersion(p.version);
    if (cpeProduct && !products.some((x) => x.toLowerCase() === cpeProduct.toLowerCase())) {
      products.push(cpeProduct);
    }
    if (cpeProduct && cpeVersion) cpeRows.push({ vendor: cpeVendor, product: cpeProduct, version: cpeVersion });
  }

  for (const p of products) {
    if (ver) addUniqueQuery(out, `${p} ${ver}`);
    if (majorMinor && majorMinor !== ver) addUniqueQuery(out, `${p} ${majorMinor}`);
  }
  for (const p of cpeRows) {
    if (p.vendor && p.vendor.toLowerCase() !== p.product.toLowerCase()) {
      addUniqueQuery(out, `${p.vendor} ${p.product} ${p.version}`);
    }
    addUniqueQuery(out, `${p.product} ${p.version}`);
  }
  if (!products.length && service && ver && !/^(?:http|https|ssl|tcpwrapped|unknown)$/i.test(service)) {
    addUniqueQuery(out, `${service} ${ver}`);
  }
  if (!out.length && row?.searchBlob) addUniqueQuery(out, row.searchBlob);
  return out.slice(0, Math.max(1, max));
}

function exploitTitle(row) {
  if (typeof row === 'string') return row;
  return row.Title || row.title || row.Path || row['EDB-ID'] || row.EDB_ID || JSON.stringify(row).slice(0, 120);
}

function exploitKey(row) {
  const id = row?.['EDB-ID'] || row?.EDB_ID || row?.id || row?.['edb-id'];
  if (id) return `edb:${id}`;
  return cleanExploitDbQuery(exploitTitle(row)).toLowerCase();
}

function exploitUrl(row) {
  const id = row['EDB-ID'] || row.EDB_ID || row.id || row['edb-id'];
  if (id) return `https://www.exploit-db.com/exploits/${id}`;
  return row.url || '';
}

function isHttp3NmapRow(row) {
  const blob = [row?.proto, row?.port, row?.name, row?.product, row?.version, row?.extrainfo, row?.searchBlob]
    .filter(Boolean)
    .join(' ');
  return /\b(?:quic|http3|http\/3|h3)\b/i.test(blob) || (String(row?.proto).toLowerCase() === 'udp' && String(row?.port) === '443');
}

/**
 * Query Google sugerida após versão nmap, focada no Exploit-DB.
 * @param {{ name?: string, product?: string, version?: string }} row
 * @returns {string|null}
 */
export function buildExploitVersionGoogleQuery(row) {
  const [query] = buildExploitDbQueries(row, { max: 1 });
  if (!query || !/\d/.test(query)) return null;
  return `site:exploit-db.com/exploits ${query} exploit`.replace(/\s+/g, ' ').trim();
}

async function searchExploitDbForNmapRow(row, {
  log,
  seenQueries,
  maxQueries = 18,
  execOpts = {},
}) {
  const queries = buildExploitDbQueries(row, {
    max: Math.max(1, Math.min(6, Number(process.env.GHOSTRECON_SEARCHSPLOIT_QUERIES_PER_SERVICE || 3))),
  });
  const usedQueries = [];
  const hitsByKey = new Map();
  for (const q of queries) {
    if (seenQueries.size >= maxQueries) break;
    const key = q.toLowerCase().slice(0, 100);
    if (seenQueries.has(key)) continue;
    seenQueries.add(key);
    usedQueries.push(q);
    const hits = await searchExploitDbOne(q, log, execOpts);
    for (const hit of hits) {
      const hk = exploitKey(hit);
      if (!hitsByKey.has(hk)) hitsByKey.set(hk, hit);
    }
    if (hitsByKey.size >= 4) break;
  }
  return { queries: usedQueries, hits: [...hitsByKey.values()] };
}

export function buildNmapCveTechStrings(rows, { max = 8 } = {}) {
  const out = [];
  const add = (product, version) => {
    const p = cleanExploitDbQuery(product);
    const v = normalizeNmapVersion(version);
    if (!p || !v) return;
    const text = `${p}/${v}`;
    if (!out.some((x) => x.toLowerCase() === text.toLowerCase())) out.push(text);
  };
  for (const row of rows || []) {
    add(row?.product, row?.version);
    for (const cpe of row?.cpes || []) {
      const p = parseCpe(cpe);
      if (p?.product && p?.version) add(p.product, p.version);
    }
    if (out.length >= max) break;
  }
  return out.slice(0, Math.max(1, max));
}

function cveFindingFromEnrichment(row) {
  const sev = row.severity || 'medium';
  const score = Math.max(sevToScore(sev), Number(row.cvss) >= 9 ? 95 : 0);
  const prio = sevToPrio(sev);
  const ev = row.evidence || {};
  const meta = [
    'source=nmap_cve_match',
    `product=${ev.product || ''}`,
    `version=${ev.version || ''}`,
    `confidence=${ev.confidence || 'observed'}`,
    ev.source ? `db=${ev.source}` : null,
    ev.advisoryUrl ? `advisory=${ev.advisoryUrl}` : null,
    ev.exploitPublic ? 'exploit_public=true' : null,
    'safe_check=public_cve_lookup',
    'backport_note=confirmar pacote real antes de reportar',
  ]
    .filter(Boolean)
    .join(' - ');
  return {
    type: 'cve_match',
    prio,
    score,
    value: row.title || `${ev.product || 'produto'} ${ev.version || ''} -> ${row.cve}`,
    meta,
    cve: row.cve,
    cvss: row.cvss ?? null,
    url: ev.advisoryUrl || undefined,
    owasp: 'A06:2021',
    mitre: 'T1190',
  };
}

async function runNmapCveMatchForRows(rows, { log, addFinding }) {
  const max = Math.max(1, Math.min(20, Number(process.env.GHOSTRECON_NMAP_CVE_MAX_SERVICES || 6)));
  const techStrings = buildNmapCveTechStrings(rows, { max });
  if (!techStrings.length) {
    log('Nmap CVE match: sem produto/versao utilizavel', 'info');
    return [];
  }
  log(`Nmap CVE match: consultando ${techStrings.length} produto(s)/versao(oes)`, 'info');
  const findings = await enrichFromTechStrings(techStrings, {
    source: 'nmap',
    useNvd: String(process.env.GHOSTRECON_NMAP_CVE_USE_NVD || '1') !== '0',
    useOsv: String(process.env.GHOSTRECON_NMAP_CVE_USE_OSV || '1') !== '0',
    checkExploits: String(process.env.GHOSTRECON_NMAP_CVE_CHECK_EXPLOITS || '0') === '1',
    maxPerProduct: Math.max(1, Math.min(8, Number(process.env.GHOSTRECON_NMAP_CVE_MAX_PER_PRODUCT || 3))),
    apiKey: process.env.NVD_API_KEY || process.env.GHOSTRECON_NVD_API_KEY || '',
  });
  const out = findings.map(cveFindingFromEnrichment);
  for (const f of out) addFinding(f, null);
  log(out.length ? `Nmap CVE match: ${out.length} CVE(s) candidata(s)` : 'Nmap CVE match: sem CVE retornada', out.length ? 'warn' : 'info');
  return out;
}

export function buildNmapBackportReviewFindings(rows) {
  const out = [];
  const seen = new Set();
  const distroRe = /\b(?:debian|ubuntu|red hat|redhat|rhel|centos|rocky|alma|amazon linux|amzn|suse|opensuse|freebsd|oracle linux|el\d)\b/i;
  const productRe = /\b(?:apache|httpd|nginx|openssh|openssl|php|tomcat|mariadb|mysql|postgresql|bind|postfix|dovecot)\b/i;
  for (const row of rows || []) {
    const blob = [row?.product, row?.version, row?.extrainfo, row?.searchBlob, ...(row?.cpes || [])].filter(Boolean).join(' ');
    if (!distroRe.test(blob) || !productRe.test(blob)) continue;
    const key = `${row.host}:${row.port}:${row.product}:${row.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      type: 'cve_backport_context',
      prio: 'low',
      score: 32,
      value: `Possivel pacote com backport: ${row.proto}/${row.port} ${row.product || row.name || '?'} ${row.version || ''}`,
      meta: [
        'source=nmap_backport_review',
        `host=${row.host}`,
        `service=${row.name || ''}`,
        `evidence=${blob.slice(0, 180)}`,
        'note=distribuicoes Linux podem corrigir CVEs mantendo versao upstream antiga',
      ].join(' - '),
      url: null,
    });
  }
  return out;
}

export function parseFfufDiscoveryJson(raw, { baseUrl = '', cap = 400, strict = false } = {}) {
  let parsed;
  try {
    parsed = JSON.parse(String(raw || '{}'));
    if (!Array.isArray(parsed?.results)) throw new Error('schema ffuf inválido');
  } catch (error) {
    if (strict) throw error;
    return [];
  }
  const allowedStatuses = new Set([200, 204, 301, 302, 307, 308, 401, 403]);
  let baseOrigin = '';
  try { baseOrigin = new URL(baseUrl).origin; } catch { /* empty */ }
  const out = [];
  for (const row of Array.isArray(parsed?.results) ? parsed.results : []) {
    const url = normalizedHttpUrl(row?.url);
    const status = Number(row?.status || 0) || 0;
    if (!url || !allowedStatuses.has(status)) continue;
    if (baseOrigin && new URL(url).origin !== baseOrigin) continue;
    out.push({
      url,
      status,
      length: Number(row?.length || 0) || 0,
      words: Number(row?.words || 0) || 0,
      lines: Number(row?.lines || 0) || 0,
      redirect: String(row?.redirectlocation || '').slice(0, 500),
    });
    if (out.length >= Math.max(1, Number(cap) || 400)) break;
  }
  return out;
}

async function readBoundedToolOutput(filePath, maxBytes = 8 * 1024 * 1024) {
  const outputStat = await stat(filePath);
  if (!outputStat.isFile()) throw new Error('saída da ferramenta não é arquivo regular');
  if (outputStat.size > maxBytes) throw new Error(`saída da ferramenta excede ${maxBytes} bytes`);
  return readFile(filePath, 'utf8');
}

function discoveryProcessOutcome(result) {
  if (result?.aborted) {
    const error = new Error('descoberta cancelada');
    error.name = 'AbortError';
    error.code = 'PROCESS_ABORTED';
    throw error;
  }
  if (result?.timedOut) return { state: 'timeout', results: [], reason: 'process_timeout' };
  if (result?.code !== 0) {
    return {
      state: 'failed', results: [], reason: 'process_exit',
      exitCode: Number.isInteger(result?.code) ? result.code : null,
    };
  }
  return null;
}

function discoveryErrorOutcome(error, signal) {
  throwIfAborted(signal);
  if (isProcessAbort(error) || error?.fatal || error?.code === 'PROCESS_UNTERMINATED') throw error;
  const state = error?.code === 'PROCESS_TIMEOUT' || error?.name === 'TimeoutError' ? 'timeout' : 'failed';
  // Não reproduzir stderr, conteúdo de resposta ou caminho temporário no evento.
  return { state, results: [], reason: state === 'timeout' ? 'process_timeout' : 'execution_or_output_invalid' };
}

export function summarizeDirectoryDiscoveryOutcomes(outcomes = []) {
  const states = outcomes.map((outcome) => outcome.state);
  const state = ['failed', 'timeout', 'done', 'skipped'].find((value) => states.includes(value)) || 'skipped';
  return {
    state,
    partial: states.includes('done') && states.some((value) => value !== 'done'),
    resultCount: outcomes.reduce((count, outcome) => count + (outcome.results?.length || 0), 0),
    attempted: outcomes.filter((outcome) => outcome.state !== 'skipped').length,
  };
}

export async function runFfufDiscovery(baseUrl, log = () => {}, execOpts = {}, {
  executor = runProc,
  outputReader = readBoundedToolOutput,
  findWordlist = () => WORDLISTS.find((p) => fs.existsSync(p)),
} = {}) {
  throwIfAborted(execOpts.signal);
  const wl = findWordlist();
  if (!wl) {
    log('ffuf: nenhuma wordlist em /usr/share/seclists ou dirb', 'warn');
    return { state: 'skipped', results: [], reason: 'wordlist_unavailable' };
  }
  const dir = await mkdtemp(join(tmpdir(), 'ghff-'));
  const out = join(dir, 'out.json');
  const base = baseUrl.replace(/\/$/, '');
  const threads = clampInt(process.env.GHOSTRECON_FFUF_THREADS, 8, 1, 20);
  try {
    const args = [
      '-u',
      `${base}/FUZZ`,
      '-w',
      wl,
      '-mc',
      '200,204,301,302,307,308,401,403',
      '-ac',
      '-t',
      String(threads),
      '-timeout',
      '8',
      '-maxtime',
      '90',
      '-of',
      'json',
      '-o',
      out,
      '-s',
    ];
    const proc = await executor('ffuf', args, 135000, {}, execOpts);
    throwIfAborted(execOpts.signal);
    const unsuccessful = discoveryProcessOutcome(proc);
    if (unsuccessful) return unsuccessful;
    const raw = await outputReader(out);
    throwIfAborted(execOpts.signal);
    const results = parseFfufDiscoveryJson(raw, { baseUrl: base, strict: true });
    return { state: 'done', results, exitCode: 0 };
  } catch (e) {
    return discoveryErrorOutcome(e, execOpts.signal);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

function parseDirsearchJsonResults(raw, cap = 400, { strict = false } = {}) {
  try {
    const j = JSON.parse(String(raw || '{}'));
    if (!j?.results || typeof j.results !== 'object') throw new Error('schema dirsearch inválido');
    const out = [];
    const queue = [];
    if (Array.isArray(j.results)) queue.push(...j.results);
    if (j.results && typeof j.results === 'object') {
      for (const v of Object.values(j.results)) {
        if (Array.isArray(v)) queue.push(...v);
      }
    }
    for (const r of queue) {
      const url = String(r?.url || r?.path || '').trim();
      if (!url || !/^https?:\/\//i.test(url)) continue;
      out.push({
        url,
        status: Number(r?.status || r?.status_code || 0) || 0,
        length: Number(r?.length || r?.content_length || 0) || 0,
      });
      if (out.length >= cap) break;
    }
    return out;
  } catch (error) {
    if (strict) throw error;
    return [];
  }
}

export function filterDirsearchDiscoveryResults(rows, { baseUrl = '', cap = 400 } = {}) {
  let baseOrigin = '';
  try { baseOrigin = new URL(baseUrl).origin; } catch { /* empty */ }
  const allowedStatuses = new Set([200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403]);
  const seen = new Set();
  const out = [];
  for (const row of Array.isArray(rows) ? rows : []) {
    if (!allowedStatuses.has(Number(row?.status))) continue;
    let parsed;
    try { parsed = new URL(row.url); } catch { continue; }
    if (baseOrigin && parsed.origin !== baseOrigin) continue;
    if (seen.has(parsed.href)) continue;
    seen.add(parsed.href);
    out.push({ ...row, url: parsed.href, status: Number(row.status) });
    if (out.length >= Math.max(1, Number(cap) || 400)) break;
  }
  return out;
}

export async function runDirsearchAll(baseUrl, log = () => {}, execOpts = {}, {
  executor = runProc,
  outputReader = readBoundedToolOutput,
  findWordlist = () => WORDLISTS.find((p) => fs.existsSync(p)),
} = {}) {
  throwIfAborted(execOpts.signal);
  const wl = findWordlist();
  if (!wl) {
    log('dirsearch: nenhuma wordlist em /usr/share/seclists ou dirb', 'warn');
    return { state: 'skipped', results: [], reason: 'wordlist_unavailable' };
  }
  const dir = await mkdtemp(join(tmpdir(), 'ghds-'));
  const out = join(dir, 'out.json');
  const base = baseUrl.replace(/\/$/, '');
  const threads = clampInt(process.env.GHOSTRECON_DIRSEARCH_THREADS, 8, 1, 20);
  const maxTimeSec = clampInt(process.env.GHOSTRECON_DIRSEARCH_MAXTIME, 300, 60, 900);
  const depth = clampInt(process.env.GHOSTRECON_DIRSEARCH_RECURSION_DEPTH, 2, 1, 4);
  try {
    const args = [
      '--url',
      `${base}/`,
      '--wordlists',
      wl,
      '--threads',
      String(threads),
      '--timeout',
      '8',
      '--max-time',
      String(maxTimeSec),
      '--recursive',
      '--recursion-depth',
      String(depth),
      '--include-status',
      '200-399,401,403',
      '--json-report',
      out,
      '--quiet-mode',
    ];
    const proc = await executor('dirsearch', args, (maxTimeSec + 60) * 1000, {}, execOpts);
    throwIfAborted(execOpts.signal);
    const unsuccessful = discoveryProcessOutcome(proc);
    if (unsuccessful) return unsuccessful;
    const raw = await outputReader(out);
    throwIfAborted(execOpts.signal);
    const results = filterDirsearchDiscoveryResults(parseDirsearchJsonResults(raw, 400, { strict: true }), { baseUrl: base });
    return { state: 'done', results, exitCode: 0 };
  } catch (e) {
    return discoveryErrorOutcome(e, execOpts.signal);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function runNucleiList(urls, log, execOpts = {}) {
  if (!urls.length) return [];
  const dir = await mkdtemp(join(tmpdir(), 'ghnu-'));
  const listFile = join(dir, 'targets.txt');
  const outFile = join(dir, 'out.jsonl');
  await writeFile(listFile, [...new Set(urls)].slice(0, 18).join('\n'), 'utf8');
  const profile = String(process.env.GHOSTRECON_NUCLEI_PROFILE || 'bb-passive').toLowerCase();
  const profileArgs =
    profile === 'safe'
      ? ['-severity', 'medium,high,critical']
      : profile === 'bb-active'
        ? ['-severity', 'low,medium,high,critical']
        : profile === 'high-impact'
          ? ['-severity', 'high,critical', '-tags', 'rce,sqli,lfi,ssrf,xss,auth-bypass']
          : ['-severity', 'medium,high,critical'];
  try {
    await runProc(
      'nuclei',
      ['-l', listFile, '-jsonl', '-o', outFile, '-silent', '-rate-limit', '35', '-timeout', '8', ...profileArgs],
      320000,
      {},
      execOpts,
    );
    let text = '';
    try {
      text = await readFile(outFile, 'utf8');
    } catch {
      return [];
    }
    return text
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
  } catch (e) {
    if (isProcessAbort(e)) throw e;
    log(`nuclei: ${e.message}`, 'warn');
    return [];
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function runNucleiTags(urls, tagsCsv, log, execOpts = {}) {
  if (!urls.length) return [];
  const dir = await mkdtemp(join(tmpdir(), 'ghnu-'));
  const listFile = join(dir, 'targets.txt');
  const outFile = join(dir, 'out.jsonl');
  await writeFile(listFile, [...new Set(urls)].slice(0, 30).join('\n'), 'utf8');
  const profile = String(process.env.GHOSTRECON_NUCLEI_PROFILE || 'bb-passive').toLowerCase();
  const sevArgs = profile === 'safe' ? ['-severity', 'medium,high,critical'] : ['-severity', 'low,medium,high,critical'];
  try {
    await runProc(
      'nuclei',
      [
        '-l',
        listFile,
        '-jsonl',
        '-o',
        outFile,
        '-silent',
        '-rate-limit',
        '25',
        '-timeout',
        '8',
        '-tags',
        tagsCsv,
        ...sevArgs,
      ],
      360000,
      {},
      execOpts,
    );
    let text = '';
    try {
      text = await readFile(outFile, 'utf8');
    } catch {
      return [];
    }
    return text
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
  } catch (e) {
    if (isProcessAbort(e)) throw e;
    log(`nuclei(${tagsCsv}): ${e.message}`, 'warn');
    return [];
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

function parseDalfoxLines(text, limit = 6) {
  const lines = String(text || '')
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean);
  const hits = [];
  for (const line of lines) {
    if (/\[(POC|VULN|WEAK)\]/i.test(line) || /\bvulnerab/i.test(line)) {
      hits.push(line.slice(0, 260));
    }
    if (hits.length >= limit) break;
  }
  return hits;
}

/** Tenta extrair achados estruturados do stdout JSON / JSONL do dalfox. */
function extractDalfoxJsonHits(text, limit = 10) {
  const hits = [];
  const walk = (obj) => {
    if (hits.length >= limit) return;
    if (!obj) return;
    if (typeof obj === 'string') return;
    if (Array.isArray(obj)) {
      for (const x of obj) {
        walk(x);
        if (hits.length >= limit) return;
      }
      return;
    }
    if (typeof obj !== 'object') return;
    const msg = String(obj.message || obj.msg || obj.data || '');
    const typ = String(obj.type || obj.Type || '');
    const hasUrl = Boolean(obj.url || obj.URL || obj.host);
    if (
      hasUrl ||
      /\bvulnerab/i.test(msg) ||
      /\b(POC|VULN|WEAK)\b/i.test(typ) ||
      (obj.param && (obj.payload || obj.poc))
    ) {
      hits.push(JSON.stringify(obj).slice(0, 400));
    }
    for (const v of Object.values(obj)) {
      if (hits.length >= limit) return;
      if (v && (typeof v === 'object' || Array.isArray(v))) walk(v);
    }
  };
  const s = String(text || '').trim();
  if (!s) return hits;
  try {
    walk(JSON.parse(s));
  } catch {
    for (const line of s.split('\n')) {
      const t = line.trim();
      if (!t.startsWith('{')) continue;
      try {
        walk(JSON.parse(t));
      } catch {
        /* ignore */
      }
      if (hits.length >= limit) break;
    }
  }
  return hits.slice(0, limit);
}

async function runDalfoxUrl(url, log, auth = null, execOpts = {}) {
  const timeoutMs = Number(process.env.GHOSTRECON_DALFOX_TIMEOUT_MS || 120000);
  const tail = ['--silence', '--skip-bav', '--skip-mining-all', '--worker', '40'];
  // Dalfox só oferece cookie/headers por argv neste wrapper. Não copie material
  // autenticado para a tabela de processos; execute sem sessão até existir um
  // canal seguro suportado pela ferramenta.
  if (auth?.cookie || auth?.headers) {
    log?.('dalfox: contexto autenticado omitido (a ferramenta exigiria segredo em argv)', 'warn');
  }

  const dalfoxBin = resolveDalfoxExecutableForSpawn();
    const runOnce = async (withJson) => {
    const args = ['url', url, ...(withJson ? ['--format', 'json'] : []), ...tail];
      const proc = await runProc(dalfoxBin, args, timeoutMs, {}, execOpts);
    const text = [proc.stdout, proc.stderr].filter(Boolean).join('\n');
    return { proc, text };
  };

  try {
    let { proc, text } = await runOnce(true);
    let hits = extractDalfoxJsonHits(proc.stdout || text);
    const looksLikeBadFlag =
      !hits.length && /unknown flag|invalid option|unrecognized.*--format/i.test(text);
    if (looksLikeBadFlag) {
      ({ proc, text } = await runOnce(false));
      hits = extractDalfoxJsonHits(proc.stdout || text);
    }
    if (!hits.length) hits = parseDalfoxLines(text);
    if (proc.code !== 0 && typeof log === 'function') {
      log(`dalfox ${url}: código ${proc.code}`, 'warn');
    }
    return { ok: true, hits, stdoutFormat: hits.length && /^\s*\{/.test(String(proc.stdout || '').trim()) ? 'json' : 'mixed' };
  } catch (e) {
    if (isProcessAbort(e)) throw e;
    return { ok: false, error: String(e?.message || e), hits: [] };
  }
}

function pickFirstMatch(re, text) {
  const m = String(text || '').match(re);
  return m?.[1] ? String(m[1]).trim() : null;
}

function pickAllMatches(re, text, limit = 8) {
  const out = [];
  const s = String(text || '');
  let m;
  // eslint-disable-next-line no-constant-condition
  while ((m = re.exec(s)) !== null) {
    if (m[1]) out.push(String(m[1]).trim());
    if (out.length >= limit) break;
  }
  return out;
}

function isSmbServiceRow(row) {
  if (!row) return false;
  const name = String(row.name || '').toLowerCase();
  const product = String(row.product || '').toLowerCase();
  const p = String(row.port || '');
  return row.proto === 'tcp' && (p === '445' || p === '139' || name.includes('smb') || product.includes('samba'));
}

function isRpcServiceRow(row) {
  if (!row) return false;
  const name = String(row.name || '').toLowerCase();
  const product = String(row.product || '').toLowerCase();
  const p = String(row.port || '');
  return row.proto === 'tcp' && (p === '135' || name.includes('msrpc') || product.includes('msrpc') || product.includes('rpc'));
}

function recordFtpWriteCleanupUnconfirmed(addFinding, endpoint, result = {}) {
  addFinding({
    type: 'ftp_write_probe_cleanup_unconfirmed',
    prio: 'high',
    score: 96,
    value: `FTP write probe: estado remoto/cleanup não confirmado @ ${endpoint}`,
    meta: {
      service: 'ftp',
      evidenceStatus: 'remote_state_uncertain',
      destructiveLabOnly: true,
      probeFile: result.probeFile ? String(result.probeFile).slice(0, 120) : null,
      payloadSent: result.payloadSent === true,
      transferConfirmed: result.transferConfirmed === true,
      cleanupVerified: false,
      detail: result.detail ? String(result.detail).slice(0, 120) : null,
      error: result.error ? String(result.error).slice(0, 120) : null,
      requiredAction: 'Inspecionar e restaurar o laboratório antes de qualquer novo write probe.',
    },
    url: null,
    provenance: {
      how: 'O servidor aceitou o reply preliminar de STOR, mas DELE seguido de confirmação de ausência não foi atestado.',
      relation: `Serviço FTP no laboratório autorizado ${endpoint}.`,
    },
  });
}

async function trySmbAnonymousList({ host, timeoutMs = 20_000, execOpts = {} }) {
  try {
    const proc = await runProc('smbclient', ['-N', '-L', `//${host}`, '-g'], timeoutMs, {}, execOpts);
    const mixed = `${proc.stdout || ''}\n${proc.stderr || ''}`;
    const hasShares = /Disk\|[^\n]+|IPC\$/i.test(mixed);
    const denied = /NT_STATUS_ACCESS_DENIED|denied|logon failure/i.test(mixed);
    return { ok: proc.code === 0 && hasShares && !denied, code: proc.code, output: mixed.slice(0, 1200) };
  } catch (e) {
    if (isProcessAbort(e)) throw e;
    return { ok: false, code: -1, output: String(e?.message || e) };
  }
}

async function tryRpcNullSession({ host, timeoutMs = 20_000, execOpts = {} }) {
  try {
    const proc = await runProc('rpcclient', ['-N', '-U', '', host, '-c', 'srvinfo'], timeoutMs, {}, execOpts);
    const mixed = `${proc.stdout || ''}\n${proc.stderr || ''}`;
    const denied = /NT_STATUS_ACCESS_DENIED|denied|logon failure/i.test(mixed);
    const hasServerInfo = /(?:platform_id|os version|server type|server\s*:|domain\s*:)/i.test(mixed);
    return { ok: proc.code === 0 && hasServerInfo && !denied, code: proc.code, output: mixed.slice(0, 1200) };
  } catch (e) {
    if (isProcessAbort(e)) throw e;
    return { ok: false, code: -1, output: String(e?.message || e) };
  }
}

/**
 * Findings / dorks / FTP / searchsploit / URLs ffuf a partir de linhas parseadas do XML nmap (TCP ou UDP).
 * @param {'tcp'|'udp'} scanKind
 */
async function ingestNmapScanRows(rows, ctx) {
  const {
    log,
    addFinding,
    cap,
    emit,
    seenQueries,
    seenExploitGoogle,
    exploitGoogleMax,
    searchsploitMax = 18,
    ftpChecked,
    smbChecked,
    rpcChecked,
    baseUrlsForFfuf,
    scanKind,
    domain: reconTarget,
    execOpts = {},
    allowNmapServiceFollowups = false,
    allowFtpAnonymousAudit = false,
    allowFtpWriteProbe = false,
    hostAllowed = () => true,
    ftpAddressAllowed = () => true,
    ftpAuditSummary = null,
    ftpWriteState = null,
    ftpAnonymousLoginImpl = probeFtpAnonymousLogin,
    ftpWritableProbeImpl = probeFtpAnonymousWritable,
  } = ctx;
  const label = scanKind === 'udp' ? 'nmap UDP' : 'nmap';
  log(`${label}: ${rows.length} serviço(s) em portas abertas`, 'success');
  for (const row of rows.slice(0, 10_000)) {
    throwIfAborted(execOpts.signal ?? null);
    if (hostAllowed(row?.host) !== true) {
      log(`${label}: observação descartada por escopo`, 'warn');
      continue;
    }
    const line = `${row.proto}/${row.port} ${row.host} — ${row.name || '?'} ${row.product || ''} ${row.version || ''}`.trim().slice(0, 400);
    let url = null;
    const rowHl = hostLiteralForUrl(row.host);
    if (row.port === '443') url = `https://${rowHl}/`;
    else if (row.port === '80') url = `http://${rowHl}/`;
    const metaBase = row.searchBlob || row.name || 'nmap';
    const meta = scanKind === 'udp' ? `udp • ${metaBase}` : metaBase;
    addFinding({
      type: 'nmap',
      prio: 'info',
      score: scanKind === 'udp' ? 24 : 22,
      value: line,
      meta: {
        source: 'kali_nmap',
        evidenceStatus: 'service_inventory',
        scanKind: scanKind === 'udp' ? 'udp' : 'tcp',
        service: String(row.name || '').slice(0, 80),
        product: String(row.product || '').slice(0, 120),
        version: String(row.version || '').slice(0, 80) || null,
        networkAddress: row.address || null,
        tunnel: row.tunnel || null,
        note: 'Porta/serviço observado não prova vulnerabilidade',
      },
      url,
    });
    if (isHttp3NmapRow(row)) {
      addFinding({
        type: 'http3',
        prio: 'low',
        score: 38,
        value: `HTTP/3 / QUIC surface via Nmap: ${line}`,
        meta: `source=nmap - evidence=${metaBase} - note=revisar UDP/443, CDN e stack QUIC`,
        url,
      });
    }

    const exploitGq = buildExploitVersionGoogleQuery(row);
    if (
      allowNmapServiceFollowups
      && exploitGq
      && typeof emit === 'function'
      && seenExploitGoogle.size < exploitGoogleMax
    ) {
      const gk = exploitGq.toLowerCase();
      if (!seenExploitGoogle.has(gk)) {
        seenExploitGoogle.add(gk);
        const googleUrl = `https://www.google.com/search?q=${encodeURIComponent(exploitGq)}`;
        emit({
          type: 'dork',
          googleUrl,
          query: exploitGq,
          mod: 'nmap_version_exploit_google',
          prio: 'med',
          forceOpen: false,
        });
        log(`Google (versão nmap): ${exploitGq}`, 'info');
      }
    }

    if (allowFtpAnonymousAudit && isFtpServiceRow(row)) {
      if (ftpAuditSummary) ftpAuditSummary.servicesDetected += 1;
      const k = `${row.host}:${row.port}`;
      if (!ftpChecked.has(k)) {
        ftpChecked.add(k);
        if (!net.isIP(String(row.address || ''))) {
          if (ftpAuditSummary) {
            ftpAuditSummary.skipped += 1;
            ftpAuditSummary.reasons.add('nmap_observed_address_missing');
          }
          log(`[FTP] ${k} ignorado: XML Nmap sem endereço IP observado`, 'warn');
        } else {
          if (ftpAuditSummary) ftpAuditSummary.attempted += 1;
        const ftpTimeout = Math.max(4000, Number(process.env.GHOSTRECON_FTP_ANON_TIMEOUT_MS || 12000));
        log(`[FTP] Teste de login anônimo em ${k} (PASS vazio, depois e-mail)`, 'info');
        try {
          const r = await ftpAnonymousLoginImpl({
            host: row.host,
            port: Number(row.port) || 21,
            timeoutMs: ftpTimeout,
            signal: execOpts.signal ?? null,
            hostAllowed,
            observedAddress: row.address || null,
            addressAllowed: (address) => ftpAddressAllowed(row.host, address),
            // O socket FTP nativo não fala SOCKS. Em Tor/proxychains ele
            // falha fechado, em vez de vazar uma conexão direta.
            allowDirectNetwork: !shouldUseProxychainsForCommand('nmap', execOpts),
          });
          if (r.ok) {
            if (ftpAuditSummary) {
              ftpAuditSummary.confirmed += 1;
              if (r.operationalPartial === true) {
                ftpAuditSummary.failed += 1;
                ftpAuditSummary.reasons.add(String(r.warning || 'ftp_login_operational_partial').slice(0, 80));
              }
              if (r.cleanupConfirmed !== true) {
                ftpAuditSummary.cleanupUnconfirmed += 1;
                ftpAuditSummary.reasons.add('ftp_socket_cleanup_unconfirmed');
              }
            }
            let w = { writable: false };
            if (allowFtpWriteProbe && r.cleanupConfirmed !== true) {
              w = { writable: false, detail: 'login_session_cleanup_unconfirmed' };
              if (ftpWriteState) {
                ftpWriteState.halted = true;
                ftpWriteState.skipped += 1;
                ftpWriteState.reasons.add('login_session_cleanup_unconfirmed');
              }
              log('[FTP] write probe bloqueado: a sessão de login anterior não confirmou encerramento', 'error');
            } else if (allowFtpWriteProbe && ftpWriteState?.halted) {
              w = { writable: false, detail: 'cleanup_failure_halt' };
              ftpWriteState.skipped += 1;
              ftpWriteState.reasons.add('cleanup_failure_halt');
              log('[FTP] write probe bloqueado: uma remoção anterior não foi confirmada', 'error');
            } else if (allowFtpWriteProbe) {
              if (ftpWriteState) ftpWriteState.attempted += 1;
              try {
                w = await ftpWritableProbeImpl({
                  host: row.host,
                  port: Number(row.port) || 21,
                  timeoutMs: Math.max(8000, Number(process.env.GHOSTRECON_FTP_WRITE_PROBE_TIMEOUT_MS || 15000)),
                  signal: execOpts.signal ?? null,
                  hostAllowed,
                  observedAddress: row.address || r.networkAddress || null,
                  addressAllowed: (address) => ftpAddressAllowed(row.host, address),
                  allowDirectNetwork: !shouldUseProxychainsForCommand('nmap', execOpts),
                });
              } catch (e) {
                if (isProcessAbort(e)) {
                  if (e?.remoteWritePossible) {
                    if (ftpWriteState) {
                      ftpWriteState.halted = true;
                      ftpWriteState.cleanupUnconfirmed += 1;
                      ftpWriteState.reasons.add('operation_cancelled_after_stor_preliminary');
                    }
                    recordFtpWriteCleanupUnconfirmed(addFinding, k, {
                      ...e,
                      error: e?.message || 'operation_cancelled',
                      detail: 'operation_cancelled_after_stor_preliminary',
                    });
                  }
                  throw e;
                }
                log(`[FTP] write probe: ${e?.message || e}`, 'warn');
                w = {
                  writable: false,
                  detail: 'probe_error',
                  error: e?.message || String(e),
                };
              }
              if (w.detail === 'probe_disabled') {
                log(
                  '[FTP] ftp_write_probe selecionado, mas o gate de escrita está desligado; nenhuma escrita foi enviada.',
                  'warn',
                );
              } else if (w.detail === 'controlled_lab_ack_required') {
                log('[FTP] STOR bloqueado: falta GHOSTRECON_FTP_WRITE_PROBE_LAB_ACK=1.', 'warn');
              } else if (w.detail === 'controlled_lab_target_not_allowlisted') {
                log('[FTP] STOR bloqueado: alvo ausente de GHOSTRECON_FTP_WRITE_PROBE_LAB_TARGETS.', 'warn');
              }
              if (ftpWriteState) {
                const detail = String(w.detail || 'write_probe_inconclusive');
                const errorText = String(w.error || '');
                ftpWriteState.reasons.add(detail.slice(0, 80));
                if (w.writable) {
                  ftpWriteState.writeConfirmed += 1;
                } else if (w.remoteWritePossible) {
                  ftpWriteState.failed += 1;
                } else if (/^stor_denied_/.test(detail)) {
                  ftpWriteState.denied += 1;
                } else if (
                  /^(?:probe_disabled|controlled_lab_|target_out_of_scope|direct_network_blocked|observed_address_)/.test(detail)
                ) {
                  ftpWriteState.skipped += 1;
                } else if (/timeout|deadline/i.test(`${detail} ${errorText}`)) {
                  ftpWriteState.timeouts += 1;
                } else {
                  ftpWriteState.failed += 1;
                }
              }
              if (w.remoteWritePossible && w.cleanupVerified !== true && ftpWriteState) {
                ftpWriteState.halted = true;
                ftpWriteState.cleanupUnconfirmed += 1;
                ftpWriteState.reasons.add('remote_cleanup_unconfirmed');
              }
            } else {
              w = { writable: false, detail: 'probe_disabled' };
            }
            const loginFinding = ftpAnonymousLoginFinding(r, {
              writeProbe: w.writable
                ? 'stor_confirmed'
                : w.detail === 'probe_disabled'
                  ? 'not_run'
                  : String(w.detail || 'not_writable'),
            });
            if (loginFinding) {
              addFinding(loginFinding);
            }
            if (w.writable) {
              addFinding({
                type: 'ftp_anonymous_write',
                // A UI/estatística legada agrega severidade máxima em `high`;
                // o rótulo CRITICAL permanece no valor e no alerta dedicado.
                prio: 'high',
                score: 99,
                value: `CRITICAL: FTP anonymous write (upload) @ ${k}`,
                meta: [
                  'service=ftp',
                  'severity=critical',
                  'anonymous_upload=stor_confirmed',
                  w.probeFile ? `probe_file=${w.probeFile}` : null,
                  w.detail ? `probe=${w.detail}` : null,
                  `cleanup_verified=${w.cleanupVerified === true ? 'yes' : 'no'}`,
                  r.banner ? `banner=${String(r.banner).slice(0, 80)}` : null,
                  'evidence=stor',
                ]
                  .filter(Boolean)
                  .join(' • '),
                url: null,
                provenance: {
                  how: 'O módulo ftp_write_probe confirmou STOR com um canário e registrou a resposta da tentativa de DELE.',
                  relation: `Serviço FTP no alvo autorizado ${k}.`,
                },
              });
              log(
                `[FTP] CRITICAL: escrita anónima (upload) permitida em ${k}; `
                  + (w.cleanupVerified ? 'remoção DELE confirmada' : 'remoção DELE NÃO confirmada'),
                'error',
              );
              if (typeof emit === 'function') {
                emit({
                  type: 'intel',
                  line: `☠ CRITICAL: FTP anonymous upload (STOR) permitido em ${k}`,
                });
              }
              const wh = process.env.GHOSTRECON_WEBHOOK_URL?.trim();
              if (wh) {
                void postFtpAnonymousWritableCriticalWebhook(wh, {
                  target: reconTarget || row.host,
                  ftpEndpoint: k,
                  probeFile: w.probeFile,
                  probeDetail: w.detail,
                  cleanupVerified: w.cleanupVerified === true,
                });
              }
            } else {
              const authHow =
                r.passUsed === '' ? 'PASS <empty>' : r.passUsed ? `PASS ${r.passUsed}` : 'sem PASS';
              log(`[FTP] ⚠ login anônimo permitido em ${k} (${authHow})`, 'warn');
            }
            if (w.remoteWritePossible && w.cleanupVerified !== true) {
              recordFtpWriteCleanupUnconfirmed(addFinding, k, w);
              log(`[FTP] BLOQUEIO: cleanup do canário não atestado em ${k}; novos writes foram interrompidos`, 'error');
            }
          } else {
            const why = r.error || r.passReply || r.userReply || 'negado';
            if (ftpAuditSummary) {
              ftpAuditSummary.reasons.add(String(why).slice(0, 80));
              if (/timeout|deadline/i.test(String(why))) ftpAuditSummary.timeouts += 1;
              else if (/out_of_scope|blocked|unsupported/i.test(String(why))) ftpAuditSummary.skipped += 1;
              else if (!r.error && (r.passReply || r.userReply)) ftpAuditSummary.denied += 1;
              else ftpAuditSummary.failed += 1;
            }
            const level = r.error === 'target_out_of_scope' || r.error === 'direct_network_blocked'
              ? 'warn'
              : 'info';
            log(`[FTP] ${k} sem login anônimo (${String(why).slice(0, 120)})`, level);
          }
        } catch (e) {
          if (isProcessAbort(e)) throw e;
          if (ftpAuditSummary) {
            ftpAuditSummary.failed += 1;
            ftpAuditSummary.reasons.add('probe_error');
          }
          log(`[FTP] erro no teste ${k}: ${e?.message || e}`, 'warn');
        }
        }
      }
    }

    if (allowNmapServiceFollowups && isSmbServiceRow(row) && cap.tools.smbclient && hostAllowed(row.host) === true) {
      const k = `${row.host}:${row.port}`;
      if (!smbChecked.has(k)) {
        smbChecked.add(k);
        log(`[SMB] Teste sessão anônima em ${k}`, 'info');
        const smb = await trySmbAnonymousList({
          host: row.host,
          timeoutMs: Math.max(6000, Number(process.env.GHOSTRECON_SMB_ANON_TIMEOUT_MS || 20000)),
          execOpts,
        });
        if (smb.ok) {
          addFinding({
            type: 'security',
            prio: 'med',
            score: 68,
            value: `SMB null session com listagem de shares observada @ ${k}`,
            meta: {
              service: 'smb',
              auth: 'null-session',
              evidenceStatus: 'share_listing_observed',
              target: reconTarget || row.host,
              note: 'Revisar se os shares enumerados foram intencionalmente publicados.',
            },
            url: null,
          });
          if (typeof emit === 'function') emit({ type: 'intel', line: `⚠ SMB null session detectada em ${k}` });
          log(`[SMB] ⚠ sessão nula permitida em ${k}`, 'warn');
        } else {
          log(`[SMB] ${k} sem sessão nula (ok)`, 'info');
        }
      }
    }

    if (allowNmapServiceFollowups && isRpcServiceRow(row) && cap.tools.rpcclient && hostAllowed(row.host) === true) {
      const k = `${row.host}:${row.port}`;
      if (!rpcChecked.has(k)) {
        rpcChecked.add(k);
        log(`[RPC] Teste null-session em ${k}`, 'info');
        const rpc = await tryRpcNullSession({
          host: row.host,
          timeoutMs: Math.max(6000, Number(process.env.GHOSTRECON_RPC_NULL_TIMEOUT_MS || 20000)),
          execOpts,
        });
        if (rpc.ok) {
          addFinding({
            type: 'security',
            prio: 'med',
            score: 64,
            value: `RPC null session com srvinfo observada @ ${k}`,
            meta: {
              service: 'rpc',
              auth: 'null-session',
              evidenceStatus: 'srvinfo_observed',
              target: reconTarget || row.host,
            },
            url: null,
          });
          if (typeof emit === 'function') emit({ type: 'intel', line: `⚠ RPC null session detectada em ${k}` });
          log(`[RPC] ⚠ null-session permitida em ${k}`, 'warn');
        } else {
          log(`[RPC] ${k} sem null-session (ok)`, 'info');
        }
      }
    }

    if (
      allowNmapServiceFollowups
      && cap.tools.searchsploit
      && seenQueries.size < searchsploitMax
    ) {
      const { queries, hits } = await searchExploitDbForNmapRow(row, {
        log,
        seenQueries,
        maxQueries: searchsploitMax,
        execOpts,
      });
      const queryLabel = queries.length ? queries.join(' | ') : row.searchBlob || row.name || 'nmap';
      for (const hit of hits.slice(0, 4)) {
        const title = exploitTitle(hit);
        addFinding({
          type: 'exploit_candidate',
          prio: 'low',
          score: 34,
          value: `Exploit-DB candidato: ${title}`,
          meta: {
            source: 'searchsploit',
            evidenceStatus: 'version_string_candidate',
            service: `${row.name || '?'} ${row.product || ''} ${row.version || ''}`.trim(),
            queries: queryLabel.slice(0, 120),
            note: 'Correspondência textual não confirma build, backport, configuração ou vulnerabilidade.',
          },
          url: exploitUrl(hit) || undefined,
        });
      }
      if (hits.length) log(`searchsploit: ${hits.length} entrada(s) para ${queryLabel.slice(0, 80)}`, 'find');
    }
  }
  for (const row of rows) {
    if (row.port === '443' || row.port === '80') {
      const rh = hostLiteralForUrl(row.host);
      const u = row.port === '443' ? `https://${rh}/` : `http://${rh}/`;
      if (!baseUrlsForFfuf.includes(u)) baseUrlsForFfuf.push(u);
    }
  }
}

function parseWhoisText(domainOrHost, whoisText) {
  // Formatos variam por registrar; usamos regexes comuns.
  const registrar = pickFirstMatch(/Registrar:\s*(.+)$/im, whoisText) || pickFirstMatch(/registrar:\s*(.+)$/im, whoisText);
  const registrantCountry =
    pickFirstMatch(/Registrant Country:\s*(.+)$/im, whoisText) || pickFirstMatch(/country:\s*(.+)$/im, whoisText);
  const created =
    pickFirstMatch(/Creation Date:\s*(.+)$/im, whoisText) ||
    pickFirstMatch(/created on:\s*(.+)$/im, whoisText) ||
    pickFirstMatch(/Created:\s*(.+)$/im, whoisText);
  const updated =
    pickFirstMatch(/Updated Date:\s*(.+)$/im, whoisText) || pickFirstMatch(/updated on:\s*(.+)$/im, whoisText);
  const expires =
    pickFirstMatch(/Registry Expiry Date:\s*(.+)$/im, whoisText) ||
    pickFirstMatch(/Expiry Date:\s*(.+)$/im, whoisText) ||
    pickFirstMatch(/expires on:\s*(.+)$/im, whoisText);

  // Alguns whois usam "Name Server:" e outros "nserver:".
  const nameServers =
    pickAllMatches(/Name Server:\s*(.+)$/gim, whoisText, 10).length
      ? pickAllMatches(/Name Server:\s*(.+)$/gim, whoisText, 10)
      : pickAllMatches(/nserver:\s*(.+)$/gim, whoisText, 10);

  // Se quase nada vier, não cria achado “vazio”.
  const hasSomething = Boolean(registrar || created || expires || nameServers.length);
  return {
    hasSomething,
    registrar,
    registrantCountry,
    created,
    updated,
    expires,
    nameServers,
    domainOrHost,
  };
}

async function runWhoisJsonLike({ target, timeoutMs, log, execOpts = {} }) {
  // quem usa whois no Kali geralmente tem o CLI "whois".
  // Não normalizamos em JSON: apenas parseamos texto com regexes.
  const proc = await runProc('whois', [target], timeoutMs, {}, execOpts);
  const text = [proc.stdout, proc.stderr].filter(Boolean).join('\n').slice(0, 220_000);
  if (typeof log === 'function' && text.includes('No match')) log(`whois: sem match para ${target}`, 'info');
  return { ok: proc.code === 0, text };
}

/**
 * Scan ativo: nmap → searchsploit (heurístico) → ffuf (só HTTP 200) → nuclei (se `runNuclei`).
 */
function nucleiEvidenceMeta({ tid, sev, extra }) {
  const parts = [
    `scanner=nuclei`,
    `severity=${sev}`,
    tid && `template=${tid}`,
    `confidence=active_scan`,
  ];
  if (extra) parts.push(extra);
  return parts.filter(Boolean).join(' • ');
}

function clampInt(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(n)));
}

function clipText(value, max = 260) {
  const s = String(value || '').replace(/\s+/g, ' ').trim();
  if (s.length <= max) return s;
  return `${s.slice(0, Math.max(0, max - 3))}...`;
}

function normalizedHttpUrl(value) {
  const s = String(value || '').trim();
  if (!/^https?:\/\//i.test(s)) return null;
  try {
    return new URL(s).href;
  } catch {
    return null;
  }
}

function normalizeInfoDisclosureSeverity(value) {
  const sev = String(value || '').trim().toUpperCase();
  if (sev === 'CRITICAL' || sev === 'HIGH' || sev === 'MEDIUM' || sev === 'LOW' || sev === 'INFO') return sev;
  if (sev === 'MED' || sev === 'MODERATE') return 'MEDIUM';
  if (sev === 'INFORMATIONAL') return 'INFO';
  return 'INFO';
}

function infoDisclosurePrio(sev) {
  if (sev === 'CRITICAL' || sev === 'HIGH') return 'high';
  if (sev === 'MEDIUM') return 'med';
  if (sev === 'LOW') return 'low';
  return 'info';
}

function infoDisclosureScore(sev) {
  if (sev === 'CRITICAL') return 96;
  if (sev === 'HIGH') return 86;
  if (sev === 'MEDIUM') return 62;
  if (sev === 'LOW') return 36;
  return 20;
}

export function infoDisclosureModulesForRun({ includeErrors = false } = {}) {
  const modules = [...INFO_DISCLOSURE_SAFE_MODULES];
  if (includeErrors) modules.push(INFO_DISCLOSURE_ERROR_MODULE);
  return modules;
}

export function infoDisclosureFindingFromRow(row, { targetUrl = null } = {}) {
  if (!row || typeof row !== 'object') return null;
  const sev = normalizeInfoDisclosureSeverity(row.severidade);
  const moduleName = clipText(row.modulo || 'unknown', 80) || 'unknown';
  const title = clipText(row.titulo || `Information disclosure (${moduleName})`, 180);
  const evidence = clipText(row.evidencia || '', 260);
  const url = normalizedHttpUrl(row.url) || normalizedHttpUrl(targetUrl);
  const errorProbe = moduleName.toLowerCase() === INFO_DISCLOSURE_ERROR_MODULE;
  const meta = [
    'scanner=infohunter_br',
    `module=${moduleName}`,
    `severity=${sev}`,
    `confidence=${errorProbe ? 'probable_differential_error' : 'active_disclosure_probe'}`,
    `evidence_status=${errorProbe ? 'probable' : 'candidate'}`,
    evidence ? `evidence=${evidence}` : null,
  ]
    .filter(Boolean)
    .join(' - ');
  return {
    type: 'info_disclosure',
    prio: infoDisclosurePrio(sev),
    score: infoDisclosureScore(sev),
    value: title,
    meta,
    url,
    owasp: 'A05:2021',
    mitre: 'T1592',
  };
}

export function validateInfoDisclosureJson(value) {
  if (!value || typeof value !== 'object' || !Array.isArray(value.achados)) return false;
  if (value.achados.length > 10_000) return false;
  return value.achados.every((row) => row && typeof row === 'object'
    && typeof row.modulo === 'string'
    && typeof row.titulo === 'string'
    && (row.url == null || typeof row.url === 'string')
    && (row.evidencia == null || typeof row.evidencia === 'string'));
}

export function mapInfoDisclosureJsonToFindings(json, { targetUrl = null, limit = 300 } = {}) {
  const rows = Array.isArray(json?.achados) ? json.achados : [];
  const out = [];
  const seen = new Set();
  for (const row of rows) {
    const finding = infoDisclosureFindingFromRow(row, { targetUrl });
    if (!finding) continue;
    const key = [finding.type, finding.value, finding.url || '', finding.meta].join('\u0001');
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(finding);
    if (out.length >= limit) break;
  }
  return out;
}

export async function executeInfoDisclosureHunter({ targetUrl, cap, log, includeErrors = false, execOpts = {},
  executor = runProc, outputReader = readBoundedToolOutput,
}) {
  throwIfAborted(execOpts.signal);
  const pyCmd = cap?.tools?.python3 ? 'python3' : cap?.tools?.python ? 'python' : null;
  if (!pyCmd) return { ok: false, findings: [], error: 'python3/python nao encontrado no PATH' };
  if (!fs.existsSync(INFO_DISCLOSURE_SCRIPT)) {
    return { ok: false, findings: [], error: `script nao encontrado: ${INFO_DISCLOSURE_SCRIPT}` };
  }
  const target = normalizedHttpUrl(targetUrl) || String(targetUrl || '').trim();
  if (!target) return { ok: false, findings: [], error: 'alvo vazio' };

  const dir = await mkdtemp(join(tmpdir(), 'ghid-'));
  const outBase = join(dir, 'info-disclosure');
  const outJson = `${outBase}.json`;
  const modules = infoDisclosureModulesForRun({ includeErrors });
  const threads = clampInt(process.env.GHOSTRECON_INFO_DISCLOSURE_THREADS, 8, 1, 30);
  const requestTimeoutSec = clampInt(process.env.GHOSTRECON_INFO_DISCLOSURE_TIMEOUT_SEC, 8, 2, 30);
  const runTimeoutMs = clampInt(process.env.GHOSTRECON_INFO_DISCLOSURE_RUN_TIMEOUT_MS, 240000, 30000, 1800000);
  const args = [
    INFO_DISCLOSURE_SCRIPT,
    target,
    '--no-color',
    '--format',
    'json',
    '-o',
    outBase,
    '-m',
    modules.join(','),
    '-t',
    String(threads),
    '--timeout',
    String(requestTimeoutSec),
  ];

  if (typeof log === 'function') {
    log(
      `[InfoHunter] ${target} - modulos=${modules.join(',')} threads=${threads} timeout=${requestTimeoutSec}s`,
      'info',
    );
  }

  try {
    const proc = await executor(pyCmd, args, runTimeoutMs, { cwd: process.cwd() }, execOpts);
    throwIfAborted(execOpts.signal);
    const unsuccessful = discoveryProcessOutcome(proc);
    if (unsuccessful) return { ok: false, findings: [], state: unsuccessful.state, error: unsuccessful.reason };
    let parsed = null;
    try {
      parsed = JSON.parse(await outputReader(outJson, 4 * 1024 * 1024));
      throwIfAborted(execOpts.signal);
      if (!validateInfoDisclosureJson(parsed)) throw new Error('schema de achados inválido');
    } catch (e) {
      throwIfAborted(execOpts.signal);
      return {
        ok: false,
        findings: [],
        state: 'failed',
        error: 'saida JSON nao encontrada, excedida ou invalida',
      };
    }
    const findings = mapInfoDisclosureJsonToFindings(parsed, { targetUrl: target });
    return { ok: true, state: 'done', findings };
  } catch (e) {
    const outcome = discoveryErrorOutcome(e, execOpts.signal);
    return { ok: false, state: outcome.state, findings: [], error: outcome.reason };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

export async function runKaliAggressiveScan({
  domain,
  subdomainsAlive,
  cap,
  log,
  addFinding,
  wordpressTargets,
  paramUrls,
  xssSignals = true,
  sqliSignals = true,
  /** Só corre scans nuclei se o módulo UI `kali_nuclei` estiver activo (e modo Kali no servidor). */
  runNuclei = false,
  /** Só corre ffuf se o módulo UI `kali_ffuf` estiver activo (e modo Kali no servidor). */
  runFfuf = false,
  /** Só corre dirsearch se o módulo UI `kali_dirsearch` estiver activo (e modo Kali no servidor). */
  runDirsearch = false,
  runInfoDisclosureHunter = false,
  runInfoDisclosureErrors = false,
  infoDisclosureDeps = {},
  /**
   * Módulo UI `kali_nmap_aggressive`: nmap com `-A -sV -p-` (todas as portas) — muito lento;
   * substitui o perfil normal desta fase. Ver `GHOSTRECON_NMAP_AGGRESSIVE_MAX_HOSTS` e timeout.
   */
  runNmapAggressive = false,
  /** Capacidades Kali só rodam quando o plano explícito as habilitou. */
  runNmapBase = false,
  runWhois = false,
  runWpscan = false,
  runDalfox = false,
  allowNmapServiceFollowups = false,
  allowFtpAnonymousAudit = false,
  allowFtpWriteProbe = false,
  ftpAnonymousLoginImpl = probeFtpAnonymousLogin,
  ftpWritableProbeImpl = probeFtpAnonymousWritable,
  nmapRunner = runNmapOnHosts,
  /**
   * Módulo UI `kali_nmap_udp`: segunda passagem nmap `-sU -A` só em portas UDP sensíveis
   * (lista curada ou `GHOSTRECON_NMAP_UDP_PORTS`). Corre após o nmap TCP desta fase.
   */
  runNmapUdp = false,
  /** Módulo UI `mysql_3306_intel`: após nmap TCP, inventário observado em 3306/tcp. */
  runNmapCveMatch = false,
  runNmapBackportReview = false,
  runMysql3306Intel = false,
  /** Contexto autenticado; não é entregue a ferramentas que só o aceitam por argv. */
  auth = null,
  /** NDJSON: eventos `dork` para fila de Google (Exploit-DB por produto/versão nmap). */
  emit = null,
  /** Módulo UI `kali_proxychains`: encadeia scanners Kali via proxychains-ng. */
  useProxychains = false,
  /** Revalida cada hostname imediatamente antes de scans e sockets. */
  hostAllowed = () => true,
  /** Revalida o endereço DNS pinado imediatamente antes do socket FTP. */
  ftpAddressAllowed = () => true,
  signal = null,
  /** Dependências restritas à descoberta, para fixtures sem executar scanners. */
  directoryDiscoveryDeps = {},
}) {
  const emitEarlyFtpPolicyFailure = (reason) => {
    if (typeof emit !== 'function') return;
    for (const moduleId of [
      ...(allowFtpAnonymousAudit ? ['ftp_anonymous_audit'] : []),
      ...(allowFtpWriteProbe ? ['ftp_write_probe'] : []),
    ]) {
      const detail = {
        reason,
        partial: false,
        attempted: 0,
        resultCount: 0,
        reasonDetails: [reason],
      };
      emit({
        type: 'module_outcome',
        moduleId,
        source: 'legacy',
        status: 'failed',
        ...detail,
      });
      emit({ type: 'pipe', name: moduleId, state: 'failed', ...detail });
    }
  };
  if (useProxychains && runNmapAggressive) {
    emitEarlyFtpPolicyFailure('proxychains_nmap_aggressive_incompatible');
    const error = new Error('kali_proxychains não suporta kali_nmap_aggressive (-A/raw); use kali_nmap TCP base com -sT');
    error.code = 'PROXYCHAINS_NMAP_AGGRESSIVE_UNSUPPORTED';
    throw error;
  }
  if (useProxychains && runNmapUdp) {
    emitEarlyFtpPolicyFailure('proxychains_nmap_udp_incompatible');
    const error = new Error('kali_proxychains não suporta kali_nmap_udp; UDP não é roteável com garantia pelo wrapper');
    error.code = 'PROXYCHAINS_NMAP_UDP_UNSUPPORTED';
    throw error;
  }
  const execOpts = { useProxychains: Boolean(useProxychains), signal };
  const pipeTool = (name, state, extra = {}) => {
    if (typeof emit !== 'function') return;
    emit({ type: 'pipe', name, state, ...extra });
  };
  const finishDirectoryTool = (name, outcomes, terminalState = null) => {
    const summary = summarizeDirectoryDiscoveryOutcomes(outcomes);
    const state = terminalState || summary.state;
    const partial = summary.partial || Boolean(terminalState && outcomes.some((outcome) => outcome.state === 'done'));
    const attempted = summary.attempted + (terminalState ? 1 : 0);
    pipeTool(name, state === 'skipped' ? 'skip' : state, {
      partial, attempted, resultCount: summary.resultCount,
    });
    if (typeof emit === 'function') {
      emit({
        type: 'module_outcome', moduleId: `kali_${name}`, source: 'legacy',
        status: state, partial, resultCount: summary.resultCount, attempted,
      });
    }
  };

  const rawHosts = [domain, ...(subdomainsAlive || [])]
    .map(sanitizeHost)
    .filter((host) => host && hostAllowed(host) === true);
  const uniqueHosts = [...new Set(rawHosts)];
  const hostsAll = uniqueHosts.slice(0, 22);
  const maxAggHosts = Math.max(
    1,
    Math.min(12, Number(process.env.GHOSTRECON_NMAP_AGGRESSIVE_MAX_HOSTS || 3)),
  );
  const hosts = runNmapAggressive ? hostsAll.slice(0, maxAggHosts) : hostsAll;
  const maxUdpHosts = Math.max(
    1,
    Math.min(12, Number(process.env.GHOSTRECON_NMAP_UDP_MAX_HOSTS || 5)),
  );
  const hostsUdp = hostsAll.slice(0, maxUdpHosts);

  log('═══ MODO KALI / SCAN ATIVO ═══', 'section');
  log('Apenas em alvos com autorização explícita (bug bounty / pentest autorizado).', 'warn');
  if (runNmapAggressive) {
    log(
      `nmap AGRESSIVO: ${hosts.length} host(s) (máx. ${maxAggHosts} — -p- escaneia todas as portas; pode demorar horas). Overrides passam por allowlist antes da execução.`,
      'warn',
    );
  }
  if (runNmapBase) log(`Alvos nmap (${hosts.length}): ${hosts.join(', ')}`, 'info');

  const apexLit = hostLiteralForUrl(domain);
  const baseUrlsForFfuf = [`https://${apexLit}/`, `http://${apexLit}/`];
  const seenQueries = new Set();
  const seenExploitGoogle = new Set();
  const exploitGoogleMax = Math.max(
    1,
    Math.min(60, Number(process.env.GHOSTRECON_EXPLOIT_GOOGLE_MAX_QUERIES || 25)),
  );
  const searchsploitMax = Math.max(
    1,
    Math.min(80, Number(process.env.GHOSTRECON_SEARCHSPLOIT_MAX_QUERIES || 18)),
  );
  const ftpChecked = new Set();
  const ftpAuditSummary = {
    servicesDetected: 0,
    attempted: 0,
    confirmed: 0,
    denied: 0,
    skipped: 0,
    failed: 0,
    timeouts: 0,
    cleanupUnconfirmed: 0,
    hostsEligible: uniqueHosts.length,
    hostsScanned: 0,
    hostsTruncated: Math.max(0, uniqueHosts.length - hosts.length),
    reasons: new Set(),
  };
  const ftpWriteState = {
    halted: false,
    attempted: 0,
    writeConfirmed: 0,
    denied: 0,
    skipped: 0,
    failed: 0,
    timeouts: 0,
    cleanupUnconfirmed: 0,
    reasons: new Set(),
  };
  const smbChecked = new Set();
  const rpcChecked = new Set();

  let nmapBaseState = 'skipped';
  let ftpOutcomeEmitted = false;
  const emitFtpAuditOutcome = (override = null) => {
    if (!allowFtpAnonymousAudit || ftpOutcomeEmitted) return;
    ftpOutcomeEmitted = true;
    const outcome = override || classifyFtpAnonymousAuditOutcome(ftpAuditSummary, {
      enabled: true,
      nmapState: nmapBaseState,
    });
    const detail = {
      partial: outcome.partial === true,
      reason: outcome.reason,
      attempted: ftpAuditSummary.attempted,
      serviceCount: ftpAuditSummary.servicesDetected,
      resultCount: ftpAuditSummary.confirmed,
      negativeCount: ftpAuditSummary.denied,
      timeoutCount: ftpAuditSummary.timeouts,
      failureCount: ftpAuditSummary.failed,
      skipCount: ftpAuditSummary.skipped,
      cleanupUnconfirmedCount: ftpAuditSummary.cleanupUnconfirmed,
      hostsEligible: ftpAuditSummary.hostsEligible,
      hostsScanned: ftpAuditSummary.hostsScanned,
      hostsTruncated: ftpAuditSummary.hostsTruncated,
      reasonDetails: [...ftpAuditSummary.reasons].slice(0, 5),
    };
    if (typeof emit === 'function') {
      emit({
        type: 'module_outcome',
        moduleId: 'ftp_anonymous_audit',
        source: 'legacy',
        status: outcome.status,
        ...detail,
      });
    }
    pipeTool(
      'ftp_anonymous_audit',
      outcome.status === 'skipped' ? 'skip' : outcome.status,
      detail,
    );
  };
  let ftpWriteOutcomeEmitted = false;
  const emitFtpWriteOutcome = (override = null) => {
    if (!allowFtpWriteProbe || ftpWriteOutcomeEmitted) return;
    ftpWriteOutcomeEmitted = true;
    const outcome = override || classifyFtpWriteProbeOutcome(ftpWriteState, {
      enabled: true,
      nmapState: nmapBaseState,
      ftpAuditSummary,
    });
    const detail = {
      partial: outcome.partial === true,
      reason: outcome.reason,
      attempted: ftpWriteState.attempted,
      resultCount: ftpWriteState.writeConfirmed,
      negativeCount: ftpWriteState.denied,
      timeoutCount: ftpWriteState.timeouts,
      failureCount: ftpWriteState.failed,
      skipCount: ftpWriteState.skipped,
      cleanupUnconfirmedCount: ftpWriteState.cleanupUnconfirmed,
      hostsEligible: ftpAuditSummary.hostsEligible,
      hostsScanned: ftpAuditSummary.hostsScanned,
      hostsTruncated: ftpAuditSummary.hostsTruncated,
      reasonDetails: [...ftpWriteState.reasons].slice(0, 5),
    };
    if (typeof emit === 'function') {
      emit({
        type: 'module_outcome',
        moduleId: 'ftp_write_probe',
        source: 'legacy',
        status: outcome.status,
        ...detail,
      });
    }
    pipeTool(
      'ftp_write_probe',
      outcome.status === 'skipped' ? 'skip' : outcome.status,
      detail,
    );
  };
  if (allowFtpAnonymousAudit) pipeTool('ftp_anonymous_audit', 'active');
  if (allowFtpWriteProbe) pipeTool('ftp_write_probe', 'active');

  if (cap.tools.nmap && runNmapBase && hosts.length > 0) {
    pipeTool('nmap', 'active');
    let tcpNmapRows = [];
    try {
      tcpNmapRows = await nmapRunner(hosts, log, {
        aggressive: runNmapAggressive,
        // A capability FTP nunca herda scripts/flags arbitrárias do ambiente.
        forceSafeProfile: allowFtpAnonymousAudit && !runNmapAggressive,
        execOpts,
      });
      nmapBaseState = 'done';
      ftpAuditSummary.hostsScanned = hosts.length;
      pipeTool('nmap', 'done');
    } catch (e) {
      nmapBaseState = isProcessAbort(e)
        ? 'cancelled'
        : e?.code === 'PROCESS_TIMEOUT'
          ? 'timeout'
          : 'failed';
      pipeTool('nmap', nmapBaseState);
      if (isProcessAbort(e)) {
        emitFtpAuditOutcome({ status: 'cancelled', reason: 'operation_cancelled', partial: false });
        emitFtpWriteOutcome({ status: 'cancelled', reason: 'operation_cancelled', partial: false });
        throw e;
      }
      log(`nmap: ${e.message}`, 'error');
    }

    if (nmapBaseState === 'done') {
      const ingestCtx = {
        log,
        addFinding,
        cap,
        emit,
        seenQueries,
        seenExploitGoogle,
        exploitGoogleMax,
        searchsploitMax,
        ftpChecked,
        smbChecked,
        rpcChecked,
        baseUrlsForFfuf,
        domain,
        execOpts,
        allowNmapServiceFollowups,
        allowFtpAnonymousAudit,
        allowFtpWriteProbe,
        hostAllowed,
        ftpAddressAllowed,
        ftpAuditSummary,
        ftpWriteState,
        ftpAnonymousLoginImpl,
        ftpWritableProbeImpl,
      };
      try {
        await ingestNmapScanRows(tcpNmapRows, { ...ingestCtx, scanKind: 'tcp' });
      } catch (e) {
        if (isProcessAbort(e)) {
          emitFtpAuditOutcome({
            status: 'cancelled',
            reason: 'operation_cancelled',
            partial: ftpAuditSummary.attempted > 0,
          });
          emitFtpWriteOutcome({
            // O cancelamento continua sendo propagado ao pipeline, mas, se o
            // servidor já aceitou o reply preliminar de STOR, o estado remoto
            // incerto prevalece no outcome desta capability destrutiva.
            status: ftpWriteState.cleanupUnconfirmed > 0 ? 'failed' : 'cancelled',
            reason: ftpWriteState.cleanupUnconfirmed > 0
              ? 'operation_cancelled_remote_cleanup_unconfirmed'
              : 'operation_cancelled',
            partial: ftpWriteState.attempted > 0,
          });
          throw e;
        }
        if (allowFtpAnonymousAudit) {
          ftpAuditSummary.failed += 1;
          ftpAuditSummary.reasons.add('post_nmap_ingest_failed');
        }
        log(`nmap pós-processamento: ${e?.message || e}`, 'error');
      } finally {
        emitFtpAuditOutcome();
        emitFtpWriteOutcome();
      }

      if (runNmapBackportReview && tcpNmapRows.length) {
        pipeTool('nmap_backport_review', 'active');
        try {
          const backports = buildNmapBackportReviewFindings(tcpNmapRows);
          for (const f of backports) addFinding(f, null);
          if (backports.length) log(`Nmap backport review: ${backports.length} contexto(s) de distro/backport`, 'info');
          pipeTool('nmap_backport_review', 'done');
        } catch (e) {
          pipeTool('nmap_backport_review', isProcessAbort(e) ? 'cancelled' : 'failed');
          if (isProcessAbort(e)) throw e;
          log(`Nmap backport review: ${e?.message || e}`, 'warn');
        }
      } else {
        pipeTool('nmap_backport_review', 'skip');
      }
      if (runNmapCveMatch && tcpNmapRows.length) {
        pipeTool('nmap_cve_match', 'active');
        try {
          await runNmapCveMatchForRows(tcpNmapRows, { log, addFinding });
          pipeTool('nmap_cve_match', 'done');
        } catch (e) {
          pipeTool('nmap_cve_match', isProcessAbort(e) ? 'cancelled' : 'failed');
          if (isProcessAbort(e)) throw e;
          log(`Nmap CVE match: ${e?.message || e}`, 'warn');
        }
      } else {
        pipeTool('nmap_cve_match', 'skip');
      }
      if (runMysql3306Intel && tcpNmapRows.length) {
        const mysqlHints = buildMysql3306IntelFindings(tcpNmapRows, {
          hostAllowed,
          signal: execOpts.signal ?? null,
        });
        if (mysqlHints.length) {
          log(`MySQL 3306/tcp: +${mysqlHints.length} achado(s) intel (follow-up)`, 'info');
          for (const f of mysqlHints) addFinding(f, null);
        }
      }
    } else {
      emitFtpAuditOutcome();
      emitFtpWriteOutcome();
      pipeTool('nmap_backport_review', 'skip');
      pipeTool('nmap_cve_match', 'skip');
    }

    if (runNmapUdp) {
      pipeTool('nmap_udp', 'active');
      let udpTerminalState = 'done';
      try {
        log(
          `nmap UDP (módulo kali_nmap_udp): -sU -A em portas sensíveis — ${hostsUdp.length} host(s) (máx. ${maxUdpHosts}). Portas: env GHOSTRECON_NMAP_UDP_PORTS ou lista por defeito.`,
          'info',
        );
        const udpRows = await runNmapUdpOnHosts(hostsUdp, log, { execOpts });
        await ingestNmapScanRows(udpRows, {
          log,
          addFinding,
          cap,
          emit,
          seenQueries,
          seenExploitGoogle,
          exploitGoogleMax,
          searchsploitMax,
          ftpChecked,
          smbChecked,
          rpcChecked,
          baseUrlsForFfuf,
          domain,
          execOpts,
          allowNmapServiceFollowups,
          allowFtpAnonymousAudit: false,
          allowFtpWriteProbe: false,
          hostAllowed,
          ftpAddressAllowed,
          ftpAuditSummary,
          ftpWriteState,
          ftpAnonymousLoginImpl,
          ftpWritableProbeImpl,
          scanKind: 'udp',
        });
        if (runNmapBackportReview && udpRows.length) {
          const backports = buildNmapBackportReviewFindings(udpRows);
          for (const f of backports) addFinding(f, null);
          if (backports.length) log(`Nmap UDP backport review: ${backports.length} contexto(s)`, 'info');
        }
      } catch (e) {
        udpTerminalState = isProcessAbort(e)
          ? 'cancelled'
          : e?.code === 'PROCESS_TIMEOUT'
            ? 'timeout'
            : 'failed';
        if (!isProcessAbort(e)) log(`nmap UDP: ${e.message}`, 'error');
        if (isProcessAbort(e)) throw e;
      } finally {
        pipeTool('nmap_udp', udpTerminalState);
      }
    } else {
      pipeTool('nmap_udp', 'skip');
    }
  } else {
    if (runNmapBase && hosts.length === 0) {
      log('nmap: nenhum host permaneceu dentro do escopo no momento da execução', 'warn');
    }
    pipeTool('nmap', 'skip');
    pipeTool('nmap_udp', 'skip');
    pipeTool('nmap_cve_match', 'skip');
    pipeTool('nmap_backport_review', 'skip');
    emitFtpAuditOutcome();
    emitFtpWriteOutcome();
  }

  // ── WHOIS (Kali) ──
  // WHOIS é leitura externa (não é exploit), mas ainda assim é "ativo". Mantemos só quando ferramenta existe
  // e com amostra limitada de subdomínios para não explodir tempo.
  if (runWhois && cap.tools.whois) {
    pipeTool('whois', 'active');
    log('═══ whois (registo domínio) ═══', 'section');

    const whoisTargets = [domain, ...(subdomainsAlive || [])]
      .map(sanitizeHost)
      .filter(Boolean)
      .slice(0, 1 + (process.env.GHOSTRECON_WHOIS_SUBDOMAINS_MAX ? Number(process.env.GHOSTRECON_WHOIS_SUBDOMAINS_MAX) : limits.whoisSubdomainsMax));

    // Normalmente whois em subdomínios devolve o mesmo registo do domínio raiz.
    // Ainda assim, seguimos a tua ideia e executamos numa amostra pequena.
    for (const t of whoisTargets) {
      try {
        const { text } = await runWhoisJsonLike({ target: t, timeoutMs: limits.whoisTimeoutMs, log, execOpts });
        const parsed = parseWhoisText(t, text);
        if (!parsed.hasSomething) continue;
        const ns = parsed.nameServers?.slice(0, 6) || [];
        const valueParts = [
          parsed.registrar ? `Registrar: ${parsed.registrar}` : null,
          parsed.expires ? `Expires: ${parsed.expires}` : null,
          parsed.created ? `Created: ${parsed.created}` : null,
        ].filter(Boolean);

        addFinding(
          {
            type: 'whois',
            prio: 'low',
            score: 26,
            value: valueParts.length ? valueParts.join(' | ') : `whois: ${t}`,
            meta: [
              parsed.domainOrHost ? `Target: ${parsed.domainOrHost}` : null,
              parsed.registrantCountry ? `Country: ${parsed.registrantCountry}` : null,
              ns.length ? `NS: ${ns.join(', ')}` : null,
              parsed.updated ? `Updated: ${parsed.updated}` : null,
            ]
              .filter(Boolean)
              .join(' • '),
            url: null,
          },
          null,
        );
      } catch (e) {
        if (isProcessAbort(e)) throw e;
        log(`whois ${t}: ${e.message}`, 'warn');
      }
    }
    pipeTool('whois', 'done');
  } else {
    pipeTool('whois', 'skip');
  }

  if (runInfoDisclosureHunter && cap.tools.info_disclosure_hunter) {
    pipeTool('info_disclosure_hunter', 'active');
    if (runInfoDisclosureErrors) pipeTool('info_disclosure_errors', 'active');
    else pipeTool('info_disclosure_errors', 'skip');
    log('=== InfoHunter BR (information disclosure) ===', 'section');
    const uniqTargets = [...new Set(baseUrlsForFfuf)].slice(0, 2);
    let hunterState = 'done';
    try {
      for (const targetUrl of uniqTargets) {
        const result = await executeInfoDisclosureHunter({
          targetUrl,
          cap,
          log,
          includeErrors: runInfoDisclosureErrors,
          execOpts,
          ...infoDisclosureDeps,
        });
        if (!result.ok) {
          hunterState = result.state === 'timeout' ? 'timeout' : 'failed';
          log(`[InfoHunter] ${targetUrl}: ${result.error || 'falha desconhecida'}`, 'warn');
          continue;
        }
        for (const finding of result.findings) addFinding(finding, null);
        log(
          `[InfoHunter] ${targetUrl} -> ${result.findings.length} achado(s) de disclosure`,
          result.findings.length ? 'warn' : 'info',
        );
      }
    } catch (error) {
      hunterState = isProcessAbort(error) || execOpts.signal?.aborted ? 'cancelled' : 'failed';
      throw error;
    } finally {
      pipeTool('info_disclosure_hunter', hunterState);
      if (runInfoDisclosureErrors) pipeTool('info_disclosure_errors', hunterState);
    }
  } else {
    pipeTool('info_disclosure_hunter', 'skip');
    pipeTool('info_disclosure_errors', 'skip');
    if (!runInfoDisclosureHunter && cap.tools.info_disclosure_hunter) {
      log('InfoHunter: omitido - ativa o modulo "InfoHunter disclosure" em Sensitive Data (so com Modo Kali).', 'info');
    } else if (runInfoDisclosureHunter && !cap.tools.info_disclosure_hunter) {
      log('InfoHunter indisponivel: precisa de python3/python e tools/info-disclosure/information_disclosure.py.', 'info');
    }
  }

  const addDirectoryFinding = (entry, source) => {
    const status = Number(entry?.status || 0) || 0;
    const len = Number(entry?.length || 0) || 0;
    const value = String(entry?.url || '').trim();
    if (!value) return;
    addFinding(
      {
        type: 'directory',
        prio: [401, 403].includes(status) ? 'low' : 'info',
        score: [200, 204].includes(status) ? 30 : [301, 302, 307, 308].includes(status) ? 26 : [401, 403].includes(status) ? 32 : 18,
        value,
        meta: `${source} • evidence_status=inventory • status=${status || '-'} • length=${len || '-'} • words=${Number(entry?.words || 0) || '-'} • lines=${Number(entry?.lines || 0) || '-'}`,
        url: value,
      },
      'directories',
    );
    // Mantemos endpoint para não perder cobertura dos módulos de verificação já existentes.
    addFinding(
      {
        type: 'endpoint',
        prio: 'info',
        score: [200, 204].includes(status) ? 28 : 22,
        value,
        meta: `${source} • evidence_status=inventory • status=${status || '-'} • length=${len || '-'}`,
        url: value,
      },
      'endpoints',
    );
  };

  if (runFfuf && cap.tools.ffuf) {
    pipeTool('ffuf', 'active');
    log('═══ ffuf (calibrado; 2xx/3xx/401/403) ═══', 'section');
    const uniqBases = [...new Set(baseUrlsForFfuf)].slice(0, 3);
    const outcomes = [];
    try {
      for (const u of uniqBases) {
        const outcome = await runFfufDiscovery(u, log, execOpts, directoryDiscoveryDeps);
        outcomes.push(outcome);
        for (const p of outcome.results) addDirectoryFinding(p, 'ffuf');
        log(`ffuf: ${outcome.state}; ${outcome.results.length} caminho(s)${outcome.reason ? `; ${outcome.reason}` : ''}`,
          ['failed', 'timeout'].includes(outcome.state) ? 'warn' : 'info');
      }
    } catch (error) {
      finishDirectoryTool('ffuf', outcomes, signal?.aborted || isProcessAbort(error) ? 'cancelled' : 'failed');
      throw error;
    }
    finishDirectoryTool('ffuf', outcomes);
  } else {
    pipeTool('ffuf', 'skip');
    if (!runFfuf && cap.tools.ffuf) {
      log('ffuf: omitido — activa o módulo «Ffuf (Kali)» em Sensitive Data (só com Modo Kali).', 'info');
    }
  }

  if (runDirsearch && cap.tools.dirsearch) {
    pipeTool('dirsearch', 'active');
    log('═══ dirsearch (recursão limitada, mesmo escopo) ═══', 'section');
    const uniqBases = [...new Set(baseUrlsForFfuf)].slice(0, 3);
    const outcomes = [];
    try {
      for (const u of uniqBases) {
        const outcome = await runDirsearchAll(u, log, execOpts, directoryDiscoveryDeps);
        outcomes.push(outcome);
        for (const h of outcome.results) addDirectoryFinding(h, 'dirsearch');
        log(`dirsearch: ${outcome.state}; ${outcome.results.length} caminho(s)${outcome.reason ? `; ${outcome.reason}` : ''}`,
          ['failed', 'timeout'].includes(outcome.state) ? 'warn' : 'info');
      }
    } catch (error) {
      finishDirectoryTool('dirsearch', outcomes, signal?.aborted || isProcessAbort(error) ? 'cancelled' : 'failed');
      throw error;
    }
    finishDirectoryTool('dirsearch', outcomes);
  } else {
    pipeTool('dirsearch', 'skip');
    if (!runDirsearch && cap.tools.dirsearch) {
      log('dirsearch: omitido — activa o módulo «Dirsearch (Kali)» em Sensitive Data (só com Modo Kali).', 'info');
    }
  }

  if (runNuclei && cap.tools.nuclei) {
    pipeTool('nuclei', 'active');
    log('═══ nuclei ═══', 'section');
    const targets = [...new Set(baseUrlsForFfuf.map((b) => b.replace(/\/$/, '')))].slice(0, 15);
    try {
      const findings = await runNucleiList(targets, log, execOpts);
      for (const f of findings) {
        const matched = f['matched-at'] || f.host || f.url || '';
        const tid = f['template-id'] || f.templateID || 'template';
        const sev = f.info?.severity || f.severity || 'info';
        addFinding({
          type: 'nuclei',
          prio: ['critical', 'high'].includes(String(sev).toLowerCase()) ? 'high' : 'med',
          score: sev === 'critical' ? 95 : sev === 'high' ? 88 : 60,
          value: `${tid} @ ${matched}`,
          meta: nucleiEvidenceMeta({
            tid,
            sev,
            extra: matched ? `matched=${String(matched).slice(0, 120)}` : null,
          }),
          url: matched.startsWith('http') ? matched : null,
        });
      }
      log(`nuclei: ${findings.length} finding(s)`, findings.length ? 'warn' : 'info');
    } catch (e) {
      if (isProcessAbort(e)) throw e;
      log(`nuclei: ${e.message}`, 'warn');
    } finally {
      pipeTool('nuclei', 'done');
    }
  } else {
    pipeTool('nuclei', 'skip');
    if (!runNuclei && cap.tools.nuclei) {
      log('Nuclei: omitido — activa o módulo «Nuclei (Kali)» em Sensitive Data (só com Modo Kali).', 'info');
    }
  }

  // XSS/SQLi via nuclei tags contra URLs com query string (vindas do corpus passivo)
  const canParamNuclei = runNuclei && cap.tools.nuclei && Array.isArray(paramUrls) && paramUrls.length;
  if (!canParamNuclei) {
    pipeTool('nuclei_xss', 'skip');
    pipeTool('nuclei_sqli', 'skip');
  } else {
    const urls = [...new Set(paramUrls)].slice(0, 30);

    if (xssSignals) {
      pipeTool('nuclei_xss', 'active');
      log(`═══ nuclei (xss) em URLs com parâmetros (${urls.length}) ═══`, 'section');
      try {
        const xss = await runNucleiTags(urls, 'xss', log, execOpts);
        for (const f of xss) {
          const matched = f['matched-at'] || f.host || f.url || '';
          const tid = f['template-id'] || f.templateID || 'template';
          const sev = f.info?.severity || f.severity || 'info';
          addFinding({
            type: 'xss',
            prio: ['critical', 'high'].includes(String(sev).toLowerCase()) ? 'high' : 'med',
            score: sev === 'critical' ? 95 : sev === 'high' ? 90 : 70,
            value: `${tid} @ ${matched}`,
            meta: nucleiEvidenceMeta({ tid, sev, extra: 'tags=xss' }),
            url: matched.startsWith('http') ? matched : null,
          });
        }
        if (xss.length) log(`XSS: ${xss.length} finding(s)`, 'warn');
      } catch (e) {
        if (isProcessAbort(e)) throw e;
        log(`XSS nuclei: ${e.message}`, 'warn');
      } finally {
        pipeTool('nuclei_xss', 'done');
      }
    } else {
      log('nuclei tags=xss: skip (sem sinais passivos)', 'info');
      pipeTool('nuclei_xss', 'skip');
    }

    if (sqliSignals) {
      pipeTool('nuclei_sqli', 'active');
      log(`═══ nuclei (sqli) em URLs com parâmetros (${urls.length}) ═══`, 'section');
      try {
        const sqli = await runNucleiTags(urls, 'sqli', log, execOpts);
        for (const f of sqli) {
          const matched = f['matched-at'] || f.host || f.url || '';
          const tid = f['template-id'] || f.templateID || 'template';
          const sev = f.info?.severity || f.severity || 'info';
          addFinding({
            type: 'sqli',
            prio: ['critical', 'high'].includes(String(sev).toLowerCase()) ? 'high' : 'med',
            score: sev === 'critical' ? 98 : sev === 'high' ? 92 : 72,
            value: `${tid} @ ${matched}`,
            meta: nucleiEvidenceMeta({ tid, sev, extra: 'tags=sqli' }),
            url: matched.startsWith('http') ? matched : null,
          });
        }
        if (sqli.length) log(`SQLi: ${sqli.length} finding(s)`, 'warn');
      } catch (e) {
        if (isProcessAbort(e)) throw e;
        log(`SQLi nuclei: ${e.message}`, 'warn');
      } finally {
        pipeTool('nuclei_sqli', 'done');
      }
    } else {
      log('nuclei tags=sqli: skip (sem sinais passivos)', 'info');
      pipeTool('nuclei_sqli', 'skip');
    }
  }

  if (runWpscan && cap.tools.wpscan) {
    const detectionMode = process.env.GHOSTRECON_WPSCAN_DETECTION_MODE || 'mixed';
    const timeoutMs = Number(process.env.GHOSTRECON_WPSCAN_TIMEOUT_MS || 240000);

    log('═══ WPScan — ferramenta wpscan (WordPress) ═══', 'section');
    const targets = Array.isArray(wordpressTargets) ? wordpressTargets : null;

    if (!targets || targets.length === 0) {
      log('[WPScan] WordPress não confirmado no passivo — wpscan não executado', 'info');
      pipeTool('wpscan', 'skip');
    } else if (isWpscanApiRequired() && !isWpscanApiTokenConfigured()) {
      log(
        '[WPScan] SKIP — token obrigatório (GHOSTRECON_WPSCAN_REQUIRE_API≠0). Define WPSCAN_API_TOKEN ou GHOSTRECON_WPSCAN_API_TOKEN no .env (wpscan.com/register). Para permitir scan sem WPVulnDB: GHOSTRECON_WPSCAN_REQUIRE_API=0',
        'warn',
      );
      pipeTool('wpscan', 'skip');
    } else {
      pipeTool('wpscan', 'active');
      let wpscanSucceeded = 0;
      let wpscanFailed = 0;
      let wpscanTimedOut = 0;
      if (isWpscanApiTokenConfigured()) {
        log(
          '[WPScan] WPVulnDB ligado — WPSCAN_API_TOKEN / GHOSTRECON_WPSCAN_API_TOKEN (CVEs conhecidos no JSON)',
          'success',
        );
      } else {
        log(
          '[WPScan] WPVulnDB desligado — sem token; só enumeração core/tema/plugins. Recomendado: WPSCAN_API_TOKEN no .env',
          'warn',
        );
      }
      const uniqTargets = [...new Set(targets)].slice(0, 6);
      log(`[WPScan] ${uniqTargets.length} alvo(s) WordPress — a iniciar wpscan em cada URL`, 'info');
      for (const t of uniqTargets) {
        throwIfAborted(signal);
        let targetHost = '';
        try { targetHost = new URL(t).hostname; } catch { /* invalid below */ }
        if (!targetHost || hostAllowed(targetHost) !== true) {
          wpscanFailed += 1;
          log('[WPScan] alvo descartado por URL inválida ou fora do escopo', 'warn');
          continue;
        }
        log(`[WPScan] ▶︎ alvo: ${t}`, 'info');
        const res = await runWpscanJson({
          targetUrl: t,
          detectionMode,
          timeoutMs,
          log,
          signal,
        });
        if (res?.json) {
          wpscanSucceeded += 1;
          const findings = extractWpscanFindings({ targetUrl: t, wpscanJson: res.json });
          const vulnN = Number.isFinite(res.vulnDbCount) ? res.vulnDbCount : countWpvulndbFindings(res.json);
          if (findings.length) {
            log(
              `[WPScan] ✓ concluído ${t} → ${findings.length} achado(s) na lista (${vulnN} entrada(s) WPVulnDB/CVE no JSON)`,
              'success',
            );
          } else {
            log(`[WPScan] ✓ concluído ${t} → sem achados extraídos (JSON OK)`, 'info');
          }
          for (const f of findings) addFinding(f, null);
        } else {
          if (res?.status === 'timeout') wpscanTimedOut += 1;
          else wpscanFailed += 1;
          log(`[WPScan] ✗ ${t}: sem JSON válido (${res?.error || 'unknown'})`, 'warn');
        }
      }
      log('[WPScan] Fim da fase wpscan (todos os alvos WordPress desta corrida)', 'info');
      const wpscanState = wpscanSucceeded > 0
        ? 'done'
        : wpscanTimedOut > 0 && wpscanFailed === 0
          ? 'timeout'
          : 'failed';
      pipeTool('wpscan', wpscanState, {
        partial: wpscanSucceeded > 0 && (wpscanFailed > 0 || wpscanTimedOut > 0),
        succeeded: wpscanSucceeded,
        failed: wpscanFailed,
        timedOut: wpscanTimedOut,
      });
    }
  } else {
    pipeTool('wpscan', 'skip');
  }

  if (runDalfox && cap.tools.dalfox && xssSignals && Array.isArray(paramUrls) && paramUrls.length) {
    pipeTool('dalfox', 'active');
    const targets = [...new Set(paramUrls)].slice(0, Number(process.env.GHOSTRECON_DALFOX_MAX_URLS || 12));
    log(`═══ dalfox (XSS) em URLs com parâmetros (${targets.length}) ═══`, 'section');
    try {
    for (const u of targets) {
      const r = await runDalfoxUrl(u, log, auth, execOpts);
      if (!r.ok) {
        log(`dalfox ${u}: ${r.error}`, 'warn');
        continue;
      }
      for (const h of r.hits) {
        addFinding({
          type: 'dalfox',
          prio: 'high',
          score: 90,
          value: `dalfox hit @ ${u}`,
          meta: `scanner=dalfox • format=${r.stdoutFormat || 'mixed'} • confidence=tool_output • ${h}`,
          url: u,
        });
      }
      if (r.hits.length) log(`dalfox ${u} → ${r.hits.length} hit(s)`, 'warn');
    }
    } finally {
      pipeTool('dalfox', 'done');
    }
  } else if (runDalfox && cap.tools.dalfox && !xssSignals && Array.isArray(paramUrls) && paramUrls.length) {
    log('dalfox: skip (sem sinais XSS passivos)', 'info');
    pipeTool('dalfox', 'skip');
  } else {
    pipeTool('dalfox', 'skip');
  }

  log('═══ Fim modo Kali ═══', 'section');
}
