import fs from 'node:fs/promises';
import path from 'node:path';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { clientIp } from '../lib/client-ip.mjs';
import { postAlert } from './alerting.mjs';
import { parseReconTarget } from './recon-target.js';
import { resolveVpsReconModules } from './vps-recon-policy.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..', '..');
const DEFAULT_STATE_DIR = path.join(ROOT, '.ghostcommand');
const DEFAULT_ALLOWED_IP = '162.243.54.185';

export function ghostCommandConfig() {
  return {
    stateDir: process.env.GHOSTCOMMAND_STATE_DIR || DEFAULT_STATE_DIR,
    allowedIps: parseCsv(process.env.GHOSTCOMMAND_ALLOWED_IPS || process.env.GHOSTCOMMAND_ALLOWED_IP || DEFAULT_ALLOWED_IP),
    apiKey: String(process.env.GHOSTCOMMAND_API_KEY || process.env.GHOSTRECON_MOBILE_API_KEY || '').trim(),
    webhook:
      String(
        process.env.GHOSTCOMMAND_WEBHOOK ||
          process.env.GHOSTRECON_WEBHOOK_URL ||
          process.env.DISCORD_WEBHOOK ||
          '',
      ).trim(),
    playbook: process.env.GHOSTCOMMAND_PLAYBOOK || 'full-recon',
  };
}

export function normalizeIp(ip) {
  const raw = String(ip || '').trim();
  if (raw.startsWith('::ffff:')) return raw.slice('::ffff:'.length);
  return raw;
}

export function requestIp(req) {
  return normalizeIp(clientIp(req));
}

export function isAllowedIp(ip, allowedIps = ghostCommandConfig().allowedIps) {
  const n = normalizeIp(ip);
  return new Set((allowedIps || []).map(normalizeIp)).has(n);
}

export function authorizeGhostCommandRequest(req, config = ghostCommandConfig()) {
  const ip = requestIp(req);
  if (!isAllowedIp(ip, config.allowedIps)) {
    return { ok: false, status: 403, code: 'ip_blocked', ip };
  }
  if (config.apiKey) {
    const got = String(req.headers['x-ghostcommand-key'] || req.headers['x-ghostrecon-mobile-key'] || '').trim();
    if (!constantTimeStringEqual(got, config.apiKey)) {
      return { ok: false, status: 401, code: 'mobile_key_invalid', ip };
    }
  }
  return { ok: true, ip };
}

export async function loadGhostCommandGate(stateDir = ghostCommandConfig().stateDir) {
  const file = gateFile(stateDir);
  try {
    const gate = JSON.parse(await fs.readFile(file, 'utf8'));
    return normalizeGate(gate);
  } catch {
    return normalizeGate({});
  }
}

export async function saveGhostCommandGate(gate, stateDir = ghostCommandConfig().stateDir) {
  const file = gateFile(stateDir);
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, JSON.stringify(normalizeGate(gate), null, 2), 'utf8');
}

export async function openGhostCommandGate({ reason = 'manual', by = 'vps' } = {}, stateDir = ghostCommandConfig().stateDir) {
  const gate = normalizeGate(await loadGhostCommandGate(stateDir));
  gate.open = true;
  gate.openedAt = new Date().toISOString();
  gate.openedBy = by;
  gate.openReason = reason;
  gate.closedAt = null;
  gate.closedBy = null;
  gate.closeReason = null;
  await saveGhostCommandGate(gate, stateDir);
  return gate;
}

export async function closeGhostCommandGate({ reason = 'manual', by = 'vps' } = {}, stateDir = ghostCommandConfig().stateDir) {
  const gate = normalizeGate(await loadGhostCommandGate(stateDir));
  gate.open = false;
  gate.closedAt = new Date().toISOString();
  gate.closedBy = by;
  gate.closeReason = reason;
  await saveGhostCommandGate(gate, stateDir);
  return gate;
}

export function createGhostCommandRunner({ runPipeline, config = ghostCommandConfig() } = {}) {
  const state = {
    running: null,
    history: [],
  };

  async function submit({ target, outOfScope = [], requestedBy = null } = {}) {
    const parsed = parseReconTarget(target);
    if (!parsed.ok) return { ok: false, status: 400, error: parsed.message || 'target invalido' };

    const gate = await loadGhostCommandGate(config.stateDir);
    if (!gate.open) return { ok: false, status: 423, error: 'ghostcommand gate fechado', gate };
    if (state.running) {
      return {
        ok: false,
        status: 409,
        error: 'ghostcommand ocupado',
        running: state.running,
      };
    }

    const job = {
      id: randomBytes(8).toString('hex'),
      target: parsed.target,
      outOfScope: Array.isArray(outOfScope) ? outOfScope.map(String) : parseCsv(outOfScope),
      requestedBy,
      requestedAt: new Date().toISOString(),
      status: 'running',
      startedAt: new Date().toISOString(),
    };
    state.running = job;
    void run(job);
    return { ok: true, job };
  }

  async function run(job) {
    await notify(config.webhook, buildGhostCommandAlert('started', state.running));

    const events = [];
    const errors = [];
    let runId = null;
    let stats = null;
    try {
      const { modules, playbook } = await resolveVpsReconModules({ playbook: config.playbook });
      await runPipeline({
        domain: job.target,
        exactMatch: false,
        modules,
        emit: (evt) => {
          events.push(evt);
          if (evt?.runId) runId = evt.runId;
          if (evt?.type === 'stats' && evt.stats) stats = evt.stats;
          if (evt?.type === 'error') errors.push(evt.message || 'erro desconhecido');
        },
        kaliMode: true,
        profile: 'aggressive',
        outOfScope: job.outOfScope.join(','),
        projectName: `ghostcommand-${job.target}`,
        autoAiReports: false,
        shannonPrecheck: false,
        shannonSkipDepsVerify: true,
        navigatorMode: false,
        navegation: { enabled: false },
        engine: 'both',
        vigoliumStrategy: 'deep',
        vigoliumUseCodex: false,
      });
      state.running = {
        ...state.running,
        status: errors.length ? 'finished_with_errors' : 'finished',
        finishedAt: new Date().toISOString(),
        runId,
        stats,
        eventCount: events.length,
        errors,
        playbook,
        moduleCount: modules.length,
      };
      await notify(config.webhook, buildGhostCommandAlert('finished', state.running));
    } catch (e) {
      state.running = {
        ...state.running,
        status: 'failed',
        finishedAt: new Date().toISOString(),
        error: e?.message || String(e),
        runId,
        stats,
        eventCount: events.length,
        errors,
      };
      await notify(config.webhook, buildGhostCommandAlert('failed', state.running));
    } finally {
      state.history.unshift(state.running);
      state.history = state.history.slice(0, 50);
      state.running = null;
    }
  }

  function status() {
    return {
      running: state.running,
      history: state.history.slice(0, 10),
    };
  }

  return { submit, status };
}

export function buildGhostCommandAlert(kind, job) {
  const title =
    kind === 'started'
      ? 'GhostCommand iniciou recon'
      : kind === 'failed'
        ? 'GhostCommand falhou'
        : 'GhostCommand finalizou recon';
  const stats = job.stats || {};
  const lines = [
    `**${title}**`,
    `Alvo: \`${job.target}\``,
    job.runId ? `Run: #${job.runId}` : null,
    job.status ? `Status: \`${job.status}\`` : null,
    job.moduleCount ? `Modulos: ${job.moduleCount}` : null,
    job.eventCount != null ? `Eventos: ${job.eventCount}` : null,
    stats.high != null ? `Resumo: high=${stats.high || 0} subs=${stats.subs || 0} endpoints=${stats.endpoints || 0}` : null,
    job.error ? `Erro: ${String(job.error).slice(0, 500)}` : null,
    job.errors?.length ? `Erros: ${job.errors.slice(0, 3).join(' | ').slice(0, 700)}` : null,
  ].filter(Boolean);
  return {
    source: 'ghostcommand',
    target: job.target,
    content: lines.join('\n'),
    summary: { high: stats.high || 0, medium: stats.medium || 0, low: stats.low || 0 },
  };
}

function gateFile(stateDir) {
  return path.join(stateDir || DEFAULT_STATE_DIR, 'gate.json');
}

function normalizeGate(gate) {
  return {
    version: 1,
    open: Boolean(gate?.open),
    openedAt: gate?.openedAt || null,
    openedBy: gate?.openedBy || null,
    openReason: gate?.openReason || null,
    closedAt: gate?.closedAt || null,
    closedBy: gate?.closedBy || null,
    closeReason: gate?.closeReason || null,
  };
}

function parseCsv(raw) {
  if (Array.isArray(raw)) return raw.map(String).map((s) => s.trim()).filter(Boolean);
  return String(raw || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function constantTimeStringEqual(a, b) {
  if (!a || !b) return false;
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

async function notify(webhook, payload) {
  if (!webhook) return;
  try {
    await postAlert(webhook, payload);
  } catch {
    // Alerts must never block recon progress.
  }
}
