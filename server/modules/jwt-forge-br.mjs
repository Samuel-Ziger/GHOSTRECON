/**
 * Integração do JWTForge BR (main.py) no pipeline GHOSTRECON.
 * Executa auditoria completa (--audit-json) em tokens descobertos durante o recon.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sevToPrio, sevToScore } from '../lib/severity.mjs';
import { analyzeJwt } from './jwt-lab.mjs';
import { extractRawToken } from './token-validator.js';
import { runProcess } from './module-runner.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const JWT_FORGE_BR_SCRIPT = path.join(__dirname, '../../tools/jwt-forge-br/main.py');

const JWT_INLINE_RE = /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g;
const MAX_TOKENS = Number(process.env.GHOSTRECON_JWT_FORGE_MAX_TOKENS || 8);
const AUDIT_TIMEOUT_MS = Number(process.env.GHOSTRECON_JWT_FORGE_TIMEOUT_MS || 45_000);

const SEV_MAP = {
  CRITICO: 'critical',
  MEDIO: 'medium',
  OK: 'info',
  INFO: 'info',
};

function isJwtShape(tok) {
  return /^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/.test(tok);
}

function addCandidate(set, raw) {
  const tok = extractRawToken(raw);
  if (isJwtShape(tok)) set.add(tok);
}

/** Extrai tokens JWT de auth, cookies, headers e findings do run. */
export function collectJwtCandidates(state) {
  const seen = new Set();
  const { auth, findings = [] } = state;

  if (auth?.cookie) {
    for (const part of String(auth.cookie).split(/[;,\s]+/)) {
      addCandidate(seen, part);
    }
  }
  for (const v of Object.values(auth?.headers || {})) {
    const s = String(v || '');
    JWT_INLINE_RE.lastIndex = 0;
    let m;
    while ((m = JWT_INLINE_RE.exec(s)) !== null) {
      addCandidate(seen, m[1]);
    }
  }

  for (const f of findings) {
    const blob = `${f.value || ''} ${f.meta || ''}`;
    JWT_INLINE_RE.lastIndex = 0;
    let m;
    while ((m = JWT_INLINE_RE.exec(blob)) !== null) {
      addCandidate(seen, m[1]);
    }
  }

  return [...seen].slice(0, MAX_TOKENS);
}

export function jwtForgeBrAvailable() {
  return fs.existsSync(JWT_FORGE_BR_SCRIPT);
}

async function resolvePythonCmd() {
  for (const cmd of ['python3', 'python', 'py']) {
    try {
      const r = await runProcess(cmd, ['--version'], {
        timeoutMs: 5_000,
        rejectOnError: false,
        stdoutMaxBytes: 512,
        stderrMaxBytes: 512,
      });
      if (r.code === 0 || /python/i.test(`${r.stdout}${r.stderr}`)) return cmd;
    } catch {
      /* try next */
    }
  }
  return null;
}

/** Executa main.py --audit-json para um token. */
export async function auditTokenWithForgeBr(token, { pythonCmd, wordlist } = {}) {
  const py = pythonCmd || (await resolvePythonCmd());
  if (!py) return { ok: false, error: 'python3/python não encontrado no PATH' };
  if (!jwtForgeBrAvailable()) {
    return { ok: false, error: `script ausente: ${JWT_FORGE_BR_SCRIPT}` };
  }

  const args = [JWT_FORGE_BR_SCRIPT];
  if (wordlist) args.push('--wordlist', wordlist);
  args.push('--audit-json', token);

  const proc = await runProcess(py, args, {
    timeoutMs: AUDIT_TIMEOUT_MS,
    rejectOnError: false,
    stdoutMaxBytes: 256 * 1024,
    stderrMaxBytes: 32 * 1024,
    label: 'jwt-forge-br',
    spawnOpts: {
      env: { ...process.env, PYTHONIOENCODING: 'utf-8', PYTHONUTF8: '1' },
    },
  });

  const raw = (proc.stdout || '').trim();
  if (!raw) {
    return {
      ok: false,
      error: proc.timedOut ? 'timeout' : (proc.stderr || 'saída vazia').trim(),
      proc,
    };
  }

  try {
    const parsed = JSON.parse(raw);
    return { ok: true, audit: parsed, proc };
  } catch (e) {
    return { ok: false, error: `JSON inválido: ${e.message}`, proc };
  }
}

export function forgeBrAuditToFindings(audit, tokenPreview = '') {
  if (!audit?.findings?.length) return [];
  const rows = [];
  for (const f of audit.findings) {
    const sev = SEV_MAP[String(f.severity || '').toUpperCase()] || 'info';
    if (sev === 'info' && /secret não está na lista de comuns|Token já expirado|Expiração em janela razoável|Algoritmo assimétrico/i.test(f.message || '')) {
      continue;
    }
    rows.push({
      type: 'intel',
      prio: sevToPrio(sev),
      score: sevToScore(sev),
      value: `JWTForge BR: ${f.message}`,
      meta: [
        tokenPreview ? `token=${tokenPreview}` : null,
        f.mitigation ? `mitigação=${f.mitigation}` : null,
        audit.header?.alg ? `alg=${audit.header.alg}` : null,
      ].filter(Boolean).join(' · '),
      owasp: 'A07:2021',
    });
  }
  return rows;
}

/**
 * Módulo jwt_lab do pipeline: análise estática (jwt-lab.mjs) + auditoria profunda (main.py).
 */
export async function runJwtLabPipeline(s) {
  const { log, addFinding } = s;
  const tokens = collectJwtCandidates(s);
  if (!tokens.length) {
    log('JWT lab: nenhum token candidato encontrado', 'info');
    return { tokens: 0, staticFindings: 0, forgeFindings: 0 };
  }

  let staticFindings = 0;
  for (const tok of tokens) {
    const r = analyzeJwt(tok);
    if (!r.ok) continue;
    for (const f of r.findings || []) {
      staticFindings += 1;
      addFinding({
        type: 'intel',
        prio: sevToPrio(f.severity),
        score: sevToScore(f.severity),
        value: `JWT lab: ${f.issue}`,
        meta: f.detail,
      });
    }
  }

  let forgeFindings = 0;
  if (jwtForgeBrAvailable()) {
    const pythonCmd = await resolvePythonCmd();
    if (!pythonCmd) {
      log('JWTForge BR: python não disponível — apenas análise estática jwt-lab', 'warn');
    } else {
      for (const tok of tokens) {
        const preview = tok.length > 24 ? `${tok.slice(0, 24)}…` : tok;
        const result = await auditTokenWithForgeBr(tok, { pythonCmd });
        if (!result.ok) {
          log(`JWTForge BR: ${preview} — ${result.error}`, 'warn');
          continue;
        }
        const rows = forgeBrAuditToFindings(result.audit, preview);
        for (const row of rows) {
          forgeFindings += 1;
          addFinding(row);
        }
      }
    }
  } else {
    log(`JWTForge BR: main.py não encontrado em ${JWT_FORGE_BR_SCRIPT}`, 'warn');
  }

  log(
    `JWT lab: ${tokens.length} token(s) · estática=${staticFindings} · JWTForge BR=${forgeFindings}`,
    forgeFindings ? 'warn' : 'info',
  );

  return { tokens: tokens.length, staticFindings, forgeFindings };
}
