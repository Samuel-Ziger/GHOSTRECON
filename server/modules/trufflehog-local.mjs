import fs from 'node:fs/promises';
import path from 'node:path';
import { runProcess } from './module-runner.mjs';
import { protectSecretFinding, safeSecretReference } from './secret-safety.js';

const MAX_RESULTS = 50;

function parseBool(value, fallback = false) {
  if (value == null || String(value).trim() === '') return fallback;
  return /^(?:1|true|yes|on)$/i.test(String(value).trim());
}

export function trufflehogLocalConfig(env = process.env) {
  return {
    enabled: parseBool(env.GHOSTRECON_TRUFFLEHOG_LOCAL_ENABLED, false),
    binary: String(env.GHOSTRECON_TRUFFLEHOG_BIN || 'trufflehog').trim() || 'trufflehog',
    timeoutMs: Math.max(5_000, Math.min(Number(env.GHOSTRECON_TRUFFLEHOG_TIMEOUT_MS) || 90_000, 600_000)),
  };
}

function sourcePath(row) {
  const fsMeta = row?.SourceMetadata?.Data?.Filesystem || row?.SourceMetadata?.Data?.Git || {};
  return String(fsMeta.file || fsMeta.path || fsMeta.File || row?.SourceName || '').slice(0, 400);
}

function rawFromRow(row) {
  const raw = row?.RawV2 ?? row?.Raw ?? '';
  if (typeof raw === 'string') return raw;
  if (Array.isArray(raw)) return Buffer.from(raw).toString('utf8');
  return '';
}

export function parseTrufflehogNdjson(text, { repoUrl = null, maxResults = MAX_RESULTS } = {}) {
  const findings = [];
  const seen = new Set();
  for (const line of String(text || '').split(/\r?\n/)) {
    if (!line.trim() || findings.length >= maxResults) continue;
    let row;
    try { row = JSON.parse(line); } catch { continue; }
    const raw = rawFromRow(row);
    const detector = String(row.DetectorName || row.DetectorType || 'secret').slice(0, 100);
    const source = sourcePath(row);
    if (!raw || raw.length < 6) continue;
    const safe = safeSecretReference(raw, { fingerprint: null });
    const key = `${detector}:${source}:${safe.fingerprint}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const finding = {
      type: 'secret',
      prio: 'med',
      score: 64,
      value: `[${detector}] ${raw}`,
      url: repoUrl || undefined,
      meta: {
        source: 'trufflehog_local',
        detector,
        path: source ? path.basename(source) : null,
        verified: false,
        verificationDisabled: true,
        confidence: 'classified_unverified',
      },
    };
    findings.push(protectSecretFinding(finding));
  }
  return findings;
}

async function isDirectory(value) {
  try { return (await fs.stat(value)).isDirectory(); } catch { return false; }
}

export async function runTrufflehogLocal({
  directory,
  repoUrl = null,
  signal = null,
  executor = runProcess,
  env = process.env,
} = {}) {
  const config = trufflehogLocalConfig(env);
  if (!config.enabled) return { skipped: true, reason: 'disabled', findings: [] };
  const resolved = path.resolve(String(directory || ''));
  if (!directory || !(await isDirectory(resolved))) {
    return { skipped: true, reason: 'directory_unavailable', findings: [] };
  }
  const result = await executor(
    config.binary,
    [
      'filesystem',
      resolved,
      '--json',
      '--no-verification',
      '--no-update',
      '--results=unverified,unknown',
      '--concurrency=2',
      '--archive-max-size=10MB',
      '--archive-max-depth=3',
    ],
    {
      timeoutMs: config.timeoutMs,
      signal,
      rejectOnError: false,
      rejectOnTimeout: false,
      stdoutMaxBytes: 8 * 1024 * 1024,
      stderrMaxBytes: 256 * 1024,
      label: 'trufflehog local',
      spawnOpts: {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
          PATH: process.env.PATH,
          LANG: 'C',
          LC_ALL: 'C',
        },
      },
    },
  );
  if (result.timedOut) return { ok: false, timedOut: true, findings: [], error: 'timeout' };
  if (result.code !== 0 && !String(result.stdout || '').trim()) {
    return { ok: false, findings: [], error: String(result.stderr || `exit_${result.code}`).slice(0, 240) };
  }
  return {
    ok: true,
    findings: parseTrufflehogNdjson(result.stdout, { repoUrl }),
    metrics: { exitCode: result.code, verificationDisabled: true },
  };
}
