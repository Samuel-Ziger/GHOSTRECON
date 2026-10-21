import { getRegistryEntry } from '../modules/module-registry.mjs';
import { moduleEnabled, normalizeModuleId } from '../modules/module-ids.mjs';
import { withProvenance } from '../modules/finding-provenance.js';
import { redactAutoText } from '../auto-agent/redaction.mjs';

const MAX_OUTCOME_TEXT_CHARS = 240;
const MAX_LOG_TEXT_CHARS = 2_000;
const SAFE_LOG_LEVELS = new Set(['info', 'success', 'warn', 'error']);

function safePublicText(value, maxChars = MAX_OUTCOME_TEXT_CHARS) {
  try {
    return redactAutoText(value, process.env, { cloud: false })
      .replace(/\0/g, '')
      .slice(0, maxChars);
  } catch {
    return '[REDACTED]';
  }
}

function safeLogLevel(value) {
  const level = String(value || 'info').toLowerCase();
  return SAFE_LOG_LEVELS.has(level) ? level : 'info';
}

function isTimeoutError(error) {
  if (!error) return false;
  if (error?.code === 'PROCESS_TIMEOUT') return true;
  if (error?.name === 'TimeoutError') return true;
  const message = String(error?.message || '');
  return /timed.?out|timeout/i.test(message) && !/aborted|cancelled|canceled/i.test(message);
}

function isAbortLikeError(error, signal = null) {
  if (signal?.aborted && !isTimeoutError(signal.reason) && !isTimeoutError(error)) return true;
  if (!error) return false;
  if (isTimeoutError(error)) return false;
  if (error?.name === 'AbortError') return true;
  const code = String(error?.code || '');
  if (code === 'PROCESS_ABORTED' || code === 'PROCESS_UNTERMINATED' || code === 'ABORT_ERR') {
    return true;
  }
  return /aborted|cancelled|canceled|unterminated/i.test(String(error?.message || ''));
}

function emitTerminalOutcome(s, moduleId, status, extra = {}) {
  const emit = typeof s?.emit === 'function' ? s.emit : null;
  const pipe = typeof s?.pipe === 'function' ? s.pipe : null;
  const pipeState = status === 'skipped' ? 'skip' : status;
  pipe?.(moduleId, pipeState);
  emit?.({
    type: 'module_outcome',
    moduleId,
    status,
    source: 'registry',
    ...extra,
  });
}

const SAFE_NUMERIC_OUTCOME_METRIC_KEYS = new Set([
  'attempts',
  'contracts',
  'completed',
  'failed',
  'skipped',
  'outcomes',
  'snapshotsMaterialized',
  'changes',
  'originsPlanned',
  'originsCompleted',
  'candidatesPerOrigin',
  'candidatesPlanned',
  'candidatesEvaluated',
  'candidatesConclusive',
  'candidatesInconclusive',
  'candidatesSkippedByLimit',
  'candidatesAbortedByDeadline',
  'candidatesSkippedByDeadline',
  'effectiveConcurrency',
  'contractsUnique',
  'contractsDiscardedByConflict',
  'duplicates',
  'bodyBytes',
  'summaryBytes',
  'snapshotBytes',
  'snapshotSchemaVersion',
  'canonicalizationVersion',
  'baselineBytesRead',
  'baselineBytesRetained',
  'baselineByteLimit',
  'state_done',
  'state_absent',
  'state_denied',
  'state_http_error',
  'state_scope_denied',
  'state_redirect_limit',
  'state_invalid_content_type',
  'state_response_too_large',
  'state_invalid_json',
  'state_invalid_yaml',
  'state_not_openapi',
  'state_invalid_contract',
  'state_timeout',
  'state_request_failed',
  'state_external_ref_unresolved',
  'state_internal_ref_unresolved',
  'state_reference_scan_incomplete',
  'state_duplicate_contract',
  'state_duplicate_contract_conflict',
  'state_collection_byte_limit',
  'state_snapshot_byte_limit',
  'state_contract_limit',
  'state_invalid_origin',
  'state_origin_limit',
  'state_deadline_aborted',
  'state_module_deadline_exhausted',
  'state_materialization_deadline_exhausted',
  'state_baseline_storage_degraded',
  'state_baseline_byte_limit',
  'state_unsupported_schema_dialect',
  'state_unknown',
]);

const SAFE_BOOLEAN_OUTCOME_METRIC_KEYS = new Set([
  'deadlineReached',
  'complete',
  'baselineByteLimitReached',
]);

const MAX_SAFE_OUTCOME_METRICS = 64;

function safeNumericOutcomeMetadata(result) {
  const metadata = {};
  for (const key of ['attempted', 'resultCount']) {
    const value = result?.[key];
    if (Number.isSafeInteger(value) && value >= 0) metadata[key] = value;
  }
  const metrics = {};
  const rawMetrics = result?.outcomeMetrics;
  const safeKeys = rawMetrics && typeof rawMetrics === 'object' && !Array.isArray(rawMetrics)
    ? Object.keys(rawMetrics)
      .filter((key) => SAFE_NUMERIC_OUTCOME_METRIC_KEYS.has(key)
        || SAFE_BOOLEAN_OUTCOME_METRIC_KEYS.has(key))
      .slice(0, MAX_SAFE_OUTCOME_METRICS)
    : [];
  for (const key of safeKeys) {
    const rawValue = rawMetrics[key];
    if (SAFE_BOOLEAN_OUTCOME_METRIC_KEYS.has(key)) {
      if (typeof rawValue === 'boolean') metrics[key] = rawValue;
      continue;
    }
    if (Number.isSafeInteger(rawValue) && rawValue >= 0) metrics[key] = rawValue;
  }
  if (Object.keys(metrics).length) metadata.metrics = metrics;
  return metadata;
}

/**
 * Executa um módulo registado se estiver activo em `s.modules`.
 * @returns {boolean} true se o módulo existe no registry e foi despachado
 */
export async function dispatchRegistryModule(s, moduleId) {
  const id = normalizeModuleId(moduleId);
  const entry = getRegistryEntry(id);
  if (!entry?.run) return false;

  const { log, addFinding, modules } = s;

  if (!moduleEnabled(modules, id)) {
    emitTerminalOutcome(s, id, 'skipped');
    return true;
  }

  s.pipe?.(id, 'active');
  try {
    const result = await entry.run(s);
    const rows = Array.isArray(result?.findings) ? result.findings : [];
    for (const f of rows) {
      addFinding(withProvenance(f, id), null);
    }
    if (result?.logOk) {
      log(safePublicText(result.logOk, MAX_LOG_TEXT_CHARS), safeLogLevel(result.logLevel));
    }
    const outcomeMetadata = safeNumericOutcomeMetadata(result);
    if (result?.status === 'timeout') {
      emitTerminalOutcome(s, id, 'timeout', {
        ...outcomeMetadata,
        partial: result?.partial === true || rows.length > 0,
        ...(result?.reason ? { reason: safePublicText(result.reason) } : {}),
      });
    } else if (result?.status === 'skipped') {
      emitTerminalOutcome(s, id, 'skipped', {
        ...outcomeMetadata,
        ...(result?.reason ? { reason: safePublicText(result.reason) } : {}),
      });
    } else {
      emitTerminalOutcome(s, id, 'done', {
        ...outcomeMetadata,
        ...(result?.status === 'partial' ? { partial: true } : {}),
        ...(result?.status === 'partial' && result?.reason
          ? { reason: safePublicText(result.reason) }
          : {}),
      });
    }
  } catch (e) {
    if (isTimeoutError(e)) {
      emitTerminalOutcome(s, id, 'timeout', { error: safePublicText(e?.message || String(e)) });
      throw e;
    }
    if (isAbortLikeError(e, s?.signal)) {
      emitTerminalOutcome(s, id, 'cancelled', { error: safePublicText(e?.message || String(e)) });
      throw e;
    }
    const message = safePublicText(e?.message || String(e));
    log(`${entry.manifest?.name || id}: ${message}`, 'warn');
    emitTerminalOutcome(s, id, 'failed', { error: message });
    // Não emite `done` após falha — outcome real para o Auto/pipeline.
  }
  return true;
}
