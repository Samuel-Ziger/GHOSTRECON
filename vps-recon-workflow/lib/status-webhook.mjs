/**
 * Webhook de status independente do webhook principal de findings.
 *
 * Diferenças vs lib/webhook.mjs:
 *  - Usa env separada: WORKFLOW_STATUS_WEBHOOK_URL (não conflita com VPS/WEBHOOK_URL).
 *  - Dispara SEMPRE no fim do ciclo (com ou sem findings novos, com ou sem erros).
 *  - Auto-formata o payload conforme o destino:
 *      * Discord  → embed colorido (verde / cinza / vermelho).
 *      * Slack    → texto simples.
 *      * Outros   → JSON cru com event="cycle_complete".
 *
 * Pensado para um canal de heartbeat/operacional separado do canal de findings.
 */

export function resolveStatusWebhookUrl() {
  return String(process.env.WORKFLOW_STATUS_WEBHOOK_URL || '').trim();
}

function isDiscord(url) {
  return /discord(?:app)?\.com\/api\/webhooks\//i.test(url);
}

function isSlack(url) {
  return /hooks\.slack\.com\//i.test(url);
}

function fmtDuration(ms) {
  if (!Number.isFinite(ms) || ms < 0) return 'n/a';
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  const m = Math.floor(s / 60);
  const rs = Math.round(s - m * 60);
  return `${m}m${rs.toString().padStart(2, '0')}s`;
}

function truncate(s, n) {
  if (!s) return '';
  const str = String(s);
  return str.length <= n ? str : str.slice(0, Math.max(0, n - 1)) + '…';
}

/**
 * Constrói o body conforme o destino. Não faz fetch.
 *
 * @param {string} url
 * @param {{
 *   cycleId: number|string,
 *   targets: string[],
 *   targetsProcessed: number,
 *   modulesCount: number,
 *   newCount: number,
 *   totalCount?: number,
 *   errorsCount: number,
 *   durationMs: number,
 *   summaryPt?: string|null,
 *   playbook?: string|null,
 *   profile?: string|null,
 *   kaliMode?: boolean,
 *   topNew?: Array<{ type?: string, target?: string, value?: string }>,
 *   fatal?: { message: string } | null,
 * }} ctx
 */
export function buildStatusPayload(url, ctx) {
  const {
    cycleId,
    targets,
    targetsProcessed,
    modulesCount,
    newCount,
    totalCount,
    errorsCount,
    durationMs,
    summaryPt,
    playbook,
    profile,
    kaliMode,
    topNew,
    fatal,
  } = ctx;

  if (isDiscord(url)) {
    let color;
    let title;
    if (fatal) {
      color = 0xe74c3c; // vermelho
      title = '⛔ GHOSTRECON — ciclo abortado';
    } else if (errorsCount > 0 && newCount === 0) {
      color = 0xe67e22; // laranja
      title = `⚠️ GHOSTRECON — ciclo concluído com ${errorsCount} erro(s)`;
    } else if (newCount > 0) {
      color = 0x2ecc71; // verde
      title = `🎯 GHOSTRECON — ${newCount} novo(s) finding(s)`;
    } else {
      color = 0x95a5a6; // cinza
      title = '✅ GHOSTRECON — ciclo concluído (sem novidades)';
    }

    const fields = [
      { name: 'Ciclo', value: '`' + String(cycleId) + '`', inline: true },
      { name: 'Alvos', value: String(targetsProcessed), inline: true },
      { name: 'Módulos', value: String(modulesCount), inline: true },
      { name: 'Novos', value: String(newCount), inline: true },
      ...(Number.isFinite(totalCount)
        ? [{ name: 'Total bruto', value: String(totalCount), inline: true }]
        : []),
      { name: 'Duração', value: fmtDuration(durationMs), inline: true },
      { name: 'Erros', value: String(errorsCount || 0), inline: true },
    ];

    if (playbook) fields.push({ name: 'Playbook', value: '`' + playbook + '`', inline: true });
    if (profile) fields.push({ name: 'Perfil', value: '`' + profile + '`', inline: true });
    if (kaliMode != null)
      fields.push({ name: 'Kali Mode', value: kaliMode ? 'on' : 'off', inline: true });

    if (Array.isArray(targets) && targets.length) {
      const list = targets.slice(0, 12).join('\n') +
        (targets.length > 12 ? `\n… +${targets.length - 12} mais` : '');
      fields.push({
        name: `Alvos (${Math.min(targets.length, 12)}/${targets.length})`,
        value: '```\n' + truncate(list, 1000) + '\n```',
      });
    }

    if (newCount > 0 && Array.isArray(topNew) && topNew.length) {
      const lines = topNew.slice(0, 8).map((f) => {
        const t = f?.type || 'finding';
        const tgt = f?.target || f?.targetBucket || '';
        const v = f?.value ? truncate(String(f.value), 80) : '';
        return `• [${t}] ${tgt}${v ? ` → ${v}` : ''}`;
      });
      fields.push({
        name: `Top novos (${Math.min(topNew.length, 8)}/${newCount})`,
        value: '```\n' + truncate(lines.join('\n'), 1000) + '\n```',
      });
    }

    if (summaryPt) {
      fields.push({ name: 'Resumo IA', value: truncate(summaryPt, 1000) });
    }

    if (fatal?.message) {
      fields.push({ name: 'Erro fatal', value: '```\n' + truncate(fatal.message, 1000) + '\n```' });
    }

    return {
      username: 'GHOSTRECON',
      embeds: [
        {
          title,
          color,
          fields,
          timestamp: new Date().toISOString(),
          footer: { text: 'ghostrecon-vps-workflow' },
        },
      ],
    };
  }

  if (isSlack(url)) {
    const head = fatal
      ? `*GHOSTRECON ciclo ${cycleId}*: ⛔ abortado (${truncate(fatal.message, 200)})`
      : `*GHOSTRECON ciclo ${cycleId}*: ${newCount} novo(s) | ${targetsProcessed} alvos | ${modulesCount} módulos${errorsCount ? ` | ⚠️ ${errorsCount} erro(s)` : ''} | ${fmtDuration(durationMs)}`;
    return { text: head };
  }

  return {
    source: 'ghostrecon-vps-workflow',
    event: 'cycle_complete',
    cycle_id: cycleId,
    started_at: ctx.startedAt || null,
    finished_at: new Date().toISOString(),
    duration_ms: durationMs,
    targets_processed: targetsProcessed,
    targets_order: targets,
    modules_count: modulesCount,
    playbook: playbook || null,
    profile: profile || null,
    kali_mode: kaliMode ?? null,
    new_findings_count: newCount,
    total_findings_count: totalCount ?? null,
    errors_count: errorsCount || 0,
    ai_summary_pt: summaryPt || null,
    fatal: fatal || null,
  };
}

/**
 * Envia o status webhook. Nunca lança — devolve { ok, skipped, error }.
 * O ciclo principal nunca deve falhar por causa deste heartbeat.
 *
 * @param {Parameters<typeof buildStatusPayload>[1]} ctx
 */
export async function postStatusWebhook(ctx) {
  const url = resolveStatusWebhookUrl();
  if (!url) {
    return { ok: false, skipped: true, reason: 'WORKFLOW_STATUS_WEBHOOK_URL ausente' };
  }

  let body;
  try {
    body = buildStatusPayload(url, ctx);
  } catch (e) {
    return { ok: false, skipped: false, error: `payload build: ${e?.message || e}` };
  }

  const headers = { 'content-type': 'application/json' };
  const bearer = String(process.env.WORKFLOW_STATUS_WEBHOOK_AUTH_BEARER || '').trim();
  if (bearer) headers.authorization = `Bearer ${bearer}`;

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const t = await res.text().catch(() => '');
      return { ok: false, skipped: false, error: `HTTP ${res.status}: ${t.slice(0, 300)}` };
    }
    return { ok: true, skipped: false };
  } catch (e) {
    return { ok: false, skipped: false, error: String(e?.message || e) };
  }
}
