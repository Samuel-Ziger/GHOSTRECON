/**
 * URL do webhook VPS: WORKFLOW_VPS_WEBHOOK_URL tem prioridade (servidor só modo VPS);
 * caso contrário WORKFLOW_WEBHOOK_URL.
 */
export function resolveWebhookUrl() {
  const vps = String(process.env.WORKFLOW_VPS_WEBHOOK_URL || '').trim();
  if (vps) return vps;
  return String(process.env.WORKFLOW_WEBHOOK_URL || '').trim();
}

export async function postWebhook(payload) {
  const url = resolveWebhookUrl();
  if (!url) {
    return {
      ok: false,
      skipped: true,
      reason: 'WORKFLOW_VPS_WEBHOOK_URL e WORKFLOW_WEBHOOK_URL ausentes',
    };
  }

  const bearer = String(process.env.WORKFLOW_WEBHOOK_AUTH_BEARER || '').trim();
  const headers = { 'content-type': 'application/json' };
  if (bearer) headers.authorization = `Bearer ${bearer}`;

  const res = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Webhook HTTP ${res.status}: ${t.slice(0, 500)}`);
  }

  return { ok: true, skipped: false };
}
