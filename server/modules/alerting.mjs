/**
 * Alerting — enviar notificações para Discord/Slack/webhook genérico.
 *
 * Detecta Discord (webhooks com host discord.com/discordapp.com) e envia
 * embed nativo. Slack usa "text". Outros hosts recebem JSON puro.
 */

import http from 'node:http';
import https from 'node:https';

function isDiscord(url) {
  try {
    const h = new URL(url).hostname.toLowerCase();
    return h === 'discord.com' || h === 'discordapp.com';
  } catch {
    return false;
  }
}
function isSlack(url) {
  try {
    const h = new URL(url).hostname.toLowerCase();
    return h.endsWith('slack.com');
  } catch {
    return false;
  }
}

function postRaw(urlStr, body, { timeoutMs = 10_000, headers = {} } = {}) {
  const url = new URL(urlStr);
  const mod = url.protocol === 'https:' ? https : http;
  const payload = Buffer.from(typeof body === 'string' ? body : JSON.stringify(body), 'utf8');
  return new Promise((resolve, reject) => {
    const req = mod.request(
      {
        method: 'POST',
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        headers: {
          'content-type': 'application/json; charset=utf-8',
          'content-length': String(payload.length),
          'user-agent': 'GHOSTRECON/1.0 alerting',
          ...headers,
        },
      },
      (res) => {
        let buf = '';
        res.setEncoding('utf8');
        res.on('data', (c) => (buf += c));
        res.on('end', () =>
          resolve({
            ok: res.statusCode >= 200 && res.statusCode < 300,
            statusCode: res.statusCode,
            body: buf.slice(0, 500),
          }),
        );
        res.on('error', reject);
      },
    );
    req.setTimeout(timeoutMs, () => req.destroy(new Error(`webhook timeout > ${timeoutMs}ms`)));
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

/**
 * Envia `payload` (texto Markdown + metadata) para o webhook apropriado.
 * `payload.content` → texto curto preferido por todos.
 */
export async function postAlert(webhookUrl, payload) {
  const u = String(webhookUrl || '').trim();
  if (!u) throw new Error('webhook vazio');
  const text = payload?.content || 'GHOSTRECON alert';

  if (isDiscord(u)) {
    const embed = {
      title: `GHOSTRECON — ${payload?.target || 'alvo desconhecido'}`,
      description: text.slice(0, 3800),
      color: 0xff4d4f,
      fields: buildDiscordFields(payload?.summary),
      timestamp: new Date().toISOString(),
      footer: { text: 'ghostrecon schedule' },
    };
    const res = await postRaw(u, { embeds: [embed] });
    if (!res.ok) throw new Error(`Discord HTTP ${res.statusCode}: ${res.body}`);
    return res;
  }

  if (isSlack(u)) {
    const res = await postRaw(u, { text: text.slice(0, 3800), mrkdwn: true });
    if (!res.ok) throw new Error(`Slack HTTP ${res.statusCode}: ${res.body}`);
    return res;
  }

  const res = await postRaw(u, payload);
  if (!res.ok) throw new Error(`webhook HTTP ${res.statusCode}: ${res.body}`);
  return res;
}

function buildDiscordFields(summary) {
  if (!summary) return [];
  const fields = [];
  const sev = summary.addedBySeverity || {};
  fields.push({
    name: 'Severidades',
    value: `high=${sev.high ?? 0} · medium=${sev.medium ?? 0} · low=${sev.low ?? 0}`,
    inline: true,
  });
  if (summary.newHosts?.length) {
    fields.push({
      name: `Novos hosts (${summary.newHosts.length})`,
      value: summary.newHosts.slice(0, 6).map((h) => `\`${h}\``).join('\n').slice(0, 1000),
      inline: false,
    });
  }
  if (summary.notableAdded?.length) {
    const bullets = summary.notableAdded
      .slice(0, 6)
      .map((f) => `• [${(f.severity || 'n/a').toUpperCase()}] ${f.title || f.category || '?'}`)
      .join('\n')
      .slice(0, 1000);
    fields.push({ name: 'Notáveis', value: bullets, inline: false });
  }
  return fields;
}
