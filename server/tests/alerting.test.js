/**
 * Alerting — verifica que Discord/Slack/webhook genérico recebem payload correto.
 * Usa transporte injetado para não abrir sockets nem acessar rede.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { postAlert } from '../modules/alerting.mjs';

function createTransport(response = { ok: true, statusCode: 200, body: '{"ok":true}' }) {
  const calls = [];
  return {
    calls,
    postImpl: async (url, body, options) => {
      calls.push({ url, body, options });
      return response;
    },
  };
}

test('alerting: webhook genérico recebe payload JSON bruto', async () => {
  const transport = createTransport();
  const payload = {
    content: 'found stuff',
    target: 'example.com',
    summary: { addedBySeverity: { high: 1 } },
  };
  await postAlert('https://alerts.invalid/generic', payload, transport);
  assert.equal(transport.calls.length, 1);
  assert.equal(transport.calls[0].url, 'https://alerts.invalid/generic');
  assert.deepEqual(transport.calls[0].body, payload);
});

test('alerting: Slack detecta host *.slack.com e envia {text,mrkdwn}', async () => {
  const transport = createTransport();
  const res = await postAlert(
    'https://hooks.slack.com/services/test',
    { content: 'x' },
    transport,
  );
  assert.ok(res.ok);
  assert.deepEqual(transport.calls[0].body, { text: 'x', mrkdwn: true });
});

test('alerting: Discord recebe embed no webhook correto', async () => {
  const transport = createTransport();
  await postAlert(
    'https://discord.com/api/webhooks/test',
    { content: 'hi', target: 'example.com' },
    transport,
  );
  assert.equal(transport.calls[0].url, 'https://discord.com/api/webhooks/test');
  assert.equal(transport.calls[0].body.embeds[0].description, 'hi');
  assert.match(transport.calls[0].body.embeds[0].title, /example\.com/);
});

test('alerting: webhook vazio lança', async () => {
  await assert.rejects(() => postAlert('', { content: 'x' }), /vazio/);
});

test('alerting: non-2xx lança com status code', async () => {
  const transport = createTransport({ ok: false, statusCode: 500, body: 'boom' });
  await assert.rejects(
    () => postAlert('https://alerts.invalid/hook', { content: 'x' }, transport),
    /HTTP 500/,
  );
});

test('alerting: falha de transporte é propagada', async () => {
  const transport = {
    postImpl: async () => {
      throw new Error('webhook timeout');
    },
  };
  await assert.rejects(
    () => postAlert('https://alerts.invalid/x', { content: 'x' }, transport),
    /timeout/,
  );
});
