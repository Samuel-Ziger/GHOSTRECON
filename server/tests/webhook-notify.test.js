import test from 'node:test';
import assert from 'node:assert/strict';

import { buildDiscordReconSummaryContent } from '../modules/webhook-notify.js';

test('Discord inclui amostra redigida dos principais findings', () => {
  const content = buildDiscordReconSummaryContent({
    target: 'lab.test',
    runId: 7,
    stats: { high: 1, subs: 2, endpoints: 3, params: 0, secrets: 0, dorks: 0 },
    highCount: 1,
    highFindings: [{
      type: 'security',
      prio: 'high',
      score: 91,
      value: 'FTP anonymous login enabled @ ftp.lab.test:21 @everyone',
      meta: 'Authorization: Bearer should-not-leak',
    }],
  });
  assert.match(content, /Principais achados/);
  assert.match(content, /FTP anonymous login enabled/);
  assert.doesNotMatch(content, /@everyone/);
  assert.doesNotMatch(content, /should-not-leak/);
  assert.ok(content.length <= 1901);
});
