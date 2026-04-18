import test from 'node:test';
import assert from 'node:assert/strict';
import { extractSuspiciousHtmlComments } from '../modules/html-surface.js';

test('extractSuspiciousHtmlComments: flag estilo CTF em comentário', () => {
  const html = '<head><!--Solyd{9NewsNews!!!NothingWrongHereVerySecure!!!9}--></head>';
  const h = extractSuspiciousHtmlComments(html);
  assert.equal(h.length, 1);
  assert.match(h[0], /Solyd/i);
});

test('extractSuspiciousHtmlComments: ignora comentários anódinos', () => {
  const html = '<!--[if IE]>x<![endif]--><!-- normal -->';
  assert.equal(extractSuspiciousHtmlComments(html).length, 0);
});
