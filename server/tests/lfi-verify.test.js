import test from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyLfiResponse,
  decodeHtmlNumericEntitiesForLfi,
  LFI_DATA_PLAIN_MARKER,
  LFI_DATA_B64_INNER,
  LFI_PHP_INPUT_POST_MARKER,
} from '../modules/verify.js';

test('classifyLfiResponse: /etc/passwd direct', () => {
  const r = classifyLfiResponse('root:x:0:0:root:/root:/bin/bash\n', '/x');
  assert.equal(r.classification, 'confirmed');
  assert.equal(r.marker, 'unix-passwd-sig');
});

test('classifyLfiResponse: win.ini', () => {
  const r = classifyLfiResponse('[fonts]\n', 'x');
  assert.equal(r.classification, 'confirmed');
});

test('classifyLfiResponse: php filter b64 (decoded passwd)', () => {
  const b64 = Buffer.from('root:x:0:0:root:/root:/bin/bash\n', 'utf8').toString('base64');
  const r = classifyLfiResponse(`<pre>${b64}</pre>`, 'php://filter/convert.base64-encode/resource=x');
  assert.equal(r.classification, 'confirmed');
  assert.equal(r.marker, 'php-filter-b64-passwd');
});

test('classifyLfiResponse: expect id', () => {
  const r = classifyLfiResponse('uid=0(root) gid=0(root)', 'expect://id');
  assert.equal(r.classification, 'confirmed');
});

test('classifyLfiResponse: RFI loopback robots', () => {
  const body = 'User-agent: *\nDisallow: /\n';
  const r = classifyLfiResponse(body, 'http://127.0.0.1/robots.txt');
  assert.equal(r.classification, 'probable');
});

test('classifyLfiResponse: open_basedir / wrapper error', () => {
  const r = classifyLfiResponse('failed to open stream: open_basedir restriction in effect', 'x');
  assert.equal(r.classification, 'probable');
});

test('classifyLfiResponse: data plain marker', () => {
  const r = classifyLfiResponse(`ok ${LFI_DATA_PLAIN_MARKER} tail`, 'data://text/plain,x');
  assert.equal(r.classification, 'probable');
  assert.equal(r.marker, 'data-plain-reflect');
});

test('classifyLfiResponse: data b64 inner', () => {
  const r = classifyLfiResponse(`prefix ${LFI_DATA_B64_INNER}`, 'data://text/plain;base64,xx');
  assert.equal(r.classification, 'probable');
  assert.equal(r.marker, 'data-b64-inner-reflect');
});

test('classifyLfiResponse: proc self fd leak', () => {
  const leak = 'HTTP_HOST=127.0.0.1\nREQUEST_METHOD=GET\n';
  const r = classifyLfiResponse(leak, '../../../../../../../proc/self/fd/0');
  assert.equal(r.classification, 'probable');
  assert.equal(r.marker, 'proc-fd-http-meta-leak');
});

test('classifyLfiResponse: php input post body reflected', () => {
  const body = `echo ${LFI_PHP_INPUT_POST_MARKER};`;
  const r = classifyLfiResponse(body, 'php://input', { postBodyMarker: LFI_PHP_INPUT_POST_MARKER });
  assert.equal(r.classification, 'probable');
  assert.equal(r.marker, 'php-input-body-reflected');
});

test('decodeHtmlNumericEntitiesForLfi: passwd com : codificado', () => {
  const raw = '&#114;&#111;&#111;&#116;:x:0:0:root:/root:/bin/bash';
  const dec = decodeHtmlNumericEntitiesForLfi(raw);
  const r = classifyLfiResponse(dec, '/x');
  assert.equal(r.classification, 'confirmed');
});
