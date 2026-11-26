import test from 'node:test';
import assert from 'node:assert/strict';
import { apiBase, parseNDJSONStream, renderMarkdown, summarizeAutoEvent } from '../src/runtime.js';

test('apiBase preserva mesma origem HTTP e fallback local para file', () => {
  assert.equal(apiBase({ protocol: 'http:', hostname: '127.0.0.1', port: '8000' }), 'http://127.0.0.1:8000');
  assert.equal(apiBase({ protocol: 'https:', hostname: 'ghost.test', port: '' }), 'https://ghost.test');
  assert.equal(apiBase({ protocol: 'file:', hostname: '', port: '' }), 'http://127.0.0.1:8000');
});

test('parseNDJSONStream recompõe linhas partidas entre chunks e aceita tail', async () => {
  const chunks = [
    new TextEncoder().encode('{"token":"a'),
    new TextEncoder().encode('"}\n{"done":true}'),
  ];
  const reader = {
    async read() {
      return chunks.length ? { done: false, value: chunks.shift() } : { done: true, value: undefined };
    },
  };
  const events = [];
  await parseNDJSONStream(reader, (event) => events.push(event));
  assert.deepEqual(events, [{ token: 'a' }, { done: true }]);
});

test('renderMarkdown escapa HTML do modelo e preserva cópia do código original', () => {
  const html = renderMarkdown('**ok**\n```html\n<img src=x>\n```');
  assert.match(html, /<strong>ok<\/strong>/);
  assert.match(html, /&lt;img src=x&gt;/);
  assert.doesNotMatch(html, /<img src=x>/);
  assert.match(html, new RegExp(encodeURIComponent('<img src=x>')));
});

test('summarizeAutoEvent mantém os eventos determinísticos principais', () => {
  assert.match(summarizeAutoEvent({ type: 'auto_plan', plan: { modules: ['a', 'b'] } }), /2 modulos/);
  assert.match(summarizeAutoEvent({ type: 'auto_evaluation', evaluation: { findings: 4, highSignals: 1, ok: true } }), /findings=4/);
  assert.equal(summarizeAutoEvent({ type: 'done' }), 'pipeline: done');
});
