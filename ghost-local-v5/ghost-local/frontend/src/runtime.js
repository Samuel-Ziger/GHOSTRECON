export function apiBase(locationObject = window.location) {
  const { protocol, hostname, port } = locationObject;
  if (protocol === 'http:' || protocol === 'https:') {
    return `${protocol}//${hostname}${port ? `:${port}` : ''}`;
  }
  return 'http://127.0.0.1:8000';
}

export async function parseNDJSONStream(reader, onObject) {
  const decoder = new TextDecoder();
  let buffer = '';
  while (true) {
    const { done, value } = await reader.read();
    buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
    const lines = buffer.split('\n');
    buffer = lines.pop() || '';
    for (const raw of lines) {
      const line = raw.trim();
      if (!line) continue;
      try { onObject(JSON.parse(line)); } catch { /* malformed event is isolated */ }
    }
    if (done) {
      const tail = buffer.trim();
      if (tail) {
        try { onObject(JSON.parse(tail)); } catch { /* malformed tail is isolated */ }
      }
      return;
    }
  }
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

export function renderMarkdown(value) {
  const fenced = [];
  const withPlaceholders = String(value ?? '').replace(/```([\w+-]*)\n?([\s\S]*?)```/g, (_all, lang, code) => {
    const index = fenced.push({ lang, raw: String(code).replace(/\n$/, '') }) - 1;
    return `GHOSTCODEBLOCK${index}END`;
  });
  let text = escapeHtml(withPlaceholders);
  text = text.replace(/`([^`\n]+)`/g, '<code>$1</code>');
  text = text.replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>');
  text = text.replace(/\*([^*\n]+)\*/g, '<em>$1</em>');
  text = text.replace(/^###? (.+)$/gm, '<h3>$1</h3>');
  text = text.replace(/^# (.+)$/gm, '<h3 style="font-size:13px;color:var(--amber)">$1</h3>');
  text = text.replace(/^[-•]\s(.+)$/gm, '<li>$1</li>');
  text = text.replace(/^---$/gm, '<hr>');
  text = text.replace(/\n/g, '<br>');
  return text.replace(/GHOSTCODEBLOCK(\d+)END/g, (_all, rawIndex) => {
    const block = fenced[Number(rawIndex)] || { lang: '', raw: '' };
    return `<div class="code-wrap"><button type="button" class="copy-code-btn" data-code="${encodeURIComponent(block.raw)}">COPIAR</button><pre><code class="lang-${escapeHtml(block.lang)}">${escapeHtml(block.raw)}</code></pre></div>`;
  });
}

export function summarizeAutoEvent(event, mode = 'balanced') {
  if (!event || typeof event !== 'object') return '';
  if (event.type === 'auto_meta') return `auto: request ${event.requestRunId || ''} modo=${event.mode || mode}`;
  if (event.type === 'auto_catalog') return `catalogo: ${event.modules?.length || 0} modulos | hex=${event.hexstrike?.installed ? (event.hexstrike.reachable ? 'online' : 'instalado/offline') : 'ausente'}`;
  if (event.type === 'auto_plan') return `plano deterministico: ${event.plan?.modules?.length || 0} modulos`;
  if (event.type === 'auto_step') return `step ${event.step}: ${event.status}`;
  if (event.type === 'auto_evaluation') return `avaliacao: findings=${event.evaluation?.findings || 0} high=${event.evaluation?.highSignals || 0} ok=${event.evaluation?.ok}`;
  if (event.type === 'finding') return `finding: ${event.finding?.type || event.type || '?'} ${event.finding?.value || ''}`.slice(0, 180);
  if (event.type === 'log') return `log: ${event.msg || event.message || ''}`.slice(0, 180);
  if (event.type === 'error') return `erro: ${event.message || event.msg || JSON.stringify(event).slice(0, 120)}`;
  if (event.type === 'done') return 'pipeline: done';
  return `${event.type || 'evento'}: ${JSON.stringify(event).slice(0, 160)}`;
}
