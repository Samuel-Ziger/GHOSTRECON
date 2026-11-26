import React, { useEffect, useMemo, useRef, useState } from 'react';
import { apiBase, parseNDJSONStream, renderMarkdown, summarizeAutoEvent } from './runtime.js';

const API = apiBase();

const PARAM_DEFS = [
  { k: 'temperature', l: 'TEMPERATURE', min: 0, max: 2, step: 0.05 },
  { k: 'top_p', l: 'TOP-P', min: 0, max: 1, step: 0.05 },
  { k: 'top_k', l: 'TOP-K', min: 0, max: 200, step: 1 },
  { k: 'min_p', l: 'MIN-P', min: 0, max: 1, step: 0.01 },
  { k: 'typical_p', l: 'TYPICAL-P', min: 0, max: 1, step: 0.05 },
  { k: 'repeat_penalty', l: 'REPEAT PENALTY', min: 0.5, max: 2, step: 0.05 },
  { k: 'repeat_last_n', l: 'REPEAT LAST-N', min: 0, max: 512, step: 8 },
  { k: 'presence_penalty', l: 'PRESENCE', min: -2, max: 2, step: 0.1 },
  { k: 'frequency_penalty', l: 'FREQUENCY', min: -2, max: 2, step: 0.1 },
  { k: 'num_ctx', l: 'CONTEXT (tokens)', min: 512, max: 32768, step: 512 },
  { k: 'num_predict', l: 'MAX PREDICT', min: 128, max: 8192, step: 128 },
  { k: 'num_keep', l: 'NUM KEEP', min: 0, max: 512, step: 8 },
  { k: 'mirostat', l: 'MIROSTAT (0/1/2)', min: 0, max: 2, step: 1 },
  { k: 'mirostat_tau', l: 'MIRO TAU', min: 0, max: 10, step: 0.5 },
  { k: 'mirostat_eta', l: 'MIRO ETA', min: 0, max: 1, step: 0.05 },
  { k: 'tfs_z', l: 'TFS-Z', min: 0, max: 1, step: 0.05 },
  { k: 'num_batch', l: 'BATCH SIZE', min: 64, max: 2048, step: 64 },
];

const BOOL_PARAM_DEFS = [
  { k: 'f16_kv', l: 'F16-KV' }, { k: 'use_mmap', l: 'MMAP' },
  { k: 'use_mlock', l: 'MLOCK' }, { k: 'low_vram', l: 'LOW-VRAM' },
  { k: 'penalize_newline', l: 'PENALIZE NL' },
];

const INITIAL_PARAMS = {
  temperature: 0.7, top_p: 0.9, top_k: 40, min_p: 0, typical_p: 1,
  repeat_penalty: 1.1, repeat_last_n: 64, presence_penalty: 0, frequency_penalty: 0,
  num_ctx: 8192, num_predict: 2048, num_keep: 0,
  mirostat: 0, mirostat_tau: 5, mirostat_eta: 0.1,
  tfs_z: 1, seed: -1, num_batch: 512,
  penalize_newline: false, low_vram: false, f16_kv: true,
  use_mmap: true, use_mlock: false,
};

const QUICK_CATEGORIES = [
  { k: 'pentest', l: 'PENTEST' }, { k: 'recon', l: 'RECON' },
  { k: 'exploit', l: 'EXPLOIT' }, { k: 'code', l: 'CÓDIGO' },
  { k: 'ghostrecon', l: 'GHOSTRECON' }, { k: 'ctf', l: 'CTF' },
];

const MEMORY_CATEGORIES = [
  { v: 'pentest', l: 'PENTEST' }, { v: 'exploit', l: 'EXPLOIT' },
  { v: 'recon', l: 'RECON' }, { v: 'tool', l: 'FERRAMENTA' },
  { v: 'code', l: 'CÓDIGO' }, { v: 'methodology', l: 'METODOLOGIA' },
  { v: 'ctf', l: 'CTF' }, { v: 'personal', l: 'PESSOAL' },
  { v: 'general', l: 'GERAL' },
];

const CODE_SCAN_MODES = [
  ['all', 'COMPLETO'], ['sqli', 'SQL INJECTION'], ['auth', 'AUTH/AUTHZ'],
  ['secrets', 'SECRETS'], ['injection', 'INJEÇÕES'], ['crypto', 'CRYPTO'],
  ['logic', 'LÓGICA'], ['memory', 'MEMÓRIA (C/C++)'], ['rop', 'GADGETS ROP'],
  ['shellcode', 'SHELLCODE'], ['race', 'RACE CONDITIONS'], ['priv', 'PRIVESC'],
].map(([v, l]) => ({ v, l }));

const ASM_MODES = [
  ['rop', 'GADGETS ROP/JOP'], ['shellcode', 'SHELLCODE'],
  ['all', 'ANÁLISE COMPLETA'], ['priv', 'RING0/PRIVESC'],
  ['race', 'RACE CONDITIONS'],
].map(([v, l]) => ({ v, l }));

const AUTO_MODES = [
  { v: 'quick', l: 'RÁPIDO' }, { v: 'balanced', l: 'BALANCEADO' },
  { v: 'deep', l: 'PROFUNDO' },
];

async function readJson(response) {
  const text = await response.text();
  let body = {};
  try { body = text ? JSON.parse(text) : {}; } catch { body = { raw: text }; }
  if (!response.ok) {
    const detail = body?.detail ?? body?.error ?? body?.raw ?? `HTTP ${response.status}`;
    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
  }
  return body;
}

function Markdown({ value, className = '' }) {
  const onClick = async (event) => {
    const button = event.target.closest?.('.copy-code-btn');
    if (!button) return;
    try {
      await navigator.clipboard.writeText(decodeURIComponent(button.dataset.code || ''));
      const previous = button.textContent;
      button.textContent = 'COPIADO';
      setTimeout(() => { button.textContent = previous || 'COPIAR'; }, 1200);
    } catch {
      button.textContent = 'ERRO';
      setTimeout(() => { button.textContent = 'COPIAR'; }, 1200);
    }
  };
  return <div className={className} onClick={onClick} dangerouslySetInnerHTML={{ __html: renderMarkdown(value) }} />;
}

export default function App() {
  const [tab, setTab] = useState('chat');
  const [grTab, setGrTab] = useState('runs');
  const [model, setModel] = useState('deepseek-coder-v2:16b');
  const [memoryK, setMemoryK] = useState(6);
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState([]);
  const [streaming, setStreaming] = useState(false);
  const [streamBuffer, setStreamBuffer] = useState('');
  const [health, setHealth] = useState({ ghost: 'offline', ollama: 'offline', hexstrike: 'offline', runs: 0 });
  const [stats, setStats] = useState({});
  const [params, setParams] = useState(INITIAL_PARAMS);
  const [modelInstall, setModelInstall] = useState({ list: '', running: false, last: '' });
  const [sessions, setSessions] = useState([]);
  const [currentSession, setCurrentSession] = useState('default');
  const [quickCategory, setQuickCategory] = useState('pentest');
  const [quickPrompts, setQuickPrompts] = useState({});
  const [notice, setNotice] = useState(null);
  const [allMemory, setAllMemory] = useState([]);
  const [memoryCategories, setMemoryCategories] = useState([]);
  const [memorySearch, setMemorySearch] = useState('');
  const [memoryCategory, setMemoryCategory] = useState('all');
  const [batchJson, setBatchJson] = useState('');
  const [teachForm, setTeachForm] = useState({ topic: '', content: '', cat: 'pentest', tags: '' });
  const [runs, setRuns] = useState([]);
  const [selectedRunId, setSelectedRunId] = useState(null);
  const [runFindings, setRunFindings] = useState([]);
  const [runDomain, setRunDomain] = useState('');
  const [grAnalyzing, setGrAnalyzing] = useState(false);
  const [ghostRecon, setGhostRecon] = useState({ dbPath: '', runJson: '', ndjson: '', result: '', analyzeRunId: '', mode: 'full', analysis: '' });
  const [auto, setAuto] = useState({ showModal: false, running: false, domain: '', mode: 'balanced', includeHexstrike: true, includeDeepPassive: false, events: [], lastPlan: null, lastEvaluation: null });
  const [hex, setHex] = useState({ base: '', reachable: false, err: '', out: '', lastPath: '', busy: false, target: '', command: '', relayPath: '/api/intelligence/analyze-target', relayJson: '{"target":"example.com","analysis_type":"comprehensive"}', healthSummary: '', loadingH: false });
  const [codeScan, setCodeScan] = useState({ path: '', file: '', exts: '', focus: 'all', llm: true, learn: true, scanning: false, findings: [], summary: null, filesScanned: 0, langs: {}, llmOutput: '', snippetMode: false, snippetCode: '', snippetLang: 'python', disasmMode: false, disasmCode: '', disasmCtx: '', arch: 'x86_64', asmFocus: 'rop' });

  const inputRef = useRef(null);
  const bottomRef = useRef(null);
  const chatAbortRef = useRef(null);
  const scanAbortRef = useRef(null);
  const messagesRef = useRef(messages);
  const streamBufferRef = useRef(streamBuffer);
  const noticeTimerRef = useRef(null);

  useEffect(() => { messagesRef.current = messages; }, [messages]);
  useEffect(() => { streamBufferRef.current = streamBuffer; }, [streamBuffer]);

  const patch = (setter) => (values) => setter((current) => ({ ...current, ...values }));
  const patchInstall = patch(setModelInstall);
  const patchGr = patch(setGhostRecon);
  const patchAuto = patch(setAuto);
  const patchHex = patch(setHex);
  const patchCodeScan = patch(setCodeScan);

  const toast = (message, type = 'ok') => {
    clearTimeout(noticeTimerRef.current);
    setNotice({ message, type });
    noticeTimerRef.current = setTimeout(() => setNotice(null), 3000);
  };

  const scrollBottom = () => requestAnimationFrame(() => bottomRef.current?.scrollIntoView({ behavior: 'smooth' }));

  const loadStats = async () => {
    try { setStats(await readJson(await fetch(`${API}/stats`))); } catch { /* health polling remains quiet */ }
  };
  const checkHealth = async () => {
    try {
      const data = await readJson(await fetch(`${API}/health`, { signal: AbortSignal.timeout(3000) }));
      setHealth({ ...data, runs: data.runs || 0, hexstrike: data.hexstrike || 'offline' });
    } catch {
      setHealth({ ghost: 'offline', ollama: 'offline', hexstrike: 'offline', runs: 0 });
    }
  };
  const loadSessions = async () => {
    try { setSessions(await readJson(await fetch(`${API}/sessions`))); } catch { /* offline is shown by health */ }
  };
  const loadQuickPrompts = async () => {
    try { setQuickPrompts(await readJson(await fetch(`${API}/quickprompts`))); } catch { /* optional */ }
  };
  const loadRuns = async () => {
    try { setRuns(await readJson(await fetch(`${API}/ghostrecon/runs`))); } catch { /* optional */ }
  };
  const loadHexStatus = async () => {
    patchHex({ err: '' });
    try {
      const data = await readJson(await fetch(`${API}/hexstrike/status`));
      patchHex({ base: data.base_url || '', reachable: Boolean(data.reachable) });
    } catch (error) {
      patchHex({ err: String(error.message || error), reachable: false });
    }
  };

  useEffect(() => {
    void checkHealth(); void loadStats(); void loadSessions(); void loadQuickPrompts(); void loadRuns(); void loadHexStatus();
    const healthTimer = setInterval(checkHealth, 8000);
    const statsTimer = setInterval(loadStats, 25000);
    return () => {
      clearInterval(healthTimer); clearInterval(statsTimer); clearTimeout(noticeTimerRef.current);
      chatAbortRef.current?.abort(); scanAbortRef.current?.abort();
    };
  }, []);

  const send = async () => {
    const text = input.trim();
    if (!text || streaming) return;
    const history = messagesRef.current.map(({ role, content }) => ({ role, content }));
    const nextMessages = [...messagesRef.current, { role: 'user', content: text }];
    messagesRef.current = nextMessages;
    setMessages(nextMessages);
    setInput('');
    if (inputRef.current) inputRef.current.style.height = 'auto';
    setStreaming(true); setStreamBuffer(''); streamBufferRef.current = '';
    scrollBottom();
    const controller = new AbortController();
    chatAbortRef.current = controller;
    try {
      const response = await fetch(`${API}/chat/stream`, {
        method: 'POST', signal: controller.signal, headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: text, model, history, params, session_id: currentSession, memory_k: memoryK }),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}: ${(await response.text()).slice(0, 280) || response.statusText}`);
      if (!response.body) throw new Error('stream NDJSON indisponível');
      let full = ''; let meta = {};
      await parseNDJSONStream(response.body.getReader(), (event) => {
        if (event.token) {
          full += event.token; streamBufferRef.current = full; setStreamBuffer(full); scrollBottom();
        }
        if (event.done) {
          if (typeof event.full === 'string' && event.full.length) full = event.full;
          meta = event; streamBufferRef.current = full; setStreamBuffer(full);
        }
      });
      setMessages((current) => [...current, { role: 'assistant', content: full || streamBufferRef.current || '[resposta vazia — confira Ollama e o modelo]', fb: null, mem: meta.memory_used || 0, tok: meta.eval_count || 0, ms: meta.total_duration || 0 }]);
    } catch (error) {
      if (error.name !== 'AbortError') {
        setMessages((current) => [...current, { role: 'assistant', content: `**[ERRO]** \`${error.message}\`\n\nVerifique:\n- \`cd backend && uvicorn main:app --reload\`\n- \`ollama serve\``, fb: null, mem: 0, tok: 0, ms: 0 }]);
      }
    } finally {
      setStreaming(false); setStreamBuffer(''); streamBufferRef.current = ''; chatAbortRef.current = null;
      scrollBottom(); inputRef.current?.focus();
    }
  };

  const stopStream = () => {
    chatAbortRef.current?.abort();
    const partial = streamBufferRef.current;
    if (partial) setMessages((current) => [...current, { role: 'assistant', content: `${partial}\n\n*[interrompido]*`, fb: null, mem: 0, tok: 0, ms: 0 }]);
    setStreaming(false); setStreamBuffer(''); streamBufferRef.current = '';
  };

  const feedback = async (index, good) => {
    const message = messagesRef.current[index];
    const question = messagesRef.current[index - 1]?.content || '';
    const correction = good ? undefined : window.prompt('Correção?');
    setMessages((current) => current.map((item, i) => i === index ? { ...item, fb: good ? 'g' : 'b' } : item));
    await fetch(`${API}/memory/feedback`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ question, answer: message.content, rating: good ? 5 : 2, correction, session_id: currentSession }) });
    toast(good ? '✓ APRENDIDO' : '✗ Registrado', good ? 'ok' : 'warn');
    if (good) void loadStats();
  };

  const saveSession = async () => {
    if (!messagesRef.current.length) return;
    const title = messagesRef.current[0]?.content?.slice(0, 50) || 'Sessão';
    await readJson(await fetch(`${API}/sessions/save`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ session_id: currentSession, title, model, messages: messagesRef.current.map(({ role, content }) => ({ role, content })), params }) }));
    toast('💾 Sessão salva'); void loadSessions();
  };
  const loadSession = async (id) => {
    const session = await readJson(await fetch(`${API}/sessions/${id}`));
    setCurrentSession(id);
    setMessages((session.messages || []).map((message) => ({ ...message, fb: null, mem: 0, tok: 0, ms: 0 })));
    setModel(session.model || model);
    if (session.params) setParams((current) => ({ ...current, ...session.params }));
    setTab('chat'); scrollBottom();
  };
  const newSession = () => { setCurrentSession(`sess_${Date.now()}`); setMessages([]); };
  const deleteSession = async (id) => {
    await fetch(`${API}/sessions/${id}`, { method: 'DELETE' });
    void loadSessions(); if (currentSession === id) newSession();
  };

  const loadAllMemory = async () => {
    try {
      const memory = await readJson(await fetch(`${API}/memory/all?limit=600`));
      setAllMemory(memory.items || []);
      setMemoryCategories(await readJson(await fetch(`${API}/memory/categories`)));
    } catch { /* optional while offline */ }
  };
  const filteredMemory = useMemo(() => allMemory.filter((item) => {
    if (memoryCategory !== 'all' && item.category !== memoryCategory) return false;
    if (!memorySearch) return true;
    const query = memorySearch.toLowerCase();
    return String(item.topic || '').toLowerCase().includes(query) || String(item.content || '').toLowerCase().includes(query);
  }), [allMemory, memoryCategory, memorySearch]);
  const deleteMemory = async (id) => {
    await fetch(`${API}/memory/${id}`, { method: 'DELETE' });
    setAllMemory((current) => current.filter((item) => item.id !== id));
    toast('✕ Removido'); void loadStats();
  };

  const teach = async () => {
    const tags = teachForm.tags.split(',').map((tag) => tag.trim()).filter(Boolean);
    const result = await readJson(await fetch(`${API}/memory/teach`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ topic: teachForm.topic, content: teachForm.content, category: teachForm.cat, tags }) }));
    toast(`⊕ ${result.topic}`); setTeachForm((current) => ({ ...current, topic: '', content: '', tags: '' })); void loadStats();
  };
  const batchTeach = async () => {
    try {
      const items = JSON.parse(batchJson);
      const result = await readJson(await fetch(`${API}/memory/teach/bulk`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(items) }));
      toast(`⊕ ${result.count} importadas`); setBatchJson(''); void loadStats();
    } catch (error) { toast(`JSON inválido: ${error.message}`, 'err'); }
  };

  const exportMemory = async () => {
    const data = await readJson(await fetch(`${API}/memory/export`));
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = `ghost_mem_${new Date().toISOString().split('T')[0]}.json`; anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 0); toast('↓ Exportado');
  };

  const installModels = async () => {
    patchInstall({ running: true, last: '' });
    try {
      const models = modelInstall.list.trim() ? modelInstall.list.split(',').map((entry) => entry.trim()).filter(Boolean) : [model];
      const result = await readJson(await fetch(`${API}/models/install`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ models }) }));
      const lines = [`Solicitados: ${result.requested} | OK: ${result.installed} | Falhas: ${result.failed}`, ...(result.results || []).map((entry) => `${entry.ok ? '✓' : '✗'} ${entry.model}`)];
      patchInstall({ list: '', last: lines.join('\n') }); toast(`Modelos: ${result.installed} instalado(s)`);
    } catch (error) {
      patchInstall({ last: `Erro: ${String(error.message || error)}` }); toast(`Erro install: ${String(error.message || error)}`, 'err');
    } finally { patchInstall({ running: false }); }
  };

  const selectRun = async (run) => {
    setSelectedRunId(run.id); setRunDomain(run.domain || '');
    try {
      const result = await readJson(await fetch(`${API}/ghostrecon/findings/${run.id}`));
      setRunFindings(result.findings || []);
    } catch { setRunFindings([]); }
    setGrTab('runs');
  };
  const ingestSqlite = async () => {
    if (!ghostRecon.dbPath) return toast('Informe o caminho do SQLite', 'warn');
    try {
      const result = await readJson(await fetch(`${API}/ghostrecon/ingest/sqlite`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ db_path: ghostRecon.dbPath }) }));
      patchGr({ result: `✓ SQLite: ${result.runs} runs, ${result.findings} findings, ${result.manual_validations} validações` });
      toast('✓ SQLite ingerido'); void loadRuns(); void loadStats();
    } catch (error) { toast(error.message, 'err'); }
  };
  const ingestRun = async () => {
    if (!ghostRecon.runJson.trim()) return toast('JSON vazio', 'warn');
    try {
      const body = JSON.parse(ghostRecon.runJson);
      const result = await readJson(await fetch(`${API}/ghostrecon/ingest/run`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }));
      patchGr({ result: `✓ Run ${result.run_id?.slice(0, 8)}: ${result.findings} findings` });
      toast('✓ Run ingerido'); void loadRuns(); void loadStats();
    } catch (error) { toast(error.message, 'err'); }
  };
  const ingestNdjson = async () => {
    if (!ghostRecon.ndjson.trim()) return toast('NDJSON vazio', 'warn');
    try {
      const result = await readJson(await fetch(`${API}/ghostrecon/ingest/ndjson`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: ghostRecon.ndjson }));
      patchGr({ result: `✓ NDJSON: ${result.findings} findings, ${result.logs} logs` });
      toast('✓ NDJSON processado'); void loadStats();
    } catch (error) { toast(error.message, 'err'); }
  };
  const analyzeRun = async () => {
    if (!ghostRecon.analyzeRunId) return;
    setGrAnalyzing(true); patchGr({ analysis: '' });
    try {
      const response = await fetch(`${API}/ghostrecon/analyze`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ run_id: ghostRecon.analyzeRunId, mode: ghostRecon.mode, model, params }) });
      if (!response.ok) throw new Error(`HTTP ${response.status}: ${(await response.text()).slice(0, 400)}`);
      if (!response.body) throw new Error('stream NDJSON indisponível');
      let full = '';
      await parseNDJSONStream(response.body.getReader(), (event) => {
        if (event.token) { full += event.token; patchGr({ analysis: full }); }
      });
    } catch (error) { toast(error.message, 'err'); }
    finally { setGrAnalyzing(false); }
  };

  const startAutoRecon = async () => {
    if (!auto.domain.trim()) return toast('Informe o alvo autorizado', 'warn');
    const mode = auto.mode;
    patchAuto({ running: true, showModal: false, events: [], lastPlan: null, lastEvaluation: null });
    let lastEvaluation = null;
    try {
      const response = await fetch(`${API}/ghostrecon/auto/stream`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: auto.domain.trim(), mode, includeHexstrike: auto.includeHexstrike, includeDeepPassive: auto.includeDeepPassive }),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}: ${(await response.text()).slice(0, 500)}`);
      if (!response.body) throw new Error('stream NDJSON indisponível');
      await parseNDJSONStream(response.body.getReader(), (event) => {
        if (event.type === 'auto_plan') patchAuto({ lastPlan: event.plan });
        if (event.type === 'auto_evaluation') { lastEvaluation = event.evaluation; patchAuto({ lastEvaluation }); }
        const line = summarizeAutoEvent(event, mode);
        if (line) setAuto((current) => ({ ...current, events: [...current.events, line].slice(-220) }));
      });
      toast(`AUTO finalizado: ${lastEvaluation?.findings || 0} findings`); void loadRuns(); void loadStats();
    } catch (error) {
      setAuto((current) => ({ ...current, events: [...current.events, `erro: ${String(error.message || error)}`].slice(-220) }));
      toast(String(error.message || error), 'err');
    } finally { patchAuto({ running: false }); }
  };

  const hexRelayRequest = async (relayPath, payload, timeout = 120) => {
    patchHex({ busy: true, err: '' });
    try {
      const result = await readJson(await fetch(`${API}/hexstrike/relay`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path: relayPath, payload, timeout }) }));
      patchHex({ lastPath: relayPath, out: typeof result === 'object' ? JSON.stringify(result, null, 2) : String(result) });
      return result;
    } catch (error) {
      patchHex({ err: String(error.message || error).slice(0, 800), out: '' });
      return null;
    } finally { patchHex({ busy: false }); }
  };
  const loadHexHealth = async () => {
    patchHex({ loadingH: true, healthSummary: '', err: '' });
    try {
      const response = await fetch(`${API}/hexstrike/health`, { signal: AbortSignal.timeout(120000) });
      const text = await response.text();
      if (!response.ok) throw new Error(`HTTP ${response.status}: ${text.slice(0, 800)}`);
      let output = text;
      try { output = JSON.stringify(JSON.parse(text), null, 2); } catch { /* keep text */ }
      patchHex({ healthSummary: output.slice(0, 120000) });
    } catch (error) { patchHex({ err: String(error.message || error) }); }
    finally { patchHex({ loadingH: false }); }
  };
  const relayHexJson = async () => {
    try { await hexRelayRequest(hex.relayPath.trim(), JSON.parse(hex.relayJson || '{}'), 180); }
    catch { toast('JSON inválido no payload', 'err'); }
  };
  const injectHexChat = () => {
    if (!hex.out) return;
    setInput(`[HexStrike] ${hex.lastPath}\n\n\`\`\`json\n${hex.out.slice(0, 14000)}\n\`\`\`\n\nResume e interpreta como pentester (âmbito autorizado).`);
    setTab('chat'); toast('Texto colocado no input — envia no chat'); requestAnimationFrame(() => inputRef.current?.focus());
  };

  const scanRepo = async () => {
    if (!codeScan.path.trim()) return;
    patchCodeScan({ scanning: true, findings: [], llmOutput: '', summary: null, filesScanned: 0, langs: {} });
    const controller = new AbortController(); scanAbortRef.current = controller;
    const extensions = codeScan.exts.trim() ? codeScan.exts.trim().split(/\s+/) : [];
    let findingCount = 0; let fileCount = 0;
    try {
      const response = await fetch(`${API}/codescan/repo`, {
        method: 'POST', signal: controller.signal, headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_path: codeScan.path, focus: codeScan.focus, model, params, include_exts: extensions, target_file: codeScan.file || null, llm_review: codeScan.llm, learn: codeScan.learn }),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}: ${(await response.text()).slice(0, 400)}`);
      if (!response.body) throw new Error('stream NDJSON indisponível');
      await parseNDJSONStream(response.body.getReader(), (event) => {
        if (event.type === 'static' && event.data) {
          const findings = event.data.static_findings || [];
          findingCount = findings.length; fileCount = event.data.files_scanned || 0;
          patchCodeScan({ findings, summary: event.data.severity_summary || {}, filesScanned: fileCount, langs: event.data.files_by_lang || {} });
        } else if (event.type === 'llm' && event.token) {
          setCodeScan((current) => ({ ...current, llmOutput: current.llmOutput + event.token }));
        }
      });
      toast(`⌥ Scan: ${findingCount} findings em ${fileCount} arquivos`);
    } catch (error) { if (error.name !== 'AbortError') toast(error.message, 'err'); }
    finally { patchCodeScan({ scanning: false }); scanAbortRef.current = null; }
  };
  const submitSnippet = async () => {
    if (!codeScan.snippetCode.trim()) return;
    patchCodeScan({ scanning: true, llmOutput: '' });
    const controller = new AbortController(); scanAbortRef.current = controller;
    try {
      const response = await fetch(`${API}/codescan/snippet`, { method: 'POST', signal: controller.signal, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: codeScan.snippetCode, lang: codeScan.snippetLang, focus: codeScan.focus, model, params }) });
      if (!response.ok) throw new Error(`HTTP ${response.status}: ${(await response.text()).slice(0, 400)}`);
      if (!response.body) throw new Error('stream NDJSON indisponível');
      await parseNDJSONStream(response.body.getReader(), (event) => { if (event.token) setCodeScan((current) => ({ ...current, llmOutput: current.llmOutput + event.token })); });
      toast('⌥ Snippet analisado');
    } catch (error) { if (error.name !== 'AbortError') toast(error.message, 'err'); }
    finally { patchCodeScan({ scanning: false }); scanAbortRef.current = null; }
  };
  const submitDisasm = async () => {
    if (!codeScan.disasmCode.trim()) return;
    patchCodeScan({ scanning: true, llmOutput: '', findings: [] });
    const controller = new AbortController(); scanAbortRef.current = controller;
    let findingCount = 0;
    try {
      const response = await fetch(`${API}/codescan/disasm`, { method: 'POST', signal: controller.signal, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ disasm: codeScan.disasmCode, focus: codeScan.asmFocus, arch: codeScan.arch, context: codeScan.disasmCtx, model, params }) });
      if (!response.ok) throw new Error(`HTTP ${response.status}: ${(await response.text()).slice(0, 400)}`);
      if (!response.body) throw new Error('stream NDJSON indisponível');
      await parseNDJSONStream(response.body.getReader(), (event) => {
        if (event.type === 'static') { const findings = event.findings || []; findingCount = findings.length; patchCodeScan({ findings }); }
        else if (event.type === 'llm' && event.token) setCodeScan((current) => ({ ...current, llmOutput: current.llmOutput + event.token }));
      });
      toast(`⚙ ASM analisado — ${findingCount} hits estáticos`);
    } catch (error) { if (error.name !== 'AbortError') toast(error.message, 'err'); }
    finally { patchCodeScan({ scanning: false }); scanAbortRef.current = null; }
  };
  const stopScan = () => { scanAbortRef.current?.abort(); patchCodeScan({ scanning: false }); toast('■ Scan interrompido', 'warn'); };

  useEffect(() => {
    const healthTimer = setInterval(() => void checkHealth(), 8000);
    const statsTimer = setInterval(() => void loadStats(), 25000);
    return () => {
      clearInterval(healthTimer); clearInterval(statsTimer); clearTimeout(noticeTimerRef.current);
      chatAbortRef.current?.abort(); scanAbortRef.current?.abort();
    };
  }, []);

  const app = {
    tab, setTab, grTab, setGrTab, model, setModel, memoryK, setMemoryK,
    input, setInput, messages, setMessages, streaming, streamBuffer, health, stats,
    params, setParams, modelInstall, patchInstall, sessions, currentSession,
    quickCategory, setQuickCategory, quickPrompts, notice, allMemory, filteredMemory,
    memoryCategories, memorySearch, setMemorySearch, memoryCategory, setMemoryCategory,
    batchJson, setBatchJson, teachForm, setTeachForm, runs, selectedRunId,
    runFindings, runDomain, grAnalyzing, ghostRecon, patchGr, auto, patchAuto,
    hex, patchHex, codeScan, patchCodeScan, inputRef, bottomRef,
    installModels: () => { patchInstall({ running: true }); void installModels(); },
    send, stopStream, feedback,
  };

  // The actions below are assigned after the state bundle to keep components declarative.
  Object.assign(app, {
    saveSession: () => void saveSessSafe(), loadSession: (id) => void loadSession(id),
    newSession, deleteSession: (id) => void deleteSession(id), exportMemory: () => void exportMemory(),
    loadAllMemory: () => void loadAllMemory(), deleteMemory: (id) => void deleteMemory(id),
    teach: () => void teach(), batchTeach: () => void batchTeach(), loadRuns: () => void loadRuns(),
    selectRun: (run) => void selectRun(run), ingestSqlite: () => void ingestSqlite(),
    ingestRun: () => void ingestRun(), ingestNdjson: () => void ingestNdjson(), analyzeRun: () => void analyzeRun(),
    startAutoRecon: () => void startAutoRecon(), loadHexStatus: () => void loadHexStatus(),
    loadHexHealth: () => void loadHexHealth(), hexRelayRequest, relayHexJson: () => void relayHexJson(),
    injectHexChat, scanRepo: () => void scanRepo(), submitSnippet: () => void submitSnippet(),
    submitDisasm: () => void submitDisasm(), stopScan,
  });

  return (
    <>
      <Sidebar app={app} />
      <main className="main">
        <Navigation app={app} />
        {tab === 'chat' && <ChatPanel app={app} />}
        {tab === 'gr' && <GhostReconPanel app={app} />}
        {tab === 'hs' && <HexStrikePanel app={app} />}
        {tab === 'code' && <CodeScanPanel app={app} />}
        {tab === 'teach' && <TeachPanel app={app} />}
        {tab === 'mem' && <MemoryPanel app={app} />}
      </main>
      {notice && <div className={`toast ${notice.type === 'err' ? 'err' : notice.type === 'warn' ? 'warn' : ''}`}>{notice.message}</div>}
    </>
  );

  async function saveSessSafe() {
    try { await saveSess(); } catch (error) { toast(error.message, 'err'); }
  }

  async function saveSess() {
    if (!messagesRef.current.length) return;
    const title = messagesRef.current[0]?.content?.slice(0, 50) || 'Sessão';
    await readJson(await fetch(`${API}/sessions/save`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ session_id: currentSession, title, model, messages: messagesRef.current.map(({ role, content }) => ({ role, content })), params }) }));
    toast('💾 Sessão salva'); void loadSessions();
  }
}

function GhostMark() {
  return (
    <svg viewBox="0 0 48 52" xmlns="http://www.w3.org/2000/svg" focusable="false" aria-hidden="true">
      <defs><linearGradient id="ghostAiLogoGrad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stopColor="#e8fbff" /><stop offset="45%" stopColor="#5ee0ff" /><stop offset="100%" stopColor="#00a8d4" /></linearGradient></defs>
      <path fill="url(#ghostAiLogoGrad)" stroke="rgba(0,212,255,0.45)" strokeWidth="0.55" d="M 24 5 C 13 5 5 13.5 5 24.5 V 40 Q 8.5 36.5 12 40 Q 15.5 36.5 19 40 Q 22.5 36.5 26 40 Q 29.5 36.5 33 40 Q 36.5 36.5 40 40 Q 43.5 36.5 43 40 V 24.5 C 43 13.5 35 5 24 5 Z" />
      <ellipse cx="17" cy="22" rx="3.2" ry="4.2" fill="#050709" /><ellipse cx="31" cy="22" rx="3.2" ry="4.2" fill="#050709" />
    </svg>
  );
}

function Sidebar({ app }) {
  const updateParam = (key, value) => app.setParams((current) => ({ ...current, [key]: value }));
  return (
    <aside className="sb">
      <div className="sb-logo">
        <div className="logo-row"><div className="logo-hex"><GhostMark /></div><div><div className="logo-name">GHOST <span style={{ color: 'var(--green2)' }}>INTELLIGENCE</span></div><div className="logo-ver">LOCAL AI · KNOWLEDGE CORE · REACT</div></div></div>
        <div className="hbar">
          <div className="hchip"><div className={`dot ${app.health.ghost === 'online' ? 'on' : 'off'}`} /><span>GHOST</span></div>
          <div className="hchip"><div className={`dot ${app.health.ollama === 'online' ? 'on' : app.health.ollama === 'offline' ? 'off' : 'warn'}`} /><span>OLLAMA</span></div>
          <div className="hchip"><div className={`dot ${app.health.hexstrike === 'online' ? 'on' : 'off'}`} /><span>HEX</span></div>
          <div className="hchip" style={{ marginLeft: 'auto' }}><span style={{ color: 'var(--amber)' }}>◈ {app.health.runs || 0} runs</span></div>
        </div>
      </div>

      <div className="sbs">
        <div className="sbl">MODELO</div>
        <select className="s" value={app.model} onChange={(event) => app.setModel(event.target.value)}>
          <option value="deepseek-coder-v2:16b">deepseek-coder-v2:16b ★</option><option value="deepseek-r1:latest">deepseek-r1:latest</option>
          <option value="llama3.3:70b">Llama 3.3 (70B)</option><option value="llama3.1:8b">Llama 3.x (8B)</option>
          <option value="gemma4:31b">Gemma 4 (31B)</option><option value="qwen3.5:9b">Qwen 3.5 (9B)</option><option value="qwen3.5:32b">Qwen 3.5 (32B)</option>
          <option value="qwen2.5-coder:7b">qwen2.5-coder:7b</option><option value="codellama:13b">codellama:13b</option><option value="mistral:7b">mistral:7b</option><option value="phi3.5:3.8b">phi3.5:3.8b (rápido)</option>
        </select>
        <div style={{ display: 'flex', gap: 6, marginTop: 8, alignItems: 'center' }}>
          <input className="fi" value={app.modelInstall.list} onChange={(event) => app.patchInstall({ list: event.target.value })} placeholder="modelos (csv): llama3.3:70b,qwen3.5:9b" style={{ fontSize: 10, padding: '5px 7px', resize: 'none' }} />
          <button className="sbtn" style={{ padding: '6px 10px', fontSize: 9, letterSpacing: 1 }} onClick={app.installModels} disabled={app.modelInstall.running}>{app.modelInstall.running ? 'INSTALANDO...' : 'INSTALAR'}</button>
        </div>
        {app.modelInstall.last && <div style={{ marginTop: 6, fontSize: 8, color: 'var(--t2)', lineHeight: 1.5, whiteSpace: 'pre-wrap' }}>{app.modelInstall.last}</div>}
      </div>

      <div className="sbs sb-params">
        <div className="sbl">PARÂMETROS</div>
        <div className="pg">
          {PARAM_DEFS.map((definition) => {
            const value = app.params[definition.k];
            const pct = ((value - definition.min) / (definition.max - definition.min) * 100).toFixed(1);
            return <div className="pr" key={definition.k}><div className="ph"><span className="pn">{definition.l}</span><span className="pv">{value}</span></div><input type="range" min={definition.min} max={definition.max} step={definition.step} value={value} onChange={(event) => updateParam(definition.k, Number(event.target.value))} style={{ '--pct': `${pct}%` }} /></div>;
          })}
          <div className="fg" style={{ margin: 0 }}><div className="ph"><span className="pn">SEED (-1=aleatório)</span><span className="pv">{app.params.seed}</span></div><input type="range" min="-1" max="999999" step="1" value={app.params.seed} onChange={(event) => updateParam('seed', Number(event.target.value))} style={{ '--pct': `${((app.params.seed + 1) / 1000000 * 100).toFixed(1)}%` }} /></div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>{BOOL_PARAM_DEFS.map((definition) => <label key={definition.k} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9, color: 'var(--t2)', cursor: 'pointer', padding: '2px 6px', border: '1px solid var(--border)' }}><input type="checkbox" checked={Boolean(app.params[definition.k])} onChange={(event) => updateParam(definition.k, event.target.checked)} style={{ accentColor: 'var(--green)', width: 10, height: 10 }} />{definition.l}</label>)}</div>
        </div>
      </div>

      <div className="sbs"><div className="sbl">MEMÓRIA & RUNS</div><div className="sg"><div className="sx"><div className="sn">{app.stats.memory_entries || 0}</div><div className="sl">DOCS</div></div><div className="sx"><div className="sn">{app.stats.feedback_count || 0}</div><div className="sl">FEEDBACK</div></div><div className="sx"><div className="sn">{app.stats.runs_count || 0}</div><div className="sl">RUNS</div></div></div></div>

      <div className="sbs sb-sessions-wrap">
        <div className="sbl" style={{ display: 'flex', justifyContent: 'space-between' }}><span>SESSÕES</span><button type="button" className="link-button" onClick={app.newSession}>+ NOVA</button></div>
        <div className="slist">
          {app.sessions.map((session) => <button type="button" key={session.id} className={`si ${app.currentSession === session.id ? 'act' : ''}`} onClick={() => app.loadSession(session.id)}><span className="si-t">{session.title || '—'}</span><span className="si-m">{session.msg_count}m</span><span role="button" tabIndex={0} className="session-delete" onClick={(event) => { event.stopPropagation(); app.deleteSession(session.id); }} onKeyDown={(event) => { if (event.key === 'Enter') { event.stopPropagation(); app.deleteSession(session.id); } }}>✕</span></button>)}
          {!app.sessions.length && <div style={{ fontSize: 9, color: 'var(--t3)', padding: '3px 0' }}>Nenhuma sessão</div>}
        </div>
      </div>
      <div className="sbs"><button className="sbb" onClick={app.saveSession}>💾 SALVAR SESSÃO</button><button className="sbb" onClick={app.exportMemory}>↓ EXPORTAR MEMÓRIA</button><button className="sbb" onClick={() => app.setMessages([])}>⟳ LIMPAR CHAT</button></div>
    </aside>
  );
}

function Navigation({ app }) {
  const go = (tab) => {
    app.setTab(tab);
    if (tab === 'gr') app.loadRuns();
    if (tab === 'hs') void app.loadHexStatus?.();
    if (tab === 'mem') app.loadAllMemory();
  };
  return <nav className="tabs" aria-label="Áreas GHOST"><button className={`tab ${app.tab === 'chat' ? 'act' : ''}`} onClick={() => go('chat')}>▸ CHAT</button><button className={`tab gr ${app.tab === 'gr' ? 'act' : ''}`} onClick={() => go('gr')}>⬡ GHOSTRECON</button><button className={`tab hs ${app.tab === 'hs' ? 'act' : ''}`} onClick={() => go('hs')}>⚑ HEXSTRIKE</button><button className={`tab ${app.tab === 'code' ? 'act actc' : ''}`} style={{ color: 'var(--purple)' }} onClick={() => go('code')}>⌥ CODESCAN</button><button className={`tab ${app.tab === 'teach' ? 'act' : ''}`} onClick={() => go('teach')}>⊕ ENSINAR</button><button className={`tab ${app.tab === 'mem' ? 'act' : ''}`} onClick={() => go('mem')}>◈ MEMÓRIA ({app.stats.memory_entries || 0})</button></nav>;
}

function ChatPanel({ app }) {
  const autoresize = (event) => { event.target.style.height = 'auto'; event.target.style.height = `${Math.min(event.target.scrollHeight, 130)}px`; };
  return (
    <>
      <div className="qbar">{QUICK_CATEGORIES.map((category) => <button key={category.k} className={`qcat ${app.quickCategory === category.k ? 'act' : ''} ${category.k === 'ghostrecon' ? 'gr' : ''}`} onClick={() => app.setQuickCategory(category.k)}>{category.l}</button>)}<span style={{ width: 1, background: 'var(--border)', flexShrink: 0, margin: '0 3px' }} />{(app.quickPrompts[app.quickCategory] || []).map((prompt) => <button key={prompt} className="qchip" title={prompt} onClick={() => { app.setInput(prompt); app.setTab('chat'); requestAnimationFrame(() => app.inputRef.current?.focus()); }}>{prompt.length > 50 ? `${prompt.slice(0, 47)}...` : prompt}</button>)}</div>
      <div className="cbody">
        {!app.messages.length && <div className="emp"><div className="emp-i">◈</div><div className="emp-t">GHOST v4 REACT PRONTO</div><div className="emp-s">Pentest · GHOSTRECON · Red Team · Dev · CTF</div></div>}
        {app.messages.map((message, index) => <div key={`${index}-${message.role}`} className={`msg ${message.role}`}><div className="mlabel">{message.role === 'user' ? 'OPERADOR' : 'GHOST'} {message.role === 'assistant' && message.mem ? <span className="mbadge mem">◈ {message.mem} mem</span> : null} {message.role === 'assistant' && message.tok ? <span className="mbadge tok">{message.tok}tk</span> : null} {message.role === 'assistant' && message.ms ? <span className="mbadge" style={{ borderColor: 'rgba(206,147,216,.15)', color: 'rgba(206,147,216,.5)' }}>{(message.ms / 1e9).toFixed(1)}s</span> : null}</div><Markdown value={message.content} className="mbubble" />{message.role === 'assistant' && <div className="meta-row"><button className={`fbtn g ${message.fb === 'g' ? 'rg' : ''}`} onClick={() => app.feedback(index, true)}>✓ BOM</button><button className={`fbtn b ${message.fb === 'b' ? 'rb' : ''}`} onClick={() => app.feedback(index, false)}>✗ RUIM</button></div>}</div>)}
        {app.streaming && <div className="msg assistant"><div className="mlabel">GHOST <span className="mbadge mem">streaming...</span></div><Markdown value={app.streamBuffer || '*gerando resposta...*'} className="mbubble" /><div className="thinking below"><span /><span /><span /><span className="stxt">processando</span></div></div>}
        <div ref={app.bottomRef} />
      </div>
      <div className="izone"><div className="irow"><div className="iwrap"><span className="isym">❯</span><textarea ref={app.inputRef} value={app.input} onChange={(event) => { app.setInput(event.target.value); autoresize(event); }} onKeyDown={(event) => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); void app.send(); } }} placeholder="Pentest, exploit, análise GHOSTRECON, código, CTF... (Enter envia)" rows="1" /></div>{!app.streaming ? <button className="sbtn" onClick={() => void app.send()} disabled={!app.input.trim()}>ENVIAR</button> : <button className="stopbtn" onClick={app.stopStream}>■ STOP</button>}</div><div className="imeta"><span>MEM-K:</span><select value={app.memoryK} onChange={(event) => app.setMemoryK(Number(event.target.value))}><option value="0">0 off</option><option value="3">3</option><option value="6">6★</option><option value="10">10</option><option value="20">20</option></select><span>|</span><span>CTX:{app.params.num_ctx / 1024}K</span><span>|</span><span>T:{app.params.temperature}</span><span>|</span><span>TOP-P:{app.params.top_p}</span><span>|</span><span>REP:{app.params.repeat_penalty}</span>{app.params.mirostat ? <span>| MIRO:{app.params.mirostat}(τ{app.params.mirostat_tau})</span> : null}{app.params.seed >= 0 ? <span>| SEED:{app.params.seed}</span> : null}</div></div>
    </>
  );
}

const ANALYSIS_MODES = [
  ['full', 'COMPLETO'], ['quick', 'RÁPIDO'], ['chain', 'CADEIAS ATAQUE'], ['report', 'RELATÓRIO EXECUTIVO'],
].map(([v, l]) => ({ v, l }));

function GhostReconPanel({ app }) {
  return (
    <div className="gr-panel">
      <div className="gr-header"><div><div className="gr-title">⬡ GHOSTRECON — INTEGRAÇÃO</div><div style={{ fontSize: 10, color: 'var(--t2)', marginTop: 4 }}>Ingira runs, analise findings, correlacione vulnerabilidades</div></div><div className="gr-actions"><button className="gr-btn auto" onClick={() => app.patchAuto({ showModal: true })}>AUTO</button><button className="gr-btn" onClick={app.loadRuns}>↻ ATUALIZAR</button><button className={`gr-btn ${app.grTab === 'ingest' ? 'act' : ''}`} onClick={() => app.setGrTab('ingest')}>⊕ INGERIR</button><button className={`gr-btn ${app.grTab === 'runs' ? 'act' : ''}`} onClick={() => app.setGrTab('runs')}>◈ RUNS</button><button className={`gr-btn ${app.grTab === 'analyze' ? 'act' : ''}`} onClick={() => app.setGrTab('analyze')}>⚡ ANALISAR</button></div></div>

      <div className="auto-card"><div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}><div><div style={{ fontSize: 10, color: 'var(--green2)', letterSpacing: 1.5 }}>MODO AUTO</div><div style={{ fontSize: 10, color: 'var(--t2)', marginTop: 3 }}>Planejamento determinístico local + pipeline GHOSTRECON.</div></div><button className="gr-btn auto" onClick={() => app.patchAuto({ showModal: true })} disabled={app.auto.running}>{app.auto.running ? 'AUTO RODANDO...' : 'ATIVAR AUTO'}</button></div>{app.auto.lastPlan && <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}><span className="auto-pill">MODO {app.auto.lastPlan.mode}</span><span className="auto-pill">{app.auto.lastPlan.modules?.length || 0} MODULOS</span></div>}</div>

      {app.auto.showModal && <div className="auto-modal-bg" onMouseDown={(event) => { if (event.target === event.currentTarget && !app.auto.running) app.patchAuto({ showModal: false }); }}><div className="auto-modal" role="dialog" aria-modal="true" aria-labelledby="auto-title"><div className="auto-modal-head"><div><div className="auto-modal-title" id="auto-title">MODO AUTO</div><div className="auto-modal-sub">O plano é calculado a partir do modo e das opções locais abaixo.</div></div><button className="auto-close" onClick={() => app.patchAuto({ showModal: false })} disabled={app.auto.running}>X</button></div><Field label="ALVO AUTORIZADO"><input className="fi" value={app.auto.domain} onChange={(event) => app.patchAuto({ domain: event.target.value })} placeholder="alvo.autorizado.com" /></Field><Field label="MODO"><div className="cchips">{[['quick', 'RAPIDO'], ['balanced', 'BALANCEADO'], ['deep', 'PROFUNDO']].map(([value, label]) => <button key={value} className={`cchip ${app.auto.mode === value ? 'act' : ''}`} onClick={() => app.patchAuto({ mode: value })}>{label}</button>)}</div></Field><div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(190px,1fr))', gap: 8 }}><button className={`auto-choice ${app.auto.includeHexstrike ? 'act' : ''}`} onClick={() => app.patchAuto({ includeHexstrike: !app.auto.includeHexstrike })}><span className="auto-choice-title">HexStrike Intelligence</span><span className="auto-choice-desc">Inclui hexstrike_orchestrator quando disponível.</span></button><button className={`auto-choice ${app.auto.includeDeepPassive ? 'act' : ''}`} onClick={() => app.patchAuto({ includeDeepPassive: !app.auto.includeDeepPassive })}><span className="auto-choice-title">Deep Passive</span><span className="auto-choice-desc">Adiciona módulos passivos extras no plano.</span></button></div><div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', flexWrap: 'wrap' }}><button className="gr-btn" onClick={() => app.patchAuto({ showModal: false })} disabled={app.auto.running}>CANCELAR</button><button className="gr-btn auto" onClick={app.startAutoRecon} disabled={app.auto.running || !app.auto.domain.trim()}>{app.auto.running ? 'EXECUTANDO...' : 'INICIAR AUTO'}</button></div></div></div>}

      {app.auto.events.length > 0 && <pre className="auto-events">{app.auto.events.join('\n')}</pre>}
      {app.grTab === 'ingest' && <IngestPanel app={app} />}
      {app.grTab === 'runs' && <RunsPanel app={app} />}
      {app.grTab === 'analyze' && <AnalyzePanel app={app} />}
    </div>
  );
}

function Field({ label, children, style }) { return <div className="fg" style={style}><label className="fl">{label}</label>{children}</div>; }

function IngestPanel({ app }) {
  return <div className="gr-ingest"><div style={{ fontSize: 9, color: 'var(--t2)', letterSpacing: 1.5, marginBottom: 12 }}>INGERIR DADOS DO GHOSTRECON</div><Field label="CAMINHO DO SQLITE (data/bugbounty.db)"><input className="fi" value={app.ghostRecon.dbPath} onChange={(event) => app.patchGr({ dbPath: event.target.value })} placeholder="/caminho/para/ghostrecon/data/bugbounty.db" /></Field><button className="gr-btn act" onClick={app.ingestSqlite} style={{ marginBottom: 12 }}>↑ INGERIR SQLITE</button><Field label="JSON DE RUN COMPLETO (copie do /api/runs/:id)"><textarea className="fi" value={app.ghostRecon.runJson} onChange={(event) => app.patchGr({ runJson: event.target.value })} rows="8" placeholder='{"domain":"alvo.com","findings":[...],"subdomains":[...]}' /></Field><button className="gr-btn act" onClick={app.ingestRun} style={{ marginBottom: 12 }}>↑ INGERIR RUN JSON</button><Field label="NDJSON DO PIPELINE (eventos em tempo real)"><textarea className="fi" value={app.ghostRecon.ndjson} onChange={(event) => app.patchGr({ ndjson: event.target.value })} rows="6" placeholder={'{"type":"finding","data":{...}}\n{"type":"log","data":{...}}'} /></Field><button className="gr-btn act" onClick={app.ingestNdjson}>↑ INGERIR NDJSON</button>{app.ghostRecon.result && <div style={{ marginTop: 12, fontSize: 10, color: 'var(--green)', padding: 8, border: '1px solid rgba(0,230,118,.2)', background: 'var(--gd)' }}>{app.ghostRecon.result}</div>}</div>;
}

function RunsPanel({ app }) {
  return <div><div style={{ fontSize: 9, color: 'var(--t2)', letterSpacing: 1.5, marginBottom: 10 }}>RUNS INGERIDOS ({app.runs.length})</div><div className="gr-runs">{!app.runs.length && <div style={{ fontSize: 11, color: 'var(--t3)', padding: 20, textAlign: 'center' }}>Nenhum run. Use a aba INGERIR ou o endpoint /ghostrecon/ingest/run</div>}{app.runs.map((run) => <button key={run.id} className={`run-card ${app.selectedRunId === run.id ? 'sel' : ''}`} onClick={() => app.selectRun(run)}><span><span className="run-domain">{run.domain}</span><span className="run-meta">{run.profile} · {run.created_at?.slice(0, 16)} · ID: {run.id?.slice(0, 8)}</span></span><span className={`run-badge ${run.findings_count < 3 ? 'low' : run.findings_count < 10 ? 'med' : ''}`}>{run.findings_count} findings</span></button>)}</div>{app.selectedRunId && app.runFindings.length > 0 && <div style={{ marginTop: 16 }}><div style={{ fontSize: 9, color: 'var(--amber)', letterSpacing: 1.5, marginBottom: 8 }}>FINDINGS — {app.runDomain} ({app.runFindings.length})</div><table className="ftable"><thead><tr><th>SEV</th><th>TIPO</th><th>URL</th><th>MITRE</th></tr></thead><tbody>{app.runFindings.slice(0, 50).map((finding, index) => { const severity = finding.severity || finding.score || 'INFO'; return <tr key={`${index}-${finding.url || finding.target || ''}`}><td><span className={`sev ${severity}`}>{severity}</span></td><td style={{ color: 'var(--text)', fontSize: 10 }}>{finding.type || finding.vuln_type || '?'}</td><td className="finding-url-cell">{finding.url || finding.target || '?'}</td><td style={{ color: 'var(--purple)', fontSize: 9 }}>{finding.mitre || '—'}</td></tr>; })}</tbody></table></div>}</div>;
}

function AnalyzePanel({ app }) {
  return <div><div style={{ fontSize: 9, color: 'var(--t2)', letterSpacing: 1.5, marginBottom: 12 }}>ANÁLISE PROFUNDA COM IA</div><Field label="RUN PARA ANALISAR"><select className="fi s" value={app.ghostRecon.analyzeRunId} onChange={(event) => app.patchGr({ analyzeRunId: event.target.value })}><option value="">Selecione um run...</option>{app.runs.map((run) => <option key={run.id} value={run.id}>{run.domain} · {run.findings_count} findings · {run.created_at?.slice(0, 10)}</option>)}</select></Field><Field label="MODO DE ANÁLISE"><div className="cchips">{ANALYSIS_MODES.map((mode) => <button key={mode.v} className={`cchip ${app.ghostRecon.mode === mode.v ? 'act' : ''}`} onClick={() => app.patchGr({ mode: mode.v })}>{mode.l}</button>)}</div></Field><button className="gr-btn act" onClick={app.analyzeRun} disabled={!app.ghostRecon.analyzeRunId || app.grAnalyzing}>{app.grAnalyzing ? '⚡ ANALISANDO...' : '⚡ INICIAR ANÁLISE'}</button>{app.ghostRecon.analysis && <Markdown value={app.ghostRecon.analysis} className="gr-result" />}</div>;
}

function HexStrikePanel({ app }) {
  const relay = (path, payload, timeout) => { if (payload) void app.hexRelayRequest(path, payload, timeout); };
  return <div className="hs-panel"><div><div className="hs-title">⚑ HEXSTRIKE AI — BRIDGE GHOST</div><div className="hs-sub">O GHOST encaminha pedidos para <strong>{app.hex.base || '—'}</strong>. Inicia antes: <code>hexstrike-ai/start-server.sh</code> (porta 8888). Variável: <code>GHOST_HEXSTRIKE_URL</code>.</div></div><div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}><span className="hchip" style={{ borderColor: 'rgba(255,82,82,.25)' }}><span className={`dot ${app.hex.reachable ? 'on' : 'off'}`} /> {app.hex.reachable ? 'ALCANÇÁVEL' : 'OFFLINE'}</span><button className="hs-btn" onClick={app.loadHexStatus}>↻ ESTADO</button><button className="hs-btn" onClick={app.loadHexHealth} disabled={app.hex.loadingH}>⏱ HEALTH COMPLETO</button></div>{app.hex.err && <div style={{ fontSize: 10, color: 'var(--red)' }}>{app.hex.err}</div>}{app.hex.healthSummary && <pre className="hs-out">{app.hex.healthSummary}</pre>}<section className="boxed hs-box"><div className="sbl hs-label">INTELIGÊNCIA — ANALISAR ALVO</div><Field label="ALVO (domínio / URL)"><input className="fi" value={app.hex.target} onChange={(event) => app.patchHex({ target: event.target.value })} placeholder="exemplo.com" /></Field><div className="action-row"><button className="hs-btn act" onClick={() => relay('/api/intelligence/analyze-target', { target: app.hex.target.trim(), analysis_type: 'comprehensive' }, 180)} disabled={app.hex.busy || !app.hex.target.trim()}>⚡ ANALISAR</button><button className="hs-btn" onClick={() => relay('/api/intelligence/select-tools', { target: app.hex.target.trim(), objective: 'comprehensive' }, 120)} disabled={app.hex.busy || !app.hex.target.trim()}>FERRAMENTAS</button></div></section><section className="boxed hs-box"><div className="sbl hs-label">COMANDO GENÉRICO (/api/command)</div><textarea className="fi" value={app.hex.command} onChange={(event) => app.patchHex({ command: event.target.value })} rows="3" placeholder="ex: nmap -sV -p 80,443 alvo.com" /><div className="action-row"><button className="hs-btn act" onClick={() => relay('/api/command', { command: app.hex.command.trim(), use_cache: false }, 300)} disabled={app.hex.busy || !app.hex.command.trim()}>▶ EXECUTAR</button></div></section><section className="boxed hs-box"><div className="sbl hs-label">RELAY AVANÇADO</div><Field label="PATH (whitelist /api/...)"><input className="fi" value={app.hex.relayPath} onChange={(event) => app.patchHex({ relayPath: event.target.value })} placeholder="/api/intelligence/select-tools" /></Field><Field label="JSON PAYLOAD"><textarea className="fi" value={app.hex.relayJson} onChange={(event) => app.patchHex({ relayJson: event.target.value })} rows="5" placeholder='{"target":"..."}' /></Field><button className="hs-btn act" onClick={app.relayHexJson} disabled={app.hex.busy}>▶ ENVIAR RELAY</button></section>{app.hex.out && <div><div style={{ fontSize: 9, color: 'var(--t2)', marginBottom: 6 }}>ÚLTIMA RESPOSTA — {app.hex.lastPath}</div><pre className="hs-out">{app.hex.out}</pre><button className="hs-btn" style={{ marginTop: 8 }} onClick={app.injectHexChat}>⤴ INSERIR NO CHAT (contexto)</button></div>}</div>;
}

function CodeScanPanel({ app }) {
  const scan = app.codeScan;
  const languages = ['python', 'java', 'javascript', 'php', 'bash', 'go', 'c', 'cpp', 'sql', 'vue'];
  const architectures = ['x86_64', 'x86', 'arm64', 'arm', 'mips', 'riscv'];
  const toggleFinding = (index) => app.patchCodeScan({ findings: scan.findings.map((finding, i) => i === index ? { ...finding, _open: !finding._open } : finding) });
  return (
    <div className="cs-panel">
      <div className="cs-header">⌥ CODESCAN — ANÁLISE DE SEGURANÇA</div>
      <div className="boxed cs-config">
        <Field label="CAMINHO DO REPOSITÓRIO / ARQUIVO" style={{ margin: 0 }}><input className="fi" value={scan.path} onChange={(event) => app.patchCodeScan({ path: event.target.value })} placeholder="/home/operador/projetos/meu-app" /></Field>
        <div className="two-columns"><Field label="ARQUIVO ESPECÍFICO (opcional)" style={{ margin: 0, flex: 1 }}><input className="fi" value={scan.file} onChange={(event) => app.patchCodeScan({ file: event.target.value })} placeholder="src/auth/login.py (relativo ao repo)" /></Field><Field label="EXTENSÕES (opcional)" style={{ margin: 0, flex: 1 }}><input className="fi" value={scan.exts} onChange={(event) => app.patchCodeScan({ exts: event.target.value })} placeholder=".py .java .js" /></Field></div>
        <div><label className="fl mode-label">FOCO DA ANÁLISE</label><div className="cs-bar">{CODE_SCAN_MODES.map((mode) => <button key={mode.v} className={`cs-mode ${scan.focus === mode.v ? 'act' : ''}`} onClick={() => app.patchCodeScan({ focus: mode.v })}>{mode.l}</button>)}</div></div>
        <div className="code-actions"><label className="check-label"><input type="checkbox" checked={scan.llm} onChange={(event) => app.patchCodeScan({ llm: event.target.checked })} /> ANÁLISE LLM PROFUNDA</label><label className="check-label"><input type="checkbox" checked={scan.learn} onChange={(event) => app.patchCodeScan({ learn: event.target.checked })} /> APRENDER FINDINGS</label><div className="code-buttons">{!scan.scanning ? <><button className="cs-btn" onClick={app.scanRepo} disabled={!scan.path.trim()}>⌥ ESCANEAR REPO</button><button className="cs-btn blue" onClick={() => app.patchCodeScan({ snippetMode: true, llmOutput: '' })}>⌥ SNIPPET</button><button className="cs-btn amber" onClick={() => app.patchCodeScan({ disasmMode: true, snippetMode: false })}>⚙ DISASM/ASM</button></> : <button className="cs-stop" onClick={app.stopScan}>■ PARAR</button>}</div></div>
      </div>

      {scan.summary && <div className="cs-grid"><div className="cs-card"><div className="cs-card-title">SEVERIDADE</div><div className="severity-summary">{[['CRITICAL', 'c'], ['HIGH', 'h'], ['MEDIUM', 'm'], ['LOW', 'l']].map(([severity, className]) => <div key={severity}><div className={`cs-stat ${className}`}>{scan.summary[severity] || 0}</div><div className="tiny-muted">{severity}</div></div>)}</div></div><div className="cs-card"><div className="cs-card-title">COBERTURA</div><div className="coverage-count">{scan.filesScanned}</div><div className="coverage-langs">arquivos · {Object.entries(scan.langs || {}).map(([language, count]) => `${language}:${count}`).join(' ')}</div></div></div>}

      {scan.findings.length > 0 && <div><div className="findings-title">FINDINGS ESTÁTICOS ({scan.findings.length}) — <span>clique para ver snippet</span></div><div className="fi-list">{scan.findings.map((finding, index) => <button key={`${finding.file || ''}-${finding.line || index}-${index}`} className="fi-card" onClick={() => toggleFinding(index)}><span className={`sev ${finding.severity}`}>{finding.severity}</span><span className="fi-body"><span className="fi-title">{finding.title}</span><span className="fi-meta">{String(finding.file || '').split('/').slice(-2).join('/')} : linha {finding.line} · {finding.lang} · {finding.cwe}</span>{finding._open && <pre className="snippet-area">{finding.snippet}</pre>}</span></button>)}</div></div>}

      {(scan.llmOutput || scan.scanning) && <div><div className="findings-title">ANÁLISE LLM {scan.scanning && <span>streaming...</span>}</div><Markdown value={scan.llmOutput} className="cs-output" /></div>}

      {scan.snippetMode && <section className="boxed snippet-panel"><div className="findings-title">ANÁLISE DE SNIPPET</div><Field label="LINGUAGEM"><select className="fi s" value={scan.snippetLang} onChange={(event) => app.patchCodeScan({ snippetLang: event.target.value })}>{languages.map((language) => <option key={language} value={language}>{language}</option>)}</select></Field><Field label="CÓDIGO"><textarea className="fi" value={scan.snippetCode} onChange={(event) => app.patchCodeScan({ snippetCode: event.target.value })} rows="10" placeholder="Cole o código aqui..." /></Field><div className="action-row"><button className="cs-btn" onClick={app.submitSnippet} disabled={!scan.snippetCode.trim() || scan.scanning}>⌥ ANALISAR</button><button className="cs-btn muted" onClick={() => app.patchCodeScan({ snippetMode: false })}>✕ FECHAR</button></div></section>}

      {scan.disasmMode && <section className="boxed disasm-panel"><div className="findings-title amber-text">⚙ ANÁLISE DE ASSEMBLY / DISASSEMBLY</div><div className="two-columns"><Field label="ARQUITETURA" style={{ margin: 0, flex: 1 }}><select className="fi s" value={scan.arch} onChange={(event) => app.patchCodeScan({ arch: event.target.value })}>{architectures.map((architecture) => <option key={architecture} value={architecture}>{architecture}</option>)}</select></Field><Field label="CONTEXTO (opcional — origem, binário, função)" style={{ margin: 0, flex: 2 }}><input className="fi" value={scan.disasmCtx} onChange={(event) => app.patchCodeScan({ disasmCtx: event.target.value })} placeholder="função authenticate() de /usr/bin/login, stripped ELF x86_64" /></Field></div><div><label className="fl mode-label">FOCO</label><div className="cs-bar">{ASM_MODES.map((mode) => <button key={mode.v} className={`cs-mode ${scan.asmFocus === mode.v ? 'act' : ''}`} onClick={() => app.patchCodeScan({ asmFocus: mode.v })}>{mode.l}</button>)}</div></div><Field label="DISASSEMBLY (output de objdump, gdb, r2, IDA, Ghidra...)"><textarea className="fi" value={scan.disasmCode} onChange={(event) => app.patchCodeScan({ disasmCode: event.target.value })} rows="14" placeholder={'0x00401136 push   rbp\n0x00401137 mov    rbp,rsp\n0x0040113a sub    rsp,0x10\n...'} /></Field><div className="action-row"><button className="cs-btn amber" onClick={app.submitDisasm} disabled={!scan.disasmCode.trim() || scan.scanning}>⚙ ANALISAR ASM</button><button className="cs-btn muted" onClick={() => app.patchCodeScan({ disasmMode: false })}>✕ FECHAR</button></div></section>}
    </div>
  );
}

function TeachPanel({ app }) {
  return <div className="panel"><div className="ptitle">⊕ ENSINAR AO GHOST</div><p className="psub">Adiciona conhecimento permanente via busca semântica. O GHOST usa automaticamente como contexto.</p><Field label="CATEGORIA"><div className="cchips">{MEMORY_CATEGORIES.map((category) => <button key={category.v} className={`cchip ${app.teachForm.cat === category.v ? 'act' : ''}`} onClick={() => app.setTeachForm((current) => ({ ...current, cat: category.v }))}>{category.l}</button>)}</div></Field><Field label="TÓPICO"><input className="fi" value={app.teachForm.topic} onChange={(event) => app.setTeachForm((current) => ({ ...current, topic: event.target.value }))} placeholder="Ex: Bypass WAF com chunked encoding" /></Field><Field label="CONTEÚDO (detalhado = melhor busca semântica)"><textarea className="fi" value={app.teachForm.content} onChange={(event) => app.setTeachForm((current) => ({ ...current, content: event.target.value }))} rows="8" placeholder="Técnica, payload, PoC, código, metodologia..." /></Field><Field label="TAGS (vírgula)"><input className="fi" value={app.teachForm.tags} onChange={(event) => app.setTeachForm((current) => ({ ...current, tags: event.target.value }))} placeholder="sqli, bypass, waf" /></Field><button className="pbtn" onClick={app.teach} disabled={!app.teachForm.topic || !app.teachForm.content}>⊕ ADICIONAR À MEMÓRIA</button><hr className="pdiv" /><div className="batch-title">IMPORTAR LOTE (JSON)</div><Field><textarea className="fi" value={app.batchJson} onChange={(event) => app.setBatchJson(event.target.value)} rows="7" placeholder='[{"topic":"...","content":"...","category":"pentest","tags":[]}]' /></Field><button className="pbtn" onClick={app.batchTeach} disabled={!app.batchJson.trim()}>↑ IMPORTAR LOTE</button></div>;
}

function MemoryPanel({ app }) {
  return <div className="panel memory-panel"><div className="mtb"><div className="mswrap"><span className="search-icon">⌕</span><input value={app.memorySearch} onChange={(event) => app.setMemorySearch(event.target.value)} placeholder="Buscar memória..." /></div><button className="memory-export" onClick={app.exportMemory}>↓ EXPORT</button></div><div className="fchips memory-filters"><button className={`fchip ${app.memoryCategory === 'all' ? 'act' : ''}`} onClick={() => app.setMemoryCategory('all')}>TODOS ({app.allMemory.length})</button>{app.memoryCategories.map((category) => <button key={category.category} className={`fchip ${app.memoryCategory === category.category ? 'act' : ''} ${category.source === 'ghostrecon' ? 'gr' : ''}`} onClick={() => app.setMemoryCategory(category.category)}>{String(category.category).toUpperCase()} ({category.count})</button>)}</div><div className="mgrid">{!app.filteredMemory.length && <div className="empty-memory">◈ Vazio</div>}{app.filteredMemory.map((memory) => <article key={memory.id} className="mcard"><div className="mc-body"><div className="mc-topic">{memory.topic}</div><div className="mc-pre">{memory.content}</div></div><div className="mc-side"><span className="cbadge">{memory.category}</span>{memory.source !== 'manual' && <span className="sbadge">{memory.source}</span>}<button className="delbtn" onClick={() => app.deleteMemory(memory.id)}>✕ DEL</button></div></article>)}</div></div>;
}

