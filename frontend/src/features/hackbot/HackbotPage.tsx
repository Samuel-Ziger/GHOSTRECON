import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import type { ReactUiPage } from '../../page-registry';
import { useNativePageDocument } from '../pages/native-page-shell';
import { createBrowserHackbotService, type HackbotRecord } from './service';

type View = 'chat' | 'agents' | 'models';
type Notice = { tone: 'info' | 'success' | 'error'; text: string };

const AGENT_LABELS: Record<string, string> = {
  orchestrator: 'Orquestrador',
  researcher: 'Pesquisador',
  analyst: 'Analista SARIF',
  document_analyst: 'Analista de documentos',
  tutor: 'Tutor',
};

function messageText(entry: HackbotRecord): string {
  return String(entry.content || entry.message || '').trim();
}

function modelOptionId(models: HackbotRecord[], binding: HackbotRecord): string {
  const match = models.find((item) => (
    item.source === 'artex' && binding?.source === 'artex'
      ? Number(item.profile_id) === Number(binding.profile_id)
      : item.source === 'codex-cli' && binding?.source === 'codex-cli'
        ? item.model === binding?.model
      : item.model === binding?.model && item.base_url === binding?.base_url
  ));
  return String(match?.id || 'custom');
}

function Usage({ value }: { value: HackbotRecord }) {
  if (!value || !(value.input_tokens || value.output_tokens || value.tool_calls)) return null;
  return (
    <small className="hackbot-usage">
      entrada {Number(value.input_tokens || 0).toLocaleString('pt-BR')} · saída {Number(value.output_tokens || 0).toLocaleString('pt-BR')} · ferramentas {Number(value.tool_calls || 0)}
    </small>
  );
}

function Trace({ steps }: { steps: HackbotRecord[] }) {
  if (!steps?.length) return null;
  return (
    <details className="hackbot-trace">
      <summary>Atividade dos agentes <span>{steps.length} eventos</span></summary>
      <ol>
        {steps.map((step, index) => (
          <li className={`is-${String(step.status || 'done')}`} key={String(step.id || index)}>
            <span>{String(step.agent || 'agente')}</span>
            <strong>{String(step.title || step.kind || 'atividade')}</strong>
            <small>{String(step.status || 'done')}</small>
          </li>
        ))}
      </ol>
    </details>
  );
}

function Message({ entry }: { entry: HackbotRecord }) {
  const role = String(entry.role || 'assistant');
  return (
    <article className={`hackbot-message is-${role}`}>
      <header>
        <strong>{role === 'user' ? 'Você' : role === 'error' ? 'Erro' : AGENT_LABELS[String(entry.agent)] || 'HackBot'}</strong>
        {entry.seconds ? <small>{Number(entry.seconds).toFixed(1)}s</small> : null}
      </header>
      <pre>{messageText(entry)}</pre>
      <Usage value={entry.usage || {}} />
      <Trace steps={entry.steps || []} />
      {entry.sources?.length ? (
        <details className="hackbot-evidence"><summary>Fontes · {entry.sources.length}</summary><pre>{JSON.stringify(entry.sources, null, 2)}</pre></details>
      ) : null}
      {entry.triage ? (
        <details className="hackbot-evidence"><summary>Triagem SARIF</summary><pre>{JSON.stringify(entry.triage, null, 2)}</pre></details>
      ) : null}
      {entry.doc_report ? (
        <details className="hackbot-evidence"><summary>Achados do documento</summary><pre>{JSON.stringify(entry.doc_report, null, 2)}</pre></details>
      ) : null}
    </article>
  );
}

export function HackbotWorkspace({ embedded = false }: { embedded?: boolean }) {
  const service = useMemo(() => createBrowserHackbotService(), []);
  const transcriptRef = useRef<HTMLDivElement | null>(null);
  const [view, setView] = useState<View>('chat');
  const [status, setStatus] = useState<HackbotRecord | null>(null);
  const [agents, setAgents] = useState<HackbotRecord[]>([]);
  const [models, setModels] = useState<HackbotRecord[]>([]);
  const [mcpServers, setMcpServers] = useState<HackbotRecord[]>([]);
  const [bindings, setBindings] = useState<Record<string, HackbotRecord>>({});
  const [conversations, setConversations] = useState<HackbotRecord[]>([]);
  const [conversationId, setConversationId] = useState('');
  const [entries, setEntries] = useState<HackbotRecord[]>([]);
  const [agent, setAgent] = useState('orchestrator');
  const [draft, setDraft] = useState('');
  const [documentPath, setDocumentPath] = useState('');
  const [documentKind, setDocumentKind] = useState<'document' | 'sarif'>('document');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<Notice | null>(null);

  const refresh = useCallback(async (quiet = false) => {
    try {
      const [nextStatus, nextAgents, nextModels, nextConversations] = await Promise.all([
        service.status(), service.agents(), service.models(), service.conversations(),
      ]);
      setStatus(nextStatus);
      setAgents(nextAgents.agents || nextStatus.agents || []);
      setModels(nextModels.models || []);
      setMcpServers(nextModels.mcp_servers || []);
      setBindings(nextStatus.config?.bindings || {});
      setConversations(nextConversations.conversations || []);
      if (!quiet) {
        const runtimeReady = nextStatus.online && nextStatus.runtime?.runtime_ready;
        setNotice(runtimeReady
          ? { tone: 'success', text: 'HackBot online. Escolha o orquestrador ou chame um especialista diretamente.' }
          : { tone: 'info', text: nextStatus.online ? 'Adaptador online; dependências do runtime HackBot ainda estão incompletas.' : `HackBot offline: ${nextStatus.error || 'serviço indisponível'}` });
      }
    } catch (error) {
      setNotice({ tone: 'error', text: error instanceof Error ? error.message : String(error) });
    }
  }, [service]);

  const loadConversation = useCallback(async (id: string) => {
    setConversationId(id);
    if (!id) { setEntries([]); return; }
    try {
      const result = await service.conversation(id);
      setEntries(result.session?.entries || []);
      if (result.conversation?.agent) setAgent(String(result.conversation.agent));
    } catch (error) {
      setNotice({ tone: 'error', text: error instanceof Error ? error.message : String(error) });
    }
  }, [service]);

  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    if (!conversationId && conversations[0]?.id) void loadConversation(String(conversations[0].id));
  }, [conversationId, conversations, loadConversation]);
  useEffect(() => {
    const node = transcriptRef.current;
    if (node) node.scrollTop = node.scrollHeight;
  }, [entries, busy]);

  const createConversation = async () => {
    try {
      const result = await service.createConversation({ agent, title: 'Nova conversa HackBot' });
      const row = result.conversation;
      setConversations((current) => [row, ...current]);
      setConversationId(String(row.id));
      setEntries([]);
      setView('chat');
    } catch (error) {
      setNotice({ tone: 'error', text: error instanceof Error ? error.message : String(error) });
    }
  };

  const removeConversation = async (id: string) => {
    if (!window.confirm('Apagar esta conversa HackBot e seu histórico local?')) return;
    try {
      await service.remove(id);
      const next = conversations.filter((row) => String(row.id) !== id);
      setConversations(next);
      if (conversationId === id) {
        setConversationId('');
        setEntries([]);
      }
    } catch (error) {
      setNotice({ tone: 'error', text: error instanceof Error ? error.message : String(error) });
    }
  };

  const send = async (event?: FormEvent) => {
    event?.preventDefault();
    const message = draft.trim();
    if (!message || busy) return;
    setBusy(true);
    setDraft('');
    let id = conversationId;
    try {
      if (!id) {
        const created = await service.createConversation({ agent, title: message.slice(0, 80) });
        id = String(created.conversation.id);
        setConversationId(id);
        setConversations((current) => [created.conversation, ...current]);
      }
      setEntries((current) => [...current, { role: 'user', content: message, agent }]);
      const body: HackbotRecord = { message, agent };
      if (documentPath.trim()) {
        body[documentKind === 'sarif' ? 'sarif_path' : 'document_path'] = documentPath.trim();
        body.document_desc = `Arquivo selecionado no painel HackBot (${documentKind})`;
      }
      const result = await service.send(id, body);
      setEntries(result.session?.entries || []);
      await refresh(true);
      setNotice({ tone: 'success', text: `${AGENT_LABELS[agent] || agent} concluiu a resposta.` });
    } catch (error) {
      const text = error instanceof Error ? error.message : String(error);
      setEntries((current) => [...current, { role: 'error', content: text, agent }]);
      setNotice({ tone: 'error', text });
    } finally {
      setBusy(false);
    }
  };

  const changeBinding = (name: string, field: string, value: string) => {
    setBindings((current) => ({ ...current, [name]: { ...(current[name] || {}), [field]: value } }));
  };

  const toggleMcp = (name: string, id: string, enabled: boolean) => {
    setBindings((current) => {
      const binding = current[name] || {};
      const selected = new Set(Array.isArray(binding.mcp_servers) ? binding.mcp_servers.map(String) : []);
      if (enabled) selected.add(id); else selected.delete(id);
      return { ...current, [name]: { ...binding, mcp_servers: [...selected] } };
    });
  };

  const selectCatalogModel = (name: string, id: string) => {
    if (id === 'custom') {
      setBindings((current) => ({
        ...current,
        [name]: { ...(current[name] || {}), source: 'direct', profile_id: null, provider: 'openai' },
      }));
      return;
    }
    const selected = models.find((item) => item.id === id);
    if (!selected) return;
    setBindings((current) => ({
      ...current,
      [name]: {
        ...(current[name] || {}),
        model: selected.model,
        base_url: selected.base_url,
        api_key_env: selected.api_key_env,
        source: selected.source || 'direct',
        profile_id: selected.profile_id || null,
        provider: selected.provider || 'openai',
        mcp_servers: selected.source === 'codex-cli'
          ? (Array.isArray(current[name]?.mcp_servers) ? current[name].mcp_servers : [])
          : [],
      },
    }));
  };

  const saveBindings = async () => {
    try {
      const result = await service.saveConfig({ bindings });
      setBindings(result.config?.bindings || bindings);
      setNotice({ tone: 'success', text: 'Roteamento por agente salvo. A próxima mensagem já usará os novos vínculos.' });
    } catch (error) {
      setNotice({ tone: 'error', text: error instanceof Error ? error.message : String(error) });
    }
  };

  const runtimeReady = Boolean(status?.online && status?.runtime?.runtime_ready);
  const missingDeps = Object.entries(status?.runtime?.dependencies || {}).filter(([, ready]) => !ready).map(([name]) => name);
  const selectedModelReady = Boolean(bindings[agent]?.configured);

  return (
    <div className={`hackbot-page-shell${embedded ? ' is-embedded' : ''}`}>
      <header className={embedded ? 'hackbot-embedded-header' : 'hackbot-topbar'}>
        {!embedded ? <a href="./index.html">← Cockpit</a> : null}
        <div><span>{embedded ? 'MOTOR MULTIAGENTE DA GHOSTIA' : 'GHOSTRECON · MULTIAGENTES'}</span><strong>{embedded ? 'Equipe HackBot' : 'HackBot'}</strong></div>
        <nav aria-label="Áreas do HackBot">
          {(['chat', 'agents', 'models'] as View[]).map((item) => (
            <button className={view === item ? 'is-active' : ''} key={item} onClick={() => setView(item)} type="button">
              {item === 'chat' ? 'Chat' : item === 'agents' ? 'Agentes' : 'Modelos'}
            </button>
          ))}
        </nav>
        <span className={`hackbot-runtime-state${runtimeReady ? ' is-online' : ''}`}>{runtimeReady ? 'RUNTIME ONLINE' : status?.online ? 'ADAPTADOR ONLINE' : 'OFFLINE'}</span>
      </header>

      {notice ? <div className={`hackbot-notice is-${notice.tone}`}>{notice.text}<button onClick={() => setNotice(null)} type="button">×</button></div> : null}
      {!runtimeReady && missingDeps.length ? <div className="hackbot-dependency-warning">Dependências pendentes: {missingDeps.join(', ')}. O painel e as configurações funcionam, mas os agentes não executam até o ambiente Python do HackBot estar pronto.</div> : null}
      {runtimeReady && !selectedModelReady ? <div className="hackbot-dependency-warning">O agente {AGENT_LABELS[agent] || agent} ainda não tem provider utilizável. Configure o vínculo na aba Modelos antes de enviar.</div> : null}

      {view === 'chat' ? (
        <div className="hackbot-chat-layout">
          <aside className="hackbot-conversations">
            <button className="hackbot-primary" onClick={() => void createConversation()} type="button">＋ Nova conversa</button>
            <div className="hackbot-conversation-list">
              {conversations.map((row) => (
                <div className={`hackbot-conversation${conversationId === String(row.id) ? ' is-active' : ''}`} key={String(row.id)}>
                  <button onClick={() => void loadConversation(String(row.id))} type="button">
                    <strong>{String(row.title || 'Conversa')}</strong>
                    <small>{AGENT_LABELS[String(row.agent)] || row.agent} · {String(row.last_status || 'idle')}</small>
                  </button>
                  <button aria-label="Apagar conversa" onClick={() => void removeConversation(String(row.id))} type="button">×</button>
                </div>
              ))}
              {!conversations.length ? <p>Nenhuma conversa ainda.</p> : null}
            </div>
          </aside>

          <main className="hackbot-chat-main">
            <div className="hackbot-chat-controls">
              <label>Agente ativo<select value={agent} onChange={(event) => setAgent(event.target.value)}>{agents.map((item) => <option key={String(item.name)} value={String(item.name)}>{String(item.label || AGENT_LABELS[String(item.name)] || item.name)}</option>)}</select></label>
              <label>Tipo do arquivo<select value={documentKind} onChange={(event) => setDocumentKind(event.target.value as 'document' | 'sarif')}><option value="document">Documento / código / log</option><option value="sarif">Relatório SARIF</option></select></label>
              <label className="is-wide">Arquivo permitido (opcional)<input onChange={(event) => setDocumentPath(event.target.value)} placeholder="reports/arquivo.sarif" value={documentPath} /></label>
            </div>
            <div className="hackbot-transcript" ref={transcriptRef}>
              {!entries.length ? (
                <div className="hackbot-empty"><span>HB</span><h1>Equipe HackBot</h1><p>Use o orquestrador para delegar, ou selecione um especialista para uma resposta direta. O histórico, as fontes e o tracing ficam nesta conversa.</p></div>
              ) : entries.map((entry, index) => <Message entry={entry} key={`${entry.role || 'entry'}-${index}`} />)}
              {busy ? <div className="hackbot-running"><i /><i /><i /><span>{AGENT_LABELS[agent] || agent} trabalhando…</span></div> : null}
            </div>
            <form className="hackbot-composer" onSubmit={(event) => void send(event)}>
              <textarea disabled={busy || !runtimeReady || !selectedModelReady} onChange={(event) => setDraft(event.target.value)} placeholder={runtimeReady && selectedModelReady ? 'Pergunte, peça pesquisa ou análise do arquivo selecionado…' : 'Configure as dependências e o modelo para executar os agentes.'} rows={3} value={draft} />
              <div><small>Orquestrador opcional · especialistas diretos · MCP/ACP preservados</small><button disabled={busy || !runtimeReady || !selectedModelReady || !draft.trim()} type="submit">{busy ? 'Executando…' : 'Enviar'}</button></div>
            </form>
          </main>
        </div>
      ) : null}

      {view === 'agents' ? (
        <main className="hackbot-section-page">
          <header><span>EQUIPE ORIGINAL PRESERVADA</span><h1>Agentes e ferramentas</h1><p>O orquestrador é apenas uma rota possível. Cada especialista continua disponível diretamente e mantém o conjunto mínimo de ferramentas do HackBot.</p></header>
          <div className="hackbot-agent-grid">
            {agents.map((item) => (
              <article key={String(item.name)}>
                <div><span>{String(item.name).slice(0, 2).toUpperCase()}</span><small>{item.name === 'orchestrator' ? 'OPCIONAL' : 'ESPECIALISTA'}</small></div>
                <h2>{String(item.label || AGENT_LABELS[String(item.name)] || item.name)}</h2>
                <p>{String(item.role || '')}</p>
                <strong>{String(item.binding?.model || bindings[String(item.name)]?.model || 'sem modelo')}</strong>
                <ul>{(item.tools || []).map((tool: string) => <li key={tool}>{tool}</li>)}</ul>
                <button onClick={() => { setAgent(String(item.name)); setView('chat'); }} type="button">Usar este agente</button>
              </article>
            ))}
          </div>
        </main>
      ) : null}

      {view === 'models' ? (
        <main className="hackbot-section-page hackbot-model-page">
          <header><span>ROTEAMENTO POR FUNÇÃO</span><h1>Um modelo para cada agente</h1><p>Use um perfil seguro do GhostIA/Artex, um preset OpenAI-compatible ou o modo Personalizado. Perfis reutilizam OpenAI, Codex, Claude, OpenRouter, DeepSeek, Kimi, GLM e outros sem copiar a chave.</p></header>
          <div className="hackbot-model-list">
            {agents.map((item) => {
              const name = String(item.name);
              const binding = bindings[name] || {};
              return (
                <article key={name}>
                  <header><div><small>{name === 'orchestrator' ? 'ROTA OPCIONAL' : 'ESPECIALISTA'}</small><h2>{String(item.label || AGENT_LABELS[name] || name)}</h2></div><span className={binding.configured ? 'is-ready' : ''}>{binding.source === 'artex' ? 'PERFIL GHOSTIA' : binding.configured ? 'CONFIGURADO' : 'SEM CHAVE'}</span></header>
                  <div className="hackbot-model-fields">
                    <label>Catálogo<select onChange={(event) => selectCatalogModel(name, event.target.value)} value={modelOptionId(models, binding)}><option value="custom">Personalizado</option>{models.map((model) => <option key={String(model.id)} value={String(model.id)}>{String(model.label)}</option>)}</select></label>
                    <label>Modelo<input onChange={(event) => changeBinding(name, 'model', event.target.value)} value={String(binding.model || '')} /></label>
                    {binding.source === 'artex' ? <><label className="is-wide">Origem<input readOnly value={`GhostIA/Artex · perfil #${String(binding.profile_id || '')}`} /></label><label>Formato<input readOnly value={String(binding.provider || 'perfil')} /></label></> : binding.source === 'codex-cli' ? <><label className="is-wide">Origem<input readOnly value="Codex CLI · login e MCPs do CODEX_HOME" /></label><label>Execução<input readOnly value="codex exec isolado" /></label></> : <><label className="is-wide">Base URL<input onChange={(event) => changeBinding(name, 'base_url', event.target.value)} value={String(binding.base_url || '')} /></label><label>Variável da chave<input onChange={(event) => changeBinding(name, 'api_key_env', event.target.value.toUpperCase())} value={String(binding.api_key_env || 'OPENAI_API_KEY')} /></label></>}
                    {binding.source === 'codex-cli' ? <fieldset className="hackbot-mcp-picker is-wide"><legend>MCPs desta instância Codex</legend><p>O Mind continua no seu Codex; o GHOSTRECON apenas liga ou desliga por execução.</p><div>{mcpServers.map((server) => <label key={String(server.id)}><input type="checkbox" disabled={server.available === false} checked={(binding.mcp_servers || []).includes(server.id)} onChange={(event) => toggleMcp(name, String(server.id), event.currentTarget.checked)} /><span><strong>{String(server.label)}</strong><small>{String(server.description || '')}</small></span></label>)}</div></fieldset> : null}
                  </div>
                </article>
              );
            })}
          </div>
          <div className="hackbot-save-bar"><p>Os modelos locais do catálogo são sugestões e não foram baixados automaticamente.</p><button onClick={() => void saveBindings()} type="button">Salvar roteamento</button></div>
        </main>
      ) : null}
    </div>
  );
}

export function HackbotPage({ page }: { page: ReactUiPage }) {
  useNativePageDocument(page, 'hackbot');
  return <HackbotWorkspace />;
}
