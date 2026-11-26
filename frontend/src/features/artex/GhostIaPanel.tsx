import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createBrowserArtexService, type ArtexRecord } from './service';

function messageText(item: ArtexRecord): string {
  const detail = item?.detail;
  if (typeof detail === 'string' && detail.trim()) {
    try {
      const parsed = JSON.parse(detail);
      if (parsed?.text) return String(parsed.text);
    } catch { return detail; }
    return detail;
  }
  return String(item?.summary || item?.message || item?.kind || 'evento');
}

export function GhostIaPanel() {
  const service = useMemo(() => createBrowserArtexService(), []);
  const [status, setStatus] = useState<ArtexRecord | null>(null);
  const [conversationId, setConversationId] = useState<string>('');
  const [messages, setMessages] = useState<ArtexRecord[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('Verificando backend Artex…');
  const [profileId, setProfileId] = useState('');
  const transcriptRef = useRef<HTMLDivElement | null>(null);

  const refreshStatus = useCallback(async () => {
    try {
      const next = await service.status();
      setStatus(next);
      const defaultProfile = (next.profiles || []).find((profile: ArtexRecord) => profile.is_default);
      if (!profileId && defaultProfile?.id) setProfileId(String(defaultProfile.id));
      const existing = (next.conversations || []).find((row: ArtexRecord) => row.agent_key === 'ghostia');
      if (!conversationId && existing?.id) setConversationId(String(existing.id));
      setNotice(next.online ? 'GhostIA online · MCP e Cortex integrados' : 'GhostIA offline');
    } catch (error) {
      setStatus(null);
      setNotice(error instanceof Error ? error.message : String(error));
    }
  }, [conversationId, profileId, service]);

  const refreshMessages = useCallback(async (id = conversationId) => {
    if (!id) return;
    try {
      const data = await service.messages(id, 0);
      setMessages(Array.isArray(data.items) ? data.items : []);
      setBusy(data.running === true);
      requestAnimationFrame(() => transcriptRef.current?.scrollTo({ top: transcriptRef.current.scrollHeight }));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    }
  }, [conversationId, service]);

  useEffect(() => { void refreshStatus(); }, [refreshStatus]);
  useEffect(() => {
    if (!conversationId) return undefined;
    void refreshMessages(conversationId);
    const timer = window.setInterval(() => void refreshMessages(conversationId), busy ? 1_100 : 3_500);
    return () => window.clearInterval(timer);
  }, [busy, conversationId, refreshMessages]);

  const newConversation = async () => {
    setBusy(true);
    try {
      const data = await service.createConversation({
        title: `GhostIA · ${new Date().toLocaleString('pt-BR')}`,
        ...(profileId ? { llm_profile_id: Number(profileId) } : {}),
      });
      const id = String(data.conversation?.id || '');
      setConversationId(id);
      setMessages([]);
      setNotice('Nova conversa GhostIA criada.');
    } catch (error) { setNotice(error instanceof Error ? error.message : String(error)); }
    finally { setBusy(false); }
  };

  const send = async () => {
    const message = input.trim();
    if (!message || busy) return;
    setBusy(true);
    setInput('');
    try {
      let id = conversationId;
      if (!id) {
        const created = await service.createConversation({
          title: message.slice(0, 80),
          ...(profileId ? { llm_profile_id: Number(profileId) } : {}),
        });
        id = String(created.conversation?.id || '');
        setConversationId(id);
      }
      await service.sendMessage(id, message);
      setNotice('GhostIA processando…');
      await refreshMessages(id);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
      setBusy(false);
    }
  };

  const connectPlan = async () => {
    try {
      const data = await service.connectChatGptPlan();
      const url = String(data.authorization_url || '');
      if (url) window.open(url, 'ghostia-chatgpt-plan', 'popup,width=680,height=800');
      setNotice('Conclua a autenticação do ChatGPT Plan na janela aberta.');
    } catch (error) { setNotice(error instanceof Error ? error.message : String(error)); }
  };

  return (
    <section className="ghostia-panel" id="ghostIaPanel" aria-labelledby="ghostIaPanelTitle">
      <header className="ghostia-panel-head">
        <div>
          <span className="ghostia-kicker">ARTEX BACKEND · GHOSTRECON MCP</span>
          <h3 id="ghostIaPanelTitle">GhostIA</h3>
          <p>{notice}</p>
        </div>
        <span className={`ghostia-state ${status?.online ? 'is-online' : 'is-offline'}`}>{status?.online ? 'ONLINE' : 'OFFLINE'}</span>
      </header>
      <div className="ghostia-toolbar">
        <label>Modelo
          <select value={profileId} onChange={(event) => setProfileId(event.currentTarget.value)}>
            <option value="">perfil ativo do Artex</option>
            {(status?.profiles || []).map((profile: ArtexRecord) => <option key={profile.id} value={profile.id}>{profile.name} · {profile.model}</option>)}
          </select>
        </label>
        <button type="button" onClick={() => void newConversation()} disabled={!status?.online || busy}>Nova conversa</button>
        <button type="button" onClick={() => void service.ensureIntegration().then(refreshStatus).catch((error) => setNotice(error.message))} disabled={!status?.online || !status?.canManage}>Validar MCP</button>
        <button type="button" onClick={() => void connectPlan()} disabled={!status?.canManage}>{status?.chatgptPlan?.connected ? 'ChatGPT conectado' : 'Conectar ChatGPT Plan'}</button>
      </div>
      <div className="ghostia-transcript" ref={transcriptRef} aria-live="polite">
        {!messages.length ? <div className="ghostia-empty">Converse com a GhostIA sem sair do GHOSTRECON. Ela recebe o prompt de pentest privado, usa o MCP e mantém os gates do modo Auto.</div> : null}
        {messages.map((item, index) => {
          const human = item.kind === 'user';
          return <article className={`ghostia-message ${human ? 'is-user' : 'is-agent'}`} key={item.seq || index}><span>{human ? 'Você' : item.worker || 'GhostIA'}</span><pre>{messageText(item)}</pre></article>;
        })}
      </div>
      <div className="ghostia-compose">
        <textarea
          id="ghostIaMessageInput"
          value={input}
          onChange={(event) => setInput(event.currentTarget.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); void send(); }
          }}
          placeholder="Pergunte à GhostIA ou peça uma análise… (Enter envia; Shift+Enter quebra linha)"
          disabled={!status?.online}
        />
        <div>
          {busy && conversationId ? <button type="button" className="ghostia-stop" onClick={() => void service.stopConversation(conversationId).then(() => setBusy(false))}>Parar</button> : null}
          <button type="button" className="ghostia-send" onClick={() => void send()} disabled={!input.trim() || busy || !status?.online}>Enviar</button>
        </div>
      </div>
    </section>
  );
}
