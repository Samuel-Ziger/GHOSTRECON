import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
} from 'react';
import type { ReactUiPage } from '../../page-registry';
import { useNativePageDocument } from '../pages/native-page-shell';
import { createBrowserArtexService, type ArtexRecord } from './service';
import { HackbotWorkspace } from '../hackbot/HackbotPage';
import { NeuroSploitWorkspace } from '../neurosploit/NeuroSploitWorkspace';

type NoticeTone = 'info' | 'success' | 'error';
type Notice = { tone: NoticeTone; text: string };

const PROFILE_DRAFT = {
  name: 'OpenAI API',
  format: 'openai-responses',
  model: '',
  base_url: 'https://api.openai.com/v1',
  api_key: '',
  reasoning_effort: '',
  context_window_k: 200,
  max_tokens: 0,
  streaming: true,
};

const DETAIL_KINDS = new Set(['user', 'text', 'result', 'thinking', 'tool_use', 'tool_result']);
const ASSISTANT_KINDS = new Set(['text', 'result']);
const STORAGE_CONVERSATION = 'ghostrecon.ghostia.conversation';

function translateKnownArtexMessage(value: string): string {
  const text = value.trim();
  if (/No LLM configuration exists yet/i.test(text)) {
    return 'Nenhum perfil LLM foi configurado no Artex. Abra “Adicionar perfil LLM”, escolha API ou ChatGPT Plan/Codex e clique em “Guardar e ativar”.';
  }
  if (/No LLM configuration is enabled/i.test(text)) {
    return 'Existe um perfil LLM, mas nenhum está ativo. Selecione um perfil e clique em “Guardar e ativar” ou ative-o antes de conversar.';
  }
  if (/Cannot start a conversation because the LLM is not ready/i.test(text)) {
    return 'O perfil LLM do Artex ainda não está pronto. Teste o provider e confirme que ele está ativo antes de enviar a mensagem.';
  }
  if (/cannot delete the active LLM profile|active LLM configuration cannot be deleted/i.test(text)) {
    return 'O Artex não permite apagar o perfil ativo. Ative outro perfil primeiro.';
  }
  return text;
}

function errorMessage(error: unknown): string {
  return translateKnownArtexMessage(error instanceof Error ? error.message : String(error));
}

function isTextModel(model: string): boolean {
  return !/(audio|embedding|image|moderation|realtime|transcri|tts|whisper|dall-e)/i.test(model);
}

function safeStorageGet(key: string): string {
  try { return window.localStorage.getItem(key) || ''; } catch { return ''; }
}

function safeStorageSet(key: string, value: string): void {
  try {
    if (value) window.localStorage.setItem(key, value);
    else window.localStorage.removeItem(key);
  } catch { /* storage indisponível: estado em memória continua funcional */ }
}

function recordText(item: ArtexRecord): string {
  const detail = String(item.detail || '').trim();
  if (detail) {
    try {
      const parsed = JSON.parse(detail);
      if (typeof parsed?.text === 'string') return translateKnownArtexMessage(parsed.text);
    } catch { /* detail textual */ }
    return translateKnownArtexMessage(detail);
  }
  return translateKnownArtexMessage(String(item.summary || item.message || item.kind || 'evento'));
}

function kindLabel(item: ArtexRecord): string {
  if (item.kind === 'user') return 'Você';
  if (item.is_error) return 'Erro do Artex';
  if (item.kind === 'thinking') return 'Raciocínio';
  if (item.kind === 'tool_use') return `Ferramenta · ${String(item.tool || 'execução')}`;
  if (item.kind === 'tool_result') return `Resultado · ${String(item.tool || 'ferramenta')}`;
  if (item.kind === 'usage') return 'Uso do modelo';
  return String(item.worker || 'GhostIA');
}

function isConversationRunning(conversations: ArtexRecord[], id: string): boolean {
  return conversations.some((item) => String(item.id) === id && item.running === true);
}

function GhostIaActivity({ item }: { item: ArtexRecord }) {
  if (item.kind === 'usage') return null;
  const text = recordText(item);
  const toolTrace = item.kind === 'tool_use' || item.kind === 'tool_result' || item.kind === 'thinking';
  if (toolTrace) {
    return (
      <details className={`ghostia-page-trace${item.is_error ? ' is-error' : ''}`}>
        <summary><span>{kindLabel(item)}</span><small>{String(item.summary || '').slice(0, 140)}</small></summary>
        <pre>{text}</pre>
      </details>
    );
  }
  return (
    <article className={`ghostia-page-message ${item.kind === 'user' ? 'is-user' : 'is-agent'}${item.is_error ? ' is-error' : ''}`}>
      <div className="ghostia-page-message-meta">
        <strong>{kindLabel(item)}</strong>
        {item.ts ? <time>{new Date(String(item.ts)).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })}</time> : null}
      </div>
      <pre>{text}</pre>
      {item.kind === 'result' && (item.input_tokens || item.output_tokens) ? (
        <small className="ghostia-page-token-line">
          entrada {Number(item.input_tokens || 0).toLocaleString('pt-BR')} · saída {Number(item.output_tokens || 0).toLocaleString('pt-BR')} tokens
        </small>
      ) : null}
    </article>
  );
}

export function GhostIaPage({ page }: { page: ReactUiPage }) {
  useNativePageDocument(page, 'ghostia');
  const service = useMemo(() => createBrowserArtexService(), []);
  const transcriptRef = useRef<HTMLDivElement | null>(null);
  const detailCache = useRef(new Map<string, string>());
  const loadingMessages = useRef(false);
  const activeConversation = useRef('');
  const [status, setStatus] = useState<ArtexRecord | null>(null);
  const [profileId, setProfileId] = useState('');
  const [conversationId, setConversationId] = useState('');
  const [messages, setMessages] = useState<ArtexRecord[]>([]);
  const [draft, setDraft] = useState('');
  const [pendingUser, setPendingUser] = useState('');
  const [busy, setBusy] = useState(false);
  const [testing, setTesting] = useState(false);
  const [savingProfile, setSavingProfile] = useState(false);
  const [loadingModels, setLoadingModels] = useState(false);
  const [connectingPlan, setConnectingPlan] = useState(false);
  const [deletingProfileId, setDeletingProfileId] = useState('');
  const [deletingConversationId, setDeletingConversationId] = useState('');
  const [availableModels, setAvailableModels] = useState<string[]>([]);
  const [profileDraft, setProfileDraft] = useState(PROFILE_DRAFT);
  const [notice, setNotice] = useState<Notice>({ tone: 'info', text: 'Verificando o backend Artex…' });
  const [workspaceMode, setWorkspaceMode] = useState<'artex' | 'hackbot' | 'neurosploit'>('artex');

  const profiles = Array.isArray(status?.profiles) ? status.profiles as ArtexRecord[] : [];
  const conversations = Array.isArray(status?.conversations) ? status.conversations as ArtexRecord[] : [];
  const selectedProfile = profiles.find((item) => String(item.id) === profileId) || null;
  const selectedConversation = conversations.find((item) => String(item.id) === conversationId) || null;
  const llmReady = Boolean(selectedProfile);

  const refreshStatus = useCallback(async (quiet = false) => {
    try {
      const next = await service.status();
      setStatus(next);
      const nextProfiles = Array.isArray(next.profiles) ? next.profiles as ArtexRecord[] : [];
      const nextConversations = Array.isArray(next.conversations) ? next.conversations as ArtexRecord[] : [];
      setProfileId((current) => {
        if (current && nextProfiles.some((item) => String(item.id) === current)) return current;
        const preferred = nextProfiles.find((item) => item.is_default) || nextProfiles[0];
        return preferred?.id ? String(preferred.id) : '';
      });
      setConversationId((current) => {
        if (current && nextConversations.some((item) => String(item.id) === current)) return current;
        const stored = safeStorageGet(STORAGE_CONVERSATION);
        if (stored && nextConversations.some((item) => String(item.id) === stored)) return stored;
        return nextConversations[0]?.id ? String(nextConversations[0].id) : '';
      });
      if (!quiet) setNotice({ tone: 'success', text: 'GhostIA online. Escolha um perfil e envie uma mensagem.' });
      return next;
    } catch (error) {
      setStatus(null);
      setNotice({ tone: 'error', text: errorMessage(error) });
      throw error;
    }
  }, [service]);

  const hydrateDetails = useCallback(async (id: string, items: ArtexRecord[]): Promise<ArtexRecord[]> => {
    const candidates = items.filter((item) => item.seq && DETAIL_KINDS.has(String(item.kind)));
    await Promise.all(candidates.map(async (item) => {
      const key = `${id}:${String(item.seq)}`;
      if (detailCache.current.has(key)) return;
      try {
        const response = await service.messageDetail(id, String(item.seq));
        detailCache.current.set(key, String(response.detail || ''));
      } catch {
        detailCache.current.set(key, '');
      }
    }));
    return items.map((item): ArtexRecord => ({
      ...item,
      detail: item.detail || detailCache.current.get(`${id}:${String(item.seq)}`) || '',
    }));
  }, [service]);

  const refreshMessages = useCallback(async (id: string, quiet = true) => {
    if (!id || loadingMessages.current) return;
    loadingMessages.current = true;
    try {
      const response = await service.messages(id, 0);
      const raw = Array.isArray(response.items) ? response.items as ArtexRecord[] : [];
      const enriched = await hydrateDetails(id, raw);
      if (activeConversation.current !== id) return;
      setMessages(enriched);
      setBusy(response.running === true);
      if (raw.some((item) => item.kind === 'user')) setPendingUser('');
      const lastError = [...enriched].reverse().find((item) => item.is_error);
      if (lastError && response.running !== true) {
        setNotice({ tone: 'error', text: recordText(lastError) });
      } else if (response.running === true) {
        setNotice({ tone: 'info', text: 'GhostIA está processando a mensagem…' });
      } else if (!quiet) {
        setNotice({ tone: 'success', text: 'Conversa atualizada.' });
      }
      requestAnimationFrame(() => transcriptRef.current?.scrollTo({ top: transcriptRef.current.scrollHeight, behavior: 'smooth' }));
    } catch (error) {
      if (activeConversation.current === id) {
        setNotice({ tone: 'error', text: errorMessage(error) });
        setBusy(false);
      }
    } finally {
      loadingMessages.current = false;
    }
  }, [hydrateDetails, service]);

  useEffect(() => {
    void refreshStatus();
    const timer = window.setInterval(() => void refreshStatus(true).catch(() => undefined), 15_000);
    return () => window.clearInterval(timer);
  }, [refreshStatus]);

  useEffect(() => {
    const planConnected = (event: MessageEvent) => {
      if (event.data?.type !== 'artex-chatgpt-plan') return;
      void refreshStatus(true).then(() => {
        setNotice(event.data?.ok
          ? { tone: 'success', text: 'Conta ChatGPT conectada. Agora carregue e selecione um modelo Codex.' }
          : { tone: 'error', text: 'O login do ChatGPT Plan não foi concluído.' });
      }).catch((error) => setNotice({ tone: 'error', text: errorMessage(error) }));
    };
    window.addEventListener('message', planConnected);
    return () => window.removeEventListener('message', planConnected);
  }, [refreshStatus]);

  useEffect(() => {
    activeConversation.current = conversationId;
    safeStorageSet(STORAGE_CONVERSATION, conversationId);
    setMessages([]);
    setPendingUser('');
    setBusy(isConversationRunning(conversations, conversationId));
    if (conversationId) void refreshMessages(conversationId, false);
  }, [conversationId]); // conversations/refreshMessages são lidos na troca, não devem reiniciar o polling

  useEffect(() => {
    if (!conversationId) return undefined;
    const timer = window.setInterval(() => void refreshMessages(conversationId), busy ? 900 : 3_500);
    return () => window.clearInterval(timer);
  }, [busy, conversationId, refreshMessages]);

  const chooseProfile = (nextId: string) => {
    if (nextId === profileId) return;
    setProfileId(nextId);
    setConversationId('');
    setMessages([]);
    setNotice({ tone: 'info', text: 'Perfil alterado. A próxima mensagem abrirá uma nova conversa com esse modelo.' });
  };

  const chooseConversation = (conversation: ArtexRecord) => {
    const id = String(conversation.id || '');
    if (conversation.llm_profile_id) setProfileId(String(conversation.llm_profile_id));
    setConversationId(id);
  };

  const createConversation = async (): Promise<string> => {
    const response = await service.createConversation({
      title: `GhostIA · ${new Date().toLocaleString('pt-BR')}`,
      ...(profileId ? { llm_profile_id: Number(profileId) } : {}),
    });
    const id = String(response.conversation?.id || '');
    if (!id) throw new Error('Artex não devolveu o ID da nova conversa');
    setConversationId(id);
    activeConversation.current = id;
    await refreshStatus(true).catch(() => undefined);
    return id;
  };

  const newConversation = () => {
    setConversationId('');
    setMessages([]);
    setBusy(false);
    setNotice({ tone: 'info', text: 'Nova conversa pronta. Ela usará o perfil selecionado.' });
  };

  const deleteConversation = async (conversation: ArtexRecord) => {
    const id = String(conversation.id || '');
    if (!id || deletingConversationId) return;
    const title = String(conversation.title || `Conversa #${id}`);
    if (!window.confirm(`Apagar definitivamente a conversa “${title}”?`)) return;
    setDeletingConversationId(id);
    try {
      await service.deleteConversation(id);
      if (conversationId === id) {
        setConversationId('');
        setMessages([]);
        setBusy(false);
      }
      await refreshStatus(true);
      setNotice({ tone: 'success', text: `Conversa #${id} apagada.` });
    } catch (error) {
      setNotice({ tone: 'error', text: errorMessage(error) });
    } finally {
      setDeletingConversationId('');
    }
  };

  const send = async (event?: FormEvent) => {
    event?.preventDefault();
    const message = draft.trim();
    if (!message || busy || !status?.online) return;
    if (!llmReady) {
      setNotice({
        tone: 'error',
        text: 'Configure e selecione um perfil LLM antes de conversar. Abra “Adicionar perfil LLM” na coluna esquerda.',
      });
      return;
    }
    setDraft('');
    setPendingUser(message);
    setBusy(true);
    setNotice({ tone: 'info', text: 'Enviando para o Artex…' });
    try {
      const id = conversationId || await createConversation();
      await service.sendMessage(id, message);
      setNotice({ tone: 'info', text: 'Mensagem aceita. GhostIA está processando…' });
      await refreshMessages(id, false);
    } catch (error) {
      setPendingUser('');
      setBusy(false);
      setNotice({ tone: 'error', text: errorMessage(error) });
    }
  };

  const stop = async () => {
    if (!conversationId) return;
    try {
      await service.stopConversation(conversationId);
      setNotice({ tone: 'info', text: 'Cancelamento solicitado ao Artex.' });
      setBusy(false);
      await refreshMessages(conversationId, false);
    } catch (error) {
      setNotice({ tone: 'error', text: errorMessage(error) });
    }
  };

  const testProvider = async () => {
    if (!profileId) {
      setNotice({ tone: 'error', text: 'Selecione um perfil LLM antes do teste.' });
      return;
    }
    setTesting(true);
    setNotice({ tone: 'info', text: 'Executando uma chamada real e curta ao provider…' });
    try {
      const response = await service.testProfile(profileId);
      const result = response.result || response;
      setNotice({
        tone: 'success',
        text: `Provider respondeu em ${Number(result.latency_ms || 0)} ms: ${String(result.reply || 'OK')}`,
      });
    } catch (error) {
      setNotice({ tone: 'error', text: errorMessage(error) });
    } finally {
      setTesting(false);
    }
  };

  const deleteProfile = async () => {
    if (!selectedProfile || deletingProfileId) return;
    const id = String(selectedProfile.id || '');
    const name = String(selectedProfile.name || `Perfil #${id}`);
    const replacement = selectedProfile.is_default
      ? profiles.find((profile) => String(profile.id) !== id)
      : null;
    if (selectedProfile.is_default && !replacement) {
      setNotice({
        tone: 'error',
        text: 'Este é o único perfil e está ativo. Crie outro perfil, ative-o e depois apague este.',
      });
      return;
    }
    const switchText = replacement
      ? `\n\nO perfil ativo será trocado automaticamente para “${String(replacement.name || `Perfil #${replacement.id}`)}”.`
      : '';
    if (!window.confirm(`Apagar definitivamente o perfil de IA “${name}”?${switchText}`)) return;
    setDeletingProfileId(id);
    setNotice({
      tone: 'info',
      text: replacement ? 'Trocando o perfil ativo e apagando o perfil selecionado…' : 'Apagando o perfil selecionado…',
    });
    try {
      if (replacement?.id) await service.activateProfile(String(replacement.id));
      await service.deleteProfile(id);
      setProfileId(replacement?.id ? String(replacement.id) : '');
      setConversationId('');
      setMessages([]);
      setBusy(false);
      await refreshStatus(true);
      setNotice({ tone: 'success', text: `Perfil “${name}” apagado definitivamente.` });
    } catch (error) {
      await refreshStatus(true).catch(() => undefined);
      setNotice({ tone: 'error', text: errorMessage(error) });
    } finally {
      setDeletingProfileId('');
    }
  };

  const loadModels = async () => {
    const usesPlan = profileDraft.format === 'chatgpt-plan';
    if (usesPlan && !status?.chatgptPlan?.connected) {
      setNotice({ tone: 'error', text: 'Conecte sua conta ChatGPT antes de carregar os modelos Codex.' });
      return;
    }
    if (!usesPlan && !profileDraft.api_key.trim()) {
      setNotice({ tone: 'error', text: 'Informe a API key para carregar os modelos disponíveis nessa conta.' });
      return;
    }
    setLoadingModels(true);
    setNotice({ tone: 'info', text: 'Consultando os modelos disponíveis no provider…' });
    try {
      const response = usesPlan
        ? await service.chatGptPlanModels()
        : await service.listModels({
          provider: profileDraft.format,
          base_url: profileDraft.base_url,
          api_key: profileDraft.api_key,
        });
      const result = response.result || response;
      const listedModels: unknown[] = Array.isArray(result.models) ? result.models : [];
      const models: string[] = [...new Set(listedModels
        .map((model) => String(model).trim())
        .filter((model) => model && isTextModel(model)))]
        .sort((left, right) => left.localeCompare(right));
      if (!models.length) throw new Error('O provider não devolveu modelos de texto compatíveis.');
      setAvailableModels(models);
      setProfileDraft((current) => ({
        ...current,
        model: models.includes(current.model) ? current.model : models[0],
      }));
      setNotice({ tone: 'success', text: `${models.length} opção(ões) de modelo carregada(s). Selecione uma na lista.` });
    } catch (error) {
      setAvailableModels([]);
      setProfileDraft((current) => ({ ...current, model: '' }));
      setNotice({ tone: 'error', text: errorMessage(error) });
    } finally {
      setLoadingModels(false);
    }
  };

  const connectChatGptPlan = async () => {
    setConnectingPlan(true);
    const popup = window.open('', 'ghostia-chatgpt-plan', 'popup,width=680,height=800');
    setNotice({ tone: 'info', text: 'Preparando o login do ChatGPT Plan…' });
    try {
      const response = await service.connectChatGptPlan();
      const authorizationUrl = String(response.authorization_url || '');
      if (!authorizationUrl) throw new Error('Artex não devolveu a URL de login do ChatGPT.');
      if (popup) popup.location.href = authorizationUrl;
      else window.open(authorizationUrl, 'ghostia-chatgpt-plan', 'popup,width=680,height=800');
      setNotice({ tone: 'info', text: 'Conclua o login na janela do ChatGPT. O GhostIA reconhecerá a conexão automaticamente.' });
    } catch (error) {
      popup?.close();
      setNotice({ tone: 'error', text: errorMessage(error) });
    } finally {
      setConnectingPlan(false);
    }
  };

  const saveProfile = async (event: FormEvent) => {
    event.preventDefault();
    const usesPlan = profileDraft.format === 'chatgpt-plan';
    if (!profileDraft.model.trim() || (!usesPlan && !profileDraft.api_key.trim())) {
      setNotice({ tone: 'error', text: usesPlan ? 'Selecione um modelo Codex para criar o perfil.' : 'Selecione o modelo e informe a API key para criar o perfil.' });
      return;
    }
    if (usesPlan && !status?.chatgptPlan?.connected) {
      setNotice({ tone: 'error', text: 'Conecte sua conta ChatGPT antes de guardar o perfil Codex.' });
      return;
    }
    setSavingProfile(true);
    setNotice({ tone: 'info', text: 'Guardando e ativando o perfil no Artex…' });
    try {
      const response = await service.saveProfile(profileDraft);
      const id = String(response.result?.id || '');
      if (!id) throw new Error('Artex não devolveu o ID do perfil');
      await service.activateProfile(id);
      setProfileDraft((current) => ({ ...current, api_key: '' }));
      await refreshStatus(true);
      setProfileId(id);
      setConversationId('');
      setNotice({ tone: 'success', text: `Perfil #${id} guardado e ativado. Use “Testar provider” antes do chat.` });
    } catch (error) {
      setNotice({ tone: 'error', text: errorMessage(error) });
    } finally {
      setSavingProfile(false);
    }
  };

  const visibleMessages = messages.filter((item) => item.kind !== 'usage');
  const hasAssistantReply = visibleMessages.some((item) => ASSISTANT_KINDS.has(String(item.kind)) && !item.is_error);

  return (
    <div className="ghostia-page-shell">
      <header className="ghostia-page-topbar">
        <a className="ghostia-page-back" href="./index.html">← Cockpit</a>
        <div className="ghostia-page-brand">
          <div className="ghostia-page-identity"><span>GHOSTRECON · IA</span><strong>GhostIA</strong></div>
          <nav className="ghostia-page-mode-switch" aria-label="Modo da GhostIA">
            <button className={workspaceMode === 'artex' ? 'is-active' : ''} onClick={() => setWorkspaceMode('artex')} type="button">Chat Artex</button>
            <button className={workspaceMode === 'hackbot' ? 'is-active' : ''} onClick={() => setWorkspaceMode('hackbot')} type="button">Multiagentes</button>
            <button className={workspaceMode === 'neurosploit' ? 'is-active' : ''} onClick={() => setWorkspaceMode('neurosploit')} type="button">NeuroSploit</button>
          </nav>
        </div>
        <div className={`ghostia-page-online ${status?.online ? 'is-online' : 'is-offline'}`}>
          <span />{workspaceMode === 'hackbot' ? 'HackBot integrado' : workspaceMode === 'neurosploit' ? 'Motor de engagements' : status?.online ? 'Artex online' : 'Artex offline'}
        </div>
      </header>

      {workspaceMode === 'artex' ? <><aside className="ghostia-page-sidebar">
        <section className="ghostia-page-provider">
          <div className="ghostia-page-section-title"><span>Provider</span><button type="button" onClick={() => void refreshStatus()}>Atualizar</button></div>
          <label>
            Perfil ativo para nova conversa
            <select id="ghostIaProfileSelect" value={profileId} onChange={(event) => chooseProfile(event.currentTarget.value)}>
              <option value="">{profiles.length ? 'selecione um perfil' : 'nenhum perfil configurado'}</option>
              {profiles.map((profile) => <option key={profile.id} value={String(profile.id)}>{String(profile.name || 'Perfil')} · {String(profile.model || 'modelo')}{profile.is_default ? ' · ativo' : ''}</option>)}
            </select>
          </label>
          <div className="ghostia-page-provider-meta">
            <span>{selectedProfile ? String(selectedProfile.format || 'provider') : 'configuração necessária'}</span>
            <span>{selectedProfile?.api_key_hint ? `key …${String(selectedProfile.api_key_hint)}` : 'chave não exibida'}</span>
          </div>
          <div className="ghostia-page-provider-actions">
            <button className="ghostia-page-test" type="button" disabled={!status?.canManage || !profileId || testing || Boolean(deletingProfileId)} onClick={() => void testProvider()}>
              {testing ? 'Testando…' : 'Testar provider'}
            </button>
            <button className="ghostia-page-delete-profile" type="button" disabled={!status?.canManage || !profileId || testing || Boolean(deletingProfileId)} onClick={() => void deleteProfile()}>
              {deletingProfileId === profileId ? 'Apagando…' : 'Apagar perfil'}
            </button>
          </div>
          {!status?.canManage ? <small>Somente admin pode configurar ou testar providers.</small> : null}
        </section>

        {status?.canManage ? (
          <details className="ghostia-page-config" open={profiles.length === 0 ? true : undefined}>
            <summary>Adicionar perfil LLM</summary>
            <form onSubmit={saveProfile}>
              <label>Nome<input value={profileDraft.name} onChange={(event) => setProfileDraft({ ...profileDraft, name: event.currentTarget.value })} /></label>
              <label>Formato<select value={profileDraft.format} onChange={(event) => { const format = event.currentTarget.value; setAvailableModels([]); setProfileDraft({ ...profileDraft, format, model: '', base_url: format === 'chatgpt-plan' ? '' : 'https://api.openai.com/v1', api_key: format === 'chatgpt-plan' ? '' : profileDraft.api_key }); }}><option value="chatgpt-plan">ChatGPT Plan / Codex</option><option value="openai-responses">OpenAI Responses (API)</option><option value="openai">OpenAI compatible</option><option value="anthropic">Anthropic</option></select></label>
              {profileDraft.format === 'chatgpt-plan' ? (
                <><div className={`ghostia-page-plan-status ${status?.chatgptPlan?.connected ? 'is-connected' : ''}`}>{status?.chatgptPlan?.connected ? 'Conta ChatGPT conectada' : 'Conta ChatGPT ainda não conectada'}</div><button type="button" disabled={connectingPlan} onClick={() => void connectChatGptPlan()}>{connectingPlan ? 'Abrindo login…' : status?.chatgptPlan?.connected ? 'Reconectar conta ChatGPT' : 'Conectar conta ChatGPT'}</button></>
              ) : (
                <><label>Base URL<input value={profileDraft.base_url} onChange={(event) => setProfileDraft({ ...profileDraft, base_url: event.currentTarget.value })} /></label><label>API key<input autoComplete="new-password" type="password" value={profileDraft.api_key} onChange={(event) => setProfileDraft({ ...profileDraft, api_key: event.currentTarget.value })} placeholder="nunca é devolvida pela API" /></label></>
              )}
              <button type="button" disabled={loadingModels || (profileDraft.format === 'chatgpt-plan' ? !status?.chatgptPlan?.connected : !profileDraft.api_key.trim())} onClick={() => void loadModels()}>{loadingModels ? 'Carregando modelos…' : profileDraft.format === 'chatgpt-plan' ? 'Carregar modelos Codex' : 'Carregar opções de modelo'}</button>
              <label>Modelo<select value={profileDraft.model} disabled={!availableModels.length || loadingModels} onChange={(event) => setProfileDraft({ ...profileDraft, model: event.currentTarget.value })}><option value="">{loadingModels ? 'consultando provider…' : availableModels.length ? 'selecione um modelo' : 'carregue as opções acima'}</option>{availableModels.map((model) => <option key={model} value={model}>{model}</option>)}</select></label>
              <label>Reasoning effort<select value={profileDraft.reasoning_effort} onChange={(event) => setProfileDraft({ ...profileDraft, reasoning_effort: event.currentTarget.value })}><option value="">padrão (não enviar)</option><option value="none">none</option><option value="off">off</option><option value="low">low</option><option value="medium">medium</option><option value="high">high</option><option value="xhigh">xhigh</option><option value="max">max</option></select></label>
              <button type="submit" disabled={savingProfile}>{savingProfile ? 'Guardando…' : 'Guardar e ativar'}</button>
            </form>
          </details>
        ) : null}

        <section className="ghostia-page-conversations">
          <div className="ghostia-page-section-title"><span>Conversas</span><button id="ghostIaNewConversation" type="button" onClick={newConversation}>+ Nova</button></div>
          <div className="ghostia-page-conversation-list">
            {conversations.length ? conversations.map((conversation) => (
              <div className="ghostia-page-conversation-row" key={conversation.id}>
                <button className={String(conversation.id) === conversationId ? 'is-active' : ''} onClick={() => chooseConversation(conversation)} type="button">
                  <strong>{String(conversation.title || `Conversa #${conversation.id}`)}</strong>
                  <small>{conversation.running ? 'processando agora' : `#${String(conversation.id)}`}</small>
                </button>
                <button className="ghostia-page-conversation-delete" type="button" disabled={Boolean(deletingConversationId)} onClick={() => void deleteConversation(conversation)} aria-label={`Apagar ${String(conversation.title || `conversa #${conversation.id}`)}`}>{deletingConversationId === String(conversation.id) ? '…' : '×'}</button>
              </div>
            )) : <p>Nenhuma conversa ainda.</p>}
          </div>
        </section>
      </aside>

      <main className="ghostia-page-main">
        <header className="ghostia-page-chat-head">
          <div>
            <span>{selectedProfile?.model ? String(selectedProfile.model) : 'perfil global do Artex'}</span>
            <h1>{selectedConversation?.title ? String(selectedConversation.title) : 'Nova conversa'}</h1>
          </div>
          <div className={`ghostia-page-notice is-${notice.tone}`} role="status" aria-live="polite">{notice.text}</div>
        </header>

        <div className="ghostia-page-transcript" id="ghostIaTranscript" ref={transcriptRef} aria-live="polite">
          {!visibleMessages.length && !pendingUser ? (
            <div className="ghostia-page-empty">
              <div className="ghostia-page-empty-icon" aria-hidden="true">◌</div>
              <h2>Converse com a GhostIA</h2>
              <p>Teste primeiro o provider. Depois envie uma pergunta; atividades, ferramentas, erros e resposta completa aparecem aqui.</p>
            </div>
          ) : null}
          {visibleMessages.map((item, index) => <GhostIaActivity item={item} key={String(item.seq || index)} />)}
          {pendingUser ? <GhostIaActivity item={{ kind: 'user', summary: pendingUser, detail: pendingUser }} /> : null}
          {busy ? (
            <div className="ghostia-page-thinking" data-testid="ghostia-processing"><span /><span /><span /><small>Artex processando</small></div>
          ) : null}
          {!busy && visibleMessages.some((item) => item.kind === 'user') && !hasAssistantReply && !visibleMessages.some((item) => item.is_error) ? (
            <div className="ghostia-page-inline-warning">A execução terminou sem uma resposta do modelo. Teste o provider e confira o erro exibido acima.</div>
          ) : null}
        </div>

        <form className="ghostia-page-composer" onSubmit={send}>
            <textarea
            id="ghostIaMessageInput"
              disabled={!status?.online || !llmReady}
            onChange={(event) => setDraft(event.currentTarget.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter' && !event.shiftKey) {
                event.preventDefault();
                void send();
              }
            }}
              placeholder={llmReady ? 'Escreva para a GhostIA… Enter envia; Shift+Enter quebra linha' : 'Configure e selecione um perfil LLM para liberar o chat'}
            value={draft}
          />
          <div>
            <span>{conversationId ? `conversa #${conversationId}` : 'nova conversa'}</span>
            {busy && conversationId ? <button className="is-stop" type="button" onClick={() => void stop()}>Parar</button> : null}
              <button className="is-send" type="submit" disabled={!draft.trim() || busy || !status?.online || !llmReady}>Enviar</button>
          </div>
        </form>
      </main></> : workspaceMode === 'hackbot'
        ? <section className="ghostia-hackbot-host"><HackbotWorkspace embedded /></section>
        : <section className="ghostia-neurosploit-host"><NeuroSploitWorkspace /></section>}
    </div>
  );
}
