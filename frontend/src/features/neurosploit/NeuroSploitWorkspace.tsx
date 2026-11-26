import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { createBrowserNeuroSploitService, type NeuroSploitRecord } from './service';

type Notice = { tone: 'info' | 'success' | 'error'; text: string };

const NETWORK_MODES = new Set(['run', 'greybox', 'host', 'aitest']);
const REPOSITORY_MODES = new Set(['whitebox', 'greybox', 'mobile', 'skills']);
const ACTIVE_PHASES = new Set(['starting', 'recon', 'planning', 'exploiting', 'validating', 'chaining', 'pausing', 'paused', 'resuming', 'stopping']);

const MODE_LABELS: Record<string, string> = {
  run: 'Black-box web',
  whitebox: 'White-box código',
  greybox: 'Grey-box',
  host: 'Host / infraestrutura',
  aitest: 'IA / LLM',
  mobile: 'Mobile / binário',
  container: 'Container',
  skills: 'Skills / n8n',
};

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function phaseLabel(value: string): string {
  return ({
    starting: 'iniciando', recon: 'reconhecimento', planning: 'planejando', exploiting: 'executando',
    validating: 'validando', chaining: 'encadeando', paused: 'pausado', pausing: 'pausando',
    resuming: 'retomando', stopping: 'encerrando', completed: 'concluído', failed: 'falhou',
    cancelled: 'cancelado', interrupted: 'interrompido',
  } as Record<string, string>)[value] || value || 'desconhecido';
}

function FindingCard({ finding }: { finding: NeuroSploitRecord }) {
  return (
    <article className="neurosploit-finding">
      <header>
        <span className={`is-${String(finding.severity || 'info').toLowerCase()}`}>{String(finding.severity || 'Info')}</span>
        <strong>{String(finding.title || finding.id || 'Achado')}</strong>
        <small>{String(finding.review_status || (finding.validated ? 'confirmado pelo motor' : 'revisão necessária'))}</small>
      </header>
      <p>{String(finding.endpoint || finding.location || 'Local não informado')}</p>
      <div><span>{String(finding.cwe || 'CWE não informado')}</span><span>confiança {Math.round(Number(finding.confidence || 0) * 100)}%</span><span>{String(finding.votes || 'sem votação')}</span></div>
      {(finding.evidence || finding.impact || finding.remediation) ? (
        <details><summary>Evidência e correção</summary><pre>{[finding.evidence, finding.impact, finding.remediation].filter(Boolean).join('\n\n')}</pre></details>
      ) : null}
    </article>
  );
}

export function NeuroSploitWorkspace() {
  const service = useMemo(() => createBrowserNeuroSploitService(), []);
  const [status, setStatus] = useState<NeuroSploitRecord | null>(null);
  const [engagements, setEngagements] = useState<NeuroSploitRecord[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [selected, setSelected] = useState<NeuroSploitRecord | null>(null);
  const [artifacts, setArtifacts] = useState<NeuroSploitRecord[]>([]);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<Notice>({ tone: 'info', text: 'Verificando o motor NeuroSploit…' });
  const [form, setForm] = useState({
    mode: 'run', target: '', repository: '', profileId: '', engagementId: '', authorizationReference: '',
    authorizationConfirmed: false, environment: 'production', policy: 'web', votes: 2, recon: 3,
    chainDepth: 2, maxAgents: 0, quick: false, focus: '', objective: '', outOfScope: '', codexCli: false, mcpServers: [] as string[],
  });

  const jobs = Array.isArray(status?.jobs) ? status.jobs as NeuroSploitRecord[] : [];
  const profiles = Array.isArray(status?.profiles) ? status.profiles as NeuroSploitRecord[] : [];
  const mcpCatalog = Array.isArray(status?.mcpServers) ? status.mcpServers as NeuroSploitRecord[] : [];
  const selectedProfile = profiles.find((profile) => String(profile.id) === form.profileId);
  const networkMode = NETWORK_MODES.has(form.mode);

  const refresh = useCallback(async (quiet = false) => {
    try {
      const [next, engagementBody] = await Promise.all([service.status(), service.engagements()]);
      setStatus(next);
      setEngagements(Array.isArray(engagementBody.engagements) ? engagementBody.engagements : Array.isArray(engagementBody) ? engagementBody : []);
      setForm((current) => {
        const available = (next.profiles || []) as NeuroSploitRecord[];
        const retained = available.find((item) => String(item.id) === current.profileId && item.ready);
        const preferred = retained
          || available.find((item) => item.ready && item.format === 'chatgpt-plan')
          || available.find((item) => item.ready)
          || available[0];
        const profileId = String(preferred?.id || '');
        if (retained) return { ...current, profileId };
        const codexCli = preferred?.format === 'chatgpt-plan';
        const mindAvailable = ((next.mcpServers || []) as NeuroSploitRecord[])
          .some((server) => server.id === 'codex:mind' && server.available !== false);
        return { ...current, profileId, codexCli, mcpServers: codexCli && mindAvailable ? ['codex:mind'] : [] };
      });
      setSelectedId((current) => current || String(next.jobs?.[0]?.id || ''));
      if (!quiet) setNotice(next.binaryReady
        ? { tone: 'success', text: 'NeuroSploit pronto. Os modelos vêm do GhostIA/Artex.' }
        : { tone: 'error', text: 'Backend importado, mas o binário ainda precisa ser compilado.' });
    } catch (error) {
      setNotice({ tone: 'error', text: errorMessage(error) });
    }
  }, [service]);

  const refreshJob = useCallback(async (id: string) => {
    if (!id) { setSelected(null); setArtifacts([]); return; }
    try {
      const response = await service.job(id);
      setSelected(response.job || null);
      if (response.job?.done) {
        const artifactBody = await service.artifacts(id);
        setArtifacts(artifactBody.artifacts || []);
      }
    } catch (error) {
      setNotice({ tone: 'error', text: errorMessage(error) });
    }
  }, [service]);

  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => { void refreshJob(selectedId); }, [refreshJob, selectedId]);
  useEffect(() => {
    const active = selected && ACTIVE_PHASES.has(String(selected.phase));
    const timer = window.setInterval(() => {
      void refresh(true);
      if (selectedId) void refreshJob(selectedId);
    }, active ? 1_200 : 5_000);
    return () => window.clearInterval(timer);
  }, [refresh, refreshJob, selectedId, selected?.phase]);

  const start = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setNotice({ tone: 'info', text: 'Validando escopo, engagement e perfil LLM…' });
    try {
      const response = await service.start({
        ...form,
        profileId: Number(form.profileId),
        votes: Number(form.votes), recon: Number(form.recon), chainDepth: Number(form.chainDepth), maxAgents: Number(form.maxAgents),
      });
      setSelectedId(String(response.job.id));
      setSelected(response.job);
      setArtifacts([]);
      await refresh(true);
      setNotice({ tone: 'success', text: 'Engagement iniciado. O token do Artex foi entregue somente ao processo em memória.' });
    } catch (error) {
      setNotice({ tone: 'error', text: errorMessage(error) });
    } finally { setBusy(false); }
  };

  const toggleMcp = (id: string, enabled: boolean) => {
    const selected = new Set(form.mcpServers);
    if (enabled) selected.add(id); else selected.delete(id);
    setForm({ ...form, mcpServers: [...selected] });
  };

  const control = async (action: 'pause' | 'continue' | 'stop' | 'resume') => {
    if (!selectedId) return;
    setBusy(true);
    try {
      const response = await service.control(selectedId, action);
      setSelected(response.job);
      setNotice({ tone: 'success', text: `Comando ${action} enviado ao NeuroSploit.` });
    } catch (error) { setNotice({ tone: 'error', text: errorMessage(error) }); }
    finally { setBusy(false); }
  };

  const download = async (artifact: NeuroSploitRecord) => {
    if (!selectedId) return;
    try {
      const blob = await service.artifact(selectedId, String(artifact.path));
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url; anchor.download = String(artifact.path).split('/').pop() || 'artifact'; anchor.click();
      URL.revokeObjectURL(url);
    } catch (error) { setNotice({ tone: 'error', text: errorMessage(error) }); }
  };

  return (
    <section className="neurosploit-workspace">
      <aside className="neurosploit-sidebar">
        <header><span>EXECUTION ENGINE</span><strong>NeuroSploit</strong><small>v{String(status?.version || '—')}</small></header>
        <div className={`neurosploit-health ${status?.binaryReady ? 'is-ready' : 'is-missing'}`}>
          <i />{status?.binaryReady ? 'motor pronto' : 'binário pendente'} · {profiles.length} perfil(is)
        </div>
        <button type="button" onClick={() => { setSelectedId(''); setSelected(null); }}>+ Novo engagement</button>
        <div className="neurosploit-job-list">
          {jobs.map((job) => (
            <button className={selectedId === String(job.id) ? 'is-active' : ''} key={job.id} type="button" onClick={() => setSelectedId(String(job.id))}>
              <strong>{MODE_LABELS[String(job.mode)] || String(job.mode)}</strong>
              <span>{String(job.target || job.repository || job.id)}</span>
              <small>{phaseLabel(String(job.phase))} · {Number(job.findings?.length || 0)} achado(s)</small>
            </button>
          ))}
          {!jobs.length ? <p>Nenhuma execução registrada.</p> : null}
        </div>
      </aside>

      <main className="neurosploit-main">
        <header className="neurosploit-main-head">
          <div><span>GHOSTIA · EXECUÇÃO VERIFICÁVEL</span><h1>{selected ? String(selected.target || selected.repository) : 'Novo engagement NeuroSploit'}</h1></div>
          <div className={`neurosploit-notice is-${notice.tone}`}>{notice.text}</div>
        </header>

        {!selected ? (
          <form className="neurosploit-form" onSubmit={start}>
            <section>
              <h2>1. Tipo e alvo</h2>
              <div className="neurosploit-form-grid">
                <label>Modo<select value={form.mode} onChange={(event) => setForm({ ...form, mode: event.currentTarget.value })}>{Object.entries(MODE_LABELS).map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select></label>
                <label>Perfil GhostIA / Artex<select value={form.profileId} onChange={(event) => { const profileId = event.currentTarget.value; const profile = profiles.find((item) => String(item.id) === profileId); const codexCli = profile?.format === 'chatgpt-plan'; const mindAvailable = mcpCatalog.some((server) => server.id === 'codex:mind' && server.available !== false); setForm({ ...form, profileId, codexCli, mcpServers: codexCli && mindAvailable ? ['codex:mind'] : [] }); }}><option value="">selecione</option>{profiles.map((profile) => <option disabled={!profile.ready} key={profile.id} value={String(profile.id)}>{String(profile.name)} · {String(profile.model)} · {profile.credentialSource === 'codex-plan' ? 'Codex' : 'API'}</option>)}</select></label>
                {form.mode !== 'whitebox' && form.mode !== 'skills' && form.mode !== 'mobile' ? <label className="is-wide">Alvo<input placeholder={form.mode === 'container' ? 'imagem:tag' : 'https://app.autorizada.test'} value={form.target} onChange={(event) => setForm({ ...form, target: event.currentTarget.value })} /></label> : null}
                {REPOSITORY_MODES.has(form.mode) ? <label className="is-wide">{form.mode === 'mobile' ? 'Caminho do artefato' : 'Repositório ou caminho local'}<input placeholder="/caminho/permitido ou https://github.com/org/repo" value={form.repository} onChange={(event) => setForm({ ...form, repository: event.currentTarget.value })} /></label> : null}
              </div>
              {selectedProfile?.format === 'chatgpt-plan' ? <div className="neurosploit-codex-mcp"><label className="neurosploit-confirm is-wide"><input type="checkbox" checked={form.codexCli} onChange={(event) => setForm({ ...form, codexCli: event.currentTarget.checked, mcpServers: event.currentTarget.checked ? form.mcpServers : [] })} /><span>Executar pelo Codex CLI local — necessário para usar o Mind e MCPs do seu Codex.</span></label>{form.codexCli ? <fieldset className="hackbot-mcp-picker"><legend>MCPs desta execução Codex</legend><p>Credenciais pessoais continuam no CODEX_HOME.</p><div>{mcpCatalog.map((server) => <label key={String(server.id)}><input type="checkbox" disabled={server.available === false} checked={form.mcpServers.includes(String(server.id))} onChange={(event) => toggleMcp(String(server.id), event.currentTarget.checked)} /><span><strong>{String(server.label)}</strong><small>{String(server.description || '')}</small></span></label>)}</div></fieldset> : null}</div> : null}
            </section>

            {networkMode ? <section>
              <h2>2. Autorização e escopo</h2>
              <div className="neurosploit-form-grid">
                <label>Engagement<select value={form.engagementId} onChange={(event) => setForm({ ...form, engagementId: event.currentTarget.value })}><option value="">selecione um engagement ativo</option>{engagements.filter((item) => item.status === 'active').map((item) => <option key={item.id} value={String(item.id)}>{String(item.id)} · {String(item.client || '')}</option>)}</select></label>
                <label>Ambiente<select value={form.environment} onChange={(event) => setForm({ ...form, environment: event.currentTarget.value })}><option value="lab">lab</option><option value="development">development</option><option value="staging">staging</option><option value="production">production</option></select></label>
                <label className="is-wide">Referência da autorização<input placeholder="Contrato, ROE, ticket ou laboratório" value={form.authorizationReference} onChange={(event) => setForm({ ...form, authorizationReference: event.currentTarget.value })} /></label>
                <label className="neurosploit-confirm is-wide"><input type="checkbox" checked={form.authorizationConfirmed} onChange={(event) => setForm({ ...form, authorizationConfirmed: event.currentTarget.checked })} /><span>Confirmo que este alvo e esta atividade estão explicitamente autorizados dentro do engagement selecionado.</span></label>
                <label className="is-wide">Fora do escopo<input placeholder="paths, hosts ou técnicas excluídas" value={form.outOfScope} onChange={(event) => setForm({ ...form, outOfScope: event.currentTarget.value })} /></label>
              </div>
            </section> : null}

            <section>
              <h2>{networkMode ? '3' : '2'}. Estratégia</h2>
              <div className="neurosploit-form-grid is-compact">
                <label>Recon<select value={form.recon} onChange={(event) => setForm({ ...form, recon: Number(event.currentTarget.value) })}>{[1, 2, 3, 4].map((n) => <option key={n}>{n}</option>)}</select></label>
                <label>Votos<input type="number" min="1" max="5" value={form.votes} onChange={(event) => setForm({ ...form, votes: Number(event.currentTarget.value) })} /></label>
                <label>Chain depth<input type="number" min="0" max="6" value={form.chainDepth} onChange={(event) => setForm({ ...form, chainDepth: Number(event.currentTarget.value) })} /></label>
                <label>Máx. agentes<input type="number" min="0" max="64" value={form.maxAgents} onChange={(event) => setForm({ ...form, maxAgents: Number(event.currentTarget.value) })} /></label>
                <label className="is-wide">Objetivo<textarea value={form.objective} onChange={(event) => setForm({ ...form, objective: event.currentTarget.value })} /></label>
                <label className="is-wide">Foco<textarea value={form.focus} onChange={(event) => setForm({ ...form, focus: event.currentTarget.value })} /></label>
                <label className="neurosploit-confirm is-wide"><input type="checkbox" checked={form.quick} onChange={(event) => setForm({ ...form, quick: event.currentTarget.checked })} /><span>Execução econômica/quick</span></label>
              </div>
            </section>
            <footer><span>{form.codexCli ? 'O Codex usa seu login local; o Mind permanece no CODEX_HOME.' : 'As chaves permanecem no cofre GhostIA/Artex.'}</span><button disabled={busy || !status?.binaryReady || !form.profileId || (networkMode && (!form.engagementId || !form.authorizationConfirmed))} type="submit">{busy ? 'Iniciando…' : 'Iniciar NeuroSploit'}</button></footer>
          </form>
        ) : (
          <section className="neurosploit-run">
            <header>
              <div><span className={`neurosploit-phase is-${String(selected.phase)}`}>{phaseLabel(String(selected.phase))}</span><strong>{String(selected.profileName)} · {String(selected.model)}</strong><small>{String(selected.engagementId || 'análise local')} · {String(selected.runId || selected.id)}</small></div>
              <nav>
                {selected.interrupted && selected.resumable ? <button disabled={busy} type="button" onClick={() => void control('resume')}>Retomar checkpoint</button> : null}
                {!selected.done && String(selected.phase) !== 'paused' ? <button disabled={busy || !selected.resumable} type="button" onClick={() => void control('pause')}>Pausar</button> : null}
                {!selected.done && String(selected.phase) === 'paused' ? <button disabled={busy} type="button" onClick={() => void control('continue')}>Continuar</button> : null}
                {!selected.done ? <button className="is-danger" disabled={busy} type="button" onClick={() => void control('stop')}>Encerrar</button> : null}
              </nav>
            </header>
            <div className="neurosploit-metrics"><span><strong>{Number(selected.agentsDone || 0)}/{Number(selected.agents || 0)}</strong> agentes</span><span><strong>{Number(selected.findings?.length || 0)}</strong> achados</span><span><strong>{selected.cortex?.imported ?? '—'}</strong> Cortex</span><span><strong>{selected.reportReady ? 'sim' : 'não'}</strong> relatório</span></div>
            <div className="neurosploit-run-grid">
              <section className="neurosploit-feed"><h2>Atividade ao vivo</h2><pre>{(selected.feed || []).filter((item: NeuroSploitRecord) => item.type === 'log').slice(-350).map((item: NeuroSploitRecord) => item.line).join('\n') || 'Aguardando eventos do motor…'}</pre></section>
              <section className="neurosploit-findings"><h2>Findings validados</h2>{(selected.findings || []).map((finding: NeuroSploitRecord, index: number) => <FindingCard finding={finding} key={String(finding.id || index)} />)}{!selected.findings?.length ? <p>Nenhum achado emitido até agora.</p> : null}</section>
            </div>
            {selected.done ? <section className="neurosploit-artifacts"><h2>Artefatos</h2><div>{artifacts.map((artifact) => <button key={artifact.path} type="button" onClick={() => void download(artifact)}><span>{String(artifact.path)}</span><small>{Number(artifact.size || 0).toLocaleString('pt-BR')} bytes</small></button>)}{!artifacts.length ? <p>Nenhum artefato exportável encontrado.</p> : null}</div></section> : null}
          </section>
        )}
      </main>
    </section>
  );
}
