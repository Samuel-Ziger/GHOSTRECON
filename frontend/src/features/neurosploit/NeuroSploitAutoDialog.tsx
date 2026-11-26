import { useEffect, useMemo, useState } from 'react';
import { createBrowserNeuroSploitService, type NeuroSploitRecord } from './service';

type Profile = {
  id: number;
  name: string;
  model: string;
  format: string;
  ready: boolean;
  credentialSource: string;
};

export function NeuroSploitAutoDialog() {
  const service = useMemo(() => createBrowserNeuroSploitService(), []);
  const [visible, setVisible] = useState(false);
  const [status, setStatus] = useState<NeuroSploitRecord | null>(null);
  const [profileId, setProfileId] = useState('');
  const [codexCli, setCodexCli] = useState(false);
  const [selectedMcps, setSelectedMcps] = useState<string[]>([]);
  const [notice, setNotice] = useState('Carregando o motor NeuroSploit…');

  const refresh = async () => {
    const next = await service.status();
    const profiles = (next.profiles || []) as Profile[];
    const ready = profiles.find((profile) => profile.ready && profile.format === 'chatgpt-plan')
      || profiles.find((profile) => profile.ready);
    const current = profiles.find((profile) => String(profile.id) === profileId && profile.ready);
    const selected = current || ready;
    const useCodexCli = selected?.format === 'chatgpt-plan';
    const mindAvailable = ((next.mcpServers || []) as NeuroSploitRecord[])
      .some((server) => server.id === 'codex:mind' && server.available !== false);
    setStatus(next);
    setProfileId(selected ? String(selected.id) : '');
    if (!current) {
      setCodexCli(useCodexCli);
      setSelectedMcps(useCodexCli && mindAvailable ? ['codex:mind'] : []);
    }
    setNotice(
      !next.binaryReady
        ? 'Binário do NeuroSploit indisponível. Compile o backend antes de iniciar.'
        : ready
          ? 'NeuroSploit pronto. Revise o engagement e valide o plano efetivo.'
          : 'Nenhum perfil LLM pronto. Configure API ou Codex em GhostIA → LLM.',
    );
    return next;
  };

  useEffect(() => {
    const open = () => {
      setVisible(true);
      void refresh().catch((error) => setNotice(error instanceof Error ? error.message : String(error)));
    };
    const close = () => setVisible(false);
    window.addEventListener('ghostrecon:auto-modal-open', open);
    window.addEventListener('ghostrecon:auto-modal-close', close);
    return () => {
      window.removeEventListener('ghostrecon:auto-modal-open', open);
      window.removeEventListener('ghostrecon:auto-modal-close', close);
    };
  }, [service]);

  const profiles = ((status?.profiles || []) as Profile[]).filter((profile) => profile.ready);
  const selectedProfile = profiles.find((profile) => String(profile.id) === profileId);
  const mcpCatalog = (status?.mcpServers || []) as NeuroSploitRecord[];
  const toggleMcp = (id: string, enabled: boolean) => setSelectedMcps((current) => enabled ? [...new Set([...current, id])] : current.filter((item) => item !== id));

  return (
    <div className="auto-modal-backdrop artex-auto-backdrop" id="autoModeModal" role="dialog" aria-modal="true" aria-labelledby="autoModeTitle" style={{ display: visible ? 'flex' : 'none' }}>
      <div className="auto-modal artex-auto-modal">
        <div className="auto-modal-head">
          <div>
            <div className="auto-modal-title" id="autoModeTitle">Modo Auto · NeuroSploit</div>
            <p className="auto-hint">O GHOSTRECON congela escopo, plano e evidências; depois o NeuroSploit valida lacunas e envia achados ao Cortex.</p>
          </div>
          <button type="button" className="auto-secondary-btn" onClick={() => window.dispatchEvent(new Event('ghostrecon:auto-modal-close'))}>Fechar</button>
        </div>

        <div className="auto-modal-body artex-auto-body">
          <section className="artex-auto-section">
            <div className="artex-auto-section-title"><span>01</span><div><strong>Operação GHOSTRECON</strong><small>fonte de verdade para autorização, escopo e coleta</small></div></div>
            <div className="auto-field"><label htmlFor="autoTargetInput">Target</label><input id="autoTargetInput" className="domain-input" type="text" placeholder="exemplo.com ou https://alvo" autoComplete="off" spellCheck="false" /></div>
            <div className="auto-grid artex-auto-grid-3">
              <div className="auto-field"><label htmlFor="autoModeSelect">Perfil</label><select id="autoModeSelect" className="domain-input" defaultValue="balanced"><option value="quick">quick</option><option value="balanced">balanced</option><option value="deep">deep</option></select></div>
              <div className="auto-field"><label htmlFor="autoAutonomyLevelSelect">Automação</label><select id="autoAutonomyLevelSelect" className="domain-input" defaultValue="authorized"><option value="observation">1 — Observação</option><option value="assisted">2 — Assistido</option><option value="authorized">3 — Autorizado</option><option value="authorized_opsec">4 — Autorizado OPSEC</option></select></div>
              <div className="auto-field"><label htmlFor="autoOpsecProfileSelect">OPSEC</label><select id="autoOpsecProfileSelect" className="domain-input" defaultValue="standard"><option value="passive">passive</option><option value="stealth">stealth</option><option value="standard">standard</option><option value="aggressive">aggressive</option></select></div>
            </div>
            <div className="auto-field"><label htmlFor="autoEngagementIdInput">Engagement autorizado</label><input id="autoEngagementIdInput" className="domain-input" type="text" placeholder="obrigatório para o NeuroSploit" /></div>
            <div className="auto-field"><label htmlFor="autoBountyContextJsonInput">Contexto do programa (JSON)</label><textarea id="autoBountyContextJsonInput" className="gh-textarea" spellCheck="false" placeholder='{"scope":["*.exemplo.com"],"focus":"API + SPA"}' /></div>
            <div hidden><select id="autoResumeSessionSelect"><option value="">—</option></select><input id="autoResumeSessionInput" /></div>
          </section>

          <section className="artex-auto-section">
            <div className="artex-auto-section-title"><span>02</span><div><strong>NeuroSploit</strong><small>engine multiagente executada dentro da mesma sessão Auto</small></div></div>
            <div className="artex-auto-health">
              <span className={status?.binaryReady ? 'is-online' : 'is-offline'}>{status?.binaryReady ? 'ENGINE PRONTA' : 'ENGINE OFFLINE'}</span>
              <span>{profiles.length} perfil(is) pronto(s)</span>
              <span>versão {String(status?.version || '—')}</span>
              <button type="button" onClick={() => void refresh()}>Atualizar</button>
            </div>
            <label className="auto-choice"><input type="checkbox" id="autoIncludeNeuroSploitToggle" defaultChecked /><div><strong>Usar NeuroSploit no Auto</strong><span>inicia somente depois das coletas GHOSTRECON e da aprovação do plano</span></div></label>
            <div className="auto-grid artex-auto-grid-3">
              <div className="auto-field"><label htmlFor="neurosploitProfileSelect">Perfil LLM</label><select id="neurosploitProfileSelect" className="domain-input" value={profileId} onChange={(event) => { const nextId = event.currentTarget.value; const nextProfile = profiles.find((profile) => String(profile.id) === nextId); const useCodex = nextProfile?.format === 'chatgpt-plan'; const mindAvailable = mcpCatalog.some((server) => server.id === 'codex:mind' && server.available !== false); setProfileId(nextId); setCodexCli(useCodex); setSelectedMcps(useCodex && mindAvailable ? ['codex:mind'] : []); }}><option value="">Selecione um perfil pronto</option>{profiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.name} · {profile.model || profile.format} · {profile.credentialSource}</option>)}</select></div>
              <div className="auto-field"><label htmlFor="neurosploitEnvironmentSelect">Ambiente</label><select id="neurosploitEnvironmentSelect" className="domain-input" defaultValue="production"><option value="production">production</option><option value="staging">staging</option><option value="development">development</option><option value="lab">ctf/lab</option></select></div>
              <div className="auto-field"><label htmlFor="neurosploitTimeoutMinutes">Timeout (min)</label><input id="neurosploitTimeoutMinutes" className="domain-input" type="number" min="1" max="120" defaultValue="90" /></div>
              <div className="auto-field"><label htmlFor="neurosploitReconSelect">Rodadas de recon</label><select id="neurosploitReconSelect" className="domain-input" defaultValue="1"><option value="1">1</option><option value="2">2</option><option value="3">3</option><option value="4">4</option></select></div>
              <div className="auto-field"><label htmlFor="neurosploitVotesInput">Votos por achado</label><input id="neurosploitVotesInput" className="domain-input" type="number" min="1" max="5" defaultValue="2" /></div>
              <div className="auto-field"><label htmlFor="neurosploitChainDepthInput">Profundidade de cadeia</label><input id="neurosploitChainDepthInput" className="domain-input" type="number" min="0" max="6" defaultValue="2" /></div>
              <div className="auto-field"><label htmlFor="neurosploitMaxAgentsInput">Limite de agentes</label><input id="neurosploitMaxAgentsInput" className="domain-input" type="number" min="0" max="64" defaultValue="0" /></div>
              <label className="auto-choice"><input type="checkbox" id="neurosploitQuickToggle" /><div><strong>Quick</strong><span>reduz profundidade do motor</span></div></label>
              <label className="auto-choice"><input type="checkbox" id="neurosploitJsonPreviewToggle" /><div><strong>JSON no terminal</strong><span>mostra apenas a configuração sem segredos</span></div></label>
            </div>
            {selectedProfile?.format === 'chatgpt-plan' ? <div className="neurosploit-codex-mcp"><label className="auto-choice"><input type="checkbox" id="neurosploitCodexCliToggle" checked={codexCli} onChange={(event) => { setCodexCli(event.currentTarget.checked); if (!event.currentTarget.checked) setSelectedMcps([]); }} /><div><strong>Codex CLI + MCP</strong><span>usa o login local do Codex; necessário para o Mind</span></div></label>{codexCli ? <fieldset className="hackbot-mcp-picker"><legend>MCPs do NeuroSploit Auto</legend><p>Cada seleção vale somente para esta execução.</p><div>{mcpCatalog.map((server) => <label key={String(server.id)}><input type="checkbox" data-neurosploit-mcp={String(server.id)} disabled={server.available === false} checked={selectedMcps.includes(String(server.id))} onChange={(event) => toggleMcp(String(server.id), event.currentTarget.checked)} /><span><strong>{String(server.label)}</strong><small>{String(server.description || '')}</small></span></label>)}</div></fieldset> : null}</div> : null}
            <div className="auto-field"><label htmlFor="neurosploitObjectiveInput">Objetivo adicional</label><input id="neurosploitObjectiveInput" className="domain-input" type="text" placeholder="opcional" /></div>
            <div className="auto-field"><label htmlFor="neurosploitFocusInput">Foco</label><input id="neurosploitFocusInput" className="domain-input" type="text" placeholder="ex.: autorização, API e cadeias de impacto" /></div>
            <div className="auto-field"><label htmlFor="neurosploitOutOfScopeInput">Fora do escopo</label><input id="neurosploitOutOfScopeInput" className="domain-input" type="text" placeholder="restrições adicionais" /></div>
            <p className="auto-hint">Os perfis de API e Codex já configurados no GhostIA são reutilizados. O gateway antigo fica interno e não cria uma segunda tarefa Auto.</p>
          </section>

          <section className="artex-auto-section">
            <div className="artex-auto-section-title"><span>03</span><div><strong>Motores e coletas</strong><small>todos permanecem sujeitos ao plano efetivo e aos gates</small></div></div>
            <div className="auto-grid">
              <label className="auto-choice"><input type="checkbox" id="autoAllApplicableModulesToggle" defaultChecked /><div><strong>Todos os módulos aplicáveis</strong><span>executa o catálogo compatível com escopo, disponibilidade e autorização</span></div></label>
              <label className="auto-choice"><input type="checkbox" id="autoHexstrikeToggle" /><div><strong>HexStrike</strong><span>capacidades opcionais no plano</span></div></label>
              <label className="auto-choice"><input type="checkbox" id="autoDeepPassiveToggle" defaultChecked /><div><strong>Deep passive</strong><span>coleta passiva profunda</span></div></label>
              <label className="auto-choice"><input type="checkbox" id="autoIncludeFrameSevenToggle" /><div><strong>FrameSeven</strong><span>etapa opcional autorizada</span></div></label>
              <label className="auto-choice"><input type="checkbox" id="autoFrameSevenAuthToggle" disabled /><div><strong>FrameSeven autenticado</strong><span>exige confirmação própria</span></div></label>
              <label className="auto-choice"><input type="checkbox" id="autoIncludeVigoliumToggle" /><div><strong>Vigolium</strong><span>DAST opcional autorizado</span></div></label>
              <label className="auto-choice"><input type="checkbox" id="autoVigoliumCodexToggle" disabled /><div><strong>Vigolium + Codex</strong><span>mantém o suporte pelo plano</span></div></label>
            </div>
          </section>

          <div className="artex-auto-prompt-note"><strong>Fluxo:</strong> autorização → plano selado → pipelines GHOSTRECON → NeuroSploit → Cortex → avaliação final.</div>
          <div className="auto-hint" id="autoModeStatus">{notice}</div>
          <button type="button" className="auto-secondary-btn" id="autoCancelBtn" onClick={() => (window as any).cancelAutoModeRecon?.()} disabled>Parar Auto</button>
        </div>

        <div className="auto-modal-foot"><p className="auto-hint">O NeuroSploit nunca inicia antes do checklist formal e da aprovação do plano efetivo.</p><div className="auto-actions"><button type="button" className="auto-secondary-btn" onClick={() => window.dispatchEvent(new Event('ghostrecon:auto-modal-close'))}>Cancelar</button><button type="button" className="auto-primary-btn" id="autoStartBtn" onClick={() => (window as any).startAutoModeRecon?.()}>Validar e iniciar</button></div></div>
      </div>
    </div>
  );
}
