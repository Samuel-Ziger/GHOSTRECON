'use client';

import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
  type MouseEvent,
  type WheelEvent,
} from 'react';
import {
  PIPE_ORDER,
  findFindingLinks,
  mitreTechniqueUrl,
  owaspEntry,
  pipeDisplayName,
  type Finding,
  type FindingBranch,
  type LiveState,
  type MitreBundle,
  type OwaspHint,
  type ProjectSecretPeer,
  type Technique,
} from './mitreLiveModel';
import { useMitreLiveRuntime } from './useMitreLiveRuntime';

const PHASE_TO_TACTIC: Record<string, string> = {
  'initial-access': 'TA0001',
  'resource-development': 'TA0042',
  reconnaissance: 'TA0043',
};

function GhostLogo() {
  return (
    <div className="logo-ghost" aria-hidden="true" title="GHOSTRECON">
      <svg viewBox="0 0 48 52" xmlns="http://www.w3.org/2000/svg" width="28" height="30" focusable="false">
        <defs>
          <linearGradient id="logoGhostGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#e8fbff" />
            <stop offset="45%" stopColor="#5ee0ff" />
            <stop offset="100%" stopColor="#00a8d4" />
          </linearGradient>
          <linearGradient id="logoGhostSheen" x1="15%" y1="0%" x2="75%" y2="85%">
            <stop offset="0%" stopColor="rgba(255,255,255,0.38)" />
            <stop offset="45%" stopColor="rgba(255,255,255,0)" />
            <stop offset="100%" stopColor="rgba(0,45,70,0.22)" />
          </linearGradient>
        </defs>
        <g className="ghost-anim">
          <path fill="url(#logoGhostGrad)" stroke="rgba(0,200,255,0.42)" strokeWidth="0.55" d="M 24 5 C 13 5 5 13.5 5 24.5 V 40 Q 8.5 36.5 12 40 Q 15.5 36.5 19 40 Q 22.5 36.5 26 40 Q 29.5 36.5 33 40 Q 36.5 36.5 40 40 Q 43.5 36.5 43 40 V 24.5 C 43 13.5 35 5 24 5 Z" />
          <path fill="url(#logoGhostSheen)" d="M 24 8 C 15 8 9 15 9 23.5 V 33 Q 16 28 24 32 Q 32 28 39 33 V 23.5 C 39 15 33 8 24 8 Z" opacity="0.88" />
          <ellipse className="ghost-eye" cx="17" cy="22" rx="3.2" ry="4.2" fill="#050709" />
          <ellipse className="ghost-eye ghost-eye-r" cx="31" cy="22" rx="3.2" ry="4.2" fill="#050709" />
        </g>
      </svg>
    </div>
  );
}

function LiveHeader({ state }: { state: LiveState }) {
  const last = state.lastMessageAt
    ? new Date(state.lastMessageAt).toLocaleTimeString('pt-PT', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : '';
  return (
    <header>
      <GhostLogo />
      <h1>GHOST<span>RECON</span> · MITRE + OWASP</h1>
      <div className="header-right">
        <span id="liveFindingsCount" className="live-hud" style={{ display: state.sessionId ? '' : 'none' }} title="Achados recebidos nesta sessão"><strong>{state.findingsReceivedCount}</strong> achados</span>
        <span id="liveLastTs" className="live-hud" style={{ display: last ? '' : 'none' }} title="Último evento ao vivo">{last ? `Último: ${last}` : ''}</span>
        <span id="targetLine" className="target-badge" style={{ display: state.target ? '' : 'none' }}>{state.target}</span>
        <span id="statePill" className={state.statusClass}>{state.statusText}</span>
      </div>
    </header>
  );
}

function ProjectSecretPeers({ peers }: { peers: ProjectSecretPeer[] }) {
  return (
    <div id="projectSecretPeersBar" className="psp-bar" hidden={!peers.length}>
      <div className="psp-bar-head"><span className="psp-bar-title">Segredos partilhados entre alvos (mesmo projeto)</span></div>
      <ul id="projectSecretPeersList" className="psp-list">
        {peers.map((peer, index) => (
          <li key={`${peer.preview || 'peer'}-${index}`}>
            <strong>{peer.kind_hint || 'secret'}</strong> · {Array.isArray(peer.targets) ? peer.targets.join(', ') : ''}
            <span className="psp-preview"> — {String(peer.preview || '').slice(0, 140)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function useEscape(active: boolean, close: () => void) {
  useEffect(() => {
    if (!active) return undefined;
    const handler = (event: KeyboardEvent) => { if (event.key === 'Escape') close(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [active, close]);
}

function JsonDock({ exportJson, importJson }: { exportJson: () => void; importJson: (text: string) => boolean }) {
  const [open, setOpen] = useState(false);
  const [importEnabled, setImportEnabled] = useState(false);
  const [text, setText] = useState('');
  const fileRef = useRef<HTMLInputElement>(null);
  useEscape(open, () => setOpen(false));

  const readFile = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.currentTarget.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setText(String(reader.result || ''));
    reader.readAsText(file);
  };
  const clear = () => {
    setText('');
    if (fileRef.current) fileRef.current.value = '';
  };

  return (
    <div id="branchJsonDockWrap" className={`branch-json-dock-wrap${open ? ' is-open' : ''}`}>
      <button type="button" id="branchJsonDockTab" className="branch-json-dock-tab" aria-expanded={open} aria-controls="branchJsonDockPanel" title="Mostrar ou ocultar importar / exportar JSON" onClick={() => setOpen((value) => !value)}>JSON</button>
      <aside id="branchJsonDockPanel" className="branch-json-dock-panel" aria-label="Importar e exportar JSON" aria-hidden={!open}>
        <div className="branch-json-dock-panel-head">
          <div className="branch-json-dock-title">Importar / exportar</div>
          <button type="button" className="branch-json-dock-close" id="branchJsonDockClose" aria-label="Fechar painel JSON" onClick={() => setOpen(false)}>×</button>
        </div>
        <div className="branch-json-toggle-row">
          <span className="toggle-label-ghm" title="Mostra ou oculta o campo para colar JSON e reaplicar ramificações (como a fila de alvos na UI principal)">JSON importar / exportar</span>
          <label className="toggle-ghm">
            <input type="checkbox" id="branchJsonPanelToggle" checked={importEnabled} onChange={(event) => setImportEnabled(event.currentTarget.checked)} />
            <div className="toggle-track-ghm"><div className="toggle-thumb-ghm" /></div>
          </label>
        </div>
        <div id="branchJsonPanelWrap" className="branch-json-panel-wrap" style={{ display: importEnabled ? 'block' : 'none' }}>
          <div id="branchImportBar" className="branch-import-bar">
            <label htmlFor="branchImportJson">Importar JSON (export GHOSTRECON / platform ou array de achados) — recria só os ramos, sem recon.</label>
            <textarea id="branchImportJson" spellCheck={false} autoComplete="off" value={text} onChange={(event) => setText(event.currentTarget.value)} placeholder={'Ex.: { "target": "exemplo.com", "findings": [ { "type":"endpoint", "priority":"high", "value":"https://…", "mitre":[{"id":"T1595"}] } ] }'} />
            <div className="branch-import-actions">
              <input ref={fileRef} type="file" id="branchImportFile" accept=".json,application/json" onChange={readFile} />
              <button type="button" id="branchImportApply" onClick={() => importJson(text.trim())}>Aplicar na timeline</button>
              <button type="button" className="branch-export-json-btn" id="branchExportJsonBtn" onClick={exportJson}>Export JSON</button>
              <button type="button" id="branchImportClearField" onClick={clear}>Limpar campo</button>
            </div>
            <p className="branch-import-hint">«Export JSON» gera um ficheiro reimportável a partir dos eventos <code>finding</code> na timeline (o buffer do mapa mantém os últimos 200 eventos). Compatível com <code>export JSON</code> da UI (<code>findings[]</code> com <code>priority</code>, <code>mitre[].id</code>). Máx. 600 achados por importação.</p>
          </div>
        </div>
      </aside>
    </div>
  );
}

function Legend() {
  const [open, setOpen] = useState(false);
  useEscape(open, () => setOpen(false));
  return (
    <div className={`ghostmap-legend-wrap${open ? ' is-open' : ''}`} id="ghostmapLegendWrap">
      <button type="button" id="ghostmapLegendTab" className="ghostmap-legend-tab" aria-expanded={open} aria-controls="ghostmapLegendPanel" title="Mostrar ou ocultar legenda" onClick={() => setOpen((value) => !value)}>Legenda</button>
      <aside id="ghostmapLegendPanel" className="ghostmap-legend-panel" aria-label="Legenda do mapa" aria-hidden={!open}>
        <div className="ghostmap-legend-panel-head"><div className="ghostmap-legend-title">Legenda</div><button type="button" className="ghostmap-legend-close" id="ghostmapLegendClose" aria-label="Fechar legenda" onClick={() => setOpen(false)}>×</button></div>
        <ul>
          <li><span className="leg-mitre" aria-hidden="true" /><span><strong style={{ color: 'var(--mitre)' }}>Quadrado laranja</strong> — técnica MITRE (<code>Txxxx</code>) ou número do achado; clique para detalhe.</span></li>
          <li><span className="leg-arrow" aria-hidden="true">↑</span><span>Ramo <strong>acima</strong> da linha / <strong className="leg-arrow">↓</strong> abaixo — alterna a cada achado.</span></li>
          <li><span><span className="leg-prio high" /><strong style={{ color: '#ff8a9a' }}>HIGH</strong> · <span className="leg-prio med" /><strong style={{ color: '#f0d060' }}>MED</strong> · <span className="leg-prio low" /><strong style={{ color: '#5ed4a8' }}>LOW</strong> — borda esquerda do cartão.</span></li>
        </ul>
      </aside>
    </div>
  );
}

function Pipeline({ state }: { state: LiveState }) {
  const extra = Object.keys(state.pipeline).filter((name) => !PIPE_ORDER.includes(name as typeof PIPE_ORDER[number]));
  const rows = [...PIPE_ORDER, ...extra];
  return (
    <>
      <div id="pipeMiniMapStrip" className="pipe-mini-strip" hidden={!state.sessionId}>
        <span className="pipe-mini-label">Pipeline</span>
        <span id="pipeMiniKaliBadge" className={`pipe-mini-kali pipe-mini-kali--${state.kaliMode ? 'on' : 'off'}`} hidden={state.kaliMode === null} title={state.kaliMode ? 'Modo Kali activo neste recon — módulos Kali no servidor conforme a caixa na UI.' : 'Modo Kali desligado ou indisponível.'} role="status" aria-live="polite">{state.kaliMode ? 'Kali ON' : 'Kali OFF'}</span>
        <div id="pipeMiniDots" className="pipe-mini-dots" aria-hidden="true">
          {PIPE_ORDER.map((name) => <span key={name} className={`pipe-mini-dot ${state.pipeline[name] || 'pending'}`} data-pipe={name} title={pipeDisplayName(name)} />)}
        </div>
      </div>
      <section className="block" aria-label="Fases do pipeline">
        <h2>Pipeline</h2>
        <div className="pipe-milestones-wrap">
          <div className="pipe-rail-h" aria-hidden="true" />
          <div id="pipeMilestonesH" className="pipe-milestones-h">
            {rows.map((name) => {
              const status = state.pipeline[name] || 'pending';
              return <div key={name} className={`pipe-ms ${status}`} data-pipe={name}><span className="pipe-ms-dot" /><span className="pipe-ms-name">{pipeDisplayName(name)}</span><span className="pipe-ms-st">{status === 'active' ? '●' : status === 'done' ? '✓' : status === 'skip' ? '○' : '—'}</span></div>;
            })}
          </div>
        </div>
        <div className="pipe-hint" id="pipeHint">{state.sessionId ? (state.lastPipeLabel ? `Último pipeline: ${state.lastPipeLabel}` : '') : 'Sem sessão ao vivo — os marcos mostram a ordem típica do pipeline.'}</div>
      </section>
    </>
  );
}

function FindingCard({ branch, onOpen }: { branch: FindingBranch; onOpen: (branch: FindingBranch) => void }) {
  const up = branch.seq % 2 === 1;
  const prio = String(branch.finding.prio || branch.finding.priority || '').toLowerCase();
  const prioClass = prio === 'high' ? 'prio-high' : prio === 'med' ? 'prio-med' : prio === 'low' ? 'prio-low' : 'prio-unk';
  const primary = branch.mitreHints[0] || '';
  const quickLink = findFindingLinks(branch.finding)[0];
  const card = <div className={`h-mini-card ${prioClass}`}><div className="t">{String(branch.finding.type || '?')} · {new Date(branch.ts).toLocaleTimeString('pt-PT', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</div><div className="v">{String(branch.finding.value || '').slice(0, 200)}</div><div className="pr">{prio.toUpperCase() || '—'}</div>{quickLink ? <div className="lnk"><a href={quickLink} target="_blank" rel="noopener noreferrer">abrir alvo ↗</a></div> : null}</div>;
  const button = <button type="button" className={primary ? 'mitre-node-btn' : 'mitre-node-btn num-only'} title={primary ? `${primary} — clique para detalhe` : `Achado #${branch.seq}`} onClick={() => onOpen(branch)}>{primary ? (primary.length > 7 ? `${primary.slice(0, 6)}…` : primary) : `#${branch.seq}`}</button>;
  return <div className={`h-seg ${up ? 'h-seg-up' : 'h-seg-down'}`}>{up ? card : button}<div className="h-vline" aria-hidden="true" />{up ? button : card}</div>;
}

function Branches({ state, onOpen }: { state: LiveState; onOpen: (branch: FindingBranch) => void }) {
  const [zoom, setZoom] = useState(1);
  const viewport = useRef<HTMLDivElement>(null);
  useEffect(() => { if (viewport.current) viewport.current.scrollLeft = viewport.current.scrollWidth; }, [state.branches.length]);
  const changeZoom = (value: number) => setZoom(Math.max(0.45, Math.min(2.25, value)));
  const wheel = (event: WheelEvent<HTMLDivElement>) => {
    if (!event.ctrlKey) return;
    event.preventDefault();
    changeZoom(zoom + (event.deltaY > 0 ? -0.06 : 0.06));
  };
  return (
    <section className="block" aria-label="Ramificações">
      <h2>Ramificações</h2>
      <div id="branchesToolbar" className="branches-toolbar" hidden={!state.sessionId}><span>Ramo / pan: arrasta · zoom:</span><button type="button" id="branchZoomOut" title="Menos (ou Ctrl+scroll)" onClick={() => changeZoom(zoom - 0.12)}>−</button><button type="button" id="branchZoomIn" title="Mais (ou Ctrl+scroll)" onClick={() => changeZoom(zoom + 0.12)}>+</button><button type="button" id="branchZoomReset" title="100%" onClick={() => setZoom(1)}>100%</button><span id="branchZoomReadout" className="branches-zoom-readout">{Math.round(zoom * 100)}% · Ctrl+scroll</span></div>
      <div ref={viewport} className="branches-wrap branches-viewport" id="branchesViewport" tabIndex={0} aria-label="Área de ramificações — zoom com Ctrl e roda do rato" onWheel={wheel}>
        <div className="branches-scale-inner" id="branchesScaleInner" style={{ transform: `scale(${zoom})` }}>
          <div className="branches-wrap-inner"><div id="feedRoot" className="h-flow-cards">
            {!state.branches.length ? <div className={state.sessionResolved && !state.sessionId ? 'err empty-state' : 'empty-state'}>{state.sessionResolved && !state.sessionId ? <>Abre a partir do GHOSTRECON (botão «Mapa MITRE») ou <code>mitre-map.html#&lt;uuid&gt;</code>.</> : 'Aguardando achados…'}</div> : null}
            {state.branches.map((branch) => branch.kind === 'cascade'
              ? <div key={`cascade-${branch.ts}`} className="h-flow-cascade-break" role="separator" aria-label={`Seguinte alvo: ${branch.domain}`}><span className="h-flow-cascade-break-tag">{branch.tag}{branch.root ? ` · ${branch.root}` : ''}</span><div className="h-flow-cascade-break-line" aria-hidden="true" /><span className="h-flow-cascade-break-label">{branch.domain}</span></div>
              : <FindingCard key={`finding-${branch.seq}-${branch.ts}`} branch={branch} onOpen={onOpen} />)}
          </div></div>
        </div>
      </div>
    </section>
  );
}

function tacticTechniques(bundle: MitreBundle | null): Map<string, Technique[]> {
  const result = new Map<string, Technique[]>((bundle?.tactics || []).map((tactic) => [tactic.id, []]));
  for (const technique of bundle?.techniques || []) {
    const tacticId = (technique.phases || []).map((phase) => PHASE_TO_TACTIC[phase]).find((id) => id && result.has(id));
    if (tacticId) result.get(tacticId)?.push(technique);
  }
  for (const rows of result.values()) rows.sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true }));
  return result;
}

function Matrix({ state }: { state: LiveState }) {
  const [hitsOnly, setHitsOnly] = useState(false);
  const [highOnly, setHighOnly] = useState(false);
  const [search, setSearch] = useState('');
  const byTactic = useMemo(() => tacticTechniques(state.bundle), [state.bundle]);
  const query = search.trim().toLowerCase();
  let visibleTactics = 0;
  let visibleChips = 0;
  const rows = (state.bundle?.tactics || []).map((tactic) => {
    const techniques = byTactic.get(tactic.id) || [];
    const chips = techniques.map((technique) => {
      const snippets = state.mitreHitSnippets[technique.id] || [];
      const matches = !query || technique.id.toLowerCase().includes(query) || String(technique.name || '').toLowerCase().includes(query) || snippets.some((item) => item.toLowerCase().includes(query));
      const shown = matches && (!highOnly || state.highMitreIds.includes(technique.id));
      return { technique, shown };
    });
    const visible = chips.filter((chip) => chip.shown);
    const tacticShown = visible.length > 0 && (!hitsOnly || visible.some((chip) => state.mitreHits.includes(chip.technique.id)));
    if (tacticShown) { visibleTactics += 1; visibleChips += visible.length; }
    return { tactic, chips, tacticShown };
  });
  const reset = () => { setHitsOnly(false); setHighOnly(false); setSearch(''); };
  return (
    <section className="block">
      <h2>Matriz tácticas</h2>
      <div id="matrixFilterBar" className="matrix-filter-bar" hidden={!state.sessionId}>
        <label><input type="checkbox" id="filtTacticsHits" checked={hitsOnly} onChange={(event) => setHitsOnly(event.currentTarget.checked)} /> Só tácticas com ≥1 achado</label>
        <label><input type="checkbox" id="filtHighOnly" checked={highOnly} onChange={(event) => setHighOnly(event.currentTarget.checked)} /> Só técnicas de achados HIGH</label>
        <input type="search" id="matrixSearch" value={search} onChange={(event) => setSearch(event.currentTarget.value)} placeholder="T1595, nome ou texto do achado…" autoComplete="off" />
        <button type="button" id="matrixFilterReset" onClick={reset}>Limpar</button>
        <span id="matrixFilterMeta" className="matrix-filter-meta">{highOnly && !state.highMitreIds.length ? 'Nenhum achado HIGH com técnica MITRE ainda — desliga o filtro ou aguarda achados.' : `Tácticas visíveis: ${visibleTactics} · chips visíveis: ${visibleChips}`}</span>
      </div>
      <div id="tacticsRoot" className="tactics">
        {state.bundleError ? <p className="err" style={{ padding: 12 }}>{state.bundleError}</p> : null}
        {rows.map(({ tactic, chips, tacticShown }) => (
          <div key={tactic.id} className={`tactic${state.liveTactics.includes(tactic.id) ? ' live' : ''}${tacticShown ? '' : ' hidden-matrix-filter'}`} data-ta={tactic.id}>
            <div className="tactic-h"><strong>{tactic.id}</strong><span>{tactic.name || ''}</span></div>
            <div className="tactic-body">
              {chips.map(({ technique, shown }) => <a key={technique.id} className={`chip${state.mitreHits.includes(technique.id) ? ' hit' : ''}${shown ? '' : ' hidden-matrix-filter'}`} href={technique.url || mitreTechniqueUrl(technique.id)} target="_blank" rel="noopener noreferrer" title={technique.name || ''}>{technique.id}</a>)}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

type ServiceInfo = { name: string; what: string; doc: string };
const SERVICES: Array<{ re: RegExp } & ServiceInfo> = [
  { re: /cloudflare/, name: 'Cloudflare', what: 'Plataforma edge/CDN com proxy reverso, mitigacao DDoS e WAF.', doc: 'https://developers.cloudflare.com/fundamentals/' },
  { re: /akamai/, name: 'Akamai', what: 'Rede de entrega e protecao de aplicacoes com camadas de WAF e bot defense.', doc: 'https://techdocs.akamai.com/' },
  { re: /(aws waf|amazon waf)/, name: 'AWS WAF', what: 'Firewall de aplicacao web da AWS para regras em ALB, API Gateway e CloudFront.', doc: 'https://docs.aws.amazon.com/waf/' },
  { re: /(f5|big-ip)/, name: 'F5 BIG-IP', what: 'Plataforma de ADC/WAF usada para balanceamento, protecao e politica de trafego.', doc: 'https://clouddocs.f5.com/' },
  { re: /imperva/, name: 'Imperva', what: 'Suite de seguranca para aplicacoes e APIs, com WAF e protecao DDoS.', doc: 'https://docs.imperva.com/' },
  { re: /sucuri/, name: 'Sucuri', what: 'Camada de protecao web com firewall cloud e monitoracao de integridade.', doc: 'https://docs.sucuri.net/' },
  { re: /nginx/, name: 'Nginx', what: 'Servidor web/proxy reverso usado para publicar apps e distribuir trafego.', doc: 'https://nginx.org/en/docs/' },
  { re: /(apache|httpd)/, name: 'Apache HTTP Server', what: 'Servidor web tradicional muito comum em stacks LAMP e hospedagens compartilhadas.', doc: 'https://httpd.apache.org/docs/' },
  { re: /(iis|microsoft-iis)/, name: 'Microsoft IIS', what: 'Servidor web da Microsoft integrado ao ecossistema Windows/ASP.NET.', doc: 'https://learn.microsoft.com/iis/' },
  { re: /wordpress/, name: 'WordPress', what: 'CMS popular em PHP; a superficie inclui plugins, temas, XML-RPC e REST API.', doc: 'https://wordpress.org/documentation/' },
  { re: /jenkins/, name: 'Jenkins', what: 'Servidor de CI/CD; exposicao indevida pode abrir risco de execucao remota e vazamento.', doc: 'https://www.jenkins.io/doc/' },
  { re: /grafana/, name: 'Grafana', what: 'Plataforma de dashboards; paineis e plugins expostos podem revelar informacao sensivel.', doc: 'https://grafana.com/docs/' },
];

function serviceInfo(finding: Finding): ServiceInfo | null {
  const haystack = `${finding.type || ''} ${finding.value || ''} ${finding.meta || ''}`.toLowerCase();
  const match = SERVICES.find((item) => item.re.test(haystack));
  if (match) return match;
  return /\bwaf\b/.test(haystack) ? { name: 'WAF (generico)', what: 'Camada de firewall para HTTP/HTTPS que filtra padroes de ataque antes da aplicacao.', doc: 'https://owasp.org/www-community/Web_Application_Firewall' } : null;
}

function findingTypeHelp(type: unknown): string {
  const value = String(type || '').toLowerCase();
  if (value === 'waf') return 'WAF (Web Application Firewall) e um filtro de protecao de aplicacoes web; pode bloquear ou desafiar pedidos suspeitos.';
  if (value === 'param') return 'Parametro potencialmente sensivel. Abre o link para validar contexto, refletir input e testar impacto.';
  if (value === 'endpoint' || value === 'url') return 'Endpoint/URL descoberto durante recon; bom ponto para validacao manual e correlacao com autenticacao.';
  if (value === 'xss' || value === 'xss_reflection') return 'Possivel superficie de XSS; valida se ha reflexao controlavel e se o contexto permite execucao.';
  return '';
}

function FindingModal({ branch, bundle, close }: { branch: FindingBranch | null; bundle: MitreBundle | null; close: () => void }) {
  useEscape(Boolean(branch), close);
  if (!branch) return <div id="modalBackdrop" className="modal-backdrop" aria-hidden="true" />;
  const links = findFindingLinks(branch.finding);
  const help = findingTypeHelp(branch.finding.type);
  const service = serviceInfo(branch.finding);
  const techniques = bundle?.techniques || [];
  const backdrop = (event: MouseEvent<HTMLDivElement>) => { if (event.target === event.currentTarget) close(); };
  return (
    <div id="modalBackdrop" className="modal-backdrop open" aria-hidden="false" onClick={backdrop}>
      <div className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="modalTitle">
        <button type="button" className="modal-close" id="modalClose" aria-label="Fechar" onClick={close}>×</button>
        <h3 id="modalTitle">Achado #{branch.seq} · {String(branch.finding.type || '?')}</h3>
        <div id="modalBody">
          <p className="lead">Badge: <strong>{branch.badgeLabel}</strong></p>
          {help ? <p className="ex" style={{ padding: '8px 10px', background: 'rgba(0,200,255,.05)', border: '1px solid rgba(0,200,255,.25)', borderRadius: 4 }}><strong style={{ color: 'var(--acc)' }}>{String(branch.finding.type || 'achado').toUpperCase()}</strong>: {help}</p> : null}
          <p className="lead">Valor: <strong>{String(branch.finding.value || '—')}</strong></p>
          {branch.finding.meta ? <p className="lead">Meta: <strong>{String(branch.finding.meta)}</strong></p> : null}
          {service ? <><h4>Servico identificado</h4><ul><li><strong style={{ color: 'var(--acc)' }}>{service.name}</strong> — {service.what}<a href={service.doc} target="_blank" rel="noopener noreferrer">documentacao ↗</a></li></ul></> : null}
          <h4>Links do achado</h4>{links.length ? <ul>{links.map((link) => <li key={link}><strong style={{ color: 'var(--acc)' }}>URL</strong><a href={link} target="_blank" rel="noopener noreferrer">{link}</a></li>)}</ul> : <p className="ex">Sem URL direta neste item.</p>}
          <h4>MITRE ATT&amp;CK</h4>{branch.mitreHints.length ? <ul>{branch.mitreHints.map((id) => { const technique = techniques.find((item) => item.id === id); return <li key={id}><strong>{id}</strong> — {technique?.name || 'Técnica no bundle recon'}<p className="ex">Indício automático a partir do tipo de achado do GHOSTRECON; confirmação manual recomendada.</p><a href={technique?.url || mitreTechniqueUrl(id)} target="_blank" rel="noopener noreferrer">attack.mitre.org ↗</a></li>; })}</ul> : <p className="ex">Sem técnica MITRE heurística. Consulta a matriz abaixo ou o bundle.</p>}
          <h4>OWASP Top 10 (2025)</h4>{branch.owaspHints.length ? <ul>{branch.owaspHints.map((hint: OwaspHint, index) => { const id = typeof hint === 'string' ? hint : String(hint.id || ''); const entry = owaspEntry(id); return <li key={`${id}-${index}`}><strong style={{ color: 'var(--owasp)' }}>{id}</strong> — {typeof hint === 'object' && hint.title ? hint.title : entry.title}<p className="ex">Etiqueta heurística (OWASP Top 10 2025). Não equivale a auditoria completa.</p><a href={entry.url} target="_blank" rel="noopener noreferrer">owasp.org ↗</a></li>; })}</ul> : <p className="ex">Sem etiqueta OWASP heurística neste achado.</p>}
        </div>
      </div>
    </div>
  );
}

export function MitreLivePage() {
  const { exportJson, importJson, liveJson, state } = useMitreLiveRuntime();
  const [selected, setSelected] = useState<FindingBranch | null>(null);
  return (
    <div className="mitre-live-react-root">
      <LiveHeader state={state} />
      <ProjectSecretPeers peers={state.peers} />
      <JsonDock exportJson={exportJson} importJson={importJson} />
      <Legend />
      <main>
        <p className="hint"><strong>Pipeline</strong> horizontal por fases. Cada <strong>achado</strong> gera um ramo <strong>↑ cima</strong> / <strong>↓ baixo</strong> em alternância. O <strong>quadrado laranja</strong> mostra a técnica MITRE (<code>T1595</code>) ou nº do achado — clique para ver os links <strong>ATT&amp;CK</strong> e <strong>OWASP</strong>. À <strong>esquerda</strong>, o separador <strong>JSON</strong> abre importar/exportar. À <strong>direita</strong>, <strong>Legenda</strong> abre o painel. O <strong>mini-pipeline</strong> mostra <strong>Kali ON / Kali OFF</strong>.</p>
        <Pipeline state={state} />
        <Branches state={state} onOpen={setSelected} />
        <Matrix state={state} />
        <details className="json-section" id="jsonDetails" open><summary>JSON live — <code>ghostrecon_mitre_live_state</code></summary><pre id="jsonLive">{JSON.stringify(liveJson, null, 2)}</pre></details>
      </main>
      <FindingModal branch={selected} bundle={state.bundle} close={() => setSelected(null)} />
    </div>
  );
}
