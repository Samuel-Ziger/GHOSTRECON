import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
} from 'react';
import type { ReactUiPage } from '../../../page-registry';
import { useVigoliumWorkbenchShell } from './hooks';
import {
  REVIEW_TEMPLATES,
  curlFor,
  findingHost,
  formatBytes,
  formatWorkbenchDate,
  groupBy,
  normalizeMatchedAt,
  responseClass,
  safeDecode,
  severityClass,
  shortText,
  statusClass,
  type AgentMode,
  type WorkbenchRecord,
} from './model';

type TabName = 'overview' | 'requests' | 'findings' | 'oast' | 'agent' | 'modules' | 'reports';
type LoadState = { error: string; loading: boolean };

const EMPTY_LOAD: LoadState = { error: '', loading: false };

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function copyText(value: unknown): Promise<void> {
  try {
    await navigator.clipboard?.writeText(String(value || ''));
  } catch {
    // Clipboard can be denied for file://; preserving the UI is more useful than throwing.
  }
}

function DetailError({ value }: { value: string }) {
  return <><div className="detail-head"><div className="detail-title red">ERRO</div></div><div className="detail-body red">{value}</div></>;
}

function LoadingDetail({ title }: { title: string }) {
  return <><div className="detail-head"><div className="detail-title">{title}</div></div><div className="detail-body muted">carregando...</div></>;
}

function TableMessage({ columns, children, error = false }: { columns: number; children: string; error?: boolean }) {
  return <tr><td colSpan={columns} className={error ? 'red' : 'muted'}>{children}</td></tr>;
}

export function VigoliumWorkbenchPage({ page }: { page: ReactUiPage }) {
  const { service, signal } = useVigoliumWorkbenchShell(page);
  const agentRefreshTimer = useRef<number | null>(null);

  const [activeTab, setActiveTab] = useState<TabName>('overview');
  const [server, setServer] = useState<WorkbenchRecord>({});
  const [serverError, setServerError] = useState('');
  const [scans, setScans] = useState<WorkbenchRecord[]>([]);
  const [requests, setRequests] = useState<WorkbenchRecord[]>([]);
  const [findings, setFindings] = useState<WorkbenchRecord[]>([]);
  const [agents, setAgents] = useState<WorkbenchRecord[]>([]);
  const [oast, setOast] = useState<WorkbenchRecord[]>([]);
  const [reports, setReports] = useState<WorkbenchRecord[]>([]);
  const [totals, setTotals] = useState<Record<string, number>>({});
  const [load, setLoad] = useState<Record<string, LoadState>>({});

  const [reqFilters, setReqFilters] = useState({ search: '', method: '', domain: '', status_code: '' });
  const [reqGrouped, setReqGrouped] = useState(false);
  const [requestDetail, setRequestDetail] = useState<WorkbenchRecord | null>(null);
  const [selectedRequest, setSelectedRequest] = useState('');
  const [findingFilters, setFindingFilters] = useState({ search: '', severity: '', domain: '', finding_source: '' });
  const [findGrouped, setFindGrouped] = useState(false);
  const [findingDetail, setFindingDetail] = useState<WorkbenchRecord | null>(null);
  const [selectedFinding, setSelectedFinding] = useState('');
  const [oastFilters, setOastFilters] = useState({ search: '', protocol: '', module_id: '' });
  const [oastDetail, setOastDetail] = useState<WorkbenchRecord | null>(null);
  const [moduleFilters, setModuleFilters] = useState({ q: '', tag: '', kind: '' });
  const [modules, setModules] = useState<WorkbenchRecord[]>([]);
  const [moduleTags, setModuleTags] = useState<string[]>([]);

  const [agentMode, setAgentMode] = useState<AgentMode>('autopilot');
  const [agentForm, setAgentForm] = useState({
    target: '', source: '', intensity: 'balanced', auditMode: 'balanced', diff: '', files: '', prompt: '', instruction: '',
  });
  const [agentOutput, setAgentOutput] = useState('Pronto. Configure GHOSTRECON_VIGOLIUM_SERVER para executar pelo server-mode do Vigolium.');
  const [reportImport, setReportImport] = useState({ sourcePath: '', name: '', html: '' });
  const [collapsedRequestGroups, setCollapsedRequestGroups] = useState<Set<string>>(new Set());
  const [collapsedFindingGroups, setCollapsedFindingGroups] = useState<Set<string>>(new Set());

  const begin = (name: string) => setLoad((current) => ({ ...current, [name]: { error: '', loading: true } }));
  const fail = (name: string, error: unknown, silent = false) => setLoad((current) => ({
    ...current,
    [name]: { error: silent ? '' : message(error), loading: false },
  }));
  const done = (name: string) => setLoad((current) => ({ ...current, [name]: EMPTY_LOAD }));

  useEffect(() => () => {
    if (agentRefreshTimer.current !== null) window.clearTimeout(agentRefreshTimer.current);
  }, []);

  const refreshStatus = useCallback(async () => {
    try {
      setServer(await service.status(signal()));
      setServerError('');
    } catch (error) {
      setServer({});
      setServerError(message(error));
    }
  }, [service]);

  const loadScans = useCallback(async (silent = false) => {
    begin('scans');
    try {
      const result = await service.scans(signal());
      setScans(result.rows);
      setTotals((current) => ({ ...current, scans: result.total }));
      done('scans');
    } catch (error) { fail('scans', error, silent); }
  }, [service]);

  const loadRequests = useCallback(async (silent = false) => {
    begin('requests');
    try {
      const result = await service.requests(reqFilters, signal());
      setRequests(result.rows);
      setTotals((current) => ({ ...current, requests: result.total }));
      done('requests');
    } catch (error) { fail('requests', error, silent); }
  }, [reqFilters, service]);

  const loadFindings = useCallback(async (silent = false) => {
    begin('findings');
    try {
      const result = await service.findings(findingFilters, signal());
      setFindings(result.rows);
      setTotals((current) => ({ ...current, findings: result.total }));
      done('findings');
    } catch (error) { fail('findings', error, silent); }
  }, [findingFilters, service]);

  const loadOast = useCallback(async (silent = false) => {
    begin('oast');
    try {
      const result = await service.oast(oastFilters, signal());
      setOast(result.rows);
      setTotals((current) => ({ ...current, oast: result.total }));
      done('oast');
    } catch (error) { fail('oast', error, silent); }
  }, [oastFilters, service]);

  const loadAgentSessions = useCallback(async (silent = false) => {
    begin('agents');
    try {
      const result = await service.agentSessions(signal());
      setAgents(result.rows);
      setTotals((current) => ({ ...current, agents: result.total }));
      done('agents');
    } catch (error) { fail('agents', error, silent); }
  }, [service]);

  const loadReports = useCallback(async (silent = false) => {
    begin('reports');
    try {
      const result = await service.reports(signal());
      const rows = Array.isArray(result?.reports) ? result.reports as WorkbenchRecord[] : [];
      setReports(rows);
      setTotals((current) => ({ ...current, reports: Number(result?.total ?? rows.length) }));
      done('reports');
    } catch (error) { fail('reports', error, silent); }
  }, [service]);

  const loadModules = useCallback(async (filters = moduleFilters) => {
    begin('modules');
    try {
      const result = await service.modules(filters, signal());
      setModules(Array.isArray(result?.modules) ? result.modules : []);
      setModuleTags(Array.isArray(result?.tags) ? result.tags.slice(0, 60).map(String) : []);
      done('modules');
    } catch (error) { fail('modules', error); }
  }, [moduleFilters, service]);

  const loadOverview = useCallback(async () => {
    await refreshStatus();
    await Promise.allSettled([
      loadScans(true), loadRequests(true), loadFindings(true), loadAgentSessions(true), loadOast(true), loadReports(true),
    ]);
  }, [loadAgentSessions, loadFindings, loadOast, loadReports, loadRequests, loadScans, refreshStatus]);

  useEffect(() => {
    void loadOverview();
    void loadModules();
    // Initial load intentionally uses the initial filter snapshot only.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const showTab = useCallback((name: TabName) => {
    setActiveTab(name);
    if (name === 'requests' && !requests.length) void loadRequests();
    if (name === 'findings' && !findings.length) void loadFindings();
    if (name === 'oast' && !oast.length) void loadOast();
    if (name === 'modules') void loadModules();
    if (name === 'agent') void loadAgentSessions();
    if (name === 'reports') void loadReports();
  }, [agents.length, findings.length, loadAgentSessions, loadFindings, loadModules, loadOast, loadReports, loadRequests, oast.length, requests.length]);

  const refreshAll = useCallback(async () => {
    await loadOverview();
    if (activeTab === 'requests') await loadRequests();
    if (activeTab === 'findings') await loadFindings();
    if (activeTab === 'oast') await loadOast();
    if (activeTab === 'agent') await loadAgentSessions();
    if (activeTab === 'modules') await loadModules();
    if (activeTab === 'reports') await loadReports();
  }, [activeTab, loadAgentSessions, loadFindings, loadModules, loadOast, loadOverview, loadReports, loadRequests]);

  const selectRequest = async (id: string) => {
    setSelectedRequest(id);
    setRequestDetail({ __loading: true });
    try { setRequestDetail(await service.request(id, signal())); }
    catch (error) { setRequestDetail({ __error: message(error) }); }
  };

  const selectFinding = async (id: string) => {
    setSelectedFinding(id);
    setFindingDetail({ __loading: true });
    try { setFindingDetail(await service.finding(id, signal())); }
    catch (error) { setFindingDetail({ __error: message(error) }); }
  };

  const selectOast = async (id: string) => {
    setOastDetail({ __loading: true });
    try { setOastDetail(await service.oastDetail(id, signal())); }
    catch (error) { setOastDetail({ __error: message(error) }); }
  };

  const selectAgentSession = async (id: string) => {
    setAgentOutput(`loading session ${id}...\n`);
    try { setAgentOutput(JSON.stringify(await service.agentSession(id, signal()), null, 2)); }
    catch (error) { setAgentOutput(`ERROR: ${message(error)}`); }
  };

  const applyReviewTemplate = (kind: keyof typeof REVIEW_TEMPLATES) => {
    const template = REVIEW_TEMPLATES[kind];
    setAgentMode(template.mode);
    setAgentForm((current) => ({ ...current, prompt: template.prompt, instruction: template.instruction }));
  };

  const reviewFinding = async (id: string) => {
    try {
      const finding = await service.finding(id, signal());
      setAgentMode('query');
      setAgentForm((current) => ({
        ...current,
        prompt: `Review this finding for exploitability and false positives:\n\n${JSON.stringify(finding, null, 2)}`,
        instruction: 'Return verdict, confidence, reasoning, reproduction notes, and what evidence is still missing.',
      }));
      showTab('agent');
    } catch (error) { setAgentOutput(`ERROR: ${message(error)}`); }
  };

  const sendRequestToAgent = async (id: string) => {
    try {
      const record = await service.request(id, signal());
      setAgentMode('query');
      setAgentForm((current) => ({
        ...current,
        target: String(record.url || ''),
        prompt: `Review this HTTP exchange for vulnerabilities, auth/session issues, sensitive data, injection signs, and next tests:\n\nREQUEST:\n${safeDecode(record.raw_request || '')}\n\nRESPONSE:\n${safeDecode(record.raw_response || '')}`,
        instruction: 'Be concrete and avoid speculation. Suggest exact follow-up requests if useful.',
      }));
      showTab('agent');
    } catch (error) { setAgentOutput(`ERROR: ${message(error)}`); }
  };

  const runAgent = async () => {
    setAgentOutput(`starting ${agentMode}...\n`);
    const files = agentForm.files.split(',').map((value) => value.trim()).filter(Boolean);
    const body: WorkbenchRecord = {
      target: agentForm.target.trim(), input: agentForm.target.trim(), source: agentForm.source.trim(),
      intensity: agentForm.intensity, audit_mode: agentForm.auditMode, mode: agentForm.auditMode,
      diff: agentForm.diff.trim(), files, focus: agentForm.prompt.trim(), prompt: agentForm.prompt.trim(),
      instruction: agentForm.instruction.trim(),
    };
    if (agentMode === 'query') body.prompt_template = body.prompt ? '' : 'security-code-review';
    try {
      const result = await service.runAgent(agentMode, body, signal());
      setAgentOutput((current) => `${current}${JSON.stringify(result, null, 2)}`);
      agentRefreshTimer.current = window.setTimeout(() => void loadAgentSessions(), 1_200);
    } catch (error) { setAgentOutput((current) => `${current}ERROR: ${message(error)}`); }
  };

  const importReport = async () => {
    const sourcePath = reportImport.sourcePath.trim();
    const html = reportImport.html.trim();
    const name = reportImport.name.trim();
    if (!sourcePath && !html) {
      window.alert('Informe um caminho .html/.htm ou cole o HTML do report.');
      return;
    }
    try {
      const result = await service.importReport({
        sourcePath: sourcePath || undefined,
        html: sourcePath ? undefined : html,
        name: name || undefined,
      }, signal());
      if (result?.report?.url) {
        setReportImport({ sourcePath: '', name: '', html: sourcePath ? html : '' });
        window.open(service.apiUrl(String(result.report.url)), '_blank', 'noopener,noreferrer');
      }
      await loadReports();
    } catch (error) { window.alert(`Import report: ${message(error)}`); }
  };

  const requestGroups = useMemo(() => groupBy(requests, (record) => String(record.hostname || '(unknown)')), [requests]);
  const findingGroups = useMemo(() => groupBy(findings, findingHost), [findings]);
  const tabs: Array<[TabName, string]> = [
    ['overview', 'OVERVIEW'], ['requests', 'HTTP RECORDS'], ['findings', 'FINDINGS'], ['oast', 'OAST'],
    ['agent', 'IA / CODE REVIEW'], ['modules', 'MODULES'], ['reports', 'REPORTS'],
  ];
  const serverOk = Boolean(server.ok);
  const serverConfigured = Boolean(server.configured);

  const enter = (handler: () => void) => (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Enter') handler();
  };

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">GHOSTRECON / VIGOLIUM WORKBENCH</div>
        <div className="subtitle">requests, findings, agent IA e catalogo de modulos</div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
          <span id="serverPill" className={`pill ${serverOk ? 'ok' : serverConfigured || serverError ? 'bad' : 'warn'}`}>
            {serverOk ? 'server: online' : serverConfigured || serverError ? 'server: erro' : 'server: nao configurado'}
          </span>
          <button type="button" onClick={() => void refreshAll()}>refresh</button>
          <button type="button" onClick={() => { window.location.href = 'index.html'; }}>voltar</button>
        </div>
      </header>

      <nav className="tabs">
        {tabs.map(([name, label]) => <button key={name} type="button" className={`tab${activeTab === name ? ' active' : ''}`} data-tab={name} onClick={() => showTab(name)}>{label}</button>)}
      </nav>

      <main className="main">
        <section id="view-overview" className={`view single${activeTab === 'overview' ? ' active' : ''}`}>
          <div className="left">
            <div className="card-grid">
              <div className="card"><div className="k">HTTP records</div><div className="v" id="ovRecords">{totals.requests ?? requests.length ?? '-'}</div></div>
              <div className="card"><div className="k">Findings</div><div className="v" id="ovFindings">{totals.findings ?? findings.length ?? '-'}</div></div>
              <div className="card"><div className="k">Scans</div><div className="v" id="ovScans">{totals.scans ?? scans.length ?? '-'}</div></div>
              <div className="card"><div className="k">Agent sessions</div><div className="v" id="ovAgents">{totals.agents ?? agents.length ?? '-'}</div></div>
              <div className="card"><div className="k">OAST</div><div className="v" id="ovOast">{totals.oast ?? oast.length ?? '-'}</div></div>
              <div className="card"><div className="k">Reports</div><div className="v" id="ovReports">{totals.reports ?? reports.length ?? '-'}</div></div>
            </div>
            <div className="toolbar"><span className="green">Server mode</span><span id="serverDetail" className="muted">{serverError || (server.baseUrl ? `${server.baseUrl} - ${server.message || ''}` : server.message || 'Use GHOSTRECON_VIGOLIUM_SERVER para conectar ao workbench de dados do Vigolium.')}</span></div>
            <div className="toolbar">
              <button type="button" className="hot" onClick={() => showTab('agent')}>abrir IA/code review</button>
              <button type="button" onClick={() => showTab('requests')}>ver requests agrupadas</button>
              <button type="button" onClick={() => showTab('findings')}>ver findings</button>
              <button type="button" onClick={() => showTab('modules')}>catalogo local</button>
              <button type="button" onClick={() => showTab('reports')}>reports HTML</button>
            </div>
            <div className="table-wrap"><table><thead><tr><th>Status</th><th>Scan</th><th>Mode/source</th><th>Findings</th><th>Started</th></tr></thead><tbody id="overviewScans">
              {load.scans?.error ? <TableMessage columns={5} error>{load.scans.error}</TableMessage> : scans.length ? scans.map((scan, index) => <tr key={String(scan.uuid || scan.scan_uuid || index)}><td><span className={statusClass(scan.status)}>{scan.status || '-'}</span></td><td>{scan.name || scan.uuid || scan.scan_uuid || '-'}</td><td className="muted">{[scan.scan_mode, scan.scan_source].filter(Boolean).join(' / ') || '-'}</td><td>{scan.total_findings ?? scan.findings ?? 0}</td><td className="muted">{formatWorkbenchDate(scan.started_at || scan.created_at)}</td></tr>) : <TableMessage columns={5}>sem scans</TableMessage>}
            </tbody></table></div>
          </div>
        </section>

        <section id="view-requests" className={`view split${activeTab === 'requests' ? ' active' : ''}`}>
          <div className="left">
            <div className="toolbar">
              <input id="reqSearch" placeholder="search url/path" value={reqFilters.search} onChange={(event) => setReqFilters((current) => ({ ...current, search: event.currentTarget.value }))} onKeyDown={enter(() => void loadRequests())} />
              <select id="reqMethod" value={reqFilters.method} onChange={(event) => setReqFilters((current) => ({ ...current, method: event.currentTarget.value }))}><option value="">method:all</option><option>GET</option><option>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option></select>
              <input id="reqHost" placeholder="host / *.domain" value={reqFilters.domain} onChange={(event) => setReqFilters((current) => ({ ...current, domain: event.currentTarget.value }))} />
              <input id="reqStatus" placeholder="status 200,301" value={reqFilters.status_code} onChange={(event) => setReqFilters((current) => ({ ...current, status_code: event.currentTarget.value }))} />
              <button type="button" onClick={() => void loadRequests()}>filtrar</button>
              <button type="button" id="reqGroupBtn" className={reqGrouped ? 'active' : ''} onClick={() => setReqGrouped((value) => !value)}>by-host</button>
            </div>
            <div className={`table-wrap${reqGrouped ? ' hidden' : ''}`} id="requestsTableWrap"><table><thead><tr><th>Meth</th><th>SC</th><th>Host</th><th>Path</th><th>Type</th><th>Size</th><th>MS</th></tr></thead><tbody id="requestsRows">
              {load.requests?.error ? <TableMessage columns={7} error>{load.requests.error}</TableMessage> : requests.length ? requests.map((record, index) => <tr key={String(record.uuid || index)} className={selectedRequest === String(record.uuid || '') ? 'selected' : ''} onClick={() => void selectRequest(String(record.uuid || ''))}><td className={`method m${record.method || ''}`}>{record.method || '-'}</td><td className={responseClass(record.status_code)}>{record.status_code || '---'}</td><td>{record.hostname || '-'}</td><td>{shortText(record.path || record.url || '-', 110)}</td><td className="muted">{shortText(record.response_content_type || '-', 34)}</td><td className="muted">{formatBytes(record.response_content_length)}</td><td className="muted">{record.response_time_ms ? `${record.response_time_ms}ms` : '-'}</td></tr>) : <TableMessage columns={7}>sem records</TableMessage>}
            </tbody></table></div>
            <div className={`table-wrap${reqGrouped ? '' : ' hidden'}`} id="requestsGrouped">
              {requestGroups.length ? requestGroups.map(([host, rows]) => <div className="group" key={host}><button type="button" className="group-head" onClick={() => setCollapsedRequestGroups((current) => { const next = new Set(current); next.has(host) ? next.delete(host) : next.add(host); return next; })}><span className="blue">{host}</span><span style={{ marginLeft: 'auto' }}>{rows.length}</span></button><div className={`group-items${collapsedRequestGroups.has(host) ? ' hidden' : ''}`}>{rows.map((record, index) => <button type="button" className="rowbtn" key={String(record.uuid || index)} onClick={() => void selectRequest(String(record.uuid || ''))}><span className={`method m${record.method || ''}`}>{record.method || '-'}</span><span className={responseClass(record.status_code)}>{record.status_code || '---'}</span><span>{shortText(record.path || record.url || '-', 120)}</span><span className="muted">{formatBytes(record.response_content_length)}</span><span className="muted">{record.response_time_ms ? `${record.response_time_ms}ms` : '-'}</span></button>)}</div></div>) : <div className="muted" style={{ padding: 10 }}>sem records</div>}
            </div>
          </div>
          <aside className="right" id="requestDetail">
            {!requestDetail ? <><div className="detail-head"><div className="detail-title">HTTP RECORD DETAIL</div></div><div className="detail-body muted">Selecione uma request para ver headers, raw request/response e curl.</div></> : requestDetail.__loading ? <LoadingDetail title="LOADING RECORD" /> : requestDetail.__error ? <DetailError value={requestDetail.__error} /> : <><div className="detail-head"><div className="detail-title">{requestDetail.method || ''} {requestDetail.url || selectedRequest}</div><button type="button" onClick={() => setRequestDetail(null)}>x</button></div><div className="detail-body"><div className="kv"><span className="key">status</span><span className={responseClass(requestDetail.status_code)}>{requestDetail.status_code || '-'} {requestDetail.status_phrase || ''}</span></div><div className="kv"><span className="key">host</span><span>{requestDetail.hostname || '-'}:{requestDetail.port || ''}</span></div><div className="kv"><span className="key">source</span><span>{requestDetail.source || '-'}</span></div><div className="kv"><span className="key">risk</span><span>{requestDetail.risk_score || 0}</span></div><div className="toolbar" style={{ padding: '6px 0', background: 'transparent', border: 0 }}><button type="button" onClick={() => void copyText(requestDetail.url)}>copy url</button><button type="button" onClick={() => void copyText(safeDecode(requestDetail.raw_request))}>copy request</button><button type="button" onClick={() => void copyText(curlFor(requestDetail))}>copy curl</button><button type="button" onClick={() => void sendRequestToAgent(selectedRequest)}>IA review request</button></div><div className="section-title">raw request</div><pre className="codebox">{safeDecode(requestDetail.raw_request) || 'sem raw_request'}</pre><div className="section-title">raw response</div><pre className="codebox">{safeDecode(requestDetail.raw_response) || 'sem raw_response'}</pre></div></>}
          </aside>
        </section>

        <section id="view-findings" className={`view split${activeTab === 'findings' ? ' active' : ''}`}>
          <div className="left"><div className="toolbar">
            <input id="findSearch" placeholder="search finding/module/url" value={findingFilters.search} onChange={(event) => setFindingFilters((current) => ({ ...current, search: event.currentTarget.value }))} onKeyDown={enter(() => void loadFindings())} />
            <select id="findSeverity" value={findingFilters.severity} onChange={(event) => setFindingFilters((current) => ({ ...current, severity: event.currentTarget.value }))}><option value="">severity:all</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select>
            <input id="findDomain" placeholder="domain" value={findingFilters.domain} onChange={(event) => setFindingFilters((current) => ({ ...current, domain: event.currentTarget.value }))} />
            <input id="findSource" placeholder="source: agent/audit/oast" value={findingFilters.finding_source} onChange={(event) => setFindingFilters((current) => ({ ...current, finding_source: event.currentTarget.value }))} />
            <button type="button" onClick={() => void loadFindings()}>filtrar</button><button type="button" id="findGroupBtn" className={findGrouped ? 'active' : ''} onClick={() => setFindGrouped((value) => !value)}>by-host</button>
          </div><div className={`table-wrap${findGrouped ? ' hidden' : ''}`} id="findingsTableWrap"><table><thead><tr><th>Sev</th><th>Conf</th><th>Module</th><th>Description</th><th>Matched</th><th>Source</th></tr></thead><tbody id="findingsRows">
            {load.findings?.error ? <TableMessage columns={6} error>{load.findings.error}</TableMessage> : findings.length ? findings.map((finding, index) => <tr key={String(finding.id || index)} className={selectedFinding === String(finding.id || '') ? 'selected' : ''} onClick={() => void selectFinding(String(finding.id || ''))}><td className={severityClass(finding.severity)}>{finding.severity || '-'}</td><td className="muted">{finding.confidence || '-'}</td><td>{shortText(finding.module_name || finding.module_id || '-', 36)}</td><td>{shortText(finding.description || finding.module_short || '-', 120)}</td><td className="muted">{shortText(normalizeMatchedAt(finding).join(', '), 90)}</td><td className="blue">{finding.finding_source || finding.module_type || '-'}</td></tr>) : <TableMessage columns={6}>sem findings</TableMessage>}
          </tbody></table></div><div className={`table-wrap${findGrouped ? '' : ' hidden'}`} id="findingsGrouped">
            {findingGroups.length ? findingGroups.map(([host, rows]) => <div className="group" key={host}><button type="button" className="group-head" onClick={() => setCollapsedFindingGroups((current) => { const next = new Set(current); next.has(host) ? next.delete(host) : next.add(host); return next; })}><span className="blue">{host}</span><span style={{ marginLeft: 'auto' }}>{rows.length}</span></button><div className={`group-items${collapsedFindingGroups.has(host) ? ' hidden' : ''}`}>{rows.map((finding, index) => <button type="button" className="rowbtn" style={{ gridTemplateColumns: '70px 90px minmax(0,1fr) 130px 90px' }} key={String(finding.id || index)} onClick={() => void selectFinding(String(finding.id || ''))}><span className={severityClass(finding.severity)}>{finding.severity || '-'}</span><span className="muted">{finding.confidence || '-'}</span><span>{shortText(finding.description || finding.module_name || '-', 120)}</span><span className="muted">{shortText(finding.module_name || finding.module_id || '-', 30)}</span><span className="blue">{finding.finding_source || '-'}</span></button>)}</div></div>) : <div className="muted" style={{ padding: 10 }}>sem findings</div>}
          </div></div>
          <aside className="right" id="findingDetail">
            {!findingDetail ? <><div className="detail-head"><div className="detail-title">FINDING DETAIL</div></div><div className="detail-body muted">Selecione um finding para ver evidencia e pedir revisao por IA.</div></> : findingDetail.__loading ? <LoadingDetail title="LOADING FINDING" /> : findingDetail.__error ? <DetailError value={findingDetail.__error} /> : <><div className="detail-head"><div className="detail-title">{findingDetail.module_name || findingDetail.module_id || 'finding'} #{findingDetail.id}</div><button type="button" onClick={() => setFindingDetail(null)}>x</button></div><div className="detail-body"><div className="kv"><span className="key">severity</span><span className={severityClass(findingDetail.severity)}>{findingDetail.severity || '-'}</span></div><div className="kv"><span className="key">confidence</span><span>{findingDetail.confidence || '-'}</span></div><div className="kv"><span className="key">source</span><span>{findingDetail.finding_source || '-'}</span></div><div className="kv"><span className="key">matched</span><span>{normalizeMatchedAt(findingDetail).join(', ') || '-'}</span></div><div className="toolbar" style={{ padding: '6px 0', background: 'transparent', border: 0 }}><button type="button" onClick={() => void copyText(JSON.stringify(findingDetail, null, 2))}>copy json</button><button type="button" onClick={() => void reviewFinding(String(findingDetail.id || selectedFinding))}>IA revisar finding</button></div><div className="section-title">description</div><div>{findingDetail.description || findingDetail.module_short || '-'}</div><div className="section-title">request</div><pre className="codebox">{findingDetail.request || 'sem request'}</pre><div className="section-title">response</div><pre className="codebox">{findingDetail.response || 'sem response'}</pre><div className="section-title">additional evidence</div><pre className="codebox">{Array.isArray(findingDetail.additional_evidence) ? findingDetail.additional_evidence.join('\n\n---\n\n') : 'sem evidencia extra'}</pre></div></>}
          </aside>
        </section>

        <section id="view-agent" className={`view split${activeTab === 'agent' ? ' active' : ''}`}>
          <div className="left"><div className="form-grid"><div className="form-wide mode-grid">{(['autopilot', 'swarm', 'audit', 'query'] as AgentMode[]).map((mode) => <button type="button" key={mode} className={`mode-card${agentMode === mode ? ' active' : ''}`} data-agent-mode={mode} onClick={() => setAgentMode(mode)}><div className="t">{mode.toUpperCase()}</div><div className="d">{{ autopilot: 'Agente autonomo: explora, escaneia, audita e itera.', swarm: 'Planejamento IA + selecao de modulos + triage.', audit: 'Review de codigo com fases do Vigolium.', query: 'Pergunta unica para confirmar finding, request ou trecho de codigo.' }[mode]}</div></button>)}</div>
            <div><label className="muted">Target URL</label><input id="agentTarget" placeholder="https://target.tld" value={agentForm.target} onChange={(event) => setAgentForm((current) => ({ ...current, target: event.currentTarget.value }))} /></div>
            <div><label className="muted">Source code / repo / zip path</label><input id="agentSource" placeholder="C:\\repo\\app ou https://github.com/org/repo" value={agentForm.source} onChange={(event) => setAgentForm((current) => ({ ...current, source: event.currentTarget.value }))} /></div>
            <div><label className="muted">Intensity</label><select id="agentIntensity" value={agentForm.intensity} onChange={(event) => setAgentForm((current) => ({ ...current, intensity: event.currentTarget.value }))}><option>quick</option><option>balanced</option><option>deep</option></select></div>
            <div><label className="muted">Audit mode</label><select id="agentAuditMode" value={agentForm.auditMode} onChange={(event) => setAgentForm((current) => ({ ...current, auditMode: event.currentTarget.value }))}><option>lite</option><option>balanced</option><option>deep</option></select></div>
            <div><label className="muted">Diff / PR</label><input id="agentDiff" placeholder="HEAD~1 ou GitHub PR URL" value={agentForm.diff} onChange={(event) => setAgentForm((current) => ({ ...current, diff: event.currentTarget.value }))} /></div>
            <div><label className="muted">Files CSV</label><input id="agentFiles" placeholder="src/auth.ts,src/api/users.ts" value={agentForm.files} onChange={(event) => setAgentForm((current) => ({ ...current, files: event.currentTarget.value }))} /></div>
            <div className="form-wide"><label className="muted">Prompt / objetivo</label><textarea id="agentPrompt" placeholder="Revise autenticacao/autorizacao, IDOR/BOLA, secrets, injection e paths de API." value={agentForm.prompt} onChange={(event) => setAgentForm((current) => ({ ...current, prompt: event.currentTarget.value }))} /></div>
            <div className="form-wide"><label className="muted">Instruction extra</label><textarea id="agentInstruction" placeholder="Foque em impacto real, PoC reproduzivel e falsos positivos baixos." value={agentForm.instruction} onChange={(event) => setAgentForm((current) => ({ ...current, instruction: event.currentTarget.value }))} /></div>
            <div className="form-wide toolbar" style={{ padding: 0, border: 0, background: 'transparent' }}><button type="button" onClick={() => applyReviewTemplate('auth')}>template auth/authz</button><button type="button" onClick={() => applyReviewTemplate('pr')}>template PR diff</button><button type="button" onClick={() => applyReviewTemplate('api')}>template API routes</button><button type="button" onClick={() => applyReviewTemplate('fp')}>template false-positive review</button><button type="button" className="hot" onClick={() => void runAgent()}>RUN IA</button><button type="button" onClick={() => void loadAgentSessions()}>sessions</button></div>
          </div><div className="table-wrap" style={{ height: 'calc(100% - 360px)' }}><table><thead><tr><th>Status</th><th>Mode</th><th>Target/source</th><th>Findings</th><th>Started</th></tr></thead><tbody id="agentRows">{load.agents?.error ? <TableMessage columns={5} error>{load.agents.error}</TableMessage> : agents.length ? agents.map((agent, index) => { const id = String(agent.uuid || agent.agentic_scan_uuid || agent.id || index); return <tr key={id} onClick={() => void selectAgentSession(id)}><td><span className={statusClass(agent.status)}>{agent.status || '-'}</span></td><td className="blue">{agent.mode || '-'}</td><td>{shortText(agent.target_url || agent.source_label || agent.source || agent.prompt || '-', 90)}</td><td>{agent.finding_count ?? agent.total_findings ?? 0}</td><td className="muted">{formatWorkbenchDate(agent.started_at || agent.created_at)}</td></tr>; }) : <TableMessage columns={5}>sem sessions</TableMessage>}</tbody></table></div></div>
          <aside className="right"><div className="detail-head"><div className="detail-title">IA OUTPUT</div><button type="button" onClick={() => setAgentOutput('')}>clear</button></div><pre id="agentOutput" className="terminal">{agentOutput}</pre></aside>
        </section>

        <section id="view-oast" className={`view split${activeTab === 'oast' ? ' active' : ''}`}>
          <div className="left"><div className="toolbar"><input id="oastSearch" placeholder="search OAST interaction" value={oastFilters.search} onChange={(event) => setOastFilters((current) => ({ ...current, search: event.currentTarget.value }))} onKeyDown={enter(() => void loadOast())} /><select id="oastProtocol" value={oastFilters.protocol} onChange={(event) => setOastFilters((current) => ({ ...current, protocol: event.currentTarget.value }))}><option value="">protocol:all</option><option>dns</option><option>http</option><option>smtp</option></select><input id="oastModule" placeholder="module_id" value={oastFilters.module_id} onChange={(event) => setOastFilters((current) => ({ ...current, module_id: event.currentTarget.value }))} /><button type="button" onClick={() => void loadOast()}>filtrar</button></div><div className="table-wrap"><table><thead><tr><th>Protocol</th><th>Unique ID</th><th>Target</th><th>Param</th><th>Module</th><th>Time</th></tr></thead><tbody id="oastRows">{load.oast?.error ? <TableMessage columns={6} error>{load.oast.error}</TableMessage> : oast.length ? oast.map((item, index) => { const id = String(item.id || item.unique_id || index); return <tr key={id} onClick={() => void selectOast(id)}><td className="blue">{item.protocol || '-'}</td><td>{item.unique_id || item.full_id || '-'}</td><td>{shortText(item.target_url || '-', 80)}</td><td className="muted">{item.parameter_name || '-'}</td><td className="muted">{item.module_id || '-'}</td><td className="muted">{formatWorkbenchDate(item.interacted_at || item.created_at)}</td></tr>; }) : <TableMessage columns={6}>sem OAST</TableMessage>}</tbody></table></div></div>
          <aside className="right" id="oastDetail">{!oastDetail ? <><div className="detail-head"><div className="detail-title">OAST DETAIL</div></div><div className="detail-body muted">Selecione uma interacao OAST para ver raw request/response.</div></> : oastDetail.__loading ? <LoadingDetail title="LOADING OAST" /> : oastDetail.__error ? <DetailError value={oastDetail.__error} /> : <><div className="detail-head"><div className="detail-title">{oastDetail.protocol || 'OAST'} {oastDetail.unique_id || oastDetail.id || ''}</div><button type="button" onClick={() => setOastDetail(null)}>x</button></div><div className="detail-body"><div className="kv"><span className="key">target</span><span>{oastDetail.target_url || '-'}</span></div><div className="kv"><span className="key">parameter</span><span>{oastDetail.parameter_name || '-'}</span></div><div className="kv"><span className="key">module</span><span>{oastDetail.module_id || '-'}</span></div><div className="kv"><span className="key">remote</span><span>{oastDetail.remote_address || '-'}</span></div><div className="section-title">raw request</div><pre className="codebox">{oastDetail.raw_request || 'sem raw_request'}</pre><div className="section-title">raw response</div><pre className="codebox">{oastDetail.raw_response || 'sem raw_response'}</pre></div></>}</aside>
        </section>

        <section id="view-modules" className={`view single${activeTab === 'modules' ? ' active' : ''}`}><div className="left"><div className="toolbar"><input id="modSearch" placeholder="buscar modulos: idor, jwt, xss" value={moduleFilters.q} onChange={(event) => setModuleFilters((current) => ({ ...current, q: event.currentTarget.value }))} onKeyDown={enter(() => void loadModules())} /><input id="modTag" placeholder="tag: access-control" value={moduleFilters.tag} onChange={(event) => setModuleFilters((current) => ({ ...current, tag: event.currentTarget.value }))} /><select id="modKind" value={moduleFilters.kind} onChange={(event) => setModuleFilters((current) => ({ ...current, kind: event.currentTarget.value }))}><option value="">kind:all</option><option>active</option><option>passive</option></select><button type="button" onClick={() => void loadModules()}>buscar</button></div><div id="moduleTags" style={{ padding: 10, borderBottom: '1px solid var(--line)' }}>{moduleTags.map((tag) => <button type="button" key={tag} className="tag" onClick={() => { const filters = { ...moduleFilters, tag }; setModuleFilters(filters); void loadModules(filters); }}>{tag}</button>)}</div><div className="table-wrap"><table><thead><tr><th>Kind</th><th>ID</th><th>Severity</th><th>Confidence</th><th>Tags</th><th>Short</th></tr></thead><tbody id="moduleRows">{load.modules?.error ? <TableMessage columns={6} error>{load.modules.error}</TableMessage> : modules.length ? modules.map((module, index) => <tr key={String(module.id || index)}><td className="blue">{module.kind || ''}</td><td>{module.id || ''}</td><td className={severityClass(module.severity)}>{module.severity || '-'}</td><td className="muted">{module.confidence || '-'}</td><td>{Array.isArray(module.tags) ? module.tags.map((tag: unknown) => <span className="tag" key={String(tag)}>{String(tag)}</span>) : null}</td><td>{module.short || module.descriptionSummary || ''}</td></tr>) : <TableMessage columns={6}>sem modulos</TableMessage>}</tbody></table></div></div></section>

        <section id="view-reports" className={`view single${activeTab === 'reports' ? ' active' : ''}`}><div className="left"><div className="toolbar"><span className="green">Vigolium HTML reports</span><span className="muted">Arquivos gerados em .runtime/vigolium-reports</span><button type="button" onClick={() => void loadReports()}>refresh</button></div><div className="toolbar"><input id="reportImportPath" placeholder="importar report externo: C:\\tmp\\report.html ou /tmp/report.html" value={reportImport.sourcePath} onChange={(event) => setReportImport((current) => ({ ...current, sourcePath: event.currentTarget.value }))} /><input id="reportImportName" placeholder="nome opcional" value={reportImport.name} onChange={(event) => setReportImport((current) => ({ ...current, name: event.currentTarget.value }))} /><button type="button" onClick={() => void importReport()}>importar</button></div><textarea id="reportImportHtml" placeholder="ou cole HTML do report aqui" style={{ minHeight: 76 }} value={reportImport.html} onChange={(event) => setReportImport((current) => ({ ...current, html: event.currentTarget.value }))} /><div className="table-wrap"><table><thead><tr><th>File</th><th>Size</th><th>Modified</th><th>Origin</th><th>Actions</th></tr></thead><tbody id="reportRows">{load.reports?.error ? <TableMessage columns={5} error>{load.reports.error}</TableMessage> : reports.length ? reports.map((report, index) => <tr key={String(report.file || index)}><td className="blue">{report.file || '-'}</td><td>{formatBytes(report.size)}</td><td className="muted">{formatWorkbenchDate(report.mtime)}</td><td className="muted">{shortText(report.origin || 'runtime', 120)}</td><td><button type="button" onClick={() => window.open(service.apiUrl(String(report.url || '')), '_blank', 'noopener,noreferrer')}>abrir</button><button type="button" onClick={() => void copyText(report.url)}>copy url</button></td></tr>) : <TableMessage columns={5}>sem reports HTML</TableMessage>}</tbody></table></div></div></section>
      </main>
    </div>
  );
}
