import { useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  appendHeadMarkup,
  executeScripts,
  snapshotLegacyDocument,
} from '../../LegacyDocument';
import type { ReactUiPage } from '../../page-registry';
import { domNodeToReact, type DomToReactOptions } from '../../runtime/react-dom-tree';
import { FindingsPanel } from '../execution/FindingsView';
import {
  PipelineBar,
  ProgressDetail,
  ProgressFill,
  ProgressPercent,
  STAT_KEY_BY_ID,
  StatValue,
} from '../execution/PipelineView';
import {
  createExecutionStore,
  ExecutionStoreProvider,
  installExecutionStore,
} from '../execution/store';
import {
  isNativeRunFormControl,
  NativeRunFormControl,
} from '../run-form/RunFormControls';
import {
  createRunFormStore,
  initialRunFormState,
  installRunFormStore,
  RunFormStoreProvider,
  useRunFormState,
} from '../run-form/store';
import {
  CockpitHelpOverlays,
  isCockpitHelpNode,
} from '../help/CockpitHelpOverlays';
import { installNativeCockpitServices } from './native-services';
import { NeuroSploitAutoDialog } from '../neurosploit/NeuroSploitAutoDialog';
import { GhostIaLaunchCard } from '../artex/GhostIaLaunchCard';

type CockpitSectionProps = {
  children: ReactNode;
};

function CockpitHeader({ children }: CockpitSectionProps) {
  return children;
}

function CockpitOverlayLayer({ children }: CockpitSectionProps) {
  return children;
}

function parseCockpitBody(source: string): Node[] {
  const parsed = new DOMParser().parseFromString(source, 'text/html');
  parsed.querySelectorAll('script').forEach((script) => script.remove());
  return [...parsed.body.childNodes].filter((node) => !isCockpitHelpNode(node));
}

const executionDomOptions: DomToReactOptions = {
  replaceElement(element, key) {
    if (element.id === 'pipelineBar') return <PipelineBar key={key} />;
    if (element.id === 'autoModeModal') return <NeuroSploitAutoDialog key={key} />;
    if (element.matches('.findings-panel')) return <FindingsPanel key={key} />;
    if (element.id === 'progressFill') return <ProgressFill key={key} />;
    if (element.id === 'progressPct') return <ProgressPercent key={key} />;
    if (element.id === 'progressDetail') return <ProgressDetail key={key} />;
    if (isNativeRunFormControl(element)) {
      return <NativeRunFormControl element={element} key={key} />;
    }
    const stat = STAT_KEY_BY_ID[element.id];
    if (stat) {
      return (
        <StatValue
          className={element.getAttribute('class') || 'stat-val'}
          id={element.id}
          key={key}
          stat={stat}
        />
      );
    }
    return undefined;
  },
};

function renderCockpitNode(node: Node, index: number): ReactNode {
  const rendered = domNodeToReact(node, index, executionDomOptions);
  if (node.nodeType !== Node.ELEMENT_NODE) return rendered;
  const element = node as Element;
  if (element.matches('header.header')) {
    return <CockpitHeader key={index}>{rendered}</CockpitHeader>;
  }
  if (element.matches('.app')) {
    return <CockpitWorkspace element={element} key={index} />;
  }
  return <CockpitOverlayLayer key={index}>{rendered}</CockpitOverlayLayer>;
}

type CockpitWorkspacePanel = 'run' | 'modules' | 'tools' | 'activity';

const COCKPIT_WORKSPACE_PANELS: ReadonlyArray<{
  id: CockpitWorkspacePanel;
  label: string;
  eyebrow: string;
}> = [
  { id: 'run', label: 'Executar', eyebrow: 'Alvo e operação' },
  { id: 'modules', label: 'Módulos', eyebrow: 'Motores e testes' },
  { id: 'tools', label: 'Ferramentas', eyebrow: 'Centrais auxiliares' },
  { id: 'activity', label: 'Atividade', eyebrow: 'Histórico e inteligência' },
];

function directElementChildren(element: Element | null): Element[] {
  return element ? [...element.children] : [];
}

function renderCockpitElements(elements: Element[], prefix: string): ReactNode[] {
  return elements.map((element, index) => (
    domNodeToReact(element, `${prefix}.${index}`, executionDomOptions)
  ));
}

function CockpitWorkspace({ element }: { element: Element }) {
  const [activePanel, setActivePanel] = useState<CockpitWorkspacePanel>('run');
  useEffect(() => {
    const openGhostIa = () => setActivePanel('tools');
    window.addEventListener('ghostrecon:open-ghost-ia', openGhostIa);
    return () => window.removeEventListener('ghostrecon:open-ghost-ia', openGhostIa);
  }, []);
  const runForm = useRunFormState();
  const selectedModules = Object.values(runForm.modules).filter(Boolean).length;
  const totalModules = Object.keys(runForm.modules).length;
  const sidebar = element.querySelector(':scope > .sidebar');
  const main = element.querySelector(':scope > .main');
  const targetSection = sidebar?.querySelector(':scope > .target-section') || null;
  const modulesSection = sidebar?.querySelector(':scope > .modules-section') || null;

  if (!sidebar || !main || !targetSection || !modulesSection) {
    return domNodeToReact(element, 'workspace-fallback', executionDomOptions);
  }

  const targetChildren = directElementChildren(targetSection);
  const historyIndex = targetChildren.findIndex((child) => child.id === 'runsHistory');
  const activityStart = historyIndex > 0 ? historyIndex - 1 : targetChildren.length;
  const runChildren = targetChildren
    .slice(0, activityStart)
    .filter((child) => child.id !== 'autoModeModal');
  const activityChildren = targetChildren.slice(activityStart);
  const autoModal = targetChildren.find((child) => child.id === 'autoModeModal');
  const moduleChildren = directElementChildren(modulesSection);
  const batchWrapIndex = runChildren.findIndex((child) => child.id === 'batchWrap');
  const essentialsEnd = batchWrapIndex >= 0 ? batchWrapIndex + 1 : 0;
  const essentialChildren = runChildren.slice(0, essentialsEnd);
  const hubActions = runChildren.find((child) => child.matches('.hub-actions-wrap'));
  const progress = runChildren.find((child) => child.id === 'progressWrap');
  const hubRows = directElementChildren(hubActions || null);
  const primaryHubItems = directElementChildren(hubRows[0] || null);
  const commandItems = primaryHubItems.filter((child) => (
    child.id === 'runBtn' || child.id === 'autoRunBtn' || child.id === 'autoRagStatusCard'
  ));
  const toolItems = primaryHubItems.filter((child) => !commandItems.includes(child));
  const toolRows = hubRows.slice(1);
  const configurationChildren = runChildren.slice(essentialsEnd)
    .filter((child) => child !== hubActions && child !== progress);
  const extraWorkspaceChildren = directElementChildren(element)
    .filter((child) => child !== sidebar && child !== main);
  const targetStatus = runForm.batchMode
    ? `${runForm.batchDomains.split(/\r?\n/).filter((value) => value.trim()).length} alvos no lote`
    : runForm.target.trim() || 'alvo ainda não informado';

  return (
    <div className="app cockpit-workspace" data-active-workspace={activePanel}>
      <aside className="sidebar cockpit-sidebar" aria-label="Controles da operação">
        <div className="cockpit-sidebar-heading">
          <span className="cockpit-sidebar-kicker">CENTRO DE CONTROLE</span>
          <div className="cockpit-sidebar-title-row">
            <strong>Operação</strong>
            <span className="cockpit-target-status" title={targetStatus}>{targetStatus}</span>
          </div>
          <span className="cockpit-sidebar-summary">
            {selectedModules} de {totalModules} módulos selecionados
          </span>
        </div>

        <nav className="cockpit-workspace-tabs" aria-label="Áreas do cockpit" role="tablist">
          {COCKPIT_WORKSPACE_PANELS.map((panel) => (
            <button
              aria-controls={`cockpit-panel-${panel.id}`}
              aria-selected={activePanel === panel.id}
              className="cockpit-workspace-tab"
              id={`cockpit-tab-${panel.id}`}
              key={panel.id}
              onClick={() => setActivePanel(panel.id)}
              role="tab"
              type="button"
            >
              <span>{panel.label}</span>
              <small>{panel.eyebrow}</small>
            </button>
          ))}
        </nav>

        <div className="cockpit-sidebar-panels">
          <section
            aria-labelledby="cockpit-tab-run"
            className="cockpit-sidebar-panel"
            hidden={activePanel !== 'run'}
            id="cockpit-panel-run"
            role="tabpanel"
          >
            <div className="target-section cockpit-run-panel">
              <div className="cockpit-run-essentials">
                {renderCockpitElements(essentialChildren, 'run-essential')}
              </div>
              <div className="cockpit-command-shelf">
                <div className="cockpit-section-heading">
                  <span>COMANDOS DA OPERAÇÃO</span>
                  <small>inicie manualmente ou delegue ao modo automático</small>
                </div>
                <div className="hub-actions-wrap cockpit-primary-actions">
                  <div>{renderCockpitElements(commandItems, 'run-action')}</div>
                </div>
                {progress ? domNodeToReact(progress, 'run-progress', executionDomOptions) : null}
              </div>
              <div className="cockpit-run-configuration">
                <div className="cockpit-section-heading">
                  <span>ESCOPO E PERFIL</span>
                  <small>ajustes avançados permanecem disponíveis abaixo</small>
                </div>
                {renderCockpitElements(configurationChildren, 'run-configuration')}
              </div>
            </div>
          </section>
          <section
            aria-labelledby="cockpit-tab-tools"
            className="cockpit-sidebar-panel"
            hidden={activePanel !== 'tools'}
            id="cockpit-panel-tools"
            role="tabpanel"
          >
            <div className="target-section cockpit-tools-panel">
              <div className="cockpit-panel-intro">
                <span>HUBS E ÁREAS ESPECIALIZADAS</span>
                <small>Abra painéis complementares sem interromper a configuração atual.</small>
              </div>
              <div className="hub-actions-wrap cockpit-tools-grid">
                <div className="cockpit-tools-first-row">
                  {renderCockpitElements(toolItems, 'tool-primary')}
                </div>
                {renderCockpitElements(toolRows, 'tool-row')}
                <GhostIaLaunchCard />
              </div>
            </div>
          </section>
          <section
            aria-labelledby="cockpit-tab-modules"
            className="cockpit-sidebar-panel"
            hidden={activePanel !== 'modules'}
            id="cockpit-panel-modules"
            role="tabpanel"
          >
            <div className="modules-section cockpit-modules-panel">
              {renderCockpitElements(moduleChildren, 'modules')}
            </div>
          </section>
          <section
            aria-labelledby="cockpit-tab-activity"
            className="cockpit-sidebar-panel"
            hidden={activePanel !== 'activity'}
            id="cockpit-panel-activity"
            role="tabpanel"
          >
            <div className="target-section cockpit-activity-panel">
              {renderCockpitElements(activityChildren, 'activity')}
            </div>
          </section>
        </div>
      </aside>

      {domNodeToReact(main, 'workspace-main', executionDomOptions)}
      {autoModal ? domNodeToReact(autoModal, 'auto-modal', executionDomOptions) : null}
      {renderCockpitElements(extraWorkspaceChildren, 'workspace-extra')}
    </div>
  );
}

/**
 * Entrada React nativa do cockpit.
 *
 * O DOM passa integralmente pelo reconciler React. O controller
 * versionado continua temporariamente como adapter de comportamento; serviços,
 * findings, pipeline e streams são extraídos por domínio sem arriscar os 225 IDs
 * e 88 valores de módulo durante a transição.
 */
export function CockpitPage({ page }: { page: ReactUiPage }) {
  const executionStore = useMemo(() => createExecutionStore(), []);
  const runFormStore = useMemo(() => {
    let storage: Storage | null = null;
    try {
      storage = window.localStorage;
    } catch {
      storage = null;
    }
    return createRunFormStore(initialRunFormState(page.source, storage));
  }, [page.source]);
  const snapshot = useMemo(() => snapshotLegacyDocument(page.source), [page.source]);
  const bodyNodes = useMemo(() => parseCockpitBody(page.source), [page.source]);
  const body = useMemo(
    () => bodyNodes.map((node, index) => renderCockpitNode(node, index)),
    [bodyNodes],
  );
  const [runtimeError, setRuntimeError] = useState('');

  useEffect(() => {
    document.title = snapshot.title;
    document.documentElement.lang = snapshot.htmlLang;
    document.body.dataset.ghostreconReactPage = page.id;
    document.body.dataset.ghostreconNativeCockpit = '1';
    for (const [name, value] of snapshot.bodyAttributes) document.body.setAttribute(name, value);

    const headElements = snapshot.headMarkup
      .map((markup) => appendHeadMarkup(markup, page.id))
      .filter((element): element is HTMLElement => Boolean(element));
    const uninstallExecutionStore = installExecutionStore(window, executionStore);
    const uninstallRunFormStore = installRunFormStore(window, runFormStore);
    const uninstallNativeServices = installNativeCockpitServices(window);
    const runtimeKey = `ghostrecon-react-runtime:${page.id}`;
    if (document.body.dataset.ghostreconLegacyRuntime !== runtimeKey) {
      document.body.dataset.ghostreconLegacyRuntime = runtimeKey;
      delete document.body.dataset.ghostreconLegacyReady;
      executeScripts(snapshot.scripts, page.id)
        .then(() => {
          document.body.dataset.ghostreconLegacyReady = '1';
        })
        .catch((error: unknown) => {
          const message = error instanceof Error ? error.message : String(error);
          setRuntimeError(message);
          console.error('[GHOSTRECON UI] falha no controller do cockpit:', error);
        });
    }

    return () => {
      uninstallNativeServices();
      uninstallRunFormStore();
      uninstallExecutionStore();
      for (const element of headElements) element.remove();
    };
  }, [executionStore, page.id, runFormStore, snapshot]);

  return (
    <RunFormStoreProvider store={runFormStore}>
      <ExecutionStoreProvider store={executionStore}>
        {runtimeError ? (
          <div className="ghostrecon-react-runtime-error" role="alert">
            <strong>Falha ao iniciar o cockpit.</strong>
            <span>{runtimeError}</span>
          </div>
        ) : null}
        {body}
        <CockpitHelpOverlays source={page.source} />
      </ExecutionStoreProvider>
    </RunFormStoreProvider>
  );
}
