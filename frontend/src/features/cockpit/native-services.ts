import {
  apiUrl,
  parseProgramHeaders,
  readOptionalAuthConfig,
  requestCsrfToken,
  resolveApiBase,
  toPipelineAuth,
  type OptionalAuthConfig,
} from '../../services/api-client';
import { NdjsonDecoder } from '../../services/ndjson';
import type { StorageLike } from '../../services/storage';
import {
  findingMatchesFilter,
  findingMatchesSearch,
  isDorkFindingType,
  isVigoliumFinding,
  selectFindings,
  type Finding,
} from '../findings/model';
import {
  createPipelineState,
  formatElapsed,
  normalizePipelineNode,
  pipelineReducer,
  type PipelineAction,
  type PipelineState,
} from '../pipeline/model';
import {
  createManualReconService,
  type ManualReconOptions,
} from '../manual-recon/service';
import { createAutoForgeService } from '../auto-forge/service';
import { installExportsIntegrations } from '../exports-integrations/service';
import { createInfraHistoryService } from '../infra-history/service';
import { createVigoliumService } from '../vigolium/service';
import {
  buildManualReconBody,
  collectRunTargets,
  extractCascadeSubdomains,
  normalizeTargetKey,
  parseBatchTargets,
  parseCascadeOutOfScopeRules,
  projectRunForm,
  type FormRoot,
  type RunFormProjectionOptions,
} from '../run-form/model';
import {
  consumeReconNdjson,
  type ReconStreamConsumeOptions,
} from '../run-form/stream-dispatcher';

type CockpitWindow = Pick<Window, 'fetch' | 'location' | 'localStorage'>;

function readableStorage(windowRef: CockpitWindow): StorageLike | null {
  try {
    return windowRef.localStorage;
  } catch {
    return null;
  }
}

export type NativeCockpitServices = ReturnType<typeof createNativeCockpitServices>;

/**
 * Ponte pequena e versionada entre o controller de compatibilidade e os
 * domínios React/TypeScript. O controller ainda coordena a interface, mas a
 * lógica abaixo deixa de existir em duas implementações independentes.
 */
export function createNativeCockpitServices(windowRef: CockpitWindow) {
  let pipelineState = createPipelineState();
  const calls = {
    api: 0,
    autoForge: 0,
    ndjson: 0,
    findings: 0,
    infraHistory: 0,
    manualRecon: 0,
    pipeline: 0,
    runForm: 0,
    vigolium: 0,
  };
  const storage = () => readableStorage(windowRef);
  const apiBase = () => resolveApiBase({
    protocol: windowRef.location.protocol,
    storage: storage(),
  });
  const optionalAuth = () => readOptionalAuthConfig(storage());
  const manualReconService = createManualReconService({
    apiBase,
    auth: optionalAuth,
    fetchImpl: windowRef.fetch.bind(windowRef),
  });
  const autoForgeService = createAutoForgeService({
    apiBase,
    auth: optionalAuth,
    fetchImpl: windowRef.fetch.bind(windowRef),
    storage: storage(),
  });
  const infraHistoryService = createInfraHistoryService({
    apiBase,
    auth: optionalAuth,
    fetchImpl: windowRef.fetch.bind(windowRef),
    protocol: () => windowRef.location.protocol,
    storage,
  });
  const vigoliumService = createVigoliumService({
    apiBase,
    auth: optionalAuth,
    fetchImpl: windowRef.fetch.bind(windowRef),
    storage: storage(),
  });

  const autoForge = Object.freeze(Object.fromEntries(
    Object.entries(autoForgeService).map(([name, handler]) => [
      name,
      (...args: unknown[]) => {
        calls.autoForge += 1;
        return (handler as (...values: unknown[]) => unknown)(...args);
      },
    ]),
  )) as typeof autoForgeService;
  const infraHistory = Object.freeze(Object.fromEntries(
    Object.entries(infraHistoryService).map(([name, handler]) => [
      name,
      (...args: unknown[]) => {
        calls.infraHistory += 1;
        return (handler as (...values: unknown[]) => unknown)(...args);
      },
    ]),
  )) as typeof infraHistoryService;
  const vigolium = Object.freeze(Object.fromEntries(
    Object.entries(vigoliumService).map(([name, handler]) => [
      name,
      (...args: unknown[]) => {
        calls.vigolium += 1;
        return (handler as (...values: unknown[]) => unknown)(...args);
      },
    ]),
  )) as typeof vigoliumService;

  return Object.freeze({
    version: 1 as const,
    calls,
    api: Object.freeze({
      resolveBase: () => {
        calls.api += 1;
        return apiBase();
      },
      url: (pathname: string) => {
        calls.api += 1;
        return apiUrl(pathname, apiBase());
      },
      readOptionalAuth: () => {
        calls.api += 1;
        return optionalAuth();
      },
      readPipelineAuth: () => {
        calls.api += 1;
        return toPipelineAuth(optionalAuth());
      },
      parseProgramHeaders: (raw: unknown) => {
        calls.api += 1;
        return parseProgramHeaders(raw);
      },
      requestCsrfToken: (options: { signal?: AbortSignal; auth?: OptionalAuthConfig | null } = {}) => (
        (calls.api += 1,
          requestCsrfToken({
            fetchImpl: windowRef.fetch.bind(windowRef),
            base: apiBase(),
            auth: options.auth === undefined ? optionalAuth() : options.auth,
            signal: options.signal,
          }))
      ),
    }),
    autoForge,
    infraHistory,
    ndjson: Object.freeze({
      createDecoder: <T = unknown>() => {
        calls.ndjson += 1;
        return new NdjsonDecoder<T>();
      },
    }),
    manualRecon: Object.freeze({
      openStream: (
        body: Parameters<typeof manualReconService.openStream>[0],
        options: ManualReconOptions = {},
      ) => {
        calls.manualRecon += 1;
        const controller = windowRef as CockpitWindow & {
          addLog?: (message: string, level: string) => void;
        };
        const pageDocument = typeof document === 'undefined' ? null : document;
        return manualReconService.openStream(body, {
          ...options,
          authorizationBasis: options.authorizationBasis || String(
            pageDocument?.getElementById('manualAuthorizationBasisSelect')?.getAttribute('value')
              || (pageDocument?.getElementById('manualAuthorizationBasisSelect') as HTMLSelectElement | null)?.value
              || 'explicit',
          ).trim().toLowerCase(),
          onTemporaryAuthorization: options.onTemporaryAuthorization || ((engagementId) => {
            controller.addLog?.(
              `Autorização manual criada: ${engagementId} · alvo vinculado · validade de 8 horas.`,
              'success',
            );
          }),
          onAuthorizationConsumed: options.onAuthorizationConsumed || (() => {
            const toggle = pageDocument?.getElementById('manualAuthorizationToggle') as HTMLInputElement | null;
            if (toggle) toggle.checked = false;
          }),
          onPlanAuthorized: options.onPlanAuthorized || (({ debugText, plan, preflightBody }) => {
            console.debug('PLANO MANUAL AUTORIZADO PELA SELEÇÃO', debugText);
            controller.addLog?.(
              `Plano manual autorizado pela seleção · alvo=${plan.target || preflightBody.domain} · intrusivos=${(plan.intrusiveModules || []).length} · hash=${String(plan.hash || '').slice(0, 16)}…`,
              'info',
            );
          }),
        });
      },
      prepareApproval: (...args: Parameters<typeof manualReconService.prepareApproval>) => {
        calls.manualRecon += 1;
        return manualReconService.prepareApproval(...args);
      },
    }),
    findings: Object.freeze({
      isDorkType: (type: unknown) => {
        calls.findings += 1;
        return isDorkFindingType(type);
      },
      isVigolium: (finding: Finding | null | undefined) => {
        calls.findings += 1;
        return isVigoliumFinding(finding);
      },
      matchesFilter: (finding: Finding, filter: string) => {
        calls.findings += 1;
        return findingMatchesFilter(finding, filter);
      },
      matchesSearch: (finding: Finding, query: string) => {
        calls.findings += 1;
        return findingMatchesSearch(finding, query);
      },
      select: (findings: Finding[], options?: { filter?: string; query?: string }) => {
        calls.findings += 1;
        return selectFindings(findings, options);
      },
    }),
    pipeline: Object.freeze({
      getState: (): PipelineState => pipelineState,
      reset: (): PipelineState => {
        calls.pipeline += 1;
        pipelineState = createPipelineState();
        return pipelineState;
      },
      normalizeNode: (name: string) => {
        calls.pipeline += 1;
        return normalizePipelineNode(name);
      },
      reduce: (action: PipelineAction): PipelineState => {
        calls.pipeline += 1;
        pipelineState = pipelineReducer(pipelineState, action);
        return pipelineState;
      },
      formatElapsed: (milliseconds: number) => {
        calls.pipeline += 1;
        return formatElapsed(milliseconds);
      },
    }),
    runForm: Object.freeze({
      normalizeTarget: (raw: unknown) => {
        calls.runForm += 1;
        return normalizeTargetKey(raw);
      },
      parseBatchTargets: (raw: unknown, maxEntries?: number) => {
        calls.runForm += 1;
        return parseBatchTargets(raw, maxEntries);
      },
      collectTargets: (input: Parameters<typeof collectRunTargets>[0]) => {
        calls.runForm += 1;
        return collectRunTargets(input);
      },
      parseCascadeOutOfScope: (raw: unknown) => {
        calls.runForm += 1;
        return parseCascadeOutOfScopeRules(raw);
      },
      extractCascadeSubdomains: (...args: Parameters<typeof extractCascadeSubdomains>) => {
        calls.runForm += 1;
        return extractCascadeSubdomains(...args);
      },
      project: (root: FormRoot, options: RunFormProjectionOptions = {}) => {
        calls.runForm += 1;
        const runtimeWindow = windowRef as CockpitWindow & {
          __ghostreconRunFormStore?: { getSelectedModules?: () => string[] };
        };
        return projectRunForm(root, {
          ...options,
          selectedModules: options.selectedModules
            || runtimeWindow.__ghostreconRunFormStore?.getSelectedModules?.(),
        });
      },
      buildBody: (...args: Parameters<typeof buildManualReconBody>) => {
        calls.runForm += 1;
        return buildManualReconBody(...args);
      },
      consumeStream: (
        response: Parameters<typeof consumeReconNdjson>[0],
        options: ReconStreamConsumeOptions = {},
      ) => {
        calls.runForm += 1;
        const runtimeWindow = windowRef as CockpitWindow & {
          __ghostreconExecutionStore?: ReconStreamConsumeOptions['executionStore'];
          dispatchEvent?: EventTarget['dispatchEvent'];
        };
        return consumeReconNdjson(response, {
          ...options,
          executionStore: options.executionStore || runtimeWindow.__ghostreconExecutionStore || null,
          eventTarget: options.eventTarget
            || (typeof runtimeWindow.dispatchEvent === 'function' ? runtimeWindow as unknown as EventTarget : null),
        });
      },
    }),
    vigolium,
  });
}

declare global {
  interface Window {
    __ghostreconNativeServices?: NativeCockpitServices;
  }
}

export function installNativeCockpitServices(windowRef: Window): () => void {
  const installed = createNativeCockpitServices(windowRef);
  windowRef.__ghostreconNativeServices = installed;
  document.body.dataset.ghostreconNativeServices = String(installed.version);
  const uninstallExportsIntegrations = installExportsIntegrations(windowRef);
  return () => {
    uninstallExportsIntegrations();
    if (windowRef.__ghostreconNativeServices === installed) {
      delete windowRef.__ghostreconNativeServices;
      delete document.body.dataset.ghostreconNativeServices;
    }
  };
}

// Mantém os tipos de Finding no bundle público da ponte sem expor mutação.
export type { Finding };
