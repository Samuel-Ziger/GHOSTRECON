import {
  useEffect,
  useMemo,
  useState,
  type ComponentType,
  type ReactNode,
} from 'react';
import {
  appendHeadMarkup,
  executeScripts,
  snapshotLegacyDocument,
} from '../../LegacyDocument';
import type { ReactUiPage } from '../../page-registry';
import { domChildrenToReact } from '../../runtime/react-dom-tree';
import { CortexPage } from './cortex/CortexPage';
import { PostExploitationPage } from './post-exploitation/PostExploitationPage';
import { ReportPage } from './report/ReportPage';
import { TorValidatorPage } from './tor-validator/TorValidatorPage';
import { VigoliumWorkbenchPage } from './vigolium-workbench/VigoliumWorkbenchPage';
import { WifiPentestPage } from './wifi-pentest/WifiPentestPage';

export type AuxiliaryPageId =
  | 'guide'
  | 'cortex'
  | 'mitre-map'
  | 'post-exploitation'
  | 'report'
  | 'tor-validator'
  | 'vigolium-workbench'
  | 'wifi-pentest';

type AuxiliaryPageProps = {
  page: ReactUiPage;
};

function parseBody(source: string): ReactNode[] {
  const parsed = new DOMParser().parseFromString(source, 'text/html');
  parsed.querySelectorAll('script').forEach((script) => script.remove());
  return domChildrenToReact(parsed.body);
}

/**
 * React owns the complete DOM tree for every auxiliary page. The versioned
 * page controllers are still executed after commit as compatibility adapters;
 * this keeps their public globals, storage keys and integrations intact while
 * their behavior is extracted into typed hooks domain by domain.
 */
function AuxiliaryDocumentPage({ page }: AuxiliaryPageProps) {
  const snapshot = useMemo(() => snapshotLegacyDocument(page.source), [page.source]);
  const body = useMemo(() => parseBody(page.source), [page.source]);
  const [runtimeError, setRuntimeError] = useState('');

  useEffect(() => {
    document.title = snapshot.title;
    document.documentElement.lang = snapshot.htmlLang;
    document.body.dataset.ghostreconReactPage = page.id;
    document.body.dataset.ghostreconReactTree = '1';
    for (const [name, value] of snapshot.bodyAttributes) document.body.setAttribute(name, value);

    const headElements = snapshot.headMarkup
      .map((markup) => appendHeadMarkup(markup, page.id))
      .filter((element): element is HTMLElement => Boolean(element));

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
          console.error(`[GHOSTRECON UI] falha no controller de ${page.id}:`, error);
        });
    }

    return () => {
      for (const element of headElements) element.remove();
    };
  }, [page.id, snapshot]);

  return (
    <>
      {runtimeError ? (
        <div className="ghostrecon-react-runtime-error" role="alert">
          <strong>Falha ao iniciar a interface.</strong>
          <span>{runtimeError}</span>
        </div>
      ) : null}
      {body}
    </>
  );
}

export function GuidePage(props: AuxiliaryPageProps) {
  return <AuxiliaryDocumentPage {...props} />;
}

export function MitreMapRedirectPage(props: AuxiliaryPageProps) {
  return <AuxiliaryDocumentPage {...props} />;
}

export const AUXILIARY_PAGE_COMPONENTS: Record<AuxiliaryPageId, ComponentType<AuxiliaryPageProps>> = {
  guide: GuidePage,
  cortex: CortexPage,
  'mitre-map': MitreMapRedirectPage,
  'post-exploitation': PostExploitationPage,
  report: ReportPage,
  'tor-validator': TorValidatorPage,
  'vigolium-workbench': VigoliumWorkbenchPage,
  'wifi-pentest': WifiPentestPage,
};

export function isAuxiliaryPageId(value: string): value is AuxiliaryPageId {
  return Object.hasOwn(AUXILIARY_PAGE_COMPONENTS, value);
}
