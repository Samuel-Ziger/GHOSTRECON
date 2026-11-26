import { useCallback, useEffect, useMemo, useRef } from 'react';
import { appendHeadMarkup, snapshotLegacyDocument } from '../../../LegacyDocument';
import type { ReactUiPage } from '../../../page-registry';
import { createVigoliumWorkbenchService } from './service';

function readableStorage(): Storage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

/**
 * Owns the native Workbench shell: template styles/head metadata, API service,
 * file://-safe storage access and request cancellation. Legacy scripts are
 * deliberately never appended to the document.
 */
export function useVigoliumWorkbenchShell(page: ReactUiPage) {
  const snapshot = useMemo(() => snapshotLegacyDocument(page.source), [page.source]);
  const service = useMemo(() => createVigoliumWorkbenchService({ storage: readableStorage() }), []);
  const abortRef = useRef(new AbortController());
  const signal = useCallback(() => abortRef.current.signal, []);

  useEffect(() => {
    document.title = snapshot.title;
    document.documentElement.lang = snapshot.htmlLang;
    document.body.dataset.ghostreconReactPage = page.id;
    document.body.dataset.ghostreconReactTree = '1';
    document.body.dataset.ghostreconNativeVigoliumWorkbench = '1';
    document.body.dataset.ghostreconLegacyReady = '1';

    const head = snapshot.headMarkup
      .map((markup) => appendHeadMarkup(markup, page.id))
      .filter((element): element is HTMLElement => Boolean(element));

    return () => {
      abortRef.current.abort();
      for (const element of head) element.remove();
      delete document.body.dataset.ghostreconNativeVigoliumWorkbench;
    };
  }, [page.id, snapshot]);

  return { service, signal } as const;
}
