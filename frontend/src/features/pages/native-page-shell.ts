import { useEffect, useMemo } from 'react';
import {
  appendHeadMarkup,
  snapshotLegacyDocument,
  type LegacySnapshot,
} from '../../LegacyDocument';
import type { ReactUiPage } from '../../page-registry';

/**
 * Reaproveita apenas metadata/CSS do documento versionado. Nenhum script do
 * template é executado; toda a interação fica sob responsabilidade do React.
 */
export function useNativePageDocument(
  page: ReactUiPage,
  marker: string,
): LegacySnapshot {
  const snapshot = useMemo(() => snapshotLegacyDocument(page.source), [page.source]);

  useEffect(() => {
    document.title = snapshot.title;
    document.documentElement.lang = snapshot.htmlLang;
    document.body.dataset.ghostreconReactPage = page.id;
    document.body.dataset.ghostreconReactTree = '1';
    document.body.dataset.ghostreconNativePage = marker;
    document.body.dataset.ghostreconLegacyReady = '1';
    for (const [name, value] of snapshot.bodyAttributes) {
      document.body.setAttribute(name, value);
    }

    const headElements = snapshot.headMarkup
      .map((markup) => appendHeadMarkup(markup, page.id))
      .filter((element): element is HTMLElement => Boolean(element));

    return () => {
      for (const element of headElements) element.remove();
      if (document.body.dataset.ghostreconNativePage === marker) {
        delete document.body.dataset.ghostreconNativePage;
      }
    };
  }, [marker, page.id, snapshot]);

  return snapshot;
}
