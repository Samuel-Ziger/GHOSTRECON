import cockpitTemplate from '../templates/index.html?raw';
import guideTemplate from '../templates/como-usar.html?raw';
import cortexTemplate from '../templates/cortex.html?raw';
import mitreTemplate from '../templates/mitre-map.html?raw';
import postExploitationTemplate from '../templates/post-exploitation.html?raw';
import reportTemplate from '../templates/reporte.html?raw';
import torValidatorTemplate from '../templates/tor-validator.html?raw';
import vigoliumWorkbenchTemplate from '../templates/vigolium-workbench.html?raw';
import wifiPentestTemplate from '../templates/wifi-pentest.html?raw';
import ghostIaTemplate from '../templates/ghostia.html?raw';
import hackbotTemplate from '../templates/hackbot.html?raw';

export type ReactUiPage = {
  id: string;
  canonicalPath: string;
  source: string;
};

const pages = new Map<string, ReactUiPage>();

function register(page: ReactUiPage, aliases: string[] = []) {
  for (const path of [page.canonicalPath, ...aliases]) pages.set(path, page);
}

register(
  { id: 'cockpit', canonicalPath: '/index.html', source: cockpitTemplate },
  ['/', 'index.html'],
);
register({ id: 'guide', canonicalPath: '/como-usar.html', source: guideTemplate });
register({ id: 'cortex', canonicalPath: '/cortex.html', source: cortexTemplate });
register({ id: 'mitre-map', canonicalPath: '/mitre-map.html', source: mitreTemplate });
register({
  id: 'post-exploitation',
  canonicalPath: '/post-exploitation.html',
  source: postExploitationTemplate,
});
register({ id: 'report', canonicalPath: '/reporte.html', source: reportTemplate });
register({
  id: 'tor-validator',
  canonicalPath: '/tor-validator.html',
  source: torValidatorTemplate,
});
register({
  id: 'vigolium-workbench',
  canonicalPath: '/vigolium-workbench.html',
  source: vigoliumWorkbenchTemplate,
});
register({ id: 'wifi-pentest', canonicalPath: '/wifi-pentest.html', source: wifiPentestTemplate });
register({ id: 'ghostia', canonicalPath: '/ghostia.html', source: ghostIaTemplate });
register({ id: 'hackbot', canonicalPath: '/hackbot.html', source: hackbotTemplate });

function normalizePath(pathname: string): string {
  const normalized = pathname.replace(/\\/g, '/');
  const basename = normalized.slice(normalized.lastIndexOf('/') + 1);
  if (!basename) return '/';
  return `/${basename}`;
}

export function resolveReactUiPage(locationLike: Pick<Location, 'pathname' | 'search'>): ReactUiPage {
  const override = new URLSearchParams(locationLike.search).get('uiPage');
  const candidate = normalizePath(override || locationLike.pathname || '/');
  return pages.get(candidate) || pages.get('/')!;
}

export const REACT_UI_PAGE_PATHS = [...new Set(
  [...pages.values()].map((page) => page.canonicalPath),
)];
