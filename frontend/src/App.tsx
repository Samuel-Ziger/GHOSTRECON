import { CockpitPage } from './features/cockpit/CockpitPage';
import {
  AUXILIARY_PAGE_COMPONENTS,
  isAuxiliaryPageId,
} from './features/pages/AuxiliaryPage';
import { resolveReactUiPage } from './page-registry';
import { GhostIaPage } from './features/artex/GhostIaPage';
import { HackbotPage } from './features/hackbot/HackbotPage';

export function App() {
  const page = resolveReactUiPage(window.location);
  if (page.id === 'cockpit') return <CockpitPage page={page} />;
  if (page.id === 'ghostia') return <GhostIaPage page={page} />;
  if (page.id === 'hackbot') return <HackbotPage page={page} />;
  if (isAuxiliaryPageId(page.id)) {
    const PageComponent = AUXILIARY_PAGE_COMPONENTS[page.id];
    return <PageComponent page={page} />;
  }
  throw new Error(`Página React não registrada: ${page.id}`);
}
