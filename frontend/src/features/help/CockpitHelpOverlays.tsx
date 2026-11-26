import {
  useCallback,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
} from 'react';
import { domNodeToReact } from '../../runtime/react-dom-tree';

export const COCKPIT_HELP_OVERLAY_IDS = [
  'aiReportsConsentOverlay',
  'sidebarHelpOverlay',
  'findingsHelpOverlay',
  'modulesHelpOverlay',
  'sqlmapHelpOverlay',
  'shellStabilizeHelpOverlay',
  'promptInjHelpOverlay',
  'xssHelpOverlay',
] as const;

export type CockpitHelpOverlayId = typeof COCKPIT_HELP_OVERLAY_IDS[number];

const HELP_NODE_IDS = new Set<string>([
  ...COCKPIT_HELP_OVERLAY_IDS,
  'shellStabilizeTemplate',
]);

const OPEN_GLOBALS: Record<string, CockpitHelpOverlayId> = {
  openAiReportsConsentOverlay: 'aiReportsConsentOverlay',
  openSidebarHelpModal: 'sidebarHelpOverlay',
  openFindingsHelpModal: 'findingsHelpOverlay',
  openModulesHelpModal: 'modulesHelpOverlay',
  openSqlmapHelpModal: 'sqlmapHelpOverlay',
  openShellStabilizeModal: 'shellStabilizeHelpOverlay',
  openPromptInjHelpModal: 'promptInjHelpOverlay',
  openXssHelpModal: 'xssHelpOverlay',
};

const CLOSE_GLOBALS: Record<string, CockpitHelpOverlayId> = {
  closeAiReportsConsentOverlay: 'aiReportsConsentOverlay',
  closeSidebarHelpModal: 'sidebarHelpOverlay',
  closeFindingsHelpModal: 'findingsHelpOverlay',
  closeModulesHelpModal: 'modulesHelpOverlay',
  closeSqlmapHelpModal: 'sqlmapHelpOverlay',
  closeShellStabilizeModal: 'shellStabilizeHelpOverlay',
  closePromptInjHelpModal: 'promptInjHelpOverlay',
  closeXssHelpModal: 'xssHelpOverlay',
};

type PreparedHelpDocument = {
  actions: WeakMap<Element, string>;
  copyKeys: WeakMap<Element, string>;
  overlays: Map<CockpitHelpOverlayId, Element>;
};

type HelpWindow = Window & Record<string, unknown> & {
  __ghostreconAiConsentPending?: boolean;
  __ghostreconAiConsentSilent?: boolean;
  __ghostreconAiStreamOpts?: {
    aiPrimaryCloud: 'gemini' | 'openrouter';
    aiUseOpenrouter: boolean;
  };
};

function prepareElement(
  element: Element,
  actions: WeakMap<Element, string>,
  copyKeys: WeakMap<Element, string>,
  overlayId: string,
) {
  let copyIndex = 0;
  for (const candidate of [element, ...element.querySelectorAll('*')]) {
    const declaredAction = candidate.getAttribute('data-ghostrecon-help-action');
    if (declaredAction) {
      actions.set(candidate, declaredAction);
      if (/copy(?:SqlmapCmd|PromptInj|ShellStabilize|Xss)Row/.test(declaredAction)) {
        copyKeys.set(candidate, `${overlayId}:${copyIndex}`);
        copyIndex += 1;
      }
      candidate.removeAttribute('data-ghostrecon-help-action');
    }
    for (const attribute of [...candidate.attributes]) {
      if (!attribute.name.toLowerCase().startsWith('on')) continue;
      if (attribute.name.toLowerCase() === 'onclick') {
        actions.set(candidate, attribute.value);
        if (!declaredAction && /copy(?:SqlmapCmd|PromptInj|ShellStabilize|Xss)Row/.test(attribute.value)) {
          copyKeys.set(candidate, `${overlayId}:${copyIndex}`);
          copyIndex += 1;
        }
      }
      candidate.removeAttribute(attribute.name);
    }
  }
}

export function parseCockpitHelpDocument(source: string): PreparedHelpDocument {
  const parsed = new DOMParser().parseFromString(source, 'text/html');
  const actions = new WeakMap<Element, string>();
  const copyKeys = new WeakMap<Element, string>();
  const overlays = new Map<CockpitHelpOverlayId, Element>();
  const shellTemplate = parsed.getElementById('shellStabilizeTemplate') as HTMLTemplateElement | null;

  for (const id of COCKPIT_HELP_OVERLAY_IDS) {
    const original = parsed.getElementById(id);
    if (!original) continue;
    const element = original.cloneNode(true) as Element;
    if (id === 'shellStabilizeHelpOverlay' && shellTemplate) {
      const scroll = element.querySelector('#shellStabilizeModalScroll');
      if (scroll) scroll.append(shellTemplate.content.cloneNode(true));
    }
    prepareElement(element, actions, copyKeys, id);
    overlays.set(id, element);
  }
  return { actions, copyKeys, overlays };
}

export function isCockpitHelpNode(node: Node): boolean {
  return node.nodeType === Node.ELEMENT_NODE
    && HELP_NODE_IDS.has((node as Element).id);
}

function syncAiModeInputs() {
  const ai = document.getElementById('modAiReports') as HTMLInputElement | null;
  const lm = document.getElementById('modAiLmStudioOnly') as HTMLInputElement | null;
  if (!ai || !lm) return;
  if (!ai.checked) {
    lm.checked = false;
    lm.disabled = true;
  } else {
    lm.disabled = false;
  }
}

async function copyRow(button: HTMLElement): Promise<void> {
  const row = button.closest('.sqlmap-cmd-row');
  const code = row?.querySelector('.sqlmap-cmd-code');
  const value = code?.textContent?.replace(/\r\n/g, '\n').trim() || '';
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    if (!code) return;
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(code);
    selection?.removeAllRanges();
    selection?.addRange(range);
  }
}

function installWindowGlobals(
  functions: Record<string, (...args: never[]) => unknown>,
): () => void {
  const windowRef = window as unknown as HelpWindow;
  const previous = new Map<string, unknown>();
  for (const [name, handler] of Object.entries(functions)) {
    previous.set(name, windowRef[name]);
    windowRef[name] = handler;
  }
  return () => {
    for (const [name, handler] of Object.entries(functions)) {
      if (windowRef[name] !== handler) continue;
      const old = previous.get(name);
      if (old === undefined) delete windowRef[name];
      else windowRef[name] = old;
    }
  };
}

export function CockpitHelpOverlays({ source }: { source: string }) {
  const prepared = useMemo(() => parseCockpitHelpDocument(source), [source]);
  const [openOverlay, setOpenOverlay] = useState<CockpitHelpOverlayId | null>(null);
  const [promptPortuguese, setPromptPortuguese] = useState(false);
  const [aiPrimary, setAiPrimary] = useState<'gemini' | 'openrouter'>('gemini');
  const [copiedKey, setCopiedKey] = useState('');
  const copyTimer = useRef<number | null>(null);

  const closeOverlay = useCallback((id: CockpitHelpOverlayId) => {
    setOpenOverlay((current) => (current === id ? null : current));
    if (id === 'promptInjHelpOverlay') setPromptPortuguese(false);
  }, []);

  const open = useCallback((id: CockpitHelpOverlayId) => {
    if (id === 'promptInjHelpOverlay') setPromptPortuguese(false);
    if (id === 'aiReportsConsentOverlay') {
      (window as unknown as HelpWindow).__ghostreconAiConsentPending = true;
      setAiPrimary('gemini');
    }
    setOpenOverlay(id);
  }, []);

  const finishAiConsent = useCallback((choice: 'cancel' | 'no_or' | 'ok') => {
    const windowRef = window as unknown as HelpWindow;
    const ai = document.getElementById('modAiReports') as HTMLInputElement | null;
    windowRef.__ghostreconAiConsentPending = false;
    setOpenOverlay((current) => (
      current === 'aiReportsConsentOverlay' ? null : current
    ));
    if (choice === 'cancel') {
      if (ai) ai.checked = false;
      windowRef.__ghostreconAiStreamOpts = {
        aiUseOpenrouter: true,
        aiPrimaryCloud: 'gemini',
      };
      syncAiModeInputs();
      return;
    }
    windowRef.__ghostreconAiStreamOpts = choice === 'no_or'
      ? { aiUseOpenrouter: false, aiPrimaryCloud: 'gemini' }
      : { aiUseOpenrouter: true, aiPrimaryCloud: aiPrimary };
    windowRef.__ghostreconAiConsentSilent = true;
    if (ai) ai.checked = true;
    syncAiModeInputs();
  }, [aiPrimary]);

  const copy = useCallback(async (button: HTMLElement, key = '') => {
    await copyRow(button);
    if (!key) return;
    setCopiedKey(key);
    if (copyTimer.current !== null) window.clearTimeout(copyTimer.current);
    copyTimer.current = window.setTimeout(() => setCopiedKey(''), 1_400);
  }, []);

  useLayoutEffect(() => {
    const globals: Record<string, (...args: never[]) => unknown> = {};
    for (const [name, id] of Object.entries(OPEN_GLOBALS)) {
      globals[name] = (() => open(id)) as (...args: never[]) => unknown;
    }
    for (const [name, id] of Object.entries(CLOSE_GLOBALS)) {
      globals[name] = (() => closeOverlay(id)) as (...args: never[]) => unknown;
    }
    globals.aiReportsConsentFinish = ((choice: 'cancel' | 'no_or' | 'ok') => (
      finishAiConsent(choice)
    )) as (...args: never[]) => unknown;
    globals.resetPromptInjLang = (() => setPromptPortuguese(false)) as (...args: never[]) => unknown;
    globals.togglePromptInjLang = (() => setPromptPortuguese((value) => !value)) as (...args: never[]) => unknown;
    for (const name of ['copySqlmapCmdRow', 'copyPromptInjRow', 'copyShellStabilizeRow', 'copyXssRow']) {
      globals[name] = ((button: HTMLElement) => copy(button)) as (...args: never[]) => unknown;
    }
    globals.mountShellStabilizeFromTemplate = (() => {}) as (...args: never[]) => unknown;
    return installWindowGlobals(globals);
  }, [closeOverlay, copy, finishAiConsent, open]);

  useLayoutEffect(() => () => {
    if (copyTimer.current !== null) window.clearTimeout(copyTimer.current);
  }, []);

  useLayoutEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape' || !openOverlay) return;
      if (openOverlay === 'aiReportsConsentOverlay') finishAiConsent('cancel');
      else closeOverlay(openOverlay);
    };
    document.addEventListener('keydown', keydown);
    return () => document.removeEventListener('keydown', keydown);
  }, [closeOverlay, finishAiConsent, openOverlay]);

  const handleAction = useCallback((
    action: string,
    event: ReactMouseEvent<HTMLElement>,
    key: string,
  ) => {
    if (action.includes('event.stopPropagation')) {
      event.stopPropagation();
      return;
    }
    if (action.includes('copySqlmapCmdRow')
      || action.includes('copyPromptInjRow')
      || action.includes('copyShellStabilizeRow')
      || action.includes('copyXssRow')) {
      void copy(event.currentTarget, key);
      return;
    }
    if (action.includes('togglePromptInjLang')) {
      setPromptPortuguese((value) => !value);
      return;
    }
    const aiChoice = action.match(/aiReportsConsentFinish\('([^']+)'\)/)?.[1];
    if (aiChoice === 'cancel' || aiChoice === 'no_or' || aiChoice === 'ok') {
      finishAiConsent(aiChoice);
      return;
    }
    for (const [name, id] of Object.entries(CLOSE_GLOBALS)) {
      if (action.includes(name)) {
        closeOverlay(id);
        return;
      }
    }
  }, [closeOverlay, copy, finishAiConsent]);

  const overlays: ReactNode[] = [];
  for (const id of COCKPIT_HELP_OVERLAY_IDS) {
    const sourceElement = prepared.overlays.get(id);
    if (!sourceElement) continue;
    overlays.push(domNodeToReact(sourceElement, `help:${id}`, {
      transformElement: (element, initialProps) => {
        const props = { ...initialProps };
        const action = prepared.actions.get(element) || '';
        const copyKey = prepared.copyKeys.get(element) || '';
        if (element.id === id) {
          const className = String(props.className || '');
          props.className = `${className}${openOverlay === id ? ' is-open' : ''}`.trim();
          props['aria-hidden'] = openOverlay === id ? 'false' : 'true';
          props.onClick = (event: ReactMouseEvent<HTMLElement>) => {
            if (event.target !== event.currentTarget) return;
            if (id === 'aiReportsConsentOverlay') finishAiConsent('cancel');
            else closeOverlay(id);
          };
        }
        if (element.id === 'promptInjHelpOverlay' && promptPortuguese) {
          props.className = `${String(props.className || '')} prompt-inj-pt`.trim();
        }
        if (element.id === 'promptInjLangToggle') {
          props.onClick = () => setPromptPortuguese((value) => !value);
          props['aria-pressed'] = promptPortuguese ? 'true' : 'false';
          props.title = promptPortuguese
            ? 'Mostrar payloads em inglês (32)'
            : 'Mostrar 30 payloads em português';
          element.textContent = promptPortuguese ? 'EN' : 'PT';
        } else if (element.id === 'aiConsentPrimaryGemini') {
          delete props.defaultChecked;
          props.checked = aiPrimary === 'gemini';
          props.onChange = () => setAiPrimary('gemini');
        } else if (element.id === 'aiConsentPrimaryOpenrouter') {
          delete props.defaultChecked;
          props.checked = aiPrimary === 'openrouter';
          props.onChange = () => setAiPrimary('openrouter');
        } else if (action && element.id !== id) {
          props.onClick = (event: ReactMouseEvent<HTMLElement>) => (
            handleAction(action, event, copyKey)
          );
        }
        if (copyKey) {
          props.disabled = copiedKey === copyKey;
          if (copiedKey === copyKey) element.textContent = '✓';
          else if (element.textContent === '✓') element.textContent = 'Copiar';
        }
        return props;
      },
    }));
  }

  return (
    <>
      <template id="shellStabilizeTemplate" data-react-help-template="true" />
      {overlays}
    </>
  );
}
