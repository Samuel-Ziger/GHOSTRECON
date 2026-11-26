export type ScriptDescriptor = {
  attributes: Array<[string, string]>;
  source: string;
};

export type LegacySnapshot = {
  bodyAttributes: Array<[string, string]>;
  headMarkup: string[];
  htmlLang: string;
  scripts: ScriptDescriptor[];
  title: string;
};

let nativeDomContentLoadedSeen = document.readyState === 'complete';
if (!nativeDomContentLoadedSeen) {
  document.addEventListener('DOMContentLoaded', () => {
    nativeDomContentLoadedSeen = true;
  }, { once: true });
}

export function snapshotLegacyDocument(source: string): LegacySnapshot {
  const parsed = new DOMParser().parseFromString(source, 'text/html');
  const scripts = [...parsed.querySelectorAll('script')].map((script) => ({
    attributes: [...script.attributes].map((attribute) => [attribute.name, attribute.value] as [string, string]),
    source: script.textContent || '',
  }));
  parsed.querySelectorAll('script').forEach((script) => script.remove());

  const headMarkup = [...parsed.head.querySelectorAll(
    'style, link[rel="stylesheet"], link[rel="preconnect"], link[rel="dns-prefetch"], meta[http-equiv="refresh"]',
  )].map((node) => node.outerHTML);

  return {
    bodyAttributes: [...parsed.body.attributes].map((attribute) => [attribute.name, attribute.value]),
    headMarkup,
    htmlLang: parsed.documentElement.lang || 'pt-BR',
    scripts,
    title: parsed.title || 'GHOSTRECON',
  };
}

export function appendHeadMarkup(markup: string, pageId: string): HTMLElement | null {
  const template = document.createElement('template');
  template.innerHTML = markup.trim();
  const element = template.content.firstElementChild as HTMLElement | null;
  if (!element) return null;
  element.dataset.ghostreconReactHead = pageId;
  document.head.appendChild(element);
  return element;
}

export async function executeScripts(scripts: ScriptDescriptor[], pageId: string): Promise<void> {
  const needsDomReadyReplay = nativeDomContentLoadedSeen
    && scripts.some((descriptor) => descriptor.source.includes('DOMContentLoaded'));

  for (const descriptor of scripts) {
    await new Promise<void>((resolve, reject) => {
      const script = document.createElement('script');
      script.dataset.ghostreconReactScript = pageId;
      for (const [name, value] of descriptor.attributes) script.setAttribute(name, value);

      if (script.src) {
        script.addEventListener('load', () => resolve(), { once: true });
        script.addEventListener('error', () => reject(new Error(`Falha ao carregar ${script.src}`)), { once: true });
      } else {
        script.textContent = descriptor.source;
      }

      document.body.appendChild(script);
      if (!script.src) resolve();
    });
  }

  // O bundle IIFE é deferido, mas o commit/effect do React pode acontecer
  // depois do DOMContentLoaded nativo. Páginas legadas que esperam esse evento
  // precisam recebê-lo uma vez, somente depois de todo o DOM e scripts existirem.
  if (needsDomReadyReplay) {
    document.dispatchEvent(new Event('DOMContentLoaded', { bubbles: true }));
  }
}

