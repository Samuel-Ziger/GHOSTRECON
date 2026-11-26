import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type PointerEvent as ReactPointerEvent,
} from 'react';
import { appendHeadMarkup, snapshotLegacyDocument } from '../../../LegacyDocument';
import type { ReactUiPage } from '../../../page-registry';
import {
  categoryTeach,
  cloneDemoCategories,
  cloneDemoLinks,
  getCategoryTeach,
  isCortexDemoLocation,
  linkDisplayUrl,
  snippetFromLink,
  taxonomyText,
  type CortexCategory,
  type CortexLink,
} from './model';
import { createCortexService } from './service';

const TOGGLE_KEY = 'cortex_obsidian_graph';

function readObsidianPreference(): boolean {
  try {
    const stored = window.localStorage.getItem(TOGGLE_KEY);
    return stored === null ? true : stored === '1';
  } catch {
    return true;
  }
}

function writeObsidianPreference(enabled: boolean) {
  try {
    window.localStorage.setItem(TOGGLE_KEY, enabled ? '1' : '0');
  } catch {
    // file:// and privacy modes can reject localStorage.
  }
}

function GhostMark() {
  return (
    <svg viewBox="0 0 48 52" xmlns="http://www.w3.org/2000/svg" width="120" height="130" focusable="false">
      <defs>
        <linearGradient id="cortexBgGhostGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#ede9fe" />
          <stop offset="50%" stopColor="#a78bfa" />
          <stop offset="100%" stopColor="#6d28d9" />
        </linearGradient>
        <linearGradient id="cortexBgGhostSheen" x1="15%" y1="0%" x2="75%" y2="85%">
          <stop offset="0%" stopColor="rgba(255,255,255,0.35)" />
          <stop offset="45%" stopColor="rgba(255,255,255,0)" />
          <stop offset="100%" stopColor="rgba(30,20,60,0.25)" />
        </linearGradient>
      </defs>
      <g className="ghost-anim-cortex">
        <path fill="url(#cortexBgGhostGrad)" stroke="rgba(139,92,246,0.4)" strokeWidth="0.55" d="M 24 5 C 13 5 5 13.5 5 24.5 V 40 Q 8.5 36.5 12 40 Q 15.5 36.5 19 40 Q 22.5 36.5 26 40 Q 29.5 36.5 33 40 Q 36.5 36.5 40 40 Q 43.5 36.5 43 40 V 24.5 C 43 13.5 35 5 24 5 Z" />
        <path fill="url(#cortexBgGhostSheen)" d="M 24 8 C 15 8 9 15 9 23.5 V 33 Q 16 28 24 32 Q 32 28 39 33 V 23.5 C 39 15 33 8 24 8 Z" opacity="0.88" />
        <ellipse className="ghost-eye-cortex" cx="17" cy="22" rx="3.2" ry="4.2" fill="#0c0a12" />
        <ellipse className="ghost-eye-cortex ghost-eye-cortex-r" cx="31" cy="22" rx="3.2" ry="4.2" fill="#0c0a12" />
      </g>
    </svg>
  );
}

function Ribbon() {
  return (
    <aside className="ribbon">
      <div className="ribbon-logo">
        <svg viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
          <circle cx="10" cy="10" r="9" stroke="rgba(139,92,246,0.6)" strokeWidth="1" />
          <circle cx="10" cy="10" r="5" stroke="var(--accent-hi)" strokeWidth="1" />
          <circle cx="10" cy="10" r="2" fill="var(--green)" />
        </svg>
      </div>
      <button type="button" className="ribbon-btn active" title="Grafo (activo)" aria-label="Grafo activo">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="5" r="2" /><circle cx="5" cy="19" r="2" /><circle cx="19" cy="19" r="2" /><line x1="12" y1="7" x2="5" y2="17" /><line x1="12" y1="7" x2="19" y2="17" /></svg>
      </button>
      <button type="button" className="ribbon-btn" title="Pesquisa" aria-label="Pesquisa">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" /></svg>
      </button>
      <button type="button" className="ribbon-btn" title="Tags" aria-label="Tags">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z" /><line x1="7" y1="7" x2="7.01" y2="7" /></svg>
      </button>
      <div className="ribbon-spacer" />
      <button type="button" className="ribbon-btn" title="Configurações" aria-label="Configurações">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" /></svg>
      </button>
    </aside>
  );
}

type GraphNode = {
  link: CortexLink;
  x: number;
  y: number;
  targetX: number;
  targetY: number;
  vx: number;
  vy: number;
  offsetX: number;
  offsetY: number;
  dragging?: boolean;
};

type DragState =
  | { type: 'hub'; pointerId: number; mouseX: number; mouseY: number; x: number; y: number }
  | { type: 'node'; pointerId: number; index: number; mouseX: number; mouseY: number; x: number; y: number }
  | null;

function ObsidianGraph({ title, links, openDrawer }: {
  title: string;
  links: CortexLink[];
  openDrawer: (link: CortexLink) => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const nodesRef = useRef<GraphNode[]>([]);
  const hubRef = useRef({ x: 400, y: 300 });
  const dragRef = useRef<DragState>(null);
  const rafRef = useRef<number | null>(null);
  const movedRef = useRef(false);
  const [size, setSize] = useState({ width: 800, height: 600 });
  const [, repaint] = useState(0);

  const cancelPhysics = useCallback(() => {
    if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);
    rafRef.current = null;
  }, []);

  const startPhysics = useCallback(() => {
    if (rafRef.current !== null) return;
    const tick = () => {
      let active = false;
      for (const node of nodesRef.current) {
        if (node.dragging) continue;
        const dx = node.targetX - node.x;
        const dy = node.targetY - node.y;
        node.vx = (node.vx + dx * 0.065) * 0.74;
        node.vy = (node.vy + dy * 0.065) * 0.74;
        if (Math.abs(node.vx) > 0.08 || Math.abs(node.vy) > 0.08 || Math.abs(dx) > 0.08 || Math.abs(dy) > 0.08) {
          node.x += node.vx;
          node.y += node.vy;
          active = true;
        } else {
          node.x = node.targetX;
          node.y = node.targetY;
          node.vx = 0;
          node.vy = 0;
        }
      }
      repaint((value) => value + 1);
      if (active) rafRef.current = requestAnimationFrame(tick);
      else rafRef.current = null;
    };
    rafRef.current = requestAnimationFrame(tick);
  }, []);

  useLayoutEffect(() => {
    const element = containerRef.current;
    if (!element) return undefined;
    const measure = () => setSize({
      width: element.clientWidth || 800,
      height: element.clientHeight || 600,
    });
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    cancelPhysics();
    const hub = { x: size.width / 2, y: size.height / 2 };
    hubRef.current = hub;
    const rx = Math.min(size.width * 0.37, 320);
    const ry = Math.min(size.height * 0.36, 230);
    const count = Math.max(links.length, 1);
    nodesRef.current = links.map((link, index) => {
      const angle = (index / count) * 2 * Math.PI - Math.PI / 2;
      const x = hub.x + Math.cos(angle) * rx;
      const y = hub.y + Math.sin(angle) * ry;
      return { link, x, y, targetX: x, targetY: y, vx: 0, vy: 0, offsetX: x - hub.x, offsetY: y - hub.y };
    });
    repaint((value) => value + 1);
  }, [cancelPhysics, links, size.height, size.width]);

  useEffect(() => cancelPhysics, [cancelPhysics]);

  const endDrag = (event: ReactPointerEvent<HTMLElement>) => {
    const drag = dragRef.current;
    if (!drag || drag.pointerId !== event.pointerId) return;
    if (drag.type === 'node') {
      const node = nodesRef.current[drag.index];
      if (node) {
        node.dragging = false;
        node.offsetX = node.x - hubRef.current.x;
        node.offsetY = node.y - hubRef.current.y;
      }
    } else {
      startPhysics();
    }
    dragRef.current = null;
    repaint((value) => value + 1);
  };

  const hubPointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    event.currentTarget.setPointerCapture(event.pointerId);
    movedRef.current = false;
    dragRef.current = { type: 'hub', pointerId: event.pointerId, mouseX: event.clientX, mouseY: event.clientY, ...hubRef.current };
    nodesRef.current.forEach((node) => {
      node.offsetX = node.x - hubRef.current.x;
      node.offsetY = node.y - hubRef.current.y;
      node.vx *= 0.3;
      node.vy *= 0.3;
    });
  };

  const hubPointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    const drag = dragRef.current;
    if (!drag || drag.type !== 'hub' || drag.pointerId !== event.pointerId) return;
    const dx = event.clientX - drag.mouseX;
    const dy = event.clientY - drag.mouseY;
    if (Math.abs(dx) + Math.abs(dy) > 2) movedRef.current = true;
    hubRef.current = { x: drag.x + dx, y: drag.y + dy };
    nodesRef.current.forEach((node) => {
      node.targetX = hubRef.current.x + node.offsetX;
      node.targetY = hubRef.current.y + node.offsetY;
    });
    startPhysics();
    repaint((value) => value + 1);
  };

  const nodePointerDown = (event: ReactPointerEvent<HTMLButtonElement>, index: number) => {
    event.preventDefault();
    event.currentTarget.setPointerCapture(event.pointerId);
    const node = nodesRef.current[index];
    if (!node) return;
    movedRef.current = false;
    node.dragging = true;
    dragRef.current = { type: 'node', pointerId: event.pointerId, index, mouseX: event.clientX, mouseY: event.clientY, x: node.x, y: node.y };
  };

  const nodePointerMove = (event: ReactPointerEvent<HTMLButtonElement>) => {
    const drag = dragRef.current;
    if (!drag || drag.type !== 'node' || drag.pointerId !== event.pointerId) return;
    const node = nodesRef.current[drag.index];
    if (!node) return;
    const dx = event.clientX - drag.mouseX;
    const dy = event.clientY - drag.mouseY;
    if (Math.abs(dx) + Math.abs(dy) > 2) movedRef.current = true;
    node.x = drag.x + dx;
    node.y = drag.y + dy;
    node.targetX = node.x;
    node.targetY = node.y;
    node.vx = 0;
    node.vy = 0;
    repaint((value) => value + 1);
  };

  const hub = hubRef.current;
  const nodes = nodesRef.current;
  return (
    <div ref={containerRef} className="obsidian-graph">
      <div className="graph-lines" aria-hidden="true" />
      <svg className="obsidian-radials" aria-hidden="true" viewBox={`0 0 ${size.width} ${size.height}`} style={{ width: size.width, height: size.height }}>
        {nodes.map((node, index) => <line key={`${String(node.link.fingerprint)}-${index}`} x1={hub.x} y1={hub.y} x2={node.x} y2={node.y} className={index % 3 === 0 ? 'line-green' : undefined} style={{ animationDelay: `${(index * 0.4).toFixed(2)}s` }} />)}
      </svg>
      <div className="hub-ring" style={{ left: hub.x, top: hub.y }} />
      <div className={`obsidian-hub${dragRef.current?.type === 'hub' ? ' is-hub-dragging' : ''}`} style={{ left: hub.x, top: hub.y }} onPointerDown={hubPointerDown} onPointerMove={hubPointerMove} onPointerUp={endDrag} onPointerCancel={endDrag}>{title}</div>
      <div className="obsidian-orbit-layer">
        {nodes.map((node, index) => {
          const fullUrl = linkDisplayUrl(node.link);
          let host = '';
          let path = fullUrl;
          try {
            const parsed = new URL(fullUrl);
            host = parsed.host;
            path = `${parsed.pathname}${parsed.search || ''}`;
          } catch {
            // Non-HTTP targets remain readable as-is.
          }
          const shortPath = path.length > 46 ? `${path.slice(0, 44)}…` : path;
          return (
            <button
              type="button"
              key={`${String(node.link.fingerprint)}-${index}`}
              className={`node node--float${node.dragging ? ' is-dragging' : ' is-drifting'}`}
              data-idx={index}
              style={{ left: node.x, top: node.y, animationDelay: `${(index * 0.62).toFixed(2)}s` }}
              title={fullUrl}
              onPointerDown={(event) => nodePointerDown(event, index)}
              onPointerMove={nodePointerMove}
              onPointerUp={endDrag}
              onPointerCancel={endDrag}
              onClick={() => { if (!movedRef.current) openDrawer(node.link); }}
            >
              <span className="node-url-float"><span className="node-dot" /><span><span className="node-url-float-host">{host}</span>{shortPath}</span></span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

function EmptyCanvas({ demoMode }: { demoMode: boolean }) {
  return (
    <div className="empty-canvas">
      <h2>Bem-vindo ao Cortex</h2>
      <p>Cada achado que ligares ao cérebro a partir da checklist no GHOSTRECON aparece aqui como um nó. Clica num nó para ver notas e snapshot no painel lateral.</p>
      <p style={{ marginTop: 10 }}>Com o <strong>Mapa local</strong> activado, o tipo fica no centro e os alvos orbitam à volta — igual ao grafo local do Obsidian. Podes <strong>arrastar</strong> cada nó livremente.</p>
      {!demoMode ? <p style={{ marginTop: 10 }}>Para pré-visualização fictícia clica em <strong>Simular GET…</strong> na barra lateral, ou usa <code>?demo=1</code> / <code>#demo</code> na URL.</p> : null}
      <div className="empty-shortcut-row"><span className="kbd">Ctrl+K</span><span style={{ color: 'var(--dim)', fontSize: 10 }}> pesquisar notas</span><span style={{ color: 'var(--dim)', fontSize: 10, marginLeft: 8 }}>Esc</span><span style={{ color: 'var(--dim)', fontSize: 10 }}> fechar painel</span></div>
    </div>
  );
}

export function CortexPage({ page }: { page: ReactUiPage }) {
  const snapshot = useMemo(() => snapshotLegacyDocument(page.source), [page.source]);
  const service = useMemo(() => createCortexService(), []);
  const searchRef = useRef<HTMLInputElement>(null);
  const [categories, setCategories] = useState<CortexCategory[]>([]);
  const [activeId, setActiveId] = useState<number | null>(null);
  const [activeLinks, setActiveLinks] = useState<CortexLink[]>([]);
  const [activeTitle, setActiveTitle] = useState('');
  const [activeDescription, setActiveDescription] = useState('');
  const [demoMode, setDemoMode] = useState(() => isCortexDemoLocation(window.location));
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [obsidian, setObsidian] = useState(readObsidianPreference);
  const [fakeLoading, setFakeLoading] = useState(false);
  const [descriptionEditing, setDescriptionEditing] = useState(false);
  const [descriptionDraft, setDescriptionDraft] = useState('');
  const [descriptionSaving, setDescriptionSaving] = useState(false);
  const [drawerLink, setDrawerLink] = useState<CortexLink | null>(null);
  const [drawerNotes, setDrawerNotes] = useState('');
  const [drawerMarked, setDrawerMarked] = useState(false);
  const [drawerSaving, setDrawerSaving] = useState(false);
  const [drawerStatus, setDrawerStatus] = useState<{ text: string; kind: '' | 'ok' | 'err' }>({ text: '', kind: '' });

  useEffect(() => {
    document.title = snapshot.title;
    document.documentElement.lang = snapshot.htmlLang;
    document.body.dataset.ghostreconReactPage = page.id;
    document.body.dataset.ghostreconReactTree = '1';
    document.body.dataset.ghostreconNativeCortex = '1';
    document.body.dataset.ghostreconLegacyReady = '1';
    for (const [name, value] of snapshot.bodyAttributes) document.body.setAttribute(name, value);
    const headElements = snapshot.headMarkup.map((markup) => appendHeadMarkup(markup, page.id)).filter((element): element is HTMLElement => Boolean(element));
    return () => {
      headElements.forEach((element) => element.remove());
      delete document.body.dataset.ghostreconNativeCortex;
    };
  }, [page.id, snapshot]);

  const updateHash = (categoryId: number) => {
    try {
      const next = new URL(window.location.href);
      next.hash = String(categoryId);
      window.history.replaceState(null, '', next.toString());
    } catch {
      // Hash synchronization is cosmetic.
    }
  };

  const applyCategory = useCallback((category: CortexCategory, links: CortexLink[]) => {
    setActiveId(Number(category.id));
    setActiveLinks(links);
    setActiveTitle(String(category.title || 'Categoria'));
    setActiveDescription(String(category.description || ''));
    setDescriptionEditing(false);
    setError('');
    updateHash(Number(category.id));
  }, []);

  const selectCategory = useCallback(async (categoryId: number, mode = demoMode) => {
    setError('');
    if (mode) {
      const category = cloneDemoCategories().find((item) => Number(item.id) === Number(categoryId));
      if (category) applyCategory(category, cloneDemoLinks(categoryId));
      return;
    }
    try {
      const result = await service.getCategory(categoryId);
      applyCategory(result.category, result.links);
    } catch (cause) {
      setActiveId(categoryId);
      setActiveLinks([]);
      setActiveTitle('');
      setActiveDescription('');
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, [applyCategory, demoMode, service]);

  useEffect(() => {
    const abort = new AbortController();
    void (async () => {
      const initialDemo = isCortexDemoLocation(window.location);
      setDemoMode(initialDemo);
      try {
        const nextCategories = initialDemo
          ? cloneDemoCategories()
          : await service.listCategories(abort.signal);
        if (abort.signal.aborted) return;
        setCategories(nextCategories);
        const hash = String(window.location.hash || '').replace(/^#/, '').trim().toLowerCase();
        const categoryId = hash === 'demo' ? Number.NaN : Number(hash);
        const selected = nextCategories.find((category) => Number(category.id) === categoryId);
        if (selected) {
          if (initialDemo) applyCategory(selected, cloneDemoLinks(selected.id));
          else {
            const detail = await service.getCategory(selected.id, abort.signal);
            if (!abort.signal.aborted) applyCategory(detail.category, detail.links);
          }
        }
      } catch (cause) {
        if (!abort.signal.aborted) {
          setCategories([]);
          setError(`Não foi possível carregar categorias: ${cause instanceof Error ? cause.message : String(cause)}`);
        }
      }
    })();
    return () => abort.abort();
  }, [applyCategory, service]);

  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setDrawerLink(null);
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        searchRef.current?.focus();
        searchRef.current?.select();
      }
    };
    document.addEventListener('keydown', keydown);
    return () => document.removeEventListener('keydown', keydown);
  }, []);

  const openDrawer = (link: CortexLink) => {
    setDrawerLink(link);
    setDrawerNotes(String(link.notes || ''));
    setDrawerMarked(link.snapshot?.cortex_marked === true);
    setDrawerStatus({ text: '', kind: '' });
  };

  const simulate = async () => {
    setFakeLoading(true);
    setError('');
    try {
      await new Promise((resolve) => setTimeout(resolve, 420));
      const demoCategories = cloneDemoCategories();
      setDemoMode(true);
      setCategories(demoCategories);
      setActiveId(null);
      setActiveLinks([]);
      if (demoCategories[0]) applyCategory(demoCategories[0], cloneDemoLinks(demoCategories[0].id));
    } catch (cause) {
      setError(`Prévia fictícia falhou: ${cause instanceof Error ? cause.message : String(cause)}`);
    } finally {
      setFakeLoading(false);
    }
  };

  const beginDescriptionEdit = () => {
    if (!activeId || demoMode) return;
    setDescriptionDraft(activeDescription || getCategoryTeach(activeTitle).text);
    setDescriptionEditing(true);
  };

  const saveDescription = async () => {
    if (!activeId || demoMode) return;
    setDescriptionSaving(true);
    setError('');
    try {
      const category = await service.saveCategoryDescription(activeId, descriptionDraft);
      const description = String(category.description ?? descriptionDraft).trim().slice(0, 2000);
      setActiveDescription(description);
      setCategories((current) => current.map((item) => Number(item.id) === activeId ? { ...item, description } : item));
      setDescriptionEditing(false);
    } catch (cause) {
      setError(`Não foi possível guardar descrição: ${cause instanceof Error ? cause.message : String(cause)}`);
    } finally {
      setDescriptionSaving(false);
    }
  };

  const saveNotes = async () => {
    if (!drawerLink || demoMode) return;
    setDrawerSaving(true);
    setDrawerStatus({ text: 'A guardar…', kind: '' });
    try {
      const result = await service.saveValidation(drawerLink, { notes: drawerNotes, marked: drawerMarked });
      const fingerprint = String(drawerLink.fingerprint || '');
      const updated = { ...drawerLink, notes: result.notes, snapshot: result.snapshot };
      setDrawerLink(updated);
      setActiveLinks((current) => current.map((link) => String(link.fingerprint || '') === fingerprint ? updated : link));
      setDrawerStatus({ text: 'Notas guardadas.', kind: 'ok' });
    } catch (cause) {
      setDrawerStatus({ text: `Falha: ${cause instanceof Error ? cause.message : String(cause)}`, kind: 'err' });
    } finally {
      setDrawerSaving(false);
    }
  };

  const filteredCategories = categories.filter((category) => String(category.title || '').toLowerCase().includes(search.trim().toLowerCase()));
  const teach = categoryTeach(activeTitle, activeDescription);
  const activeType = String(activeLinks[0]?.snapshot?.type || '—');
  const hint = !activeId
    ? 'Selecciona uma vulnerabilidade à esquerda para ver os alvos confirmados.'
    : !activeLinks.length
      ? 'Sem alvos ligados a este tipo — valida na checklist no GHOSTRECON e adiciona ao cérebro.'
      : obsidian
        ? `${activeLinks.length} nó(s) · Arrasta o centro para mover tudo · arrasta um nó individualmente · clica para detalhes`
        : `${activeLinks.length} confirmação(ões) · clica num cartão para abrir o painel lateral`;

  return (
    <>
      <div id="demoBanner" className="demo-banner" role="status" style={{ display: demoMode ? 'block' : 'none' }}><strong>Modo demonstração</strong> — dados fictícios. Remove <code>?demo=1</code> ou o hash <code>#demo</code> para o Cortex real.</div>
      <Ribbon />
      <aside className="rail">
        <div className="rail-head"><div className="rail-brand">Cortex</div><div className="rail-sub" id="railSub">{demoMode ? 'Vista fictícia · no GHOSTRECON principal ligas achados validados ao cérebro (SQLite)' : fakeLoading ? 'A simular…' : 'Tipos do cérebro · validações manuais e candidatos GhostIA (SQLite local)'}</div></div>
        <div className="rail-search">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" /></svg>
          <input ref={searchRef} type="search" placeholder="Pesquisar notas…" id="railSearchInput" autoComplete="off" value={search} onChange={(event) => setSearch(event.currentTarget.value)} />
        </div>
        <div className="rail-fake" style={{ marginTop: 8 }}><button type="button" className="rail-fake-btn" id="btnFakeBrain" disabled={fakeLoading} onClick={() => void simulate()}>Simular GET /api/brain/categories</button></div>
        <div className="rail-section">Vulnerabilidades <span className="rail-section-badge" id="catCount">{categories.length}</span></div>
        <div className="rail-list" id="railList">
          {!categories.length ? <p style={{ padding: '14px 16px', fontSize: 10, color: 'var(--dim)', lineHeight: 1.6 }}>Sem categorias.<br />No GHOSTRECON principal usa checklist + cérebro (SQLite), ou clica em <em>Simular</em> acima.</p> : (
            <><div className="nav-folder"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" /></svg>findings</div>{filteredCategories.map((category) => <button type="button" key={category.id} className={`nav-item${activeId === Number(category.id) ? ' is-active' : ''}`} onClick={() => void selectCategory(Number(category.id))}><span className="nav-item-label">{String(category.title || '')}</span><span className="nav-count">{Number(category.linkCount) || 0}</span></button>)}</>
          )}
        </div>
      </aside>
      <main className="cortex-main" id="cortexMain">
        <div className="err-banner" id="errBanner" style={{ display: error ? 'block' : 'none' }}>{error}</div>
        <header className="canvas-head">
          <div className="canvas-head-main">
            <div className="canvas-ghost-bg" aria-hidden="true"><GhostMark /></div>
            <div className="canvas-head-front">
              <div className="canvas-breadcrumb"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="5" r="2" /><circle cx="5" cy="19" r="2" /><circle cx="19" cy="19" r="2" /><line x1="12" y1="7" x2="5" y2="17" /><line x1="12" y1="7" x2="19" y2="17" /></svg><span>GHOSTRECON</span> / <span id="breadcrumbCat">{activeTitle || '—'}</span></div>
              <h1 className="canvas-title" id="canvasTitle"><span className="canvas-title-accent">{activeId ? activeTitle : 'Cortex'}</span>{activeId ? null : ' — Cérebro'}</h1>
              <p className="canvas-hint" id="canvasHint">{hint}</p>
              <div id="categoryTeach" className="category-teach" hidden={!activeId}>
                <div className="category-teach-head"><strong id="categoryTeachHead">{teach.headline}</strong><div className="category-teach-actions"><button type="button" className="category-teach-edit-btn" id="categoryTeachEditBtn" aria-label="Editar descrição" title={demoMode ? 'Edição indisponível no modo demo' : 'Editar descrição'} disabled={demoMode} onClick={beginDescriptionEdit}>✎</button></div></div>
                <p id="categoryTeachPara" className="category-teach-para">{teach.text}</p>
                <div id="categoryTeachEditWrap" className={`category-teach-edit${descriptionEditing ? ' is-open' : ''}`}>
                  <textarea id="categoryTeachInput" className="category-teach-input" maxLength={2000} placeholder="Descreve esta categoria..." value={descriptionDraft} onChange={(event) => setDescriptionDraft(event.currentTarget.value)} />
                  <div className="category-teach-edit-actions"><button type="button" className="category-teach-btn" id="categoryTeachSaveBtn" disabled={descriptionSaving} onClick={() => void saveDescription()}>Guardar</button><button type="button" className="category-teach-btn" id="categoryTeachCancelBtn" onClick={() => setDescriptionEditing(false)}>Cancelar</button></div>
                </div>
              </div>
            </div>
          </div>
          <div className="canvas-head-tools">
            <div className="canvas-stats" id="canvasStats" style={{ display: activeId ? 'flex' : 'none' }}><div className="stat-pill"><strong id="statNodes">{activeLinks.length}</strong>&nbsp;nós</div><div className="stat-pill" style={{ color: 'var(--border2)' }}>|</div><div className="stat-pill"><strong id="statType">{activeType}</strong>&nbsp;tipo</div></div>
            <input type="checkbox" id="toggleObsidianGraph" checked={obsidian} style={{ display: 'none' }} onChange={(event) => { const enabled = event.currentTarget.checked; setObsidian(enabled); writeObsidianPreference(enabled); }} />
            <label htmlFor="toggleObsidianGraph" className="toggle-pill"><span className="toggle-pill-dot" />Mapa local</label>
          </div>
        </header>
        <div className={`canvas-body${obsidian && activeLinks.length ? ' canvas-body--graph' : ''}`} id="canvasBody">
          {!activeId ? <EmptyCanvas demoMode={demoMode} /> : !activeLinks.length ? <p className="empty-canvas">Sem nós nesta categoria. Liga achados na checklist (app principal) ao cérebro.</p> : obsidian ? <ObsidianGraph title={activeTitle || 'Tipo'} links={activeLinks} openDrawer={openDrawer} /> : <div className="graph-wrap"><div className="graph-lines" aria-hidden="true" /><div className="nodes">{activeLinks.map((link, index) => <button type="button" className="node" data-idx={index} key={`${String(link.fingerprint)}-${index}`} onClick={() => openDrawer(link)}>{link.snapshot?.type ? <span className="node-type-badge">{String(link.snapshot.type)}</span> : null}<div className="node-target">{String(link.target || '')}</div><div className="node-snippet">{snippetFromLink(link)}</div><div className="node-meta"><span>{String(link.fingerprint || '').slice(0, 12)}…</span><span>{String(link.linked_at || '').slice(0, 10)}</span></div></button>)}</div></div>}
        </div>
      </main>
      <div className={`drawer-backdrop${drawerLink ? ' is-open' : ''}`} id="drawerBackdrop" aria-hidden={!drawerLink} onClick={() => setDrawerLink(null)} />
      <aside className={`drawer${drawerLink ? ' is-open' : ''}`} id="drawer" aria-hidden={!drawerLink} style={{ transform: drawerLink ? 'translateX(0)' : 'translateX(100%)' }}>
        <div className="drawer-head"><div className="drawer-title-wrap"><div className="drawer-icon" /><h2 className="drawer-title" id="drawerTitle">{activeTitle || 'Detalhe'}</h2></div><button type="button" className="drawer-close" id="drawerClose" aria-label="Fechar" onClick={() => setDrawerLink(null)}>×</button></div>
        <div className="drawer-body" id="drawerBody">
          {drawerLink ? <>
            {drawerLink.snapshot?.type ? <div style={{ marginBottom: 12 }}><span className="drawer-tag drawer-tag-type">{String(drawerLink.snapshot.type)}</span>{drawerLink.snapshot.prio ? <span className={`drawer-tag ${drawerLink.snapshot.prio === 'high' ? 'drawer-tag-prio-high' : drawerLink.snapshot.prio === 'medium' ? 'drawer-tag-prio-medium' : ''}`}>{String(drawerLink.snapshot.prio)}</span> : null}</div> : null}
            <div className="drawer-section"><div className="drawer-label">Alvo</div><pre className="drawer-pre">{String(drawerLink.target || '')}</pre></div>
            <div className="drawer-section"><div className="drawer-label">URL</div><pre className="drawer-pre">{linkDisplayUrl(drawerLink)}</pre></div>
            <div className="drawer-section"><div className="drawer-label">Fingerprint</div><pre className="drawer-pre">{String(drawerLink.fingerprint || '')}</pre></div>
            {taxonomyText(drawerLink.snapshot?.owasp) ? <div className="drawer-section"><div className="drawer-label">OWASP</div><pre className="drawer-pre">{taxonomyText(drawerLink.snapshot?.owasp)}</pre></div> : null}
            {taxonomyText(drawerLink.snapshot?.mitre) ? <div className="drawer-section"><div className="drawer-label">MITRE ATT&amp;CK</div><pre className="drawer-pre">{taxonomyText(drawerLink.snapshot?.mitre)}</pre></div> : null}
            <div className="drawer-section"><div className="drawer-label">Notas</div><textarea id="drawerNotesInput" className="drawer-notes-edit" placeholder="Escreve notas deste alvo..." value={drawerNotes} onChange={(event) => setDrawerNotes(event.currentTarget.value)} /><div className="drawer-note-tools"><label className="drawer-note-check"><input type="checkbox" id="drawerMarkedCheck" checked={drawerMarked} onChange={(event) => setDrawerMarked(event.currentTarget.checked)} /> Marcar alvo</label><button type="button" className="drawer-note-save" id="drawerNotesSaveBtn" disabled={drawerSaving || demoMode} onClick={() => void saveNotes()}>Guardar notas</button><span id="drawerNoteStatus" className={`drawer-note-status${drawerStatus.kind ? ` ${drawerStatus.kind}` : ''}`}>{drawerStatus.text}</span></div></div>
            <div className="drawer-section"><div className="drawer-label">Snapshot</div><pre className="drawer-pre">{JSON.stringify(drawerLink.snapshot || {}, null, 2)}</pre></div>
          </> : null}
        </div>
      </aside>
    </>
  );
}
