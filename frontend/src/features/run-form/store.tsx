import {
  createContext,
  useContext,
  useSyncExternalStore,
  type ReactNode,
} from 'react';
import { normalizeReconProfile, type ReconProfile } from './model';

export type RunFormState = {
  batchDomains: string;
  batchMode: boolean;
  modules: Readonly<Record<string, boolean>>;
  profile: ReconProfile;
  target: string;
};

export type RunFormStore = ReturnType<typeof createRunFormStore>;

function cloneState(state: RunFormState): RunFormState {
  return { ...state, modules: { ...state.modules } };
}

export function initialRunFormState(
  source: string,
  storage?: Pick<Storage, 'getItem'> | null,
): RunFormState {
  const parsed = new DOMParser().parseFromString(source, 'text/html');
  const modules: Record<string, boolean> = {};
  for (const input of parsed.querySelectorAll<HTMLInputElement>('input.mod[type="checkbox"]')) {
    if (input.value) modules[input.value] = input.checked;
  }
  let profile = normalizeReconProfile(
    (parsed.getElementById('reconProfileSelect') as HTMLSelectElement | null)?.value,
  );
  try {
    const saved = storage?.getItem('ghostrecon_profile');
    if (saved) profile = normalizeReconProfile(saved);
  } catch {
    // Storage bloqueado não impede o cockpit em file://.
  }
  return {
    batchDomains: (parsed.getElementById('batchDomainsInput') as HTMLTextAreaElement | null)?.value || '',
    batchMode: Boolean((parsed.getElementById('batchModeToggle') as HTMLInputElement | null)?.checked),
    modules,
    profile,
    target: (parsed.getElementById('domainInput') as HTMLInputElement | null)?.value || '',
  };
}

export function createRunFormStore(initial: RunFormState) {
  let state = cloneState(initial);
  const listeners = new Set<() => void>();
  const update = (next: RunFormState | ((current: RunFormState) => RunFormState)) => {
    const resolved = typeof next === 'function' ? next(state) : next;
    if (Object.is(resolved, state)) return state;
    state = resolved;
    for (const listener of listeners) listener();
    return state;
  };

  return Object.freeze({
    getState: () => state,
    subscribe(listener: () => void) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    getSelectedModules() {
      return Object.entries(state.modules)
        .filter(([, selected]) => selected)
        .map(([module]) => module);
    },
    setTarget(target: string) {
      return update((current) => ({ ...current, target: String(target || '') })).target;
    },
    setBatchMode(batchMode: boolean) {
      return update((current) => ({ ...current, batchMode: Boolean(batchMode) })).batchMode;
    },
    setBatchDomains(batchDomains: string) {
      return update((current) => ({ ...current, batchDomains: String(batchDomains || '') }))
        .batchDomains;
    },
    setProfile(profile: unknown) {
      return update((current) => ({ ...current, profile: normalizeReconProfile(profile) })).profile;
    },
    setModule(module: string, selected: boolean) {
      const name = String(module || '');
      if (!name || state.modules[name] === Boolean(selected)) return state.modules;
      return update((current) => ({
        ...current,
        modules: { ...current.modules, [name]: Boolean(selected) },
      })).modules;
    },
    replaceModules(selectedModules: Iterable<string>) {
      const selected = new Set([...selectedModules].map(String));
      const modules = Object.fromEntries(
        Object.keys(state.modules).map((module) => [module, selected.has(module)]),
      );
      return update((current) => ({ ...current, modules })).modules;
    },
  });
}

const RunFormStoreContext = createContext<RunFormStore | null>(null);

export function RunFormStoreProvider({
  children,
  store,
}: {
  children: ReactNode;
  store: RunFormStore;
}) {
  return <RunFormStoreContext.Provider value={store}>{children}</RunFormStoreContext.Provider>;
}

export function useRunFormStore(): RunFormStore {
  const store = useContext(RunFormStoreContext);
  if (!store) throw new Error('RunFormStoreProvider ausente');
  return store;
}

export function useRunFormState(): RunFormState {
  const store = useRunFormStore();
  return useSyncExternalStore(store.subscribe, store.getState, store.getState);
}

declare global {
  interface Window {
    __ghostreconRunFormStore?: RunFormStore;
  }
}

export function installRunFormStore(windowRef: Window, store: RunFormStore): () => void {
  windowRef.__ghostreconRunFormStore = store;
  document.body.dataset.ghostreconRunFormStore = '1';
  return () => {
    if (windowRef.__ghostreconRunFormStore === store) {
      delete windowRef.__ghostreconRunFormStore;
      delete document.body.dataset.ghostreconRunFormStore;
    }
  };
}
