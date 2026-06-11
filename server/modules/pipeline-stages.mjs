export const PIPELINE_STAGE_ORDER = [
  'input',
  'discovery',
  'surface',
  'secrets',
  'validation',
  'aggressive',
  'score',
  'whitebox',
  'ai',
  'persistence',
];

export const KALI_SUB_PIPE_STEPS = [
  'nmap',
  'nmap_udp',
  'whois',
  'ffuf',
  'dirsearch',
  'nuclei',
  'nuclei_xss',
  'nuclei_sqli',
  'wpscan',
  'dalfox',
  'xss_vibes',
];

export function createPipelineStageTracker(emit = () => {}) {
  const active = new Map();
  return {
    pipe(name, state) {
      active.set(name, state);
      emit({ type: 'pipe', name, state });
    },
    progress(pct) {
      emit({ type: 'progress', pct });
    },
    skipMany(names) {
      for (const name of names || []) this.pipe(name, 'skip');
    },
    snapshot() {
      return {
        order: PIPELINE_STAGE_ORDER,
        pipes: Object.fromEntries(active.entries()),
      };
    },
  };
}
