/**
 * Parser de argumentos minimalista (zero dependências) — POSIX-ish.
 * Suporta: --flag, --key=value, --key value, -x shortcut, repetidos → array.
 *
 * Spec item-by-item:
 *   { name: 'target', type: 'string', required: true, alias: 't' }
 *   { name: 'modules', type: 'csv' }        // vira array de strings
 *   { name: 'kali', type: 'bool' }
 *   { name: 'auth-header', type: 'repeat' } // repetível, vira array
 *   { name: 'timeout', type: 'int', default: 1800 }
 *
 * Retorna { opts, positional, unknown }.
 */

export function parseArgs(argv, spec) {
  const opts = {};
  const positional = [];
  const unknown = [];
  const byName = new Map(); // name → specEntry
  const byAlias = new Map(); // alias → specEntry

  for (const entry of spec) {
    byName.set(entry.name, entry);
    if (entry.alias) byAlias.set(entry.alias, entry);
    if (entry.default !== undefined) opts[entry.name] = entry.default;
    if (entry.type === 'repeat' || entry.type === 'csv') {
      if (opts[entry.name] === undefined) opts[entry.name] = [];
    }
  }

  let i = 0;
  while (i < argv.length) {
    const tok = argv[i];
    if (tok === '--') {
      positional.push(...argv.slice(i + 1));
      break;
    }
    if (tok.startsWith('--')) {
      const eq = tok.indexOf('=');
      const key = eq >= 0 ? tok.slice(2, eq) : tok.slice(2);
      const inlineVal = eq >= 0 ? tok.slice(eq + 1) : null;
      const entry = byName.get(key);
      if (!entry) {
        unknown.push(tok);
        i++;
        continue;
      }
      i = consume(entry, argv, i, inlineVal, opts);
      continue;
    }
    if (tok.startsWith('-') && tok.length > 1) {
      const alias = tok.slice(1);
      const entry = byAlias.get(alias);
      if (!entry) {
        unknown.push(tok);
        i++;
        continue;
      }
      i = consume(entry, argv, i, null, opts);
      continue;
    }
    positional.push(tok);
    i++;
  }

  // Required / validation
  const missing = [];
  for (const entry of spec) {
    if (entry.required && (opts[entry.name] === undefined || opts[entry.name] === '')) {
      missing.push(`--${entry.name}`);
    }
  }
  if (missing.length) {
    throw new Error(`argumentos obrigatórios ausentes: ${missing.join(', ')}`);
  }

  return { opts, positional, unknown };
}

function consume(entry, argv, i, inlineVal, opts) {
  const next = () => {
    if (inlineVal != null) return inlineVal;
    return argv[i + 1];
  };
  switch (entry.type) {
    case 'bool':
      opts[entry.name] = true;
      return inlineVal != null ? i + 1 : i + 1;
    case 'int': {
      const v = next();
      if (v == null) throw new Error(`--${entry.name} requer um número`);
      const n = Number(v);
      if (!Number.isFinite(n)) throw new Error(`--${entry.name} valor inválido: ${v}`);
      opts[entry.name] = Math.trunc(n);
      return inlineVal != null ? i + 1 : i + 2;
    }
    case 'csv': {
      const v = next();
      if (v == null) throw new Error(`--${entry.name} requer uma lista CSV`);
      const arr = String(v)
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      opts[entry.name] = arr;
      return inlineVal != null ? i + 1 : i + 2;
    }
    case 'repeat': {
      const v = next();
      if (v == null) throw new Error(`--${entry.name} requer um valor`);
      opts[entry.name] = [...(opts[entry.name] || []), v];
      return inlineVal != null ? i + 1 : i + 2;
    }
    case 'string':
    default: {
      const v = next();
      if (v == null) throw new Error(`--${entry.name} requer um valor`);
      opts[entry.name] = String(v);
      return inlineVal != null ? i + 1 : i + 2;
    }
  }
}

/** Converte ["K=V","K2=V2"] em { K: V, K2: V2 }. */
export function kvListToObject(list) {
  const out = {};
  for (const item of list || []) {
    const s = String(item);
    const eq = s.indexOf('=');
    if (eq <= 0) continue;
    const k = s.slice(0, eq).trim();
    const v = s.slice(eq + 1);
    if (k) out[k] = v;
  }
  return out;
}

/** "6h" → 21600000ms, "30m" → 1800000, "45s" → 45000, "2d" → 172800000. */
export function parseDuration(str) {
  const s = String(str || '').trim().toLowerCase();
  const m = /^(\d+)(ms|s|m|h|d)$/.exec(s);
  if (!m) {
    const n = Number(s);
    if (Number.isFinite(n) && n > 0) return Math.trunc(n);
    throw new Error(`duração inválida: ${str}`);
  }
  const n = Number(m[1]);
  switch (m[2]) {
    case 'ms':
      return n;
    case 's':
      return n * 1000;
    case 'm':
      return n * 60_000;
    case 'h':
      return n * 3_600_000;
    case 'd':
      return n * 86_400_000;
    default:
      throw new Error(`unidade desconhecida: ${m[2]}`);
  }
}
