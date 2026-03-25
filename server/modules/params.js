const PARAM_RE = /[?&]([a-zA-Z_][a-zA-Z0-9_]{0,64})=/g;

export function extractParamsFromUrls(urls) {
  const map = new Map();
  for (const raw of urls) {
    let u;
    try {
      u = new URL(raw);
    } catch {
      continue;
    }
    u.searchParams.forEach((_, k) => {
      if (!map.has(k)) map.set(k, 0);
      map.set(k, map.get(k) + 1);
    });
    let m;
    const s = u.search;
    while ((m = PARAM_RE.exec(s)) !== null) {
      const k = m[1];
      if (!map.has(k)) map.set(k, 0);
      map.set(k, map.get(k) + 1);
    }
  }
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ name, count }));
}
