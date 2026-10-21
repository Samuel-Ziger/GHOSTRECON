/**
 * Contexto de descoberta para achados — explicar **como** surgiu e **ligação ao alvo**.
 * A UI e os exports JSON incluem `provenance` quando presente.
 */

/**
 * @param {object} finding
 * @param {string | { how?: string, relation?: string }} p
 * @returns {object}
 */
export function withProvenance(finding, p) {
  const descriptor = typeof p === 'string' ? { how: p } : p || {};
  const how = String(descriptor.how ?? finding?.provenance?.how ?? '').trim();
  const relation = String(descriptor.relation ?? finding?.provenance?.relation ?? '').trim();
  if (!how && !relation) return finding;
  return {
    ...finding,
    provenance: { how, relation },
  };
}
