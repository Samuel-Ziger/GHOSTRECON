/**
 * GraphQL recon — introspection probe + alias DoS detect + auth matrix hooks.
 *
 * Lógica de parsing/diagnóstico é pura. Caller injeta `executor(query, vars, headers)`.
 */

const INTROSPECTION_QUERY = `
  query IntrospectionQuery {
    __schema {
      queryType { name }
      mutationType { name }
      subscriptionType { name }
      types {
        kind name description
        fields(includeDeprecated: true) { name description type { kind name } args { name type { kind name } } }
        inputFields { name type { kind name } }
        interfaces { name }
        enumValues(includeDeprecated: true) { name }
        possibleTypes { name }
      }
    }
  }
`;

export function getIntrospectionQuery() {
  return INTROSPECTION_QUERY.trim();
}

/**
 * Diagnóstico do schema: superfície sensível, mutations, scalars custom, etc.
 */
export function analyzeSchema(introspection) {
  const out = {
    queryType: null, mutationType: null, subscriptionType: null,
    types: 0, mutations: [], queries: [], sensitiveFields: [], deprecated: [],
  };
  const root = introspection?.data?.__schema || introspection?.__schema;
  if (!root) return out;
  out.queryType = root.queryType?.name || null;
  out.mutationType = root.mutationType?.name || null;
  out.subscriptionType = root.subscriptionType?.name || null;
  out.types = (root.types || []).length;

  for (const t of root.types || []) {
    if (t.name === out.mutationType) {
      for (const f of t.fields || []) out.mutations.push(f.name);
    }
    if (t.name === out.queryType) {
      for (const f of t.fields || []) out.queries.push(f.name);
    }
    for (const f of t.fields || []) {
      if (/^(password|secret|token|apiKey|api_key|privateKey|ssn|creditCard|cardNumber|otp|mfa|seed|webhook)/i.test(f.name)) {
        out.sensitiveFields.push(`${t.name}.${f.name}`);
      }
      if (f.isDeprecated || f.deprecationReason) out.deprecated.push(`${t.name}.${f.name}`);
    }
  }
  return out;
}

/**
 * Alias-based DoS heuristic — se introspection tá ON e tem mutation cara
 * (ex: `createUser`), gera query alias-bombed para teste manual.
 */
export function buildAliasDosProbe(fieldName, count = 100) {
  const aliases = Array.from({ length: count }, (_, i) => `a${i}: ${fieldName}`).join('\n  ');
  return `query AliasDoS {\n  ${aliases}\n}`;
}

/**
 * Field suggestion attack — error-based discovery quando introspection OFF.
 * Gera query inválida cujo erro normalmente vaza nomes de fields ("Did you mean...").
 */
export function buildFieldSuggestionProbe(typeName, candidate = 'aaa') {
  return `query Suggest {\n  __type(name: "${typeName}") { fields { name } }\n  ${candidate}\n}`;
}

/**
 * Roda introspection via executor injetado. Devolve findings.
 */
export async function probeGraphqlEndpoint(url, { executor, headers = {} }) {
  if (typeof executor !== 'function') throw new Error('probeGraphqlEndpoint: executor obrigatório');
  const findings = [];
  let intro;
  try {
    intro = await executor(INTROSPECTION_QUERY, {}, headers);
  } catch (e) {
    return { url, findings, error: e?.message || String(e) };
  }
  const ok = intro?.data?.__schema || intro?.__schema;
  if (ok) {
    const analysis = analyzeSchema(intro);
    findings.push({
      severity: 'medium', category: 'graphql-introspection',
      title: `GraphQL introspection ativo em ${url}`,
      description: `Schema exposto. ${analysis.queries.length} queries, ${analysis.mutations.length} mutations, ${analysis.sensitiveFields.length} fields sensíveis.`,
      evidence: { url, queries: analysis.queries.slice(0, 30), mutations: analysis.mutations.slice(0, 30), sensitive: analysis.sensitiveFields },
    });
    if (analysis.sensitiveFields.length) {
      findings.push({
        severity: 'high', category: 'graphql-sensitive-field',
        title: `GraphQL expõe fields sensíveis (${analysis.sensitiveFields.length})`,
        description: `Fields como ${analysis.sensitiveFields.slice(0, 6).join(', ')} podem retornar PII/credenciais.`,
        evidence: { url, sensitive: analysis.sensitiveFields },
      });
    }
    return { url, findings, analysis };
  }
  // fallback: probe field suggestion
  let suggestion;
  try { suggestion = await executor(buildFieldSuggestionProbe('Query'), {}, headers); } catch {}
  if (suggestion?.errors?.some((e) => /Did you mean/i.test(e.message || ''))) {
    findings.push({
      severity: 'low', category: 'graphql-field-suggestion',
      title: `GraphQL field-suggestion ativo em ${url}`,
      description: 'Endpoint vaza nomes de fields via "Did you mean..." — enumeration manual viável mesmo com introspection off.',
      evidence: { url, errors: suggestion.errors.slice(0, 5) },
    });
  }
  return { url, findings };
}
