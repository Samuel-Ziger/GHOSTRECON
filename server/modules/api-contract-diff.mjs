import { createHash } from 'node:crypto';
import { limits } from '../config.js';
import { urlInReconScope } from './scope.js';
import { pickStealthUserAgent, stealthEnabled, stealthPause } from './request-policy.js';
import { mapPool, readResponseSnippet } from './module-runner.mjs';
import { combineAbortSignals, throwIfAborted } from './http-utils.js';
import { fetchScoped } from './scoped-fetch.mjs';
import { loadAutoRedactionPolicy, redactAutoText } from '../auto-agent/redaction.mjs';
import {
  parseJsonDocumentStrict,
  parseJsonDocumentInWorker,
  parseYamlDocumentInWorker,
} from './api-contract-parser-worker.mjs';

export const API_CONTRACT_SNAPSHOT_FORMAT = 'ghostrecon.api-contract-snapshot';
export const API_CONTRACT_SNAPSHOT_SCHEMA_VERSION = 2;
export const API_CONTRACT_CANONICALIZATION_VERSION = 8;

const LEGACY_CANONICALIZATION_VERSION = 2;
const SURFACE_CANONICALIZATION_VERSION = 3;
const V4_CANONICALIZATION_VERSION = 4;
const REFERENCE_COVERAGE_CANONICALIZATION_VERSION = 5;
const REFERENCE_VALIDATION_CANONICALIZATION_VERSION = 6;
const CONTEXTUAL_REFERENCE_CANONICALIZATION_VERSION = 7;
const COMPONENT_DEFAULTS_CANONICALIZATION_VERSION = 8;
const SUPPORTED_CANONICALIZATION_VERSIONS = new Set([
  LEGACY_CANONICALIZATION_VERSION,
  SURFACE_CANONICALIZATION_VERSION,
  V4_CANONICALIZATION_VERSION,
  REFERENCE_COVERAGE_CANONICALIZATION_VERSION,
  REFERENCE_VALIDATION_CANONICALIZATION_VERSION,
  CONTEXTUAL_REFERENCE_CANONICALIZATION_VERSION,
  COMPONENT_DEFAULTS_CANONICALIZATION_VERSION,
  API_CONTRACT_CANONICALIZATION_VERSION,
]);

export const moduleManifest = {
  id: 'api_contract_diff',
  name: 'API Contract Diff',
  category: 'surface',
  intrusive: false,
  requiresAuth: false,
  requiresKali: false,
  timeoutMs: 30_000,
  concurrency: 2,
  outputs: ['finding'],
};

const SPEC_PATHS = [
  '/openapi.json',
  '/openapi.yaml',
  '/openapi.yml',
  '/swagger.json',
  '/swagger.yaml',
  '/swagger.yml',
  '/v2/api-docs',
  '/v3/api-docs',
  '/api-docs/swagger.json',
  '/swagger/v1/swagger.json',
];

const HTTP_METHODS = new Set([
  'get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'trace',
  // QUERY passou a integrar o Path Item no OpenAPI 3.2.
  'query',
]);
const FIXED_HTTP_WIRE_METHODS = new Set(
  [...HTTP_METHODS].map((method) => method.toUpperCase()),
);
const HTTP_METHOD_TOKEN_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const ANNOTATION_KEYS = new Set([
  'description',
  'summary',
  'title',
  'example',
  'examples',
  'externalDocs',
]);
const UNORDERED_ARRAY_KEYS = new Set([
  'allOf', 'anyOf', 'oneOf', 'enum', 'required', 'type',
  'consumes', 'produces', 'schemes',
]);
const SEMANTIC_MAP_KEYS = new Set([
  '$defs',
  'additionalOperations',
  'callbacks',
  'content',
  'definitions',
  'dependentSchemas',
  'encoding',
  'headers',
  'links',
  'mapping',
  'parameters',
  'pathItems',
  'patternProperties',
  'properties',
  'requestBodies',
  'responses',
  'schemas',
  'scopes',
  'securitySchemes',
  'variables',
]);
const REFERENCE_OBJECT_KINDS = new Set([
  'callback',
  'example',
  'header',
  'link',
  'parameter',
  'pathItem',
  'requestBody',
  'response',
  'schema',
  'securityScheme',
]);
const LEGACY_SCHEMA_MAP_KEYS = new Set(['properties']);
const MODERN_SCHEMA_MAP_KEYS = new Set([
  '$defs',
  'dependentSchemas',
  'patternProperties',
  'properties',
]);
const LEGACY_SCHEMA_CHILD_KEYS = new Set([
  'additionalProperties',
  'allOf',
  'anyOf',
  'items',
  'not',
  'oneOf',
]);
const MODERN_SCHEMA_CHILD_KEYS = new Set([
  'additionalProperties',
  'allOf',
  'anyOf',
  'contains',
  'contentSchema',
  'else',
  'if',
  'items',
  'not',
  'oneOf',
  'prefixItems',
  'propertyNames',
  'then',
  'unevaluatedItems',
  'unevaluatedProperties',
]);
const COMMON_SCHEMA_SEMANTIC_KEYS = new Set([
  '$ref',
  'additionalProperties', 'allOf', 'anyOf', 'const', 'default',
  'deprecated', 'description', 'discriminator', 'else', 'enum', 'example',
  'examples', 'exclusiveMaximum', 'exclusiveMinimum', 'externalDocs', 'format',
  'if', 'items', 'maxItems', 'maxLength', 'maxProperties', 'maximum',
  'minItems', 'minLength', 'minProperties', 'minimum', 'multipleOf', 'not',
  'oneOf', 'pattern', 'properties', 'readOnly', 'required', 'title', 'type',
  'uniqueItems', 'writeOnly', 'xml',
]);
const MODERN_SCHEMA_SEMANTIC_KEYS = new Set([
  ...COMMON_SCHEMA_SEMANTIC_KEYS,
  '$anchor', '$defs', '$dynamicAnchor', '$dynamicRef', '$id', '$schema', '$vocabulary',
  'contains', 'contentEncoding', 'contentMediaType', 'contentSchema',
  'dependentRequired', 'dependentSchemas', 'maxContains', 'minContains',
  'patternProperties', 'prefixItems', 'propertyNames', 'then',
  'unevaluatedItems', 'unevaluatedProperties',
]);
const LEGACY_SCHEMA_SEMANTIC_KEYS = new Set([
  ...COMMON_SCHEMA_SEMANTIC_KEYS,
  'nullable',
]);
const SWAGGER_SCHEMA_SEMANTIC_KEYS = new Set(COMMON_SCHEMA_SEMANTIC_KEYS);
const SUPPORTED_SCHEMA_DIALECTS = new Set([
  'https://json-schema.org/draft/2020-12/schema',
  'https://spec.openapis.org/oas/3.1/dialect/base',
  'https://spec.openapis.org/oas/3.2/dialect/base',
]);
const SUPPORTED_DOCUMENT_VERSIONS = new Set(['2.0', '3.0', '3.1', '3.2']);
const EXPLICIT_OPERATION_KEYS = new Set([
  'operationId', 'tags', 'parameters', 'requestBody', 'responses', 'security',
  'deprecated', 'summary', 'description', 'externalDocs',
]);
const RESPONSE_CODE_RE = /^(?:DEFAULT|[1-5](?:\d{2}|XX))$/;
const MAX_SPEC_BYTES = 2_000_000;
const MAX_TOTAL_SPEC_BYTES = 16_000_000;
const MAX_TOTAL_SUMMARY_BYTES = 16_000_000;
const MAX_TOTAL_SNAPSHOT_BYTES = 16_000_000;
const MAX_TOTAL_BASELINE_BYTES = 16_000_000;
const MAX_CONTRACTS_PER_RUN = 100;
const MAX_ORIGINS = 25;
const MAX_ORIGIN_INPUTS = 1_000;
const MAX_PATHS = 2_500;
const MAX_WEBHOOKS = 1_000;
const MAX_OPERATIONS = 5_000;
const MAX_PARAMETERS_PER_CONTAINER = 128;
const MAX_PARAMETERS_PER_OPERATION = MAX_PARAMETERS_PER_CONTAINER * 2;
const MAX_RESPONSES_PER_OPERATION = 128;
const MAX_SECURITY_SCHEMES = 256;
const MAX_SECURITY_ALTERNATIVES = 64;
const MAX_SECURITY_SCHEMES_PER_ALTERNATIVE = 32;
const MAX_SECURITY_SCOPES = 128;
const MAX_TAGS_PER_OPERATION = 64;
const MAX_CANONICAL_NODES = 250_000;
const MAX_CANONICAL_DEPTH = 24;
const MAX_COLLECTION_ITEMS = 512;
const MAX_TEXT_LENGTH = 4_096;
const MAX_NAME_LENGTH = 512;
const MAX_API_CONTRACT_SNAPSHOTS_PER_RUN = MAX_CONTRACTS_PER_RUN;
const MAX_DIFF_EVIDENCE_ITEMS = 100;
const MAX_REDIRECTS = 3;
const MAX_ADDITIONAL_OPERATIONS = 64;
const MAX_HTTP_METHOD_LENGTH = 64;
const MAX_REFERENCE_SCAN_NODES = MAX_CANONICAL_NODES;
const MAX_REFERENCE_SCAN_DEPTH = MAX_CANONICAL_DEPTH;
const MAX_REFERENCES_PER_DOCUMENT = 4_096;
const MAX_SOURCE_ALIASES = MAX_ORIGINS * SPEC_PATHS.length;
const IGNORED_HEADER_PARAMETERS = new Set(['accept', 'content-type', 'authorization']);
const UNRESOLVED_REFERENCE_TARGET = Symbol('unresolved_api_contract_reference');

function schemaMapKeysFor(documentVersion) {
  return ['3.1', '3.2'].includes(documentVersion)
    ? MODERN_SCHEMA_MAP_KEYS
    : LEGACY_SCHEMA_MAP_KEYS;
}

function schemaChildKeysFor(documentVersion) {
  return ['3.1', '3.2'].includes(documentVersion)
    ? MODERN_SCHEMA_CHILD_KEYS
    : LEGACY_SCHEMA_CHILD_KEYS;
}

function schemaSemanticKeysFor(documentVersion) {
  if (['3.1', '3.2'].includes(documentVersion)) return MODERN_SCHEMA_SEMANTIC_KEYS;
  return documentVersion === '2.0'
    ? SWAGGER_SCHEMA_SEMANTIC_KEYS
    : LEGACY_SCHEMA_SEMANTIC_KEYS;
}

function normalizedSchemaDialect(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  try {
    const parsed = new URL(value);
    parsed.hash = '';
    return parsed.href.replace(/\/$/, '');
  } catch {
    return null;
  }
}

function supportedSchemaDialect(value) {
  const normalized = normalizedSchemaDialect(value);
  return normalized != null && SUPPORTED_SCHEMA_DIALECTS.has(normalized);
}

export class ApiContractFormatError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ApiContractFormatError';
    this.code = code;
  }
}

function formatError(code, message) {
  return new ApiContractFormatError(code, message);
}

function normalizedTimeoutMs(value, fallback = moduleManifest.timeoutMs) {
  const numeric = Number(value);
  const selected = Number.isFinite(numeric) && numeric > 0 ? numeric : fallback;
  return Math.max(1, Math.min(120_000, Math.floor(selected)));
}

function deadlineError(message = 'API contract deadline exhausted') {
  const error = new Error(message);
  error.name = 'TimeoutError';
  error.code = 'API_CONTRACT_DEADLINE';
  return error;
}

function deadlineExpired(deadlineAt) {
  return Number.isFinite(deadlineAt) && Date.now() >= deadlineAt;
}

function throwIfAbortedOrDeadline(signal, deadlineAt) {
  throwIfAborted(signal);
  if (deadlineExpired(deadlineAt)) throw deadlineError();
}

function isRecord(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function requireRecord(value, field) {
  if (!isRecord(value)) throw formatError('API_CONTRACT_INVALID_RECORD', `${field} deve ser objeto`);
  return value;
}

function compareOrdinal(left, right) {
  const a = String(left);
  const b = String(right);
  return a < b ? -1 : a > b ? 1 : 0;
}

function boundedString(
  value,
  field,
  maxLength = MAX_TEXT_LENGTH,
  { allowEmpty = true, redactSensitive = false } = {},
) {
  if (value == null) return '';
  if (!['string', 'number', 'boolean'].includes(typeof value)) {
    throw formatError('API_CONTRACT_INVALID_STRING', `${field} deve ser texto`);
  }
  const text = String(value);
  if (!allowEmpty && !text) throw formatError('API_CONTRACT_EMPTY_STRING', `${field} não pode ser vazio`);
  if (text.length > maxLength || text.includes('\0')) {
    throw formatError('API_CONTRACT_STRING_LIMIT', `${field} excede o limite`);
  }
  return redactSensitive
    ? redactAutoText(text, process.env, { cloud: false })
    : text;
}

function boundedArray(value, field, maxItems) {
  if (!Array.isArray(value)) throw formatError('API_CONTRACT_INVALID_ARRAY', `${field} deve ser lista`);
  if (value.length > maxItems) throw formatError('API_CONTRACT_COLLECTION_LIMIT', `${field} excede o limite`);
  return value;
}

function boundedRecordEntries(value, field, maxItems) {
  const entries = Object.entries(requireRecord(value, field));
  if (entries.length > maxItems) throw formatError('API_CONTRACT_COLLECTION_LIMIT', `${field} excede o limite`);
  return entries;
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

function currentRedactionPolicyHash(env = process.env) {
  const policy = loadAutoRedactionPolicy(env);
  return `sha256:${sha256(stableJson({
    version: policy.version,
    extras: [...policy.extras].sort(compareOrdinal),
  }))}`;
}

function canonicalContractUrl(value, { allowEmpty = false, redactSensitive = false } = {}) {
  const raw = boundedString(value, 'summary.url', MAX_TEXT_LENGTH, { allowEmpty });
  if (!raw && allowEmpty) return '';
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw formatError('API_CONTRACT_INVALID_URL', 'URL do contrato inválida');
  }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw formatError('API_CONTRACT_INVALID_URL', 'URL do contrato fora do formato HTTP permitido');
  }
  if (redactSensitive) {
    parsed = new URL(redactAutoText(parsed.href, process.env, { cloud: false }));
  }
  parsed.hash = '';
  const orderedParams = [...parsed.searchParams.entries()]
    .sort(([ak, av], [bk, bv]) => compareOrdinal(ak, bk) || compareOrdinal(av, bv));
  parsed.search = '';
  for (const [key, item] of orderedParams) parsed.searchParams.append(key, item);
  return parsed.href;
}

function normalizeSourceAliases(values, fallbackUrl = '', { redactSensitive = false } = {}) {
  const input = Array.isArray(values) ? values : [];
  if (input.length > MAX_SOURCE_ALIASES) {
    throw formatError('API_CONTRACT_ALIAS_LIMIT', 'fontes alternativas excedem o limite');
  }
  const aliases = new Set();
  for (const value of [fallbackUrl, ...input]) {
    if (!value) continue;
    const alias = canonicalContractUrl(value, { redactSensitive });
    if (!aliases.has(alias) && aliases.size >= MAX_SOURCE_ALIASES) {
      throw formatError('API_CONTRACT_ALIAS_LIMIT', 'fontes alternativas excedem o limite');
    }
    aliases.add(alias);
  }
  return [...aliases].sort(compareOrdinal);
}

function inspectReferenceResolution(doc, sourceUrl = '', signal = null, deadlineAt = null) {
  const seenObjects = new WeakMap();
  const externalReferences = new Set();
  const referenceIdentities = new Set();
  const resourceRoots = new Map();
  const knownAnchors = new Map();
  const referenceTargetKinds = new WeakMap();
  const referenceTargetKindsByLocation = new Map();
  const semanticReferenceIdentities = new WeakMap();
  const resolvedReferenceTargets = new WeakMap();
  const resourceLabels = new WeakMap([[doc, 'document']]);
  const recordedReferences = [];
  const coverageIssues = new Set();
  const documentVersion = canonicalDocumentVersion(getDocumentVersion(doc));
  const supportsSchemaResourceIds = ['3.1', '3.2'].includes(documentVersion);
  const supportsDynamicRef = supportsSchemaResourceIds;
  const schemaMapKeys = schemaMapKeysFor(documentVersion);
  const schemaChildKeys = schemaChildKeysFor(documentVersion);
  if (supportsSchemaResourceIds && Object.hasOwn(doc, 'jsonSchemaDialect')) {
    if (!supportedSchemaDialect(doc.jsonSchemaDialect)) {
      coverageIssues.add('unsupported_schema_dialect');
    }
  }
  let nodes = 0;
  let referencesSeen = 0;
  let scanTruncated = false;

  let retrievalUrl;
  try {
    retrievalUrl = sourceUrl
      ? new URL(sourceUrl)
      : new URL('https://ghostrecon.invalid/__api_contract_document__');
  } catch {
    retrievalUrl = new URL('https://ghostrecon.invalid/__api_contract_document__');
    coverageIssues.add('invalid_reference_base');
  }

  function resourceKey(url) {
    const normalized = new URL(url);
    normalized.hash = '';
    return normalized.href;
  }

  function resourceSemanticIdentity(url) {
    const redactedKey = redactAutoText(resourceKey(url), process.env, { cloud: false });
    return `resource:sha256:${sha256(redactedKey)}`;
  }

  function resolveBase(value, parentBase) {
    try {
      const resolved = new URL(value, parentBase);
      if (resolved.hash) {
        coverageIssues.add('invalid_reference_base');
        return parentBase;
      }
      return resolved;
    } catch {
      coverageIssues.add('invalid_reference_base');
      return parentBase;
    }
  }

  let documentBase = retrievalUrl;
  if (documentVersion === '3.2' && Object.hasOwn(doc, '$self')) {
    if (typeof doc.$self === 'string') {
      documentBase = resolveBase(doc.$self, retrievalUrl);
    } else {
      coverageIssues.add('invalid_reference_base');
    }
  }
  resourceRoots.set(resourceKey(retrievalUrl), doc);
  resourceRoots.set(resourceKey(documentBase), doc);

  function registerResource(base, value) {
    const key = resourceKey(base);
    const existing = resourceRoots.get(key);
    if (existing && existing !== value) {
      coverageIssues.add('duplicate_reference_base');
      return;
    }
    resourceRoots.set(key, value);
    if (!resourceLabels.has(value)) {
      resourceLabels.set(value, resourceSemanticIdentity(base));
    }
  }

  function markReferenceTargetKind(value, kind) {
    if (!isRecord(value) || !kind || kind === 'generic') return;
    let kinds = referenceTargetKinds.get(value);
    if (!kinds) {
      kinds = new Set();
      referenceTargetKinds.set(value, kinds);
    }
    kinds.add(kind);
  }

  function markReferenceTargetKindAtLocation(base, tokens, kind) {
    if (!kind || kind === 'generic') return;
    const resource = resourceKey(base);
    let locations = referenceTargetKindsByLocation.get(resource);
    if (!locations) {
      locations = new Map();
      referenceTargetKindsByLocation.set(resource, locations);
    }
    const pointer = tokens.length ? canonicalPointer(tokens) : '';
    let kinds = locations.get(pointer);
    if (!kinds) {
      kinds = new Set();
      locations.set(pointer, kinds);
    }
    kinds.add(kind);
  }

  function targetHasReferenceKind(target, targetUrl, pointerTokens, expectedKind) {
    if (!expectedKind) return true;
    if (isRecord(target)
      && referenceTargetKinds.get(target)?.has(expectedKind) === true) return true;
    const locations = referenceTargetKindsByLocation.get(resourceKey(targetUrl));
    const pointer = pointerTokens.length ? canonicalPointer(pointerTokens) : '';
    return locations?.get(pointer)?.has(expectedKind) === true;
  }

  function childReferenceKind(mapKind) {
    if (['schemas', 'definitions', '$defs', 'properties', 'patternProperties', 'dependentSchemas'].includes(mapKind)) return 'schema';
    if (mapKind === 'responses') return 'response';
    if (mapKind === 'parameters') return 'parameter';
    if (mapKind === 'requestBodies') return 'requestBody';
    if (mapKind === 'headers') return 'header';
    if (['paths', 'webhooks', 'pathItems', 'callbackExpressions'].includes(mapKind)) return 'pathItem';
    if (mapKind === 'callbacks') return 'callback';
    if (mapKind === 'links') return 'link';
    if (mapKind === 'examples') return 'example';
    if (mapKind === 'securitySchemes') return 'securityScheme';
    if (mapKind === 'additionalOperations') return 'operation';
    if (mapKind === 'content') return 'mediaType';
    if (mapKind === 'encoding') return 'encoding';
    return 'generic';
  }

  function recordReference(
    item,
    key,
    base,
    owner = null,
    propertyKey = key,
    expectedKind = '',
  ) {
    referencesSeen += 1;
    if ((referencesSeen & 127) === 0) {
      throwIfAbortedOrDeadline(signal, deadlineAt);
    }
    if (referencesSeen > MAX_REFERENCES_PER_DOCUMENT) {
      scanTruncated = true;
      return;
    }
    if (typeof item !== 'string') {
      coverageIssues.add('invalid_reference_value');
      return;
    }
    const reference = boundedString(
      item,
      key,
      MAX_TEXT_LENGTH,
      { allowEmpty: true },
    );
    recordedReferences.push({
      reference,
      key,
      base: new URL(base),
      owner,
      propertyKey: String(propertyKey),
      expectedKind,
    });
  }

  function visitExamples(value, depth, base) {
    if (!isRecord(value) || depth > MAX_REFERENCE_SCAN_DEPTH) return;
    let exampleIndex = 0;
    for (const exampleKey of Object.keys(value)) {
      exampleIndex += 1;
      if ((exampleIndex & 63) === 0) {
        throwIfAbortedOrDeadline(signal, deadlineAt);
      }
      const example = value[exampleKey];
      if (!isRecord(example)) continue;
      if (Object.hasOwn(example, '$ref')) {
        markReferenceTargetKind(example, 'example');
        recordReference(example.$ref, '$ref', base, example, '$ref', 'example');
      }
      if (scanTruncated) return;
    }
  }

  function visit(
    value,
    depth,
    keysAreContractNames = false,
    inheritedBase = documentBase,
    schemaContext = false,
    mapKind = '',
    location = [],
    objectKind = 'generic',
  ) {
    if (scanTruncated) return;
    let nodeBase = inheritedBase;
    let nodeLocation = location;
    if (isRecord(value)
      && !keysAreContractNames
      && schemaContext
      && supportsSchemaResourceIds
      && Object.hasOwn(value, '$id')) {
      if (typeof value.$id === 'string') {
        nodeBase = resolveBase(value.$id, inheritedBase);
        setReferenceMetadata(value, '$id', `$id:${resourceSemanticIdentity(nodeBase)}`);
        if (resourceKey(nodeBase) !== resourceKey(inheritedBase)) {
          registerResource(nodeBase, value);
          nodeLocation = [];
        }
      } else {
        coverageIssues.add('invalid_reference_base');
      }
    }
    const targetKind = schemaContext ? 'schema' : objectKind;
    if (!Array.isArray(value)) {
      markReferenceTargetKind(value, targetKind);
      const booleanSchema = schemaContext
        && typeof value === 'boolean'
        && ['3.1', '3.2'].includes(documentVersion);
      if (isRecord(value) || booleanSchema) {
        markReferenceTargetKindAtLocation(nodeBase, nodeLocation, targetKind);
      }
    }
    if (value == null || typeof value !== 'object') return;
    if (schemaContext
      && isRecord(value)
      && Object.hasOwn(value, '$schema')
      && !supportedSchemaDialect(value.$schema)) {
      coverageIssues.add('unsupported_schema_dialect');
    }
    const seenKey = `${nodeBase.href}\u0000${keysAreContractNames ? 'names' : 'object'}`;
    const seenAt = seenObjects.get(value);
    if (seenAt?.has(seenKey)) return;
    if (seenAt) seenAt.add(seenKey);
    else seenObjects.set(value, new Set([seenKey]));
    nodes += 1;
    if ((nodes & 255) === 0) throwIfAbortedOrDeadline(signal, deadlineAt);
    if (nodes > MAX_REFERENCE_SCAN_NODES || depth > MAX_REFERENCE_SCAN_DEPTH) {
      scanTruncated = true;
      return;
    }
    const entryKeys = Array.isArray(value)
      ? Array.from({ length: value.length }, (_, index) => String(index))
      : Object.keys(value);
    let entryIndex = 0;
    for (const key of entryKeys) {
      entryIndex += 1;
      if ((entryIndex & 63) === 0) {
        throwIfAbortedOrDeadline(signal, deadlineAt);
      }
      const item = value[key];
      const structuralKey = Array.isArray(value) || !keysAreContractNames;
      if (structuralKey && !Array.isArray(value) && key.startsWith('x-')) continue;
      const referenceKeyword = (key === '$ref'
          && (schemaContext || REFERENCE_OBJECT_KINDS.has(objectKind)))
        || (key === '$dynamicRef' && schemaContext && supportsDynamicRef)
        || (key === 'operationRef' && objectKind === 'link' && documentVersion !== '2.0');
      if (structuralKey && referenceKeyword) {
        const expectedKind = key === 'operationRef'
          ? 'operation'
          : schemaContext
            ? 'schema'
            : objectKind;
        recordReference(item, key, nodeBase, value, key, expectedKind);
        if (scanTruncated) return;
        continue;
      }
      if (structuralKey
        && schemaContext
        && supportsSchemaResourceIds
        && ['$anchor', '$dynamicAnchor'].includes(key)) {
        if (typeof item === 'string' && /^[A-Za-z_][-A-Za-z0-9._]*$/.test(item)) {
          const anchorIdentity = `${resourceKey(nodeBase)}#${item}`;
          const existing = knownAnchors.get(anchorIdentity);
          if (existing) coverageIssues.add('duplicate_reference_anchor');
          else knownAnchors.set(anchorIdentity, { value, kind: key });
        } else {
          coverageIssues.add('invalid_reference_anchor');
        }
        continue;
      }
      if (structuralKey
        && schemaContext
        && documentVersion !== '2.0'
        && key === 'discriminator'
        && isRecord(item)) {
        const recordDiscriminatorTarget = (
          mappingValue,
          referenceKey,
          owner,
          propertyKey,
        ) => {
          const isKnownComponent = typeof mappingValue === 'string'
            && isRecord(doc?.components?.schemas)
            && Object.hasOwn(doc.components.schemas, mappingValue);
          const componentPointer = isKnownComponent
            ? `#/components/schemas/${mappingValue.replace(/~/g, '~0').replace(/\//g, '~1')}`
            : mappingValue;
          recordReference(
            componentPointer,
            referenceKey,
              isKnownComponent ? documentBase : nodeBase,
              owner,
              propertyKey,
              'schema',
          );
        };
        if (Object.hasOwn(item, 'mapping')) {
          if (!isRecord(item.mapping)) {
            coverageIssues.add('invalid_discriminator_mapping');
          } else {
            let mappingIndex = 0;
            for (const mappingKey of Object.keys(item.mapping)) {
              mappingIndex += 1;
              if ((mappingIndex & 63) === 0) {
                throwIfAbortedOrDeadline(signal, deadlineAt);
              }
              const mappingValue = item.mapping[mappingKey];
              recordDiscriminatorTarget(
                mappingValue,
                'discriminator.mapping',
                item.mapping,
                mappingKey,
              );
              if (scanTruncated) return;
            }
          }
        }
        if (documentVersion === '3.2' && Object.hasOwn(item, 'defaultMapping')) {
          recordDiscriminatorTarget(
            item.defaultMapping,
            'discriminator.defaultMapping',
            item,
            'defaultMapping',
          );
          if (scanTruncated) return;
        }
      }
      // Esses campos carregam valores de exemplo/instância, não objetos do
      // contrato. Um texto "$ref" dentro deles é dado do usuário.
      if (structuralKey && ['example', 'default', 'const', 'enum'].includes(key)) continue;
      if (structuralKey
        && objectKind === 'link'
        && ['parameters', 'requestBody'].includes(key)) continue;
      if (structuralKey && key === 'examples') {
        if (!schemaContext && !(documentVersion === '2.0' && objectKind === 'response')) {
          visitExamples(item, depth + 1, nodeBase);
        }
        if (scanTruncated) return;
        continue;
      }
      if (schemaContext
        && structuralKey
        && !Array.isArray(value)
        && !schemaChildKeys.has(key)
        && !schemaMapKeys.has(key)) continue;
      const childKeysAreContractNames = structuralKey
        && (SEMANTIC_MAP_KEYS.has(key) || ['paths', 'webhooks'].includes(key));
      const schemaMapEntry = keysAreContractNames
        && (schemaMapKeys.has(mapKind)
          || (mapKind === 'schemas' && documentVersion !== '2.0')
          || (mapKind === 'definitions' && documentVersion === '2.0'));
      const childSchemaContext = Array.isArray(value)
        ? schemaContext
        : schemaMapEntry
        || (structuralKey && key === 'schema')
        || (schemaContext && schemaChildKeys.has(key));
      const mapEntryKind = childReferenceKind(mapKind);
      let childObjectKind = 'generic';
      if (keysAreContractNames || Array.isArray(value)) childObjectKind = mapEntryKind;
      else if (objectKind === 'callback') childObjectKind = 'pathItem';
      else if (objectKind === 'pathItem' && HTTP_METHODS.has(key)) childObjectKind = 'operation';
      else if (objectKind === 'operation' && key === 'requestBody') childObjectKind = 'requestBody';
      else if (objectKind === 'document' && key === 'components') childObjectKind = 'components';
      else if (structuralKey && key === 'schema') childObjectKind = 'schema';
      visit(
        item,
        depth + 1,
        childKeysAreContractNames,
        nodeBase,
        childSchemaContext,
        childKeysAreContractNames ? key : '',
        [...nodeLocation, key],
        childObjectKind,
      );
      if (scanTruncated) return;
    }
  }

  function pointerTarget(root, encodedFragment) {
    let pointer;
    try {
      pointer = decodeURIComponent(encodedFragment);
    } catch {
      return { found: false, value: undefined, pointer: null, tokens: [] };
    }
    if (!pointer.startsWith('/')) {
      return { found: false, value: undefined, pointer: null, tokens: [] };
    }
    let current = root;
    const tokens = [];
    let tokenIndex = 0;
    for (const encodedToken of pointer.slice(1).split('/')) {
      tokenIndex += 1;
      if ((tokenIndex & 127) === 0) {
        throwIfAbortedOrDeadline(signal, deadlineAt);
      }
      if (/~(?:[^01]|$)/.test(encodedToken)) {
        return { found: false, value: undefined, pointer: null, tokens: [] };
      }
      const token = decodePointerToken(encodedToken);
      tokens.push(token);
      if (Array.isArray(current)) {
        if (!/^(?:0|[1-9]\d*)$/.test(token) || Number(token) >= current.length) {
          return { found: false, value: undefined, pointer, tokens };
        }
        current = current[Number(token)];
      } else if (isRecord(current) && Object.hasOwn(current, token)) {
        current = current[token];
      } else {
        return { found: false, value: undefined, pointer, tokens };
      }
    }
    return { found: true, value: current, pointer, tokens };
  }

  function canonicalPointer(tokens) {
    return `/${tokens
      .map((token) => String(token).replace(/~/g, '~0').replace(/\//g, '~1'))
      .join('/')}`;
  }

  function pointerIsOperation(pointer) {
    if (!pointer.found || !isRecord(pointer.value) || !isRecord(pointer.value.responses)) {
      return false;
    }
    const operationLocation = (tokens) => {
      const rawMethod = tokens.at(-1) || '';
      const additionalMethod = documentVersion === '3.2'
        && tokens.at(-2) === 'additionalOperations'
        && rawMethod.length <= MAX_HTTP_METHOD_LENGTH
        && HTTP_METHOD_TOKEN_RE.test(rawMethod)
        && !FIXED_HTTP_WIRE_METHODS.has(rawMethod.toUpperCase());
      const fixedMethod = HTTP_METHODS.has(rawMethod)
        && (rawMethod !== 'query' || documentVersion === '3.2');
      if (!fixedMethod && !additionalMethod) return false;
      return pathItemLocation(tokens.slice(0, additionalMethod ? -2 : -1));
    };
    const pathItemLocation = (tokens) => {
      if (tokens.length === 2 && tokens[0] === 'paths') return true;
      if (tokens.length === 2
        && tokens[0] === 'webhooks'
        && ['3.1', '3.2'].includes(documentVersion)) return true;
      if (tokens.length === 3
        && tokens[0] === 'components'
        && tokens[1] === 'pathItems'
        && ['3.1', '3.2'].includes(documentVersion)) return true;
      if (tokens.length === 4
        && tokens[0] === 'components'
        && tokens[1] === 'callbacks'
        && documentVersion !== '2.0') return true;
      const callbackIndex = tokens.length - 3;
      return callbackIndex > 0
        && tokens[callbackIndex] === 'callbacks'
        && operationLocation(tokens.slice(0, callbackIndex));
    };
    return operationLocation(pointer.tokens.map(String));
  }

  function setReferenceMetadata(owner, propertyKey, identity, resolvedTarget = undefined) {
    if (!owner || typeof owner !== 'object') return;
    let identities = semanticReferenceIdentities.get(owner);
    if (!identities) {
      identities = new Map();
      semanticReferenceIdentities.set(owner, identities);
    }
    identities.set(String(propertyKey), identity);
    if (resolvedTarget !== undefined) {
      let targets = resolvedReferenceTargets.get(owner);
      if (!targets) {
        targets = new Map();
        resolvedReferenceTargets.set(owner, targets);
      }
      targets.set(String(propertyKey), resolvedTarget);
    }
  }

  visit(doc, 0, false, documentBase, false, '', [], 'document');
  throwIfAbortedOrDeadline(signal, deadlineAt);
  let unresolvedInternalReferences = 0;
  for (let referenceIndex = 0;
    referenceIndex < recordedReferences.length;
    referenceIndex += 1) {
    if ((referenceIndex & 63) === 0) {
      throwIfAbortedOrDeadline(signal, deadlineAt);
    }
    const {
      reference,
      key,
      base,
      owner,
      propertyKey,
      expectedKind,
    } = recordedReferences[referenceIndex];
    let target;
    try {
      target = new URL(reference, base);
    } catch {
      const invalidIdentity = `invalid:${redactAutoText(reference, process.env, { cloud: false })}`;
      externalReferences.add(invalidIdentity);
      referenceIdentities.add(`${key}:${invalidIdentity}`);
      setReferenceMetadata(owner, propertyKey, `${key}:${invalidIdentity}`);
      continue;
    }
    const resource = resourceRoots.get(resourceKey(target));
    if (!resource) {
      let canonicalFragment = '';
      if (target.hash) {
        const rawFragment = target.hash.slice(1);
        try {
          const decoded = decodeURIComponent(rawFragment);
          if (decoded.startsWith('/') && !/~(?:[^01]|$)/.test(decoded)) {
            canonicalFragment = `#${canonicalPointer(decoded.slice(1).split('/').map(decodePointerToken))}`;
          } else {
            canonicalFragment = `#${decoded}`;
          }
        } catch {
          canonicalFragment = target.hash;
        }
      }
      const publicIdentity = redactAutoText(
        `${resourceKey(target)}${canonicalFragment}`,
        process.env,
        { cloud: false },
      );
      externalReferences.add(publicIdentity);
      referenceIdentities.add(`${key}:${publicIdentity}`);
      setReferenceMetadata(owner, propertyKey, `${key}:${publicIdentity}`);
      continue;
    }
    const resourceLabel = resourceLabels.get(resource) || 'document';
    let resolved = key !== 'operationRef';
    let resolvedTarget = resource;
    let resolvedPointerTokens = [];
    let canonicalTarget = `internal:${resourceLabel}`;
    if (target.hash) {
      const fragment = target.hash.slice(1);
      resolved = false;
      resolvedTarget = undefined;
      if (fragment.startsWith('/') || /^%2f/i.test(fragment)) {
        const pointer = pointerTarget(resource, fragment);
        if (pointer.pointer != null) {
          canonicalTarget = `internal:${resourceLabel}#${canonicalPointer(pointer.tokens)}`;
        } else {
          canonicalTarget = `internal:${resourceLabel}#invalid-pointer`;
        }
        resolved = key === 'operationRef' ? pointerIsOperation(pointer) : pointer.found;
        if (resolved) {
          resolvedTarget = pointer.value;
          resolvedPointerTokens = pointer.tokens;
        }
      } else {
        let decodedAnchor;
        try {
          decodedAnchor = decodeURIComponent(fragment);
        } catch {
          decodedAnchor = '';
        }
        canonicalTarget = `internal:${resourceLabel}#${decodedAnchor || 'invalid-anchor'}`;
        resolved = key !== 'operationRef'
          && Boolean(decodedAnchor)
          && knownAnchors.has(`${resourceKey(target)}#${decodedAnchor}`);
        if (resolved) resolvedTarget = knownAnchors.get(
          `${resourceKey(target)}#${decodedAnchor}`,
        )?.value;
      }
    }
    if (resolved && expectedKind && key !== 'operationRef') {
      const targetKindMatches = targetHasReferenceKind(
        resolvedTarget,
        target,
        resolvedPointerTokens,
        expectedKind,
      );
      if (!targetKindMatches) {
        coverageIssues.add('reference_target_type_mismatch');
        resolved = false;
      }
    }
    const semanticIdentity = `${key}:${canonicalTarget}`;
    referenceIdentities.add(semanticIdentity);
    setReferenceMetadata(
      owner,
      propertyKey,
      semanticIdentity,
      resolved ? resolvedTarget : UNRESOLVED_REFERENCE_TARGET,
    );
    if (!resolved) unresolvedInternalReferences += 1;
  }
  const unresolvedExternalReferences = externalReferences.size;
  const issueCodes = [...coverageIssues];
  if (unresolvedExternalReferences > 0) issueCodes.push('external_references_unresolved');
  if (unresolvedInternalReferences > 0) issueCodes.push('internal_references_unresolved');
  if (scanTruncated) issueCodes.push('reference_scan_limit');
  issueCodes.sort(compareOrdinal);
  const coverage = {
    mode: 'detect_only_v1',
    status: issueCodes.length ? 'partial' : 'complete',
    referencesSeen: Math.min(referencesSeen, MAX_REFERENCES_PER_DOCUMENT),
    externalReferences: unresolvedExternalReferences,
    unresolvedExternalReferences,
    unresolvedInternalReferences,
    referenceSetHash: `sha256:${sha256(stableJson([...referenceIdentities].sort(compareOrdinal)))}`,
    issueCodes,
  };
  Object.defineProperties(coverage, {
    documentBaseIdentity: { value: resourceSemanticIdentity(documentBase) },
    semanticReferenceIdentities: { value: semanticReferenceIdentities },
    resolvedReferenceTargets: { value: resolvedReferenceTargets },
  });
  return coverage;
}

function childObjectKindForMap(mapKind) {
  if (mapKind === 'additionalOperations') return 'operation';
  if (mapKind === 'parameters') return 'parameter';
  if (mapKind === 'requestBodies') return 'requestBody';
  if (mapKind === 'responses') return 'response';
  if (mapKind === 'headers') return 'header';
  if (mapKind === 'encoding') return 'encoding';
  if (mapKind === 'callbackExpressions') return 'pathItem';
  if (['schemas', 'definitions', '$defs', 'properties', 'patternProperties', 'dependentSchemas'].includes(mapKind)) {
    return 'schema';
  }
  return 'generic';
}

function semanticValue(
  value,
  state,
  parentKey = '',
  depth = 0,
  context = { mode: 'keyword-object', mapKind: '', objectKind: 'generic', caseInsensitiveNames: false },
) {
  state.nodes += 1;
  if ((state.nodes & 255) === 0) {
    throwIfAbortedOrDeadline(state.signal, state.deadlineAt);
  }
  if (state.nodes > MAX_CANONICAL_NODES) {
    throw formatError('API_CONTRACT_NODE_LIMIT', 'contrato excede o orçamento semântico');
  }
  if (depth > MAX_CANONICAL_DEPTH) {
    throw formatError('API_CONTRACT_DEPTH_LIMIT', 'contrato excede a profundidade permitida');
  }
  if (value == null || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw formatError('API_CONTRACT_INVALID_NUMBER', 'número não finito no contrato');
    return value;
  }
  if (typeof value === 'string') {
    return boundedString(value, parentKey || 'valor', MAX_TEXT_LENGTH, { redactSensitive: true });
  }
  if (Array.isArray(value)) {
    if (value.length > MAX_COLLECTION_ITEMS) {
      throw formatError('API_CONTRACT_COLLECTION_LIMIT', `${parentKey || 'lista'} excede o limite`);
    }
    const list = value.map((item) => semanticValue(
      item,
      state,
      parentKey,
      depth + 1,
      context,
    ));
    if (UNORDERED_ARRAY_KEYS.has(parentKey)) {
      list.sort((a, b) => compareOrdinal(stableJson(a), stableJson(b)));
    }
    return list;
  }
  if (!isRecord(value)) throw formatError('API_CONTRACT_INVALID_VALUE', 'valor semântico inválido');
  const mapKeysAreContractNames = context.mode === 'name-map';
  const entries = boundedRecordEntries(value, parentKey || 'objeto', MAX_COLLECTION_ITEMS)
    .filter(([key, item]) => {
      if (context.objectKind === 'schema'
        && !mapKeysAreContractNames
        && !schemaSemanticKeysFor(state.documentVersion).has(key)
        && !key.startsWith('x-')) return false;
      if (context.objectKind !== 'header') return true;
      if (['3.0', '3.1', '3.2'].includes(state.documentVersion)) {
        if (['required', 'deprecated'].includes(key) && item === false) return false;
        const schemaBranch = Object.hasOwn(value, 'schema');
        if (schemaBranch && key === 'style' && item === 'simple') return false;
        if (schemaBranch && key === 'explode' && item === false) return false;
      }
      if (state.documentVersion === '2.0'
        && key === 'collectionFormat'
        && item === 'csv'
        && value.type === 'array') return false;
      return true;
    })
    .filter(([key, item]) => {
      if (context.objectKind === 'requestBody') {
        return !(key === 'required' && item === false);
      }
      if (context.objectKind !== 'parameter') return true;
      if (['required', 'deprecated', 'allowEmptyValue', 'allowReserved'].includes(key)
        && item === false) return false;
      const location = String(value.in || '').toLowerCase();
      if (['3.0', '3.1', '3.2'].includes(state.documentVersion)) {
        const defaultStyle = ['query', 'querystring', 'cookie'].includes(location)
          ? 'form'
          : ['path', 'header'].includes(location)
            ? 'simple'
            : null;
        const effectiveStyle = typeof value.style === 'string'
          ? value.style
          : defaultStyle;
        if (defaultStyle && key === 'style' && item === defaultStyle) return false;
        if (defaultStyle && key === 'explode' && item === (effectiveStyle === 'form')) {
          return false;
        }
      }
      if (state.documentVersion === '2.0'
        && ['query', 'formdata'].includes(location)
        && key === 'collectionFormat'
        && item === 'csv') return false;
      return true;
    })
    .filter(([key, item]) => !(context.mode === 'keyword-object'
      && context.objectKind === 'response'
      && key === 'headers'
      && isRecord(item)
      && Object.keys(item).every((name) => name.toLowerCase() === 'content-type')))
    .filter(([key]) => mapKeysAreContractNames || (!ANNOTATION_KEYS.has(key) && !key.startsWith('x-')))
    .filter(([key]) => !(mapKeysAreContractNames
      && context.mapKind === 'headers'
      && context.objectKind === 'response'
      && key.toLowerCase() === 'content-type'))
    .map(([key, item]) => {
      const referenceIdentity = state.semanticReferenceIdentities?.get(value)?.get(key);
      const normalizedItem = context.objectKind === 'schema'
        && key === '$schema'
        && typeof item === 'string'
        ? normalizedSchemaDialect(item) || item
        : item;
      return [
        context.caseInsensitiveNames
          ? boundedString(key, `${parentKey}.key`, MAX_NAME_LENGTH, { allowEmpty: false, redactSensitive: true }).toLowerCase()
          : boundedString(key, `${parentKey}.key`, MAX_NAME_LENGTH, { allowEmpty: false, redactSensitive: true }),
        referenceIdentity ?? normalizedItem,
      ];
    })
    .sort(([a], [b]) => compareOrdinal(a, b));
  if (new Set(entries.map(([key]) => key)).size !== entries.length) {
    throw formatError('API_CONTRACT_DUPLICATE_NAME', `${parentKey} contém nomes canônicos duplicados`);
  }
  const out = Object.create(null);
  for (const [key, item] of entries) {
    let childContext;
    if (mapKeysAreContractNames) {
      childContext = context.mapKind === 'callbacks'
        ? { mode: 'name-map', mapKind: 'callbackExpressions', objectKind: 'generic', caseInsensitiveNames: false }
        : {
            mode: 'keyword-object',
            mapKind: '',
            objectKind: childObjectKindForMap(context.mapKind),
            caseInsensitiveNames: false,
          };
    } else if (SEMANTIC_MAP_KEYS.has(key)) {
      childContext = {
        mode: 'name-map',
        mapKind: key,
        objectKind: key === 'headers' ? context.objectKind : 'generic',
        caseInsensitiveNames: key === 'headers'
          && ['response', 'encoding'].includes(context.objectKind),
      };
    } else {
      let childObjectKind = 'generic';
      if (context.objectKind === 'pathItem' && HTTP_METHODS.has(key)) {
        childObjectKind = 'operation';
      } else if (context.objectKind === 'schema'
        && schemaChildKeysFor(state.documentVersion).has(key)) {
        childObjectKind = 'schema';
      }
      childContext = {
        mode: 'keyword-object',
        mapKind: '',
        objectKind: childObjectKind,
        caseInsensitiveNames: false,
      };
    }
    out[key] = semanticValue(item, state, key, depth + 1, childContext);
  }
  return out;
}

function semanticFingerprint(value, state, field, { objectKind = 'generic' } = {}) {
  if (value == null) return null;
  return `sha256:${sha256(stableJson(semanticValue(
    value,
    state,
    field,
    0,
    { mode: 'keyword-object', mapKind: '', objectKind, caseInsensitiveNames: false },
  )))}`;
}

function decodePointerToken(token) {
  return token.replace(/~1/g, '/').replace(/~0/g, '~');
}

function resolveLocalRef(doc, value, resolvedReferenceTargets = null) {
  let current = value;
  const seen = new Set();
  for (let depth = 0; depth < 8; depth += 1) {
    if (!isRecord(current) || typeof current.$ref !== 'string') return current;
    const mappedTargets = resolvedReferenceTargets?.get(current);
    if (mappedTargets?.has('$ref')) {
      if (seen.has(current)) throw formatError('API_CONTRACT_REF_CYCLE', 'ciclo de referência local');
      seen.add(current);
      const mappedTarget = mappedTargets.get('$ref');
      if (mappedTarget === UNRESOLVED_REFERENCE_TARGET) return current;
      current = mappedTarget;
      continue;
    }
    const ref = boundedString(current.$ref, '$ref', MAX_TEXT_LENGTH, { allowEmpty: false });
    if (!ref.startsWith('#/')) return current;
    if (seen.has(ref)) throw formatError('API_CONTRACT_REF_CYCLE', 'ciclo de referência local');
    seen.add(ref);
    const tokens = ref.slice(2).split('/').map(decodePointerToken);
    let next = doc;
    for (const token of tokens) {
      if (!isRecord(next) || !Object.hasOwn(next, token)) return current;
      next = next[token];
    }
    current = next;
  }
  throw formatError('API_CONTRACT_REF_DEPTH', 'cadeia de referência local excede o limite');
}

function normalizeStringList(
  value,
  field,
  maxItems,
  { lower = false, redactSensitive = false } = {},
) {
  const input = value == null ? [] : boundedArray(value, field, maxItems);
  return [...new Set(input.map((item, index) => {
    const text = boundedString(item, `${field}[${index}]`, MAX_NAME_LENGTH, {
      allowEmpty: false,
      redactSensitive,
    });
    return lower ? text.toLowerCase() : text;
  }))].sort();
}

function normalizeSecurityRequirements(value, field = 'security', { redactSensitive = false } = {}) {
  if (value == null) return [];
  const alternatives = boundedArray(value, field, MAX_SECURITY_ALTERNATIVES);
  const normalized = alternatives.map((requirement, index) => {
    const entries = boundedRecordEntries(
      requirement,
      `${field}[${index}]`,
      MAX_SECURITY_SCHEMES_PER_ALTERNATIVE,
    ).map(([name, scopes]) => {
      const safeName = boundedString(name, `${field}.scheme`, MAX_NAME_LENGTH, {
        allowEmpty: false,
        redactSensitive,
      });
      const safeScopes = normalizeStringList(
        scopes,
        `${field}.${safeName}`,
        MAX_SECURITY_SCOPES,
        { redactSensitive },
      );
      return `${safeName}(${safeScopes.join(',')})`;
    }).sort();
    return entries.join('&');
  });
  return [...new Set(normalized)].sort();
}

function securityIsRequired(requirements) {
  return requirements.length > 0 && !requirements.includes('');
}

function getDocumentVersion(doc) {
  const openapi = boundedString(doc?.openapi, 'openapi', MAX_NAME_LENGTH);
  const swagger = boundedString(doc?.swagger, 'swagger', MAX_NAME_LENGTH);
  if (/^3\.(?:0|1|2)(?:\.\d+)?(?:[-+].*)?$/.test(openapi)) return openapi;
  if (swagger === '2.0') return swagger;
  throw formatError(
    'API_CONTRACT_UNSUPPORTED_VERSION',
    'apenas OpenAPI 3.0–3.2 e Swagger 2.0 são aceitos',
  );
}

function canonicalDocumentVersion(version) {
  if (version === '2.0') return version;
  const match = String(version).match(/^(3\.(?:0|1|2))/);
  return match?.[1] || version;
}

function normalizeSummaryDocumentVersions(versionInput, sourceVersionInput) {
  const version = boundedString(
    versionInput,
    'version',
    MAX_NAME_LENGTH,
    { allowEmpty: false },
  );
  const sourceDocumentVersion = boundedString(
    sourceVersionInput,
    'sourceDocumentVersion',
    MAX_NAME_LENGTH,
    { allowEmpty: false },
  );
  if (!SUPPORTED_DOCUMENT_VERSIONS.has(version)) {
    throw formatError(
      'API_CONTRACT_INCONSISTENT_VERSION',
      'versão canônica do snapshot não é suportada',
    );
  }
  let detectedSourceVersion;
  try {
    detectedSourceVersion = getDocumentVersion(sourceDocumentVersion === '2.0'
      ? { swagger: sourceDocumentVersion }
      : { openapi: sourceDocumentVersion });
  } catch {
    throw formatError(
      'API_CONTRACT_INCONSISTENT_VERSION',
      'versão original do documento não é suportada',
    );
  }
  if (canonicalDocumentVersion(detectedSourceVersion) !== version) {
    throw formatError(
      'API_CONTRACT_INCONSISTENT_VERSION',
      'versão canônica diverge da versão original do documento',
    );
  }
  return { version, sourceDocumentVersion };
}

function securitySchemeFingerprintSource(definition, type, location, safeName) {
  let source = { ...definition, type };
  if (location) source.in = location;
  if (type === 'http') {
    source.scheme = boundedString(
      definition.scheme,
      `${safeName}.scheme`,
      MAX_NAME_LENGTH,
      { redactSensitive: true },
    ).toLowerCase();
    // `bearerFormat` é somente dica documental para o cliente.
    delete source.bearerFormat;
  }
  if (type === 'apikey' && location === 'header') {
    source = {
      ...source,
      name: boundedString(
        definition.name,
        `${safeName}.name`,
        MAX_NAME_LENGTH,
        { allowEmpty: false },
      ).toLowerCase(),
    };
  }
  if (type === 'oauth2' && isRecord(definition.flows)) {
    source = {
      ...source,
      flows: Object.fromEntries(Object.entries(definition.flows).map(([flowName, flow]) => {
        if (!isRecord(flow) || !isRecord(flow.scopes)) return [flowName, flow];
        return [flowName, {
          ...flow,
          // O texto de descrição do scope é anotativo; os nomes são contratuais.
          scopes: Object.fromEntries(Object.keys(flow.scopes).sort().map((scope) => [scope, null])),
        }];
      })),
    };
  }
  if (type === 'oauth2' && isRecord(definition.scopes)) {
    source = {
      ...source,
      // Swagger 2 também usa descrições apenas documentais para cada scope.
      scopes: Object.fromEntries(Object.keys(definition.scopes).sort().map((scope) => [scope, null])),
    };
  }
  return source;
}

function omitDefaultFalseFields(value, fields) {
  const out = { ...value };
  for (const field of fields) {
    if (out[field] !== true) delete out[field];
  }
  return out;
}

function getSecuritySchemes(doc, semanticState) {
  const source = isRecord(doc?.components?.securitySchemes)
    ? doc.components.securitySchemes
    : isRecord(doc?.securityDefinitions)
      ? doc.securityDefinitions
      : {};
  return boundedRecordEntries(source, 'securitySchemes', MAX_SECURITY_SCHEMES)
    .map(([name, rawDefinition]) => {
      const safeName = boundedString(name, 'securitySchemes.name', MAX_NAME_LENGTH, {
        allowEmpty: false,
        redactSensitive: true,
      });
      const definition = resolveLocalRef(doc, rawDefinition, semanticState.resolvedReferenceTargets);
      if (!isRecord(definition)) {
        throw formatError('API_CONTRACT_INVALID_SECURITY_SCHEME', `security scheme ${safeName} inválido`);
      }
      const type = boundedString(definition.type, `${safeName}.type`, MAX_NAME_LENGTH, {
        redactSensitive: true,
      }).toLowerCase();
      const location = boundedString(definition.in, `${safeName}.in`, MAX_NAME_LENGTH, {
        redactSensitive: true,
      }).toLowerCase();
      const fingerprintSource = securitySchemeFingerprintSource(
        definition,
        type,
        location,
        safeName,
      );
      return {
        name: safeName,
        type,
        scheme: boundedString(definition.scheme, `${safeName}.scheme`, MAX_NAME_LENGTH, {
          redactSensitive: true,
        }).toLowerCase(),
        in: location,
        fingerprint: semanticFingerprint(fingerprintSource, semanticState, `securitySchemes.${safeName}`),
      };
    })
    .sort((a, b) => compareOrdinal(a.name, b.name));
}

function summarizeParameter(doc, rawParameter, semanticState, field) {
  const resolved = resolveLocalRef(doc, rawParameter, semanticState.resolvedReferenceTargets);
  if (!isRecord(resolved)) throw formatError('API_CONTRACT_INVALID_PARAMETER', `${field} inválido`);
  if (!resolved.name || !resolved.in) {
    const ref = typeof rawParameter?.$ref === 'string' ? rawParameter.$ref : '';
    if (!ref) throw formatError('API_CONTRACT_INVALID_PARAMETER', `${field} sem name/in`);
    return {
      key: `ref:${sha256(ref).slice(0, 20)}`,
      signature: semanticFingerprint(rawParameter, semanticState, field),
    };
  }
  const name = boundedString(resolved.name, `${field}.name`, MAX_NAME_LENGTH, {
    allowEmpty: false,
    redactSensitive: true,
  });
  const location = boundedString(resolved.in, `${field}.in`, 32, {
    allowEmpty: false,
    redactSensitive: true,
  }).toLowerCase();
  const canonicalName = location === 'header'
    ? name.toLowerCase()
    : ['body', 'querystring'].includes(location)
      ? ''
      : name;
  if (location === 'header' && IGNORED_HEADER_PARAMETERS.has(canonicalName)) return null;
  const fingerprintSource = omitDefaultFalseFields(
    { ...resolved, in: location },
    ['required', 'deprecated', 'allowEmptyValue', 'allowReserved'],
  );
  const documentVersion = canonicalDocumentVersion(getDocumentVersion(doc));
  if (!documentVersion.startsWith('2.')) {
    const defaultStyle = ['query', 'querystring', 'cookie'].includes(location)
      ? 'form'
      : ['path', 'header'].includes(location)
        ? 'simple'
        : null;
    const effectiveStyle = typeof resolved.style === 'string'
      ? resolved.style
      : defaultStyle;
    if (defaultStyle && (resolved.style == null || resolved.style === defaultStyle)) {
      delete fingerprintSource.style;
    }
    const defaultExplode = effectiveStyle === 'form';
    if (defaultStyle
      && (resolved.explode == null || resolved.explode === defaultExplode)) {
      delete fingerprintSource.explode;
    }
  } else if (['query', 'formdata'].includes(location)
    && (resolved.collectionFormat == null || resolved.collectionFormat === 'csv')) {
    delete fingerprintSource.collectionFormat;
  }
  if (['body', 'querystring'].includes(location)) delete fingerprintSource.name;
  else fingerprintSource.name = canonicalName;
  return {
    key: `${location}:${canonicalName}`,
    signature: semanticFingerprint(fingerprintSource, semanticState, field),
  };
}

function parameterMap(doc, rawParameters, semanticState, field) {
  if (rawParameters == null) return new Map();
  const parameters = boundedArray(rawParameters, field, MAX_PARAMETERS_PER_CONTAINER);
  const out = new Map();
  for (let index = 0; index < parameters.length; index += 1) {
    const item = summarizeParameter(doc, parameters[index], semanticState, `${field}[${index}]`);
    if (!item) continue;
    if (out.has(item.key)) {
      throw formatError('API_CONTRACT_DUPLICATE_PARAMETER', `${field} contém parâmetro duplicado`);
    }
    out.set(item.key, item);
  }
  return out;
}

function canonicalResponseHeaders(value, field) {
  if (value == null) return value;
  const out = Object.create(null);
  for (const [rawName, definition] of boundedRecordEntries(value, field, MAX_COLLECTION_ITEMS)) {
    const name = boundedString(rawName, `${field}.name`, MAX_NAME_LENGTH, { allowEmpty: false }).toLowerCase();
    if (name === 'content-type') continue;
    if (Object.hasOwn(out, name)) {
      throw formatError('API_CONTRACT_DUPLICATE_HEADER', `${field} contém header duplicado`);
    }
    out[name] = definition;
  }
  return out;
}

function responseFingerprintSource(response, field) {
  if (!Object.hasOwn(response, 'headers')) return response;
  const headers = canonicalResponseHeaders(response.headers, `${field}.headers`);
  if (Object.keys(headers).length === 0) {
    const { headers: _ignored, ...withoutHeaders } = response;
    return withoutHeaders;
  }
  return {
    ...response,
    headers,
  };
}

function summarizeResponses(doc, value, semanticState, field) {
  if (value == null) return [];
  const seenCodes = new Set();
  return boundedRecordEntries(value, field, MAX_RESPONSES_PER_OPERATION)
    .map(([rawCode, rawResponse]) => {
      const code = boundedString(rawCode, `${field}.code`, 16, { allowEmpty: false }).toUpperCase();
      if (!RESPONSE_CODE_RE.test(code)) {
        throw formatError('API_CONTRACT_INVALID_RESPONSE_CODE', `${field} contém status inválido`);
      }
      if (seenCodes.has(code)) {
        throw formatError('API_CONTRACT_DUPLICATE_RESPONSE', `${field} contém status duplicado`);
      }
      seenCodes.add(code);
      const resolved = resolveLocalRef(doc, rawResponse, semanticState.resolvedReferenceTargets);
      if (!isRecord(resolved)) {
        throw formatError('API_CONTRACT_INVALID_RESPONSE', `${field}.${code} deve ser objeto ou referência`);
      }
      return {
        code,
        signature: semanticFingerprint(
          responseFingerprintSource(resolved, `${field}.${code}`),
          semanticState,
          `${field}.${code}`,
          { objectKind: 'response' },
        ),
      };
    })
    .sort((a, b) => compareOrdinal(a.code, b.code));
}

function operationIdentity(surface, surfaceKey, method, preserveMethodCase = false) {
  const rawMethod = String(method);
  const displayMethod = preserveMethodCase ? rawMethod : rawMethod.toUpperCase();
  return surface === 'webhook'
    ? `WEBHOOK ${displayMethod} ${JSON.stringify(surfaceKey)}`
    : `${displayMethod} ${surfaceKey}`;
}

function summarizeOperation(
  doc,
  surfaceKey,
  pathItem,
  method,
  operation,
  globalSecurity,
  semanticState,
  surface = 'path',
  preserveMethodCase = false,
) {
  const operationId = operationIdentity(surface, surfaceKey, method, preserveMethodCase);
  const pathMap = parameterMap(doc, pathItem.parameters, semanticState, `${surfaceKey}.parameters`);
  const operationMap = parameterMap(doc, operation.parameters, semanticState, `${operationId}.parameters`);
  for (const [key, detail] of operationMap) pathMap.set(key, detail);
  const parameterDetails = [...pathMap.values()].sort((a, b) => compareOrdinal(a.key, b.key));
  const securityRequirements = Object.hasOwn(operation, 'security')
    ? normalizeSecurityRequirements(
        operation.security,
        `${operationId}.security`,
        { redactSensitive: true },
      )
    : globalSecurity;
  const responseDetails = summarizeResponses(
    doc,
    operation.responses || {},
    semanticState,
    `${operationId}.responses`,
  );
  const bodyParameter = [...pathMap.values()].find((item) => item.key.startsWith('body:')) || null;
  const rawRequestBody = Object.hasOwn(operation, 'requestBody')
    ? resolveLocalRef(doc, operation.requestBody, semanticState.resolvedReferenceTargets)
    : null;
  if (rawRequestBody != null && !isRecord(rawRequestBody)) {
    throw formatError('API_CONTRACT_INVALID_REQUEST_BODY', `${operationId}.requestBody inválido`);
  }
  const requestBody = Boolean(rawRequestBody || bodyParameter);
  const requestBodySignature = rawRequestBody
    ? semanticFingerprint(
        omitDefaultFalseFields(rawRequestBody, ['required']),
        semanticState,
        `${operationId}.requestBody`,
      )
    : bodyParameter?.signature || null;
  const tags = normalizeStringList(
    operation.tags,
    `${operationId}.tags`,
    MAX_TAGS_PER_OPERATION,
    { redactSensitive: true },
  );
  const residualOperation = Object.fromEntries(
    Object.entries(operation).filter(([key]) => !EXPLICIT_OPERATION_KEYS.has(key)),
  );
  const semanticSignature = semanticFingerprint({
    operation: residualOperation,
    pathServers: pathItem.servers || null,
  }, semanticState, operationId);

  return {
    id: operationId,
    surface,
    method: preserveMethodCase ? method : method.toUpperCase(),
    route: surfaceKey,
    operationId: boundedString(operation.operationId, `${operationId}.operationId`, MAX_NAME_LENGTH, {
      redactSensitive: true,
    }),
    tags,
    params: parameterDetails.map((item) => item.key),
    parameterSignatures: parameterDetails,
    requestBody,
    requestBodySignature,
    responses: responseDetails.map((item) => item.code),
    responseSignatures: responseDetails,
    hasSecurity: securityIsRequired(securityRequirements),
    securityRequirements,
    deprecated: operation.deprecated === true,
    semanticSignature,
  };
}

function appendSurfaceOperations({
  doc,
  entries,
  surface,
  globalSecurity,
  semanticState,
  operations,
  params,
  signal,
  allowQuery = false,
  allowAdditional = false,
}) {
  for (const [rawSurfaceKey, rawPathItem] of entries) {
    throwIfAbortedOrDeadline(signal, semanticState.deadlineAt);
    const surfaceKey = boundedString(
      rawSurfaceKey,
      `${surface}.key`,
      MAX_TEXT_LENGTH,
      { allowEmpty: false, redactSensitive: true },
    );
    if (surface === 'path' && !surfaceKey.startsWith('/')) {
      throw formatError('API_CONTRACT_INVALID_PATH', 'path OpenAPI deve iniciar com /');
    }
    const pathItem = resolveLocalRef(doc, rawPathItem, semanticState.resolvedReferenceTargets);
    if (!isRecord(pathItem)) {
      throw formatError('API_CONTRACT_INVALID_PATH_ITEM', `${surfaceKey} inválido`);
    }
    const seenMethods = new Set();
    for (const [methodRaw, operation] of Object.entries(pathItem)) {
      const method = String(methodRaw);
      if (!HTTP_METHODS.has(method)) continue;
      if (method === 'query' && !allowQuery) continue;
      const canonicalMethod = method.toUpperCase();
      if (seenMethods.has(canonicalMethod)) {
        throw formatError(
          'API_CONTRACT_DUPLICATE_OPERATION',
          `${operationIdentity(surface, surfaceKey, method)} duplicado`,
        );
      }
      seenMethods.add(canonicalMethod);
      if (!isRecord(operation)) {
        throw formatError(
          'API_CONTRACT_INVALID_OPERATION',
          `${operationIdentity(surface, surfaceKey, method)} inválido`,
        );
      }
      if (operations.length >= MAX_OPERATIONS) {
        throw formatError('API_CONTRACT_OPERATION_LIMIT', 'contrato excede o limite de operações');
      }
      const summary = summarizeOperation(
        doc,
        surfaceKey,
        pathItem,
        method,
        operation,
        globalSecurity,
        semanticState,
        surface,
      );
      for (const item of summary.params) params.add(item);
      operations.push(summary);
    }
    if (allowAdditional && pathItem.additionalOperations != null) {
      for (const [rawMethod, operation] of boundedRecordEntries(
        pathItem.additionalOperations,
        `${surfaceKey}.additionalOperations`,
        MAX_ADDITIONAL_OPERATIONS,
      )) {
        const method = boundedString(
          rawMethod,
          `${surfaceKey}.additionalOperations.method`,
          MAX_HTTP_METHOD_LENGTH,
          { allowEmpty: false },
        );
        const canonicalMethod = method;
        if (!HTTP_METHOD_TOKEN_RE.test(method)
          || FIXED_HTTP_WIRE_METHODS.has(method)
          || seenMethods.has(canonicalMethod)) {
          throw formatError(
            'API_CONTRACT_DUPLICATE_OPERATION',
            `${operationIdentity(surface, surfaceKey, method, true)} inválido ou duplicado`,
          );
        }
        if (!isRecord(operation)) {
          throw formatError(
            'API_CONTRACT_INVALID_OPERATION',
            `${operationIdentity(surface, surfaceKey, method, true)} inválido`,
          );
        }
        if (operations.length >= MAX_OPERATIONS) {
          throw formatError('API_CONTRACT_OPERATION_LIMIT', 'contrato excede o limite de operações');
        }
        seenMethods.add(canonicalMethod);
        const summary = summarizeOperation(
          doc,
          surfaceKey,
          pathItem,
          method,
          operation,
          globalSecurity,
          semanticState,
          surface,
          true,
        );
        for (const item of summary.params) params.add(item);
        operations.push(summary);
      }
    }
  }
}

function surfaceItemsSignature(doc, entries, semanticState, surface, version) {
  const items = [];
  const seenKeys = new Set();
  const supportsPathServers = version !== '2.0';

  for (const [rawSurfaceKey, rawPathItem] of entries) {
    throwIfAbortedOrDeadline(semanticState.signal, semanticState.deadlineAt);
    const surfaceKey = boundedString(
      rawSurfaceKey,
      `${surface}.key`,
      MAX_TEXT_LENGTH,
      { allowEmpty: false, redactSensitive: true },
    );
    if (seenKeys.has(surfaceKey)) {
      throw formatError('API_CONTRACT_DUPLICATE_NAME', `${surface} contém nomes canônicos duplicados`);
    }
    seenKeys.add(surfaceKey);

    const pathItem = resolveLocalRef(doc, rawPathItem, semanticState.resolvedReferenceTargets);
    if (!isRecord(pathItem)) {
      throw formatError('API_CONTRACT_INVALID_PATH_ITEM', `${surfaceKey} inválido`);
    }
    const parameterSignatures = [...parameterMap(
      doc,
      pathItem.parameters,
      semanticState,
      `${surfaceKey}.parameters`,
    ).values()].sort((left, right) => compareOrdinal(left.key, right.key));
    const unresolvedReference = typeof pathItem.$ref === 'string'
      ? boundedString(pathItem.$ref, `${surfaceKey}.$ref`, MAX_TEXT_LENGTH, {
          allowEmpty: false,
          redactSensitive: true,
        })
      : null;
    const signature = semanticFingerprint({
      unresolvedReference,
      parameterSignatures,
      pathServers: supportsPathServers ? pathItem.servers || null : null,
    }, semanticState, `${surface}.${surfaceKey}`, { objectKind: 'pathItem' });
    items.push({ key: surfaceKey, signature });
  }

  items.sort((left, right) => compareOrdinal(left.key, right.key));
  return `sha256:${sha256(stableJson(items))}`;
}

function summaryHashPayload(summary) {
  const payload = {
    schemaVersion: summary.schemaVersion,
    canonicalizationVersion: summary.canonicalizationVersion,
    version: summary.version,
    title: summary.title,
    apiVersion: summary.apiVersion,
    serversSignature: summary.serversSignature,
    componentsSignature: summary.componentsSignature,
    rootContractSignature: summary.rootContractSignature,
    pathItemsSignature: summary.pathItemsSignature,
    webhooksSignature: summary.webhooksSignature,
    pathCount: summary.pathCount,
    webhookCount: summary.webhookCount,
    operationCount: summary.operationCount,
    paramCount: summary.paramCount,
    operationsWithoutSecurity: summary.operationsWithoutSecurity,
    securitySchemes: summary.securitySchemes,
    operations: summary.operations,
  };
  if (summary.canonicalizationVersion === LEGACY_CANONICALIZATION_VERSION) {
    delete payload.rootContractSignature;
    delete payload.pathItemsSignature;
    delete payload.webhooksSignature;
    delete payload.webhookCount;
    payload.operations = summary.operations.map((operation) => {
      const route = operation.route ?? operation.path;
      const {
        surface: _surface,
        route: _route,
        path: _path,
        ...legacyOperation
      } = operation;
      return { ...legacyOperation, path: route };
    });
  }
  if (summary.canonicalizationVersion >= V4_CANONICALIZATION_VERSION) {
    payload.redactionPolicyHash = summary.compatibility.redactionPolicyHash;
  }
  if (summary.canonicalizationVersion >= REFERENCE_COVERAGE_CANONICALIZATION_VERSION) {
    payload.referenceResolution = summary.referenceResolution;
  }
  return payload;
}

function computedSummaryHash(summary) {
  return sha256(stableJson(summaryHashPayload(summary)));
}

export function collectOpenApiSummary(
  doc,
  {
    url = '',
    resolvedUrl = url,
    sourceAliases = [url],
    signal = null,
    deadlineAt = null,
  } = {},
) {
  throwIfAbortedOrDeadline(signal, deadlineAt);
  requireRecord(doc, 'documento OpenAPI');
  const sourceDocumentVersion = getDocumentVersion(doc);
  const version = canonicalDocumentVersion(sourceDocumentVersion);
  const supportsWebhooks = !version.startsWith('2.') && !version.startsWith('3.0');
  if (doc.paths == null && !supportsWebhooks) {
    throw formatError('API_CONTRACT_INVALID_RECORD', 'paths deve ser objeto');
  }
  const pathEntries = boundedRecordEntries(doc.paths || {}, 'paths', MAX_PATHS)
    .filter(([key]) => !String(key).startsWith('x-'));
  const webhookEntries = supportsWebhooks
    ? boundedRecordEntries(doc.webhooks || {}, 'webhooks', MAX_WEBHOOKS)
      .filter(([key]) => !String(key).startsWith('x-'))
    : [];
  if (!pathEntries.length && !webhookEntries.length && !isRecord(doc.components)) {
    throw formatError(
      'API_CONTRACT_EMPTY_DOCUMENT',
      'contrato deve declarar paths, webhooks ou components',
    );
  }
  const referenceResolution = inspectReferenceResolution(
    doc,
    resolvedUrl || url,
    signal,
    deadlineAt,
  );
  const semanticState = {
    nodes: 0,
    signal,
    deadlineAt,
    documentVersion: version,
    semanticReferenceIdentities: referenceResolution.semanticReferenceIdentities,
    resolvedReferenceTargets: referenceResolution.resolvedReferenceTargets,
  };
  const globalSecurity = normalizeSecurityRequirements(
    doc.security,
    'security',
    { redactSensitive: true },
  );
  const securitySchemes = getSecuritySchemes(doc, semanticState);
  const operations = [];
  const params = new Set();

  appendSurfaceOperations({
    doc,
    entries: pathEntries,
    surface: 'path',
    globalSecurity,
    semanticState,
    operations,
    params,
    signal,
    allowQuery: version.startsWith('3.2'),
    allowAdditional: version.startsWith('3.2'),
  });
  appendSurfaceOperations({
    doc,
    entries: webhookEntries,
    surface: 'webhook',
    globalSecurity,
    semanticState,
    operations,
    params,
    signal,
    allowQuery: version.startsWith('3.2'),
    allowAdditional: version.startsWith('3.2'),
  });

  operations.sort((a, b) => compareOrdinal(a.id, b.id));
  throwIfAbortedOrDeadline(signal, deadlineAt);
  const ids = new Set();
  for (const operation of operations) {
    if (ids.has(operation.id)) {
      throw formatError('API_CONTRACT_DUPLICATE_OPERATION', `${operation.id} duplicado`);
    }
    ids.add(operation.id);
  }
  const componentsSource = version === '2.0'
    ? {
        definitions: doc.definitions || {},
        parameters: doc.parameters || {},
        responses: doc.responses || {},
      }
    : Object.fromEntries(
        Object.entries(isRecord(doc.components) ? doc.components : {})
          .filter(([key]) => key !== 'securitySchemes'),
      );
  const serversSource = version === '2.0'
    ? { schemes: doc.schemes || [], host: doc.host || '', basePath: doc.basePath || '' }
    : doc.servers || [];
  const summary = {
    schemaVersion: API_CONTRACT_SNAPSHOT_SCHEMA_VERSION,
    canonicalizationVersion: API_CONTRACT_CANONICALIZATION_VERSION,
    compatibility: {
      sourceSchemaVersion: API_CONTRACT_SNAPSHOT_SCHEMA_VERSION,
      detailLevel: 'full',
      redactionPolicyHash: currentRedactionPolicyHash(),
    },
    url: canonicalContractUrl(url, { allowEmpty: true, redactSensitive: true }),
    resolvedUrl: canonicalContractUrl(resolvedUrl, { allowEmpty: true, redactSensitive: true }),
    sourceAliases: normalizeSourceAliases(sourceAliases, url, { redactSensitive: true }),
    version,
    title: boundedString(doc?.info?.title, 'info.title', MAX_NAME_LENGTH, { redactSensitive: true }),
    apiVersion: boundedString(doc?.info?.version, 'info.version', MAX_NAME_LENGTH, { redactSensitive: true }),
    pathCount: pathEntries.length,
    webhookCount: webhookEntries.length,
    operationCount: operations.length,
    paramCount: params.size,
    securitySchemes,
    operationsWithoutSecurity: operations.filter((operation) => !operation.hasSecurity).length,
    serversSignature: semanticFingerprint(serversSource, semanticState, 'servers'),
    componentsSignature: semanticFingerprint(
      componentsSource,
      semanticState,
      'components',
      { objectKind: 'components' },
    ),
    rootContractSignature: semanticFingerprint(
      version === '2.0'
        ? {
            consumes: doc.consumes || [],
            produces: doc.produces || [],
            security: globalSecurity,
          }
        : {
            $self: Object.hasOwn(doc, '$self')
              ? referenceResolution.documentBaseIdentity
              : '',
            jsonSchemaDialect: typeof doc.jsonSchemaDialect === 'string'
              ? normalizedSchemaDialect(doc.jsonSchemaDialect) || doc.jsonSchemaDialect
              : doc.jsonSchemaDialect || '',
            security: globalSecurity,
          },
      semanticState,
      'rootContract',
    ),
    pathItemsSignature: surfaceItemsSignature(doc, pathEntries, semanticState, 'paths', version),
    webhooksSignature: surfaceItemsSignature(doc, webhookEntries, semanticState, 'webhooks', version),
    operations,
    sourceDocumentVersion,
    referenceResolution,
  };
  summary.hash = computedSummaryHash(summary);
  throwIfAbortedOrDeadline(signal, deadlineAt);
  return summary;
}

function legacySummaryHash(summary) {
  return sha256(stableJson({
    version: summary.version,
    title: summary.title,
    apiVersion: summary.apiVersion,
    securitySchemes: summary.securitySchemes,
    operations: summary.operations,
  }));
}

function normalizeLegacyOperation(value, index) {
  const operation = requireRecord(value, `operations[${index}]`);
  const method = boundedString(
    operation.method,
    `operations[${index}].method`,
    16,
    { allowEmpty: false },
  ).toUpperCase();
  const path = boundedString(operation.path, `operations[${index}].path`, MAX_TEXT_LENGTH, {
    allowEmpty: false,
    redactSensitive: true,
  });
  if (!HTTP_METHODS.has(method.toLowerCase()) || !path.startsWith('/')) {
    throw formatError('API_CONTRACT_INVALID_OPERATION', `operations[${index}] inválida`);
  }
  const id = `${method} ${path}`;
  if (operation.id && operation.id !== id) {
    throw formatError('API_CONTRACT_INVALID_OPERATION', `operations[${index}].id inconsistente`);
  }
  const params = normalizeStringList(
    operation.params,
    `operations[${index}].params`,
    MAX_PARAMETERS_PER_OPERATION,
    { redactSensitive: true },
  );
  const responses = normalizeStringList(operation.responses, `operations[${index}].responses`, MAX_RESPONSES_PER_OPERATION)
    .map((code) => code.toUpperCase());
  return {
    id,
    surface: 'path',
    method,
    route: path,
    operationId: boundedString(
      operation.operationId,
      `operations[${index}].operationId`,
      MAX_NAME_LENGTH,
      { redactSensitive: true },
    ),
    tags: normalizeStringList(
      operation.tags,
      `operations[${index}].tags`,
      MAX_TAGS_PER_OPERATION,
      { redactSensitive: true },
    ),
    params,
    parameterSignatures: [],
    requestBody: operation.requestBody === true,
    requestBodySignature: null,
    responses,
    responseSignatures: [],
    hasSecurity: operation.hasSecurity === true,
    securityRequirements: [],
    deprecated: operation.deprecated === true,
    semanticSignature: null,
  };
}

function migrateV1Summary(input) {
  const legacy = requireRecord(input, 'snapshot v1');
  const hash = boundedString(legacy.hash, 'snapshot v1 hash', 64, { allowEmpty: false });
  if (!/^[a-f0-9]{64}$/i.test(hash) || legacySummaryHash(legacy) !== hash.toLowerCase()) {
    throw formatError('API_CONTRACT_INTEGRITY_MISMATCH', 'hash do snapshot v1 não confere');
  }
  const operations = boundedArray(legacy.operations, 'operations', MAX_OPERATIONS)
    .map(normalizeLegacyOperation)
    .sort((a, b) => compareOrdinal(a.id, b.id));
  const ids = new Set();
  for (const operation of operations) {
    if (ids.has(operation.id)) throw formatError('API_CONTRACT_DUPLICATE_OPERATION', `${operation.id} duplicado`);
    ids.add(operation.id);
  }
  const legacySchemes = boundedArray(legacy.securitySchemes || [], 'securitySchemes', MAX_SECURITY_SCHEMES)
    .map((raw, index) => {
      const scheme = requireRecord(raw, `securitySchemes[${index}]`);
      return {
        name: boundedString(scheme.name, `securitySchemes[${index}].name`, MAX_NAME_LENGTH, {
          allowEmpty: false,
          redactSensitive: true,
        }),
        type: boundedString(scheme.type, `securitySchemes[${index}].type`, MAX_NAME_LENGTH).toLowerCase(),
        scheme: boundedString(scheme.scheme, `securitySchemes[${index}].scheme`, MAX_NAME_LENGTH).toLowerCase(),
        in: boundedString(scheme.in, `securitySchemes[${index}].in`, MAX_NAME_LENGTH).toLowerCase(),
        fingerprint: null,
      };
    })
    .sort((a, b) => compareOrdinal(a.name, b.name));
  const params = new Set(operations.flatMap((operation) => operation.params));
  const legacySourceDocumentVersion = boundedString(
    legacy.version,
    'version',
    MAX_NAME_LENGTH,
    { allowEmpty: false },
  );
  const legacyVersions = normalizeSummaryDocumentVersions(
    canonicalDocumentVersion(legacySourceDocumentVersion),
    legacySourceDocumentVersion,
  );
  const summary = {
    schemaVersion: API_CONTRACT_SNAPSHOT_SCHEMA_VERSION,
    canonicalizationVersion: API_CONTRACT_CANONICALIZATION_VERSION,
    compatibility: {
      sourceSchemaVersion: 1,
      detailLevel: 'legacy_v1',
      lossyFields: [
        'component_schemas',
        'parameter_schemas',
        'response_schemas',
        'security_requirements',
        'servers',
        'path_items',
        'webhooks',
        'reference_resolution',
        'source_aliases',
      ],
      redactionPolicyHash: currentRedactionPolicyHash(),
    },
    url: canonicalContractUrl(legacy.url, { allowEmpty: true, redactSensitive: true }),
    resolvedUrl: canonicalContractUrl(legacy.url, { allowEmpty: true, redactSensitive: true }),
    sourceAliases: normalizeSourceAliases([legacy.url], legacy.url, { redactSensitive: true }),
    version: legacyVersions.version,
    title: boundedString(legacy.title, 'title', MAX_NAME_LENGTH, { redactSensitive: true }),
    apiVersion: boundedString(legacy.apiVersion, 'apiVersion', MAX_NAME_LENGTH, { redactSensitive: true }),
    pathCount: Math.max(0, Math.min(MAX_PATHS, Number(legacy.pathCount) || 0)),
    webhookCount: 0,
    operationCount: operations.length,
    paramCount: params.size,
    securitySchemes: legacySchemes,
    operationsWithoutSecurity: operations.filter((operation) => !operation.hasSecurity).length,
    serversSignature: null,
    componentsSignature: null,
    rootContractSignature: null,
    pathItemsSignature: null,
    webhooksSignature: null,
    operations,
    sourceDocumentVersion: legacyVersions.sourceDocumentVersion,
    referenceResolution: {
      mode: 'detect_only_v1',
      status: 'partial',
      referencesSeen: 0,
      externalReferences: 0,
      unresolvedExternalReferences: 0,
      unresolvedInternalReferences: 0,
      referenceSetHash: `sha256:${sha256(stableJson([]))}`,
      issueCodes: ['legacy_reference_coverage_unknown'],
    },
  };
  summary.hash = computedSummaryHash(summary);
  return summary;
}

function normalizeV2Operation(value, index, detailLevel, canonicalizationVersion) {
  const operation = requireRecord(value, `operations[${index}]`);
  const surface = canonicalizationVersion >= SURFACE_CANONICALIZATION_VERSION
    ? boundedString(operation.surface, `operations[${index}].surface`, 16, { allowEmpty: false })
    : 'path';
  if (!['path', 'webhook'].includes(surface)) {
    throw formatError('API_CONTRACT_INVALID_OPERATION', `operations[${index}].surface inválida`);
  }
  const rawMethod = boundedString(
    operation.method,
    `operations[${index}].method`,
    canonicalizationVersion >= V4_CANONICALIZATION_VERSION
      ? MAX_HTTP_METHOD_LENGTH
      : 16,
    { allowEmpty: false },
  );
  const preservesWireMethod = canonicalizationVersion >= V4_CANONICALIZATION_VERSION;
  const method = preservesWireMethod ? rawMethod : rawMethod.toUpperCase();
  const route = boundedString(
    canonicalizationVersion >= SURFACE_CANONICALIZATION_VERSION
      ? operation.route
      : operation.path,
    `operations[${index}].route`,
    MAX_TEXT_LENGTH,
    { allowEmpty: false },
  );
  const id = operationIdentity(surface, route, method, preservesWireMethod);
  const methodSupported = preservesWireMethod
    ? method.length <= MAX_HTTP_METHOD_LENGTH && HTTP_METHOD_TOKEN_RE.test(method)
    : FIXED_HTTP_WIRE_METHODS.has(method);
  if (!methodSupported
    || (surface === 'path' && !route.startsWith('/'))
    || operation.id !== id) {
    throw formatError('API_CONTRACT_INVALID_OPERATION', `operations[${index}] inválida`);
  }
  const params = normalizeStringList(operation.params, `operations[${index}].params`, MAX_PARAMETERS_PER_OPERATION);
  const responses = normalizeStringList(operation.responses, `operations[${index}].responses`, MAX_RESPONSES_PER_OPERATION)
    .map((code) => code.toUpperCase());
  if (responses.some((code) => !RESPONSE_CODE_RE.test(code))) {
    throw formatError('API_CONTRACT_INVALID_RESPONSE_CODE', `operations[${index}].responses contém status inválido`);
  }
  const parameterSignatures = detailLevel === 'full'
    ? boundedArray(operation.parameterSignatures, `operations[${index}].parameterSignatures`, MAX_PARAMETERS_PER_OPERATION)
      .map((item, itemIndex) => {
        const detail = requireRecord(item, `operations[${index}].parameterSignatures[${itemIndex}]`);
        const key = boundedString(detail.key, 'parameter key', MAX_TEXT_LENGTH, { allowEmpty: false });
        const signature = boundedString(detail.signature, 'parameter signature', 71, { allowEmpty: false });
        if (!/^sha256:[a-f0-9]{64}$/i.test(signature)) throw formatError('API_CONTRACT_INVALID_HASH', 'parameter signature inválida');
        return { key, signature: signature.toLowerCase() };
      }).sort((a, b) => compareOrdinal(a.key, b.key))
    : [];
  const responseSignatures = detailLevel === 'full'
    ? boundedArray(operation.responseSignatures, `operations[${index}].responseSignatures`, MAX_RESPONSES_PER_OPERATION)
      .map((item, itemIndex) => {
        const detail = requireRecord(item, `operations[${index}].responseSignatures[${itemIndex}]`);
        const code = boundedString(detail.code, 'response code', 16, { allowEmpty: false }).toUpperCase();
        const signature = boundedString(detail.signature, 'response signature', 71, { allowEmpty: false });
        if (!/^sha256:[a-f0-9]{64}$/i.test(signature)) throw formatError('API_CONTRACT_INVALID_HASH', 'response signature inválida');
        return { code, signature: signature.toLowerCase() };
      }).sort((a, b) => compareOrdinal(a.code, b.code))
    : [];
  const securityRequirements = detailLevel === 'full'
    ? normalizeStringList(operation.securityRequirements, `operations[${index}].securityRequirements`, MAX_SECURITY_ALTERNATIVES)
    : [];
  const requestBodySignature = detailLevel === 'full' && operation.requestBodySignature != null
    ? boundedString(operation.requestBodySignature, 'request body signature', 71, { allowEmpty: false }).toLowerCase()
    : null;
  const semanticSignature = detailLevel === 'full'
    ? boundedString(operation.semanticSignature, 'operation signature', 71, { allowEmpty: false }).toLowerCase()
    : null;
  if (requestBodySignature && !/^sha256:[a-f0-9]{64}$/.test(requestBodySignature)) {
    throw formatError('API_CONTRACT_INVALID_HASH', 'request body signature inválida');
  }
  if (semanticSignature && !/^sha256:[a-f0-9]{64}$/.test(semanticSignature)) {
    throw formatError('API_CONTRACT_INVALID_HASH', 'operation signature inválida');
  }
  if (detailLevel === 'full') {
    const parameterKeys = parameterSignatures.map((item) => item.key);
    const responseCodes = responseSignatures.map((item) => item.code);
    if (new Set(parameterKeys).size !== parameterKeys.length
      || !sameList([...parameterKeys].sort(), params)
      || new Set(responseCodes).size !== responseCodes.length
      || !sameList([...responseCodes].sort(), responses)
      || securityIsRequired(securityRequirements) !== (operation.hasSecurity === true)
      || Boolean(requestBodySignature) !== (operation.requestBody === true)) {
      throw formatError('API_CONTRACT_INCONSISTENT_OPERATION', `operations[${index}] possui campos derivados inconsistentes`);
    }
  }
  return {
    id,
    surface,
    method,
    ...(canonicalizationVersion >= SURFACE_CANONICALIZATION_VERSION
      ? { route }
      : { path: route }),
    operationId: boundedString(operation.operationId, `operations[${index}].operationId`, MAX_NAME_LENGTH),
    tags: normalizeStringList(operation.tags, `operations[${index}].tags`, MAX_TAGS_PER_OPERATION),
    params,
    parameterSignatures,
    requestBody: operation.requestBody === true,
    requestBodySignature,
    responses,
    responseSignatures,
    hasSecurity: operation.hasSecurity === true,
    securityRequirements,
    deprecated: operation.deprecated === true,
    semanticSignature,
  };
}

function normalizeReferenceResolution(value, canonicalizationVersion) {
  if (canonicalizationVersion < REFERENCE_COVERAGE_CANONICALIZATION_VERSION) return null;
  const raw = requireRecord(value, 'referenceResolution');
  const mode = boundedString(raw.mode, 'referenceResolution.mode', 64, { allowEmpty: false });
  const status = boundedString(raw.status, 'referenceResolution.status', 16, { allowEmpty: false });
  if (mode !== 'detect_only_v1' || !['complete', 'partial'].includes(status)) {
    throw formatError('API_CONTRACT_INVALID_REFERENCE_COVERAGE', 'cobertura de referências inválida');
  }
  const referencesSeen = Number(raw.referencesSeen);
  const externalReferences = Number(raw.externalReferences);
  const unresolvedExternalReferences = Number(raw.unresolvedExternalReferences);
  const validatesInternalReferences = canonicalizationVersion
    >= REFERENCE_VALIDATION_CANONICALIZATION_VERSION;
  const unresolvedInternalReferences = validatesInternalReferences
    ? Number(raw.unresolvedInternalReferences)
    : 0;
  if (![referencesSeen, externalReferences, unresolvedExternalReferences, unresolvedInternalReferences].every(
    (count) => Number.isSafeInteger(count) && count >= 0 && count <= MAX_REFERENCES_PER_DOCUMENT,
  ) || externalReferences > referencesSeen
    || unresolvedExternalReferences > externalReferences
    || unresolvedExternalReferences + unresolvedInternalReferences > referencesSeen) {
    throw formatError('API_CONTRACT_INVALID_REFERENCE_COVERAGE', 'contadores de referências inválidos');
  }
  const referenceSetHash = boundedString(
    raw.referenceSetHash,
    'referenceResolution.referenceSetHash',
    71,
    { allowEmpty: false },
  ).toLowerCase();
  if (!/^sha256:[a-f0-9]{64}$/.test(referenceSetHash)) {
    throw formatError('API_CONTRACT_INVALID_HASH', 'fingerprint de referências inválida');
  }
  const issueCodes = normalizeStringList(
    raw.issueCodes,
    'referenceResolution.issueCodes',
    16,
    { lower: true },
  );
  if (issueCodes.some((code) => !/^[a-z0-9_]{1,64}$/.test(code))
    || (status === 'complete'
      && (unresolvedExternalReferences !== 0
        || unresolvedInternalReferences !== 0
        || issueCodes.length !== 0))
    || (status === 'partial' && issueCodes.length === 0)
    || (mode === 'detect_only_v1' && externalReferences !== unresolvedExternalReferences)
    || (validatesInternalReferences
      && ((unresolvedExternalReferences > 0)
        !== issueCodes.includes('external_references_unresolved')))
    || (validatesInternalReferences
      && ((unresolvedInternalReferences > 0)
        !== issueCodes.includes('internal_references_unresolved')))) {
    throw formatError('API_CONTRACT_INVALID_REFERENCE_COVERAGE', 'estado de referências inconsistente');
  }
  return {
    mode,
    status,
    referencesSeen,
    externalReferences,
    unresolvedExternalReferences,
    ...(validatesInternalReferences ? { unresolvedInternalReferences } : {}),
    referenceSetHash,
    issueCodes,
  };
}

function normalizeV2Summary(input) {
  const raw = requireRecord(input, 'snapshot v2');
  const canonicalizationVersion = Number(raw.canonicalizationVersion);
  if (!SUPPORTED_CANONICALIZATION_VERSIONS.has(canonicalizationVersion)) {
    throw formatError('API_CONTRACT_UNSUPPORTED_CANONICALIZATION', 'canonicalização do snapshot não suportada');
  }
  const sourceSchemaVersion = Number(raw.compatibility?.sourceSchemaVersion);
  const detailLevel = raw.compatibility?.detailLevel;
  if (![1, API_CONTRACT_SNAPSHOT_SCHEMA_VERSION].includes(sourceSchemaVersion)
    || !['full', 'legacy_v1'].includes(detailLevel)
    || (sourceSchemaVersion === 1) !== (detailLevel === 'legacy_v1')) {
    throw formatError('API_CONTRACT_INVALID_COMPATIBILITY', 'metadados de compatibilidade inválidos');
  }
  const redactionPolicyHash = canonicalizationVersion >= V4_CANONICALIZATION_VERSION
    ? boundedString(
        raw.compatibility?.redactionPolicyHash,
        'compatibility.redactionPolicyHash',
        71,
        { allowEmpty: false },
      ).toLowerCase()
    : null;
  if (redactionPolicyHash && !/^sha256:[a-f0-9]{64}$/.test(redactionPolicyHash)) {
    throw formatError('API_CONTRACT_INVALID_HASH', 'fingerprint da política de redação inválida');
  }
  const operations = boundedArray(raw.operations, 'operations', MAX_OPERATIONS)
    .map((operation, index) => normalizeV2Operation(
      operation,
      index,
      detailLevel,
      canonicalizationVersion,
    ))
    .sort((a, b) => compareOrdinal(a.id, b.id));
  const operationIds = new Set();
  for (const operation of operations) {
    if (operationIds.has(operation.id)) throw formatError('API_CONTRACT_DUPLICATE_OPERATION', `${operation.id} duplicado`);
    operationIds.add(operation.id);
  }
  const securitySchemes = boundedArray(raw.securitySchemes || [], 'securitySchemes', MAX_SECURITY_SCHEMES)
    .map((item, index) => {
      const scheme = requireRecord(item, `securitySchemes[${index}]`);
      const fingerprint = detailLevel === 'full'
        ? boundedString(scheme.fingerprint, 'security scheme fingerprint', 71, { allowEmpty: false }).toLowerCase()
        : null;
      if (fingerprint && !/^sha256:[a-f0-9]{64}$/.test(fingerprint)) {
        throw formatError('API_CONTRACT_INVALID_HASH', 'security scheme fingerprint inválida');
      }
      return {
        name: boundedString(scheme.name, `securitySchemes[${index}].name`, MAX_NAME_LENGTH, { allowEmpty: false }),
        type: boundedString(scheme.type, `securitySchemes[${index}].type`, MAX_NAME_LENGTH).toLowerCase(),
        scheme: boundedString(scheme.scheme, `securitySchemes[${index}].scheme`, MAX_NAME_LENGTH).toLowerCase(),
        in: boundedString(scheme.in, `securitySchemes[${index}].in`, MAX_NAME_LENGTH).toLowerCase(),
        fingerprint,
      };
    }).sort((a, b) => compareOrdinal(a.name, b.name));
  if (new Set(securitySchemes.map((scheme) => scheme.name)).size !== securitySchemes.length) {
    throw formatError('API_CONTRACT_DUPLICATE_SECURITY_SCHEME', 'securitySchemes contém nome duplicado');
  }
  const serversSignature = detailLevel === 'full'
    ? boundedString(raw.serversSignature, 'serversSignature', 71, { allowEmpty: false }).toLowerCase()
    : null;
  const componentsSignature = detailLevel === 'full'
    ? boundedString(raw.componentsSignature, 'componentsSignature', 71, { allowEmpty: false }).toLowerCase()
    : null;
  if ((serversSignature && !/^sha256:[a-f0-9]{64}$/.test(serversSignature))
    || (componentsSignature && !/^sha256:[a-f0-9]{64}$/.test(componentsSignature))) {
    throw formatError('API_CONTRACT_INVALID_HASH', 'fingerprint estrutural inválida');
  }
  const rootContractSignature = detailLevel === 'full'
    && canonicalizationVersion >= SURFACE_CANONICALIZATION_VERSION
    ? boundedString(raw.rootContractSignature, 'rootContractSignature', 71, { allowEmpty: false }).toLowerCase()
    : null;
  if (rootContractSignature && !/^sha256:[a-f0-9]{64}$/.test(rootContractSignature)) {
    throw formatError('API_CONTRACT_INVALID_HASH', 'fingerprint raiz inválida');
  }
  const surfaceSignaturesSupported = detailLevel === 'full'
    && canonicalizationVersion >= SURFACE_CANONICALIZATION_VERSION;
  const pathItemsSignature = surfaceSignaturesSupported
    ? boundedString(raw.pathItemsSignature, 'pathItemsSignature', 71, { allowEmpty: false }).toLowerCase()
    : null;
  const webhooksSignature = surfaceSignaturesSupported
    ? boundedString(raw.webhooksSignature, 'webhooksSignature', 71, { allowEmpty: false }).toLowerCase()
    : null;
  if ((pathItemsSignature && !/^sha256:[a-f0-9]{64}$/.test(pathItemsSignature))
    || (webhooksSignature && !/^sha256:[a-f0-9]{64}$/.test(webhooksSignature))) {
    throw formatError('API_CONTRACT_INVALID_HASH', 'fingerprint de Path Item/webhook inválida');
  }
  const params = new Set(operations.flatMap((operation) => operation.params));
  const pathCount = Number(raw.pathCount);
  const webhookCount = canonicalizationVersion >= SURFACE_CANONICALIZATION_VERSION
    ? Number(raw.webhookCount)
    : 0;
  if (!Number.isInteger(pathCount) || pathCount < 0 || pathCount > MAX_PATHS
    || !Number.isInteger(webhookCount) || webhookCount < 0 || webhookCount > MAX_WEBHOOKS
    || Number(raw.operationCount) !== operations.length
    || Number(raw.paramCount) !== params.size
    || Number(raw.operationsWithoutSecurity) !== operations.filter((operation) => !operation.hasSecurity).length) {
    throw formatError('API_CONTRACT_INCONSISTENT_SUMMARY', 'contadores do snapshot v2 são inconsistentes');
  }
  const normalizedUrl = canonicalContractUrl(raw.url, {
    allowEmpty: true,
    redactSensitive: true,
  });
  const referenceResolution = normalizeReferenceResolution(raw.referenceResolution, canonicalizationVersion);
  const sourceAliases = canonicalizationVersion >= REFERENCE_COVERAGE_CANONICALIZATION_VERSION
      ? normalizeSourceAliases(
          boundedArray(raw.sourceAliases, 'sourceAliases', MAX_SOURCE_ALIASES),
          normalizedUrl,
          { redactSensitive: true },
        )
    : null;
  const rawSourceDocumentVersion = canonicalizationVersion >= V4_CANONICALIZATION_VERSION
    ? raw.sourceDocumentVersion
    : raw.version;
  const normalizedVersions = normalizeSummaryDocumentVersions(
    raw.version,
    rawSourceDocumentVersion,
  );
  const normalized = {
    schemaVersion: API_CONTRACT_SNAPSHOT_SCHEMA_VERSION,
    canonicalizationVersion,
    compatibility: detailLevel === 'full'
      ? {
          sourceSchemaVersion: API_CONTRACT_SNAPSHOT_SCHEMA_VERSION,
          detailLevel: 'full',
          ...(redactionPolicyHash ? { redactionPolicyHash } : {}),
        }
      : {
          sourceSchemaVersion: 1,
          detailLevel: 'legacy_v1',
          lossyFields: [
            'component_schemas',
            'parameter_schemas',
            'response_schemas',
            'security_requirements',
            'servers',
            ...(canonicalizationVersion >= SURFACE_CANONICALIZATION_VERSION
              ? ['path_items', 'webhooks']
              : []),
            ...(canonicalizationVersion >= REFERENCE_COVERAGE_CANONICALIZATION_VERSION
              ? ['reference_resolution', 'source_aliases']
              : []),
          ],
          ...(redactionPolicyHash ? { redactionPolicyHash } : {}),
        },
    url: normalizedUrl,
    resolvedUrl: canonicalizationVersion >= V4_CANONICALIZATION_VERSION
      ? canonicalContractUrl(raw.resolvedUrl, { allowEmpty: true, redactSensitive: true })
      : normalizedUrl,
    ...(sourceAliases ? { sourceAliases } : {}),
    version: normalizedVersions.version,
    title: boundedString(raw.title, 'title', MAX_NAME_LENGTH),
    apiVersion: boundedString(raw.apiVersion, 'apiVersion', MAX_NAME_LENGTH),
    pathCount,
    webhookCount,
    operationCount: operations.length,
    paramCount: params.size,
    securitySchemes,
    operationsWithoutSecurity: operations.filter((operation) => !operation.hasSecurity).length,
    serversSignature,
    componentsSignature,
    rootContractSignature,
    pathItemsSignature,
    webhooksSignature,
    operations,
    sourceDocumentVersion: normalizedVersions.sourceDocumentVersion,
    ...(referenceResolution ? { referenceResolution } : {}),
  };
  normalized.hash = computedSummaryHash(normalized);
  const suppliedHash = boundedString(raw.hash, 'hash', 64, { allowEmpty: false }).toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(suppliedHash) || suppliedHash !== normalized.hash) {
    throw formatError('API_CONTRACT_INTEGRITY_MISMATCH', 'hash do snapshot v2 não confere');
  }
  return normalized;
}

export function migrateApiContractSummary(input) {
  const schemaVersion = Number(input?.schemaVersion);
  if (schemaVersion === 1) return migrateV1Summary(input);
  if (schemaVersion === API_CONTRACT_SNAPSHOT_SCHEMA_VERSION) return normalizeV2Summary(input);
  throw formatError('API_CONTRACT_UNSUPPORTED_SNAPSHOT', `schemaVersion ${String(input?.schemaVersion)} não suportada`);
}

function setDiff(current, previous) {
  const previousSet = new Set(previous);
  return current.filter((item) => !previousSet.has(item));
}

function sameList(a, b) {
  return stableJson(a) === stableJson(b);
}

function operationChanges(previous, current, fullDetail) {
  const changes = [];
  if (previous.operationId !== current.operationId) changes.push('operation_id');
  if (!sameList(previous.tags, current.tags)) changes.push('tags');
  if (!sameList(previous.params, current.params)) changes.push('parameters');
  if (previous.requestBody !== current.requestBody) changes.push('request_body_presence');
  if (!sameList(previous.responses, current.responses)) changes.push('responses');
  if (previous.hasSecurity !== current.hasSecurity) changes.push('security_requirement');
  if (previous.deprecated !== current.deprecated) changes.push('deprecation');
  if (fullDetail) {
    if (!sameList(previous.parameterSignatures, current.parameterSignatures)) changes.push('parameter_contract');
    if (previous.requestBodySignature !== current.requestBodySignature) changes.push('request_body_contract');
    if (!sameList(previous.responseSignatures, current.responseSignatures)) changes.push('response_contract');
    if (!sameList(previous.securityRequirements, current.securityRequirements)) changes.push('security_alternatives');
    if (previous.semanticSignature !== current.semanticSignature) changes.push('operation_contract');
  }
  return changes;
}

export function diffOpenApiSummaries(previousInput, currentInput) {
  if (!previousInput || !currentInput) return null;
  const previous = migrateApiContractSummary(previousInput);
  const current = migrateApiContractSummary(currentInput);
  if (previous.canonicalizationVersion !== current.canonicalizationVersion
    || previous.compatibility.redactionPolicyHash
      !== current.compatibility.redactionPolicyHash) {
    throw formatError(
      'API_CONTRACT_INCOMPATIBLE_CANONICALIZATION',
      'snapshots usam canonicalizações incompatíveis; grave um novo baseline',
    );
  }
  const legacyCompatible = previous.compatibility.detailLevel === 'legacy_v1'
    || current.compatibility.detailLevel === 'legacy_v1';
  if (!legacyCompatible
    && current.canonicalizationVersion >= REFERENCE_COVERAGE_CANONICALIZATION_VERSION
    && (previous.referenceResolution.status !== 'complete'
      || current.referenceResolution.status !== 'complete')) {
    throw formatError(
      'API_CONTRACT_INCOMPLETE_REFERENCE_COVERAGE',
      'snapshot com cobertura de referências incompleta não pode produzir diff',
    );
  }
  const previousOperations = new Map(previous.operations.map((operation) => [operation.id, operation]));
  const currentOperations = new Map(current.operations.map((operation) => [operation.id, operation]));
  const previousIds = [...previousOperations.keys()].sort();
  const currentIds = [...currentOperations.keys()].sort();
  const previousParams = previous.operations.flatMap((operation) => operation.params.map((param) => `${operation.id}:${param}`)).sort();
  const currentParams = current.operations.flatMap((operation) => operation.params.map((param) => `${operation.id}:${param}`)).sort();
  const previousSchemes = new Map(previous.securitySchemes.map((scheme) => [scheme.name, scheme]));
  const currentSchemes = new Map(current.securitySchemes.map((scheme) => [scheme.name, scheme]));
  const previousSchemeNames = [...previousSchemes.keys()].sort();
  const currentSchemeNames = [...currentSchemes.keys()].sort();
  const fullDetail = previous.compatibility.detailLevel === 'full'
    && current.compatibility.detailLevel === 'full';
  const modifiedOperations = [];
  const securityRegressions = [];
  const securityImprovements = [];
  for (const id of currentIds) {
    const oldOperation = previousOperations.get(id);
    if (!oldOperation) continue;
    const newOperation = currentOperations.get(id);
    const changes = operationChanges(oldOperation, newOperation, fullDetail);
    if (changes.length) modifiedOperations.push({ id, changes });
    if (oldOperation.hasSecurity && !newOperation.hasSecurity) securityRegressions.push(id);
    if (!oldOperation.hasSecurity && newOperation.hasSecurity) securityImprovements.push(id);
  }
  const changedSecuritySchemes = currentSchemeNames.filter((name) => {
    const oldScheme = previousSchemes.get(name);
    if (!oldScheme) return false;
    const newScheme = currentSchemes.get(name);
    const commonChanged = oldScheme.type !== newScheme.type
      || oldScheme.scheme !== newScheme.scheme
      || oldScheme.in !== newScheme.in;
    return commonChanged || (fullDetail && oldScheme.fingerprint !== newScheme.fingerprint);
  });
  const metadataChanges = [];
  if (previous.version !== current.version) metadataChanges.push('document_version');
  if (previous.title !== current.title) metadataChanges.push('title');
  if (previous.apiVersion !== current.apiVersion) metadataChanges.push('api_version');
  const serversChanged = fullDetail && previous.serversSignature !== current.serversSignature;
  const componentsChanged = fullDetail && previous.componentsSignature !== current.componentsSignature;
  const rootContractChanged = fullDetail
    && previous.rootContractSignature !== current.rootContractSignature;
  const pathItemsChanged = fullDetail
    && previous.pathItemsSignature !== current.pathItemsSignature;
  const webhooksChanged = fullDetail
    && previous.webhooksSignature !== current.webhooksSignature;
  const addedOperations = setDiff(currentIds, previousIds);
  const removedOperations = setDiff(previousIds, currentIds);
  const addedParams = setDiff(currentParams, previousParams);
  const removedParams = setDiff(previousParams, currentParams);
  const addedSecuritySchemes = setDiff(currentSchemeNames, previousSchemeNames);
  const removedSecuritySchemes = setDiff(previousSchemeNames, currentSchemeNames);
  const addedWebhooks = addedOperations.filter((id) => id.startsWith('WEBHOOK '));
  const removedWebhooks = removedOperations.filter((id) => id.startsWith('WEBHOOK '));
  const modifiedWebhooks = modifiedOperations.filter((item) => item.id.startsWith('WEBHOOK '));
  const pathCountDelta = current.pathCount - previous.pathCount;
  const webhookCountDelta = current.webhookCount - previous.webhookCount;
  const classifiedChange = Boolean(
    addedOperations.length
    || removedOperations.length
    || modifiedOperations.length
    || addedSecuritySchemes.length
    || removedSecuritySchemes.length
    || changedSecuritySchemes.length
    || metadataChanges.length
    || serversChanged
    || componentsChanged
    || rootContractChanged
    || pathItemsChanged
    || webhooksChanged
    || (fullDetail && pathCountDelta)
    || (fullDetail && webhookCountDelta)
  );
  // Snapshots v1 não continham as dimensões semânticas do v3. Nesse modo
  // compatível, somente os campos efetivamente compartilhados podem declarar
  // mudança; comparar o hash v3 reconstruído produziria falso positivo.
  const hashComparable = fullDetail;
  const hashChanged = previous.hash !== current.hash;
  const changed = hashComparable ? hashChanged : classifiedChange;
  return {
    changed,
    unclassifiedContractChanged: hashComparable && changed && !classifiedChange,
    comparisonDetail: fullDetail ? 'full' : 'legacy_compatible',
    previousHash: previous.hash,
    currentHash: current.hash,
    addedOperations,
    removedOperations,
    modifiedOperations,
    addedParams,
    removedParams,
    addedSecuritySchemes,
    removedSecuritySchemes,
    changedSecuritySchemes,
    securityRegressions,
    securityImprovements,
    metadataChanges,
    serversChanged,
    componentsChanged,
    rootContractChanged,
    pathItemsChanged,
    webhooksChanged,
    addedWebhooks,
    removedWebhooks,
    modifiedWebhooks,
    pathCountDelta,
    webhookCountDelta,
    operationsWithoutSecurityDelta:
      current.operationsWithoutSecurity - previous.operationsWithoutSecurity,
  };
}

function prioFor(score) {
  if (score >= 72) return 'high';
  if (score >= 50) return 'med';
  if (score >= 30) return 'low';
  return 'info';
}

function snapshotProvenance(summary) {
  return {
    moduleId: moduleManifest.id,
    sourceUrl: summary.url,
    resolvedSourceUrl: summary.resolvedUrl,
    sourceDocumentVersion: summary.sourceDocumentVersion,
    sourceSnapshotSchemaVersion: summary.compatibility.sourceSchemaVersion,
    detailLevel: summary.compatibility.detailLevel,
    redactionPolicyHash: summary.compatibility.redactionPolicyHash || null,
    ...(summary.canonicalizationVersion >= REFERENCE_COVERAGE_CANONICALIZATION_VERSION
      ? {
          sourceAliases: summary.sourceAliases,
          referenceResolution: summary.referenceResolution,
        }
      : {}),
  };
}

function buildApiContractSnapshot(summary) {
  const snapshot = {
    format: API_CONTRACT_SNAPSHOT_FORMAT,
    schemaVersion: API_CONTRACT_SNAPSHOT_SCHEMA_VERSION,
    canonicalizationVersion: summary.canonicalizationVersion,
    summaryHash: summary.hash,
    provenance: snapshotProvenance(summary),
    summary,
  };
  if (summary.canonicalizationVersion >= V4_CANONICALIZATION_VERSION) {
    snapshot.integrityHash = `sha256:${sha256(stableJson({
      format: snapshot.format,
      schemaVersion: snapshot.schemaVersion,
      canonicalizationVersion: snapshot.canonicalizationVersion,
      summaryHash: snapshot.summaryHash,
      provenance: snapshot.provenance,
    }))}`;
  }
  return snapshot;
}

export function createApiContractSnapshot(summaryInput) {
  return buildApiContractSnapshot(migrateApiContractSummary(summaryInput));
}

function snapshotFinding(summary) {
  // Summaries emitted by the collector were normalized and hashed in the same
  // call. Avoid a second O(n) normalization solely to project persistence size.
  const snapshot = buildApiContractSnapshot(summary);
  return {
    type: 'api_contract_snapshot',
    prio: 'info',
    score: 22,
    value: `OpenAPI snapshot: ${summary.operationCount} ops / ${summary.pathCount} paths / ${summary.webhookCount} webhooks`,
    meta: `source=api_contract_diff - snapshot_schema=${snapshot.schemaVersion} - canonicalization=${snapshot.canonicalizationVersion} - hash=${summary.hash} - ops=${summary.operationCount} - paths=${summary.pathCount} - webhooks=${summary.webhookCount} - reference_coverage=${summary.referenceResolution?.status || 'untracked'}`,
    url: summary.url,
    verification: {
      classification: 'noisy',
      confidenceScore: summary.referenceResolution?.status === 'partial' ? 0.72 : 1,
      verifiedAt: new Date().toISOString(),
      evidence: {
        evidenceHash: summary.hash,
        apiContractSnapshot: snapshot,
      },
    },
  };
}

function snapshotStorageBytes(summary) {
  return Buffer.byteLength(JSON.stringify(snapshotFinding(summary)), 'utf8');
}

function diffFinding(diff, current, previousMeta = {}) {
  const score = diff.securityRegressions.length || diff.removedSecuritySchemes.length
    ? 38
    : diff.removedOperations.length
      ? 28
      : 22;
  const truncate = (items) => items.slice(0, MAX_DIFF_EVIDENCE_ITEMS);
  return {
    type: 'api_contract_diff',
    prio: prioFor(score),
    score,
    value: `OpenAPI contract mudou: +${diff.addedOperations.length} / -${diff.removedOperations.length} / ~${diff.modifiedOperations.length} operações`,
    meta: [
      'source=api_contract_diff',
      'evidence_status=contract_change',
      'runtime_enforcement_tested=false',
      `comparison=${diff.comparisonDetail}`,
      previousMeta.runId ? `previous_run=${previousMeta.runId}` : '',
      `prev=${diff.previousHash}`,
      `cur=${diff.currentHash}`,
      `added_ops=${diff.addedOperations.length}`,
      `removed_ops=${diff.removedOperations.length}`,
      `modified_ops=${diff.modifiedOperations.length}`,
      `security_regressions=${diff.securityRegressions.length}`,
      `no_security_delta=${diff.operationsWithoutSecurityDelta}`,
    ].filter(Boolean).join(' - '),
    url: current.url,
    owasp: 'A05:2021',
    verification: {
      classification: 'noisy',
      confidenceScore: diff.comparisonDetail === 'full' ? 0.9 : 0.72,
      verifiedAt: new Date().toISOString(),
      evidence: {
        evidenceHash: current.hash,
        apiContractDiff: {
          snapshotSchemaVersion: API_CONTRACT_SNAPSHOT_SCHEMA_VERSION,
          canonicalizationVersion: API_CONTRACT_CANONICALIZATION_VERSION,
          comparisonDetail: diff.comparisonDetail,
          previousRunId: previousMeta.runId || null,
          previousCreatedAt: previousMeta.createdAt || null,
          previousHash: diff.previousHash,
          currentHash: diff.currentHash,
          addedOperations: truncate(diff.addedOperations),
          removedOperations: truncate(diff.removedOperations),
          modifiedOperations: truncate(diff.modifiedOperations),
          addedParams: truncate(diff.addedParams),
          removedParams: truncate(diff.removedParams),
          addedSecuritySchemes: truncate(diff.addedSecuritySchemes),
          removedSecuritySchemes: truncate(diff.removedSecuritySchemes),
          changedSecuritySchemes: truncate(diff.changedSecuritySchemes),
          securityRegressions: truncate(diff.securityRegressions),
          securityImprovements: truncate(diff.securityImprovements),
          metadataChanges: diff.metadataChanges,
          serversChanged: diff.serversChanged,
          componentsChanged: diff.componentsChanged,
          rootContractChanged: diff.rootContractChanged,
          pathItemsChanged: diff.pathItemsChanged,
          webhooksChanged: diff.webhooksChanged,
          addedWebhooks: truncate(diff.addedWebhooks),
          removedWebhooks: truncate(diff.removedWebhooks),
          modifiedWebhooks: truncate(diff.modifiedWebhooks),
          pathCountDelta: diff.pathCountDelta,
          webhookCountDelta: diff.webhookCountDelta,
          unclassifiedContractChanged: diff.unclassifiedContractChanged,
          operationsWithoutSecurityDelta: diff.operationsWithoutSecurityDelta,
          evidenceTruncated: [
            diff.addedOperations,
            diff.removedOperations,
            diff.modifiedOperations,
            diff.addedParams,
            diff.removedParams,
          ].some((items) => items.length > MAX_DIFF_EVIDENCE_ITEMS),
        },
      },
    },
  };
}

function waitForAbortable(promise, signal) {
  throwIfAborted(signal);
  if (!signal) return promise;
  return new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = () => signal.removeEventListener('abort', onAbort);
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      cleanup();
      callback(value);
    };
    const onAbort = () => finish(reject, signal.reason || new DOMException('cancelado', 'AbortError'));
    signal.addEventListener('abort', onAbort, { once: true });
    Promise.resolve(promise).then(
      (value) => finish(resolve, value),
      (error) => finish(reject, error),
    );
    if (signal.aborted) onAbort();
  });
}

function cancelResponseBodyBestEffort(response, reason) {
  try {
    Promise.resolve(response?.body?.cancel?.(reason)).catch(() => {});
  } catch {
    // O transporte não pode prolongar o deadline durante cleanup.
  }
}

function publicContractUrl(value) {
  try {
    return canonicalContractUrl(value, { allowEmpty: true, redactSensitive: true });
  } catch {
    return '';
  }
}

function apiDocumentEncoding(url, contentType, text) {
  let pathname = '';
  try {
    pathname = new URL(url).pathname.toLowerCase();
  } catch {
    // A URL já foi validada pelo fetch com escopo; fallback pelo MIME/conteúdo.
  }
  if (/ya?ml/.test(contentType) || /\.ya?ml$/.test(pathname)) return 'yaml';
  if (/json|javascript/.test(contentType) || /\.json$/.test(pathname)) return 'json';
  return /^[\s\uFEFF]*[\[{]/.test(text) ? 'json' : 'yaml';
}

async function parseApiContractDocument(text, { url, contentType, signal }) {
  const encoding = apiDocumentEncoding(url, contentType, text);
  if (encoding === 'json') {
    try {
      const doc = Buffer.byteLength(text, 'utf8') <= 256_000
        ? parseJsonDocumentStrict(text)
        : await parseJsonDocumentInWorker(text, { signal });
      return { state: 'done', doc, encoding };
    } catch (error) {
      throwIfAborted(signal);
      return {
        state: 'invalid_json',
        reason: /^JSON_[A-Z0-9_]+$/.test(String(error?.code || ''))
          ? error.code
          : 'JSON_PARSE_ERROR',
        encoding,
      };
    }
  }
  try {
    const doc = await parseYamlDocumentInWorker(text, { signal });
    return { state: 'done', doc, encoding };
  } catch (error) {
    throwIfAborted(signal);
    return {
      state: 'invalid_yaml',
      reason: /^YAML_[A-Z0-9_]+$/.test(String(error?.code || ''))
        ? error.code
        : 'YAML_PARSE_ERROR',
      encoding,
    };
  }
}

async function fetchSpec(url, {
  fetchImpl = fetch,
  timeoutMs = 10_000,
  headers = {},
  signal = null,
  urlAllowed = () => false,
  maxBytes = MAX_SPEC_BYTES,
} = {}) {
  if (typeof fetchImpl !== 'function') throw new TypeError('fetch implementation unavailable');
  const requestSignal = combineAbortSignals(signal, normalizedTimeoutMs(timeoutMs, 10_000));
  throwIfAborted(requestSignal);
  let scopedResult;
  try {
    scopedResult = await waitForAbortable(
      fetchScoped(url, {
        fetchImpl,
        method: 'GET',
        signal: requestSignal,
        headers: {
          Accept: 'application/openapi+json,application/openapi+yaml,application/json,application/yaml,text/yaml,*/*;q=0.5',
          ...headers,
        },
        urlAllowed,
        maxRedirects: MAX_REDIRECTS,
        returnMeta: true,
      }),
      requestSignal,
    );
  } catch (error) {
    throwIfAborted(requestSignal);
    if (error?.code === 'OUT_OF_SCOPE') {
      return {
        state: 'scope_denied',
        reason: 'redirect_out_of_scope',
        url,
        httpStatus: null,
      };
    }
    if (error?.code === 'TOO_MANY_REDIRECTS') {
      return {
        state: 'redirect_limit',
        reason: 'redirect_limit_exceeded',
        url,
        httpStatus: null,
      };
    }
    throw error;
  }
  throwIfAborted(requestSignal);
  const res = scopedResult?.response;
  const responseUrl = scopedResult?.url || res?.url || url;
  if (urlAllowed(responseUrl) !== true) {
    cancelResponseBodyBestEffort(res);
    return { state: 'scope_denied', url: responseUrl, httpStatus: res?.status ?? null };
  }
  const contentType = String(res?.headers?.get?.('content-type') || '').toLowerCase();
  if (!res?.ok) {
    cancelResponseBodyBestEffort(res);
    const status = Number(res?.status) || 0;
    return {
      state: [404, 410].includes(status) ? 'absent'
        : [401, 403].includes(status) ? 'denied'
          : 'http_error',
      url: responseUrl,
      httpStatus: status,
    };
  }
  if (contentType && !/json|ya?ml|text|javascript|openapi/.test(contentType)) {
    cancelResponseBodyBestEffort(res);
    return { state: 'invalid_content_type', url: responseUrl, httpStatus: res?.status ?? null };
  }
  const contentLength = Number(res.headers?.get?.('content-length'));
  const responseByteLimit = Math.max(1, Math.min(MAX_SPEC_BYTES, Number(maxBytes) || MAX_SPEC_BYTES));
  if (Number.isFinite(contentLength) && contentLength > responseByteLimit) {
    cancelResponseBodyBestEffort(res);
    return { state: 'response_too_large', url: responseUrl, httpStatus: res?.status ?? null };
  }
  const text = await waitForAbortable(
    readResponseSnippet(
      res,
      responseByteLimit + 1,
      { signal: requestSignal },
    ),
    requestSignal,
  )
    .catch((error) => {
      cancelResponseBodyBestEffort(res, error);
      throw error;
    });
  throwIfAborted(requestSignal);
  const bodyBytes = Buffer.byteLength(text, 'utf8');
  if (bodyBytes > responseByteLimit) {
    return {
      state: 'response_too_large',
      url: responseUrl,
      httpStatus: res?.status ?? null,
      bodyBytes,
    };
  }
  const parsed = await parseApiContractDocument(text, {
    url: responseUrl,
    contentType,
    signal: requestSignal,
  });
  throwIfAborted(requestSignal);
  if (parsed.state !== 'done') {
    return {
      state: parsed.state,
      reason: parsed.reason,
      url: responseUrl,
      httpStatus: res?.status ?? null,
      bodyBytes,
    };
  }
  const { doc } = parsed;
  if (!isRecord(doc?.paths) && !isRecord(doc?.webhooks) && !isRecord(doc?.components)) {
    return {
      state: 'not_openapi',
      url: responseUrl,
      httpStatus: res?.status ?? null,
      bodyBytes,
      encoding: parsed.encoding,
    };
  }
  try {
    getDocumentVersion(doc);
  } catch (error) {
    return {
      state: 'invalid_contract',
      reason: error?.code || 'API_CONTRACT_INVALID_DOCUMENT',
      url: responseUrl,
      httpStatus: res?.status ?? null,
      bodyBytes,
      encoding: parsed.encoding,
    };
  }
  return {
    state: 'done',
    doc,
    url: responseUrl,
    httpStatus: res.status ?? null,
    redirects: scopedResult?.redirects || 0,
    bodyBytes,
    encoding: parsed.encoding,
  };
}

function normalizeOriginList(origins) {
  const out = new Set();
  let invalid = 0;
  let dropped = 0;
  const configured = Math.max(1, Number(limits.openapiMaxOrigins) || 10);
  const cap = Math.min(MAX_ORIGINS, configured);
  const input = Array.isArray(origins) ? origins : [];
  const inspected = input.slice(0, MAX_ORIGIN_INPUTS);
  dropped += Math.max(0, input.length - inspected.length);
  for (const value of inspected) {
    try {
      const parsed = new URL(boundedString(value, 'origin', MAX_TEXT_LENGTH, { allowEmpty: false }));
      if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
        invalid += 1;
        continue;
      }
      if (out.has(parsed.origin)) continue;
      if (out.size >= cap) {
        dropped += 1;
        continue;
      }
      out.add(parsed.origin);
    } catch {
      // Origem inválida não vira request implícito.
      invalid += 1;
    }
  }
  return { origins: [...out], invalid, dropped, cap };
}

function deadlineCollectionResult({ origins, modules, detailed }) {
  const normalizedInput = normalizeOriginList(origins);
  const normalizedOrigins = normalizedInput.origins;
  const candidatesPlanned = normalizedOrigins.length * SPEC_PATHS.length;
  const outcomes = [];
  if (normalizedInput.invalid > 0) {
    outcomes.push({
      origin: null,
      url: '',
      state: 'invalid_origin',
      httpStatus: null,
      count: normalizedInput.invalid,
    });
  }
  if (normalizedInput.dropped > 0) {
    outcomes.push({
      origin: null,
      url: '',
      state: 'origin_limit',
      httpStatus: null,
      count: normalizedInput.dropped,
      limit: normalizedInput.cap,
    });
  }
  outcomes.push({
    origin: null,
    url: '',
    state: 'module_deadline_exhausted',
    httpStatus: null,
    count: candidatesPlanned,
  });
  const coverage = {
    originsPlanned: normalizedOrigins.length,
    originsCompleted: 0,
    candidatesPerOrigin: SPEC_PATHS.length,
    candidatesPlanned,
    candidatesEvaluated: 0,
    candidatesConclusive: 0,
    candidatesInconclusive: 0,
    candidatesSkippedByLimit: 0,
    candidatesAbortedByDeadline: 0,
    candidatesSkippedByDeadline: candidatesPlanned,
    deadlineReached: true,
    effectiveConcurrency: stealthEnabled(modules)
      ? 1
      : Math.max(1, Number(moduleManifest.concurrency) || 1),
    contractsUnique: 0,
    contractsDiscardedByConflict: 0,
    duplicates: 0,
    bodyBytes: 0,
    summaryBytes: 0,
    snapshotBytes: 0,
    complete: false,
  };
  return detailed
    ? {
        summaries: [],
        outcomes,
        status: 'timeout',
        reason: 'module_deadline_exhausted',
        discoveryPolicy: 'all_known_per_origin_v1',
        coverage,
      }
    : [];
}

export async function fetchOpenApiContracts({
  origins = [],
  domain = '',
  outOfScopeList = [],
  scopePolicy = null,
  modules = [],
  fetchImpl = fetch,
  pauseImpl = stealthPause,
  perRequestTimeoutMs = null,
  log = () => {},
  signal = null,
  timeoutMs = moduleManifest.timeoutMs,
  detailed = false,
} = {}) {
  const moduleTimeoutMs = normalizedTimeoutMs(timeoutMs);
  const deadlineAt = Date.now() + moduleTimeoutMs;
  const deadlineController = new AbortController();
  const deadlineTimer = setTimeout(
    () => deadlineController.abort(deadlineError()),
    moduleTimeoutMs,
  );
  const deadlineSignal = deadlineController.signal;
  const moduleSignal = signal
    ? AbortSignal.any([signal, deadlineSignal])
    : deadlineSignal;
  try {
    throwIfAbortedOrDeadline(moduleSignal, deadlineAt);
    const out = [];
    const outcomes = [];
    const userAgent = pickStealthUserAgent(modules);
    const effectiveConcurrency = stealthEnabled(modules)
      ? 1
      : Math.max(1, Number(moduleManifest.concurrency) || 1);
    const requestTimeoutMs = Math.min(
      14_000,
      normalizedTimeoutMs(
        perRequestTimeoutMs,
        Number(limits.probeTimeoutMs) || 12_000,
      ),
    );
    const urlAllowed = (url) => urlInReconScope(url, domain, outOfScopeList, scopePolicy);
    const normalizedInput = normalizeOriginList(origins);
    const normalizedOrigins = normalizedInput.origins;
    const candidatesPlanned = normalizedOrigins.length * SPEC_PATHS.length;
    const resolvedSources = new Map();
    const conflictedSources = new Set();
    let candidatesEvaluated = 0;
    let candidatesConclusive = 0;
    let duplicates = 0;
    let totalBodyBytes = 0;
    let totalSummaryBytes = 0;
    let totalSnapshotBytes = 0;
    let originsCompleted = 0;
    let incompleteCoverage = normalizedInput.invalid > 0 || normalizedInput.dropped > 0;
    let limitReached = false;
    let deadlineReached = false;
    let candidatesAbortedByDeadline = 0;
    if (normalizedInput.invalid > 0) {
      outcomes.push({
        origin: null,
        url: '',
        state: 'invalid_origin',
        httpStatus: null,
        count: normalizedInput.invalid,
      });
    }
    if (normalizedInput.dropped > 0) {
      outcomes.push({
        origin: null,
        url: '',
        state: 'origin_limit',
        httpStatus: null,
        count: normalizedInput.dropped,
        limit: normalizedInput.cap,
      });
    }

    for (const origin of normalizedOrigins) {
      let originIncomplete = false;
      let originCandidates = 0;
      for (let pathOffset = 0;
        pathOffset < SPEC_PATHS.length && !limitReached && !deadlineReached;) {
        throwIfAborted(signal);
        if (deadlineSignal.aborted || deadlineExpired(deadlineAt)) {
          deadlineReached = true;
          incompleteCoverage = true;
          originIncomplete = true;
          break;
        }
        if (totalBodyBytes >= MAX_TOTAL_SPEC_BYTES) {
          outcomes.push({
            origin: null,
            url: '',
            state: 'collection_byte_limit',
            httpStatus: null,
            limit: MAX_TOTAL_SPEC_BYTES,
          });
          incompleteCoverage = true;
          originIncomplete = true;
          limitReached = true;
          break;
        }
        const remainingBytes = MAX_TOTAL_SPEC_BYTES - totalBodyBytes;
        const batchWidth = remainingBytes > effectiveConcurrency * (MAX_SPEC_BYTES + 1)
          ? effectiveConcurrency
          : 1;
        const paths = SPEC_PATHS.slice(pathOffset, pathOffset + batchWidth);
        pathOffset += paths.length;
        const candidates = paths.map((path) => {
          const url = new URL(path, `${origin}/`).href;
          return { origin, url, allowed: urlAllowed(url) };
        });
        const fetchableCount = candidates.filter((candidate) => candidate.allowed).length;
        if (fetchableCount > 0 && remainingBytes <= fetchableCount) {
          outcomes.push({
            origin: null,
            url: '',
            state: 'collection_byte_limit',
            httpStatus: null,
            limit: MAX_TOTAL_SPEC_BYTES,
          });
          incompleteCoverage = true;
          originIncomplete = true;
          limitReached = true;
          break;
        }
        const perCandidateBytes = fetchableCount > 0
          ? Math.max(1, Math.min(
              MAX_SPEC_BYTES,
              Math.floor((remainingBytes - fetchableCount) / fetchableCount),
            ))
          : MAX_SPEC_BYTES;
        candidatesEvaluated += candidates.length;
        originCandidates += candidates.length;
        const batchResults = await mapPool(
          candidates,
          effectiveConcurrency,
          async (candidate) => {
            if (!candidate.allowed) return { kind: 'scope_denied', candidate };
            try {
              await waitForAbortable(
                Promise.resolve().then(() => pauseImpl(modules, moduleSignal)),
                moduleSignal,
              );
              throwIfAbortedOrDeadline(moduleSignal, deadlineAt);
              const fetched = await waitForAbortable(
                fetchSpec(candidate.url, {
                  fetchImpl,
                  timeoutMs: requestTimeoutMs,
                  signal: moduleSignal,
                  urlAllowed,
                  headers: { 'User-Agent': userAgent },
                  maxBytes: perCandidateBytes,
                }),
                moduleSignal,
              );
              throwIfAbortedOrDeadline(moduleSignal, deadlineAt);
              if (fetched.state !== 'done') return { kind: 'fetched', candidate, fetched };
              try {
                const summary = collectOpenApiSummary(fetched.doc, {
                  url: candidate.url,
                  resolvedUrl: fetched.url,
                  sourceAliases: [candidate.url],
                  signal,
                  deadlineAt,
                });
                return { kind: 'fetched', candidate, fetched, summary };
              } catch (error) {
                throwIfAborted(signal);
                if (error?.code === 'API_CONTRACT_DEADLINE'
                  || deadlineSignal.aborted
                  || deadlineExpired(deadlineAt)) throw error;
                return { kind: 'fetched', candidate, fetched, summaryError: error };
              }
            } catch (error) {
              if (signal?.aborted) return { kind: 'parent_abort', candidate, error };
              if (deadlineSignal.aborted || deadlineExpired(deadlineAt)) {
                return { kind: 'deadline', candidate, error };
              }
              return { kind: 'request_error', candidate, error };
            }
          },
        );
        throwIfAborted(signal);
        if (deadlineSignal.aborted || deadlineExpired(deadlineAt)) {
          deadlineReached = true;
          incompleteCoverage = true;
          originIncomplete = true;
        }
        for (const batchResult of batchResults) {
          const { candidate } = batchResult;
          const { url } = candidate;
          if (batchResult.kind === 'parent_abort') throw batchResult.error;
          if (batchResult.kind === 'scope_denied') {
            outcomes.push({ origin, url: publicContractUrl(url), state: 'scope_denied', httpStatus: null });
            incompleteCoverage = true;
            originIncomplete = true;
            continue;
          }
          if (batchResult.kind === 'deadline') {
            deadlineReached = true;
            candidatesAbortedByDeadline += 1;
            incompleteCoverage = true;
            originIncomplete = true;
            outcomes.push({
              origin,
              url: publicContractUrl(url),
              state: 'deadline_aborted',
              httpStatus: null,
            });
            continue;
          }
          if (batchResult.kind === 'request_error') {
            const { error } = batchResult;
            const state = error?.name === 'TimeoutError' ? 'timeout' : 'request_failed';
            outcomes.push({ origin, url: publicContractUrl(url), state, httpStatus: null });
            incompleteCoverage = true;
            originIncomplete = true;
            log(`API contract: leitura indisponível (${state})`, 'warn');
            continue;
          }
          const { fetched, summary, summaryError } = batchResult;
          totalBodyBytes += Number(fetched.bodyBytes) || 0;
          if (fetched.state !== 'done') {
            const collectionLimit = fetched.state === 'response_too_large'
              && MAX_TOTAL_SPEC_BYTES - totalBodyBytes < MAX_SPEC_BYTES;
            const state = collectionLimit ? 'collection_byte_limit' : fetched.state;
            outcomes.push({
              origin,
              url: publicContractUrl(fetched.url || url),
              state,
              httpStatus: fetched.httpStatus ?? null,
              ...(fetched.reason ? { reason: fetched.reason } : {}),
              ...(collectionLimit ? { limit: MAX_TOTAL_SPEC_BYTES } : {}),
            });
            if (['absent', 'not_openapi'].includes(state)) {
              candidatesConclusive += 1;
            } else {
              incompleteCoverage = true;
              originIncomplete = true;
            }
            if (collectionLimit) {
              limitReached = true;
              break;
            }
            continue;
          }
          if (summaryError || !summary) {
            outcomes.push({
              origin,
              url: publicContractUrl(url),
              resolvedUrl: publicContractUrl(fetched.url),
              state: 'invalid_contract',
              httpStatus: fetched.httpStatus ?? null,
              reason: summaryError?.code || 'API_CONTRACT_INVALID_DOCUMENT',
            });
            incompleteCoverage = true;
            originIncomplete = true;
            continue;
          }
          const resolvedIdentity = contractIdentity(summary.resolvedUrl);
          const duplicateIndex = resolvedIdentity == null ? null : resolvedSources.get(resolvedIdentity);
          if (duplicateIndex != null) {
            const existing = out[duplicateIndex];
            const sourceAliases = normalizeSourceAliases(
              [...existing.sourceAliases, summary.url],
              existing.url,
            );
            const previousBytes = Buffer.byteLength(stableJson(existing), 'utf8');
            const nextBytes = Buffer.byteLength(stableJson({ ...existing, sourceAliases }), 'utf8');
            const previousSnapshotBytes = snapshotStorageBytes(existing);
            const nextSnapshotBytes = snapshotStorageBytes({ ...existing, sourceAliases });
            const summaryLimitExceeded = totalSummaryBytes - previousBytes + nextBytes
              > MAX_TOTAL_SUMMARY_BYTES;
            const snapshotLimitExceeded = totalSnapshotBytes
              - previousSnapshotBytes
              + nextSnapshotBytes
              > MAX_TOTAL_SNAPSHOT_BYTES;
            if (summaryLimitExceeded || snapshotLimitExceeded) {
              outcomes.push({
                origin,
                url: summary.url,
                resolvedUrl: summary.resolvedUrl,
                state: 'snapshot_byte_limit',
                httpStatus: fetched.httpStatus ?? null,
                limit: snapshotLimitExceeded
                  ? MAX_TOTAL_SNAPSHOT_BYTES
                  : MAX_TOTAL_SUMMARY_BYTES,
                limitKind: snapshotLimitExceeded ? 'serialized_snapshots' : 'summaries',
              });
              incompleteCoverage = true;
              originIncomplete = true;
              limitReached = true;
              break;
            }
            existing.sourceAliases = sourceAliases;
            totalSummaryBytes += nextBytes - previousBytes;
            totalSnapshotBytes += nextSnapshotBytes - previousSnapshotBytes;
            const hashConflict = existing.hash !== summary.hash;
            const duplicateCoverageComplete = existing.referenceResolution.status === 'complete'
              && summary.referenceResolution.status === 'complete';
            if (hashConflict && resolvedIdentity) conflictedSources.add(resolvedIdentity);
            outcomes.push({
              origin,
              url: summary.url,
              resolvedUrl: summary.resolvedUrl,
              state: hashConflict ? 'duplicate_contract_conflict' : 'duplicate_contract',
              httpStatus: fetched.httpStatus ?? null,
              duplicateOf: existing.url,
              summaryHash: summary.hash,
            });
            duplicates += 1;
            candidatesConclusive += !hashConflict && duplicateCoverageComplete ? 1 : 0;
            if (hashConflict) {
              incompleteCoverage = true;
              originIncomplete = true;
              log(`API contract: conteúdo divergente para ${existing.url}; baseline descartado`, 'warn');
            } else if (!duplicateCoverageComplete) {
              incompleteCoverage = true;
              originIncomplete = true;
            }
            continue;
          }
          const summaryBytes = Buffer.byteLength(stableJson(summary), 'utf8');
          const serializedSnapshotBytes = snapshotStorageBytes(summary);
          if (out.length >= MAX_CONTRACTS_PER_RUN
            || totalSummaryBytes + summaryBytes > MAX_TOTAL_SUMMARY_BYTES
            || totalSnapshotBytes + serializedSnapshotBytes > MAX_TOTAL_SNAPSHOT_BYTES) {
            const state = out.length >= MAX_CONTRACTS_PER_RUN
              ? 'contract_limit'
              : 'snapshot_byte_limit';
            const snapshotLimitExceeded = totalSnapshotBytes + serializedSnapshotBytes
              > MAX_TOTAL_SNAPSHOT_BYTES;
            outcomes.push({
              origin,
              url: summary.url,
              resolvedUrl: summary.resolvedUrl,
              state,
              httpStatus: fetched.httpStatus ?? null,
              limit: state === 'contract_limit'
                ? MAX_CONTRACTS_PER_RUN
                : snapshotLimitExceeded
                  ? MAX_TOTAL_SNAPSHOT_BYTES
                  : MAX_TOTAL_SUMMARY_BYTES,
              ...(state === 'snapshot_byte_limit'
                ? { limitKind: snapshotLimitExceeded ? 'serialized_snapshots' : 'summaries' }
                : {}),
            });
            incompleteCoverage = true;
            originIncomplete = true;
            limitReached = true;
            break;
          }
          if (resolvedIdentity) resolvedSources.set(resolvedIdentity, out.length);
          totalSummaryBytes += summaryBytes;
          totalSnapshotBytes += serializedSnapshotBytes;
          out.push(summary);
          const referenceCoveragePartial = summary.referenceResolution.status !== 'complete';
          const unresolvedExternal = summary.referenceResolution.unresolvedExternalReferences;
          const unresolvedInternal = summary.referenceResolution.unresolvedInternalReferences ?? 0;
          const referenceOutcomeState = unresolvedExternal > 0
            ? 'external_ref_unresolved'
            : unresolvedInternal > 0
              ? 'internal_ref_unresolved'
              : 'reference_scan_incomplete';
          outcomes.push({
            origin,
            url: summary.url,
            resolvedUrl: summary.resolvedUrl,
            state: referenceCoveragePartial ? referenceOutcomeState : 'done',
            httpStatus: fetched.httpStatus ?? null,
            summaryHash: summary.hash,
            ...(referenceCoveragePartial
              ? {
                  reason: summary.referenceResolution.issueCodes[0],
                  count: unresolvedExternal + unresolvedInternal,
                }
              : {}),
          });
          if (referenceCoveragePartial) {
            incompleteCoverage = true;
            originIncomplete = true;
          } else {
            candidatesConclusive += 1;
          }
          log(`API contract: snapshot ${summary.operationCount} ops em ${summary.url}`, 'success');
        }
        if (limitReached || deadlineReached) break;
      }
      if (!originIncomplete && originCandidates === SPEC_PATHS.length) originsCompleted += 1;
      if (limitReached || deadlineReached) break;
    }
    if (normalizedOrigins.length > 0
      && (deadlineSignal.aborted || deadlineExpired(deadlineAt))) {
      deadlineReached = true;
      incompleteCoverage = true;
    }
    const unstartedCandidates = Math.max(0, candidatesPlanned - candidatesEvaluated);
    const candidatesSkippedByDeadline = deadlineReached ? unstartedCandidates : 0;
    const candidatesSkippedByLimit = limitReached && !deadlineReached ? unstartedCandidates : 0;
    if (deadlineReached) {
      outcomes.push({
        origin: null,
        url: '',
        state: 'module_deadline_exhausted',
        httpStatus: null,
        count: candidatesAbortedByDeadline + candidatesSkippedByDeadline,
      });
    }
    if (unstartedCandidates > 0) incompleteCoverage = true;
    const summaries = out.filter((summary) => {
      const identity = contractIdentity(summary.resolvedUrl);
      return identity == null || !conflictedSources.has(identity);
    });
    const status = normalizedOrigins.length === 0
      ? 'skipped'
      : deadlineReached
        ? 'timeout'
      : incompleteCoverage
        ? 'partial'
        : 'done';
    const reason = status === 'skipped'
      ? 'no_http_origins_in_scope'
      : status === 'timeout'
        ? 'module_deadline_exhausted'
        : undefined;
    const coverage = {
      originsPlanned: normalizedOrigins.length,
      originsCompleted,
      candidatesPerOrigin: SPEC_PATHS.length,
      candidatesPlanned,
      candidatesEvaluated,
      candidatesConclusive,
      candidatesInconclusive: Math.max(0, candidatesEvaluated - candidatesConclusive),
      candidatesSkippedByLimit,
      candidatesAbortedByDeadline,
      candidatesSkippedByDeadline,
      deadlineReached,
      effectiveConcurrency,
      contractsUnique: summaries.length,
      contractsDiscardedByConflict: out.length - summaries.length,
      duplicates,
      bodyBytes: totalBodyBytes,
      summaryBytes: totalSummaryBytes,
      snapshotBytes: totalSnapshotBytes,
      complete: status === 'done',
    };
    return detailed
      ? {
          summaries,
          outcomes,
          status,
          reason,
          discoveryPolicy: 'all_known_per_origin_v1',
          coverage,
        }
      : summaries;
  } catch (error) {
    // Cancelamento explícito do operador sempre vence o deadline interno.
    throwIfAborted(signal);
    if (error?.code === 'API_CONTRACT_DEADLINE'
      || deadlineSignal.aborted
      || deadlineExpired(deadlineAt)) {
      return deadlineCollectionResult({ origins, modules, detailed });
    }
    throw error;
  } finally {
    clearTimeout(deadlineTimer);
  }
}

function extractSnapshotEnvelope(value) {
  const envelope = requireRecord(value, 'apiContractSnapshot');
  if (envelope.format !== API_CONTRACT_SNAPSHOT_FORMAT
    || envelope.schemaVersion !== API_CONTRACT_SNAPSHOT_SCHEMA_VERSION
    || !SUPPORTED_CANONICALIZATION_VERSIONS.has(Number(envelope.canonicalizationVersion))) {
    throw formatError('API_CONTRACT_UNSUPPORTED_ENVELOPE', 'envelope de snapshot não suportado');
  }
  const summary = migrateApiContractSummary(envelope.summary);
  const currentEnvelope = summary.canonicalizationVersion >= V4_CANONICALIZATION_VERSION;
  const coverageEnvelope = summary.canonicalizationVersion
    >= REFERENCE_COVERAGE_CANONICALIZATION_VERSION;
  const expectedSourceDocumentVersion = currentEnvelope
    ? summary.sourceDocumentVersion
    : summary.version;
  const expectedResolvedSourceUrl = currentEnvelope
    ? summary.resolvedUrl
    : summary.url;
  const normalizedSourceUrl = canonicalContractUrl(
    envelope.provenance?.sourceUrl,
    { allowEmpty: true, redactSensitive: true },
  );
  const normalizedResolvedSourceUrl = currentEnvelope
    ? canonicalContractUrl(
        envelope.provenance?.resolvedSourceUrl,
        { allowEmpty: true, redactSensitive: true },
      )
    : expectedResolvedSourceUrl;
  const normalizedAliases = coverageEnvelope
    ? normalizeSourceAliases(
        boundedArray(
          envelope.provenance?.sourceAliases,
          'provenance.sourceAliases',
          MAX_SOURCE_ALIASES,
        ),
        normalizedSourceUrl,
        { redactSensitive: true },
      )
    : null;
  const normalizedReferenceResolution = coverageEnvelope
    ? normalizeReferenceResolution(
        envelope.provenance?.referenceResolution,
        summary.canonicalizationVersion,
      )
    : null;
  const normalizedProvenance = snapshotProvenance(summary);
  const expectedIntegrityHash = currentEnvelope
    ? `sha256:${sha256(stableJson({
        format: envelope.format,
        schemaVersion: envelope.schemaVersion,
        canonicalizationVersion: envelope.canonicalizationVersion,
        summaryHash: envelope.summaryHash,
        provenance: normalizedProvenance,
      }))}`
    : null;
  if (envelope.summaryHash !== summary.hash
    || Number(envelope.canonicalizationVersion) !== summary.canonicalizationVersion
    || envelope.provenance?.moduleId !== moduleManifest.id
    || normalizedSourceUrl !== summary.url
    || (currentEnvelope
      && normalizedResolvedSourceUrl !== expectedResolvedSourceUrl)
    || envelope.provenance?.sourceDocumentVersion !== expectedSourceDocumentVersion
    || envelope.provenance?.sourceSnapshotSchemaVersion !== summary.compatibility.sourceSchemaVersion
    || envelope.provenance?.detailLevel !== summary.compatibility.detailLevel
    || (currentEnvelope
      && envelope.provenance?.redactionPolicyHash !== summary.compatibility.redactionPolicyHash)
    || (coverageEnvelope
      && !sameList(normalizedAliases, summary.sourceAliases))
    || (coverageEnvelope
      && stableJson(normalizedReferenceResolution)
        !== stableJson(summary.referenceResolution))
    || (currentEnvelope && envelope.integrityHash !== expectedIntegrityHash)) {
    throw formatError('API_CONTRACT_PROVENANCE_MISMATCH', 'proveniência do snapshot não confere');
  }
  return {
    integrityVerified: currentEnvelope,
    provenance: normalizedProvenance,
    summary,
  };
}

export function extractApiContractSnapshots(run) {
  const findings = Array.isArray(run?.findings) ? run.findings : [];
  const out = [];
  for (const finding of findings) {
    if (finding?.type !== 'api_contract_snapshot') continue;
    if (out.length >= MAX_API_CONTRACT_SNAPSHOTS_PER_RUN) break;
    try {
      const envelope = finding.verification?.evidence?.apiContractSnapshot;
      const legacySummary = finding.verification?.evidence?.apiContractSummary
        || (isRecord(finding.meta) ? finding.meta.summary : null);
      const extracted = envelope
        ? extractSnapshotEnvelope(envelope)
        : null;
      const summary = extracted?.summary || migrateApiContractSummary(legacySummary);
      out.push({
        runId: run.id,
        createdAt: run.created_at,
        summary,
        integrityVerified: extracted?.integrityVerified === true,
        provenance: extracted?.provenance || snapshotProvenance(summary),
      });
    } catch {
      // Snapshot persistido inválido/tampered nunca vira baseline.
    }
  }
  return out;
}

export async function findPreviousApiContractSnapshots({
  target,
  listRunsFn,
  listRunsForTargetFn = null,
  getRunByIdFn,
  limit = 80,
  maxBaselineBytes = MAX_TOTAL_BASELINE_BYTES,
  signal = null,
} = {}) {
  throwIfAborted(signal);
  if ((typeof listRunsForTargetFn !== 'function' && typeof listRunsFn !== 'function')
    || typeof getRunByIdFn !== 'function') return [];
  const runLimit = Math.max(1, Math.min(500, Number(limit) || 80));
  const normalizedTarget = boundedString(target, 'target', MAX_NAME_LENGTH).trim().toLowerCase();
  const usesTargetedQuery = typeof listRunsForTargetFn === 'function';
  const rows = await waitForAbortable(Promise.resolve().then(() => (
    usesTargetedQuery
      ? listRunsForTargetFn(normalizedTarget, runLimit, { signal })
      : listRunsFn(runLimit, { signal })
  )), signal);
  throwIfAborted(signal);
  const snapshots = [];
  const identities = new Set();
  let storageDegraded = false;
  let baselineByteLimitReached = false;
  let baselineBytesRead = 0;
  let baselineBytesRetained = 0;
  const baselineByteLimit = Math.max(
    1,
    Math.min(
      MAX_TOTAL_BASELINE_BYTES,
      Math.floor(Number(maxBaselineBytes) || MAX_TOTAL_BASELINE_BYTES),
    ),
  );
  const withStorageMetadata = () => {
    for (const [property, value] of Object.entries({
      storageDegraded,
      baselineByteLimitReached,
      baselineBytesRead,
      baselineBytesRetained,
      baselineByteLimit,
    })) {
      Object.defineProperty(snapshots, property, {
        configurable: false,
        enumerable: false,
        value,
        writable: false,
      });
    }
    return snapshots;
  };
  const snapshotLimit = Math.min(1_000, runLimit * 10);
  const candidateLimit = usesTargetedQuery ? runLimit * 2 : runLimit;
  const candidateRows = (Array.isArray(rows) ? [...rows] : [])
    .sort((left, right) => {
      const leftCreated = Date.parse(
        left?.created_at instanceof Date
          ? left.created_at.toISOString()
          : String(left?.created_at || ''),
      );
      const rightCreated = Date.parse(
        right?.created_at instanceof Date
          ? right.created_at.toISOString()
          : String(right?.created_at || ''),
      );
      const createdDelta = (Number.isFinite(rightCreated) ? rightCreated : Number.NEGATIVE_INFINITY)
        - (Number.isFinite(leftCreated) ? leftCreated : Number.NEGATIVE_INFINITY);
      if (createdDelta) return createdDelta;
      const leftId = Number(left?.id);
      const rightId = Number(right?.id);
      if (Number.isSafeInteger(leftId) && Number.isSafeInteger(rightId) && rightId !== leftId) {
        return rightId - leftId;
      }
      return compareOrdinal(String(right?.id || ''), String(left?.id || ''));
    })
    .slice(0, candidateLimit);
  for (const row of candidateRows) {
    throwIfAborted(signal);
    if (row?._storageDegraded === true) storageDegraded = true;
    if (String(row?.target || '').trim().toLowerCase() !== normalizedTarget) continue;
    const run = await waitForAbortable(Promise.resolve().then(() => getRunByIdFn(
      row.id,
      { row, signal },
    )), signal);
    throwIfAborted(signal);
    if (run?.target != null && String(run.target).trim().toLowerCase() !== normalizedTarget) continue;
    for (const snapshot of extractApiContractSnapshots(run)) {
      const snapshotBytes = Buffer.byteLength(stableJson({
        integrityVerified: snapshot.integrityVerified,
        provenance: snapshot.provenance,
        summary: snapshot.summary,
      }), 'utf8');
      if (baselineBytesRead + snapshotBytes > baselineByteLimit) {
        baselineByteLimitReached = true;
        return withStorageMetadata();
      }
      baselineBytesRead += snapshotBytes;
      const summaryEligible = snapshot.integrityVerified === true
        && snapshot.summary.compatibility.sourceSchemaVersion
          === API_CONTRACT_SNAPSHOT_SCHEMA_VERSION
        && snapshot.summary.compatibility.detailLevel === 'full'
        && snapshot.summary.canonicalizationVersion === API_CONTRACT_CANONICALIZATION_VERSION
        && snapshot.summary.referenceResolution?.status === 'complete';
      if (!summaryEligible) continue;
      const snapshotIdentities = contractIdentities(snapshot.summary);
      const identityPrefix = stableJson([
        snapshot.summary.canonicalizationVersion,
        snapshot.summary.compatibility.redactionPolicyHash || null,
        snapshot.summary.compatibility.sourceSchemaVersion,
        snapshot.summary.compatibility.detailLevel,
      ]);
      const versionedIdentities = snapshotIdentities.map((identity) => `${identityPrefix}:${identity}`);
      if (!versionedIdentities.length
        || versionedIdentities.every((identity) => identities.has(identity))) continue;
      for (const identity of versionedIdentities) identities.add(identity);
      snapshots.push(snapshot);
      baselineBytesRetained += snapshotBytes;
      if (snapshots.length >= snapshotLimit) return withStorageMetadata();
    }
  }
  return withStorageMetadata();
}

function contractIdentity(url) {
  try {
    return canonicalContractUrl(url);
  } catch {
    return null;
  }
}

function contractIdentities(summary) {
  const inputs = summary?.canonicalizationVersion >= REFERENCE_COVERAGE_CANONICALIZATION_VERSION
    ? [...(Array.isArray(summary.sourceAliases) ? summary.sourceAliases : []), summary.resolvedUrl]
    : summary?.canonicalizationVersion >= V4_CANONICALIZATION_VERSION
      ? [summary?.url, summary?.resolvedUrl]
      : [summary?.url];
  const identities = new Set();
  for (const value of Array.isArray(inputs) ? inputs : []) {
    const identity = contractIdentity(value);
    if (identity) identities.add(identity);
  }
  return [...identities].sort(compareOrdinal);
}

export function previousApiContractSnapshotFor(currentInput, previousSnapshots) {
  const current = migrateApiContractSummary(currentInput);
  const currentIdentities = new Set(contractIdentities(current));
  const currentCoverageComplete = current.canonicalizationVersion
      < REFERENCE_COVERAGE_CANONICALIZATION_VERSION
    || current.referenceResolution.status === 'complete';
  if (!currentIdentities.size || !currentCoverageComplete) return null;
  for (const previous of Array.isArray(previousSnapshots) ? previousSnapshots : []) {
    try {
      const summary = migrateApiContractSummary(previous?.summary);
      const eligibleBaseline = summary.compatibility.sourceSchemaVersion
          === API_CONTRACT_SNAPSHOT_SCHEMA_VERSION
        && summary.compatibility.detailLevel === 'full'
        && previous?.integrityVerified === true
        && (summary.canonicalizationVersion < REFERENCE_COVERAGE_CANONICALIZATION_VERSION
          || summary.referenceResolution.status === 'complete');
      const sharesIdentity = contractIdentities(summary)
        .some((identity) => currentIdentities.has(identity));
      if (eligibleBaseline
        && summary.canonicalizationVersion === current.canonicalizationVersion
        && summary.compatibility.redactionPolicyHash
          === current.compatibility.redactionPolicyHash
        && sharesIdentity) {
        return { ...previous, summary };
      }
    } catch {
      // Baseline incompatível ou sem integridade é ignorado de forma fechada.
    }
  }
  return null;
}

export async function runApiContractDiff({
  origins = [],
  domain = '',
  outOfScopeList = [],
  scopePolicy = null,
  modules = [],
  previousSnapshots = [],
  fetchImpl = fetch,
  log = () => {},
  signal = null,
  timeoutMs = moduleManifest.timeoutMs,
} = {}) {
  const effectiveTimeoutMs = normalizedTimeoutMs(timeoutMs);
  const startedAt = Date.now();
  const finalizationReserveMs = Math.min(
    Math.max(0, effectiveTimeoutMs - 1),
    Math.min(500, Math.max(25, Math.ceil(effectiveTimeoutMs * 0.05))),
  );
  const collectionTimeoutMs = Math.max(1, effectiveTimeoutMs - finalizationReserveMs);
  const hardDeadlineAt = startedAt + effectiveTimeoutMs;
  throwIfAborted(signal);
  const collection = await fetchOpenApiContracts({
    origins,
    domain,
    outOfScopeList,
    scopePolicy,
    modules,
    fetchImpl,
    log,
    signal,
    timeoutMs: collectionTimeoutMs,
    detailed: true,
  });
  const summaries = collection.summaries;
  const baselineStorageDegraded = previousSnapshots?.storageDegraded === true
    && summaries.length > 0;
  const baselineByteLimitReached = previousSnapshots?.baselineByteLimitReached === true
    && summaries.length > 0;
  const baselineCoverageDegraded = baselineStorageDegraded || baselineByteLimitReached;
  const outcomes = [...collection.outcomes];
  if (baselineStorageDegraded) {
    outcomes.push({
      origin: null,
      url: '',
      state: 'baseline_storage_degraded',
      httpStatus: null,
    });
  }
  if (baselineByteLimitReached) {
    outcomes.push({
      origin: null,
      url: '',
      state: 'baseline_byte_limit',
      httpStatus: null,
      count: previousSnapshots.baselineBytesRead,
      limit: previousSnapshots.baselineByteLimit,
    });
  }
  const findings = [];
  let materializationDeadlineReached = false;
  for (const current of summaries) {
    throwIfAborted(signal);
    if (deadlineExpired(hardDeadlineAt)) {
      materializationDeadlineReached = true;
      break;
    }
    findings.push(snapshotFinding(current));
    if (deadlineExpired(hardDeadlineAt)) {
      materializationDeadlineReached = true;
      break;
    }
    if (baselineCoverageDegraded) continue;
    const previous = previousApiContractSnapshotFor(current, previousSnapshots);
    if (deadlineExpired(hardDeadlineAt)) {
      materializationDeadlineReached = true;
      break;
    }
    if (!previous?.summary) continue;
    const diff = diffOpenApiSummaries(previous.summary, current);
    if (diff?.changed) findings.push(diffFinding(diff, current, previous));
    if (deadlineExpired(hardDeadlineAt)) {
      materializationDeadlineReached = true;
      break;
    }
  }
  const snapshotsMaterialized = findings.filter(
    (finding) => finding.type === 'api_contract_snapshot',
  ).length;
  if (materializationDeadlineReached) {
    outcomes.push({
      origin: null,
      url: '',
      state: 'materialization_deadline_exhausted',
      httpStatus: null,
      count: Math.max(
        0,
        summaries.length - snapshotsMaterialized,
      ),
    });
  }
  const status = collection.status === 'timeout' || materializationDeadlineReached
    ? 'timeout'
    : baselineCoverageDegraded
      ? 'partial'
      : collection.status;
  const reason = status === 'timeout'
    ? collection.status === 'timeout'
      ? collection.reason || 'module_deadline_exhausted'
      : 'materialization_deadline_exhausted'
    : baselineCoverageDegraded
      ? baselineByteLimitReached
        ? 'baseline_byte_limit'
        : 'baseline_storage_degraded'
      : collection.reason;
  return {
    findings,
    summaries,
    metrics: {
      status,
      snapshotSchemaVersion: API_CONTRACT_SNAPSHOT_SCHEMA_VERSION,
      canonicalizationVersion: API_CONTRACT_CANONICALIZATION_VERSION,
      contracts: summaries.length,
      snapshotsMaterialized,
      changes: findings.filter((finding) => finding.type === 'api_contract_diff').length,
      baselineBytesRead: Number(previousSnapshots?.baselineBytesRead) || 0,
      baselineBytesRetained: Number(previousSnapshots?.baselineBytesRetained) || 0,
      baselineByteLimit: Number(previousSnapshots?.baselineByteLimit) || 0,
      baselineByteLimitReached,
      discoveryPolicy: collection.discoveryPolicy,
      coverage: collection.coverage,
      outcomes,
    },
    outcomes,
    status,
    reason,
  };
}
