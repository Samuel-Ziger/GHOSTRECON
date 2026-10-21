import { gunzipSync } from 'node:zlib';

import { UA, limits } from '../config.js';
import { urlInReconScope } from './scope.js';
import { fetchScoped } from './scoped-fetch.mjs';

export { hostnameInScope } from './scope.js';

const MAX_XML_BYTES = 2_000_000;
const MAX_LOCS_PER_DOCUMENT = 5_000;
const MAX_SITEMAP_URL_LENGTH = 4_096;
const XML_NAME = '[A-Za-z_][A-Za-z0-9_.-]*(?::[A-Za-z_][A-Za-z0-9_.-]*)?';
const XML_NAMESPACE_URI = 'http://www.w3.org/XML/1998/namespace';
const XMLNS_NAMESPACE_URI = 'http://www.w3.org/2000/xmlns/';
const SITEMAP_NAMESPACE_URI = 'http://www.sitemaps.org/schemas/sitemap/0.9';

function extractSitemapLines(robotsText) {
  const out = [];
  if (!robotsText) return out;
  for (const line of robotsText.split(/\r?\n/)) {
    const m = line.match(/^\s*Sitemap:\s*(\S+)/i);
    if (m) out.push(m[1].trim());
  }
  return out;
}

function extractDisallowInteresting(robotsText, rootDomain) {
  const paths = [];
  if (!robotsText) return paths;
  for (const line of robotsText.split(/\r?\n/)) {
    const m = line.match(/^\s*Disallow:\s*(\S+)/i);
    if (!m) continue;
    const p = m[1].trim();
    if (!p || p === '/') continue;
    if (/\/(admin|api|internal|debug|backup|\.git|config|test|dev|staging)/i.test(p)) paths.push(p);
  }
  return [...new Set(paths)].slice(0, 30);
}

function boundedInteger(value, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(parsed)));
}

function isXmlCodePoint(point) {
  return point === 0x09
    || point === 0x0a
    || point === 0x0d
    || (point >= 0x20 && point <= 0xd7ff)
    || (point >= 0xe000 && point <= 0xfffd)
    || (point >= 0x10000 && point <= 0x10ffff);
}

function validateXmlCharacters(value) {
  for (const character of value) {
    if (!isXmlCodePoint(character.codePointAt(0))) throw new Error('caractere XML inválido');
  }
}

function decodeXmlText(value) {
  validateXmlCharacters(value);
  const named = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
  let cursor = 0;
  let decoded = '';

  while (cursor < value.length) {
    const ampersand = value.indexOf('&', cursor);
    if (ampersand === -1) {
      decoded += value.slice(cursor);
      break;
    }
    decoded += value.slice(cursor, ampersand);
    const semicolon = value.indexOf(';', ampersand + 1);
    if (semicolon === -1 || semicolon - ampersand > 64) {
      throw new Error('entidade XML incompleta');
    }
    const entity = value.slice(ampersand + 1, semicolon);
    if (!entity || entity.includes('&') || /\s/.test(entity)) {
      throw new Error('entidade XML inválida');
    }
    if (Object.hasOwn(named, entity)) {
      decoded += named[entity];
    } else {
      if (!/^#(?:x[\da-f]+|\d+)$/i.test(entity)) {
        throw new Error('entidade XML não suportada');
      }
      const point = entity[1].toLowerCase() === 'x'
        ? Number.parseInt(entity.slice(2), 16)
        : Number(entity.slice(1));
      if (!Number.isSafeInteger(point) || !isXmlCodePoint(point)) {
        throw new Error('entidade XML inválida');
      }
      decoded += String.fromCodePoint(point);
    }
    cursor = semicolon + 1;
  }
  return decoded;
}

function markupEnd(source, start) {
  let quote = '';
  for (let index = start + 1; index < source.length; index += 1) {
    const character = source[index];
    if (quote) {
      if (character === quote) quote = '';
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      continue;
    }
    if (character === '>') return index;
  }
  return -1;
}

function parseStartMarkup(markup) {
  let content = markup.slice(1, -1).trimEnd();
  const selfClosing = content.endsWith('/');
  if (selfClosing) content = content.slice(0, -1).trimEnd();
  const nameMatch = content.match(new RegExp(`^(${XML_NAME})(?=\\s|$)`));
  if (!nameMatch) throw new Error('elemento XML inválido');

  const name = nameMatch[1];
  const attributes = new Map();
  let cursor = name.length;
  while (cursor < content.length) {
    const whitespace = content.slice(cursor).match(/^\s+/);
    if (!whitespace) throw new Error('atributo XML sem separador');
    cursor += whitespace[0].length;
    if (cursor >= content.length) break;

    const attributeMatch = content.slice(cursor).match(new RegExp(`^(${XML_NAME})`));
    if (!attributeMatch) throw new Error('nome de atributo XML inválido');
    const attribute = attributeMatch[1];
    if (attributes.has(attribute)) throw new Error('atributo XML duplicado');
    cursor += attribute.length;
    while (/\s/.test(content[cursor] || '')) cursor += 1;
    if (content[cursor] !== '=') throw new Error('atributo XML sem valor');
    cursor += 1;
    while (/\s/.test(content[cursor] || '')) cursor += 1;
    const quote = content[cursor];
    if (quote !== '"' && quote !== "'") throw new Error('atributo XML sem aspas');
    cursor += 1;
    const end = content.indexOf(quote, cursor);
    if (end === -1) throw new Error('atributo XML incompleto');
    const value = content.slice(cursor, end);
    if (value.includes('<')) throw new Error('atributo XML contém caractere proibido');
    attributes.set(attribute, decodeXmlText(value));
    cursor = end + 1;
  }
  return { name, selfClosing, attributes };
}

function localName(name) {
  return String(name || '').split(':').at(-1);
}

function namespacePrefix(name) {
  const parts = String(name || '').split(':');
  return parts.length === 2 ? parts[0] : '';
}

function resolveElementNamespace(name, namespaces) {
  const prefix = namespacePrefix(name);
  if (prefix === 'xmlns') throw new Error('prefixo xmlns reservado');
  if (!prefix) return namespaces.get('') || '';
  if (!namespaces.has(prefix)) throw new Error('prefixo XML sem namespace declarado');
  return namespaces.get(prefix);
}

function applyNamespaceDeclarations(parentNamespaces, attributes) {
  const namespaces = new Map(parentNamespaces || [['xml', XML_NAMESPACE_URI]]);
  for (const [name, uri] of attributes) {
    if (name !== 'xmlns' && !name.startsWith('xmlns:')) continue;
    const prefix = name === 'xmlns' ? '' : name.slice('xmlns:'.length);
    if (prefix === 'xmlns'
      || (prefix && prefix.toLowerCase().startsWith('xml') && prefix !== 'xml')
      || (prefix && !uri)
      || uri === XMLNS_NAMESPACE_URI
      || (prefix === 'xml' && uri !== XML_NAMESPACE_URI)
      || (prefix !== 'xml' && uri === XML_NAMESPACE_URI)) {
      throw new Error('declaração de namespace XML inválida');
    }
    namespaces.set(prefix, uri);
  }
  return namespaces;
}

function validateAttributeNamespaces(attributes, namespaces) {
  const expandedNames = new Set();
  for (const name of attributes.keys()) {
    if (name === 'xmlns' || name.startsWith('xmlns:')) continue;
    const prefix = namespacePrefix(name);
    const uri = prefix ? resolveElementNamespace(name, namespaces) : '';
    const expanded = `${uri}\u0000${localName(name)}`;
    if (expandedNames.has(expanded)) throw new Error('atributo XML duplicado por namespace');
    expandedNames.add(expanded);
  }
}

/**
 * Parser estrito do subconjunto XML usado pelo protocolo Sitemap.
 *
 * Ele valida balanceamento, atributos, entidades, CDATA, namespaces e uma única
 * raiz. DTD e entidades externas falham fechadas. Elementos de extensão são
 * aceitos, mas apenas <loc> na posição definida pelo protocolo vira candidato.
 * Não é um parser XML genérico.
 */
export function parseSitemapDocument(xml, limit = 5000) {
  const source = String(xml || '').replace(/^\uFEFF/, '');
  if (Buffer.byteLength(source, 'utf8') > MAX_XML_BYTES) throw new Error('XML excede limite');
  validateXmlCharacters(source);

  const outputLimit = boundedInteger(limit, MAX_LOCS_PER_DOCUMENT, {
    min: 0,
    max: MAX_LOCS_PER_DOCUMENT,
  });
  const stack = [];
  const urls = [];
  let root = null;
  let rootClosed = false;
  let declarationSeen = false;
  let locCapture = null;
  let locCount = 0;
  let cursor = 0;

  while (cursor < source.length) {
    if (source[cursor] !== '<') {
      const next = source.indexOf('<', cursor);
      const end = next === -1 ? source.length : next;
      const rawText = source.slice(cursor, end);
      const text = decodeXmlText(rawText);
      if (!stack.length && text.trim()) throw new Error('texto fora da raiz');
      if (locCapture && stack.length === locCapture.depth) locCapture.text += text;
      cursor = end;
      continue;
    }

    if (source.startsWith('<!--', cursor)) {
      const end = source.indexOf('-->', cursor + 4);
      if (end === -1) throw new Error('comentário XML incompleto');
      const comment = source.slice(cursor + 4, end);
      if (comment.includes('--') || comment.endsWith('-')) throw new Error('comentário XML inválido');
      cursor = end + 3;
      continue;
    }

    if (source.startsWith('<![CDATA[', cursor)) {
      if (!stack.length) throw new Error('CDATA fora da raiz');
      const end = source.indexOf(']]>', cursor + 9);
      if (end === -1) throw new Error('CDATA incompleta');
      const text = source.slice(cursor + 9, end);
      validateXmlCharacters(text);
      if (locCapture && stack.length === locCapture.depth) locCapture.text += text;
      cursor = end + 3;
      continue;
    }

    if (source.startsWith('<?', cursor)) {
      const end = source.indexOf('?>', cursor + 2);
      if (end === -1) throw new Error('processing instruction incompleta');
      const instruction = source.slice(cursor + 2, end);
      const target = instruction.match(new RegExp(`^(${XML_NAME})(?=\\s|$)`))?.[1] || '';
      if (!target) throw new Error('processing instruction inválida');
      if (target.toLowerCase() === 'xml') {
        if (declarationSeen || root || target !== 'xml') throw new Error('declaração XML inválida');
        const encoding = instruction.match(/\bencoding\s*=\s*(["'])([^"']+)\1/i)?.[2];
        if (encoding && !/^utf-?8$/i.test(encoding)) throw new Error('encoding XML não suportado');
        declarationSeen = true;
      }
      cursor = end + 2;
      continue;
    }

    if (source.startsWith('<!', cursor)) throw new Error('DTD/declaração XML não permitida');

    const end = markupEnd(source, cursor);
    if (end === -1) throw new Error('elemento XML incompleto');
    const markup = source.slice(cursor, end + 1);
    const closeMatch = markup.match(new RegExp(`^<\\/(${XML_NAME})\\s*>$`));
    if (closeMatch) {
      const closingName = closeMatch[1];
      if (stack.at(-1)?.name !== closingName) throw new Error('XML desbalanceado');
      if (locCapture && locCapture.depth === stack.length) {
        if (localName(closingName) !== 'loc') throw new Error('loc XML inválido');
        const candidate = locCapture.text.trim();
        if (candidate) {
          locCount += 1;
          if (urls.length < outputLimit) urls.push(candidate);
        }
        locCapture = null;
      }
      stack.pop();
      if (!stack.length) rootClosed = true;
      cursor = end + 1;
      continue;
    }

    if (rootClosed) throw new Error('múltiplas raízes XML');
    if (locCapture) throw new Error('loc não pode conter elementos');
    const { name, selfClosing, attributes } = parseStartMarkup(markup);
    const parentNamespaces = stack.at(-1)?.namespaces || new Map([['xml', XML_NAMESPACE_URI]]);
    const namespaces = applyNamespaceDeclarations(parentNamespaces, attributes);
    validateAttributeNamespaces(attributes, namespaces);
    const elementNamespace = resolveElementNamespace(name, namespaces);
    const nameLocal = localName(name);
    if (!stack.length) {
      if (root) throw new Error('múltiplas raízes XML');
      root = nameLocal;
      if (!['urlset', 'sitemapindex'].includes(root)) throw new Error('raiz não é sitemap');
      if (elementNamespace && elementNamespace !== SITEMAP_NAMESPACE_URI) {
        throw new Error('namespace raiz não é Sitemap');
      }
    }
    const rootNamespace = stack[0]?.namespaceUri ?? elementNamespace;
    const parent = stack.at(-1);
    const grandparent = stack.at(-2);
    const expectedLoc = nameLocal === 'loc' && (
      (root === 'urlset' && parent?.local === 'url' && grandparent?.local === 'urlset')
      || (root === 'sitemapindex' && parent?.local === 'sitemap' && grandparent?.local === 'sitemapindex')
    ) && elementNamespace === rootNamespace
      && parent?.namespaceUri === rootNamespace
      && grandparent?.namespaceUri === rootNamespace;
    if (!selfClosing) {
      stack.push({ name, local: nameLocal, namespaceUri: elementNamespace, namespaces });
      if (expectedLoc) locCapture = { depth: stack.length, text: '' };
    } else if (!stack.length) {
      rootClosed = true;
    }
    if (stack.length > 16) throw new Error('XML excede profundidade');
    cursor = end + 1;
  }
  if (stack.length || !rootClosed || !root || locCapture) throw new Error('XML incompleto');
  return {
    kind: root === 'sitemapindex' ? 'index' : 'pages',
    urls,
    locCount,
    truncated: locCount > urls.length,
  };
}

export function canonicalizeSitemapUrl(value) {
  const raw = String(value || '').trim();
  if (!raw || raw.length > MAX_SITEMAP_URL_LENGTH || /[\u0000-\u0020\u007f]/.test(raw)) return null;
  try {
    const parsed = new URL(raw);
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return null;
    parsed.hash = '';
    return parsed.href.length <= MAX_SITEMAP_URL_LENGTH ? parsed.href : null;
  } catch {
    return null;
  }
}

async function readBoundedResponseBody(response, maxBytes) {
  const limit = boundedInteger(maxBytes, MAX_XML_BYTES, { min: 1, max: MAX_XML_BYTES });
  const contentLength = Number(response?.headers?.get?.('content-length'));
  if (Number.isFinite(contentLength) && contentLength > limit) {
    await response.body?.cancel?.().catch(() => {});
    return { bytes: Buffer.alloc(0), bytesRead: 0, tooLarge: true };
  }
  if (!response?.body) return { bytes: Buffer.alloc(0), bytesRead: 0, tooLarge: false };

  const reader = response.body.getReader?.();
  if (!reader) throw new Error('corpo HTTP não é stream limitado');
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value || []);
      if (total + chunk.length > limit) {
        total += chunk.length;
        await reader.cancel().catch(() => {});
        return { bytes: Buffer.alloc(0), bytesRead: total, tooLarge: true };
      }
      chunks.push(chunk);
      total += chunk.length;
    }
  } finally {
    try { reader.releaseLock?.(); } catch { /* noop */ }
  }
  return { bytes: Buffer.concat(chunks, total), bytesRead: total, tooLarge: false };
}

function decodeSitemapBody(bytes, maxBytes) {
  const limit = boundedInteger(maxBytes, MAX_XML_BYTES, { min: 1, max: MAX_XML_BYTES });
  let payload = bytes;
  let gzip = false;
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    gzip = true;
    try {
      payload = gunzipSync(bytes, { maxOutputLength: limit + 1 });
    } catch (error) {
      const tooLarge = error?.code === 'ERR_BUFFER_TOO_LARGE'
        || /larger than|output length|buffer size/i.test(error?.message || '');
      return { error: tooLarge ? 'response_too_large' : 'invalid_gzip', gzip };
    }
  }
  if (payload.length > limit) return { error: 'response_too_large', gzip };
  try {
    return {
      text: new TextDecoder('utf-8', { fatal: true }).decode(payload),
      decodedBytes: payload.length,
      gzip,
    };
  } catch {
    return { error: 'invalid_encoding', gzip };
  }
}

/**
 * @param {string} baseOrigin ex. https://www.example.com/
 * @param {string} rootDomain ex. example.com
 * @param {string[]} [outOfScopeRules] hosts fora de escopo (env GHOSTRECON_OUT_OF_SCOPE)
 */
export async function crawlRobotsAndSitemapsForOrigin(
  baseOrigin,
  rootDomain,
  outOfScopeRules = [],
  scopePolicy = null,
  {
    signal = null,
    fetchImpl = globalThis.fetch,
    timeoutMs = 60_000,
    maxBytes = MAX_XML_BYTES,
    maxPages = limits.maxSitemapUrlsPerHost,
    maxSitemapFiles = limits.maxSitemapFilesTotal,
    maxDepth = 4,
    maxRedirects = 5,
    urlAllowed = null,
  } = {},
) {
  const result = {
    robotsUrl: null,
    robotsOk: false,
    sitemapUrls: [],
    disallowHints: [],
    pageUrls: [],
    pageSources: [],
    error: null,
    status: 'done',
    outcomes: [],
    provenance: {
      schemaVersion: 1,
      collector: 'robots_sitemap',
      origin: null,
    },
    metrics: {
      sitemapCandidates: 0,
      sitemapFilesFetched: 0,
      pageCandidates: 0,
      pageUrlsAccepted: 0,
      invalidUrls: 0,
      outOfScopeUrls: 0,
      duplicateUrls: 0,
      filesSkippedByLimit: 0,
      urlsSkippedByLimit: 0,
      indexesStoppedByDepth: 0,
    },
  };

  let origin;
  try {
    origin = new URL(baseOrigin);
  } catch (e) {
    result.error = e?.message || String(e);
    result.status = 'failed';
    return result;
  }
  if (
    !['http:', 'https:'].includes(origin.protocol)
    || origin.username
    || origin.password
    || !urlInReconScope(origin.href, rootDomain, outOfScopeRules, scopePolicy)
  ) {
    result.error = 'origem fora do escopo autorizado';
    result.status = 'refused';
    return result;
  }
  result.provenance.origin = origin.origin;

  const robotsUrl = new URL('/robots.txt', origin).href;
  result.robotsUrl = robotsUrl;
  const perRequestTimeout = boundedInteger(limits.robotsFetchTimeoutMs, 12_000, {
    min: 1,
    max: 120_000,
  });
  const effectiveMaxBytes = boundedInteger(maxBytes, MAX_XML_BYTES, {
    min: 1,
    max: MAX_XML_BYTES,
  });
  const effectiveMaxPages = boundedInteger(maxPages, limits.maxSitemapUrlsPerHost, {
    min: 1,
    max: limits.maxSitemapUrlsPerHost,
  });
  const effectiveMaxFiles = boundedInteger(maxSitemapFiles, limits.maxSitemapFilesTotal, {
    min: 1,
    max: limits.maxSitemapFilesTotal,
  });
  const effectiveMaxDepth = boundedInteger(maxDepth, 4, { min: 0, max: 8 });
  const effectiveMaxRedirects = boundedInteger(maxRedirects, 5, { min: 0, max: 5 });
  const moduleTimeout = boundedInteger(timeoutMs, 60_000, { min: 1, max: 120_000 });
  const moduleTimeoutSignal = AbortSignal.timeout(moduleTimeout);
  const moduleSignal = AbortSignal.any([
    ...(signal ? [signal] : []),
    moduleTimeoutSignal,
  ]);
  const allowed = (candidate) => {
    try {
      const url = new URL(candidate);
      return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password
        && urlInReconScope(url.href, rootDomain, outOfScopeRules, scopePolicy)
        && (typeof urlAllowed === 'function' ? urlAllowed(url.href) === true : scopePolicy ? true : url.origin === origin.origin);
    } catch { return false; }
  };

  async function fetchText(url, provenance) {
    if (signal?.aborted) signal.throwIfAborted();
    const outcome = {
      url,
      role: provenance.role,
      depth: provenance.depth ?? null,
      parentUrl: provenance.parentUrl || null,
      discoveredBy: provenance.discoveredBy,
      state: 'failed',
    };
    result.outcomes.push(outcome);
    if (moduleTimeoutSignal.aborted) {
      outcome.state = 'timeout';
      return null;
    }
    const requestTimeoutSignal = AbortSignal.timeout(perRequestTimeout);
    const requestSignal = AbortSignal.any([moduleSignal, requestTimeoutSignal]);
    try {
      const res = await fetchScoped(url, {
        headers: { 'User-Agent': UA, Accept: 'text/plain,application/xml,text/xml' },
        signal: requestSignal,
        fetchImpl,
        urlAllowed: allowed,
        maxRedirects: effectiveMaxRedirects,
      });
      outcome.httpStatus = res.status;
      outcome.finalUrl = canonicalizeSitemapUrl(res.url || url) || url;
      const contentType = String(res.headers?.get?.('content-type') || '').slice(0, 128);
      if (contentType) outcome.contentType = contentType;
      if (!res.ok) {
        await res.body?.cancel?.().catch(() => {});
        if ([404, 410].includes(res.status)) outcome.state = 'absent';
        else if ([401, 403].includes(res.status)) outcome.state = 'denied';
        return null;
      }
      const body = await readBoundedResponseBody(res, effectiveMaxBytes);
      moduleSignal.throwIfAborted();
      outcome.bytesRead = body.bytesRead;
      if (body.tooLarge) {
        outcome.state = 'response_too_large';
        return null;
      }
      const decoded = decodeSitemapBody(body.bytes, effectiveMaxBytes);
      outcome.gzip = decoded.gzip === true;
      if (decoded.error) {
        outcome.state = decoded.error;
        return null;
      }
      outcome.decodedBytes = decoded.decodedBytes;
      outcome.state = 'done';
      return { text: decoded.text, outcome };
    } catch (error) {
      if (signal?.aborted) throw signal.reason || error;
      if (moduleTimeoutSignal.aborted || requestTimeoutSignal.aborted || error?.name === 'TimeoutError') {
        outcome.state = 'timeout';
      }
      else if (error?.code === 'OUT_OF_SCOPE') outcome.state = 'scope_denied';
      else if (error?.code === 'TOO_MANY_REDIRECTS') outcome.state = 'redirect_limit';
      return null;
    }
  }

  let robotsSitemaps = [];
  const robots = await fetchText(robotsUrl, {
    role: 'robots',
    discoveredBy: 'origin',
  });
  if (robots) {
    try {
      result.robotsOk = true;
      robotsSitemaps = extractSitemapLines(robots.text);
      result.disallowHints = extractDisallowInteresting(robots.text, rootDomain);
    } catch {
      robots.outcome.state = 'invalid_robots';
      result.robotsOk = false;
    }
  }

  const defaultSitemap = new URL('/sitemap.xml', origin).href;
  const sitemapQueue = [];
  const knownSitemaps = new Set();
  const seenSitemaps = new Set();
  const pages = new Map();
  let moduleTimedOut = false;

  const accountRejectedUrl = (raw, kind) => {
    const canonical = canonicalizeSitemapUrl(raw);
    if (!canonical) {
      result.metrics.invalidUrls += 1;
      return null;
    }
    if (!allowed(canonical)) {
      result.metrics.outOfScopeUrls += 1;
      return null;
    }
    if (kind === 'sitemap') result.metrics.sitemapCandidates += 1;
    else result.metrics.pageCandidates += 1;
    return canonical;
  };

  const enqueueSitemap = (raw, provenance) => {
    const canonical = accountRejectedUrl(raw, 'sitemap');
    if (!canonical) return false;
    if (knownSitemaps.has(canonical)) {
      result.metrics.duplicateUrls += 1;
      return false;
    }
    if (knownSitemaps.size >= effectiveMaxFiles) {
      result.metrics.filesSkippedByLimit += 1;
      return false;
    }
    knownSitemaps.add(canonical);
    result.sitemapUrls.push(canonical);
    sitemapQueue.push({ url: canonical, ...provenance });
    return true;
  };

  for (const candidate of robotsSitemaps) {
    enqueueSitemap(candidate, {
      depth: 0,
      parentUrl: robotsUrl,
      rootSitemapUrl: null,
      discoveredBy: 'robots',
    });
  }
  enqueueSitemap(defaultSitemap, {
    depth: 0,
    parentUrl: robotsUrl,
    rootSitemapUrl: null,
    discoveredBy: 'default',
  });

  while (sitemapQueue.length && pages.size < effectiveMaxPages) {
    if (signal?.aborted) signal.throwIfAborted();
    if (moduleTimeoutSignal.aborted) {
      moduleTimedOut = true;
      break;
    }
    const item = sitemapQueue.shift();
    if (seenSitemaps.has(item.url)) continue;
    seenSitemaps.add(item.url);

    const fetched = await fetchText(item.url, {
      role: 'sitemap',
      depth: item.depth,
      parentUrl: item.parentUrl,
      discoveredBy: item.discoveredBy,
    });
    if (!fetched) continue;
    result.metrics.sitemapFilesFetched += 1;

    let parsed;
    try {
      parsed = parseSitemapDocument(fetched.text, MAX_LOCS_PER_DOCUMENT);
      fetched.outcome.documentKind = parsed.kind;
      fetched.outcome.locCount = parsed.locCount;
      fetched.outcome.truncated = parsed.truncated;
    } catch {
      fetched.outcome.state = 'invalid_xml';
      continue;
    }

    const documentUrl = fetched.outcome.finalUrl || item.url;
    if (documentUrl !== item.url && !seenSitemaps.has(documentUrl)) {
      seenSitemaps.add(documentUrl);
    }
    const rootSitemapUrl = item.rootSitemapUrl || documentUrl;

    if (parsed.kind === 'index') {
      if (item.depth >= effectiveMaxDepth) {
        result.metrics.indexesStoppedByDepth += 1;
        result.metrics.filesSkippedByLimit += parsed.urls.length;
        continue;
      }
      for (const nested of parsed.urls) {
        enqueueSitemap(nested, {
          depth: item.depth + 1,
          parentUrl: documentUrl,
          rootSitemapUrl,
          discoveredBy: 'sitemap_index',
        });
      }
      if (parsed.truncated) {
        result.metrics.filesSkippedByLimit += Math.max(1, parsed.locCount - parsed.urls.length);
      }
      continue;
    }

    for (const rawPage of parsed.urls) {
      const pageUrl = accountRejectedUrl(rawPage, 'page');
      if (!pageUrl) continue;
      if (pages.has(pageUrl)) {
        result.metrics.duplicateUrls += 1;
        continue;
      }
      if (pages.size >= effectiveMaxPages) {
        result.metrics.urlsSkippedByLimit += 1;
        continue;
      }
      pages.set(pageUrl, {
        url: pageUrl,
        sitemapUrl: documentUrl,
        requestedSitemapUrl: item.url,
        parentSitemapUrl: item.parentUrl,
        rootSitemapUrl,
        depth: item.depth,
      });
    }
    if (parsed.truncated) {
      result.metrics.urlsSkippedByLimit += Math.max(1, parsed.locCount - parsed.urls.length);
    }
  }

  if (pages.size >= effectiveMaxPages && sitemapQueue.length) {
    result.metrics.urlsSkippedByLimit += 1;
  }
  result.pageSources = [...pages.values()];
  result.pageUrls = result.pageSources.map((entry) => entry.url);
  result.metrics.pageUrlsAccepted = result.pageUrls.length;

  // 401/403 comprovam que a tentativa ocorreu, mas não que a superfície foi
  // inventariada; portanto degradam cobertura em vez de virar negativo limpo.
  const healthyStates = new Set(['done', 'absent']);
  const unhealthyOutcome = result.outcomes.some((outcome) => !healthyStates.has(outcome.state));
  const limited = result.metrics.filesSkippedByLimit > 0
    || result.metrics.urlsSkippedByLimit > 0
    || result.metrics.indexesStoppedByDepth > 0;
  if (unhealthyOutcome || limited || moduleTimedOut) {
    const observed = result.outcomes.some((outcome) => healthyStates.has(outcome.state));
    result.status = observed ? 'partial' : 'failed';
    result.error = moduleTimedOut
      ? 'coleta interrompida pelo timeout seguro do módulo; consulte metrics/outcomes'
      : limited
      ? 'coleta limitada pelos orçamentos seguros; consulte metrics/outcomes'
      : 'coleta incompleta; consulte outcomes';
  }
  return result;
}
