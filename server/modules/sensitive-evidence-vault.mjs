import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomUUID,
} from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  mkdir,
  open,
  readdir,
  realpath,
  rm,
  stat,
} from 'node:fs/promises';
import path from 'node:path';

const MAX_EVIDENCE_BYTES = 8 * 1024 * 1024;
const MAX_TTL_MS = 30 * 24 * 60 * 60 * 1_000;
const VERSION = 1;

function digest(value) {
  return createHash('sha256').update(value).digest('hex');
}

function safeKind(value) {
  return String(value || 'sensitive_evidence').toLowerCase().replace(/[^a-z0-9_.-]/g, '_').slice(0, 80);
}

function validateKey(key) {
  const bytes = Buffer.from(key || '');
  if (bytes.length !== 32) throw new Error('sensitive_evidence_vault: chave AES-256 de 32 bytes obrigatoria');
  return Buffer.from(bytes);
}

function inside(root, candidate) {
  const rel = path.relative(root, candidate);
  return rel && !rel.startsWith('..') && !path.isAbsolute(rel);
}

export class SensitiveEvidenceVault {
  #key;
  #root;
  #ready;
  #closed = false;
  #audit;

  constructor({ root, key, optIn = false, audit = () => {} } = {}) {
    if (optIn !== true) throw new Error('sensitive_evidence_vault: opt-in explicito obrigatorio');
    if (!path.isAbsolute(String(root || ''))) throw new Error('sensitive_evidence_vault: root absoluto obrigatorio');
    this.#root = path.resolve(String(root));
    this.#key = validateKey(key);
    this.#audit = typeof audit === 'function' ? audit : () => {};
    this.#ready = this.#initialize();
  }

  async #initialize() {
    await mkdir(this.#root, { recursive: true, mode: 0o700 });
    await stat(this.#root).then((value) => {
      if (!value.isDirectory()) throw new Error('sensitive_evidence_vault: root nao e diretorio');
    });
    this.#root = await realpath(this.#root);
  }

  #assertOpen() {
    if (this.#closed || !this.#key) throw new Error('sensitive_evidence_vault: fechado');
  }

  #pathFor(locator) {
    if (!/^[a-f0-9-]{36}\.vault$/i.test(String(locator || ''))) {
      throw new Error('sensitive_evidence_vault: locator invalido');
    }
    const candidate = path.resolve(this.#root, locator);
    if (!inside(this.#root, candidate)) throw new Error('sensitive_evidence_vault: path fora do vault');
    return candidate;
  }

  async put(value, { kind = 'sensitive_evidence', ttlMs = 24 * 60 * 60 * 1_000 } = {}) {
    this.#assertOpen();
    await this.#ready;
    const plaintext = Buffer.isBuffer(value)
      ? Buffer.from(value)
      : Buffer.from(typeof value === 'string' ? value : JSON.stringify(value), 'utf8');
    if (!plaintext.length || plaintext.length > MAX_EVIDENCE_BYTES) {
      plaintext.fill(0);
      throw new Error('sensitive_evidence_vault: tamanho de evidencia invalido');
    }
    const boundedTtl = Math.min(MAX_TTL_MS, Math.max(1_000, Math.floor(Number(ttlMs) || 0)));
    const createdAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + boundedTtl).toISOString();
    const fingerprint = digest(plaintext);
    const secretRef = `vault:sha256:${fingerprint}`;
    const locator = `${randomUUID()}.vault`;
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.#key, iv);
    cipher.setAAD(Buffer.from(`${VERSION}:${secretRef}:${expiresAt}`, 'utf8'));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    plaintext.fill(0);
    const envelope = Buffer.from(`${JSON.stringify({
      version: VERSION,
      algorithm: 'aes-256-gcm',
      kind: safeKind(kind),
      secretRef,
      createdAt,
      expiresAt,
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
    })}\n`, 'utf8');
    const target = this.#pathFor(locator);
    const handle = await open(target, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    try {
      await handle.writeFile(envelope);
      await handle.chmod(0o600);
      await handle.sync();
    } finally {
      await handle.close();
      envelope.fill(0);
      ciphertext.fill(0);
    }
    this.#audit({ action: 'put', secretRef, kind: safeKind(kind), createdAt, expiresAt });
    return { secretRef, fingerprint, locator, kind: safeKind(kind), createdAt, expiresAt };
  }

  async get({ secretRef, locator } = {}) {
    this.#assertOpen();
    await this.#ready;
    const target = this.#pathFor(locator);
    const noFollow = typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0;
    const handle = await open(target, fsConstants.O_RDONLY | noFollow);
    let raw;
    try {
      const info = await handle.stat();
      if (!info.isFile() || info.size > MAX_EVIDENCE_BYTES * 2) throw new Error('sensitive_evidence_vault: envelope invalido');
      raw = await handle.readFile('utf8');
    } finally {
      await handle.close();
    }
    const envelope = JSON.parse(raw);
    if (envelope.version !== VERSION || envelope.algorithm !== 'aes-256-gcm') throw new Error('sensitive_evidence_vault: versao invalida');
    if (!secretRef || envelope.secretRef !== secretRef) throw new Error('sensitive_evidence_vault: secretRef divergente');
    if (Date.parse(envelope.expiresAt) <= Date.now()) throw new Error('sensitive_evidence_vault: evidencia expirada');
    const decipher = createDecipheriv('aes-256-gcm', this.#key, Buffer.from(envelope.iv, 'base64'));
    decipher.setAAD(Buffer.from(`${VERSION}:${secretRef}:${envelope.expiresAt}`, 'utf8'));
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
      decipher.final(),
    ]);
    if (digest(plaintext) !== secretRef.replace(/^vault:sha256:/, '')) {
      plaintext.fill(0);
      throw new Error('sensitive_evidence_vault: fingerprint divergente');
    }
    this.#audit({ action: 'get', secretRef, kind: envelope.kind });
    return plaintext;
  }

  async delete({ secretRef, locator } = {}) {
    this.#assertOpen();
    await this.#ready;
    await rm(this.#pathFor(locator), { force: true });
    this.#audit({ action: 'delete', secretRef: String(secretRef || '') });
  }

  async cleanupExpired({ now = Date.now() } = {}) {
    this.#assertOpen();
    await this.#ready;
    let removed = 0;
    const noFollow = typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0;
    for (const entry of await readdir(this.#root, { withFileTypes: true })) {
      if (!entry.isFile() || !/^[a-f0-9-]{36}\.vault$/i.test(entry.name)) continue;
      const target = this.#pathFor(entry.name);
      try {
        const raw = JSON.parse(await open(target, fsConstants.O_RDONLY | noFollow).then(async (handle) => {
          try { return await handle.readFile('utf8'); } finally { await handle.close(); }
        }));
        if (Date.parse(raw.expiresAt) > now) continue;
        await rm(target, { force: true });
        removed += 1;
        this.#audit({ action: 'expire', secretRef: String(raw.secretRef || '') });
      } catch {
        // Corrupt/unknown files are not followed or exposed; operators can
        // investigate them separately rather than deleting evidence silently.
      }
    }
    return { removed };
  }

  close() {
    if (this.#key) this.#key.fill(0);
    this.#key = null;
    this.#closed = true;
  }
}
