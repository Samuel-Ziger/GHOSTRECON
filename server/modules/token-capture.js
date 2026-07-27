/**
 * token-capture.js
 *
 * Quando um finding do tipo 'secret' é gerado, baixa a página onde o token foi
 * encontrado e, somente quando explicitamente habilitado, grava evidência
 * redigida em tokens/<domain>/. Material cru nunca entra em arquivo, curl,
 * evento ou log.
 */

import https from 'node:https';
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { validateToken } from './token-validator.js';
import {
  rawSecretFromFinding,
  redactSecretText,
  safeSecretReference,
} from './secret-safety.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(__dirname, '..', '..');
export const TOKENS_DIR = path.join(REPO_ROOT, 'tokens');

const MAX_BODY     = 2 * 1024 * 1024; // 2 MB
const TIMEOUT_MS   = 15_000;
const MAX_REDIRECTS = 5;

function shortHash(str) {
  return createHash('sha256').update(String(str)).digest('hex').slice(0, 8);
}

function safeFilename(str) {
  return String(str || '').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 60);
}

async function fetchFollowRedirects(urlStr, redirectsLeft = MAX_REDIRECTS) {
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(urlStr); } catch { return reject(new Error(`URL inválida: ${urlStr}`)); }

    const mod = parsed.protocol === 'https:' ? https : http;
    const req = mod.get(urlStr, {
      timeout: TIMEOUT_MS,
      headers: {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Cache-Control': 'no-cache',
      },
    }, async (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && redirectsLeft > 0) {
        res.destroy();
        try {
          const next = new URL(res.headers.location, urlStr).toString();
          resolve(await fetchFollowRedirects(next, redirectsLeft - 1));
        } catch (e) { reject(e); }
        return;
      }
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { body += c; if (body.length > MAX_BODY) req.destroy(); });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body, finalUrl: urlStr }));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error(`timeout ${TIMEOUT_MS}ms`)));
    req.on('error', reject);
  });
}

export async function captureTokenFinding(
  finding,
  domain,
  emit,
  {
    enabled = false,
    fetchSource = false,
    networkValidation = false,
    outputDir = TOKENS_DIR,
    fetchImpl = fetchFollowRedirects,
    probeImpl = null,
  } = {},
) {
  if (enabled !== true) return { skipped: 'disabled' };
  const { url, value, meta } = finding;
  if (!url) return;
  const rawMaterial = rawSecretFromFinding(finding);
  const safeRef = safeSecretReference(rawMaterial || value);
  const safeUrl = redactSecretText(url, rawMaterial);

  const domainSlug = safeFilename(domain);
  const domainDir  = path.join(outputDir, domainSlug);

  try {
    await fs.mkdir(domainDir, { recursive: true, mode: 0o700 });
    await fs.chmod(domainDir, 0o700);
  } catch (e) {
    emit?.({ type: 'log', msg: `[token-capture] falha ao criar pasta: ${e.message}`, level: 'warn' });
    return;
  }

  const kindMatch = String(value || '').match(/^\[([^\]]+)\]/);
  const kind = safeFilename(kindMatch?.[1] || 'secret');
  const hash = shortHash(url + (value || ''));
  const base = `${kind}_${hash}`;

  if (fetchSource) {
    emit?.({ type: 'log', msg: `[token-capture] a baixar ${safeUrl} …`, level: 'info' });
  }

  let fetchResult = null;
  if (fetchSource === true) {
    try {
      fetchResult = await fetchImpl(url);
      emit?.({
        type: 'log',
        msg: `[token-capture] HTTP ${fetchResult.status} — ${redactSecretText(fetchResult.finalUrl || safeUrl, rawMaterial)}`,
        level: fetchResult.status >= 400 ? 'warn' : 'ok',
      });
    } catch (e) {
      emit?.({
        type: 'log',
        msg: `[token-capture] fetch falhou (${safeUrl}): ${redactSecretText(e.message, rawMaterial)}`,
        level: 'warn',
      });
    }
  }

  // ── Validação activa do token ────────────────────────────────────
  let validation = null;
  try {
    emit?.({ type: 'log', msg: `[token-capture] a validar token (${kind})…`, level: 'info' });
    validation = await validateToken(rawMaterial || value, url, {
      network: networkValidation === true,
      probeImpl,
    });
    const icon = { valid: '✓ VÁLIDO', expired: '✗ EXPIRADO', invalid: '✗ INVÁLIDO',
                   revoked: '⊘ REVOGADO', probable: '~ PROVÁVEL', unknown: '? DESCONHECIDO' };
    emit?.({
      type: 'log',
      msg: `[token-capture] token: ${icon[validation.status] ?? validation.status} — ${redactSecretText(validation.evidence || 'sem evidência de rede', rawMaterial)}`,
      level: validation.status === 'valid' ? 'ok' : validation.status === 'probable' ? 'info' : 'warn',
    });
  } catch (e) {
    emit?.({
      type: 'log',
      msg: `[token-capture] validação do token falhou: ${redactSecretText(e.message, rawMaterial)}`,
      level: 'warn',
    });
  }
  if (validation) {
    validation = JSON.parse(redactSecretText(JSON.stringify(validation), rawMaterial));
  }

  const writes = [];

  // 1. Conteúdo redigido
  if (fetchResult?.body) {
    const htmlPath = path.join(domainDir, `${base}.html`);
    writes.push(
      fs.writeFile(
        htmlPath,
        redactSecretText(fetchResult.body.slice(0, MAX_BODY), rawMaterial),
        { encoding: 'utf8', mode: 0o600 },
      ).then(() => fs.chmod(htmlPath, 0o600)),
    );
  }

  // 2. Curl sem credencial. Não reproduz probes autenticados.
  const tokenType = validation?.tokenType ?? 'unknown';

  const curlScript = [
    '#!/bin/bash',
    `# Token ref   : ${safeRef.ref}`,
    `# Tipo        : ${tokenType}`,
    `# Status      : ${validation?.status ?? 'não validado'}`,
    `# Evidência   : ${redactSecretText(validation?.evidence ?? 'n/a', rawMaterial)}`,
    `# URL         : ${safeUrl}`,
    `# Capturado   : ${new Date().toISOString()}`,
    `# HTTP fonte  : ${fetchResult?.status ?? 'n/a'}`,
    validation?.offlineExpired ? `# AVISO       : JWT expirado offline (exp ${validation.expiredAt ?? '?'})` : null,
    '',
    '# — Fetch da página fonte —',
    `curl -sv -L -o "${base}.html" \\`,
    `  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \\`,
    `  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \\`,
    `  -H "Cache-Control: no-cache" \\`,
    `  "${safeUrl}"`,
    '',
    '# Probe autenticado omitido: credenciais nunca são gravadas em curl.',
    `echo "Guardado em ${base}.html — HTTP $?"`,
  ].filter(Boolean).join('\n');

  const curlPath = path.join(domainDir, `${base}.curl.sh`);
  writes.push(
    fs.writeFile(curlPath, curlScript, { encoding: 'utf8', mode: 0o600 })
      .then(() => fs.chmod(curlPath, 0o600)),
  );

  // 3. Metadata JSON redigida
  const jsonPath = path.join(domainDir, `${base}.json`);
  writes.push(
    fs.writeFile(
      jsonPath,
      JSON.stringify({
        domain,
        url:         safeUrl,
        finalUrl:    fetchResult?.finalUrl ? redactSecretText(fetchResult.finalUrl, rawMaterial) : null,
        tokenRef:    safeRef.ref,
        tokenFingerprint: safeRef.fingerprint,
        meta:        redactSecretText(
          typeof meta === 'string' ? meta : JSON.stringify(meta || {}),
          rawMaterial,
        ),
        capturedAt:  new Date().toISOString(),
        httpStatus:  fetchResult?.status ?? null,
        bodyBytes:   fetchResult?.body?.length ?? 0,
        tokenValidation: validation ?? null,
        files: {
          html: fetchResult?.body ? `${base}.html` : null,
          curl: `${base}.curl.sh`,
          meta: `${base}.json`,
        },
      }, null, 2),
      { encoding: 'utf8', mode: 0o600 },
    ).then(() => fs.chmod(jsonPath, 0o600)),
  );

  await Promise.allSettled(writes);

  const validStatus = validation?.status ?? 'não validado';
  emit?.({
    type: 'log',
    msg: `[token-capture] → tokens/${domainSlug}/${base} | html=${!!fetchResult?.body} | HTTP ${fetchResult?.status ?? 'n/a'} | token=${validStatus.toUpperCase()}`,
    level: 'ok',
  });

  // Emite evento dedicado com resultado da validação para o frontend
  if (validation) {
    emit?.({
      type:            'token_validation',
      tokenRef:        safeRef.ref,
      tokenFingerprint: safeRef.fingerprint,
      tokenType:       validation.tokenType,
      status:          validation.status,
      evidence:        validation.evidence,
      offlineExpired:  validation.offlineExpired,
      expiredAt:       validation.expiredAt ?? null,
      expiresAt:       validation.expiresAt ?? null,
      noExpiration:    validation.noExpiration ?? false,
      jwtClaims:       validation.jwtClaims ?? null,
      probes:          validation.probes,
      checkedAt:       validation.checkedAt,
    });
  }
}
