import net from 'node:net';
import { lookup as dnsLookup } from 'node:dns/promises';

const DEFAULT_PASSWORDS = Object.freeze(['', 'anonymous@ghostrecon.local']);

function abortError(signal) {
  const reason = signal?.reason;
  const error = new Error(
    reason instanceof Error && reason.message
      ? reason.message
      : 'FTP anonymous login probe cancelado',
    reason === undefined ? undefined : { cause: reason },
  );
  error.name = 'AbortError';
  error.code = reason?.code || 'PROCESS_ABORTED';
  return error;
}

export function isFtpServiceRow(row) {
  if (!row) return false;
  const name = String(row.name || '').toLowerCase();
  const product = String(row.product || '').toLowerCase();
  const port = String(row.port || '');
  if (row.proto !== 'tcp') return false;
  // ftp-data (20/tcp), FTPS implícito (990/tcp) e SFTP não falam o canal
  // de controle FTP plaintext esperado por este probe.
  const tunnel = String(row.tunnel || '').toLowerCase();
  if (
    port === '20'
    || port === '990'
    || /^(?:ftp-data|ftps|ftps-data|sftp)$/.test(name)
    || /^(?:ssl|tls)$/.test(tunnel)
  ) return false;
  return port === '21'
    || /^(?:ftp|ftp-alt)$/.test(name)
    || /(?:^|[^a-z0-9])(?:filezilla|proftpd|vsftpd|pure-ftpd)(?:$|[^a-z0-9])/.test(product);
}

async function resolvePinnedAddress(host, {
  timeoutMs,
  signal,
  lookupImpl,
  addressAllowed,
}) {
  if (net.isIP(host)) {
    return addressAllowed(host) === true ? host : null;
  }
  let timer = null;
  let onAbort = null;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => reject(Object.assign(new Error('dns_lookup_timeout'), {
      code: 'FTP_DNS_TIMEOUT',
    })), timeoutMs);
  });
  const aborted = new Promise((_, reject) => {
    onAbort = () => reject(abortError(signal));
    signal?.addEventListener('abort', onAbort, { once: true });
  });
  try {
    const resolved = await Promise.race([
      Promise.resolve(lookupImpl(host, { all: true, verbatim: true })),
      deadline,
      aborted,
    ]);
    const rows = (Array.isArray(resolved) ? resolved : [resolved]).slice(0, 16);
    for (const row of rows) {
      const address = typeof row === 'string' ? row : String(row?.address || '');
      if (net.isIP(address) && addressAllowed(address) === true) return address;
    }
    return null;
  } finally {
    if (timer) clearTimeout(timer);
    if (onAbort) signal?.removeEventListener('abort', onAbort);
  }
}

/**
 * Valida somente o login FTP anonymous e encerra a sessão com QUIT.
 * Não lista diretórios, não transfere arquivos e não altera estado remoto.
 */
export async function probeFtpAnonymousLogin({
  host,
  port = 21,
  timeoutMs = 12_000,
  closeGraceMs = 500,
  signal = null,
  hostAllowed = () => true,
  addressAllowed = () => true,
  allowDirectNetwork = true,
  observedAddress = null,
  lookupImpl = dnsLookup,
  connectImpl = (options) => net.createConnection(options),
} = {}) {
  const normalizedHost = String(host || '').trim();
  const normalizedPort = Number(port);
  const boundedTimeoutMs = Number.isFinite(Number(timeoutMs))
    ? Math.max(1, Math.min(30_000, Math.floor(Number(timeoutMs))))
    : 12_000;
  const boundedCloseGraceMs = Number.isFinite(Number(closeGraceMs))
    ? Math.max(10, Math.min(1_000, Math.floor(Number(closeGraceMs))))
    : 500;
  // A capability não aceita listas de senhas. Estas são exclusivamente as
  // duas variantes públicas usuais do login `anonymous`.
  const passCandidates = DEFAULT_PASSWORDS;
  if (!normalizedHost || normalizedHost.length > 253 || /[\s/@\\?#]/.test(normalizedHost)) {
    return { ok: false, host: normalizedHost, port: normalizedPort, error: 'invalid_host' };
  }
  if (!Number.isInteger(normalizedPort) || normalizedPort < 1 || normalizedPort > 65535) {
    return { ok: false, host: normalizedHost, port: normalizedPort, error: 'invalid_port' };
  }
  if (signal?.aborted) throw abortError(signal);
  if (hostAllowed(normalizedHost) !== true) {
    return { ok: false, host: normalizedHost, port: normalizedPort, error: 'target_out_of_scope' };
  }
  if (allowDirectNetwork !== true) {
    return { ok: false, host: normalizedHost, port: normalizedPort, error: 'direct_network_blocked' };
  }

  const startedAt = Date.now();
  let pinnedAddress = String(observedAddress || '').trim();
  if (pinnedAddress) {
    if (!net.isIP(pinnedAddress) || addressAllowed(pinnedAddress) !== true) {
      return {
        ok: false,
        host: normalizedHost,
        port: normalizedPort,
        error: 'observed_address_out_of_scope',
      };
    }
  } else {
    try {
      pinnedAddress = await resolvePinnedAddress(normalizedHost, {
        timeoutMs: boundedTimeoutMs,
        signal,
        lookupImpl,
        addressAllowed,
      });
    } catch (error) {
      if (error?.name === 'AbortError') throw error;
      return {
        ok: false,
        host: normalizedHost,
        port: normalizedPort,
        error: error?.code === 'FTP_DNS_TIMEOUT' ? 'dns_lookup_timeout' : 'dns_lookup_failed',
      };
    }
  }
  if (!pinnedAddress) {
    return {
      ok: false,
      host: normalizedHost,
      port: normalizedPort,
      error: 'resolved_address_out_of_scope',
    };
  }
  const remainingTimeoutMs = Math.max(1, boundedTimeoutMs - (Date.now() - startedAt));

  return new Promise((resolve, reject) => {
    // Conecta ao endereço que acabou de ser validado, evitando uma segunda
    // resolução DNS entre o gate de escopo e o socket.
    let sock;
    try {
      sock = connectImpl({
        host: pinnedAddress,
        port: normalizedPort,
        originalHost: normalizedHost,
      });
    } catch {
      resolve({ ok: false, host: normalizedHost, port: normalizedPort, error: 'connect_failed' });
      return;
    }

    let buffer = '';
    let closingBuffer = '';
    let responseBytes = 0;
    let multilineCode = null;
    let terminal = false;
    let closingSuccess = false;
    let pendingSuccess = null;
    let deadlineTimer = null;
    let closeGraceTimer = null;
    let sentUser = false;
    let sentPass = false;
    let passIndex = -1;
    const triedPasses = [];
    let banner = '';
    let userReply = '';
    let passReply = '';

    const removeSocketListener = (event, listener) => {
      if (typeof sock?.off === 'function') sock.off(event, listener);
      else sock?.removeListener?.(event, listener);
    };
    const cleanup = () => {
      signal?.removeEventListener('abort', onAbort);
      if (deadlineTimer) clearTimeout(deadlineTimer);
      if (closeGraceTimer) clearTimeout(closeGraceTimer);
      deadlineTimer = null;
      closeGraceTimer = null;
      removeSocketListener('connect', onConnect);
      removeSocketListener('data', onData);
      removeSocketListener('timeout', onTimeout);
      removeSocketListener('error', onError);
      removeSocketListener('close', onClose);
    };
    const destroySocket = () => {
      try { sock?.destroy?.(); } catch { /* ignore */ }
      return sock?.destroyed === true;
    };
    const settleResult = (result, { destroy = false } = {}) => {
      if (terminal) return;
      terminal = true;
      closingSuccess = false;
      cleanup();
      const socketDestroyed = destroy ? destroySocket() : sock?.destroyed === true;
      resolve({ ...result, ...(destroy ? { socketDestroyed } : {}) });
    };
    const fail = (result) => settleResult(result, { destroy: true });
    const settleSuccess = (connectionClose, { closeAttested = false, destroy = false } = {}) => {
      if (terminal || !closingSuccess || !pendingSuccess) return;
      const socketDestroyed = destroy ? destroySocket() : sock?.destroyed === true;
      if (destroy && !socketDestroyed) {
        settleResult({
          ...pendingSuccess,
          ok: false,
          loginConfirmed: true,
          error: 'FTP_SOCKET_UNTERMINATED',
          connectionClose,
          closeAttested: false,
          forcedDestroy: true,
          terminationConfirmed: false,
          cleanupConfirmed: false,
        });
        return;
      }
      settleResult({
        ...pendingSuccess,
        connectionClose,
        closeAttested,
        forcedDestroy: destroy,
        terminationConfirmed: closeAttested || socketDestroyed,
        cleanupConfirmed: closeAttested || socketDestroyed,
      });
    };
    const beginSuccess = (result) => {
      if (terminal || closingSuccess) return;
      closingSuccess = true;
      pendingSuccess = {
        ...result,
        triedPasses: [...(result.triedPasses || [])],
        quitSent: true,
        quitFlushed: false,
        quitReplyCode: null,
      };
      if (deadlineTimer) clearTimeout(deadlineTimer);
      deadlineTimer = null;
      closeGraceTimer = setTimeout(() => {
        settleSuccess('quit_sent_force_destroyed', { destroy: true });
      }, boundedCloseGraceMs);
      try {
        if (typeof sock?.end !== 'function') throw new Error('socket_end_unavailable');
        sock.end('QUIT\r\n', () => {
          if (pendingSuccess && !terminal) pendingSuccess.quitFlushed = true;
        });
      } catch {
        pendingSuccess.quitSent = false;
        settleSuccess('quit_send_failed_force_destroyed', { destroy: true });
      }
    };
    const onAbort = () => {
      if (terminal) return;
      terminal = true;
      closingSuccess = false;
      cleanup();
      destroySocket();
      reject(abortError(signal));
    };
    const writeCommand = (command) => {
      if (terminal || closingSuccess) return false;
      try {
        if (typeof sock?.write !== 'function') throw new Error('socket_write_unavailable');
        sock.write(command);
        return true;
      } catch {
        fail({ ok: false, host: normalizedHost, port: normalizedPort, error: 'socket_write_failed' });
        return false;
      }
    };
    const nextPass = () => {
      if (terminal || closingSuccess) return false;
      const nextIndex = passIndex + 1;
      if (nextIndex >= passCandidates.length) return false;
      passIndex = nextIndex;
      const candidate = String(passCandidates[passIndex] ?? '');
      triedPasses.push(candidate);
      if (!writeCommand(`PASS ${candidate}\r\n`)) return false;
      sentPass = true;
      return true;
    };
    const onConnect = () => {
      if (terminal || closingSuccess) return;
      const peer = String(sock?.remoteAddress || '');
      const normalizedPeer = peer.startsWith('::ffff:') && net.isIP(peer.slice(7)) === 4
        ? peer.slice(7)
        : peer;
      if (
        !normalizedPeer
        || normalizedPeer.toLowerCase() !== pinnedAddress.toLowerCase()
        || addressAllowed(normalizedPeer) !== true
      ) {
        fail({
          ok: false,
          host: normalizedHost,
          port: normalizedPort,
          error: 'peer_address_mismatch',
        });
      }
    };
    const onLine = (line) => {
      if (terminal || closingSuccess) return;
      const match = String(line).match(/^(\d{3})([\s-])(.*)$/);
      if (!match) return;
      const code = Number(match[1]);
      const separator = match[2];
      const message = match[3] || '';
      if (multilineCode !== null) {
        if (code !== multilineCode || separator !== ' ') return;
        multilineCode = null;
      } else if (separator === '-') {
        multilineCode = code;
        return;
      }
      if (!banner && code === 220 && separator === ' ') banner = message;
      if (separator !== ' ') return;

      if (!sentUser && code === 220) {
        if (writeCommand('USER anonymous\r\n')) sentUser = true;
        return;
      }

      if (sentUser && !sentPass) {
        userReply = `${code} ${message}`.trim();
        if (code === 230) {
          beginSuccess({
            ok: true,
            host: normalizedHost,
            port: normalizedPort,
            networkAddress: pinnedAddress,
            banner,
            userReply,
            passReply: '',
            passUsed: '(none-required)',
            triedPasses,
          });
          return;
        }
        if (code === 331) {
          if (!nextPass() && !terminal) {
            fail({
              ok: false,
              host: normalizedHost,
              port: normalizedPort,
              banner,
              userReply,
              passReply: '',
              triedPasses: [...triedPasses],
            });
          }
          return;
        }
        if (code >= 400) {
          fail({
            ok: false,
            host: normalizedHost,
            port: normalizedPort,
            banner,
            userReply,
            passReply: '',
            triedPasses: [...triedPasses],
          });
        }
        return;
      }

      if (!sentPass) return;
      passReply = `${code} ${message}`.trim();
      if (code === 230) {
        beginSuccess({
          ok: true,
          host: normalizedHost,
          port: normalizedPort,
          networkAddress: pinnedAddress,
          banner,
          userReply,
          passReply,
          passUsed: String(passCandidates[passIndex] ?? ''),
          triedPasses,
        });
        return;
      }
      if (code >= 400) {
        // Muitos servidores FTP voltam ao estado inicial depois de um PASS
        // recusado. Reenvie USER antes do próximo candidato, em vez de
        // assumir que dois comandos PASS consecutivos serão aceitos.
        if (passIndex + 1 < passCandidates.length) {
          sentPass = false;
          writeCommand('USER anonymous\r\n');
          return;
        }
        fail({
          ok: false,
          host: normalizedHost,
          port: normalizedPort,
          banner,
          userReply,
          passReply,
          triedPasses: [...triedPasses],
        });
      }
    };
    const onData = (chunk) => {
      if (terminal) return;
      const text = String(chunk || '');
      responseBytes += Buffer.byteLength(text, 'utf8');
      if (responseBytes > 64 * 1024) {
        if (closingSuccess && pendingSuccess) {
          pendingSuccess.operationalPartial = true;
          pendingSuccess.warning = 'response_too_large_after_login';
          settleSuccess('quit_response_limit_force_destroyed', { destroy: true });
          return;
        }
        fail({
          ok: false,
          host: normalizedHost,
          port: normalizedPort,
          error: 'response_too_large',
        });
        return;
      }
      if (closingSuccess) {
        closingBuffer = `${closingBuffer}${text}`.slice(-4_096);
        if (/(?:^|\r?\n)221\s[^\r\n]*(?:\r?\n|$)/.test(closingBuffer) && pendingSuccess) {
          pendingSuccess.quitReplyCode = 221;
        }
        return;
      }
      buffer += text;
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() || '';
      for (const line of lines) {
        if (terminal || closingSuccess) break;
        onLine(line);
      }
    };
    const onTimeout = () => {
      if (closingSuccess) {
        settleSuccess('quit_sent_timeout_force_destroyed', { destroy: true });
        return;
      }
      fail({
        ok: false,
        host: normalizedHost,
        port: normalizedPort,
        error: `timeout ${boundedTimeoutMs}ms`,
      });
    };
    const onError = () => {
      if (closingSuccess) {
        settleSuccess('quit_sent_socket_error_force_destroyed', { destroy: true });
        return;
      }
      fail({ ok: false, host: normalizedHost, port: normalizedPort, error: 'socket_error' });
    };
    const onClose = () => {
      if (terminal) return;
      if (closingSuccess) {
        settleSuccess('quit_sent_close_attested', { closeAttested: true });
        return;
      }
      fail({ ok: false, host: normalizedHost, port: normalizedPort, error: 'connection_closed' });
    };

    try {
      sock?.setEncoding?.('utf8');
      sock?.setTimeout?.(remainingTimeoutMs);
    } catch {
      fail({ ok: false, host: normalizedHost, port: normalizedPort, error: 'socket_setup_failed' });
      return;
    }
    sock?.once?.('connect', onConnect);
    sock?.on?.('data', onData);
    sock?.on?.('timeout', onTimeout);
    sock?.on?.('error', onError);
    sock?.on?.('close', onClose);
    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) {
      onAbort();
      return;
    }
    deadlineTimer = setTimeout(() => fail({
      ok: false,
      host: normalizedHost,
      port: normalizedPort,
      error: `deadline ${boundedTimeoutMs}ms`,
    }), remainingTimeoutMs);
  });
}

export function ftpAnonymousLoginFinding(result, { writeProbe = 'not_run' } = {}) {
  if (!result?.ok) return null;
  const endpoint = `${result.host}:${result.port}`;
  const safeWriteProbe = String(writeProbe || 'not_run')
    .replace(/[^a-z0-9_.-]+/gi, '_')
    .slice(0, 80);
  const authMethod = result.passUsed === ''
    ? 'anonymous-empty-pass'
    : result.passUsed === '(none-required)'
      ? 'anonymous-user-no-pass'
      : 'anonymous-email-pass';
  return {
    type: 'ftp_anonymous_login',
    prio: 'low',
    score: 32,
    value: `FTP anonymous login observado @ ${endpoint}`,
    meta: {
      service: 'ftp',
      auth: authMethod,
      banner: result.banner ? String(result.banner).slice(0, 90) : null,
      userReply: result.userReply ? String(result.userReply).slice(0, 90) : null,
      passReply: result.passReply ? String(result.passReply).slice(0, 90) : null,
      evidenceStatus: 'active_read_only_login_confirmed',
      connection: result.connectionClose || 'connection_state_unknown',
      quitSent: result.quitSent === true,
      closeAttested: result.closeAttested === true,
      forcedDestroy: result.forcedDestroy === true,
      terminationConfirmed: result.terminationConfirmed === true,
      cleanupConfirmed: result.cleanupConfirmed === true,
      operationalPartial: result.operationalPartial === true,
      warning: result.warning ? String(result.warning).slice(0, 100) : null,
      quitFlushed: result.quitFlushed === true,
      quitReplyCode: Number.isInteger(result.quitReplyCode) ? result.quitReplyCode : null,
      networkAddress: result.networkAddress || null,
      writeProbe: safeWriteProbe,
      note: 'Acesso anônimo pode ser intencional; revisar permissões de listagem/leitura separadamente.',
    },
    url: null,
    provenance: {
      how: 'Nmap identificou FTP; o GHOSTRECON confirmou USER anonymous com um login limitado e encerrou com QUIT.',
      relation: `Serviço TCP no alvo autorizado ${endpoint}.`,
    },
  };
}
