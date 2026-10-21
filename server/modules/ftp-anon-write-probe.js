/**
 * Após login FTP anónimo bem-sucedido, testa se o servidor aceita STOR (upload).
 * Usa modo passivo (PASV / EPSV) e ignora o host anunciado, mantendo o IP
 * observado no canal de controle para impedir FTP bounce.
 */
import net from 'net';
import { randomBytes } from 'crypto';

function boolFlag(value) {
  const v = String(value ?? '0').trim().toLowerCase();
  return ['1', 'true', 'yes', 'on'].includes(v);
}

function normalizeHost(value) {
  return String(value || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
}

function ftpAbortError(signal) {
  const reason = signal?.reason;
  const error = new Error(
    reason instanceof Error && reason.message ? reason.message : 'FTP write probe cancelado',
    reason === undefined ? undefined : { cause: reason },
  );
  error.name = 'AbortError';
  error.code = reason?.code || 'PROCESS_ABORTED';
  return error;
}

export function resolveFtpWriteProbePolicy(env = process.env) {
  const targets = [...new Set(
    String(env?.GHOSTRECON_FTP_WRITE_PROBE_LAB_TARGETS || '')
      .split(/[,;\n]/)
      .map(normalizeHost)
      .filter((host) => host && host !== '*' && !host.includes('/')),
  )].sort();
  return Object.freeze({
    enabled: boolFlag(env?.GHOSTRECON_FTP_WRITE_PROBE),
    labAcknowledged: boolFlag(env?.GHOSTRECON_FTP_WRITE_PROBE_LAB_ACK),
    labTargets: Object.freeze(targets),
  });
}

function ftpWriteProbeEnabled(env = process.env) {
  const policy = resolveFtpWriteProbePolicy(env);
  return policy.enabled && policy.labAcknowledged && policy.labTargets.length > 0;
}

function parsePasv227(text, controlHost) {
  const m = String(text).match(/\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)/);
  if (!m) return null;
  const port = Number(m[5]) * 256 + Number(m[6]);
  // Nunca siga o host anunciado em PASV: além de evitar FTP bounce, manter o
  // host do canal de controle preserva o alvo que já passou pelo gate de escopo.
  return { host: controlHost, port };
}

function parseEpsv229(text, controlHost) {
  const m = String(text).match(/\(\|\|\|(\d+)\|\)/);
  if (!m) return null;
  return { host: controlHost, port: Number(m[1]) };
}

function createFtpReplyReader(sock, { maxBytes = 64 * 1024, maxQueued = 128 } = {}) {
  let buf = '';
  let totalBytes = 0;
  let multilineCode = null;
  let terminalError = null;
  let closed = false;
  const queued = [];
  const waiters = [];

  const detach = () => {
    sock.removeListener('data', onData);
    sock.removeListener('error', onError);
    sock.removeListener('close', onClose);
  };
  const rejectAll = (error) => {
    if (terminalError) return;
    terminalError = error instanceof Error ? error : new Error(String(error));
    detach();
    queued.length = 0;
    while (waiters.length) {
      const waiter = waiters.shift();
      clearTimeout(waiter.timer);
      waiter.reject(terminalError);
    }
  };
  const enqueue = (reply) => {
    const waiter = waiters.shift();
    if (waiter) {
      clearTimeout(waiter.timer);
      waiter.resolve(reply);
      return;
    }
    queued.push(reply);
    if (queued.length > maxQueued) rejectAll(new Error('FTP reply queue exceeds limit'));
  };
  function onData(chunk) {
    if (closed || terminalError) return;
    const text = chunk.toString('utf8');
    totalBytes += Buffer.byteLength(text, 'utf8');
    if (totalBytes > maxBytes) {
      rejectAll(new Error(`FTP reply exceeds ${maxBytes} bytes`));
      return;
    }
    buf += text;
    const lines = buf.split(/\r?\n/);
    buf = lines.pop() || '';
    for (const line of lines) {
      const fm = line.match(/^(\d{3})([\s-])(.*)$/);
      if (!fm) continue;
      const code = Number(fm[1]);
      const separator = fm[2];
      if (multilineCode !== null) {
        if (code !== multilineCode || separator !== ' ') continue;
        multilineCode = null;
      } else if (separator === '-') {
        multilineCode = code;
        continue;
      }
      enqueue({ code, line: line.trim(), text: fm[3] });
      if (terminalError) return;
    }
  }
  function onError(error) {
    rejectAll(error || new Error('FTP socket error'));
  }
  function onClose() {
    rejectAll(new Error('FTP connection closed'));
  }

  sock.on('data', onData);
  sock.on('error', onError);
  sock.on('close', onClose);
  return {
    next(timeoutMs) {
      if (terminalError) return Promise.reject(terminalError);
      if (closed) return Promise.reject(new Error('FTP reply reader closed'));
      if (queued.length) return Promise.resolve(queued.shift());
      const bounded = Math.max(1, Math.min(30_000, Number(timeoutMs) || 1));
      return new Promise((resolve, reject) => {
        const waiter = { resolve, reject, timer: null };
        waiter.timer = setTimeout(() => {
          const index = waiters.indexOf(waiter);
          if (index >= 0) waiters.splice(index, 1);
          reject(new Error(`FTP read timeout ${bounded}ms`));
        }, bounded);
        waiters.push(waiter);
      });
    },
    close() {
      if (closed) return;
      closed = true;
      detach();
      while (waiters.length) {
        const waiter = waiters.shift();
        clearTimeout(waiter.timer);
        waiter.reject(new Error('FTP reply reader closed'));
      }
      queued.length = 0;
    },
  };
}

function writeCmd(sock, cmd) {
  sock.write(`${cmd}\r\n`);
}

/**
 * @returns {Promise<{
 *   writable: boolean,
 *   probeFile?: string,
 *   remoteWritePossible?: boolean,
 *   payloadSent?: boolean,
 *   transferConfirmed?: boolean,
 *   cleanupVerified?: boolean,
 *   cleanupCode?: number|null,
 *   absenceCode?: number|null,
 *   detail?: string,
 *   error?: string,
 * }>}
 */
export async function probeFtpAnonymousWritable({
  host,
  port = 21,
  timeoutMs = 15000,
  signal = null,
  enabled = undefined,
  labAcknowledged = undefined,
  labTargets = undefined,
  env = process.env,
  hostAllowed = () => true,
  addressAllowed = () => true,
  allowDirectNetwork = true,
  observedAddress = null,
  connectImpl = (options) => net.createConnection(options),
  randomBytesImpl = randomBytes,
  now = () => Date.now(),
}) {
  const policy = resolveFtpWriteProbePolicy(env);
  const writeEnabled = enabled === undefined ? policy.enabled : enabled === true;
  const labAck = labAcknowledged === undefined
    ? policy.labAcknowledged
    : labAcknowledged === true;
  const allowedLabTargets = new Set(
    (labTargets === undefined ? policy.labTargets : labTargets)
      .map(normalizeHost)
      .filter(Boolean),
  );
  if (!writeEnabled) {
    return { writable: false, detail: 'probe_disabled' };
  }
  if (!labAck) return { writable: false, detail: 'controlled_lab_ack_required' };
  if (signal?.aborted) throw ftpAbortError(signal);
  const normalizedHost = normalizeHost(host);
  const normalizedPort = Number(port);
  if (
    !normalizedHost
    || normalizedHost.length > 253
    || /[\s/@\\?#]/.test(normalizedHost)
  ) return { writable: false, detail: 'invalid_host' };
  if (!Number.isInteger(normalizedPort) || normalizedPort < 1 || normalizedPort > 65_535) {
    return { writable: false, detail: 'invalid_port' };
  }
  if (!allowedLabTargets.has(normalizedHost)) {
    return { writable: false, detail: 'controlled_lab_target_not_allowlisted' };
  }
  if (hostAllowed(normalizedHost) !== true) {
    return { writable: false, detail: 'target_out_of_scope' };
  }
  if (allowDirectNetwork !== true) {
    return { writable: false, detail: 'direct_network_blocked' };
  }
  const controlAddress = normalizeHost(observedAddress || (net.isIP(normalizedHost) ? normalizedHost : ''));
  if (!net.isIP(controlAddress)) {
    return { writable: false, detail: 'observed_address_required' };
  }
  if (addressAllowed(controlAddress) !== true) {
    return { writable: false, detail: 'observed_address_out_of_scope' };
  }
  const t = Math.min(30_000, Math.max(8_000, Number(timeoutMs) || 15_000));
  const probeFile = `.ghr_w_${now()}_${randomBytesImpl(4).toString('hex')}.txt`;
  const payload = Buffer.from('GHOSTRECON write probe — safe to delete\n', 'utf8');

  return new Promise((resolve, reject) => {
    let sock;
    try {
      sock = connectImpl({
        host: controlAddress,
        port: normalizedPort,
        channel: 'control',
        originalHost: normalizedHost,
      });
    } catch {
      resolve({ writable: false, detail: 'control_connect_failed' });
      return;
    }
    let phase = 'banner';
    let dataSock = null;
    let replyReader = null;
    let settled = false;
    let absoluteDeadline = null;
    let remoteWritePossible = false;
    let payloadSent = false;
    let transferConfirmed = false;
    let remoteCleanupInFlight = null;
    let remoteRecoveryStarted = false;
    const cleanupSockets = () => {
      try {
        sock.destroy();
      } catch {
        /* ignore */
      }
      try {
        dataSock?.destroy();
      } catch {
        /* ignore */
      }
    };
    const finish = (out) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener('abort', onAbort);
      if (absoluteDeadline) clearTimeout(absoluteDeadline);
      replyReader?.close();
      cleanupSockets();
      resolve(out);
    };
    const onAbort = () => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener('abort', onAbort);
      if (absoluteDeadline) clearTimeout(absoluteDeadline);
      replyReader?.close();
      cleanupSockets();
      const error = ftpAbortError(signal);
      if (remoteWritePossible) {
        error.remoteWritePossible = true;
        error.probeFile = probeFile;
        error.payloadSent = payloadSent;
        error.transferConfirmed = transferConfirmed;
        error.cleanupVerified = false;
      }
      reject(error);
    };
    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) {
      onAbort();
      return;
    }
    const fail = (error, detail) => finish({
      writable: transferConfirmed,
      error,
      detail,
      ...(remoteWritePossible ? {
        probeFile,
        remoteWritePossible: true,
        payloadSent,
        transferConfirmed,
        cleanupVerified: false,
      } : {}),
    });
    const cleanupRemoteCanary = async () => {
      let cleanupResponse = null;
      let absenceResponse = null;
      try {
        phase = 'delete';
        writeCmd(sock, `DELE ${probeFile}`);
        cleanupResponse = await replyReader.next(Math.min(8_000, t));
      } catch (cleanupError) {
        cleanupResponse = { code: null, line: cleanupError?.message || String(cleanupError) };
      }
      if (cleanupResponse?.code === 250) {
        try {
          phase = 'size_after_delete';
          writeCmd(sock, `SIZE ${probeFile}`);
          absenceResponse = await replyReader.next(Math.min(8_000, t));
        } catch (absenceError) {
          absenceResponse = { code: null, line: absenceError?.message || String(absenceError) };
        }
      }
      try { writeCmd(sock, 'QUIT'); } catch { /* socket may already be closed */ }
      return {
        cleanupVerified: cleanupResponse?.code === 250 && absenceResponse?.code === 550,
        cleanupCode: cleanupResponse?.code ?? null,
        absenceCode: absenceResponse?.code ?? null,
      };
    };
    const attemptRemoteCleanup = () => {
      if (!remoteCleanupInFlight) remoteCleanupInFlight = cleanupRemoteCanary();
      return remoteCleanupInFlight;
    };
    const recoverRemoteState = async (error, detail) => {
      if (settled || remoteRecoveryStarted) return;
      remoteRecoveryStarted = true;
      try { dataSock?.destroy(); } catch { /* ignore */ }
      const cleanup = await attemptRemoteCleanup();
      if (settled) return;
      finish({
        writable: transferConfirmed,
        probeFile,
        remoteWritePossible: true,
        payloadSent,
        transferConfirmed,
        ...cleanup,
        error: `${error}${detail ? `:${detail}` : ''}`,
        detail: cleanup.cleanupVerified
          ? 'stor_incomplete_but_cleanup_verified'
          : 'stor_incomplete_cleanup_unverified',
      });
    };
    absoluteDeadline = setTimeout(
      () => fail('deadline', 'overall_timeout'),
      Math.min(90_000, t * 4),
    );

    try {
      sock.setEncoding('utf8');
      sock.setTimeout(t + 5000, () => {
        if (remoteWritePossible) {
          void recoverRemoteState('timeout', phase);
          return;
        }
        fail('timeout', phase);
      });
      replyReader = createFtpReplyReader(sock);
    } catch {
      finish({ writable: false, detail: 'control_socket_setup_failed' });
      return;
    }

    sock.once('connect', () => {
      void (async () => {
        let pasvEndpoint = null;
        try {
        const peer = normalizeHost(sock.remoteAddress || '');
        const normalizedPeer = peer.startsWith('::ffff:') && net.isIP(peer.slice(7)) === 4
          ? peer.slice(7)
          : peer;
        if (
          !normalizedPeer
          || normalizedPeer !== controlAddress
          || addressAllowed(normalizedPeer) !== true
        ) {
          fail('peer_address_mismatch', phase);
          return;
        }
        let r = await replyReader.next(t);
        if (r.code !== 220) {
          fail(`banner_${r.code}`, r.line);
          return;
        }
        phase = 'user';
        writeCmd(sock, 'USER anonymous');
        r = await replyReader.next(t);
        if (r.code === 530) {
          fail('user_denied', r.line);
          return;
        }
        if (r.code !== 331 && r.code !== 230) {
          fail(`user_${r.code}`, r.line);
          return;
        }
        if (r.code === 331) {
          phase = 'pass';
          writeCmd(sock, 'PASS anonymous@ghostrecon.local');
          r = await replyReader.next(t);
        }
        if (r.code !== 230) {
          fail(`pass_${r.code}`, r.line);
          return;
        }

        phase = 'type';
        writeCmd(sock, 'TYPE I');
        r = await replyReader.next(t);
        if (r.code !== 200 && r.code !== 250) {
          fail(`type_${r.code}`, r.line);
          return;
        }

        phase = 'pasv';
        writeCmd(sock, 'PASV');
        r = await replyReader.next(t);
        if (r.code === 227) {
          pasvEndpoint = parsePasv227(r.line, controlAddress);
        }
        if (!pasvEndpoint && r.code === 229) {
          pasvEndpoint = parseEpsv229(`${r.text} ${r.line}`, controlAddress);
        }
        if (!pasvEndpoint) {
          writeCmd(sock, 'EPSV');
          r = await replyReader.next(t);
          if (r.code === 229) pasvEndpoint = parseEpsv229(`${r.text} ${r.line}`, controlAddress);
        }
        if (!pasvEndpoint) {
          fail('pasv_parse', r.line);
          return;
        }
        if (
          !Number.isInteger(pasvEndpoint.port)
          || pasvEndpoint.port < 1024
          || pasvEndpoint.port > 65535
          || pasvEndpoint.port === normalizedPort
        ) {
          fail('pasv_port_refused', String(pasvEndpoint.port));
          return;
        }

        if (addressAllowed(pasvEndpoint.host) !== true) {
          fail('data_target_out_of_scope', `${pasvEndpoint.host}:${pasvEndpoint.port}`);
          return;
        }
        phase = 'data_connect';
        dataSock = connectImpl({
          host: pasvEndpoint.host,
          port: pasvEndpoint.port,
          channel: 'data',
          originalHost: normalizedHost,
        });
        await new Promise((res, rej) => {
          dataSock.once('connect', () => {
            const dataPeer = normalizeHost(dataSock.remoteAddress || '');
            const normalizedDataPeer = dataPeer.startsWith('::ffff:') && net.isIP(dataPeer.slice(7)) === 4
              ? dataPeer.slice(7)
              : dataPeer;
            if (
              !normalizedDataPeer
              || normalizedDataPeer !== controlAddress
              || addressAllowed(normalizedDataPeer) !== true
            ) {
              rej(new Error('data peer address mismatch'));
              return;
            }
            res();
          });
          dataSock.once('error', rej);
          dataSock.setTimeout(t, () => rej(new Error('data connect timeout')));
        });

        phase = 'stor';
        writeCmd(sock, `STOR ${probeFile}`);
        r = await replyReader.next(t);
        if (r.code === 550 || r.code === 553 || r.code === 532) {
          try {
            dataSock.destroy();
          } catch {
            /* ignore */
          }
          writeCmd(sock, 'QUIT');
          finish({ writable: false, detail: `stor_denied_${r.code}`, probeFile });
          return;
        }
        if (r.code !== 150 && r.code !== 125) {
          try {
            dataSock.destroy();
          } catch {
            /* ignore */
          }
          fail(`stor_${r.code}`, r.line);
          return;
        }
        // Um reply preliminar pode criar/truncar o arquivo antes mesmo de o
        // payload terminar. A partir daqui toda saída precisa carregar estado
        // de resíduo e tentar cleanup quando o deadline permitir.
        remoteWritePossible = true;

        phase = 'transfer';
        await new Promise((res, rej) => {
          dataSock.write(payload, (e) => (e ? rej(e) : res()));
        });
        if (remoteRecoveryStarted || settled) return;
        payloadSent = true;
        dataSock.end();

        r = await replyReader.next(t);
        if (r.code !== 226 && r.code !== 250) {
          throw new Error(`after_upload_${r.code}: ${r.line}`);
        }
        transferConfirmed = true;

        const cleanup = await attemptRemoteCleanup();
        finish({
          writable: true,
          probeFile,
          remoteWritePossible: true,
          payloadSent,
          transferConfirmed,
          ...cleanup,
          detail: cleanup.cleanupVerified
            ? 'stor_ok_dele_and_absence_verified'
            : `stor_ok_cleanup_unverified${cleanup.cleanupCode ? `_dele_${cleanup.cleanupCode}` : ''}${cleanup.absenceCode ? `_size_${cleanup.absenceCode}` : ''}`,
        });
      } catch (e) {
        if (settled) return;
        try {
          if (dataSock) dataSock.destroy();
        } catch {
          /* ignore */
        }
        if (remoteWritePossible) {
          const cleanup = await attemptRemoteCleanup();
          finish({
            writable: transferConfirmed,
            probeFile,
            remoteWritePossible: true,
            payloadSent,
            transferConfirmed,
            ...cleanup,
            error: e?.message || String(e),
            detail: cleanup.cleanupVerified
              ? 'stor_incomplete_but_cleanup_verified'
              : 'stor_incomplete_cleanup_unverified',
          });
          return;
        }
        fail(e?.message || String(e), phase);
      }
      })();
    });
  });
}

export { ftpWriteProbeEnabled };
