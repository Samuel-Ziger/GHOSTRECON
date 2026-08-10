import { requireScope } from '../modules/auth.js';
import {
  getWifiCapabilities,
  runWifiPentest,
  KALI_WIFI_MODULE_ID,
} from '../modules/kali-wifi.mjs';

export function registerWifiRoutes(app, { validateCsrfToken, allowReconRequest }) {
  app.get('/api/wifi/capabilities', requireScope('recon.read'), async (req, res) => {
    try {
      const wifi = await getWifiCapabilities({ signal: req.signal });
      res.json({ ok: true, wifi });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  app.post('/api/wifi/stream', requireScope('recon.run', {
    intrusiveCheck: () => true,
  }), async (req, res) => {
    res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('X-Accel-Buffering', 'no');

    const controller = new AbortController();
    const abortFromClient = (source) => {
      if (controller.signal.aborted) return;
      const error = new Error(`wifi pentest cancelado: cliente desconectado (${source})`);
      error.name = 'AbortError';
      error.code = 'CLIENT_DISCONNECTED';
      controller.abort(error);
    };
    const onRequestAborted = () => {
      abortFromClient('request_aborted');
      cleanupAbortListeners();
    };
    const onResponseClose = () => {
      if (!res.writableEnded) abortFromClient('response_close');
      cleanupAbortListeners();
    };
    let abortListenersCleaned = false;
    const cleanupAbortListeners = () => {
      if (abortListenersCleaned) return;
      abortListenersCleaned = true;
      req.removeListener('aborted', onRequestAborted);
      res.removeListener('close', onResponseClose);
      res.removeListener('finish', cleanupAbortListeners);
    };
    req.once('aborted', onRequestAborted);
    res.once('close', onResponseClose);
    res.once('finish', cleanupAbortListeners);

    const endResponse = () => {
      if (!res.destroyed && !res.writableEnded) res.end();
      cleanupAbortListeners();
    };

    const send = (obj) => {
      if (res.destroyed || res.writableEnded) return false;
      return res.write(`${JSON.stringify(obj)}\n`);
    };

    if (!validateCsrfToken(req)) {
      send({ type: 'error', message: 'CSRF token inválido/ausente' });
      endResponse();
      return;
    }

    if (typeof allowReconRequest === 'function' && !allowReconRequest(req)) {
      send({ type: 'error', message: 'Rate limit — aguarde antes de novo run WiFi' });
      endResponse();
      return;
    }

    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const targetsText = String(body.targets ?? body.wifiTargets ?? '').trim();
    const labConfirm = body.labConfirm === true || body.wifiLabConfirm === true;
    const wordlist = body.wordlist != null ? String(body.wordlist).trim() : null;
    const iface = body.iface != null ? String(body.iface).trim() : null;

    send({
      type: 'start',
      module: KALI_WIFI_MODULE_ID,
      labConfirm,
      hasTargets: Boolean(targetsText),
    });

    try {
      const result = await runWifiPentest({
        targetsText,
        labConfirm,
        wordlist: wordlist || null,
        iface: iface || null,
        signal: controller.signal,
        emit: send,
      });
      send({
        type: 'done',
        ok: result.ok,
        reason: result.reason,
        findingCount: result.findings?.length || 0,
      });
    } catch (e) {
      send({
        type: 'error',
        message: e?.message || String(e),
        cancelled: e?.name === 'AbortError',
      });
    } finally {
      endResponse();
    }
  });
}
