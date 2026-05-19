"""
GhostMap — Playwright Browser Instrumenter

Abre um browser controlado, injeta scripts de instrumentacao no contexto e
publica eventos no Redis Stream `gm:capture:browser`. Eventos capturados:

  * navigation         (URL change, frame attach)
  * fetch / xhr        (proxied via page.route OR via injected fetch monkey patch)
  * mutation           (MutationObserver injetado)
  * storage_change     (localStorage / sessionStorage hook)
  * cookie_change      (page.context.cookies diff)
  * redirect           (response.status in 3xx)
  * script_load        (script src tag inserido dinamicamente)
  * websocket_event    (CDP: Network.webSocketFrameSent/Received)

Roda alem do mitmproxy: o mitmproxy captura o trafego, mas algumas coisas (DOM,
storage, JS dinamico) so existem do lado do browser.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import orjson
import redis.asyncio as redis
from playwright.async_api import (
    Browser,
    BrowserContext,
    CDPSession,
    Page,
    Playwright,
    async_playwright,
)
from ulid import ULID

log = logging.getLogger("ghostmap.browser")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

STREAM = "gm:capture:browser"
MAXLEN = 100_000


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# Script injetado em todos os documentos do contexto.
# Engancha localStorage/sessionStorage, MutationObserver e fetch/XHR
# para enviar eventos via window.__ghostmap_emit, que e exposto pelo Python.
INIT_SCRIPT = r"""
(() => {
  if (window.__ghostmap_installed) return;
  window.__ghostmap_installed = true;
  const emit = (kind, payload) => {
    try { window.__ghostmap_emit(JSON.stringify({ kind, payload, ts: Date.now() })); }
    catch (e) { /* no-op */ }
  };

  // storage hooks
  for (const storage of ["localStorage", "sessionStorage"]) {
    const target = window[storage];
    if (!target) continue;
    const _set = target.setItem.bind(target);
    const _rem = target.removeItem.bind(target);
    target.setItem = (k, v) => { emit("storage_change", { storage, op: "set", key: k, value: v }); _set(k, v); };
    target.removeItem = (k) => { emit("storage_change", { storage, op: "remove", key: k }); _rem(k); };
  }

  // mutation observer (sumarizado, nao spammy)
  try {
    const obs = new MutationObserver(muts => {
      const summary = { adds: 0, removes: 0, attrs: 0, samples: [] };
      for (const m of muts) {
        summary.adds += m.addedNodes ? m.addedNodes.length : 0;
        summary.removes += m.removedNodes ? m.removedNodes.length : 0;
        if (m.type === "attributes") summary.attrs++;
        if (summary.samples.length < 3 && m.target && m.target.nodeName) {
          summary.samples.push(m.target.nodeName.toLowerCase());
        }
      }
      if (summary.adds + summary.removes + summary.attrs > 0) emit("mutation", summary);
    });
    obs.observe(document.documentElement || document, {
      childList: true, subtree: true, attributes: true,
    });
  } catch (e) { /* document not ready */ }

  // fetch + XHR monkey patches (so para metadata; o body real vem do mitmproxy)
  const _fetch = window.fetch;
  window.fetch = function (input, init) {
    const url = (typeof input === "string") ? input : input.url;
    const method = (init && init.method) || (input && input.method) || "GET";
    emit("fetch", { url, method, hasBody: !!(init && init.body) });
    return _fetch.apply(this, arguments);
  };
  const _xhrOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    this.__gm_method = method; this.__gm_url = url;
    return _xhrOpen.apply(this, arguments);
  };
  const _xhrSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function (body) {
    emit("xhr", { url: this.__gm_url, method: this.__gm_method, hasBody: !!body });
    return _xhrSend.apply(this, arguments);
  };

  // script tag dinamico (deteccao de carregamento de JS pos-load)
  const scriptObserver = new MutationObserver(muts => {
    for (const m of muts) {
      for (const n of m.addedNodes || []) {
        if (n.tagName === "SCRIPT" && n.src) emit("script_load", { src: n.src, async: n.async, defer: n.defer });
      }
    }
  });
  try { scriptObserver.observe(document.documentElement, { childList: true, subtree: true }); }
  catch (e) { /* ignore */ }
})();
"""


class Instrumenter:
    """Wrap em torno do Playwright que abre uma session capturando tudo."""

    def __init__(
        self,
        project_id: str,
        session_id: str,
        redis_url: str = "redis://redis:6379/0",
        proxy_url: str | None = None,
        headless: bool = False,
    ) -> None:
        self.project_id = project_id
        self.session_id = session_id
        self.redis_url = redis_url
        self.proxy_url = proxy_url
        self.headless = headless
        self._redis: redis.Redis | None = None
        self._pw: Playwright | None = None
        self._browser: Browser | None = None
        self._context: BrowserContext | None = None
        self._cookie_snapshot: dict[str, str] = {}

    async def __aenter__(self) -> "Instrumenter":
        self._redis = redis.from_url(self.redis_url, decode_responses=False)
        await self._redis.ping()
        self._pw = await async_playwright().start()
        proxy_cfg = {"server": self.proxy_url} if self.proxy_url else None
        self._browser = await self._pw.chromium.launch(headless=self.headless, proxy=proxy_cfg)
        self._context = await self._browser.new_context(
            ignore_https_errors=True,  # mitmproxy CA
        )
        await self._context.add_init_script(INIT_SCRIPT)
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        if self._context: await self._context.close()
        if self._browser: await self._browser.close()
        if self._pw: await self._pw.stop()
        if self._redis: await self._redis.aclose()

    # ---------- public ----------
    async def open(self, url: str) -> Page:
        assert self._context is not None
        page = await self._context.new_page()
        await self._wire_page(page)
        await page.goto(url, wait_until="domcontentloaded")
        await self._snapshot_cookies()
        return page

    async def run_forever(self, start_url: str) -> None:
        """Mantem o browser vivo para uso humano (modo hunter)."""
        page = await self.open(start_url)
        log.info("browser pronto. navegue normalmente. ctrl+c para sair.")
        try:
            while not page.is_closed():
                await asyncio.sleep(2.0)
                await self._snapshot_cookies()
        except KeyboardInterrupt:
            log.info("encerrando instrumenter")

    # ---------- wiring ----------
    async def _wire_page(self, page: Page) -> None:
        # bridge JS -> Python
        await page.expose_function("__ghostmap_emit", lambda raw: asyncio.create_task(self._emit_raw(raw)))

        # navegacao
        page.on("framenavigated", lambda frame: asyncio.create_task(self._emit("navigation", {
            "url": frame.url, "is_main": frame is page.main_frame,
        })))
        # redirects
        page.on("response", lambda resp: asyncio.create_task(self._emit_response(resp)))
        # console nao e capturado por padrao (poluiriamos demais)

        # CDP para WebSocket frames + Network sumario
        try:
            cdp: CDPSession = await page.context.new_cdp_session(page)
            await cdp.send("Network.enable")
            cdp.on("Network.webSocketFrameSent", lambda p: asyncio.create_task(self._emit("websocket_event", {
                "direction": "client_to_server", "payload": p.get("response", {}).get("payloadData", "")[:4096],
                "request_id": p.get("requestId"),
            })))
            cdp.on("Network.webSocketFrameReceived", lambda p: asyncio.create_task(self._emit("websocket_event", {
                "direction": "server_to_client", "payload": p.get("response", {}).get("payloadData", "")[:4096],
                "request_id": p.get("requestId"),
            })))
        except Exception as e:  # pragma: no cover
            log.warning("CDP wiring falhou: %s", e)

    async def _emit_response(self, resp: Any) -> None:
        try:
            if 300 <= resp.status < 400:
                await self._emit("redirect", {"from": resp.url, "to": resp.headers.get("location"), "status": resp.status})
        except Exception:
            pass

    async def _snapshot_cookies(self) -> None:
        assert self._context is not None
        cookies = await self._context.cookies()
        compact = {f"{c['domain']}|{c['name']}": c.get("value", "") for c in cookies}
        diff_added = {k: v for k, v in compact.items() if k not in self._cookie_snapshot}
        diff_changed = {k: v for k, v in compact.items()
                        if k in self._cookie_snapshot and self._cookie_snapshot[k] != v}
        diff_removed = [k for k in self._cookie_snapshot if k not in compact]
        if diff_added or diff_changed or diff_removed:
            await self._emit("cookie_change", {
                "added": list(diff_added.keys()),
                "changed": list(diff_changed.keys()),
                "removed": diff_removed,
            })
            self._cookie_snapshot = compact

    # ---------- emit ----------
    async def _emit_raw(self, raw: str) -> None:
        try:
            data = json.loads(raw)
            await self._emit(data.get("kind", "unknown"), data.get("payload", {}))
        except Exception:
            log.exception("emit_raw failed")

    async def _emit(self, kind: str, payload: dict[str, Any]) -> None:
        if self._redis is None:
            return
        event = {
            "event_id": str(ULID()),
            "schema": "gm.capture.browser/1",
            "project_id": self.project_id,
            "session_id": self.session_id,
            "kind": kind,
            "occurred_at": _now(),
            "payload": payload,
        }
        try:
            await self._redis.xadd(STREAM, {b"d": orjson.dumps(event)}, maxlen=MAXLEN, approximate=True)
        except Exception:
            log.exception("xadd browser stream failed")


async def main() -> None:
    project_id = os.environ["GHOSTMAP_PROJECT_ID"]
    session_id = os.environ.get("GHOSTMAP_SESSION_ID") or str(ULID())
    start_url = os.environ.get("GHOSTMAP_START_URL", "https://example.com")
    proxy = os.environ.get("GHOSTMAP_BROWSER_PROXY", "http://mitmproxy:8080")
    headless = os.environ.get("GHOSTMAP_HEADLESS", "0") == "1"
    async with Instrumenter(project_id, session_id, proxy_url=proxy, headless=headless) as inst:
        await inst.run_forever(start_url)


if __name__ == "__main__":
    asyncio.run(main())
