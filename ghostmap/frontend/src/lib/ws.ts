// Cliente WebSocket com reconexao exponencial.
// Mensagens chegam como JSON { type, data }.

export type WSMessage = { type: string; data: unknown };
type Handler = (m: WSMessage) => void;

export class GhostWS {
  private url: string;
  private ws: WebSocket | null = null;
  private handlers = new Set<Handler>();
  private retry = 0;
  private alive = false;

  constructor(url?: string) {
    this.url = url ?? (process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000/ws");
  }

  connect(): void {
    if (this.alive) return;
    this.alive = true;
    this.open();
  }

  disconnect(): void {
    this.alive = false;
    this.ws?.close();
    this.ws = null;
  }

  on(h: Handler): () => void { this.handlers.add(h); return () => this.handlers.delete(h); }

  private open(): void {
    if (!this.alive) return;
    try {
      this.ws = new WebSocket(this.url);
    } catch {
      this.scheduleReconnect();
      return;
    }
    this.ws.onopen = () => {
      this.retry = 0;
      // keepalive simples
      const ping = setInterval(() => { try { this.ws?.send("ping"); } catch { /* ignore */ } }, 25_000);
      this.ws!.addEventListener("close", () => clearInterval(ping));
    };
    this.ws.onmessage = (ev) => {
      if (ev.data === "pong") return;
      try { this.handlers.forEach((h) => h(JSON.parse(ev.data))); }
      catch { /* ignore */ }
    };
    this.ws.onclose = () => this.scheduleReconnect();
    this.ws.onerror = () => this.ws?.close();
  }

  private scheduleReconnect(): void {
    if (!this.alive) return;
    const delay = Math.min(15_000, 500 * Math.pow(2, this.retry++));
    setTimeout(() => this.open(), delay);
  }
}

export const ghostws = new GhostWS();
