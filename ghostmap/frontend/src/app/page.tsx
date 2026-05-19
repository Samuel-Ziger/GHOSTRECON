export default function HomePage() {
  return (
    <div className="p-10 max-w-3xl">
      <h1 className="text-3xl font-semibold tracking-tight mb-2">GhostMap</h1>
      <p className="text-mute mb-8">
        Mapeamento visual de aplicações web para bug bounty e pentest ofensivo.
      </p>
      <div className="grid grid-cols-2 gap-4">
        <a href="/ghostrecon" className="block rounded-xl border border-accent/30 bg-panel p-5 hover:border-accent/50 transition col-span-2">
          <div className="text-sm text-mute mb-1">GHOSTRECON</div>
          <div className="font-medium">Hub MITRE + grafo de achados (ao vivo)</div>
        </a>
        <a href="/projects" className="block rounded-xl border border-border bg-panel p-5 hover:border-accent/40 transition">
          <div className="text-sm text-mute mb-1">Comece aqui</div>
          <div className="font-medium">Criar / abrir projeto</div>
        </a>
        <a href="/proxy" className="block rounded-xl border border-border bg-panel p-5 hover:border-accent/40 transition">
          <div className="text-sm text-mute mb-1">Live capture</div>
          <div className="font-medium">Proxy & requests</div>
        </a>
        <a href="/graph" className="block rounded-xl border border-border bg-panel p-5 hover:border-accent/40 transition">
          <div className="text-sm text-mute mb-1">Topologia</div>
          <div className="font-medium">Grafo da aplicação</div>
        </a>
        <a href="/roles" className="block rounded-xl border border-border bg-panel p-5 hover:border-accent/40 transition">
          <div className="text-sm text-mute mb-1">Diferencial</div>
          <div className="font-medium">Role differential</div>
        </a>
      </div>
    </div>
  );
}
