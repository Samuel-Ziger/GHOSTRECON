export function HackbotLaunchCard() {
  const open = () => {
    const url = new URL('hackbot.html', window.location.href).href;
    const opened = window.open(url, 'ghostrecon_hackbot', 'noopener,noreferrer');
    if (!opened) window.location.href = url;
  };
  return (
    <button
      aria-label="Abrir painel multiagente HackBot"
      className="mitre-map-btn hackbot-hub-btn"
      onClick={open}
      title="HackBot — equipe multiagente, seleção direta de especialistas e modelos por função."
      type="button"
    >
      <span className="mitre-map-btn-icon-wrap hackbot-hub-icon" aria-hidden="true">HB</span>
      <span className="mitre-map-btn-copy">
        <span className="mitre-map-btn-kicker">MULTIAGENTES</span>
        <span className="mitre-map-btn-title">HackBot</span>
        <span className="mitre-map-btn-subtitle">Orquestrador opcional · MCP · ACP · modelos por função</span>
      </span>
    </button>
  );
}
