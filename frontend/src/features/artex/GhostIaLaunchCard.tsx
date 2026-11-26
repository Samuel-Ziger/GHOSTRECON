export function GhostIaLaunchCard() {
  const open = () => {
    const url = new URL('ghostia.html', window.location.href).href;
    const opened = window.open(url, 'ghostrecon_ghostia', 'noopener,noreferrer');
    if (!opened) window.location.assign(url);
  };

  return (
    <div className="hub-actions-row-mitre">
      <button
        aria-label="Abrir GhostIA em tela própria"
        className="mitre-map-btn ghostia-hub-btn"
        id="ghostIaHubBtn"
        onClick={open}
        title="GhostIA — chat Artex, modo multiagente HackBot, modelos por função e MCP GHOSTRECON."
        type="button"
      >
        <span className="mitre-map-btn-skin" aria-hidden="true">
          <span className="mitre-map-btn-shine" />
          <span className="mitre-map-btn-inner">
            <span className="mitre-map-btn-icon-wrap ghostia-hub-icon">
              <svg viewBox="0 0 32 32" aria-hidden="true" focusable="false">
                <path d="M16 4.5c-6.2 0-10.5 4.7-10.5 10.8v10.2l3.1-2.7 3.2 2.7 4.1-2.7 4.1 2.7 3.3-2.7 3.2 2.7V15.3C26.5 9.2 22.2 4.5 16 4.5Z" />
                <circle cx="12.3" cy="14.6" r="1.8" />
                <circle cx="19.7" cy="14.6" r="1.8" />
                <path className="ghostia-hub-signal" d="M9.5 8.7c3.7-3 9.3-3 13 0M12 11.1c2.3-1.6 5.7-1.6 8 0" />
              </svg>
            </span>
            <span className="mitre-map-btn-copy">
              <span className="mitre-map-btn-title">GhostIA</span>
            </span>
            <span className="mitre-map-btn-aside">
              <span className="mitre-map-btn-live"><span className="mitre-map-btn-live-dot" /> chat</span>
              <span className="mitre-map-btn-arrow" aria-hidden="true">↗</span>
            </span>
          </span>
        </span>
      </button>
    </div>
  );
}
