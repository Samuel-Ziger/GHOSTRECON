import { useEffect, useRef, useState } from 'react';
import { analisarConteudo, extrairTextoHTML } from '../script.js';

const ICON_PATHS = {
  alert: <><polygon points="40,8 74,68 6,68" fill="rgba(255,0,0,.12)" stroke="red" strokeWidth="4" strokeLinejoin="round" /><line x1="40" y1="28" x2="40" y2="50" stroke="red" strokeWidth="5" strokeLinecap="round" /><circle cx="40" cy="60" r="3.8" fill="red" /></>,
  calendar: <><rect x="3" y="4" width="18" height="18" rx="2" /><line x1="16" y1="2" x2="16" y2="6" /><line x1="8" y1="2" x2="8" y2="6" /><line x1="3" y1="10" x2="21" y2="10" /><circle cx="12" cy="15" r="1" /><circle cx="16" cy="15" r="1" /><circle cx="8" cy="15" r="1" /></>,
  globe: <><circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" /><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z" /></>,
  image: <><rect x="2" y="2" width="20" height="20" rx="2" /><circle cx="8.5" cy="8.5" r="1.5" /><circle cx="15.5" cy="15.5" r="1.5" /><path d="M8.5 15.5L15.5 8.5" /></>,
  info: <><circle cx="12" cy="12" r="10" /><path d="M12 16v-4M12 8h.01" strokeLinecap="round" /></>,
  layers: <><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" /></>,
  link: <><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71" /><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71" /></>,
  megaphone: <><path d="M3 11v2a4 4 0 004 4h1l1 4h2l1-4h.5L18 20V4l-5.5 3H7a4 4 0 00-4 4z" /><path d="M18 8a3 3 0 010 8" /></>,
  search: <><circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" /></>,
  shield: <><path d="M12 2L4 5v6c0 5.25 3.5 10.15 8 11.35C16.5 21.15 20 16.25 20 11V5L12 2z" /><path d="M9 12l2 2 4-4" /></>,
  skull: <><path d="M12 2a7 7 0 00-7 7c0 2.5 1.3 4.7 3.3 6H8v1h8v-1h-.3C17.7 13.7 19 11.5 19 9a7 7 0 00-7-7z" /><path d="M10 19v2M14 19v2M9 12a2 2 0 002-2M15 12a2 2 0 01-2-2" /></>,
};

function Icon({ name, viewBox = '0 0 24 24', className }) {
  return <svg className={className} viewBox={viewBox} aria-hidden="true">{ICON_PATHS[name]}</svg>;
}

function Header({ page }) {
  return (
    <header>
      <div className="container header-wrap">
        <a className="logo logo-link" href="./index.html" aria-label="LinkSeguro - início">
          Link<span>Seguro</span><span className="logo-icon"><Icon name="shield" /></span>
        </a>
        <nav id="mainNav" aria-label="Navegação principal">
          <a href="./index.html" className={page === 'home' ? 'active' : ''}>Início</a>
          <a href="./dicas.html" className={page === 'tips' ? 'active' : ''}>Dicas</a>
        </nav>
      </div>
    </header>
  );
}

function BottomNav({ page }) {
  return (
    <nav className="bottom-nav" aria-label="Navegação móvel">
      <a href="./index.html" className={`bottom-nav-item ${page === 'home' ? 'active' : ''}`}>
        <svg viewBox="0 0 256 256" aria-hidden="true"><path d="M219.31 108.68l-80-80a16 16 0 00-22.62 0l-80 80A15.87 15.87 0 0032 120v96a8 8 0 008 8h64a8 8 0 008-8v-56h32v56a8 8 0 008 8h64a8 8 0 008-8v-96a15.87 15.87 0 00-4.69-11.32zM208 208h-48v-56a8 8 0 00-8-8h-48a8 8 0 00-8 8v56H48v-88l80-80 80 80z" /></svg>
        <span>Início</span>
      </a>
      <a href="./dicas.html" className={`bottom-nav-item ${page === 'tips' ? 'active' : ''}`}>
        <svg viewBox="0 0 256 256" aria-hidden="true"><path d="M176 232a8 8 0 01-8 8H88a8 8 0 010-16h80a8 8 0 018 8zm40-128a87.55 87.55 0 01-33.64 69.21A16.24 16.24 0 00176 186v6a16 16 0 01-16 16H96a16 16 0 01-16-16v-6a16 16 0 00-6.23-12.66A87.59 87.59 0 0140 104.49C39.74 56.83 78.26 17.14 125.88 16A88 88 0 01216 104zm-16 0a72 72 0 00-73.74-72C87.26 32.92 55.79 65.39 56 104.39a71.65 71.65 0 0027.64 56.3A32 32 0 0196 186v6h64v-6a32.15 32.15 0 0112.47-25.35A71.65 71.65 0 00200 104z" /></svg>
        <span>Dicas</span>
      </a>
    </nav>
  );
}

function ModalIcon({ type }) {
  if (type === 'safe') return <svg viewBox="0 0 36 36"><path d="M18 3L6 8v9c0 7.88 5.14 15.27 12 17 6.86-1.73 12-9.12 12-17V8L18 3z" fill="#00c896" opacity=".18" /><path d="M18 3L6 8v9c0 7.88 5.14 15.27 12 17 6.86-1.73 12-9.12 12-17V8L18 3z" fill="none" stroke="#00c896" strokeWidth="2" /><path d="M13 18l3.5 3.5L23 14" stroke="#00c896" strokeWidth="2.8" fill="none" /></svg>;
  const color = type === 'danger' ? '#ff3b3b' : type === 'suspicious' ? '#ff8c00' : '#ffcc00';
  return <svg viewBox="0 0 80 80"><polygon points="40,8 74,68 6,68" fill={`${color}2e`} stroke={color} strokeWidth="3" /><line x1="40" y1="28" x2="40" y2="50" stroke={color} strokeWidth="5" strokeLinecap="round" /><circle cx="40" cy="60" r="4" fill={color} /></svg>;
}

function ResultModal({ result, onClose }) {
  const [drag, setDrag] = useState(0);
  const startY = useRef(0);
  useEffect(() => {
    if (!result) return undefined;
    const onKey = (event) => event.key === 'Escape' && onClose();
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [result, onClose]);
  if (!result) return null;
  const type = result.veredicto.tipo;
  const messageClass = type === 'safe' ? 'safe' : type === 'danger' ? 'danger' : 'warning';
  return (
    <div className="modal-overlay active" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <section
        className={`modal-box ${drag ? 'swiping' : ''}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby="result-title"
        style={{ transform: drag ? `translateY(${drag}px)` : undefined }}
        onTouchStart={(event) => { startY.current = event.touches[0].clientY; }}
        onTouchMove={(event) => setDrag(Math.max(0, Math.min(200, event.touches[0].clientY - startY.current)))}
        onTouchEnd={() => { if (drag > 80) onClose(); setDrag(0); }}
      >
        <div className="modal-swipe-indicator" />
        <div className={`modal-icon modal-icon--${messageClass}`}><ModalIcon type={type} /></div>
        <h2 id="result-title" style={{ color: result.veredicto.cor }}>{result.veredicto.titulo}</h2>
        <div className={`modal-message-list modal-message-list--${messageClass}`}>
          <ul>{result.motivos.map((motivo, index) => <li key={`${index}-${motivo}`}>{motivo}</li>)}</ul>
        </div>
        <button type="button" onClick={onClose}>FECHAR</button>
      </section>
    </div>
  );
}

function BrowserCard() {
  const cardRef = useRef(null);
  const target = useRef({ x: 0, y: 0 });
  const paused = useRef(false);
  useEffect(() => {
    let frame = 0;
    let currentX = 0;
    let currentY = 0;
    const started = performance.now();
    const tick = (now) => {
      currentX += (target.current.x - currentX) * 0.055;
      currentY += (target.current.y - currentY) * 0.055;
      if (cardRef.current) cardRef.current.style.transform = `perspective(1000px) rotateY(${12 + currentX}deg) rotateX(${4 + currentY}deg) translateY(${Math.sin((now - started) / 900) * 7}px)`;
      frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, []);
  return (
    <div className="visual" onMouseMove={(event) => {
      if (paused.current || !cardRef.current) return;
      const box = cardRef.current.getBoundingClientRect();
      target.current = { x: ((event.clientX - box.left - box.width / 2) / box.width) * 16, y: -((event.clientY - box.top - box.height / 2) / box.height) * 12 };
    }} onMouseLeave={() => { target.current = { x: 0, y: 0 }; }}>
      <div className="browser-card" ref={cardRef}>
        <div className="browser-bar">
          {[0, 1, 2].map((dot) => <button type="button" className="dot" aria-label={`Indicador ${dot + 1}`} key={dot} />)}
          <div className="url-bar"><Icon name="link" /><span id="urlText" contentEditable suppressContentEditableWarning spellCheck="false" onFocus={(event) => { paused.current = true; const selection = window.getSelection(); const range = document.createRange(); range.selectNodeContents(event.currentTarget); selection.removeAllRanges(); selection.addRange(range); }} onBlur={(event) => { paused.current = false; if (!event.currentTarget.textContent.trim()) event.currentTarget.textContent = 'LinkSeguro.com'; }} onInput={(event) => { if (event.currentTarget.textContent.length > 30) event.currentTarget.textContent = event.currentTarget.textContent.slice(0, 30); }}>LinkSeguro.com</span></div>
        </div>
        <div className="alert-area">
          <div className="alert-triangle"><Icon name="alert" viewBox="0 0 80 80" /></div>
          <div className="alert-lines"><div className="alert-title">ALERTA</div><div className="alert-line-bar" /><div className="alert-line-bar" /><div className="alert-line-bar" /></div>
        </div>
      </div>
    </div>
  );
}

function HomePage() {
  const [value, setValue] = useState('');
  const [fetchContent, setFetchContent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [buttonText, setButtonText] = useState('VERIFICAR');
  const [result, setResult] = useState(null);
  const inputRef = useRef(null);

  const pasteLink = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text.trim()) setValue(text.trim());
    } catch {
      inputRef.current?.focus();
    }
  };

  const verify = async () => {
    let normalized = value.trim();
    if (!normalized) {
      setResult({ veredicto: { tipo: 'warning', titulo: 'Campo vazio', cor: '#ffcc00' }, motivos: ['Cole ou digite um link antes de verificar.'] });
      return;
    }
    if (!/^https?:\/\//i.test(normalized)) normalized = `https://${normalized}`;
    let url;
    try { url = new URL(normalized); } catch {
      setResult({ veredicto: { tipo: 'warning', titulo: 'Link inválido', cor: '#ffcc00' }, motivos: ['O endereço não parece válido.', 'Verifique se está completo e tente novamente.'] });
      return;
    }

    setBusy(true);
    setButtonText('Analisando...');
    const messages = ['Verificando domínio…', 'Analisando estrutura…', 'Examinando conteúdo…', 'Calculando veredicto…'];
    let messageIndex = 0;
    const messageTimer = window.setInterval(() => { messageIndex += 1; if (messageIndex < messages.length) setButtonText(messages[messageIndex]); }, 1200);
    let rawHtml = '';
    let extractedText = '';

    try {
      if (fetchContent) {
        const controller = new AbortController();
        const timeout = window.setTimeout(() => controller.abort(), 6000);
        try {
          const proxy = `https://api.allorigins.win/get?url=${encodeURIComponent(normalized)}`;
          const response = await fetch(proxy, { signal: controller.signal });
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          const body = await response.json();
          rawHtml = String(body.contents || '');
          extractedText = extrairTextoHTML(rawHtml);
        } finally {
          window.clearTimeout(timeout);
        }
      }
    } catch (error) {
      console.warn('Conteúdo não obtido; usando análise local:', error);
    } finally {
      window.clearInterval(messageTimer);
    }

    setResult(analisarConteudo(url, extractedText, rawHtml));
    setButtonText('VERIFICAR');
    setBusy(false);
  };

  return (
    <>
      <section className="hero" id="inicioSecao">
        <div className="container hero-wrap">
          <div className="hero-left">
            <div className="title-white">NEM TUDO QUE<br />VOCÊ VÊ</div>
            <div className="title-red">É VERDADE.<span className="shield-check"><Icon name="shield" /></span></div>
            <p className="hero-sub">Cole o link suspeito abaixo e descubra se ele é confiável ou se pode ser <span>desinformação</span>.</p>
            <div className="search-wrap">
              <div className="search-bar" id="verifyBox">
                <button className="search-icon paste-action" type="button" onClick={pasteLink} aria-label="Colar link da área de transferência" title="Colar link"><Icon name="link" /></button>
                <input ref={inputRef} type="url" id="linkInput" value={value} onChange={(event) => setValue(event.target.value)} onKeyDown={(event) => event.key === 'Enter' && !busy && verify()} placeholder="https://cole-o-link-aqui.com" autoComplete="off" />
                <button id="verifyBtn" type="button" className={busy ? 'loading' : ''} disabled={busy} onClick={verify}><Icon name="search" />{buttonText}</button>
              </div>
              <div className="below-search">
                <div className="search-hint"><span className="hint-label">Exemplo:</span><span className="hint-example">https://noticia.com/artigo</span></div>
                <label className="consent-option"><input type="checkbox" checked={fetchContent} onChange={(event) => setFetchContent(event.target.checked)} />Consultar o conteúdo por proxy público (envia a URL ao AllOrigins)</label>
                <div className="features-row">
                  <div className="feature-item"><Icon name="shield" />Detecta encurtadores</div><div className="feature-sep" />
                  <div className="feature-item"><Icon name="globe" />Analisa<br className="mobile-only" /> domínios</div><div className="feature-sep" />
                  <div className="feature-item"><Icon name="search" />Verifica confiabilidade</div>
                </div>
                <div className="safe"><Icon name="shield" />A análise de domínio é local. A consulta externa só ocorre com sua seleção.</div>
              </div>
            </div>
          </div>
          <BrowserCard />
        </div>
      </section>
      <ResultModal result={result} onClose={() => setResult(null)} />
    </>
  );
}

const IDENTIFY_CARDS = [
  ['megaphone', 'Título Sensacionalista', 'Desconfie de títulos chamativos, alarmistas ou que prometem revelações absurdas. O exagero é uma bandeira vermelha.'],
  ['search', 'Fonte Desconhecida', 'Verifique quem publicou. Sites sem nome, sem "sobre" ou com muitos erros grotescos podem ser falsos e perigosos.'],
  ['skull', 'Apelo Emocional', 'Notícias que usam raiva, medo ou comoção para manipular você. Informação séria apresenta dados, não apenas sentimentos.'],
  ['link', 'Link Estranho', 'Cuidado com links encurtados ou com domínios bizarros. Um clique pode levar a golpes.'],
];

const PRACTICE_CARDS = [
  ['info', 'Pesquise a Origem', 'Antes de compartilhar, veja se outros veículos sérios e portais oficiais divulgaram a mesma notícia. A falta de fontes múltiplas é suspeita.'],
  ['calendar', 'Cuidado com Datas Antigas', 'Muitas fake news reciclam acontecimentos velhos e os reapresentam como se fossem atuais. Sempre cheque a data original.'],
  ['image', 'Verifique Imagens', 'Use busca reversa de imagens para descobrir se uma foto ou print foi tirado de contexto ou manipulado digitalmente.'],
  ['layers', 'Não Compartilhe no Impulso', 'Evite o viral emocional. Leia além da manchete, confira fontes e só então decida se realmente vale compartilhar.'],
];

function InfoCard({ data }) {
  const ref = useRef(null);
  useEffect(() => {
    const element = ref.current;
    if (!element) return undefined;
    if (!('IntersectionObserver' in window)) { element.classList.add('show'); return undefined; }
    const observer = new IntersectionObserver(([entry]) => entry.isIntersecting && element.classList.add('show'), { threshold: 0.15 });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  return (
    <article ref={ref} className="info-card" onMouseMove={(event) => { const box = event.currentTarget.getBoundingClientRect(); event.currentTarget.style.transform = `perspective(1000px) rotateX(${(event.clientY - box.top - box.height / 2) / 18}deg) rotateY(${(box.width / 2 - (event.clientX - box.left)) / 18}deg) translateY(-8px) scale(1.02)`; }} onMouseLeave={(event) => { event.currentTarget.style.transform = ''; }} onTouchStart={(event) => event.currentTarget.classList.add('touched')} onTouchEnd={(event) => window.setTimeout(() => event.currentTarget.classList.remove('touched'), 300)}>
      <div className="card-icon-wrap"><Icon name={data[0]} /></div><h3>{data[1]}</h3><div className="line" /><p>{data[2]}</p>
    </article>
  );
}

function TipsPage() {
  return (
    <>
      <section className="page-hero"><div className="container"><div className="page-hero-label">Guia de Proteção</div></div></section>
      <section className="section container" id="identificarSecao"><h2>Como identificar <span>fake news?</span></h2><p className="sub">Fique atento a esses sinais antes de acreditar ou compartilhar qualquer conteúdo.</p><div className="grid">{IDENTIFY_CARDS.map((card) => <InfoCard key={card[1]} data={card} />)}</div></section>
      <section className="section container" id="dicasSecao"><h2>Dicas práticas para <span>não cair em golpes</span></h2><p className="sub">Pequenas ações que fazem toda diferença.</p><div className="grid">{PRACTICE_CARDS.map((card) => <InfoCard key={card[1]} data={card} />)}</div></section>
      <section className="cta-section container"><div className="cta-box"><h2>Quer verificar um link suspeito?</h2><p>Use o LinkSeguro e descubra em segundos se um link é confiável.</p><a href="./index.html" className="cta-btn" draggable="false">VERIFICAR AGORA</a></div></section>
    </>
  );
}

export function App({ page }) {
  useEffect(() => {
    document.title = page === 'tips' ? 'LinkSeguro | Dicas & Identificação' : 'LinkSeguro | Verificador de Confiabilidade';
  }, [page]);
  return <><Header page={page} /><main>{page === 'tips' ? <TipsPage /> : <HomePage />}</main><BottomNav page={page} /></>;
}
