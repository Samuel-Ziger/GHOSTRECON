// ============================================================
// VERIFICADOR DE FAKE NEWS — VERSÃO CORRIGIDA (MENOS FALSOS POSITIVOS)
// ============================================================

// -------------------------------
// HELPERS DE DOM
// -------------------------------
const modal      = document.getElementById("modalOverlay");
const modalIcon  = document.getElementById("modalIcon");
const modalTitle = document.getElementById("modalTitle");
const modalText  = document.getElementById("modalText");
const verifyBtn  = document.getElementById("verifyBtn");
const linkInput  = document.getElementById("linkInput");

// -------------------------------
// URL BAR EDITÁVEL
// -------------------------------
const urlTextInput = document.getElementById("urlText");
if (urlTextInput) {
  urlTextInput.addEventListener("focus", function () {
    window._tiltPaused = true;
    const range = document.createRange();
    range.selectNodeContents(this);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  });
  urlTextInput.addEventListener("keydown", function (e) {
    if (e.key === "Enter") { e.preventDefault(); this.blur(); }
  });
  urlTextInput.addEventListener("input", function () {
    if (this.innerText.length > 30) {
      this.innerText = this.innerText.slice(0, 30);
      const range = document.createRange();
      const sel   = window.getSelection();
      range.selectNodeContents(this);
      range.collapse(false);
      sel.removeAllRanges();
      sel.addRange(range);
    }
  });
  urlTextInput.addEventListener("blur", function () {
    window._tiltPaused = false;
    if (!this.innerText.trim()) this.innerText = "LinkSeguro.com";
  });
}

// -------------------------------
// COLAR LINK
// -------------------------------
async function colarLink() {
  try {
    const text = await navigator.clipboard.readText();
    if (text && text.trim() !== "") {
      linkInput.value = text.trim();
      linkInput.focus();
      const box = document.getElementById("verifyBox");
      box.style.borderColor = "rgba(0,200,150,.9)";
      box.style.boxShadow   = "0 0 30px rgba(0,200,150,.25)";
      setTimeout(() => { box.style.borderColor = ""; box.style.boxShadow = ""; }, 600);
    } else {
      linkInput.focus();
    }
  } catch {
    linkInput.focus();
    try { document.execCommand("paste"); } catch {}
  }
}

// -------------------------------
// ÍCONES DO MODAL
// -------------------------------
function getModalIcon(type) {
  if (type === "safe")
    return `<svg viewBox="0 0 36 36" width="56" height="56"><path d="M18 3L6 8v9c0 7.88 5.14 15.27 12 17 6.86-1.73 12-9.12 12-17V8L18 3z" fill="#00c896" opacity=".18"/><path d="M18 3L6 8v9c0 7.88 5.14 15.27 12 17 6.86-1.73 12-9.12 12-17V8L18 3z" fill="none" stroke="#00c896" stroke-width="2"/><path d="M13 18l3.5 3.5L23 14" stroke="#00c896" stroke-width="2.8" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
  if (type === "warning")
    return `<svg viewBox="0 0 80 80" width="56" height="56"><polygon points="40,8 74,68 6,68" fill="rgba(255,204,0,.18)" stroke="#ffcc00" stroke-width="3"/><line x1="40" y1="28" x2="40" y2="50" stroke="#ffcc00" stroke-width="5" stroke-linecap="round"/><circle cx="40" cy="60" r="4" fill="#ffcc00"/></svg>`;
  if (type === "suspicious")
    return `<svg viewBox="0 0 80 80" width="56" height="56"><polygon points="40,8 74,68 6,68" fill="rgba(255,140,0,.18)" stroke="#ff8c00" stroke-width="3"/><line x1="40" y1="28" x2="40" y2="50" stroke="#ff8c00" stroke-width="5" stroke-linecap="round"/><circle cx="40" cy="60" r="4" fill="#ff8c00"/></svg>`;
  return `<svg viewBox="0 0 36 36" width="56" height="56"><path d="M18 3L6 8v9c0 7.88 5.14 15.27 12 17 6.86-1.73 12-9.12 12-17V8L18 3z" fill="red" opacity=".18"/><path d="M18 3L6 8v9c0 7.88 5.14 15.27 12 17 6.86-1.73 12-9.12 12-17V8L18 3z" fill="none" stroke="red" stroke-width="2"/><line x1="18" y1="12" x2="18" y2="21" stroke="red" stroke-width="3" stroke-linecap="round"/><circle cx="18" cy="26" r="2" fill="red"/></svg>`;
}

// -------------------------------
// MODAL
// -------------------------------
function abrirModalComDetalhes(tipo, titulo, motivosArray, cor) {
  if (!modal || !modalIcon || !modalTitle || !modalText) return;
  modalIcon.innerHTML = getModalIcon(tipo);
  modalTitle.innerText = titulo;
  modalTitle.style.color = cor;
  modalIcon.classList.remove("modal-icon--safe", "modal-icon--warning", "modal-icon--danger");
  const cls = tipo === "safe" ? "modal-icon--safe" : tipo === "warning" || tipo === "suspicious" ? "modal-icon--warning" : "modal-icon--danger";
  modalIcon.classList.add(cls);

  const bgClass =
    tipo === "safe"      ? "modal-message-list--safe"    :
    tipo === "warning"   ? "modal-message-list--warning"  :
    tipo === "suspicious"? "modal-message-list--warning"  :
                           "modal-message-list--danger";

  modalText.innerHTML = motivosArray && motivosArray.length > 0
    ? `<div class="modal-message-list ${bgClass}"><ul>${motivosArray.map(m => `<li>${m}</li>`).join("")}</ul></div>`
    : `<div class="modal-message-list ${bgClass}"><p>Nenhum detalhe adicional.</p></div>`;

  modal.classList.add("active");
  setTimeout(initSwipeToClose, 50);
}

function fecharModal() {
  modal.classList.remove("active");
  if (modalBoxElement) { modalBoxElement.style.transform = ""; modalBoxElement.classList.remove("swiping"); }
  modal.style.background = "";
  isSwiping = false; touchStartY = 0; touchCurrentY = 0;
}

modal.addEventListener("click", e => { if (e.target === modal) fecharModal(); });

// ============================================================
// NOVA FUNÇÃO: VERIFICAÇÃO DE WHITELIST CORRIGIDA
// ============================================================
function dominioEstaNaWhitelist(dominio) {
  // Remove www. se existir
  const dominioLimpo = dominio.replace(/^www\./, '');
  
  return [...DOMINIOS_CONFIAVEIS].some(s => {
    const sLimpo = s.replace(/^www\./, '');
    return dominioLimpo === sLimpo || dominioLimpo.endsWith('.' + sLimpo);
  });
}

// ============================================================
// EXTRAÇÃO DE TEXTO DO HTML (MELHORADA)
// ============================================================
function extrairTextoHTML(html) {
  const tmp = document.createElement("div");
  tmp.innerHTML = html
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<nav[\s\S]*?<\/nav>/gi, "")
    .replace(/<header[\s\S]*?<\/header>/gi, "")
    .replace(/<footer[\s\S]*?<\/footer>/gi, "")
    .replace(/<aside[\s\S]*?<\/aside>/gi, "")
    .replace(/<form[\s\S]*?<\/form>/gi, "")
    // Remoção adicional de elementos de navegação/anúncios com classes comuns
    .replace(/<div[^>]*class="[^"]*menu[^"]*"[\s\S]*?<\/div>/gi, "")
    .replace(/<div[^>]*class="[^"]*sidebar[^"]*"[\s\S]*?<\/div>/gi, "")
    .replace(/<div[^>]*class="[^"]*advertisement[^"]*"[\s\S]*?<\/div>/gi, "")
    .replace(/<div[^>]*class="[^"]*related[^"]*"[\s\S]*?<\/div>/gi, "")
    .replace(/<div[^>]*class="[^"]*footer[^"]*"[\s\S]*?<\/div>/gi, "")
    .replace(/<div[^>]*class="[^"]*nav[^"]*"[\s\S]*?<\/div>/gi, "")
    .replace(/<[^>]+>/g, " ");
  return tmp.textContent.replace(/\s+/g, " ").trim().slice(0, 8000);
}

// ============================================================
// LISTA NEGRA DE DOMÍNIOS (DESINFORMAÇÃO BRASILEIRA)
// ============================================================
const DOMINIOS_FAKE_BR = new Set([
  // Política / conspiração
  "noticias24horas.net","verdadeoculta.com","obrasilqueamedia.com",
  "acordabrasil.com.br","jornaldaverdade.net","noticias-agora.net",
  "oalertabrasil.com","folhadovovo.com","osegredodesvelado.com",
  "portalzap.com.br","tverdade.com.br","imprensanacional.net",
  "diariodobrasil.org","brasilsemfiltro.com","olavete.com",
  "revodelia.com","estudosnatologia.com","noticiasbr.net",
  "agorabrasilia.com","verdadeiro.net","boletimbrasil.com",
  "alertanacional.net","canallivre.net","brasilurgente.org",
  "brazilnews247.com","noticiasagora.org","portalverdade.com",
  "portalimparcial.com","jornalimparcial.net","brasilreal.net",
  "patriotabrasil.com","nacionaofiel.com","voxpopuli.com.br",
  "novaordem.org","resistenciabrasil.com","brasilweb.news",
  "oradiobr.com","contranews.com","brasil247fake.com",
  "folhaverdade.com","gazetabrasil.net","tribunabr.com",
  "jornaloliberal.com","notizbrasil.com","conectabrasil.net",
  "alertabrasil.news","tribunadopovo.net","jornalhorasul.com",
  "brasiliaurgente.com","agoranoticias.net","plataformabrasil.org",
  // Saúde falsa
  "curanatural.net","saudealternativa.com","remedioscaseiros.net",
  "saude365.com.br","natureba.com.br","curamilagrosa.com",
  "saúdeemfoco.net","fitosaude.com","medicinanaturalista.com",
  "terapiasnaturais.net","saudenaural.com","curanativa.com",
  "ervasnaturais.com","receitasnaturais.net","naturoterapia.com",
  "saudeecura.com","portaldasaude.info","curabolsonaro.com",
  "medicamentosproibidos.net","saúdeglobal.net","vidanaturalista.com",
  // Financeiro / golpe
  "rendaextra.com.br","ganhedinheiro.net","bitcoinbrasil.info",
  "investimentoseguro.com","fortunafacil.net","ricoinvestidor.com",
  "investinow.com.br","cryptocoins.com.br","quickprofit.com.br",
  "moneybr.net","sitemilionario.com","emprestimofacil.net",
  "creditorapido.info","dinheiroemcasa.net","aposentadoriafacil.com",
  "beneficiogov.org","inssalerta.com","beneficiourgente.com",
  "auxilio2024.com","bolsafamiliagov.org","caixagovauxilio.com",
  // Sites imitadores / typosquatting
  "g1-globo.com","g1noticias.com","folhadespaullo.com",
  "estadaoo.com","oglobonews.com","bbcbrasil.net",
  "cnnbrasilnews.com","bnews.com.br","uolnoticias.org",
  "vejanoticias.com","examebrasil.com","gazetadopovobr.com",
  "agenciabrasill.com","agenciabrasilnews.com","r7news.net",
  "sbtnoticiasoficial.com","redenews.com.br","recordnoticias.net",
  // Religiosos / conspiracionistas
  "fim-dos-tempos.com","apocalipse-now.net","profeciabrasil.com",
  "revelacaoceleste.com","oraculo.news","visaoprofética.com",
  "evangelhodiario.net","alertacristao.com","igrejadaverdade.net"
]);

// ============================================================
// DOMÍNIOS CONFIÁVEIS (WHITELIST EXPANDIDA)
// ============================================================
const DOMINIOS_CONFIAVEIS = new Set([
  // Domínios de veículos de imprensa
  "g1.globo.com", "ge.globo.com", "gshow.globo.com", "globo.com",
  "uol.com.br", "folha.uol.com.br", "band.uol.com.br",
  "bbc.com", "bbc.co.uk", "cnn.com", "cnnbrasil.com.br",
  "reuters.com", "apnews.com",
  "estadao.com.br", "oglobo.globo.com", "correiobraziliense.com.br",
  "agenciabrasil.ebc.com.br", "ebc.com.br",
  "veja.abril.com.br", "abril.com.br",
  "exame.com", "valor.com.br", "gazetadopovo.com.br",
  "terra.com.br", "r7.com", "sbt.com.br", "recordtv.com.br",
  "carta.capital.com.br", "istoe.com.br", "poder360.com.br",
  "nexojornal.com.br", "agenciapublica.org.br", "piauí.art.br",
  "theintercept.com", "metropoles.com", "em.com.br",
  "elpais.com", "nytimes.com", "theguardian.com",
  "washingtonpost.com", "lemonde.fr", "dw.com", "france24.com",
  "euronews.com", "aljazeera.com",
  // Fontes oficiais do governo
  "gov.br", "saude.gov.br", "mec.gov.br", "anvisa.gov.br", "inpe.br",
  "ibge.gov.br", "planalto.gov.br", "senado.leg.br", "camara.leg.br",
  "stf.jus.br", "tse.jus.br", "leg.br", "jus.br",
  // Fontes científicas e de saúde
  "portal.fiocruz.br", "who.int", "cdc.gov", "nature.com",
  "sciencedirect.com", "pubmed.ncbi.nlm.nih.gov",
  // Outros
  "noticiaspaulistanas.com.br"
]);

// ============================================================
// ENCURTADORES DE URL
// ============================================================
const ENCURTADORES = new Set([
  "bit.ly","tinyurl.com","cutt.ly","ow.ly","t.co","goo.gl",
  "rb.gy","linktr.ee","is.gd","short.io","tiny.cc","lnkd.in",
  "buff.ly","ht.ly","soo.gd","snip.ly","clk.sh","bl.ink"
]);

// ============================================================
// TLDs DE ALTO RISCO
// ============================================================
const TLDS_SUSPEITOS = new Set([
  ".xyz",".top",".click",".tk",".ml",".ga",".cf",".pw",
  ".gq",".icu",".buzz",".cc",".ws",".monster",".cyou",
  ".cfd",".bond",".hair",".dad",".zip",".mov",".fit",
  ".lol",".sbs",".beauty",".skin",".cam",".live"
]);

// ============================================================
// ANÁLISE DE DOMÍNIO (CORRIGIDA)
// ============================================================
function analisarDominio(url) {
  const dominio = url.hostname.toLowerCase();
  const partes  = dominio.split(".");
  const tld     = "." + partes.slice(-1)[0];
  let score = 0, fatores = [];

  // HTTPS
  if (url.protocol === "https:") { score += 1; }
  else { score -= 2; fatores.push({ peso: -2, texto: "⚠ Site sem HTTPS (conexão insegura)" }); }

  // Whitelist (CORRIGIDA)
  if (dominioEstaNaWhitelist(dominio)) {
    score += 8; // Peso maior para confiáveis
    fatores.push({ peso: 8, texto: `✔ Domínio reconhecido como veículo confiável: ${dominio}` });
    return { score, fatores }; // Retorna imediatamente, ignorando outras verificações
  }

  // Blacklist
  if ([...DOMINIOS_FAKE_BR].some(s => dominio === s || dominio.endsWith("." + s))) {
    score -= 6;
    fatores.push({ peso: -6, texto: `✖ Domínio presente em lista de sites de desinformação conhecidos` });
  }

  // Encurtadores
  if (ENCURTADORES.has(dominio)) {
    score -= 2;
    fatores.push({ peso: -2, texto: "⚠ Link encurtado — destino real oculto" });
  }

  // TLD suspeito
  if (TLDS_SUSPEITOS.has(tld)) {
    score -= 3;
    fatores.push({ peso: -3, texto: `⚠ Extensão de domínio de alto risco: ${tld}` });
  }

  // IP direto
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(dominio)) {
    score -= 4;
    fatores.push({ peso: -4, texto: "✖ URL usa endereço IP direto (padrão de phishing)" });
  }

  // Subdomínios excessivos
  if (partes.length > 4) {
    score -= 2;
    fatores.push({ peso: -2, texto: `⚠ Subdomínios excessivos (${partes.length} níveis)` });
  }

  // Typosquatting
  const marcas = [
    { nome: "globo", legitimos: ["globo.com","g1.globo.com","ge.globo.com","gshow.globo.com"] },
    { nome: "uol",   legitimos: ["uol.com.br","folha.uol.com.br","band.uol.com.br"] },
    { nome: "folha", legitimos: ["folha.uol.com.br"] },
    { nome: "estadao", legitimos: ["estadao.com.br"] },
    { nome: "bbc",   legitimos: ["bbc.com","bbc.co.uk"] },
    { nome: "cnn",   legitimos: ["cnn.com","cnnbrasil.com.br"] },
    { nome: "veja",  legitimos: ["veja.abril.com.br"] },
    { nome: "exame", legitimos: ["exame.com"] },
    { nome: "gov",   legitimos: [] },
    { nome: "reuters",legitimos: ["reuters.com"] },
  ];
  for (const marca of marcas) {
    if (dominio.includes(marca.nome) && !marca.legitimos.some(l => dominio === l || dominio.endsWith("." + l))) {
      score -= 4;
      fatores.push({ peso: -4, texto: `✖ Possível imitação (typosquatting) de veículo: "${marca.nome}"` });
      break;
    }
  }

  // Domínio com dígitos excessivos
  if (/\d{3,}/.test(partes[0])) {
    score -= 1;
    fatores.push({ peso: -1, texto: "⚠ Números excessivos no nome do domínio" });
  }

  // Hifens excessivos
  if ((dominio.match(/-/g) || []).length >= 3) {
    score -= 1;
    fatores.push({ peso: -1, texto: "⚠ Muitos hifens no domínio (padrão suspeito)" });
  }

  // Domínio .com.br ou .org.br (sinal neutro positivo)
  if (dominio.endsWith(".com.br") || dominio.endsWith(".org.br") || dominio.endsWith(".net.br")) {
    score += 1;
    fatores.push({ peso: 1, texto: "✔ Domínio brasileiro registrado (.com.br / .org.br)" });
  }

  return { score, fatores };
}

// ============================================================
// ANÁLISE AVANÇADA DA URL
// ============================================================
function analisarURLAvancada(url) {
  const href = url.href.toLowerCase();
  const path = url.pathname.toLowerCase();
  const fatores = [];

  // Palavras de alarme na URL
  const alarme = [
    "verdade","revelado","urgente","chocante","exclusivo","segredo",
    "proibido","censurado","vazou","bomba","milagre","cura","escondido",
    "exposto","inacreditavel","choquei","voce-nao-vai-acreditar",
    "antes-que-apaguem","governo-esconde","fake","mentira"
  ];
  const alarmeEnc = alarme.filter(p => href.includes(p));
  if (alarmeEnc.length >= 3)
    fatores.push({ peso: -4, texto: `✖ URL repleta de termos alarmantes: "${alarmeEnc.slice(0,3).join('", "')}"` });
  else if (alarmeEnc.length >= 1)
    fatores.push({ peso: -2, texto: `⚠ Termo suspeito na URL: "${alarmeEnc[0]}"` });

  // URL muito longa
  if (url.href.length > 250)
    fatores.push({ peso: -2, texto: "⚠ URL excessivamente longa (padrão de phishing)" });

  // Arquivo executável
  if (/\.(exe|zip|rar|apk|bat|cmd|scr|pif|msi|dmg)(\?|$)/i.test(path))
    fatores.push({ peso: -6, texto: "✖ URL aponta para arquivo executável (altíssimo risco)" });

  // Parâmetros de rastreamento suspeitos (excesso)
  const params = [...url.searchParams.keys()];
  if (params.length > 8)
    fatores.push({ peso: -1, texto: `⚠ URL com muitos parâmetros de rastreamento (${params.length})` });

  // Porta não-padrão
  if (url.port && url.port !== "80" && url.port !== "443")
    fatores.push({ peso: -3, texto: `⚠ URL usa porta não-padrão: ${url.port}` });

  return fatores;
}

// ============================================================
// ANÁLISE DE TEXTO (COM THRESHOLDS AJUSTADOS)
// ============================================================
function analisarTextoCompleto(texto) {
  const t      = texto.toLowerCase();
  const palavras = t.split(/\s+/).filter(Boolean);
  const total  = palavras.length;
  const fatores = [];

  // --- Maiúsculas em bloco ---
  const maiusculas = (texto.match(/[A-ZÁÉÍÓÚÀÃÕÂÊÔ]{4,}/g) || []).length;
  if (maiusculas >= 8)  fatores.push({ peso: -3, texto: `✖ Excesso grave de letras em caixa alta (${maiusculas}x)` });
  else if (maiusculas >= 3) fatores.push({ peso: -1, texto: `⚠ Uso de caixa alta em bloco (${maiusculas}x)` });

  // --- Pontuação excessiva (AJUSTADO) ---
  const exclamacoes = (texto.match(/!/g) || []).length;
  if (exclamacoes >= 8)  fatores.push({ peso: -3, texto: `✖ Pontuação excessiva: ${exclamacoes} exclamações` });
  else if (exclamacoes >= 5) fatores.push({ peso: -1, texto: `⚠ Múltiplas exclamações (${exclamacoes})` });

  // --- Linguagem sensacionalista ---
  const sensacional = [
    "urgente","imperdível","chocante","inacreditável","bomba","revelado",
    "vazado","censurado","milagre","exclusivo","segredo","espalhe",
    "compartilhe agora","antes que apaguem","governo esconde",
    "médicos odeiam","eles não querem que você saiba","viralizou",
    "nunca antes visto","assustador","confirmado agora","proibido",
    "ninguém acredita","isso mudou tudo","chocou o brasil",
    "impressionante","absurdo","inédito","histórico","revelação bombástica",
    "você precisa ver","salva antes de sumir","informação censurada"
  ];
  const sensEnc = sensacional.filter(p => t.includes(p));
  if (sensEnc.length >= 4) fatores.push({ peso: -4, texto: `✖ Linguagem fortemente sensacionalista: "${sensEnc.slice(0,3).join('", "')}"` });
  else if (sensEnc.length >= 2) fatores.push({ peso: -2, texto: `⚠ Termos sensacionalistas: "${sensEnc.slice(0,2).join('", "')}"` });
  else if (sensEnc.length === 1) fatores.push({ peso: -1, texto: `⚠ Termo sensacionalista: "${sensEnc[0]}"` });

  // --- Fontes citadas ---
  const fontesPadroes = [
    "segundo","de acordo com","conforme","afirmou","declarou","disse",
    "informou","relatou","apurou","publicou","divulgou","noticiou",
    "pesquisa","estudo","levantamento","ministério","secretaria",
    "especialistas afirmam","cientistas","pesquisadores","instituto"
  ];
  const fontesEnc = fontesPadroes.filter(p => t.includes(p)).length;
  if (fontesEnc === 0 && total > 80)
    fatores.push({ peso: -3, texto: "✖ Nenhuma fonte citada no conteúdo" });
  else if (fontesEnc >= 4)
    fatores.push({ peso: 3, texto: `✔ Múltiplas fontes identificadas no texto (${fontesEnc}x)` });
  else if (fontesEnc >= 1)
    fatores.push({ peso: 1, texto: `✔ Ao menos uma fonte citada (${fontesEnc}x)` });

  // --- Apelo ao medo ---
  const apelMedo = [
    "cuidado","perigo","atenção","alerta","grave","sérios riscos",
    "todos serão afetados","isso vai te matar","pode matar","risco de morte",
    "acorde","estão te enganando","não deixe seus filhos","o fim",
    "apocalipse","colapso","golpe","ditadura","invasão","catástrofe",
    "tragédia iminente","fim do mundo","ameaça real","exterminação"
  ];
  const medoEnc = apelMedo.filter(p => t.includes(p));
  if (medoEnc.length >= 4) fatores.push({ peso: -4, texto: `✖ Apelo intenso ao medo: "${medoEnc.slice(0,3).join('", "')}"` });
  else if (medoEnc.length >= 2) fatores.push({ peso: -2, texto: `⚠ Apelo ao medo: "${medoEnc.slice(0,2).join('", "')}"` });
  else if (medoEnc.length === 1) fatores.push({ peso: -1, texto: `⚠ Linguagem de medo: "${medoEnc[0]}"` });

  // --- Contexto temporal ---
  const temData = /\b(janeiro|fevereiro|março|abril|maio|junho|julho|agosto|setembro|outubro|novembro|dezembro|\d{1,2}\/\d{1,2}\/\d{2,4}|20\d\d|ontem|hoje|esta semana|este mês)\b/i.test(texto);
  if (!temData && total > 100)
    fatores.push({ peso: -2, texto: "⚠ Ausência de datas ou contexto temporal verificável" });
  else if (temData)
    fatores.push({ peso: 1, texto: "✔ Referência temporal presente" });

  // --- Autoria ---
  const temAutor = /\b(redação|por |repórter|jornalista|editor|equipe|staff|correspondente|autor)\b/i.test(texto);
  if (!temAutor && total > 80)
    fatores.push({ peso: -2, texto: "⚠ Autoria não identificada no conteúdo" });
  else if (temAutor)
    fatores.push({ peso: 1, texto: "✔ Autoria ou veículo identificado" });

  // --- Generalizações absolutas ---
  const absolutos = [
    "todo mundo sabe","todos concordam","é fato que","ninguém pode negar",
    "ficou provado","já está comprovado","100% eficaz","absolutamente certo",
    "definitivamente","sem sombra de dúvida","é mentira que","não existe",
    "impossível questionar","é a verdade absoluta"
  ];
  const absEnc = absolutos.filter(p => t.includes(p));
  if (absEnc.length >= 3) fatores.push({ peso: -3, texto: `✖ Múltiplas generalizações absolutas: "${absEnc.slice(0,2).join('", "')}"` });
  else if (absEnc.length >= 1) fatores.push({ peso: -2, texto: `⚠ Afirmação absoluta: "${absEnc[0]}"` });

  // --- Pedido de compartilhamento viral ---
  const share = [
    "compartilhe","repasse","manda pra todo mundo","passa pra frente",
    "mostre para","avise seus amigos","salva esse post","não deixa sumir",
    "antes que deletem","copia e cola","manda no grupo","espalha",
    "manda para sua família","reencaminhe","encaminhe agora"
  ];
  const shareEnc = share.filter(p => t.includes(p));
  if (shareEnc.length >= 2)
    fatores.push({ peso: -4, texto: `✖ Forte pedido de compartilhamento viral: "${shareEnc[0]}"` });
  else if (shareEnc.length === 1)
    fatores.push({ peso: -3, texto: `⚠ Pedido de compartilhamento: "${shareEnc[0]}"` });

  // --- Teorias da conspiração ---
  const conspiracao = [
    "élite","illuminati","deep state","estado profundo","nova ordem mundial",
    "agenda oculta","querem te calar","supressão da verdade","grande reset",
    "chip","implante","controle mental","5g mata","vacina mata",
    "veneno na água","chemtrail","sionismo","novo hitler","globalismo",
    "george soros","bill gates matar","wef agenda","foro de são paulo"
  ];
  const conspEnc = conspiracao.filter(p => t.includes(p));
  if (conspEnc.length >= 3)
    fatores.push({ peso: -5, texto: `✖ Narrativa conspiratória intensa: "${conspEnc.slice(0,3).join('", "')}"` });
  else if (conspEnc.length >= 1)
    fatores.push({ peso: -3, texto: `⚠ Elemento conspiratório: "${conspEnc[0]}"` });

  // --- Saúde falsa ---
  const saudeFalsa = [
    "cura definitiva","cura o câncer","elimina o vírus","médicos estão escondendo",
    "faz emagrecer","basta tomar","receita caseira que cura","remédio natural milagroso",
    "farmacêuticas não querem","proibido pela anvisa","proibido nos eua","funciona mesmo",
    "tratamento caseiro","100% natural sem efeitos","emagrece sem dieta",
    "cura aids","cura diabetes","inverte o envelhecimento"
  ];
  const saudeEnc = saudeFalsa.filter(p => t.includes(p));
  if (saudeEnc.length >= 2)
    fatores.push({ peso: -5, texto: `✖ Múltiplas alegações de saúde falsas: "${saudeEnc[0]}"` });
  else if (saudeEnc.length === 1)
    fatores.push({ peso: -4, texto: `✖ Alegação de saúde suspeita: "${saudeEnc[0]}"` });

  // --- Fact-checkers citados ---
  const factcheck = [
    "agência lupa","aos fatos","boatos.org","e-farsas","snopes",
    "politifact","fact.check","verificado por","fato ou fake",
    "checamos","checagem","comprova","reuters fact check","afp fact check"
  ];
  if (factcheck.filter(p => t.includes(p)).length >= 1)
    fatores.push({ peso: 3, texto: "✔ Referência a agência de fact-checking" });

  // --- Fontes oficiais e científicas ---
  const agencias = [
    "reuters","ap news","agência brasil","ibge","fiocruz","ministério da saúde",
    "oms","who","anvisa","inpe","cdc","nasa","ipca","banco central",
    "senado federal","câmara dos deputados","stf","tse","receita federal",
    "pnad","oxford","harvard","unicamp","usp","fgv"
  ];
  const agEnc = agencias.filter(p => t.includes(p));
  if (agEnc.length >= 3)
    fatores.push({ peso: 4, texto: `✔ Fontes institucionais citadas: ${agEnc.slice(0,3).join(", ")}` });
  else if (agEnc.length >= 1)
    fatores.push({ peso: 2, texto: `✔ Fonte institucional mencionada: ${agEnc[0]}` });

  // --- Linguagem de ódio ---
  const odio = [
    "deveria morrer","são lixo","não são humanos","exterminar",
    "raça inferior","vermes","parasitas","bandidos do mal",
    "escória da sociedade","devem ser eliminados","merecem morrer"
  ];
  const odioEnc = odio.filter(p => t.includes(p));
  if (odioEnc.length >= 1)
    fatores.push({ peso: -5, texto: `✖ Linguagem de ódio detectada` });

  // --- Linguagem política extremamente polarizada ---
  const polarizacao = [
    "comunista","fascista","nazista","esquerdista","direitista",
    "lula ladrão","bolsominion","petralha","golpista","milícia",
    "bandido vermelho","coxinha","mortadela","genocida","traidor da pátria",
    "marxismo cultural","destruir a família","projeto socialista"
  ];
  const polEnc = polarizacao.filter(p => t.includes(p));
  if (polEnc.length >= 4)
    fatores.push({ peso: -4, texto: `✖ Linguagem altamente polarizada (${polEnc.length} termos)` });
  else if (polEnc.length >= 2)
    fatores.push({ peso: -2, texto: `⚠ Linguagem política polarizada: "${polEnc.slice(0,2).join('", "')}"` });

  // --- Dados numéricos (jornalismo real cita números) ---
  const numeros = (texto.match(/\b\d+([.,]\d+)?(%|mil|milhão|bilhão|kg|km|m²)?\b/g) || []).length;
  if (total > 100 && numeros < 2)
    fatores.push({ peso: -1, texto: "⚠ Nenhum dado numérico verificável no texto" });
  else if (numeros >= 5)
    fatores.push({ peso: 1, texto: "✔ Dados numéricos presentes no conteúdo" });

  // --- Diversidade vocabular ---
  const unicos     = new Set(palavras).size;
  const diversidade = total > 0 ? unicos / total : 0;
  if (total > 100 && diversidade < 0.35)
    fatores.push({ peso: -1, texto: `⚠ Baixa diversidade vocabular — texto repetitivo (${Math.round(diversidade * 100)}%)` });
  else if (total > 100 && diversidade > 0.6)
    fatores.push({ peso: 1, texto: `✔ Boa diversidade vocabular (${Math.round(diversidade * 100)}%)` });

  // --- Tamanho do texto ---
  if (total < 50)
    fatores.push({ peso: -2, texto: "⚠ Texto muito curto para análise confiável" });
  else if (total > 400)
    fatores.push({ peso: 1, texto: "✔ Texto extenso — maior contexto disponível" });

  // --- Alegações financeiras milagrosas ---
  const financeiro = [
    "ganhe dinheiro fácil","renda extra garantida","fique rico rapidamente",
    "investimento seguro com retorno","retorno garantido","sem risco nenhum",
    "dinheiro na conta hoje","esquema lucrativo","pirâmide financeira",
    "enriqueça em dias","lucro certo","renda passiva imediata"
  ];
  const finEnc = financeiro.filter(p => t.includes(p));
  if (finEnc.length >= 1)
    fatores.push({ peso: -5, texto: `✖ Alegação financeira suspeita: "${finEnc[0]}"` });

  // --- Previsões catastrofistas ---
  const futuro = [
    "vai acabar","vão fechar","será proibido","vão prender",
    "vai colapsar","vão destruir","o fim de","vai sumir",
    "o brasil vai acabar","economia vai colapsar"
  ];
  const futuroEnc = futuro.filter(p => t.includes(p));
  if (futuroEnc.length >= 3)
    fatores.push({ peso: -3, texto: `⚠ Previsões catastrofistas: "${futuroEnc[0]}"` });

  // --- Links externos (transparência) ---
  if (/https?:\/\/|www\./.test(texto))
    fatores.push({ peso: 1, texto: "✔ Referências externas mencionadas no texto" });

  return { score: fatores.reduce((s, f) => s + f.peso, 0), fatores, totalPalavras: total };
}

// ============================================================
// ANÁLISE DE ESTRUTURA DO HTML BRUTO
// ============================================================
function analisarEstruturaHTML(html) {
  const h = html.toLowerCase();
  const fatores = [];

  // Página tem seção "sobre" ou "quem somos"
  if (/sobre|quem somos|nossa equipe|redação|about us/i.test(h))
    fatores.push({ peso: 2, texto: "✔ Site possui seção 'sobre' ou 'quem somos'" });
  else
    fatores.push({ peso: -1, texto: "⚠ Site sem página de apresentação identificada" });

  // Política de privacidade
  if (/política de privacidade|termos de uso|privacy policy/i.test(h))
    fatores.push({ peso: 1, texto: "✔ Política de privacidade ou termos de uso encontrados" });

  // Contato
  if (/contato|fale conosco|contact|redação@|jornalismo@/i.test(h))
    fatores.push({ peso: 1, texto: "✔ Canal de contato identificado" });

  // Muitos anúncios / scripts de ads
  const adScripts = (h.match(/doubleclick|adsense|taboola|outbrain|mgid|revcontent|adsbygoogle/g) || []).length;
  if (adScripts >= 3)
    fatores.push({ peso: -1, texto: `⚠ Alta densidade de anúncios (${adScripts} redes de ads detectadas)` });

  // WordPress, Blogger (plataforma genérica)
  if (/wp-content|wp-json|wordpress\.com|blogspot\.com/i.test(h))
    fatores.push({ peso: -1, texto: "⚠ Site em plataforma de blog genérica (WordPress/Blogspot)" });

  // Metatags de veículo de imprensa
  if (/og:site_name|article:publisher|application\/ld\+json/i.test(h))
    fatores.push({ peso: 1, texto: "✔ Metadados estruturados de veículo de imprensa presentes" });

  // CNPJ / registro legal mencionado
  if (/cnpj|inscri[çc][aã]o estadual|razão social/i.test(h))
    fatores.push({ peso: 1, texto: "✔ CNPJ ou registro empresarial mencionado" });

  // Data de publicação em metadados
  if (/published_time|datePublished|article:published/i.test(h))
    fatores.push({ peso: 1, texto: "✔ Data de publicação nos metadados" });

  // Muitos redirects / iframes suspeitos
  const iframes = (h.match(/<iframe/g) || []).length;
  if (iframes >= 5)
    fatores.push({ peso: -2, texto: `⚠ Muitos iframes na página (${iframes}) — padrão de conteúdo pago enganoso` });

  return fatores;
}

// ============================================================
// VERIFICAÇÃO DE CONSISTÊNCIA INTERNA DO TEXTO
// ============================================================
function verificarConsistenciaInterna(texto) {
  const fatores = [];
  const frases = texto.split(/[.!?]+/).filter(f => f.trim().length > 10);

  // Título com letras maiúsculas na primeira linha
  const primFrase = texto.slice(0, 200);
  if (/[A-ZÁÉÍÓÚÀÃÕÂÊÔ]{5,}/.test(primFrase) && (primFrase.match(/!/g) || []).length >= 2)
    fatores.push({ peso: -2, texto: "⚠ Título com caixa alta e exclamações — padrão de clickbait" });

  // Texto com primeira pessoa apelativa
  const primeiraP = ["eu vi","eu descobri","eu soube","fui informado","me disseram que","um amigo me contou"];
  const ppEnc = primeiraP.filter(p => texto.toLowerCase().includes(p));
  if (ppEnc.length >= 1)
    fatores.push({ peso: -2, texto: `⚠ Relato em primeira pessoa sem verificação: "${ppEnc[0]}"` });

  // Texto coerente (tem parágrafos e pontuação)
  const paragrafos = texto.split(/\n\n+/).filter(p => p.trim().length > 50).length;
  if (paragrafos >= 3 && frases.length >= 5)
    fatores.push({ peso: 1, texto: "✔ Texto com estrutura editorial coerente" });

  return fatores;
}

// ============================================================
// VEREDICTO — 5 NÍVEIS
// ============================================================
function calcVeredicto(score) {
  if (score >= 7)  return { tipo: "safe",       titulo: "✔ Provavelmente Confiável",     cor: "#00c896" };
  if (score >= 3)  return { tipo: "warning",    titulo: "⚠ Requer Atenção",              cor: "#60c030" };
  if (score >= 0)  return { tipo: "warning",    titulo: "⚠ Conteúdo Questionável",       cor: "#ffcc00" };
  if (score >= -4) return { tipo: "suspicious", titulo: "⚠ Conteúdo Suspeito",           cor: "#ff8c00" };
  return               { tipo: "danger",     titulo: "✖ Alto Risco de Desinformação",  cor: "#ff3b3b" };
}

// ============================================================
// VERIFICAÇÃO PRINCIPAL (COM PROTEÇÃO CONTRA FALSOS POSITIVOS)
// ============================================================
async function verificarLink() {
  let valor = linkInput.value.trim();
  if (valor === "") {
    abrirModalComDetalhes("warning", "Campo vazio", ["Cole ou digite um link antes de verificar."], "#ffcc00");
    return;
  }

  verifyBtn.classList.add("loading");
  verifyBtn.textContent = "Analisando...";

  if (!/^https?:\/\//i.test(valor)) valor = "https://" + valor;

  let url;
  try { url = new URL(valor); } catch {
    verifyBtn.classList.remove("loading");
    verifyBtn.textContent = "VERIFICAR";
    abrirModalComDetalhes("warning", "Link inválido",
      ["O endereço não parece válido.", "Verifique se está completo e tente novamente."], "#ffcc00");
    return;
  }

  const msgs = ["Verificando domínio…", "Analisando estrutura…", "Examinando conteúdo…", "Calculando veredicto…"];
  let msgIdx = 0;
  const msgTimer = setInterval(() => {
    if (++msgIdx < msgs.length) verifyBtn.textContent = msgs[msgIdx];
  }, 1200);

  let textoExtraido = "";
  let htmlBruto     = "";

  try {
    const ctrl  = new AbortController();
    const tid   = setTimeout(() => ctrl.abort(), 6000);
    const proxy = "https://api.allorigins.win/get?url=" + encodeURIComponent(valor);
    const resp  = await fetch(proxy, { signal: ctrl.signal });
    clearTimeout(tid);
    const json  = await resp.json();
    htmlBruto     = json.contents || "";
    textoExtraido = extrairTextoHTML(htmlBruto);
  } catch (e) {
    console.warn("Conteúdo não obtido:", e);
  } finally {
    clearInterval(msgTimer);
  }

  // --- Camadas de análise ---
  const domRes    = analisarDominio(url);
  const urlExtra  = analisarURLAvancada(url);

  let scoreTotal        = domRes.score + urlExtra.reduce((s, f) => s + f.peso, 0);
  let fatoresCombinados = [...domRes.fatores, ...urlExtra];
  let totalPalavras     = 0;

  // Verifica se é domínio confiável para suavizar a análise de texto
  const dominioAtual = url.hostname.toLowerCase();
  const ehConfiável = dominioEstaNaWhitelist(dominioAtual);

  if (textoExtraido.length > 150) {
    const textoRes    = analisarTextoCompleto(textoExtraido);
    const consistRes  = verificarConsistenciaInterna(textoExtraido);
    const estrutHTML  = htmlBruto.length > 100 ? analisarEstruturaHTML(htmlBruto) : [];

    let pesoTexto = textoRes.score;
    let pesoConsist = consistRes.reduce((s, f) => s + f.peso, 0);
    let pesoEstrut = estrutHTML.reduce((s, f) => s + f.peso, 0);

    // Se for domínio confiável, reduzimos o impacto de análises textuais
    if (ehConfiável) {
      // Apenas considera fatores muito graves (peso <= -3) e reduz pela metade
      const fatoresGravesTexto = textoRes.fatores.filter(f => f.peso <= -3);
      pesoTexto = fatoresGravesTexto.reduce((s, f) => s + Math.round(f.peso * 0.5), 0) 
                  + textoRes.fatores.filter(f => f.peso > 0).reduce((s, f) => s + f.peso, 0);
      
      const fatoresGravesConsist = consistRes.filter(f => f.peso <= -3);
      pesoConsist = fatoresGravesConsist.reduce((s, f) => s + Math.round(f.peso * 0.5), 0)
                    + consistRes.filter(f => f.peso > 0).reduce((s, f) => s + f.peso, 0);
      
      // Estrutura do HTML é menos penalizada
      pesoEstrut = estrutHTML.filter(f => f.peso > 0).reduce((s, f) => s + f.peso, 0)
                   + estrutHTML.filter(f => f.peso <= -3).reduce((s, f) => s + Math.round(f.peso * 0.5), 0);
    }

    scoreTotal += pesoTexto + pesoConsist + pesoEstrut;

    // Fatores mantidos para exibição, mas com pesos originais (para o usuário ver)
    fatoresCombinados = [
      ...fatoresCombinados,
      ...textoRes.fatores,
      ...consistRes,
      ...estrutHTML
    ];
    totalPalavras = textoRes.totalPalavras;
  } else {
    fatoresCombinados.push({
      peso: 0,
      texto: "ℹ Conteúdo não extraído — análise baseada no domínio e URL"
    });
  }

  const veredicto = calcVeredicto(scoreTotal);

  // --- Ordenar fatores: negativos primeiro, depois positivos, neutros por último ---
  const negativos = fatoresCombinados.filter(f => f.peso < 0).sort((a, b) => a.peso - b.peso).map(f => f.texto);
  const positivos = fatoresCombinados.filter(f => f.peso > 0).map(f => f.texto);
  const neutros   = fatoresCombinados.filter(f => f.peso === 0).map(f => f.texto);

  const scoreLabel = scoreTotal >= 0 ? `+${scoreTotal}` : `${scoreTotal}`;
  const motivosArray = [
    `🔗 Domínio: ${url.hostname}`,
    totalPalavras ? `📄 Palavras analisadas: ${totalPalavras}` : null,
    `📊 Pontuação de confiabilidade: ${scoreLabel}`,
    ...negativos,
    ...positivos,
    ...neutros
  ].filter(Boolean);

  verifyBtn.classList.remove("loading");
  verifyBtn.textContent = "VERIFICAR";
  abrirModalComDetalhes(veredicto.tipo, veredicto.titulo, motivosArray, veredicto.cor);
}

// -------------------------------
// EVENT LISTENERS
// -------------------------------
if (linkInput) linkInput.addEventListener("keypress", e => { if (e.key === "Enter") verificarLink(); });
if (verifyBtn) verifyBtn.addEventListener("click", verificarLink);

// -------------------------------
// FECHAR MODAL — BOTÃO
// -------------------------------
const modalCloseBtn = document.getElementById("modalCloseBtn");
if (modalCloseBtn) modalCloseBtn.addEventListener("click", fecharModal);

// -------------------------------
// ANIMAÇÃO DOS CARDS
// -------------------------------
const cards   = document.querySelectorAll(".info-card");
const observer = new IntersectionObserver(entries => {
  entries.forEach(e => { if (e.isIntersecting) e.target.classList.add("show"); });
}, { threshold: 0.15 });

cards.forEach(card => {
  observer.observe(card);
  card.addEventListener("touchstart", () => card.classList.add("touched"), { passive: true });
  card.addEventListener("touchend",   () => setTimeout(() => card.classList.remove("touched"), 300));
  card.addEventListener("mousemove", e => {
    const r = card.getBoundingClientRect();
    card.style.transform = `perspective(1000px) rotateX(${(e.clientY - r.top - r.height / 2) / 18}deg) rotateY(${(r.width / 2 - (e.clientX - r.left)) / 18}deg) translateY(-8px) scale(1.02)`;
  });
  card.addEventListener("mouseleave", () => { card.style.transform = ""; });
});

// -------------------------------
// TILT 3D NO BROWSER CARD
// -------------------------------
const browserCard = document.querySelector(".browser-card");
const visual      = document.querySelector(".visual");

if (browserCard && visual) {
  let targetX = 0, targetY = 0, currentX = 0, currentY = 0;
  const startTime = performance.now();
  function lerp(a, b, t) { return a + (b - a) * t; }
  function tick(now) {
    currentX = lerp(currentX, targetX, 0.055);
    currentY = lerp(currentY, targetY, 0.055);
    browserCard.style.transform = `perspective(1000px) rotateY(${12 + currentX}deg) rotateX(${4 + currentY}deg) translateY(${Math.sin((now - startTime) / 900) * 7}px)`;
    requestAnimationFrame(tick);
  }
  visual.addEventListener("mousemove", e => {
    if (window._tiltPaused) return;
    const r = browserCard.getBoundingClientRect();
    targetX =  ((e.clientX - r.left - r.width  / 2) / r.width)  * 16;
    targetY = -((e.clientY - r.top  - r.height / 2) / r.height) * 12;
  });
  visual.addEventListener("mouseleave", () => {
    if (window._tiltPaused) return;
    targetX = 0; targetY = 0;
  });
  setTimeout(() => {
    browserCard.style.willChange = "transform";
    browserCard.style.animation  = "none";
    requestAnimationFrame(tick);
  }, 1000);
}

// -------------------------------
// EFEITO DOTS
// -------------------------------
document.querySelectorAll(".dot").forEach(dot => {
  dot.addEventListener("click", () => {
    dot.style.transform = "scale(1.25)";
    setTimeout(() => { dot.style.transform = "scale(1)"; }, 180);
  });
});

// -------------------------------
// SWIPE TO CLOSE (MOBILE)
// -------------------------------
let touchStartY = 0, touchCurrentY = 0, isSwiping = false, modalBoxElement = null;

function initSwipeToClose() {
  modalBoxElement = document.querySelector(".modal-box");
  if (!modalBoxElement) return;
  if (!document.querySelector(".modal-swipe-indicator") && window.innerWidth <= 480) {
    const ind = document.createElement("div");
    ind.className = "modal-swipe-indicator";
    modalBoxElement.insertBefore(ind, modalBoxElement.firstChild);
  }
  modalBoxElement.removeEventListener("touchstart", handleTouchStart);
  modalBoxElement.removeEventListener("touchmove",  handleTouchMove);
  modalBoxElement.removeEventListener("touchend",   handleTouchEnd);
  modalBoxElement.addEventListener("touchstart", handleTouchStart, { passive: false });
  modalBoxElement.addEventListener("touchmove",  handleTouchMove,  { passive: false });
  modalBoxElement.addEventListener("touchend",   handleTouchEnd);
}

function handleTouchStart(e) {
  if (!modal.classList.contains("active")) return;
  touchStartY = e.touches[0].clientY;
  isSwiping   = true;
  if (modalBoxElement) modalBoxElement.classList.add("swiping");
}

function handleTouchMove(e) {
  if (!isSwiping || !modal.classList.contains("active")) return;
  touchCurrentY  = e.touches[0].clientY;
  const diffY    = touchCurrentY - touchStartY;
  if (diffY > 0) {
    e.preventDefault();
    if (modalBoxElement) modalBoxElement.style.transform = `translateY(${Math.min(diffY, 200)}px)`;
    modal.style.background = `rgba(0,0,0,${Math.max(0, 0.85 - diffY / 800)})`;
  }
}

function handleTouchEnd() {
  if (!isSwiping || !modal.classList.contains("active")) { isSwiping = false; return; }
  if (touchCurrentY - touchStartY > 80) fecharModal();
  if (modalBoxElement) { modalBoxElement.style.transform = ""; modalBoxElement.classList.remove("swiping"); }
  modal.style.background = "";
  isSwiping = false; touchStartY = 0; touchCurrentY = 0;
}

document.addEventListener("DOMContentLoaded", initSwipeToClose);

// -------------------------------
// AJUSTE DE TEXTO NO MOBILE
// -------------------------------
if (window.innerWidth <= 768) {
  document.querySelectorAll(".feature-item").forEach(item => {
    if (item.textContent.includes("Analisa domínios")) {
      item.childNodes.forEach(node => {
        if (node.nodeType === 3 && node.textContent.trim() === "Analisa domínios") {
          node.textContent = "";
          const span = document.createElement("span");
          span.innerHTML = "Analisa<br>domínios";
          item.appendChild(span);
        }
      });
    }
  });
}