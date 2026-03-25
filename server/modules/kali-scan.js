import fs from 'fs';
import { readFile, writeFile, mkdtemp, rm } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';
import { spawn } from 'node:child_process';

const WORDLISTS = [
  '/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt',
  '/usr/share/seclists/Discovery/Web-Content/common.txt',
  '/usr/share/wordlists/dirb/common.txt',
];

function sanitizeHost(h) {
  if (typeof h !== 'string' || h.length > 253 || h.length < 3) return null;
  const s = h.trim().toLowerCase();
  if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(s)) return null;
  return s;
}

async function pathWhich(cmd) {
  return new Promise((resolve) => {
    const p = spawn('which', [cmd], { stdio: ['ignore', 'pipe', 'pipe'] });
    p.on('close', (c) => resolve(c === 0));
  });
}

export async function getKaliCapabilities() {
  const force = process.env.GHOSTRECON_FORCE_KALI === '1';
  let distroKali = false;
  try {
    const rel = fs.readFileSync('/etc/os-release', 'utf8');
    if (/\bID=kali\b/i.test(rel)) distroKali = true;
    else if (/PRETTY_NAME=.*[Kk]ali/i.test(rel)) distroKali = true;
  } catch {
    /* não-Linux ou sem os-release */
  }

  const qualifyDistro = distroKali || force;
  const tools = {
    nmap: await pathWhich('nmap'),
    nuclei: await pathWhich('nuclei'),
    ffuf: await pathWhich('ffuf'),
    searchsploit: await pathWhich('searchsploit'),
  };

  const ready = qualifyDistro && tools.nmap;
  let message = 'Modo agressivo disponível.';
  if (!qualifyDistro) {
    message = 'Não é Kali Linux. Usa Kali ou define GHOSTRECON_FORCE_KALI=1 (apenas testes).';
  } else if (!tools.nmap) {
    message = 'nmap não encontrado no PATH.';
  }

  return {
    kali: ready,
    kaliDistro: distroKali,
    forced: force,
    qualifyDistro,
    tools,
    message,
  };
}

function runProc(cmd, args, timeoutMs) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    let killed = false;
    const t = setTimeout(() => {
      killed = true;
      try {
        child.kill('SIGKILL');
      } catch {
        /* ignore */
      }
      reject(new Error(`${cmd} timeout (${timeoutMs}ms)`));
    }, timeoutMs);
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.on('error', (e) => {
      clearTimeout(t);
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(t);
      if (killed) return;
      resolve({
        code,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8'),
      });
    });
  });
}

function getAttr(attrStr, key) {
  const m = attrStr.match(new RegExp(`${key}="([^"]*)"`));
  return m ? m[1] : '';
}

export function parseNmapXml(xml) {
  const rows = [];
  const parts = xml.split(/<host[\s>]/);
  for (let i = 1; i < parts.length; i++) {
    const hc = parts[i];
    const hostLabel =
      (hc.match(/<hostname name="([^"]+)"/) || [])[1] ||
      (hc.match(/<address addr="([^"]+)" addrtype="ipv4"/) || [])[1] ||
      (hc.match(/<address addr="([^"]+)" addrtype="ipv6"/) || [])[1] ||
      'unknown';

    const portRe =
      /<port protocol="(\w+)" portid="(\d+)">\s*<state state="open"[^>]*\/>\s*<service([^/]*)\/>/g;
    let m;
    while ((m = portRe.exec(hc)) !== null) {
      const attrs = m[3];
      const name = getAttr(attrs, 'name');
      const product = getAttr(attrs, 'product');
      const version = getAttr(attrs, 'version');
      const extrainfo = getAttr(attrs, 'extrainfo');
      const searchBlob = [product, version, name, extrainfo].filter(Boolean).join(' ').trim();
      rows.push({
        host: hostLabel,
        port: m[2],
        proto: m[1],
        name,
        product,
        version,
        extrainfo,
        searchBlob,
      });
    }
  }
  return rows;
}

async function runNmapOnHosts(hosts, log) {
  const dir = await mkdtemp(join(tmpdir(), 'ghnr-'));
  const xmlPath = join(dir, 'nmap.xml');
  const extra = (process.env.GHOSTRECON_NMAP_ARGS || '-sV -Pn -T4 --host-timeout 180s')
    .split(/\s+/)
    .filter(Boolean);
  const args = [...extra, '-oX', xmlPath, ...hosts];
  log(`nmap ${args.slice(0, -hosts.length).join(' ')} [${hosts.length} hosts]`, 'info');
  try {
    const proc = await runProc('nmap', args, 660000);
    if (proc.code !== 0) {
      log(`nmap terminou com código ${proc.code}`, 'warn');
    }
    const xml = await readFile(xmlPath, 'utf8');
    return parseNmapXml(xml);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function searchExploitDbOne(query, log) {
  const q = query.slice(0, 100).trim();
  if (q.length < 2) return [];
  const tryJson = async (args) => {
    const r = await runProc('searchsploit', args, 40000);
    if (!r.stdout.trim()) return [];
    try {
      const j = JSON.parse(r.stdout);
      if (Array.isArray(j)) return j.slice(0, 8);
      if (j.RESULTS_EXPLOIT && Array.isArray(j.RESULTS_EXPLOIT)) return j.RESULTS_EXPLOIT.slice(0, 8);
      if (j.RESULTS_SHELLCODE && Array.isArray(j.RESULTS_SHELLCODE)) return j.RESULTS_SHELLCODE.slice(0, 8);
      if (j.results && Array.isArray(j.results)) return j.results.slice(0, 8);
    } catch {
      /* texto */
    }
    return [];
  };
  try {
    let rows = await tryJson(['--json', q]);
    if (rows.length) return rows;
    rows = await tryJson(['-j', q]);
    return rows;
  } catch (e) {
    log(`searchsploit "${q.slice(0, 40)}…": ${e.message}`, 'warn');
    return [];
  }
}

function exploitTitle(row) {
  if (typeof row === 'string') return row;
  return row.Title || row.title || row.Path || row['EDB-ID'] || row.EDB_ID || JSON.stringify(row).slice(0, 120);
}

function exploitUrl(row) {
  const id = row['EDB-ID'] || row.EDB_ID || row.id || row['edb-id'];
  if (id) return `https://www.exploit-db.com/exploits/${id}`;
  return row.url || '';
}

async function runFfuf200(baseUrl, log) {
  const wl = WORDLISTS.find((p) => fs.existsSync(p));
  if (!wl) {
    log('ffuf: nenhuma wordlist em /usr/share/seclists ou dirb', 'warn');
    return [];
  }
  const dir = await mkdtemp(join(tmpdir(), 'ghff-'));
  const out = join(dir, 'out.json');
  const base = baseUrl.replace(/\/$/, '');
  try {
    const args = [
      '-u',
      `${base}/FUZZ`,
      '-w',
      wl,
      '-mc',
      '200',
      '-t',
      '32',
      '-timeout',
      '8',
      '-maxtime',
      '120',
      '-of',
      'json',
      '-o',
      out,
      '-s',
    ];
    await runProc('ffuf', args, 135000);
    const raw = await readFile(out, 'utf8');
    const j = JSON.parse(raw);
    return (j.results || []).map((r) => r.url).filter(Boolean);
  } catch (e) {
    log(`ffuf ${base}: ${e.message}`, 'warn');
    return [];
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function runNucleiList(urls, log) {
  if (!urls.length) return [];
  const dir = await mkdtemp(join(tmpdir(), 'ghnu-'));
  const listFile = join(dir, 'targets.txt');
  const outFile = join(dir, 'out.jsonl');
  await writeFile(listFile, [...new Set(urls)].slice(0, 18).join('\n'), 'utf8');
  try {
    await runProc(
      'nuclei',
      ['-l', listFile, '-jsonl', '-o', outFile, '-silent', '-rate-limit', '35', '-timeout', '8'],
      320000,
    );
    let text = '';
    try {
      text = await readFile(outFile, 'utf8');
    } catch {
      return [];
    }
    return text
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
  } catch (e) {
    log(`nuclei: ${e.message}`, 'warn');
    return [];
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/**
 * Scan ativo: nmap → searchsploit (heurístico) → ffuf (só HTTP 200) → nuclei.
 */
export async function runKaliAggressiveScan({ domain, subdomainsAlive, cap, log, addFinding }) {
  const rawHosts = [domain, ...(subdomainsAlive || [])].map(sanitizeHost).filter(Boolean);
  const hosts = [...new Set(rawHosts)].slice(0, 22);

  log('═══ MODO KALI / SCAN ATIVO ═══', 'section');
  log('Apenas em alvos com autorização explícita (bug bounty / pentest autorizado).', 'warn');
  log(`Alvos nmap (${hosts.length}): ${hosts.join(', ')}`, 'info');

  const baseUrlsForFfuf = [
    `https://${domain}/`,
    `http://${domain}/`,
  ];
  const seenQueries = new Set();

  if (cap.tools.nmap) {
    try {
      const rows = await runNmapOnHosts(hosts, log);
      log(`nmap: ${rows.length} serviço(s) em portas abertas`, 'success');
      for (const row of rows) {
        const line = `${row.proto}/${row.port} ${row.host} — ${row.name || '?'} ${row.product || ''} ${row.version || ''}`.trim();
        let url = null;
        if (row.port === '443') url = `https://${row.host}/`;
        else if (row.port === '80') url = `http://${row.host}/`;
        addFinding({
          type: 'nmap',
          prio: 'med',
          score: 56,
          value: line,
          meta: row.searchBlob || row.name || 'nmap',
          url,
        });

        if (cap.tools.searchsploit && row.searchBlob && seenQueries.size < 12) {
          const key = row.searchBlob.toLowerCase().slice(0, 60);
          if (seenQueries.has(key)) continue;
          seenQueries.add(key);
          const hits = await searchExploitDbOne(row.searchBlob, log);
          for (const hit of hits.slice(0, 4)) {
            const title = exploitTitle(hit);
            addFinding({
              type: 'exploit',
              prio: 'high',
              score: 82,
              value: title,
              meta: `Exploit-DB / searchsploit — ref. a «${row.searchBlob.slice(0, 50)}»`,
              url: exploitUrl(hit) || undefined,
            });
          }
          if (hits.length) log(`searchsploit: ${hits.length} entrada(s) para «${row.searchBlob.slice(0, 40)}…»`, 'find');
        }
      }
      for (const row of rows) {
        if (row.port === '443' || row.port === '80') {
          const u = row.port === '443' ? `https://${row.host}/` : `http://${row.host}/`;
          if (!baseUrlsForFfuf.includes(u)) baseUrlsForFfuf.push(u);
        }
      }
    } catch (e) {
      log(`nmap: ${e.message}`, 'error');
    }
  }

  if (cap.tools.ffuf) {
    log('═══ ffuf (apenas HTTP 200) ═══', 'section');
    const uniqBases = [...new Set(baseUrlsForFfuf)].slice(0, 5);
    for (const u of uniqBases) {
      const paths = await runFfuf200(u, log);
      for (const p of paths) {
        addFinding(
          {
            type: 'endpoint',
            prio: 'high',
            score: 72,
            value: p,
            meta: 'ffuf • código 200',
            url: p,
          },
          'endpoints',
        );
      }
      if (paths.length) log(`ffuf ${u} → ${paths.length} caminho(s) 200`, 'success');
    }
  }

  if (cap.tools.nuclei) {
    log('═══ nuclei ═══', 'section');
    const targets = [...new Set(baseUrlsForFfuf.map((b) => b.replace(/\/$/, '')))].slice(0, 15);
    try {
      const findings = await runNucleiList(targets, log);
      for (const f of findings) {
        const matched = f['matched-at'] || f.host || f.url || '';
        const tid = f['template-id'] || f.templateID || 'template';
        const sev = f.info?.severity || f.severity || 'info';
        addFinding({
          type: 'nuclei',
          prio: ['critical', 'high'].includes(String(sev).toLowerCase()) ? 'high' : 'med',
          score: sev === 'critical' ? 95 : sev === 'high' ? 88 : 60,
          value: `${tid} @ ${matched}`,
          meta: `nuclei • ${sev}`,
          url: matched.startsWith('http') ? matched : null,
        });
      }
      log(`nuclei: ${findings.length} finding(s)`, findings.length ? 'warn' : 'info');
    } catch (e) {
      log(`nuclei: ${e.message}`, 'warn');
    }
  }

  log('═══ Fim modo Kali ═══', 'section');
}
