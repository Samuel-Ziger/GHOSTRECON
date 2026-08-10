/**
 * Ponto de entrada da CLI ghostrecon. Despacha subcomandos.
 */

import '../../load-env.js';
import { runCommand } from './commands/run.mjs';
import { runsCommand } from './commands/runs.mjs';
import { playbooksCommand } from './commands/playbooks.mjs';
import { scheduleCommand } from './commands/schedule.mjs';
import { diffCommand } from './commands/diff.mjs';
import { exportCommand } from './commands/export.mjs';
import { projectsCommand } from './commands/projects.mjs';
import { engagementCommand } from './commands/engagement.mjs';
import { narrativeCommand } from './commands/narrative.mjs';
import { purpleCommand } from './commands/purple.mjs';
import { teamCommand } from './commands/team.mjs';
import { replayCommand } from './commands/replay.mjs';
import { obsidianCommand } from './commands/obsidian.mjs';
import { phishInfraCommand } from './commands/phish-infra.mjs';
import { ghostwatchCommand } from './commands/ghostwatch.mjs';
import { autoCommand } from './commands/auto.mjs';

const VERSION = '1.1.0-cli';

const HELP = `GHOSTRECON CLI — v${VERSION}

Uso:
  ghostrecon <comando> [opções]

Comandos:
  run, scan          Executa um recon e grava o resultado (scan = alias de run).
  auto               Modo Auto (NDJSON); aprovação interactive/deny via --approval-mode.
  runs               Lista os últimos runs (--target opcional).
  diff               Mostra a diferença entre dois runs (baseline vs newer).
  playbooks          Lista playbooks disponíveis e seus módulos.
  schedule           Agendador com cron-like interval + diff + alerta new-only.
  export             Exporta findings para Linear/Jira/GitHub Issues.
  projects           Gestor de projetos (add/list/remove/scope).
  engagement         ROE + metadata de engagement + op-report + checklist.
  narrative          Kill-chain/MITRE narrative + cenários nomeados.
  purple             Export purple-team (finding + controle + Sigma YAML).
  team               Locks por alvo + operator trail (concorrência).
  replay             Replay NDJSON / tabletop rerank de runs antigos.
  obsidian           Exporta engagement+runs para Obsidian vault.
  phish-infra        Recon passivo de domínio canário + fingerprint compare.
  version            Imprime a versão da CLI.

Opções globais:
  --server URL       URL base do server (default: http://127.0.0.1:3847)
  --start-server     Auto-spawn do server caso não esteja a correr.
  --quiet / --verbose
  --help             Mostra help.

Opções de "run":
  --target DOMAIN    (obrigatório) Domínio alvo (ex.: example.com).
  --modules LIST     CSV de módulos (ex.: crtsh,http,github,tls).
  --playbook NAME    Nome de um playbook (api-first, wordpress, ...).
                     Se combinado com --modules, a união é aplicada.
  --profile NAME     standard | stealth | aggressive (default: standard).
  --output FILE      Ficheiro de saída (JSON final agregado).
                     Se omisso, escreve o JSON final em stdout.
  --format FORMAT    json (default) | ndjson | summary
  --exact-match      Só aceita subs exatos do alvo.
  --kali             Ativa módulos Kali (requer ferramentas locais).
  --out-of-scope CSV Lista de hosts/padrões fora de escopo.
  --project NAME     Atribui o run a um projeto (ver "projects").
  --engagement ID    Opcional — checklist ROE/escopo + watermark no POST /api/recon/stream.
  --operator NAME    Metadados no engagement e team trail.
  --opsec-profile passive|stealth|standard|aggressive  Gate de módulos intrusivos.
  --confirm-active   ACK explícito para módulos intrusivos (OPSEC).
  --auth-header K=V  Header extra (repetível).
  --auth-cookie STR  Cookie bruto para requisições autenticadas.
  --timeout SEC      Timeout global do stream (default: 1800).
  --engine MODE      node | go | both — motor Vigolium DAST (default: env ou node).
  --strategy NAME    lite | balanced | deep — estratégia Vigolium (com --engine go/both ou módulo vigolium_dast).
  --vigolium-modules CSV  Filtro -m do vigolium scan.
  --vigolium-module-tag TAG  Filtro --module-tag do Vigolium (repetivel; ex.: access-control).
  --vigolium-auth-file FILE  YAML/JSON de sessao Vigolium (repetivel; primary/compare para IDOR/BOLA).
  --vigolium-auth ROLE:KIND:VALUE  Auth inline (ex.: admin:Cookie:session_id=abc123).
  --vigolium-input-file FILE  Entrada -T (ex.: openapi.yaml); combine com --vigolium-input-type openapi.
  --vigolium-html-report  Gera HTML em .runtime/vigolium-reports usando o Vigolium instalado.
  --vigolium-prefer-path  Prefere o binario vigolium do PATH no modo Kali.
  --vigolium-use-codex  Usa Codex/OAuth no agent IA (requer plano/login).

Exemplos:
  ghostrecon run --target example.com --modules crtsh,http,github
  ghostrecon scan -t example.com --engine both --strategy lite --modules rdap,vigolium_dast
  ghostrecon scan -t example.com --kali --engine both --modules vigolium_dast --strategy deep --vigolium-prefer-path
  ghostrecon scan -t api.example.com --engine both --modules vigolium_dast --vigolium-input-file openapi.yaml --vigolium-input-type openapi
  ghostrecon run --target api.example.com --playbook api-first --output api.json
  ghostrecon runs --target example.com --limit 5
  ghostrecon diff --baseline 12 --newer 18 --format summary
  ghostrecon schedule --target example.com --interval 6h --playbook api-first
  ghostrecon export --run 42 --to github --repo myorg/myrepo --severity high
`;

export async function cliMain(argv) {
  if (!argv.length || argv[0] === '-h' || argv[0] === '--help') {
    process.stdout.write(HELP);
    return 0;
  }

  const [cmd, ...rest] = argv;

  switch (cmd) {
    case 'version':
    case '-v':
    case '--version':
      process.stdout.write(`${VERSION}\n`);
      return 0;
    case 'run':
    case 'scan':
      return runCommand(rest);
    case 'runs':
      return runsCommand(rest);
    case 'diff':
      return diffCommand(rest);
    case 'playbooks':
      return playbooksCommand(rest);
    case 'schedule':
      return scheduleCommand(rest);
    case 'export':
      return exportCommand(rest);
    case 'projects':
      return projectsCommand(rest);
    case 'engagement':
      return engagementCommand(rest);
    case 'narrative':
      return narrativeCommand(rest);
    case 'purple':
      return purpleCommand(rest);
    case 'team':
      return teamCommand(rest);
    case 'replay':
      return replayCommand(rest);
    case 'obsidian':
      return obsidianCommand(rest);
    case 'phish-infra':
      return phishInfraCommand(rest);
    case 'ghostwatch':
      return ghostwatchCommand(rest);
    case 'auto':
      return autoCommand(rest);
    default:
      process.stderr.write(`ghostrecon: comando desconhecido "${cmd}"\n${HELP}`);
      return 2;
  }
}
