'use client';

/**
 * GhostTrace — exportador DOCX cliente-side.
 *
 * Constrói um Word document (.docx) a partir do projeto e seus artefatos,
 * espelhando 1:1 a estrutura do template LocBook documentada em
 * docs/REPORT_TEMPLATE.md. Roda no navegador via lib `docx` — sem backend.
 *
 * Estrutura:
 *   1. Capa
 *   2. Introdução (Objetivo · Metodologia · Ferramentas)
 *   3. Sumário executivo
 *   4. Sumário dos testes (escopo, totais)
 *   5. Resumo da cadeia de ataque
 *   6. Vulnerabilidades — lista por severidade
 *   7. Detalhamento das vulnerabilidades
 *   8. Apêndice E — credenciais e artefatos
 *   9. Apêndice F — referências
 */

import {
  Document,
  Packer,
  Paragraph,
  TextRun,
  HeadingLevel,
  AlignmentType,
  Table,
  TableRow,
  TableCell,
  WidthType,
  BorderStyle,
  ShadingType,
  PageBreak,
  Header,
  Footer,
  PageNumber,
  LevelFormat,
  ImageRun,
  convertInchesToTwip
} from 'docx';
import type {
  Project,
  Vulnerability,
  AttackChainNode,
  Credential,
  Severity
} from '@/lib/types';
import {
  SEVERITY_LABEL,
  SEVERITY_ORDER,
  STATUS_LABEL,
  compareBySeverity,
  PRIVILEGE_LABEL
} from '@/lib/utils/severity';
import { computeSummary } from '@/lib/mock/store';
import { fmtDate } from '@/lib/utils/format';

/* ─────────────── design tokens ─────────────── */

const COLORS = {
  text: '1c1d21',
  textMuted: '6a6b71',
  accent: '00aa66',
  black: '000000',
  white: 'ffffff',
  surface: 'f4f4f4',
  border: 'd5d5d8',
  sevCritical: 'ff3366',
  sevHigh: 'ff8a3d',
  sevMedium: 'ffcc33',
  sevLow: '3dd6a8',
  sevInfo: '5b9bff'
};

const SEV_HEX: Record<Severity, string> = {
  critical: COLORS.sevCritical,
  high: COLORS.sevHigh,
  medium: COLORS.sevMedium,
  low: COLORS.sevLow,
  info: COLORS.sevInfo
};

/* ─────────────── builders ─────────────── */

function h1(text: string): Paragraph {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 480, after: 200 },
    children: [
      new TextRun({
        text: text.toUpperCase(),
        bold: true,
        size: 36,
        color: COLORS.text,
        font: 'Segoe UI Light'
      })
    ]
  });
}

function h2(text: string): Paragraph {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 320, after: 140 },
    children: [
      new TextRun({
        text: text.toUpperCase(),
        bold: true,
        size: 26,
        color: COLORS.text,
        font: 'Segoe UI Light'
      })
    ]
  });
}

function h3(text: string): Paragraph {
  return new Paragraph({
    heading: HeadingLevel.HEADING_3,
    spacing: { before: 220, after: 100 },
    children: [
      new TextRun({
        text: text.toUpperCase(),
        bold: true,
        size: 20,
        color: COLORS.text
      })
    ]
  });
}

function p(text: string, opts: { mono?: boolean; muted?: boolean; bold?: boolean; italic?: boolean } = {}): Paragraph {
  return new Paragraph({
    spacing: { after: 120, line: 320 },
    children: [
      new TextRun({
        text,
        font: opts.mono ? 'Consolas' : 'Calibri',
        size: opts.mono ? 18 : 22,
        color: opts.muted ? COLORS.textMuted : COLORS.text,
        bold: opts.bold,
        italics: opts.italic
      })
    ]
  });
}

function bullet(text: string, mono = false): Paragraph {
  return new Paragraph({
    spacing: { after: 80 },
    bullet: { level: 0 },
    children: [
      new TextRun({
        text,
        font: mono ? 'Consolas' : 'Calibri',
        size: mono ? 18 : 22,
        color: COLORS.text
      })
    ]
  });
}

function numbered(text: string, ref = 'main-list'): Paragraph {
  return new Paragraph({
    spacing: { after: 80 },
    numbering: { reference: ref, level: 0 },
    children: [new TextRun({ text, font: 'Calibri', size: 22, color: COLORS.text })]
  });
}

function codeBlock(content: string): Paragraph {
  return new Paragraph({
    spacing: { before: 100, after: 200 },
    indent: { left: 200 },
    shading: { type: ShadingType.SOLID, color: '0f1116', fill: '0f1116' },
    children: content
      .split('\n')
      .flatMap((line, i) => [
        ...(i > 0 ? [new TextRun({ break: 1 })] : []),
        new TextRun({
          text: line || ' ',
          font: 'Consolas',
          size: 18,
          color: 'a3e4c0'
        })
      ])
  });
}

function emptyLine(): Paragraph {
  return new Paragraph({ spacing: { after: 120 }, children: [] });
}

/* ─────────────── screenshots / imagens ─────────────── */

/** Detecta o `type` da ImageRun a partir do mime do data URL. */
function imageTypeFromDataUrl(dataUrl: string): 'png' | 'jpg' | 'gif' | 'bmp' {
  const m = /^data:image\/(png|jpe?g|gif|bmp)/i.exec(dataUrl);
  const t = (m?.[1] || 'png').toLowerCase();
  if (t === 'jpeg' || t === 'jpg') return 'jpg';
  if (t === 'gif') return 'gif';
  if (t === 'bmp') return 'bmp';
  return 'png';
}

/** Converte um data URL base64 em Uint8Array (cliente-side via atob). */
function dataUrlToBytes(dataUrl: string): Uint8Array | null {
  try {
    const base64 = dataUrl.includes(',') ? dataUrl.split(',')[1] : dataUrl;
    const bin = atob(base64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

/**
 * Renderiza um screenshot (data URL) como parágrafo de imagem centralizado,
 * escalando para caber na largura útil da página (~620px). Espelha as
 * evidências embutidas na seção PROOF OF CONCEPT do template.
 */
function imageParagraph(dataUrl: string, caption?: string): Paragraph[] {
  if (typeof window === 'undefined' || !dataUrl?.startsWith('data:image')) return [];
  const bytes = dataUrlToBytes(dataUrl);
  if (!bytes) return [];

  // largura útil da página (~620px); proporção padrão 5:3 (o Word renderiza
  // no DPI do documento). Dimensões reais exigiriam carregar a imagem async.
  const width = 620;
  const height = Math.round(width * 0.6);

  const out: Paragraph[] = [
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 120, after: caption ? 40 : 160 },
      children: [
        new ImageRun({
          data: bytes,
          type: imageTypeFromDataUrl(dataUrl),
          transformation: { width, height }
        })
      ]
    })
  ];
  if (caption) {
    out.push(
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 160 },
        children: [
          new TextRun({ text: caption, font: 'Calibri', size: 16, italics: true, color: COLORS.textMuted })
        ]
      })
    );
  }
  return out;
}

/* ─────────────── HTML → docx Paragraph[] ─────────────── */

/**
 * Converte HTML simples do TipTap (p, strong, em, code, ul, ol, blockquote)
 * para um array de Paragraphs do docx. Usa DOMParser (cliente-side).
 */
function htmlToParagraphs(html: string): Paragraph[] {
  if (!html || html.trim() === '' || html.trim() === '<p></p>') return [];
  if (typeof window === 'undefined') {
    // SSR-safe fallback — vira um único paragraph com o texto puro
    const plain = html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    return plain ? [p(plain)] : [];
  }
  const doc = new DOMParser().parseFromString(`<div>${html}</div>`, 'text/html');
  const root = doc.body.firstElementChild!;
  return Array.from(root.children).flatMap(nodeToParagraphs);
}

function nodeToParagraphs(node: Element): Paragraph[] {
  switch (node.tagName.toLowerCase()) {
    case 'p': {
      const runs = inlineToRuns(node);
      if (runs.length === 0) return [emptyLine()];
      return [
        new Paragraph({
          spacing: { after: 120, line: 320 },
          children: runs
        })
      ];
    }
    case 'ul':
      return Array.from(node.children).map((li) =>
        new Paragraph({
          spacing: { after: 80 },
          bullet: { level: 0 },
          children: inlineToRuns(li)
        })
      );
    case 'ol':
      return Array.from(node.children).map((li) =>
        new Paragraph({
          spacing: { after: 80 },
          numbering: { reference: 'inline-list', level: 0 },
          children: inlineToRuns(li)
        })
      );
    case 'blockquote':
      return [
        new Paragraph({
          spacing: { after: 120, line: 320 },
          indent: { left: 360 },
          border: {
            left: { style: BorderStyle.SINGLE, size: 12, color: COLORS.accent, space: 8 }
          },
          children: inlineToRuns(node).map(
            (r) =>
              new TextRun({
                ...((r as any).options ?? {}),
                color: COLORS.textMuted,
                italics: true
              })
          )
        })
      ];
    case 'pre': {
      const text = node.textContent ?? '';
      return [codeBlock(text)];
    }
    case 'h1':
      return [h1(node.textContent ?? '')];
    case 'h2':
      return [h2(node.textContent ?? '')];
    case 'h3':
      return [h3(node.textContent ?? '')];
    default:
      // fallback — pega texto cru
      return [p(node.textContent ?? '')];
  }
}

function inlineToRuns(node: Element): TextRun[] {
  const out: TextRun[] = [];
  walk(node, { bold: false, italic: false, code: false });
  return out;

  function walk(n: Node, ctx: { bold: boolean; italic: boolean; code: boolean }) {
    if (n.nodeType === Node.TEXT_NODE) {
      const text = n.textContent ?? '';
      if (!text) return;
      out.push(
        new TextRun({
          text,
          bold: ctx.bold,
          italics: ctx.italic,
          font: ctx.code ? 'Consolas' : 'Calibri',
          size: ctx.code ? 20 : 22,
          color: COLORS.text,
          shading: ctx.code
            ? { type: ShadingType.SOLID, color: COLORS.surface, fill: COLORS.surface }
            : undefined
        })
      );
      return;
    }
    if (n.nodeType !== Node.ELEMENT_NODE) return;
    const el = n as Element;
    const tag = el.tagName.toLowerCase();
    const next = {
      bold: ctx.bold || tag === 'strong' || tag === 'b',
      italic: ctx.italic || tag === 'em' || tag === 'i',
      code: ctx.code || tag === 'code'
    };
    el.childNodes.forEach((c) => walk(c, next));
  }
}

/* ─────────────── tables ─────────────── */

function noBorders() {
  const b = { style: BorderStyle.NONE, size: 0, color: 'auto' } as const;
  return { top: b, bottom: b, left: b, right: b };
}

function thinBorders() {
  const b = { style: BorderStyle.SINGLE, size: 4, color: COLORS.border } as const;
  return { top: b, bottom: b, left: b, right: b };
}

function tableCell(content: string | Paragraph[], opts: { header?: boolean; width?: number; mono?: boolean } = {}): TableCell {
  const isHeader = !!opts.header;
  const paragraphs =
    typeof content === 'string'
      ? [
          new Paragraph({
            children: [
              new TextRun({
                text: content,
                bold: isHeader,
                color: isHeader ? COLORS.white : COLORS.text,
                font: opts.mono ? 'Consolas' : 'Calibri',
                size: opts.mono ? 18 : 21
              })
            ]
          })
        ]
      : content;

  return new TableCell({
    width: opts.width ? { size: opts.width, type: WidthType.PERCENTAGE } : undefined,
    shading: isHeader
      ? { type: ShadingType.SOLID, color: COLORS.black, fill: COLORS.black }
      : undefined,
    margins: { top: 100, bottom: 100, left: 140, right: 140 },
    children: paragraphs
  });
}

/* ─────────────── sections ─────────────── */

function coverSection(project: Project): Paragraph[] {
  return [
    new Paragraph({ spacing: { before: 2400 }, children: [] }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [
        new TextRun({
          text: 'ghost',
          font: 'Consolas',
          size: 56,
          color: COLORS.text,
          bold: true
        }),
        new TextRun({
          text: 'trace',
          font: 'Consolas',
          size: 56,
          color: COLORS.accent,
          bold: true
        })
      ]
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 80, after: 1800 },
      children: [
        new TextRun({
          text: 'OFFENSIVE DOCUMENTATION PLATFORM',
          font: 'Consolas',
          size: 14,
          color: COLORS.textMuted
        })
      ]
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 240 },
      children: [
        new TextRun({
          text: 'Relatório de Vulnerabilidades',
          font: 'Segoe UI Light',
          size: 48,
          color: COLORS.text
        })
      ]
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 80 },
      shading: { type: ShadingType.SOLID, color: COLORS.black, fill: COLORS.black },
      children: [
        new TextRun({
          text: `   ${project.codename || project.client}   `,
          font: 'Calibri',
          size: 36,
          color: COLORS.white,
          bold: true
        })
      ]
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 1600 },
      children: [
        new TextRun({
          text: fmtDate(project.startDate, 'dd-MM-yyyy'),
          font: 'Consolas',
          size: 22,
          color: COLORS.textMuted
        })
      ]
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 60 },
      children: [
        new TextRun({
          text: 'INFORMAÇÃO CONFIDENCIAL',
          font: 'Calibri',
          size: 18,
          color: COLORS.text,
          bold: true
        })
      ]
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [
        new TextRun({
          text: `Este documento é estritamente confidencial e destina-se exclusivamente ao cliente contratante (${project.client}). Sua reprodução, distribuição ou divulgação total ou parcial sem autorização formal é proibida.`,
          font: 'Calibri',
          size: 16,
          color: COLORS.textMuted
        })
      ]
    }),
    new Paragraph({ children: [new PageBreak()] })
  ];
}

function introSection(project: Project): Paragraph[] {
  const methodologyLabel =
    project.methodology === 'graybox'
      ? 'Gray Box'
      : project.methodology === 'blackbox'
      ? 'Black Box'
      : 'White Box';

  return [
    h1('Introdução'),
    h2('Objetivo'),
    p(
      `Este relatório foi elaborado com o intuito de identificar, analisar e catalogar as vulnerabilidades envolvidas nos domínios e servidores do ambiente analisado (${project.client}), levando em conta os pilares de integridade, confidencialidade e disponibilidade das informações. Foi feita a classificação e a organização dos problemas encontrados, bem como as possíveis abordagens iniciais para a sua resolução, considerando o impacto de cada falha em isolado e o impacto combinado ao longo da cadeia de ataque demonstrada.`
    ),
    h2('Metodologia'),
    p(
      `Foram utilizadas metodologias e recomendações de órgãos internacionais especializados em segurança da informação para a obtenção dos riscos envolvidos em todas as operações de TI. Para a catalogação e verificação de riscos em Aplicações Web e Servidores foi utilizado o padrão OWASP, com classificação adicional segundo CWE e CVSS v3.1.`
    ),
    p(
      `A primeira intervenção foi feita segundo a metodologia ${methodologyLabel}, em que parte do contexto e evidências é utilizada para orientar a exploração dentro do escopo permitido. Foram utilizados diversos softwares especializados em testes de intrusão e verificações manuais em todos os pontos críticos do sistema.`
    )
  ];
}

function toolsSection(project: Project): (Paragraph | Table)[] {
  if (!project.tools || project.tools.length === 0) return [];
  return [
    h2('Ferramentas utilizadas'),
    new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      borders: thinBorders(),
      rows: [
        new TableRow({
          tableHeader: true,
          children: [
            tableCell('FINALIDADE', { header: true, width: 40 }),
            tableCell('FERRAMENTAS', { header: true, width: 60 })
          ]
        }),
        ...project.tools.map(
          (t) =>
            new TableRow({
              children: [
                tableCell(t.purpose),
                tableCell(t.tools.map((x) => new Paragraph({
                  bullet: { level: 0 },
                  children: [new TextRun({ text: x, font: 'Calibri', size: 21, color: COLORS.text })]
                })))
              ]
            })
        )
      ]
    })
  ];
}

function execSummary(project: Project, vulns: Vulnerability[]): (Paragraph | Table)[] {
  const s = computeSummary(vulns);
  return [
    h1('Sumário executivo'),
    h2('Visão geral dos testes de segurança'),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 200, after: 80 },
      children: [
        new TextRun({
          text: 'TOTAL DE VULNERABILIDADES ÚNICAS',
          font: 'Calibri',
          size: 18,
          color: COLORS.textMuted,
          bold: true
        })
      ]
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 240 },
      children: [
        new TextRun({
          text: String(s.totalUnique),
          font: 'Segoe UI Light',
          size: 96,
          color: COLORS.text
        })
      ]
    }),
    new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      borders: thinBorders(),
      rows: [
        new TableRow({
          tableHeader: true,
          children: SEVERITY_ORDER.map((sev) =>
            new TableCell({
              shading: { type: ShadingType.SOLID, color: SEV_HEX[sev], fill: SEV_HEX[sev] },
              margins: { top: 80, bottom: 80, left: 80, right: 80 },
              children: [
                new Paragraph({
                  alignment: AlignmentType.CENTER,
                  children: [
                    new TextRun({
                      text: SEVERITY_LABEL[sev],
                      bold: true,
                      color: sev === 'medium' ? COLORS.text : COLORS.white,
                      font: 'Calibri',
                      size: 18
                    })
                  ]
                })
              ]
            })
          )
        }),
        new TableRow({
          children: SEVERITY_ORDER.map((sev) =>
            new TableCell({
              margins: { top: 100, bottom: 100, left: 80, right: 80 },
              children: [
                new Paragraph({
                  alignment: AlignmentType.CENTER,
                  children: [
                    new TextRun({
                      text: String(s.bySeverity[sev]),
                      font: 'Segoe UI Light',
                      size: 44,
                      color: COLORS.text
                    })
                  ]
                })
              ]
            })
          )
        })
      ]
    }),
    emptyLine(),
    new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      borders: thinBorders(),
      rows: [
        new TableRow({
          children: [
            tableCell('ZERO-DAY', { header: true, width: 50 }),
            tableCell('EASILY-EXPLOITABLE', { header: true, width: 50 })
          ]
        }),
        new TableRow({
          children: [
            tableCell([
              new Paragraph({
                alignment: AlignmentType.CENTER,
                children: [
                  new TextRun({
                    text: String(s.zeroDay),
                    font: 'Segoe UI Light',
                    size: 40,
                    color: COLORS.text
                  })
                ]
              })
            ]),
            tableCell([
              new Paragraph({
                alignment: AlignmentType.CENTER,
                children: [
                  new TextRun({
                    text: String(s.easilyExploitable),
                    font: 'Segoe UI Light',
                    size: 40,
                    color: COLORS.text
                  })
                ]
              })
            ])
          ]
        })
      ]
    })
  ];
}

function testSummary(project: Project, vulns: Vulnerability[]): (Paragraph | Table)[] {
  const s = computeSummary(vulns);
  const rows: { label: string; value: string }[] = [
    { label: 'Início', value: fmtDate(project.startDate, 'dd/MM/yyyy') },
    { label: 'Fim', value: project.endDate ? fmtDate(project.endDate, 'dd/MM/yyyy') : '—' },
    { label: 'Total de vulnerabilidades', value: String(s.totalUnique) },
    { label: 'Severidade crítica', value: String(s.bySeverity.critical) },
    { label: 'Severidade alta', value: String(s.bySeverity.high) },
    { label: 'Severidade média', value: String(s.bySeverity.medium) },
    { label: 'Severidade baixa', value: String(s.bySeverity.low) },
    { label: 'Informacionais', value: String(s.bySeverity.info) },
    { label: 'Corrigidas', value: String(s.fixed) },
    { label: 'Em reteste', value: String(s.retest) },
    { label: 'Não corrigidas', value: String(s.unfixed) }
  ];

  return [
    h1('Sumário dos testes'),
    new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      borders: thinBorders(),
      rows: rows.map(
        (r) =>
          new TableRow({
            children: [tableCell(r.label, { width: 70 }), tableCell(r.value, { width: 30, mono: true })]
          })
      )
    }),
    h2('Escopo do projeto'),
    ...project.scope.map((t) => numbered(t)),
    h2('Histórico de reteste'),
    p(s.retest > 0 ? `${s.retest} vulnerabilidade(s) em processo de reteste.` : 'Nenhum reteste realizado.'),
    h2('Notas do projeto'),
    p(project.notes ? project.notes : 'Nenhuma nota de projeto.')
  ];
}

function attackChainSection(chain: AttackChainNode[]): Paragraph[] {
  if (chain.length === 0) return [];
  const out: Paragraph[] = [
    h1('Resumo da cadeia de ataque'),
    p(
      'O diagrama abaixo descreve, de forma simplificada, o caminho percorrido durante a exploração. Cada salto representa um aumento concreto de privilégio e/ou acesso a um novo ativo.'
    ),
    emptyLine()
  ];

  chain.forEach((node, idx) => {
    out.push(
      new Paragraph({
        spacing: { before: 200, after: 80 },
        children: [
          new TextRun({
            text: `[ ${node.host}${node.ip ? ` — ${node.ip}` : ''} ]    `,
            font: 'Consolas',
            size: 22,
            color: COLORS.text,
            bold: true
          }),
          new TextRun({
            text: PRIVILEGE_LABEL[node.privilege],
            font: 'Consolas',
            size: 18,
            color: COLORS.white,
            bold: true,
            shading: { type: ShadingType.SOLID, color: SEV_HEX[node.privilege === 'root' ? 'critical' : node.privilege === 'user' ? 'info' : 'medium'], fill: SEV_HEX[node.privilege === 'root' ? 'critical' : node.privilege === 'user' ? 'info' : 'medium'] }
          })
        ]
      })
    );
    node.steps.forEach((s) => {
      out.push(
        new Paragraph({
          spacing: { after: 40 },
          indent: { left: 320 },
          children: [
            new TextRun({
              text: `(${String(s.order).padStart(2, '0')}) ${s.action}`,
              font: 'Consolas',
              size: 18,
              color: COLORS.text
            })
          ]
        })
      );
    });
    if (idx < chain.length - 1) {
      out.push(
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { before: 80, after: 80 },
          children: [
            new TextRun({ text: '↓', font: 'Consolas', size: 32, color: COLORS.textMuted })
          ]
        })
      );
    }
  });

  return out;
}

function vulnListSection(vulns: Vulnerability[]): Paragraph[] {
  const sorted = [...vulns].sort((a, b) => compareBySeverity(a.severity, b.severity));
  const out: Paragraph[] = [h1('Vulnerabilidades')];

  SEVERITY_ORDER.forEach((sev) => {
    const list = sorted.filter((v) => v.severity === sev);
    if (list.length === 0) return;
    out.push(h2(SEVERITY_LABEL[sev]));
    list.forEach((v) => {
      out.push(
        new Paragraph({
          spacing: { after: 60 },
          bullet: { level: 0 },
          children: [
            new TextRun({
              text: `[${STATUS_LABEL[v.status]}] `,
              font: 'Consolas',
              size: 18,
              color: COLORS.textMuted,
              bold: true
            }),
            new TextRun({ text: v.title, font: 'Calibri', size: 22, color: COLORS.text })
          ]
        })
      );
      out.push(
        new Paragraph({
          spacing: { after: 80 },
          indent: { left: 360 },
          children: [
            new TextRun({
              text: `total de ativos afetados: ${v.targets.length} - corrigidas: ${v.status === 'fixed' ? v.targets.length : 0} - reteste: ${v.status === 'retest' ? v.targets.length : 0} - não corrigidas: ${v.status === 'unfixed' || v.status === 'wont_fix' ? v.targets.length : 0}`,
              font: 'Calibri',
              size: 18,
              color: COLORS.textMuted
            })
          ]
        })
      );
    });
  });

  return out;
}

function vulnDetailSection(vulns: Vulnerability[]): Paragraph[] {
  const sorted = [...vulns].sort((a, b) => compareBySeverity(a.severity, b.severity));
  const out: Paragraph[] = [
    new Paragraph({ children: [new PageBreak()] }),
    h1('Detalhamento das vulnerabilidades')
  ];

  sorted.forEach((v, idx) => {
    if (idx > 0) out.push(new Paragraph({ children: [new PageBreak()] }));

    // header com número + severidade
    out.push(
      new Paragraph({
        spacing: { before: 240, after: 200 },
        children: [
          new TextRun({
            text: `${String(idx + 1).padStart(2, '0')}. ${v.title}    `,
            font: 'Segoe UI Light',
            size: 32,
            color: COLORS.text,
            bold: true
          }),
          new TextRun({
            text: ` ${SEVERITY_LABEL[v.severity]} `,
            font: 'Calibri',
            size: 20,
            bold: true,
            color: v.severity === 'medium' ? COLORS.text : COLORS.white,
            shading: { type: ShadingType.SOLID, color: SEV_HEX[v.severity], fill: SEV_HEX[v.severity] }
          })
        ]
      })
    );

    if (v.description) {
      out.push(h3('Descrição'));
      out.push(...htmlToParagraphs(v.description));
    }
    if (v.attackScenario) {
      out.push(h3('Cenário de ataque'));
      out.push(...htmlToParagraphs(v.attackScenario));
    }
    if (v.recommendation) {
      out.push(h3('Recomendação'));
      out.push(...htmlToParagraphs(v.recommendation));
    }

    out.push(h3('Tags'));
    v.tags.forEach((t) => out.push(bullet(t)));
    v.cwe.forEach((c) => out.push(bullet(c)));
    if (v.cvss) {
      out.push(bullet(v.cvss.vector, true));
      out.push(bullet(`CVSSv3.1 Base Score: ${v.cvss.score.toFixed(1)}`));
    }

    out.push(h3('Ativos afetados'));
    v.targets.forEach((t) => out.push(bullet(t, true)));

    // Notas sempre presentes (espelha o template: "Nenhuma nota...")
    out.push(h3('Notas de remediação'));
    out.push(...(v.remediationNotes ? htmlToParagraphs(v.remediationNotes) : [p('Nenhuma nota de remediação.')]));
    out.push(h3('Notas adicionais'));
    out.push(...(v.additionalNotes ? htmlToParagraphs(v.additionalNotes) : [p('Nenhuma nota adicional.')]));

    if (v.steps.length > 0) {
      out.push(h3('Passos de reprodução'));
      v.steps.forEach((s) => {
        out.push(numbered(s.text, 'steps-list'));
        if (s.command) out.push(codeBlock(s.command));
        (s.screenshots || []).forEach((shot) => out.push(...imageParagraph(shot)));
      });
    }

    // Proof of concept — sempre presente, com evidências (screenshots) embutidas
    out.push(h3('Proof of concept'));
    if (v.pocs.length > 0) {
      v.pocs.forEach((poc) => {
        out.push(p(poc.title, { bold: true }));
        if (poc.description) out.push(p(poc.description));
        if (poc.code?.content) out.push(codeBlock(poc.code.content));
        (poc.screenshots || []).forEach((shot) => out.push(...imageParagraph(shot)));
      });
    } else {
      out.push(p('Nenhuma prova de conceito registrada.'));
    }
  });

  return out;
}

function credentialsAppendix(creds: Credential[]): (Paragraph | Table)[] {
  if (creds.length === 0) return [];
  return [
    new Paragraph({ children: [new PageBreak()] }),
    h1('Apêndice E — Credenciais e artefatos coletados'),
    p(
      'As credenciais e artefatos listados abaixo foram coletados durante o pentest e devem ser ROTACIONADOS imediatamente. Esta lista deve ser tratada como confidencial e excluída de cópias eletrônicas após a remediação.'
    ),
    emptyLine(),
    new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      borders: thinBorders(),
      rows: [
        new TableRow({
          tableHeader: true,
          children: [
            tableCell('USUÁRIO', { header: true, width: 20 }),
            tableCell('CONTEXTO', { header: true, width: 35 }),
            tableCell('HOST', { header: true, width: 20 }),
            tableCell('VALOR', { header: true, width: 25 })
          ]
        }),
        ...creds.map(
          (c) =>
            new TableRow({
              children: [
                tableCell(c.user, { mono: true }),
                tableCell(c.context),
                tableCell(c.host ?? '—', { mono: true }),
                tableCell(c.value, { mono: true })
              ]
            })
        )
      ]
    })
  ];
}

function referencesAppendix(): Paragraph[] {
  return [
    new Paragraph({ children: [new PageBreak()] }),
    h1('Apêndice F — Referências'),
    bullet('OWASP Top 10 (2021) — https://owasp.org/Top10'),
    bullet('CWE Top 25 Most Dangerous Software Weaknesses — https://cwe.mitre.org/top25'),
    bullet('CVSS v3.1 Specification — https://www.first.org/cvss/v3.1/specification-document'),
    bullet(
      'GhostTrace — plataforma operacional ofensiva para Pentest, Red Team e Bug Bounty.'
    )
  ];
}

/* ─────────────── main entry point ─────────────── */

export interface ExportArgs {
  project: Project;
  vulnerabilities: Vulnerability[];
  attackChain: AttackChainNode[];
  credentials: Credential[];
}

/**
 * Gera o DOCX e dispara o download no navegador.
 */
export async function exportProjectToDocx(args: ExportArgs): Promise<void> {
  if (typeof window === 'undefined') {
    throw new Error('exportProjectToDocx must run in the browser');
  }
  const { project, vulnerabilities, attackChain, credentials } = args;

  const doc = new Document({
    creator: 'GhostTrace',
    title: `Relatório de Vulnerabilidades — ${project.client}`,
    description: 'Generated by GhostTrace · Offensive Documentation Platform',
    styles: {
      default: {
        document: {
          run: { font: 'Calibri', size: 22, color: COLORS.text }
        }
      }
    },
    numbering: {
      config: [
        {
          reference: 'main-list',
          levels: [
            {
              level: 0,
              format: LevelFormat.DECIMAL,
              text: '%1.',
              alignment: AlignmentType.START,
              style: {
                paragraph: { indent: { left: convertInchesToTwip(0.5), hanging: 260 } }
              }
            }
          ]
        },
        {
          reference: 'inline-list',
          levels: [
            {
              level: 0,
              format: LevelFormat.DECIMAL,
              text: '%1.',
              alignment: AlignmentType.START,
              style: {
                paragraph: { indent: { left: convertInchesToTwip(0.5), hanging: 260 } }
              }
            }
          ]
        },
        {
          reference: 'steps-list',
          levels: [
            {
              level: 0,
              format: LevelFormat.DECIMAL,
              text: '%1.',
              alignment: AlignmentType.START,
              style: {
                paragraph: { indent: { left: convertInchesToTwip(0.5), hanging: 260 } }
              }
            }
          ]
        }
      ]
    },
    sections: [
      {
        properties: {
          page: {
            margin: {
              top: convertInchesToTwip(1),
              bottom: convertInchesToTwip(1),
              left: convertInchesToTwip(1),
              right: convertInchesToTwip(1)
            }
          }
        },
        headers: {
          default: new Header({
            children: [
              new Paragraph({
                alignment: AlignmentType.LEFT,
                children: [
                  new TextRun({
                    text: `${project.codename || project.client} · Relatório de Vulnerabilidades`,
                    font: 'Calibri',
                    size: 16,
                    color: COLORS.textMuted
                  })
                ]
              })
            ]
          })
        },
        footers: {
          default: new Footer({
            children: [
              new Paragraph({
                alignment: AlignmentType.CENTER,
                children: [
                  new TextRun({
                    text: 'INFORMAÇÃO CONFIDENCIAL  ·  Página ',
                    font: 'Calibri',
                    size: 16,
                    color: COLORS.textMuted
                  }),
                  new TextRun({
                    children: [PageNumber.CURRENT],
                    font: 'Calibri',
                    size: 16,
                    color: COLORS.text,
                    bold: true
                  }),
                  new TextRun({
                    text: ' de ',
                    font: 'Calibri',
                    size: 16,
                    color: COLORS.textMuted
                  }),
                  new TextRun({
                    children: [PageNumber.TOTAL_PAGES],
                    font: 'Calibri',
                    size: 16,
                    color: COLORS.text,
                    bold: true
                  })
                ]
              })
            ]
          })
        },
        children: [
          ...coverSection(project),
          ...introSection(project),
          ...toolsSection(project),
          ...execSummary(project, vulnerabilities),
          ...testSummary(project, vulnerabilities),
          ...attackChainSection(attackChain),
          ...vulnListSection(vulnerabilities),
          ...vulnDetailSection(vulnerabilities),
          ...credentialsAppendix(credentials),
          ...referencesAppendix()
        ]
      }
    ]
  });

  const blob = await Packer.toBlob(doc);
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const slug = (project.codename || project.client)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
  const date = fmtDate(new Date().toISOString(), 'yyyy-MM-dd');
  a.href = url;
  a.download = `ghosttrace-${slug}-${date}.docx`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
