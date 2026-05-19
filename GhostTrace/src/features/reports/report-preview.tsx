'use client';

import { GhostTraceMark } from '@/components/icons/ghosttrace-mark';
import { SEVERITY_LABEL, SEVERITY_ORDER, STATUS_LABEL, compareBySeverity } from '@/lib/utils/severity';
import { fmtDate, fmtRange } from '@/lib/utils/format';
import { computeSummary } from '@/lib/mock/store';
import type {
  Project,
  Vulnerability,
  TimelineEvent,
  AttackChainNode,
  Credential
} from '@/lib/types';

interface Props {
  project: Project;
  vulnerabilities: Vulnerability[];
  timeline: TimelineEvent[];
  attackChain: AttackChainNode[];
  credentials: Credential[];
}

/**
 * Render preview do relatório seguindo a estrutura do template LocBook/BancoCN.
 * Layout estilo "page" sobre fundo claro — espelha como será o DOCX final.
 */
export function ReportPreview({
  project,
  vulnerabilities,
  timeline,
  attackChain,
  credentials
}: Props) {
  const summary = computeSummary(vulnerabilities);
  const sortedVulns = [...vulnerabilities].sort((a, b) => compareBySeverity(a.severity, b.severity));

  return (
    <div className="bg-[#fafaf9] text-[#1c1d21] rounded-md p-10 font-serif shadow-2xl max-w-3xl mx-auto leading-relaxed">
      {/* COVER */}
      <section className="border-b border-[#1c1d21]/15 pb-8 mb-8">
        <div className="flex items-center gap-3 mb-12 text-[#1c1d21]">
          <GhostTraceMark size={28} />
          <span className="font-mono text-xl tracking-tight">
            ghost<span className="text-[#00aa66]">trace</span>
          </span>
        </div>
        <h1 className="text-4xl font-light text-[#1c1d21]">Relatório de Vulnerabilidades</h1>
        <div className="mt-3 bg-[#1c1d21] text-white inline-block px-4 py-1.5 text-xl tracking-wide">
          {project.codename || project.client}
        </div>
        <div className="mt-2 text-sm text-[#1c1d21]/70 font-mono">{fmtDate(project.startDate, 'dd-MM-yyyy')}</div>
        <p className="mt-10 text-xs uppercase tracking-[0.2em] text-[#1c1d21]/60">
          Informação confidencial
        </p>
        <p className="text-xs text-[#1c1d21]/60 mt-2 max-w-md font-sans leading-snug">
          Este documento é estritamente confidencial e destina-se exclusivamente ao cliente
          contratante ({project.client}). Sua reprodução, distribuição ou divulgação total ou
          parcial sem autorização formal é proibida.
        </p>
      </section>

      {/* INTRODUÇÃO */}
      <H1>Introdução</H1>
      <H2>Objetivo</H2>
      <P>
        Este relatório foi elaborado com o intuito de identificar, analisar e catalogar as
        vulnerabilidades envolvidas nos domínios e servidores do ambiente analisado ({project.client}),
        levando em conta os pilares de integridade, confidencialidade e disponibilidade das
        informações.
      </P>
      <H2>Metodologia</H2>
      <P>
        Foram utilizadas metodologias e recomendações de órgãos internacionais especializados em
        segurança da informação. Para a catalogação e verificação de riscos foi utilizado o padrão
        OWASP, com classificação adicional segundo CWE e CVSS v3.1. A intervenção foi feita segundo
        a metodologia <strong>{project.methodology === 'graybox' ? 'Gray Box' : project.methodology === 'blackbox' ? 'Black Box' : 'White Box'}</strong>.
      </P>

      {project.tools && project.tools.length > 0 && (
        <>
          <H2>Ferramentas utilizadas</H2>
          <table className="w-full text-sm border-collapse mt-2">
            <thead>
              <tr className="bg-[#1c1d21] text-white">
                <th className="text-left px-3 py-2 font-medium">Finalidade</th>
                <th className="text-left px-3 py-2 font-medium">Ferramentas</th>
              </tr>
            </thead>
            <tbody>
              {project.tools.map((t, i) => (
                <tr key={i} className="border-b border-[#1c1d21]/10">
                  <td className="px-3 py-2 align-top text-[#1c1d21]">{t.purpose}</td>
                  <td className="px-3 py-2 align-top">
                    <ul className="space-y-0.5">
                      {t.tools.map((tn) => (
                        <li key={tn} className="text-[#1c1d21]/80 before:content-['•'] before:mr-2 before:text-[#00aa66]">{tn}</li>
                      ))}
                    </ul>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {/* SUMÁRIO EXECUTIVO */}
      <H1>Sumário executivo</H1>
      <H2>Visão geral dos testes de segurança</H2>
      <div className="text-center py-4 border border-[#1c1d21]/15 my-3">
        <div className="text-xs uppercase tracking-widest text-[#1c1d21]/60">
          Total de vulnerabilidades únicas
        </div>
        <div className="text-6xl font-light mt-2">{summary.totalUnique}</div>
        <div className="grid grid-cols-5 gap-2 mt-4 max-w-md mx-auto text-center text-sm">
          {SEVERITY_ORDER.map((s) => (
            <div key={s}>
              <div className="font-medium uppercase text-xs tracking-wider text-[#1c1d21]/60">
                {SEVERITY_LABEL[s]}
              </div>
              <div className="text-2xl mt-1">{summary.bySeverity[s]}</div>
            </div>
          ))}
        </div>
        <div className="grid grid-cols-2 gap-2 mt-4 max-w-md mx-auto text-center text-sm">
          <div>
            <div className="font-medium uppercase text-xs tracking-wider text-[#1c1d21]/60">Zero-Day</div>
            <div className="text-2xl mt-1">{summary.zeroDay}</div>
          </div>
          <div>
            <div className="font-medium uppercase text-xs tracking-wider text-[#1c1d21]/60">Easily-Exploitable</div>
            <div className="text-2xl mt-1">{summary.easilyExploitable}</div>
          </div>
        </div>
      </div>

      <H2>Sumário dos testes</H2>
      <table className="text-sm w-full mt-2">
        <tbody className="font-mono">
          <Row label="Início" value={fmtDate(project.startDate, 'dd/MM/yyyy')} />
          {project.endDate && <Row label="Fim" value={fmtDate(project.endDate, 'dd/MM/yyyy')} />}
          <Row label="Total de vulnerabilidades" value={summary.totalUnique} />
          <Row label="Crítica" value={summary.bySeverity.critical} />
          <Row label="Alta" value={summary.bySeverity.high} />
          <Row label="Média" value={summary.bySeverity.medium} />
          <Row label="Baixa" value={summary.bySeverity.low} />
          <Row label="Info" value={summary.bySeverity.info} />
          <Row label="Corrigidas" value={summary.fixed} />
          <Row label="Em reteste" value={summary.retest} />
          <Row label="Não corrigidas" value={summary.unfixed} />
        </tbody>
      </table>

      <H2>Escopo do projeto</H2>
      <ol className="list-decimal pl-6 mt-2 text-sm space-y-0.5">
        {project.scope.map((s) => (
          <li key={s} className="font-mono">
            {s}
          </li>
        ))}
      </ol>

      {project.notes && (
        <>
          <H2>Notas do projeto</H2>
          <P>{project.notes}</P>
        </>
      )}

      {/* ATTACK CHAIN */}
      {attackChain.length > 0 && (
        <>
          <H1>Resumo da cadeia de ataque</H1>
          <P>
            A figura abaixo descreve, de forma simplificada, o caminho percorrido durante a
            exploração. Cada salto representa um aumento concreto de privilégio e/ou acesso a um
            novo ativo.
          </P>
          {attackChain.map((node, idx) => (
            <div key={node.id} className="mb-4">
              <div className="text-sm font-medium border border-[#1c1d21]/30 px-3 py-1.5 inline-block bg-[#1c1d21]/5">
                [ {node.host} {node.ip ? `— ${node.ip}` : ''} ]
                <span className="ml-3 text-xs font-mono uppercase text-[#1c1d21]/70">
                  {node.privilege}
                </span>
              </div>
              <ul className="font-mono text-sm pl-4 mt-1 space-y-0.5">
                {node.steps.map((s) => (
                  <li key={s.order}>
                    ({String(s.order).padStart(2, '0')}) {s.action}
                  </li>
                ))}
              </ul>
              {idx < attackChain.length - 1 && (
                <div className="text-center py-2 font-mono">↓</div>
              )}
            </div>
          ))}
        </>
      )}

      {/* LISTA POR SEVERIDADE */}
      <H1>Vulnerabilidades</H1>
      {SEVERITY_ORDER.map((sev) => {
        const list = sortedVulns.filter((v) => v.severity === sev);
        if (list.length === 0) return null;
        return (
          <div key={sev} className="mb-3">
            <H2 className="!mt-2">{SEVERITY_LABEL[sev]}</H2>
            <ol className="list-decimal pl-6 text-sm space-y-1">
              {list.map((v) => (
                <li key={v.id}>
                  <span className="text-[#1c1d21]/70">[{STATUS_LABEL[v.status]}]</span>{' '}
                  {v.title}
                </li>
              ))}
            </ol>
          </div>
        );
      })}

      {/* DETALHAMENTO */}
      <H1>Detalhamento das vulnerabilidades</H1>
      {sortedVulns.map((v, idx) => (
        <div key={v.id} className="border-t-2 border-[#1c1d21]/15 pt-5 mt-5">
          <div className="flex items-baseline justify-between">
            <h3 className="text-xl">
              {String(idx + 1).padStart(2, '0')}. {v.title}
            </h3>
            <span
              className="text-sm font-mono uppercase px-2 py-0.5"
              style={{ background: `var(--sev-${v.severity})`, color: '#fff' }}
            >
              {SEVERITY_LABEL[v.severity]}
            </span>
          </div>
          <ContentBlock title="Descrição" html={v.description} />
          <ContentBlock title="Cenário de ataque" html={v.attackScenario} />
          <ContentBlock title="Recomendação" html={v.recommendation} />
          <H3>Tags</H3>
          <ul className="text-xs space-y-0.5 font-mono">
            {v.tags.map((t) => (
              <li key={t}>{t}</li>
            ))}
            {v.cwe.map((c) => (
              <li key={c}>{c}</li>
            ))}
            {v.cvss && (
              <>
                <li>{v.cvss.vector}</li>
                <li>CVSSv3.1 Base Score: {v.cvss.score.toFixed(1)}</li>
              </>
            )}
          </ul>
          <H3>Ativos afetados</H3>
          <ul className="list-disc pl-6 text-sm font-mono">
            {v.targets.map((t) => (
              <li key={t}>{t}</li>
            ))}
          </ul>
          {v.steps.length > 0 && (
            <>
              <H3>Passos de reprodução</H3>
              <ol className="list-decimal pl-6 text-sm space-y-2">
                {v.steps.map((s) => (
                  <li key={s.id}>
                    {s.text}
                    {s.command && (
                      <pre className="bg-[#0f1116] text-[#a3e4c0] text-xs p-3 rounded mt-1 overflow-x-auto font-mono">
                        {s.command}
                      </pre>
                    )}
                  </li>
                ))}
              </ol>
            </>
          )}
          {v.pocs.length > 0 && (
            <>
              <H3>Proof of concept</H3>
              {v.pocs.map((p) => (
                <div key={p.id} className="mb-3">
                  <p className="text-sm font-medium">{p.title}</p>
                  {p.description && (
                    <p className="text-sm text-[#1c1d21]/80 mt-1">{p.description}</p>
                  )}
                  {p.code?.content && (
                    <pre className="bg-[#0f1116] text-[#a3e4c0] text-xs p-3 rounded mt-1 overflow-x-auto font-mono whitespace-pre">
                      {p.code.content}
                    </pre>
                  )}
                </div>
              ))}
            </>
          )}
        </div>
      ))}

      {/* APÊNDICE E - credenciais */}
      {credentials.length > 0 && (
        <>
          <H1>Apêndice E — Credenciais e artefatos coletados</H1>
          <P>
            As credenciais e artefatos listados abaixo foram coletados durante o pentest e devem
            ser <strong>ROTACIONADOS</strong> imediatamente.
          </P>
          <table className="w-full text-xs mt-2 border-collapse font-mono">
            <thead>
              <tr className="bg-[#1c1d21] text-white">
                <th className="text-left px-2 py-1.5 font-medium">USUÁRIO</th>
                <th className="text-left px-2 py-1.5 font-medium">CONTEXTO</th>
                <th className="text-left px-2 py-1.5 font-medium">VALOR</th>
              </tr>
            </thead>
            <tbody>
              {credentials.map((c) => (
                <tr key={c.id} className="border-b border-[#1c1d21]/10">
                  <td className="px-2 py-1.5">{c.user}</td>
                  <td className="px-2 py-1.5">{c.context}</td>
                  <td className="px-2 py-1.5">{c.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      <H1>Apêndice F — Referências</H1>
      <ul className="text-sm space-y-0.5">
        <li>
          OWASP Top 10 (2021) —{' '}
          <span className="font-mono text-[#1c1d21]/70">https://owasp.org/Top10</span>
        </li>
        <li>
          CWE Top 25 —{' '}
          <span className="font-mono text-[#1c1d21]/70">https://cwe.mitre.org/top25</span>
        </li>
        <li>
          CVSS v3.1 Specification —{' '}
          <span className="font-mono text-[#1c1d21]/70">
            https://www.first.org/cvss/v3.1/specification-document
          </span>
        </li>
      </ul>
    </div>
  );
}

function H1({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="text-2xl font-light mt-10 mb-3 text-[#1c1d21] uppercase tracking-wide">
      {children}
    </h2>
  );
}

function H2({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <h3
      className={`text-base uppercase tracking-wider text-[#1c1d21]/80 font-medium mt-5 mb-2 ${className ?? ''}`}
    >
      {children}
    </h3>
  );
}

function H3({ children }: { children: React.ReactNode }) {
  return (
    <h4 className="text-sm uppercase tracking-wider text-[#1c1d21]/70 font-medium mt-3 mb-1">
      {children}
    </h4>
  );
}

function P({ children }: { children: React.ReactNode }) {
  return <p className="text-sm leading-relaxed text-[#1c1d21]/90 my-2">{children}</p>;
}

function Row({ label, value }: { label: string; value: string | number }) {
  return (
    <tr>
      <td className="py-0.5 text-[#1c1d21]/70 pr-3">
        {label}
        {' '}<span className="text-[#1c1d21]/30">{'.'.repeat(28)}</span>
      </td>
      <td className="py-0.5 text-right">{value}</td>
    </tr>
  );
}

function ContentBlock({ title, html }: { title: string; html: string }) {
  if (!html || html.trim() === '<p></p>') return null;
  return (
    <>
      <H3>{title}</H3>
      <div
        className="text-sm leading-relaxed text-[#1c1d21]/90"
        dangerouslySetInnerHTML={{ __html: html }}
      />
    </>
  );
}
