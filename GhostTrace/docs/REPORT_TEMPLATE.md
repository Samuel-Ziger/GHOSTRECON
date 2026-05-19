# GhostTrace — Mapa do Template de Relatório

Engenharia reversa dos exemplos de referência (BancoCN.docx / LocBook). Este documento é a **fonte da verdade** para o data model das vulnerabilidades e para o gerador DOCX.

## Hierarquia de seções

1. **Capa** — logo da consultoria, "Relatório de Vulnerabilidades", `<Cliente>`, data, badge `INFORMAÇÃO CONFIDENCIAL`.
2. **Índice** (auto-gerado pelo Word ou inserido manualmente).
3. **Introdução** (H1)
   - Objetivo (H2)
   - Metodologia (H2) — Black/Gray/White Box + padrões OWASP / CWE / CVSS v3.1
   - Ferramentas utilizadas (H2) — tabela 2 colunas (Finalidade | Ferramentas)
   - Ordem operacional do engajamento (linha do tempo) — extensão LocBook
4. **Sumário executivo**
   - Big number: total de vulnerabilidades únicas
   - Grid de severidades (Crítica | Alta | Média | Baixa | Info)
   - Indicadores especiais (Zero-Day | Easily-Exploitable)
5. **Sumário dos testes**
   - Datas Início / Fim
   - Contagens por status e severidade
   - Escopo do projeto (lista de alvos)
   - Histórico de reteste
   - Notas do projeto
6. **Resumo da cadeia de ataque (Attack Chain)** — extensão LocBook
   - Diagrama por host (numerado `(1)..(N)`), com salto entre EDGE → pivot → interno
7. **Vulnerabilidades — lista resumida por severidade**
   - Cada item: `[STATUS] Título` + linha `total de ativos afetados: X - corrigidas: Y - reteste: Z - não corrigidas: W`
8. **Detalhamento das vulnerabilidades** — uma seção por finding:
   - Severidade
   - Descrição
   - Cenário de ataque
   - Recomendação
   - Tags (OWASP, CWE, CVSS string + score)
   - Ativos afetados
   - Notas de remediação
   - Notas adicionais
   - Proof of Concept
   - Passos de reprodução (numerados, com imagens)
9. **Conclusão**
   - Recomendações prioritárias
   - Recomendações de médio prazo
10. **Apêndices**
    - A — Overview explicado (definições de severidade, zero-day, easily-exploitable)
    - B — Definição dos níveis de severidade (tabela probabilidade × impacto)
    - C — Mapeamento dos ativos afetados para cada vulnerabilidade
    - D — Plano de ação (Sev | Vuln | Ação | Impacto)
    - E — Credenciais e artefatos coletados (Usuário | Contexto | Valor)
    - F — Referências (OWASP Top 10, CWE Top 25, CVSS v3.1, CVEs específicas)

## Estilos do DOCX de referência

- **Heading 1, Heading 2** — Calibri / Segoe UI Light
- **Texto monoespaçado** — Menlo / Courier New (usado em código, comandos, payloads)
- **Cores tema (Office defaults usados)** — `#000000` (banner capa preto), `#44546A` (azul-cinza acento), `#0563C1` (links), `#404040` (texto), `#4472C4 #5B9BD5 #70AD47 #ED7D31 #FFC000` (acentos)
- **Tabelas** — header com fundo preto + texto branco
- **Code blocks** — monospace com fundo cinza claro

## Mapeamento Template ↔ Data Model

| Seção do relatório | Tipo TS | Campo |
|---|---|---|
| Capa | `Project` | `client`, `startDate`, `codename` |
| Metodologia | `Project` | `methodology`, `tools[]` |
| Escopo | `Project` | `scope[]` |
| Sumário executivo | derivado | `count(vulnerabilities) by severity` |
| Sumário dos testes | `Project` + derivado | `startDate`, `endDate`, contagens |
| Attack chain | `AttackChainNode[]` | grafo de hosts comprometidos |
| Lista por severidade | derivado | agrupamento de `Vulnerability` por `severity` |
| Detalhamento vuln | `Vulnerability` | todos os campos (description, scenario, recommendation, …) |
| Apêndice C | derivado | join `Vulnerability.targets × scope` |
| Apêndice D | derivado | agregação de `recommendation` por severidade |
| Apêndice E | `Credential[]` | tabela direta |

## Severidades — semântica (Apêndice B)

| Severidade | Probabilidade 12 meses | Significado |
|---|---|---|
| Crítica | Alta | Espera-se que o evento ocorra |
| Alta | ~50% | Provável com proteções existentes |
| Média | ~10% | Pode ocorrer em algumas circunstâncias |
| Baixa | ~1% | Pode ocorrer em circunstâncias específicas |
| Info | n/a | Sem ameaça imediata, registro informacional |

Marcadores especiais:
- **Zero-Day** — desconhecida pelo fornecedor à época do teste
- **Easily-Exploitable** — exploit público pronto, default config, sem auth
