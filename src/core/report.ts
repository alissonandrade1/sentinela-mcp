/**
 * Sentinela — Report Generator
 *
 * Formata AuditReport em markdown legível e gera diff entre relatórios.
 */

import type { AuditReport, Finding } from "./types.js";

// ============================================================================
// Markdown Report
// ============================================================================

const SEVERITY_ICON: Record<string, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
};

export function generateMarkdownReport(report: AuditReport): string {
  const lines: string[] = [];

  lines.push(`# 🛡️ Sentinela — Relatório de Segurança`);
  lines.push(``);
  lines.push(`**Projeto:** ${report.project.name}`);
  lines.push(`**Data:** ${new Date(report.timestamp).toLocaleString("pt-BR")}`);
  lines.push(`**Duração:** ${report.duration_ms}ms`);
  lines.push(`**Stack:** ${report.project.stack.language} / ${report.project.stack.framework} / ${report.project.stack.database}`);
  lines.push(``);

  // Score
  const scoreBar = "█".repeat(Math.floor(report.score / 5)) + "░".repeat(20 - Math.floor(report.score / 5));
  lines.push(`## Score: ${report.score}/100`);
  lines.push(`\`${scoreBar}\``);
  lines.push(``);

  // Summary
  lines.push(`## Resumo`);
  lines.push(``);
  lines.push(`| Severidade | Quantidade |`);
  lines.push(`|---|---|`);
  lines.push(`| 🔴 Crítica | ${report.summary.critical} |`);
  lines.push(`| 🟠 Alta | ${report.summary.high} |`);
  lines.push(`| 🟡 Média | ${report.summary.medium} |`);
  lines.push(`| 🔵 Baixa | ${report.summary.low} |`);
  lines.push(`| **Total** | **${report.summary.total}** |`);
  lines.push(``);

  // By category
  if (Object.keys(report.summary.by_category).length > 0) {
    lines.push(`### Por Categoria`);
    lines.push(``);
    lines.push(`| Categoria | Quantidade |`);
    lines.push(`|---|---|`);
    const sorted = Object.entries(report.summary.by_category).sort((a, b) => b[1] - a[1]);
    for (const [cat, count] of sorted) {
      lines.push(`| ${cat} | ${count} |`);
    }
    lines.push(``);
  }

  // Findings by severity
  const bySeverity = groupBySeverity(report.findings);

  for (const severity of ["critical", "high", "medium", "low"] as const) {
    const group = bySeverity[severity] ?? [];
    if (group.length === 0) continue;

    const icon = SEVERITY_ICON[severity];
    lines.push(`## ${icon} ${severity.toUpperCase()} (${group.length})`);
    lines.push(``);

    for (const f of group) {
      lines.push(`### ${f.id} — ${f.title}`);
      if (f.file) lines.push(`📄 \`${f.file}${f.line ? `:${f.line}` : ""}\``);
      lines.push(``);
      lines.push(f.description);
      lines.push(``);
      if (f.evidence) {
        lines.push("```");
        lines.push(f.evidence.trim());
        lines.push("```");
        lines.push(``);
      }
      lines.push(`**Recomendação:** ${f.recommendation}`);
      if (f.cwe || f.owasp) {
        lines.push(`**Ref:** ${[f.cwe, f.owasp].filter(Boolean).join(" | ")}`);
      }
      lines.push(``);
      lines.push(`---`);
      lines.push(``);
    }
  }

  return lines.join("\n");
}

// ============================================================================
// Report Comparison
// ============================================================================

export interface ReportDiff {
  new_findings: Finding[];
  resolved_findings: Finding[];
  persistent_findings: Finding[];
  score_before: number;
  score_after: number;
  score_change: number;
  summary: string;
}

export function compareReports(before: AuditReport, after: AuditReport): ReportDiff {
  const beforeIds = new Set(before.findings.map((f) => `${f.category}:${f.file}:${f.line}:${f.title}`));
  const afterIds = new Set(after.findings.map((f) => `${f.category}:${f.file}:${f.line}:${f.title}`));

  const newFindings = after.findings.filter(
    (f) => !beforeIds.has(`${f.category}:${f.file}:${f.line}:${f.title}`),
  );

  const resolvedFindings = before.findings.filter(
    (f) => !afterIds.has(`${f.category}:${f.file}:${f.line}:${f.title}`),
  );

  const persistentFindings = after.findings.filter(
    (f) => beforeIds.has(`${f.category}:${f.file}:${f.line}:${f.title}`),
  );

  const scoreChange = after.score - before.score;

  let summary: string;
  if (resolvedFindings.length > 0 && newFindings.length === 0) {
    summary = `✅ ${resolvedFindings.length} vulnerabilidade(s) corrigida(s). Score: ${before.score} → ${after.score} (+${scoreChange}).`;
  } else if (newFindings.length > 0 && resolvedFindings.length === 0) {
    summary = `⚠️ ${newFindings.length} nova(s) vulnerabilidade(s) introduzida(s). Score: ${before.score} → ${after.score} (${scoreChange}).`;
  } else if (newFindings.length > 0 && resolvedFindings.length > 0) {
    summary = `🔄 ${resolvedFindings.length} corrigida(s), ${newFindings.length} nova(s). Score: ${before.score} → ${after.score} (${scoreChange >= 0 ? "+" : ""}${scoreChange}).`;
  } else {
    summary = `Sem mudanças. Score: ${after.score}/100. ${persistentFindings.length} pendente(s).`;
  }

  return {
    new_findings: newFindings,
    resolved_findings: resolvedFindings,
    persistent_findings: persistentFindings,
    score_before: before.score,
    score_after: after.score,
    score_change: scoreChange,
    summary,
  };
}

// ============================================================================
// Checklist
// ============================================================================

export function generateChecklist(findings: Finding[]): { item: string; status: "pass" | "fail"; finding_id?: string; section: string }[] {
  const CHECKLIST_ITEMS = [
    { item: "Nenhuma credencial hardcoded no código", category: "secrets", section: "13" },
    { item: ".env no .gitignore", category: "secrets", section: "13" },
    { item: "Nenhum output XSS inseguro", category: "xss", section: "18" },
    { item: "Sem eval/desserialização insegura", category: "deserialization", section: "28" },
    { item: "Dados sensíveis não aparecem em logs", category: "logging", section: "22" },
    { item: "Erros não expõem detalhes internos", category: "error-messages", section: "4" },
    { item: "Error handling com global handler", category: "error-handling", section: "31" },
    { item: "Identidade do usuário vem do server (JWT/session)", category: "identity", section: "2" },
    { item: "CORS configurado com whitelist", category: "cors", section: "19" },
    { item: "Security headers configurados", category: "headers", section: "11" },
    { item: "Dependências com lock file e Dependabot", category: "dependencies", section: "21" },
    { item: "Rate limiting em rotas de autenticação", category: "rate-limiting", section: "5" },
    { item: "Input validado com schema (zod/yup/joi)", category: "input-validation", section: "3" },
    { item: "Sem mass assignment (spread de req.body)", category: "mass-assignment", section: "20" },
    { item: "UPDATE/DELETE com filtro de ownership", category: "idor", section: "6" },
    { item: "Auth com bcrypt/argon2, cookies seguros", category: "auth", section: "8" },
    { item: "Webhooks com verificação de assinatura", category: "webhooks", section: "27" },
    { item: "Upload com validação de tipo e tamanho", category: "uploads", section: "10" },
    { item: "Sem SSRF (URLs do usuário validadas)", category: "ssrf", section: "23" },
    { item: "Sem open redirect", category: "redirects", section: "24" },
    { item: "Testes de segurança existem", category: "tests", section: "14" },
    { item: "Secrets management com .env.example", category: "secrets-mgmt", section: "26" },
    { item: "Sem timing attacks em comparações de secret", category: "timing", section: "29" },
    { item: "Request limits configurados (body size, timeout)", category: "request-limits", section: "32" },
  ];

  const findingsByCategory = new Map<string, Finding>();
  for (const f of findings) {
    if (!findingsByCategory.has(f.category)) {
      findingsByCategory.set(f.category, f);
    }
  }

  return CHECKLIST_ITEMS.map((item) => {
    const finding = findingsByCategory.get(item.category);
    return {
      item: item.item,
      section: item.section,
      status: finding ? "fail" as const : "pass" as const,
      finding_id: finding?.id,
    };
  });
}

// ============================================================================
// Helpers
// ============================================================================

function groupBySeverity(findings: Finding[]): Record<string, Finding[]> {
  const groups: Record<string, Finding[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };
  for (const f of findings) {
    groups[f.severity]?.push(f);
  }
  return groups;
}
