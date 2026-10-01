/**
 * Sentinela — IDOR Analyzer
 *
 * Detecta Insecure Direct Object References — queries de
 * UPDATE/DELETE sem verificação de ownership.
 *
 * Referência: context.md — Seção 6
 * CWE-639: Authorization Bypass Through User-Controlled Key
 * OWASP: A01:2021 — Broken Access Control
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { grepMulti } from "../core/grep.js";

const PATTERNS = [
  {
    id: "update-no-owner",
    pattern: /\.(?:update|updateMany|updateFirst)\s*\(\s*\{[\s\S]*?where\s*:\s*\{[^}]*id\s*:/,
    title: "UPDATE com WHERE por id sem filtro de owner_id — possível IDOR",
    severity: "critical" as const,
  },
  {
    id: "delete-no-owner",
    pattern: /\.(?:delete|deleteMany|deleteFirst|destroy)\s*\(\s*\{[\s\S]*?where\s*:\s*\{[^}]*id\s*:/,
    title: "DELETE com WHERE por id sem filtro de owner_id — possível IDOR",
    severity: "critical" as const,
  },
  {
    id: "supabase-no-owner-update",
    pattern: /\.from\s*\([^)]+\)\s*\.(?:update|delete)\s*\([^)]*\)\s*\.(?:eq|match)\s*\(\s*["']id["']/,
    title: "Supabase update/delete filtrando apenas por id — verificar ownership",
    severity: "high" as const,
  },
  {
    id: "sql-update-where-id",
    pattern: /(?:UPDATE|DELETE\s+FROM)\s+\w+\s+.*?WHERE\s+(?:id|_id)\s*=/i,
    title: "SQL UPDATE/DELETE com WHERE id= — verificar se inclui user_id/owner_id",
    severity: "high" as const,
  },
  {
    id: "findUnique-param-id",
    pattern: /\.findUnique\s*\(\s*\{[^}]*where\s*:\s*\{\s*id\s*:\s*(?:req\.params|params|args)\./,
    title: "findUnique por params.id sem validação de ownership",
    severity: "high" as const,
  },
  {
    id: "django-get-pk",
    pattern: /\.objects\.get\s*\(\s*pk\s*=\s*(?:request\.|kwargs\[)/,
    title: "Django objects.get(pk=) direto do request — possível IDOR",
    severity: "high" as const,
  },
];

export const idorAnalyzer: Analyzer = {
  name: "idor",
  section: "6",

  async analyze(context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let counter = 0;

    const grepPatterns = PATTERNS.map((p) => ({ id: p.id, pattern: p.pattern }));
    const results = await grepMulti(context.project_path, grepPatterns, {
      extensions: [".ts", ".tsx", ".js", ".jsx", ".py", ".rb", ".php", ".java", ".cs", ".go"],
    });

    for (const pat of PATTERNS) {
      const matches = results.get(pat.id) ?? [];
      for (const match of matches) {
        if (match.file.includes("test") || match.file.includes("spec") || match.file.includes("migration")) continue;
        if (match.content.trimStart().startsWith("//") || match.content.trimStart().startsWith("#")) continue;
        // Se já tem owner_id, user_id ou org_id no mesmo trecho, provavelmente ok
        if (match.content.includes("owner_id") || match.content.includes("user_id") || match.content.includes("userId") || match.content.includes("org_id")) continue;

        counter++;
        findings.push({
          id: `SENT-IDR-${String(counter).padStart(3, "0")}`,
          rule_id: "6.1",
          severity: pat.severity,
          category: "idor",
          title: pat.title,
          description: "Sem filtro de ownership, um usuário pode alterar/deletar recursos de outro usuário apenas adivinhando o ID. Todo UPDATE/DELETE deve incluir AND user_id = <current_user>.",
          file: match.file,
          line: match.line,
          evidence: match.content,
          recommendation: "Adicionar filtro de ownership: WHERE id = :id AND user_id = :currentUserId. Ou usar RLS no banco.",
          confidence: "medium",
          detection_method: "deterministic",
          cwe: "CWE-639",
          owasp: "A01:2021",
        });
      }
    }

    return findings;
  },
};
