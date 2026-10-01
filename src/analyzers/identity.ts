/**
 * Sentinela — Identity Analyzer
 *
 * Detecta quando identidade do usuário é aceita do frontend em mutações.
 *
 * Referência: context.md — Seção 2.1 (Zero Trust do Frontend)
 * CWE-639: Authorization Bypass Through User-Controlled Key
 * OWASP: A01:2021 — Broken Access Control
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { grepMulti } from "../core/grep.js";

const PATTERNS = [
  {
    id: "user-id-from-body",
    pattern: /(?:req\.body|body|request\.body)\s*\.\s*(?:user_?id|userId|owner_?id|ownerId|author_?id)/,
    title: "user_id extraído do body da request (deve vir do JWT/session)",
    severity: "critical" as const,
  },
  {
    id: "user-id-from-query",
    pattern: /(?:req\.query|query|request\.query|searchParams)\s*\.\s*(?:user_?id|userId|owner_?id)/,
    title: "user_id extraído de query params (deve vir do JWT/session)",
    severity: "critical" as const,
  },
  {
    id: "user-id-from-params",
    pattern: /(?:req\.params|params)\s*\.\s*(?:user_?id|userId|owner_?id)/,
    title: "user_id extraído de URL params — verificar se é validado contra sessão",
    severity: "high" as const,
  },
  {
    id: "destructure-user-id",
    pattern: /const\s*\{[^}]*user_?[Ii]d[^}]*\}\s*=\s*(?:req\.body|body|await\s+req\.json\(\))/,
    title: "user_id desestruturado do body — identidade deve vir do server",
    severity: "critical" as const,
  },
];

export const identityAnalyzer: Analyzer = {
  name: "identity",
  section: "2",

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
        if (match.file.includes("test") || match.file.includes("spec")) continue;
        if (match.content.trimStart().startsWith("//") || match.content.trimStart().startsWith("#")) continue;

        counter++;
        findings.push({
          id: `SENT-IDN-${String(counter).padStart(3, "0")}`,
          rule_id: "2.1",
          severity: pat.severity,
          category: "identity",
          title: pat.title,
          description: "A identidade do usuário NUNCA deve ser aceita do frontend. Deve ser derivada do JWT/token de sessão no server-side. Um atacante pode enviar qualquer user_id no body.",
          file: match.file,
          line: match.line,
          evidence: match.content,
          recommendation: "Extrair user_id do JWT/session no middleware de autenticação. Nunca aceitar do req.body, req.query, ou req.params sem validação contra a sessão.",
          confidence: "high",
          detection_method: "deterministic",
          cwe: "CWE-639",
          owasp: "A01:2021",
        });
      }
    }

    return findings;
  },
};
