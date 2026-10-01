/**
 * Sentinela — Open Redirect Analyzer
 *
 * Detecta redirects com URLs do usuário sem validação.
 *
 * Referência: context.md — Seção 24
 * CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
 * OWASP: A01:2021 — Broken Access Control
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { grepMulti } from "../core/grep.js";

const PATTERNS = [
  {
    id: "redirect-query-param",
    pattern: /(?:res\.redirect|redirect|Response\.redirect)\s*\(\s*(?:req\.query|searchParams\.get|query)\.\s*(?:redirect|next|return|url|to|target|callback|continue)/i,
    title: "Redirect com URL de query param — open redirect",
    severity: "high" as const,
  },
  {
    id: "redirect-body-param",
    pattern: /(?:res\.redirect|redirect)\s*\(\s*(?:req\.body|body)\.\s*(?:redirect|next|return|url|to)/i,
    title: "Redirect com URL de body param — open redirect",
    severity: "high" as const,
  },
  {
    id: "location-header-user",
    pattern: /(?:Location|location)\s*[:=]\s*(?:req\.query|query|searchParams)\./,
    title: "Header Location com valor do query param — open redirect",
    severity: "high" as const,
  },
  {
    id: "window-location-param",
    pattern: /window\.location(?:\.href)?\s*=\s*(?:params|searchParams|query)\./,
    title: "window.location com valor de URL param — open redirect no client",
    severity: "high" as const,
  },
  {
    id: "django-redirect-param",
    pattern: /redirect\s*\(\s*request\.(?:GET|POST)\.\s*get\s*\(\s*["'](?:next|redirect|return)/i,
    title: "Django redirect com request.GET['next'] — open redirect",
    severity: "high" as const,
  },
];

export const redirectsAnalyzer: Analyzer = {
  name: "redirects",
  section: "24",

  async analyze(context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let counter = 0;

    const grepPatterns = PATTERNS.map((p) => ({ id: p.id, pattern: p.pattern }));
    const results = await grepMulti(context.project_path, grepPatterns, {
      extensions: [".ts", ".tsx", ".js", ".jsx", ".py", ".rb", ".php"],
    });

    for (const pat of PATTERNS) {
      const matches = results.get(pat.id) ?? [];
      for (const match of matches) {
        if (match.file.includes("test") || match.file.includes("spec")) continue;
        if (match.content.trimStart().startsWith("//") || match.content.trimStart().startsWith("#")) continue;

        counter++;
        findings.push({
          id: `SENT-RED-${String(counter).padStart(3, "0")}`,
          rule_id: "24.1",
          severity: pat.severity,
          category: "redirects",
          title: pat.title,
          description: "Open redirect permite que um atacante crie links com seu domínio que redirecionam para sites maliciosos, usado em phishing.",
          file: match.file,
          line: match.line,
          evidence: match.content,
          recommendation: "Validar URL de redirect: 1) Usar whitelist de paths permitidos, 2) Verificar que URL começa com '/' (path relativo), 3) Nunca aceitar URLs absolutas do usuário.",
          confidence: "high",
          detection_method: "deterministic",
          cwe: "CWE-601",
          owasp: "A01:2021",
        });
      }
    }

    return findings;
  },
};
