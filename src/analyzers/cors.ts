/**
 * Sentinela — CORS Analyzer
 *
 * Detecta configurações CORS inseguras.
 *
 * Referência: context.md — Seção 19
 * CWE-942: Overly Permissive Cross-domain Whitelist
 * OWASP: A05:2021 — Security Misconfiguration
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { grepMulti } from "../core/grep.js";

const PATTERNS = [
  {
    id: "cors-wildcard",
    pattern: /(?:origin|Access-Control-Allow-Origin)\s*[:=]\s*["']\*["']/,
    title: "CORS com origin: '*' — permite qualquer origem",
    severity: "high" as const,
    rule_id: "19.1",
  },
  {
    id: "cors-wildcard-header",
    pattern: /Access-Control-Allow-Origin.*\*/,
    title: "Header Access-Control-Allow-Origin com wildcard",
    severity: "high" as const,
    rule_id: "19.1",
  },
  {
    id: "cors-reflect-origin",
    pattern: /(?:origin|Access-Control-Allow-Origin)\s*[:=]\s*req\.headers\.origin/,
    title: "CORS reflete origin do request sem validação (anti-pattern)",
    severity: "critical" as const,
    rule_id: "19.2",
  },
  {
    id: "cors-credentials-true",
    pattern: /(?:credentials|Access-Control-Allow-Credentials)\s*[:=]\s*(?:true|["']true["'])/,
    title: "CORS com credentials: true — verificar se origin não é '*'",
    severity: "medium" as const,
    rule_id: "19.1",
  },
  {
    id: "django-cors-all",
    pattern: /CORS_ALLOW_ALL_ORIGINS\s*=\s*True/,
    title: "Django CORS_ALLOW_ALL_ORIGINS = True — permite qualquer origem",
    severity: "high" as const,
    rule_id: "19.1",
  },
  {
    id: "rails-cors-all",
    pattern: /origins\s+["']\*["']/,
    title: "Rails CORS com origins '*' — permite qualquer origem",
    severity: "high" as const,
    rule_id: "19.1",
  },
];

export const corsAnalyzer: Analyzer = {
  name: "cors",
  section: "19",

  async analyze(context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let counter = 0;

    const grepPatterns = PATTERNS.map((p) => ({ id: p.id, pattern: p.pattern }));
    const results = await grepMulti(context.project_path, grepPatterns, {
      extensions: [".ts", ".tsx", ".js", ".jsx", ".py", ".rb", ".php", ".java", ".json", ".yaml", ".yml"],
    });

    for (const pat of PATTERNS) {
      const matches = results.get(pat.id) ?? [];
      for (const match of matches) {
        if (match.file.includes("test") || match.file.includes("spec")) continue;
        if (match.content.trimStart().startsWith("//") || match.content.trimStart().startsWith("#")) continue;

        counter++;
        findings.push({
          id: `SENT-COR-${String(counter).padStart(3, "0")}`,
          rule_id: pat.rule_id,
          severity: pat.severity,
          category: "cors",
          title: pat.title,
          description: "Configuração CORS permissiva permite que sites maliciosos façam requests autenticados ao seu backend, roubando dados do usuário.",
          file: match.file,
          line: match.line,
          evidence: match.content,
          recommendation: "Definir whitelist explícita de origens permitidas. NUNCA usar '*' com credentials. NUNCA refletir origin sem validação.",
          confidence: "high",
          detection_method: "deterministic",
          cwe: "CWE-942",
          owasp: "A05:2021",
        });
      }
    }

    return findings;
  },
};
