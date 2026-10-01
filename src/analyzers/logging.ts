/**
 * Sentinela — Logging Analyzer
 *
 * Detecta dados sensíveis em logs (senhas, tokens, secrets).
 *
 * Referência: context.md — Seção 22 (Logging & Monitoring)
 * CWE-532: Insertion of Sensitive Information into Log File
 * OWASP: A09:2021 — Security Logging and Monitoring Failures
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { grepMulti } from "../core/grep.js";

const PATTERNS = [
  {
    id: "log-req-body",
    pattern: /(?:console\.log|logger?\.\w+)\s*\(\s*(?:req\.body|request\.body)/,
    title: "req.body logado diretamente — pode conter senhas/tokens",
    severity: "high" as const,
  },
  {
    id: "log-password",
    pattern: /(?:console\.log|logger?\.\w+)\s*\([^)]*(?:password|passwd|pwd|senha)/i,
    title: "Campo de senha pode estar sendo logado",
    severity: "critical" as const,
  },
  {
    id: "log-token",
    pattern: /(?:console\.log|logger?\.\w+)\s*\([^)]*(?:token|jwt|bearer|auth_key|api_key|secret)/i,
    title: "Token/secret pode estar sendo logado",
    severity: "critical" as const,
  },
  {
    id: "log-credit-card",
    pattern: /(?:console\.log|logger?\.\w+)\s*\([^)]*(?:card_number|cardNumber|cvv|credit_card)/i,
    title: "Dados de cartão de crédito podem estar sendo logados",
    severity: "critical" as const,
  },
  {
    id: "console-log-prod",
    pattern: /console\.log\s*\(\s*(?:err|error)\s*\)/,
    title: "console.log(error) em código que pode rodar em produção",
    severity: "medium" as const,
  },
];

export const loggingAnalyzer: Analyzer = {
  name: "logging",
  section: "22",

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
          id: `SENT-LOG-${String(counter).padStart(3, "0")}`,
          rule_id: "22.1",
          severity: pat.severity,
          category: "logging",
          title: pat.title,
          description: "Dados sensíveis em logs podem ser acessados por equipe de ops, sistemas de monitoramento, ou atacantes que comprometam o armazenamento de logs.",
          file: match.file,
          line: match.line,
          evidence: match.content,
          recommendation: "Usar logger estruturado com redação automática de campos sensíveis. Nunca logar req.body, senhas, tokens ou dados financeiros.",
          confidence: "medium",
          detection_method: "deterministic",
          cwe: "CWE-532",
          owasp: "A09:2021",
        });
      }
    }

    return findings;
  },
};
