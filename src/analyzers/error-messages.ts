/**
 * Sentinela — Error Messages Analyzer
 *
 * Detecta mensagens de erro que revelam estado interno do sistema.
 *
 * Referência: context.md — Seção 4 (Mensagens de Erro)
 * CWE-209: Generation of Error Message Containing Sensitive Information
 * OWASP: A04:2021 — Insecure Design
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { grepMulti } from "../core/grep.js";

const PATTERNS = [
  {
    id: "error-object-exposed",
    pattern: /(?:res\.json|res\.send|Response\.json|JsonResponse|jsonify)\s*\(\s*\{[^}]*(?:error|err|exception)\s*:\s*(?:err|error|e)\b/,
    title: "Objeto de erro enviado diretamente ao cliente",
    severity: "critical" as const,
  },
  {
    id: "error-message-exposed",
    pattern: /(?:res\.json|res\.send|Response\.json)\s*\(\s*\{[^}]*(?:error|message)\s*:\s*(?:err|error|e)\.message/,
    title: "err.message enviado ao cliente — pode conter detalhes internos",
    severity: "high" as const,
  },
  {
    id: "error-stack-exposed",
    pattern: /(?:res\.json|res\.send|Response\.json)\s*\(\s*\{[^}]*stack\s*:/,
    title: "Stack trace enviado ao cliente",
    severity: "critical" as const,
  },
  {
    id: "sql-error-exposed",
    pattern: /(?:res\.json|res\.send)\s*\([^)]*(?:sql|query|database|relation|column|table)\s*(?:error|err)/i,
    title: "Erro de SQL/banco exposto ao cliente",
    severity: "critical" as const,
  },
  {
    id: "catch-rethrow-raw",
    pattern: /catch\s*\(\s*(?:err|error|e)\s*\)\s*\{[^}]*(?:res\.status\(\d+\)\.json|res\.json)\s*\(\s*(?:err|error|e)\s*\)/,
    title: "Catch que reenvia erro raw ao cliente",
    severity: "critical" as const,
  },
];

export const errorMessagesAnalyzer: Analyzer = {
  name: "error-messages",
  section: "4",

  async analyze(context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let counter = 0;

    const grepPatterns = PATTERNS.map((p) => ({ id: p.id, pattern: p.pattern }));
    const results = await grepMulti(context.project_path, grepPatterns, {
      extensions: [".ts", ".tsx", ".js", ".jsx", ".py", ".rb", ".php", ".java", ".cs"],
    });

    for (const pat of PATTERNS) {
      const matches = results.get(pat.id) ?? [];
      for (const match of matches) {
        if (match.file.includes("test") || match.file.includes("spec")) continue;

        counter++;
        findings.push({
          id: `SENT-ERR-${String(counter).padStart(3, "0")}`,
          rule_id: "4.1",
          severity: pat.severity,
          category: "error-messages",
          title: pat.title,
          description: "Mensagens de erro que revelam detalhes internos (stack trace, SQL, nomes de tabelas, caminhos de arquivo) ajudam atacantes a mapear a aplicação.",
          file: match.file,
          line: match.line,
          evidence: match.content,
          recommendation: "Retornar mensagens genéricas ao cliente (ex: 'Ocorreu um erro.'). Logar detalhes completos no servidor.",
          confidence: "high",
          detection_method: "deterministic",
          cwe: "CWE-209",
          owasp: "A04:2021",
        });
      }
    }

    return findings;
  },
};
