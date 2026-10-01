/**
 * Sentinela — Error Handling Analyzer
 *
 * Detecta rotas de API sem try-catch e catch que expõe erro ao cliente.
 *
 * Referência: context.md — Seção 31
 * CWE-755: Improper Handling of Exceptional Conditions
 * OWASP: A04:2021 — Insecure Design
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { grep, grepMulti } from "../core/grep.js";

export const errorHandlingAnalyzer: Analyzer = {
  name: "error-handling",
  section: "31",

  async analyze(context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let counter = 0;

    // 1. Catch blocks que expõem erro diretamente
    const catchPatterns = [
      {
        id: "catch-return-error",
        pattern: /catch\s*\([^)]*\)\s*\{[^}]*return\s+(?:res\.json|NextResponse\.json|Response\.json)\s*\(\s*(?:err|error|e)\s*\)/,
        title: "Catch block retorna objeto de erro raw ao cliente",
        severity: "critical" as const,
      },
      {
        id: "empty-catch",
        pattern: /catch\s*\([^)]*\)\s*\{\s*\}/,
        title: "Catch block vazio — erros são silenciosamente ignorados",
        severity: "medium" as const,
      },
      {
        id: "catch-console-only",
        pattern: /catch\s*\([^)]*\)\s*\{\s*console\.\w+\s*\([^)]*\)\s*;?\s*\}/,
        title: "Catch block apenas com console.log — sem tratamento real",
        severity: "medium" as const,
      },
    ];

    const grepPatterns = catchPatterns.map((p) => ({ id: p.id, pattern: p.pattern }));
    const results = await grepMulti(context.project_path, grepPatterns, {
      extensions: [".ts", ".tsx", ".js", ".jsx"],
    });

    for (const pat of catchPatterns) {
      const matches = results.get(pat.id) ?? [];
      for (const match of matches) {
        if (match.file.includes("test") || match.file.includes("spec")) continue;

        counter++;
        findings.push({
          id: `SENT-EHD-${String(counter).padStart(3, "0")}`,
          rule_id: "31.1",
          severity: pat.severity,
          category: "error-handling",
          title: pat.title,
          description: "Error handling inadequado pode expor detalhes internos ao atacante ou esconder bugs críticos.",
          file: match.file,
          line: match.line,
          evidence: match.content,
          recommendation: "Logar o erro completo no servidor e retornar mensagem genérica ao cliente. Nunca ignorar erros silenciosamente.",
          confidence: "medium",
          detection_method: "deterministic",
          cwe: "CWE-755",
          owasp: "A04:2021",
        });
      }
    }

    // 2. Verificar se existe global error handler
    const globalHandlers = await grep(context.project_path, {
      pattern: /(?:app\.use\s*\(\s*(?:function\s*\(err|[\w.]*errorHandler|[\w.]*ErrorHandler)|process\.on\s*\(\s*["']unhandledRejection|process\.on\s*\(\s*["']uncaughtException|GlobalErrorBoundary|ErrorBoundary)/,
      maxMatches: 3,
    });

    if (globalHandlers.length === 0) {
      // Verificar se o projeto tem API routes
      const hasApiRoutes = await grep(context.project_path, {
        pattern: /(?:export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)|app\.(?:get|post|put|patch|delete)\s*\()/,
        maxMatches: 1,
      });

      if (hasApiRoutes.length > 0) {
        counter++;
        findings.push({
          id: `SENT-EHD-${String(counter).padStart(3, "0")}`,
          rule_id: "31.2",
          severity: "high",
          category: "error-handling",
          title: "Nenhum global error handler encontrado",
          description: "Sem error handler global, erros não tratados em qualquer rota podem expor stack traces ao cliente.",
          recommendation: "Implementar middleware de error handling global (ex: app.use((err, req, res, next) => { ... })) e tratar unhandledRejection/uncaughtException.",
          confidence: "medium",
          detection_method: "deterministic",
          cwe: "CWE-755",
          owasp: "A04:2021",
        });
      }
    }

    return findings;
  },
};
