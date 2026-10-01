/**
 * Sentinela — Rate Limiting Analyzer
 *
 * Detecta ausência de rate limiting em rotas de autenticação.
 *
 * Referência: context.md — Seção 5
 * CWE-307: Improper Restriction of Excessive Authentication Attempts
 * OWASP: A07:2021 — Identification and Authentication Failures
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { grep } from "../core/grep.js";
import { parsePackageJSON, hasDependency } from "../core/config-parser.js";

export const rateLimitingAnalyzer: Analyzer = {
  name: "rate-limiting",
  section: "5",

  async analyze(context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let counter = 0;

    // 1. Verificar se o projeto tem rate limiting configurado
    const rateLimitMatches = await grep(context.project_path, {
      pattern: /(?:rateLimit|rate_limit|rateLimiter|throttle|Throttle|slowDown|limiter)/i,
      maxMatches: 5,
    });

    const pkg = await parsePackageJSON(context.project_path);
    const hasRateLimitDep = pkg ? hasDependency(pkg, "express-rate-limit") || hasDependency(pkg, "rate-limiter-flexible") || hasDependency(pkg, "@upstash/ratelimit") : false;

    // Verificar se tem rotas de autenticação
    const authRoutes = await grep(context.project_path, {
      pattern: /(?:\/(?:api\/)?(?:auth|login|register|signup|sign-in|sign-up|forgot-password|reset-password))|(?:export\s+(?:async\s+)?function\s+POST)/i,
      extensions: [".ts", ".tsx", ".js", ".jsx", ".py", ".rb", ".php"],
      maxMatches: 10,
    });

    if (authRoutes.length > 0 && rateLimitMatches.length === 0 && !hasRateLimitDep) {
      counter++;
      findings.push({
        id: `SENT-RLM-${String(counter).padStart(3, "0")}`,
        rule_id: "5.1",
        severity: "high",
        category: "rate-limiting",
        title: "Nenhum rate limiting encontrado — rotas de auth vulneráveis a brute force",
        description: "Sem rate limiting, um atacante pode fazer milhares de tentativas de login por segundo para adivinhar senhas.",
        recommendation: "Instalar express-rate-limit, @upstash/ratelimit, ou rate-limiter-flexible. Aplicar rate limit em: /login, /register, /forgot-password, /api/auth/*.",
        confidence: "medium",
        detection_method: "deterministic",
        cwe: "CWE-307",
        owasp: "A07:2021",
      });
    }

    // 2. Rate limit existe mas é muito permissivo?
    const permissiveLimit = await grep(context.project_path, {
      pattern: /(?:max|limit)\s*:\s*(?:1000|5000|10000|99999)/,
      maxMatches: 5,
    });

    for (const match of permissiveLimit) {
      if (match.file.includes("test") || match.file.includes("spec")) continue;
      if (match.content.includes("rate") || match.content.includes("limit") || match.content.includes("throttle")) {
        counter++;
        findings.push({
          id: `SENT-RLM-${String(counter).padStart(3, "0")}`,
          rule_id: "5.2",
          severity: "medium",
          category: "rate-limiting",
          title: "Rate limit configurado com valor muito alto",
          description: "Rate limit com max muito alto (1000+) não protege efetivamente contra brute force.",
          file: match.file,
          line: match.line,
          evidence: match.content,
          recommendation: "Para login: max 5-10 tentativas por 15min por IP. Para APIs gerais: max 100-200 por minuto.",
          confidence: "low",
          detection_method: "heuristic",
          cwe: "CWE-307",
          owasp: "A07:2021",
        });
      }
    }

    return findings;
  },
};
