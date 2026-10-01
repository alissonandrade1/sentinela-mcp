/**
 * Sentinela — Security Headers Analyzer
 *
 * Verifica configuração de headers de segurança.
 *
 * Referência: context.md — Seção 11
 * CWE-693: Protection Mechanism Failure
 * OWASP: A05:2021 — Security Misconfiguration
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { grep } from "../core/grep.js";
import { readFileContent } from "../core/filesystem.js";
import { join } from "node:path";

const REQUIRED_HEADERS = [
  { name: "Strict-Transport-Security", pattern: /strict-transport-security/i, severity: "high" as const },
  { name: "X-Content-Type-Options", pattern: /x-content-type-options/i, severity: "medium" as const },
  { name: "X-Frame-Options", pattern: /x-frame-options/i, severity: "medium" as const },
  { name: "Content-Security-Policy", pattern: /content-security-policy/i, severity: "high" as const },
  { name: "Referrer-Policy", pattern: /referrer-policy/i, severity: "low" as const },
  { name: "Permissions-Policy", pattern: /permissions-policy/i, severity: "low" as const },
];

export const headersAnalyzer: Analyzer = {
  name: "headers",
  section: "11",

  async analyze(context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let counter = 0;

    // Buscar headers em configs e middleware
    for (const header of REQUIRED_HEADERS) {
      const matches = await grep(context.project_path, {
        pattern: header.pattern,
        extensions: [".ts", ".tsx", ".js", ".jsx", ".py", ".rb", ".php", ".json", ".yaml", ".yml", ".toml"],
        maxMatches: 5,
      });

      // Também verificar next.config
      const nextConfig = await readFileContent(join(context.project_path, "next.config.js"))
        ?? await readFileContent(join(context.project_path, "next.config.mjs"))
        ?? await readFileContent(join(context.project_path, "next.config.ts"));

      const inNextConfig = nextConfig ? header.pattern.test(nextConfig) : false;

      // Verificar vercel.json
      const vercelConfig = await readFileContent(join(context.project_path, "vercel.json"));
      const inVercel = vercelConfig ? header.pattern.test(vercelConfig) : false;

      if (matches.length === 0 && !inNextConfig && !inVercel) {
        counter++;
        findings.push({
          id: `SENT-HDR-${String(counter).padStart(3, "0")}`,
          rule_id: "11.1",
          severity: header.severity,
          category: "headers",
          title: `Security header "${header.name}" não encontrado`,
          description: `O header ${header.name} não foi encontrado em nenhum middleware, config ou arquivo do projeto. Isso pode deixar a aplicação vulnerável.`,
          recommendation: `Configurar o header ${header.name} no middleware, next.config.js, ou proxy reverso (nginx/Cloudflare).`,
          confidence: "medium",
          detection_method: "deterministic",
          cwe: "CWE-693",
          owasp: "A05:2021",
        });
      }
    }

    return findings;
  },
};
