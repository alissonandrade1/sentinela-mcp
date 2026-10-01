/**
 * Sentinela — Request Limits Analyzer
 *
 * Verifica configuração de limites de request (body size, timeout, JSON depth).
 *
 * Referência: context.md — Seção 32
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { grep } from "../core/grep.js";
import { readFileContent } from "../core/filesystem.js";
import { join } from "node:path";

export const requestLimitsAnalyzer: Analyzer = {
  name: "request-limits",
  section: "32",

  async analyze(context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let counter = 0;

    // 1. Body size limit configurado?
    const bodySizeMatches = await grep(context.project_path, {
      pattern: /(?:bodyParser|body_parser|limit|sizeLimit|bodyLimit|max_body_size|MAX_CONTENT_LENGTH|DATA_UPLOAD_MAX)/i,
      maxMatches: 5,
    });

    // Verificar next.config também
    const nextConfig = await readFileContent(join(context.project_path, "next.config.js"))
      ?? await readFileContent(join(context.project_path, "next.config.mjs"))
      ?? await readFileContent(join(context.project_path, "next.config.ts"));

    const hasBodyLimit = bodySizeMatches.length > 0 || (nextConfig?.includes("sizeLimit") ?? false);

    if (!hasBodyLimit) {
      // Verificar se o projeto tem API routes (senão não é relevante)
      const hasApiRoutes = await grep(context.project_path, {
        pattern: /(?:export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)|app\.(?:get|post|put|patch|delete)|@app\.route|Router)/,
        maxMatches: 1,
      });

      if (hasApiRoutes.length > 0) {
        counter++;
        findings.push({
          id: `SENT-RQL-${String(counter).padStart(3, "0")}`,
          rule_id: "32.1",
          severity: "high",
          category: "request-limits",
          title: "Body size limit não configurado — vulnerável a payloads enormes",
          description: "Sem limite de tamanho de body, um atacante pode enviar payloads de GB para consumir memória do servidor.",
          recommendation: "Configurar body size limit (ex: express.json({ limit: '1mb' }), Next.js bodyParser.sizeLimit, Django DATA_UPLOAD_MAX_MEMORY_SIZE).",
          confidence: "medium",
          detection_method: "deterministic",
        });
      }
    }

    // 2. Request timeout configurado?
    const timeoutMatches = await grep(context.project_path, {
      pattern: /(?:timeout|requestTimeout|server\.timeout|CONN_MAX_AGE|request_timeout)/i,
      extensions: [".ts", ".js", ".py", ".rb", ".json", ".yaml", ".yml"],
      maxMatches: 3,
    });

    if (timeoutMatches.length === 0) {
      counter++;
      findings.push({
        id: `SENT-RQL-${String(counter).padStart(3, "0")}`,
        rule_id: "32.2",
        severity: "medium",
        category: "request-limits",
        title: "Request timeout não configurado explicitamente",
        description: "Sem timeout, requests lentos podem manter conexões abertas indefinidamente, consumindo recursos do servidor.",
        recommendation: "Configurar timeout de request (ex: server.timeout = 30000 em Node.js).",
        confidence: "low",
        detection_method: "deterministic",
      });
    }

    return findings;
  },
};
