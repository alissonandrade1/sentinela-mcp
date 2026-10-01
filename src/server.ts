/**
 * Sentinela MCP Server — Entry Point
 *
 * Infraestrutura de segurança para agentes de IA.
 * Este servidor expõe ferramentas de auditoria de segurança via MCP.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { detectStack } from "./analyzers/detect-stack.js";
import { secretsAnalyzer } from "./analyzers/secrets.js";
import { xssAnalyzer } from "./analyzers/xss.js";
import { deserializationAnalyzer } from "./analyzers/deserialization.js";
import { loggingAnalyzer } from "./analyzers/logging.js";
import { errorMessagesAnalyzer } from "./analyzers/error-messages.js";
import { calculateScore, summarizeFindings } from "./core/scoring.js";
import type { Analyzer, AnalyzerContext, AuditReport, Finding } from "./core/types.js";

// ============================================================================
// Server Setup
// ============================================================================

const server = new McpServer({
  name: "sentinela",
  version: "0.1.0",
});

// ============================================================================
// Analyzer Registry
// ============================================================================

const analyzers: Analyzer[] = [
  secretsAnalyzer,
  xssAnalyzer,
  deserializationAnalyzer,
  loggingAnalyzer,
  errorMessagesAnalyzer,
];

// ============================================================================
// Tools
// ============================================================================

// --- sentinela_detect_stack ---
server.tool(
  "sentinela_detect_stack",
  "Detecta a stack de um projeto: linguagem, framework, ORM, banco de dados, auth provider, hosting.",
  { project_path: z.string().describe("Caminho absoluto para o diretório raiz do projeto") },
  async ({ project_path }) => {
    const stack = await detectStack(project_path);
    return {
      content: [{ type: "text" as const, text: JSON.stringify(stack, null, 2) }],
    };
  },
);

// --- sentinela_audit_full ---
server.tool(
  "sentinela_audit_full",
  "Executa auditoria completa de segurança no projeto. Retorna AuditReport com todos os findings, score e checklist.",
  { project_path: z.string().describe("Caminho absoluto para o diretório raiz do projeto") },
  async ({ project_path }) => {
    const startTime = Date.now();
    const stack = await detectStack(project_path);

    const context: AnalyzerContext = {
      project_path,
      stack,
    };

    // Executar todos os analyzers
    const allFindings: Finding[] = [];
    for (const analyzer of analyzers) {
      try {
        const findings = await analyzer.analyze(context);
        allFindings.push(...findings);
      } catch (err) {
        console.error(`[sentinela] Analyzer ${analyzer.name} failed:`, err);
      }
    }

    const report: AuditReport = {
      project: {
        name: project_path.split(/[\\/]/).pop() ?? "unknown",
        path: project_path,
        stack,
      },
      timestamp: new Date().toISOString(),
      duration_ms: Date.now() - startTime,
      summary: summarizeFindings(allFindings),
      findings: allFindings,
      checklist: [],
      score: calculateScore(allFindings),
    };

    return {
      content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }],
    };
  },
);

// --- Tools individuais por domínio ---
for (const analyzer of analyzers) {
  const toolName = `sentinela_audit_${analyzer.name.replace(/-/g, "_")}`;
  const toolDesc = `Audita o domínio "${analyzer.name}" (Seção ${analyzer.section}). Retorna findings estruturados.`;

  server.tool(
    toolName,
    toolDesc,
    { project_path: z.string().describe("Caminho absoluto para o diretório raiz do projeto") },
    async ({ project_path }) => {
      const stack = await detectStack(project_path);
      const context: AnalyzerContext = { project_path, stack };
      const findings = await analyzer.analyze(context);

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            analyzer: analyzer.name,
            section: analyzer.section,
            total: findings.length,
            findings,
          }, null, 2),
        }],
      };
    },
  );
}

// ============================================================================
// Start
// ============================================================================

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`[sentinela] MCP server running — ${analyzers.length} analyzers loaded`);
}

main().catch((error) => {
  console.error("[sentinela] Fatal error:", error);
  process.exit(1);
});
