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
import { timingAnalyzer } from "./analyzers/timing.js";
import { identityAnalyzer } from "./analyzers/identity.js";
import { mutationsAnalyzer } from "./analyzers/mutations.js";
import { dependenciesAnalyzer } from "./analyzers/dependencies.js";
import { headersAnalyzer } from "./analyzers/headers.js";
import { corsAnalyzer } from "./analyzers/cors.js";
import { testsAnalyzer } from "./analyzers/tests.js";
import { secretsMgmtAnalyzer } from "./analyzers/secrets-mgmt.js";
import { requestLimitsAnalyzer } from "./analyzers/request-limits.js";
import { idorAnalyzer } from "./analyzers/idor.js";
import { massAssignmentAnalyzer } from "./analyzers/mass-assignment.js";
import { errorHandlingAnalyzer } from "./analyzers/error-handling.js";
import { uploadsAnalyzer } from "./analyzers/uploads.js";
import { ssrfAnalyzer } from "./analyzers/ssrf.js";
import { redirectsAnalyzer } from "./analyzers/redirects.js";
import { rateLimitingAnalyzer } from "./analyzers/rate-limiting.js";
import { authAnalyzer } from "./analyzers/auth.js";
import { webhooksAnalyzer } from "./analyzers/webhooks.js";
import { inputValidationAnalyzer } from "./analyzers/input-validation.js";
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
  // M2 — Grep puro
  secretsAnalyzer,
  xssAnalyzer,
  deserializationAnalyzer,
  loggingAnalyzer,
  errorMessagesAnalyzer,
  timingAnalyzer,
  identityAnalyzer,
  mutationsAnalyzer,
  // M3 — Filesystem + Config
  dependenciesAnalyzer,
  headersAnalyzer,
  corsAnalyzer,
  testsAnalyzer,
  secretsMgmtAnalyzer,
  requestLimitsAnalyzer,
  // M4 — AST + Advanced
  idorAnalyzer,
  massAssignmentAnalyzer,
  errorHandlingAnalyzer,
  uploadsAnalyzer,
  ssrfAnalyzer,
  redirectsAnalyzer,
  rateLimitingAnalyzer,
  authAnalyzer,
  webhooksAnalyzer,
  inputValidationAnalyzer,
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
