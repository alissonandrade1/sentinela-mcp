/**
 * Sentinela MCP Server — Entry Point
 *
 * Infraestrutura de segurança para agentes de IA.
 * Este servidor expõe ferramentas de auditoria de segurança via MCP.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new McpServer({
  name: "sentinela",
  version: "0.1.0",
});

// TODO: Registrar ferramentas MCP
// - sentinela_detect_stack
// - sentinela_audit_full
// - sentinela_audit_{domain}
// - sentinela_get_rules
// - sentinela_get_checklist
// - sentinela_suggest_fix
// - sentinela_validate_fix
// - sentinela_generate_report
// - sentinela_compare_reports

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[sentinela] MCP server running on stdio");
}

main().catch((error) => {
  console.error("[sentinela] Fatal error:", error);
  process.exit(1);
});
