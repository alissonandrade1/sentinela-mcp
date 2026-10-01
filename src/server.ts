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
import { searchRules, listAllRules, getRuleContent } from "./core/rules.js";
import { generateMarkdownReport, compareReports, generateChecklist } from "./core/report.js";
import { suggestFix } from "./core/fix-suggester.js";
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
// Helper: run full audit
// ============================================================================

async function runFullAudit(projectPath: string): Promise<AuditReport> {
  const startTime = Date.now();
  const stack = await detectStack(projectPath);
  const context: AnalyzerContext = { project_path: projectPath, stack };

  const allFindings: Finding[] = [];
  for (const analyzer of analyzers) {
    try {
      const findings = await analyzer.analyze(context);
      allFindings.push(...findings);
    } catch (err) {
      console.error(`[sentinela] Analyzer ${analyzer.name} failed:`, err);
    }
  }

  return {
    project: {
      name: projectPath.split(/[\\/]/).pop() ?? "unknown",
      path: projectPath,
      stack,
    },
    timestamp: new Date().toISOString(),
    duration_ms: Date.now() - startTime,
    summary: summarizeFindings(allFindings),
    findings: allFindings,
    checklist: generateChecklist(allFindings),
    score: calculateScore(allFindings),
  };
}

// ============================================================================
// Tools — Audit
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
    const report = await runFullAudit(project_path);
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
// Tools — Rules & Checklist (M5)
// ============================================================================

// --- sentinela_get_rules ---
server.tool(
  "sentinela_get_rules",
  "Consulta regras de segurança por categoria ou termo. Retorna seções relevantes do knowledge base.",
  {
    query: z.string().describe("Categoria, seção ou termo para buscar (ex: 'xss', 'auth', 'cors', '13')"),
    include_content: z.boolean().optional().describe("Se verdadeiro, inclui o texto explicativo da regra extraído do knowledge base"),
  },
  async ({ query, include_content }) => {
    const results = query === "all" ? listAllRules() : searchRules(query);
    if (include_content && results.length > 0) {
      const detailed = await Promise.all(
        results.slice(0, 5).map(async (r) => ({
          ...r,
          content: await getRuleContent(r.section),
        })),
      );
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            query,
            total: results.length,
            rules: detailed,
          }, null, 2),
        }],
      };
    }

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          query,
          total: results.length,
          rules: results,
        }, null, 2),
      }],
    };
  },
);

// --- sentinela_get_checklist ---
server.tool(
  "sentinela_get_checklist",
  "Retorna checklist de segurança com status pass/fail baseado nos findings do último audit.",
  { project_path: z.string().describe("Caminho absoluto para o diretório raiz do projeto") },
  async ({ project_path }) => {
    const report = await runFullAudit(project_path);
    const checklist = generateChecklist(report.findings);

    const passed = checklist.filter((c) => c.status === "pass").length;
    const failed = checklist.filter((c) => c.status === "fail").length;

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          score: report.score,
          passed,
          failed,
          total: checklist.length,
          checklist,
        }, null, 2),
      }],
    };
  },
);

// ============================================================================
// Tools — Reports (M5)
// ============================================================================

// --- sentinela_generate_report ---
server.tool(
  "sentinela_generate_report",
  "Gera relatório de segurança em Markdown a partir de uma auditoria completa.",
  { project_path: z.string().describe("Caminho absoluto para o diretório raiz do projeto") },
  async ({ project_path }) => {
    const report = await runFullAudit(project_path);
    const markdown = generateMarkdownReport(report);
    return {
      content: [{ type: "text" as const, text: markdown }],
    };
  },
);

// --- sentinela_compare_reports ---
server.tool(
  "sentinela_compare_reports",
  "Compara dois AuditReports (antes vs depois). Mostra findings novos, resolvidos e evolução do score.",
  {
    report_before: z.string().describe("JSON string do AuditReport anterior"),
    report_after: z.string().describe("JSON string do AuditReport atual"),
  },
  async ({ report_before, report_after }) => {
    const before = JSON.parse(report_before) as AuditReport;
    const after = JSON.parse(report_after) as AuditReport;
    const diff = compareReports(before, after);

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify(diff, null, 2),
      }],
    };
  },
);

// ============================================================================
// Tools — Fix & Validate (M6)
// ============================================================================

// --- sentinela_suggest_fix ---
server.tool(
  "sentinela_suggest_fix",
  "Dado um finding (JSON), sugere código corrigido com exemplo prático para a stack do projeto.",
  {
    finding: z.string().describe("JSON string do Finding a corrigir"),
    project_path: z.string().describe("Caminho do projeto (para detectar stack)"),
  },
  async ({ finding, project_path }) => {
    const f = JSON.parse(finding) as Finding;
    const stack = await detectStack(project_path);
    const fix = suggestFix(f, stack);

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          finding_id: f.id,
          category: f.category,
          fix,
        }, null, 2),
      }],
    };
  },
);

// --- sentinela_validate_fix ---
server.tool(
  "sentinela_validate_fix",
  "Re-executa o analyzer de um finding específico para verificar se a correção foi aplicada com sucesso.",
  {
    finding_id: z.string().describe("ID do finding a validar (ex: SENT-XSS-001)"),
    category: z.string().describe("Categoria do finding (ex: xss, secrets, idor)"),
    project_path: z.string().describe("Caminho do projeto"),
  },
  async ({ finding_id, category, project_path }) => {
    // Encontrar o analyzer correto
    const analyzer = analyzers.find((a) => a.name === category || a.name === category.replace(/_/g, "-"));
    if (!analyzer) {
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ error: `Analyzer "${category}" não encontrado.` }) }],
      };
    }

    const stack = await detectStack(project_path);
    const context: AnalyzerContext = { project_path, stack };
    const findings = await analyzer.analyze(context);

    const stillExists = findings.some((f) => f.id === finding_id);
    const similarExists = findings.some(
      (f) => f.category === category,
    );

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          finding_id,
          category,
          fixed: !stillExists && !similarExists,
          still_exists: stillExists,
          similar_findings: similarExists ? findings.length : 0,
          message: !stillExists && !similarExists
            ? `✅ Finding ${finding_id} corrigido com sucesso! Nenhum finding similar na categoria.`
            : stillExists
              ? `❌ Finding ${finding_id} ainda presente. A correção não foi aplicada.`
              : `⚠️ Finding ${finding_id} original não encontrado, mas ${findings.length} finding(s) similar(es) na categoria "${category}" ainda existem.`,
        }, null, 2),
      }],
    };
  },
);

// ============================================================================
// Prompts (Slash Commands / MCP Prompts)
// ============================================================================

// --- /audit: Auditoria completa ---
server.prompt(
  "audit",
  "Executa auditoria completa de segurança no projeto e gera relatório detalhado com score",
  {
    project_path: z.string().describe("Caminho absoluto para o diretório raiz do projeto"),
  },
  ({ project_path }) => ({
    description: `Auditoria completa de segurança em: ${project_path}`,
    messages: [
      {
        role: "user" as const,
        content: {
          type: "text" as const,
          text: `Por favor, execute uma auditoria completa de segurança no projeto localizado em "${project_path}".

Siga este procedimento:
1. Chame \`sentinela_detect_stack\` para identificar a stack tecnológica.
2. Execute a auditoria completa com \`sentinela_audit_full\`.
3. Gere o relatório formatado em Markdown com \`sentinela_generate_report\` e apresente o score de segurança, a matriz de checklist e os principais findings com prioridade de correção.`,
        },
      },
    ],
  }),
);

// --- /audit_category: Análise focada em categoria específica ---
server.prompt(
  "audit_category",
  "Executa análise de segurança focada em uma categoria ou vulnerabilidade específica (ex: xss, secrets, auth, idor, ssrf)",
  {
    category: z.string().describe("Categoria ou vulnerabilidade a analisar (ex: secrets, xss, auth, idor, mass-assignment, rate-limiting, ssrf, uploads, cors, headers)"),
    project_path: z.string().describe("Caminho absoluto para o diretório raiz do projeto"),
  },
  ({ category, project_path }) => ({
    description: `Auditoria focada em "${category}" no projeto: ${project_path}`,
    messages: [
      {
        role: "user" as const,
        content: {
          type: "text" as const,
          text: `Por favor, execute uma auditoria de segurança focada especificamente na categoria "${category}" para o projeto em "${project_path}".

Siga este procedimento:
1. Chame \`sentinela_detect_stack\` para entender a stack.
2. Execute o analisador correspondente da categoria (ex: \`sentinela_audit_${category.replace(/-/g, "_")}\`) ou utilize \`sentinela_get_rules\` para entender as diretrizes de segurança aplicáveis.
3. Se houver vulnerabilidades, mostre o arquivo, linha e evidência, e sugira a correção com \`sentinela_suggest_fix\`.`,
        },
      },
    ],
  }),
);

// --- /fix_finding: Correção e validação de vulnerabilidade ---
server.prompt(
  "fix_finding",
  "Orienta a correção de uma vulnerabilidade e valida determinísticamente se o problema foi resolvido",
  {
    finding_id: z.string().describe("ID do finding a ser corrigido (ex: SENT-SEC-001, SENT-XSS-001)"),
    category: z.string().describe("Categoria do finding (ex: secrets, xss, idor, auth)"),
    project_path: z.string().describe("Caminho absoluto para o diretório raiz do projeto"),
  },
  ({ finding_id, category, project_path }) => ({
    description: `Correção e validação do finding ${finding_id} (${category})`,
    messages: [
      {
        role: "user" as const,
        content: {
          type: "text" as const,
          text: `Por favor, ajude a remediar o finding de segurança "${finding_id}" (${category}) no projeto em "${project_path}".

Siga este procedimento:
1. Consulte \`sentinela_suggest_fix\` para obter a sugestão de correção adequada para a stack.
2. Apresente o código antes/depois e aplique a alteração recomendada no arquivo.
3. Após aplicar a alteração, execute \`sentinela_validate_fix\` para confirmar que a vulnerabilidade foi eliminada e não gerou regressões.`,
        },
      },
    ],
  }),
);

// --- /checklist: Matriz de conformidade rápida ---
server.prompt(
  "checklist",
  "Gera a matriz de conformidade com 24 itens de segurança e status pass/fail",
  {
    project_path: z.string().describe("Caminho absoluto para o diretório raiz do projeto"),
  },
  ({ project_path }) => ({
    description: `Checklist de conformidade de segurança para: ${project_path}`,
    messages: [
      {
        role: "user" as const,
        content: {
          type: "text" as const,
          text: `Por favor, verifique o checklist de conformidade de segurança no projeto em "${project_path}" chamando \`sentinela_get_checklist\`.
Apresente uma tabela clara com todos os 24 itens, destacando o percentual de aprovação e os pontos críticos que reprovaram.`,
        },
      },
    ],
  }),
);

// --- /security_rules: Consulta de regras e diretrizes ---
server.prompt(
  "security_rules",
  "Consulta diretrizes arquiteturais de segurança e boas práticas da base de conhecimento",
  {
    topic: z.string().describe("Tema, categoria ou seção a consultar (ex: xss, auth, cors, rate-limiting, 13)"),
  },
  ({ topic }) => ({
    description: `Consulta de regras de segurança sobre: ${topic}`,
    messages: [
      {
        role: "user" as const,
        content: {
          type: "text" as const,
          text: `Por favor, consulte as diretrizes de segurança da base do Sentinela executando \`sentinela_get_rules\` com include_content: true para o tema "${topic}".
Explique os requisitos de segurança, os riscos de implementação e como arquitetar a solução de forma segura.`,
        },
      },
    ],
  }),
);

// ============================================================================
// Start
// ============================================================================

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  const toolCount = analyzers.length + 8; // 24 individual + detect_stack + audit_full + get_rules + get_checklist + generate_report + compare_reports + suggest_fix + validate_fix
  console.error(`[sentinela] MCP server running — ${analyzers.length} analyzers, ${toolCount} tools`);
}

main().catch((error) => {
  console.error("[sentinela] Fatal error:", error);
  process.exit(1);
});
