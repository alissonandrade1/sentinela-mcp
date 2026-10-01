/**
 * Sentinela — Smoke Test
 *
 * Roda o audit completo contra o fixture vulnerável e testa M5/M6.
 * Uso: npx tsx tests/smoke.ts
 */

import { resolve } from "node:path";
import { detectStack } from "../src/analyzers/detect-stack.js";
import { secretsAnalyzer } from "../src/analyzers/secrets.js";
import { xssAnalyzer } from "../src/analyzers/xss.js";
import { deserializationAnalyzer } from "../src/analyzers/deserialization.js";
import { loggingAnalyzer } from "../src/analyzers/logging.js";
import { errorMessagesAnalyzer } from "../src/analyzers/error-messages.js";
import { timingAnalyzer } from "../src/analyzers/timing.js";
import { identityAnalyzer } from "../src/analyzers/identity.js";
import { mutationsAnalyzer } from "../src/analyzers/mutations.js";
import { dependenciesAnalyzer } from "../src/analyzers/dependencies.js";
import { headersAnalyzer } from "../src/analyzers/headers.js";
import { corsAnalyzer } from "../src/analyzers/cors.js";
import { testsAnalyzer } from "../src/analyzers/tests.js";
import { secretsMgmtAnalyzer } from "../src/analyzers/secrets-mgmt.js";
import { requestLimitsAnalyzer } from "../src/analyzers/request-limits.js";
import { idorAnalyzer } from "../src/analyzers/idor.js";
import { massAssignmentAnalyzer } from "../src/analyzers/mass-assignment.js";
import { errorHandlingAnalyzer } from "../src/analyzers/error-handling.js";
import { uploadsAnalyzer } from "../src/analyzers/uploads.js";
import { ssrfAnalyzer } from "../src/analyzers/ssrf.js";
import { redirectsAnalyzer } from "../src/analyzers/redirects.js";
import { rateLimitingAnalyzer } from "../src/analyzers/rate-limiting.js";
import { authAnalyzer } from "../src/analyzers/auth.js";
import { webhooksAnalyzer } from "../src/analyzers/webhooks.js";
import { inputValidationAnalyzer } from "../src/analyzers/input-validation.js";
import { calculateScore, summarizeFindings } from "../src/core/scoring.js";
import { generateMarkdownReport, generateChecklist, compareReports } from "../src/core/report.js";
import { searchRules, getRuleContent } from "../src/core/rules.js";
import { suggestFix } from "../src/core/fix-suggester.js";
import type { Analyzer, AuditReport, Finding } from "../src/core/types.js";

const FIXTURE_PATH = resolve(import.meta.dirname!, "fixtures/vulnerable-nextjs");

const analyzers: Analyzer[] = [
  // M2
  secretsAnalyzer,
  xssAnalyzer,
  deserializationAnalyzer,
  loggingAnalyzer,
  errorMessagesAnalyzer,
  timingAnalyzer,
  identityAnalyzer,
  mutationsAnalyzer,
  // M3
  dependenciesAnalyzer,
  headersAnalyzer,
  corsAnalyzer,
  testsAnalyzer,
  secretsMgmtAnalyzer,
  requestLimitsAnalyzer,
  // M4
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

async function main() {
  console.log("═══════════════════════════════════════════════════════════");
  console.log("  🛡️  SENTINELA — Smoke Test (24 Analyzers + M5/M6)");
  console.log("═══════════════════════════════════════════════════════════");
  console.log(`\n📁 Projeto: ${FIXTURE_PATH}\n`);

  // 1. Detectar stack
  console.log("📋 1. Detectando stack...");
  const stack = await detectStack(FIXTURE_PATH);
  console.log(`  Linguagem: ${stack.language} | Framework: ${stack.framework} | Banco: ${stack.database}`);

  // 2. Rodar analyzers
  console.log(`\n🔍 2. Executando ${analyzers.length} analyzers...`);
  const allFindings: Finding[] = [];

  for (const analyzer of analyzers) {
    const start = Date.now();
    const findings = await analyzer.analyze({ project_path: FIXTURE_PATH, stack });
    const elapsed = Date.now() - start;
    console.log(`  ✓ ${analyzer.name.padEnd(20)} (seção ${analyzer.section.padEnd(2)}): ${findings.length.toString().padStart(2)} findings [${elapsed}ms]`);
    allFindings.push(...findings);
  }

  // 3. Resumo & Score
  const summary = summarizeFindings(allFindings);
  const score = calculateScore(allFindings);
  const checklist = generateChecklist(allFindings);

  console.log("\n═══════════════════════════════════════════════════════════");
  console.log("  📊 3. RESULTADO DA AUDITORIA");
  console.log("═══════════════════════════════════════════════════════════");
  console.log(`\n  Score: ${score}/100`);
  console.log(`  Total: ${summary.total} (🔴 ${summary.critical} | 🟠 ${summary.high} | 🟡 ${summary.medium} | 🔵 ${summary.low})`);
  console.log(`  Checklist: ${checklist.filter(c => c.status === "pass").length} pass / ${checklist.filter(c => c.status === "fail").length} fail`);

  // 4. Testar M5 — Rules
  console.log("\n═══════════════════════════════════════════════════════════");
  console.log("  📚 4. TESTE M5 — RULES ENGINE");
  console.log("═══════════════════════════════════════════════════════════");
  const xssRules = searchRules("xss");
  console.log(`  Busca por 'xss': ${xssRules.length} resultado(s) -> Seção ${xssRules[0]?.section}: ${xssRules[0]?.title}`);
  const ruleContent = await getRuleContent("18");
  console.log(`  Conteúdo Seção 18 (XSS): ${ruleContent ? `${ruleContent.substring(0, 80)}...` : "Não encontrado"}`);

  // 5. Testar M5 — Markdown Report & Diff
  console.log("\n═══════════════════════════════════════════════════════════");
  console.log("  📄 5. TESTE M5 — REPORT & DIFF");
  console.log("═══════════════════════════════════════════════════════════");
  const report: AuditReport = {
    project: { name: "vulnerable-nextjs", path: FIXTURE_PATH, stack },
    timestamp: new Date().toISOString(),
    duration_ms: 120,
    summary,
    findings: allFindings,
    checklist,
    score,
  };
  const markdown = generateMarkdownReport(report);
  console.log(`  Relatório Markdown gerado: ${markdown.length} caracteres`);

  // Testar diff (simulando 1 finding corrigido)
  const reportAfter: AuditReport = {
    ...report,
    findings: allFindings.slice(1), // remove o primeiro
    score: Math.min(100, score + 10),
  };
  const diff = compareReports(report, reportAfter);
  console.log(`  Diff: ${diff.summary}`);

  // 6. Testar M6 — Fix Suggester
  console.log("\n═══════════════════════════════════════════════════════════");
  console.log("  💡 6. TESTE M6 — FIX SUGGESTER");
  console.log("═══════════════════════════════════════════════════════════");
  const sampleFinding = allFindings.find(f => f.category === "secrets") ?? allFindings[0];
  if (sampleFinding) {
    const fix = suggestFix(sampleFinding, stack);
    console.log(`  Sugestão para [${sampleFinding.id} - ${sampleFinding.category}]:`);
    console.log(`  Descrição: ${fix.description}`);
    if (fix.code) {
      console.log(`  Exemplo de código:\n${fix.code.split("\n").map(l => "    " + l).slice(0, 6).join("\n")}...`);
    }
  }

  console.log("\n═══════════════════════════════════════════════════════════");
  console.log(`  ✅ Todos os 24 analyzers + M5 + M6 executados com sucesso!`);
  console.log("═══════════════════════════════════════════════════════════\n");
}

main().catch(console.error);
