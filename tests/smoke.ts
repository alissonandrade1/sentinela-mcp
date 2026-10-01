/**
 * Sentinela — Smoke Test
 *
 * Roda o audit completo contra o fixture vulnerável e imprime os resultados.
 * Uso: npx tsx tests/smoke.ts
 */

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
import { calculateScore, summarizeFindings } from "../src/core/scoring.js";
import { resolve } from "node:path";
import type { Analyzer, Finding } from "../src/core/types.js";

const FIXTURE_PATH = resolve(import.meta.dirname!, "fixtures/vulnerable-nextjs");

const analyzers: Analyzer[] = [
  secretsAnalyzer,
  xssAnalyzer,
  deserializationAnalyzer,
  loggingAnalyzer,
  errorMessagesAnalyzer,
  timingAnalyzer,
  identityAnalyzer,
  mutationsAnalyzer,
  dependenciesAnalyzer,
  headersAnalyzer,
  corsAnalyzer,
  testsAnalyzer,
  secretsMgmtAnalyzer,
  requestLimitsAnalyzer,
];

async function main() {
  console.log("═══════════════════════════════════════════════════════════");
  console.log("  🛡️  SENTINELA — Smoke Test");
  console.log("═══════════════════════════════════════════════════════════");
  console.log(`\n📁 Projeto: ${FIXTURE_PATH}\n`);

  // 1. Detectar stack
  console.log("📋 Detectando stack...\n");
  const stack = await detectStack(FIXTURE_PATH);
  console.log("  Linguagem:  ", stack.language);
  console.log("  Framework:  ", stack.framework);
  console.log("  ORM:        ", stack.orm ?? "—");
  console.log("  Banco:      ", stack.database);
  console.log("  SQL Dialect:", stack.sql_dialect);
  console.log("  Auth:       ", stack.auth_provider ?? "—");
  console.log("  Hosting:    ", stack.hosting ?? "—");

  // 2. Rodar analyzers
  console.log("\n🔍 Executando analyzers...\n");
  const allFindings: Finding[] = [];

  for (const analyzer of analyzers) {
    const start = Date.now();
    const findings = await analyzer.analyze({ project_path: FIXTURE_PATH, stack });
    const elapsed = Date.now() - start;
    console.log(`  ✓ ${analyzer.name} (seção ${analyzer.section}): ${findings.length} findings [${elapsed}ms]`);
    allFindings.push(...findings);
  }

  // 3. Resumo
  const summary = summarizeFindings(allFindings);
  const score = calculateScore(allFindings);

  console.log("\n═══════════════════════════════════════════════════════════");
  console.log("  📊 RESULTADO");
  console.log("═══════════════════════════════════════════════════════════");
  console.log(`\n  Score: ${score}/100\n`);
  console.log(`  Total:    ${summary.total}`);
  console.log(`  🔴 Crítica: ${summary.critical}`);
  console.log(`  🟠 Alta:    ${summary.high}`);
  console.log(`  🟡 Média:   ${summary.medium}`);
  console.log(`  🔵 Baixa:   ${summary.low}`);
  console.log(`\n  Por categoria:`);
  for (const [cat, count] of Object.entries(summary.by_category)) {
    console.log(`    ${cat}: ${count}`);
  }

  // 4. Listar findings
  console.log("\n═══════════════════════════════════════════════════════════");
  console.log("  🔎 FINDINGS DETALHADOS");
  console.log("═══════════════════════════════════════════════════════════\n");

  const severityIcon: Record<string, string> = {
    critical: "🔴",
    high: "🟠",
    medium: "🟡",
    low: "🔵",
  };

  for (const f of allFindings) {
    const icon = severityIcon[f.severity] ?? "⚪";
    console.log(`${icon} ${f.id} [${f.severity.toUpperCase()}] — ${f.title}`);
    if (f.file) console.log(`   📄 ${f.file}${f.line ? `:${f.line}` : ""}`);
    if (f.evidence) console.log(`   💡 ${f.evidence.trim().substring(0, 100)}`);
    console.log(`   🔧 ${f.recommendation}`);
    if (f.cwe) console.log(`   📚 ${f.cwe} | ${f.owasp ?? ""}`);
    console.log("");
  }

  console.log("═══════════════════════════════════════════════════════════");
  console.log(`  ✅ Teste concluído — ${allFindings.length} vulnerabilidades encontradas`);
  console.log("═══════════════════════════════════════════════════════════\n");
}

main().catch(console.error);
