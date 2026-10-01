/**
 * Sentinela — Security Tests Analyzer
 *
 * Verifica existência de testes de segurança no projeto.
 *
 * Referência: context.md — Seção 14
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { findFiles, isDirectory } from "../core/filesystem.js";
import { join } from "node:path";

export const testsAnalyzer: Analyzer = {
  name: "tests",
  section: "14",

  async analyze(context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let counter = 0;

    // 1. Diretório tests/security existe?
    const hasSecurityTests =
      await isDirectory(join(context.project_path, "tests/security")) ||
      await isDirectory(join(context.project_path, "test/security")) ||
      await isDirectory(join(context.project_path, "__tests__/security"));

    if (!hasSecurityTests) {
      // Verificar se ao menos existem arquivos de teste com "security" no nome
      const securityTestFiles = await findFiles(context.project_path, {
        names: [
          "security.test.ts", "security.test.js", "security.spec.ts", "security.spec.js",
          "auth.test.ts", "auth.test.js", "auth.spec.ts", "auth.spec.js",
          "test_security.py", "test_auth.py",
        ],
        maxResults: 5,
      });

      if (securityTestFiles.length === 0) {
        counter++;
        findings.push({
          id: `SENT-TST-${String(counter).padStart(3, "0")}`,
          rule_id: "14.1",
          severity: "medium",
          category: "tests",
          title: "Nenhum teste de segurança encontrado",
          description: "O projeto não possui diretório tests/security/ nem arquivos de teste de segurança. Vulnerabilidades podem ser introduzidas sem detecção.",
          recommendation: "Criar diretório tests/security/ com testes para: IDOR, SQL injection, XSS, auth bypass, rate limiting.",
          confidence: "high",
          detection_method: "deterministic",
        });
      }
    }

    // 2. Verificar se existe algum teste no projeto
    const anyTests = await findFiles(context.project_path, {
      extensions: [".test.ts", ".test.js", ".spec.ts", ".spec.js"],
      maxResults: 1,
    });
    const anyPyTests = await findFiles(context.project_path, {
      names: ["test_*.py", "conftest.py"],
      maxResults: 1,
    });

    if (anyTests.length === 0 && anyPyTests.length === 0) {
      counter++;
      findings.push({
        id: `SENT-TST-${String(counter).padStart(3, "0")}`,
        rule_id: "14.2",
        severity: "medium",
        category: "tests",
        title: "Nenhum teste encontrado no projeto",
        description: "O projeto não possui nenhum arquivo de teste. Mudanças em código de segurança não são validadas automaticamente.",
        recommendation: "Configurar framework de testes (vitest, jest, pytest) e criar testes mínimos para autenticação e autorização.",
        confidence: "high",
        detection_method: "deterministic",
      });
    }

    return findings;
  },
};
