/**
 * Sentinela — Secrets Management Analyzer
 *
 * Verifica boas práticas de gerenciamento de secrets.
 *
 * Referência: context.md — Seção 26
 * CWE-798: Use of Hard-coded Credentials
 * OWASP: A07:2021 — Identification and Authentication Failures
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { fileExists } from "../core/filesystem.js";
import { parseEnvFile } from "../core/config-parser.js";
import { grep } from "../core/grep.js";
import { join } from "node:path";

export const secretsMgmtAnalyzer: Analyzer = {
  name: "secrets-mgmt",
  section: "26",

  async analyze(context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let counter = 0;

    // 1. .env.example existe?
    const hasEnvExample = await fileExists(join(context.project_path, ".env.example"));
    const hasEnv = await fileExists(join(context.project_path, ".env"));

    if (hasEnv && !hasEnvExample) {
      counter++;
      findings.push({
        id: `SENT-SMG-${String(counter).padStart(3, "0")}`,
        rule_id: "26.1",
        severity: "medium",
        category: "secrets-mgmt",
        title: ".env existe mas .env.example ausente",
        description: "Sem .env.example, novos devs não sabem quais variáveis de ambiente são necessárias.",
        recommendation: "Criar .env.example com todas as chaves necessárias (sem valores reais).",
        confidence: "high",
        detection_method: "deterministic",
        cwe: "CWE-798",
        owasp: "A07:2021",
      });
    }

    // 2. .env.example com valores reais?
    if (hasEnvExample) {
      const envExample = await parseEnvFile(join(context.project_path, ".env.example"));
      const suspiciousValues = Object.entries(envExample).filter(([_key, value]) => {
        if (!value || value === '""' || value === "''") return false;
        if (value.startsWith("your_") || value.startsWith("xxx") || value === "changeme") return false;
        // Verificar se parece um valor real
        if (value.length > 20 && /[a-zA-Z0-9]{20,}/.test(value)) return true;
        if (value.includes("://") && value.includes("@")) return true; // connection string
        return false;
      });

      for (const [key] of suspiciousValues) {
        counter++;
        findings.push({
          id: `SENT-SMG-${String(counter).padStart(3, "0")}`,
          rule_id: "26.2",
          severity: "critical",
          category: "secrets-mgmt",
          title: `.env.example pode conter valor real para "${key}"`,
          description: ".env.example é commitado ao git. Valores reais nele expõem credenciais.",
          file: ".env.example",
          recommendation: `Substituir valor de "${key}" por placeholder (ex: your_${key.toLowerCase()}_here).`,
          confidence: "medium",
          detection_method: "heuristic",
          cwe: "CWE-798",
          owasp: "A07:2021",
        });
      }
    }

    // 3. Validação de env vars na inicialização?
    const envCheckMatches = await grep(context.project_path, {
      pattern: /(?:process\.env\.\w+|os\.environ|ENV\[)/,
      extensions: [".ts", ".js", ".py", ".rb"],
      maxMatches: 1,
    });

    if (envCheckMatches.length > 0) {
      // Projeto usa env vars — verifica se tem validação na startup
      const hasEnvCheck = await grep(context.project_path, {
        pattern: /(?:if\s*\(\s*!process\.env\.|required.*env|env.*required|z\.string\(\).*env|envalid|env-var|dotenv.*config)/i,
        maxMatches: 1,
      });

      if (hasEnvCheck.length === 0) {
        counter++;
        findings.push({
          id: `SENT-SMG-${String(counter).padStart(3, "0")}`,
          rule_id: "26.3",
          severity: "medium",
          category: "secrets-mgmt",
          title: "Variáveis de ambiente usadas sem validação na inicialização",
          description: "O projeto usa process.env mas não valida se todas as vars necessárias estão presentes na startup. Pode crashar em produção.",
          recommendation: "Criar arquivo env-check.ts que valida todas as env vars obrigatórias na inicialização (com z.string() ou envalid).",
          confidence: "medium",
          detection_method: "heuristic",
        });
      }
    }

    return findings;
  },
};
