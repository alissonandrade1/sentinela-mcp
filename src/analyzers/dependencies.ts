/**
 * Sentinela — Dependencies Analyzer
 *
 * Verifica segurança de dependências: lock files, CVEs, configs de atualização.
 *
 * Referência: context.md — Seção 21
 * CWE-1104: Use of Unmaintained Third-Party Components
 * OWASP: A06:2021 — Vulnerable and Outdated Components
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { fileExists } from "../core/filesystem.js";
import { parsePackageJSON } from "../core/config-parser.js";
import { join } from "node:path";

export const dependenciesAnalyzer: Analyzer = {
  name: "dependencies",
  section: "21",

  async analyze(context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let counter = 0;

    // 1. Lock file existe?
    const hasPackageLock = await fileExists(join(context.project_path, "package-lock.json"));
    const hasYarnLock = await fileExists(join(context.project_path, "yarn.lock"));
    const hasPnpmLock = await fileExists(join(context.project_path, "pnpm-lock.yaml"));
    const hasPipLock = await fileExists(join(context.project_path, "Pipfile.lock"));
    const hasPoetryLock = await fileExists(join(context.project_path, "poetry.lock"));
    const hasGemLock = await fileExists(join(context.project_path, "Gemfile.lock"));

    const hasAnyLock = hasPackageLock || hasYarnLock || hasPnpmLock || hasPipLock || hasPoetryLock || hasGemLock;

    const hasPkg = await fileExists(join(context.project_path, "package.json"));
    const hasRequirements = await fileExists(join(context.project_path, "requirements.txt"));
    const hasGemfile = await fileExists(join(context.project_path, "Gemfile"));

    if ((hasPkg || hasRequirements || hasGemfile) && !hasAnyLock) {
      counter++;
      findings.push({
        id: `SENT-DEP-${String(counter).padStart(3, "0")}`,
        rule_id: "21.1",
        severity: "high",
        category: "dependencies",
        title: "Lock file ausente — versões de dependências não são fixas",
        description: "Sem lock file, cada instalação pode trazer versões diferentes de dependências, incluindo versões comprometidas.",
        recommendation: "Rodar npm install / yarn install / pip freeze e commitar o lock file.",
        confidence: "high",
        detection_method: "deterministic",
        cwe: "CWE-1104",
        owasp: "A06:2021",
      });
    }

    // 2. Dependabot ou Renovate configurado?
    const hasDependabot = await fileExists(join(context.project_path, ".github/dependabot.yml"));
    const hasDependabotYaml = await fileExists(join(context.project_path, ".github/dependabot.yaml"));
    const hasRenovate = await fileExists(join(context.project_path, "renovate.json"));
    const hasRenovateJson5 = await fileExists(join(context.project_path, "renovate.json5"));
    const hasRenovateConfig = await fileExists(join(context.project_path, ".renovaterc"));

    if (!hasDependabot && !hasDependabotYaml && !hasRenovate && !hasRenovateJson5 && !hasRenovateConfig) {
      counter++;
      findings.push({
        id: `SENT-DEP-${String(counter).padStart(3, "0")}`,
        rule_id: "21.2",
        severity: "medium",
        category: "dependencies",
        title: "Nenhum bot de atualização de dependências configurado",
        description: "Sem Dependabot ou Renovate, vulnerabilidades em dependências não são detectadas automaticamente.",
        recommendation: "Configurar .github/dependabot.yml ou renovate.json para receber PRs automáticos de atualização.",
        confidence: "high",
        detection_method: "deterministic",
        cwe: "CWE-1104",
        owasp: "A06:2021",
      });
    }

    // 3. Verificar versões wildcard em package.json
    const pkg = await parsePackageJSON(context.project_path);
    if (pkg?.dependencies) {
      for (const [name, version] of Object.entries(pkg.dependencies)) {
        if (version === "*" || version === "latest") {
          counter++;
          findings.push({
            id: `SENT-DEP-${String(counter).padStart(3, "0")}`,
            rule_id: "21.3",
            severity: "high",
            category: "dependencies",
            title: `Dependência "${name}" com versão wildcard ("${version}")`,
            description: "Versões wildcard ou 'latest' podem instalar qualquer versão, incluindo versões comprometidas.",
            file: "package.json",
            recommendation: `Fixar versão específica: "${name}": "^x.y.z"`,
            confidence: "high",
            detection_method: "deterministic",
            cwe: "CWE-1104",
            owasp: "A06:2021",
          });
        }
      }
    }

    return findings;
  },
};
