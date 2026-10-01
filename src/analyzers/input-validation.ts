/**
 * Sentinela — Input Validation Analyzer
 *
 * Detecta ausência de validação de input em rotas de API.
 *
 * Referência: context.md — Seção 3
 * CWE-20: Improper Input Validation
 * OWASP: A03:2021 — Injection
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { grep } from "../core/grep.js";
import { parsePackageJSON, hasDependency } from "../core/config-parser.js";

export const inputValidationAnalyzer: Analyzer = {
  name: "input-validation",
  section: "3",

  async analyze(context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let counter = 0;

    // 1. Verificar se o projeto usa alguma lib de validação
    const pkg = await parsePackageJSON(context.project_path);
    const hasValidationLib = pkg
      ? hasDependency(pkg, "zod") || hasDependency(pkg, "yup") || hasDependency(pkg, "joi")
        || hasDependency(pkg, "class-validator") || hasDependency(pkg, "valibot")
        || hasDependency(pkg, "superstruct") || hasDependency(pkg, "ajv")
      : false;

    // 2. Buscar uso de req.body sem validação
    const directBodyUsage = await grep(context.project_path, {
      pattern: /const\s+\{[^}]+\}\s*=\s*(?:await\s+req\.json\(\)|req\.body|request\.body)/,
      extensions: [".ts", ".tsx", ".js", ".jsx"],
      maxMatches: 30,
    });

    // Para cada uso de req.body, verificar se tem validação próxima
    for (const match of directBodyUsage) {
      if (match.file.includes("test") || match.file.includes("spec")) continue;
      if (match.content.trimStart().startsWith("//")) continue;

      // Se tem validação inline na mesma linha, ok
      if (match.content.includes("parse") || match.content.includes("validate") || match.content.includes("safeParse")) continue;

      counter++;
      findings.push({
        id: `SENT-INP-${String(counter).padStart(3, "0")}`,
        rule_id: "3.1",
        severity: "high",
        category: "input-validation",
        title: "Dados do request usados sem validação de schema",
        description: "Destruturar req.body sem validação permite dados malformados, tipos incorretos, ou campos extras que podem causar bugs ou vulnerabilidades.",
        file: match.file,
        line: match.line,
        evidence: match.content,
        recommendation: hasValidationLib
          ? "Usar schema.parse(body) antes de processar dados. Ex: const data = mySchema.parse(await req.json())"
          : "Instalar biblioteca de validação (zod, yup, joi) e validar todo input de API.",
        confidence: "medium",
        detection_method: "deterministic",
        cwe: "CWE-20",
        owasp: "A03:2021",
      });
    }

    // 3. Se o projeto tem muitas rotas mas nenhuma lib de validação
    if (!hasValidationLib) {
      const apiRoutes = await grep(context.project_path, {
        pattern: /export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)/,
        extensions: [".ts", ".tsx", ".js", ".jsx"],
        maxMatches: 5,
      });

      if (apiRoutes.length >= 2) {
        counter++;
        findings.push({
          id: `SENT-INP-${String(counter).padStart(3, "0")}`,
          rule_id: "3.2",
          severity: "high",
          category: "input-validation",
          title: "Nenhuma biblioteca de validação de input instalada",
          description: `Projeto tem ${apiRoutes.length}+ rotas de API mas nenhuma lib de validação (zod, yup, joi, etc.). Todo input do usuário deve ser validado com schema.`,
          recommendation: "Instalar zod (recomendado): npm install zod. Criar schemas para cada rota.",
          confidence: "high",
          detection_method: "deterministic",
          cwe: "CWE-20",
          owasp: "A03:2021",
        });
      }
    }

    return findings;
  },
};
