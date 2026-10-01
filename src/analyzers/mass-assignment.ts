/**
 * Sentinela — Mass Assignment Analyzer
 *
 * Detecta spread de req.body direto em queries/models (mass assignment).
 *
 * Referência: context.md — Seção 20
 * CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
 * OWASP: A08:2021 — Software and Data Integrity Failures
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { grepMulti } from "../core/grep.js";

const PATTERNS = [
  {
    id: "spread-req-body",
    pattern: /\.(?:create|insert|update|upsert)\s*\(\s*\{[^}]*\.\.\.(?:req\.body|body|data)/,
    title: "Spread de req.body direto em operação de banco — mass assignment",
    severity: "critical" as const,
  },
  {
    id: "spread-into-query",
    pattern: /(?:data|values|set)\s*:\s*\{?\s*\.\.\.(?:req\.body|body|request\.body)/,
    title: "Spread de body em data/values de query — mass assignment",
    severity: "critical" as const,
  },
  {
    id: "model-create-body",
    pattern: /(?:Model|model)\.\s*create\s*\(\s*(?:req\.body|body|request\.body)\s*\)/,
    title: "Model.create(req.body) — todas as propriedades aceitas sem filtro",
    severity: "critical" as const,
  },
  {
    id: "object-assign-body",
    pattern: /Object\.assign\s*\(\s*\w+\s*,\s*(?:req\.body|body|request\.body)\s*\)/,
    title: "Object.assign com req.body — sobrescreve todas as propriedades",
    severity: "critical" as const,
  },
  {
    id: "django-form-no-fields",
    pattern: /class\s+\w+Form\s*\(.*?\)[\s\S]*?fields\s*=\s*["']__all__["']/,
    title: "Django Form com fields = '__all__' — aceita todos os campos",
    severity: "high" as const,
  },
  {
    id: "django-exclude-only",
    pattern: /class\s+\w+Serializer\s*\(.*?\)[\s\S]*?exclude\s*=/,
    title: "Django Serializer com exclude — melhor usar fields explícito",
    severity: "medium" as const,
  },
  {
    id: "rails-permit-all",
    pattern: /\.permit!\s*$/,
    title: "Rails params.permit! — permite todos os parâmetros (mass assignment)",
    severity: "critical" as const,
  },
];

export const massAssignmentAnalyzer: Analyzer = {
  name: "mass-assignment",
  section: "20",

  async analyze(context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let counter = 0;

    const grepPatterns = PATTERNS.map((p) => ({ id: p.id, pattern: p.pattern }));
    const results = await grepMulti(context.project_path, grepPatterns, {
      extensions: [".ts", ".tsx", ".js", ".jsx", ".py", ".rb", ".php", ".java", ".cs", ".go"],
    });

    for (const pat of PATTERNS) {
      const matches = results.get(pat.id) ?? [];
      for (const match of matches) {
        if (match.file.includes("test") || match.file.includes("spec") || match.file.includes("migration")) continue;
        if (match.content.trimStart().startsWith("//") || match.content.trimStart().startsWith("#")) continue;

        counter++;
        findings.push({
          id: `SENT-MAS-${String(counter).padStart(3, "0")}`,
          rule_id: "20.1",
          severity: pat.severity,
          category: "mass-assignment",
          title: pat.title,
          description: "Mass assignment permite que um atacante envie campos extras no body (ex: role: 'admin', is_active: true) e modifique dados que não deveria.",
          file: match.file,
          line: match.line,
          evidence: match.content,
          recommendation: "Extrair apenas os campos permitidos com destructuring ou whitelist: const { name, email } = req.body. Nunca usar spread do body inteiro.",
          confidence: "high",
          detection_method: "deterministic",
          cwe: "CWE-915",
          owasp: "A08:2021",
        });
      }
    }

    return findings;
  },
};
