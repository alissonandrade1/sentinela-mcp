/**
 * Sentinela — Deserialization Analyzer
 *
 * Detecta uso de desserialização insegura (eval, pickle, unserialize, etc.)
 *
 * Referência: context.md — Seção 28 (Secure Deserialization)
 * CWE-502: Deserialization of Untrusted Data
 * OWASP: A08:2021 — Software and Data Integrity Failures
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { grepMulti } from "../core/grep.js";

const PATTERNS = [
  // JavaScript
  {
    id: "js-eval",
    pattern: /\beval\s*\(/,
    title: "eval() usado — possível execução remota de código",
    severity: "critical" as const,
    extensions: [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"],
  },
  {
    id: "js-new-function",
    pattern: /new\s+Function\s*\(/,
    title: "new Function() usado — equivalente a eval()",
    severity: "critical" as const,
    extensions: [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"],
  },
  {
    id: "js-settimeout-string",
    pattern: /setTimeout\s*\(\s*["'`]/,
    title: "setTimeout() com string — executa código como eval()",
    severity: "high" as const,
    extensions: [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"],
  },
  // Python
  {
    id: "py-pickle",
    pattern: /pickle\.loads?\s*\(/,
    title: "pickle.load/loads usado — desserialização insegura (RCE)",
    severity: "critical" as const,
    extensions: [".py"],
  },
  {
    id: "py-yaml-unsafe",
    pattern: /yaml\.load\s*\([^)]*\)/,
    title: "yaml.load() sem SafeLoader — pode executar código",
    severity: "critical" as const,
    extensions: [".py"],
  },
  {
    id: "py-eval",
    pattern: /\beval\s*\(/,
    title: "eval() em Python — execução remota de código",
    severity: "critical" as const,
    extensions: [".py"],
  },
  {
    id: "py-exec",
    pattern: /\bexec\s*\(/,
    title: "exec() em Python — execução remota de código",
    severity: "critical" as const,
    extensions: [".py"],
  },
  // PHP
  {
    id: "php-unserialize",
    pattern: /\bunserialize\s*\(/,
    title: "unserialize() em PHP — object injection",
    severity: "critical" as const,
    extensions: [".php"],
  },
  // Ruby
  {
    id: "ruby-marshal",
    pattern: /Marshal\.load\s*\(/,
    title: "Marshal.load em Ruby — desserialização insegura (RCE)",
    severity: "critical" as const,
    extensions: [".rb"],
  },
  {
    id: "ruby-yaml-load",
    pattern: /YAML\.load\s*\(/,
    title: "YAML.load em Ruby — pode executar código",
    severity: "critical" as const,
    extensions: [".rb"],
  },
];

// ============================================================================
// Analyzer
// ============================================================================

export const deserializationAnalyzer: Analyzer = {
  name: "deserialization",
  section: "28",

  async analyze(context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let counter = 0;

    // Agrupar por extensão para eficiência
    const allExtensions = [...new Set(PATTERNS.flatMap((p) => p.extensions))];

    const grepPatterns = PATTERNS.map((p) => ({
      id: p.id,
      pattern: p.pattern,
    }));

    const results = await grepMulti(context.project_path, grepPatterns, {
      extensions: allExtensions,
    });

    for (const pat of PATTERNS) {
      const matches = results.get(pat.id) ?? [];

      for (const match of matches) {
        // Ignorar testes, comments
        if (match.file.includes("test") || match.file.includes("spec")) continue;
        if (match.content.trimStart().startsWith("//") || match.content.trimStart().startsWith("#")) continue;
        // Ignorar yaml.safe_load (seguro)
        if (pat.id === "py-yaml-unsafe" && match.content.includes("safe_load")) continue;
        // Ignorar unserialize com allowed_classes => false (seguro)
        if (pat.id === "php-unserialize" && match.content.includes("allowed_classes")) continue;

        counter++;
        findings.push({
          id: `SENT-DES-${String(counter).padStart(3, "0")}`,
          rule_id: "28.1",
          severity: pat.severity,
          category: "deserialization",
          title: pat.title,
          description: `Desserialização insegura detectada. Se dados do usuário forem passados a esta função, pode permitir execução remota de código (RCE).`,
          file: match.file,
          line: match.line,
          evidence: match.content,
          recommendation: "Usar JSON.parse/json.loads para dados. Nunca desserializar dados do usuário com formatos que executam código.",
          confidence: "high",
          detection_method: "deterministic",
          cwe: "CWE-502",
          owasp: "A08:2021",
        });
      }
    }

    return findings;
  },
};
