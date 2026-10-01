/**
 * Sentinela — XSS Analyzer
 *
 * Detecta padrões de Cross-Site Scripting em código frontend e backend.
 *
 * Referência: context.md — Seção 18 (XSS Prevention)
 * CWE-79: Improper Neutralization of Input During Web Page Generation
 * OWASP: A03:2021 — Injection
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { grepMulti } from "../core/grep.js";

// ============================================================================
// Patterns
// ============================================================================

const XSS_PATTERNS = [
  // React
  {
    id: "react-dangerously",
    pattern: /dangerouslySetInnerHTML\s*=\s*\{/,
    title: "dangerouslySetInnerHTML usado com dados potencialmente não sanitizados",
    severity: "critical" as const,
    rule_id: "18.2",
  },
  // Vue
  {
    id: "vue-v-html",
    pattern: /v-html\s*=\s*"/,
    title: "v-html usado — renderiza HTML sem escapar",
    severity: "critical" as const,
    rule_id: "18.2",
  },
  // Svelte
  {
    id: "svelte-at-html",
    pattern: /\{@html\s/,
    title: "{@html} usado — renderiza HTML sem escapar",
    severity: "critical" as const,
    rule_id: "18.2",
  },
  // Angular
  {
    id: "angular-innerhtml",
    pattern: /\[innerHTML\]\s*=\s*"/,
    title: "[innerHTML] binding usado — pode injetar HTML",
    severity: "critical" as const,
    rule_id: "18.2",
  },
  // DOM API insegura
  {
    id: "dom-innerhtml",
    pattern: /\.innerHTML\s*=/,
    title: "innerHTML atribuído diretamente — risco de XSS",
    severity: "critical" as const,
    rule_id: "18.2",
  },
  {
    id: "dom-outerhtml",
    pattern: /\.outerHTML\s*=/,
    title: "outerHTML atribuído diretamente — risco de XSS",
    severity: "critical" as const,
    rule_id: "18.2",
  },
  {
    id: "document-write",
    pattern: /document\.write\s*\(/,
    title: "document.write() usado — risco de XSS",
    severity: "high" as const,
    rule_id: "18.2",
  },
  {
    id: "insert-adjacent-html",
    pattern: /\.insertAdjacentHTML\s*\(/,
    title: "insertAdjacentHTML() usado — risco de XSS se dados do usuário",
    severity: "high" as const,
    rule_id: "18.2",
  },
  // Template engines inseguros
  {
    id: "ejs-unescaped",
    pattern: /<%-\s/,
    title: "EJS output não-escapado (<%- %>) — risco de XSS",
    severity: "critical" as const,
    rule_id: "18.2",
  },
  // URL sanitization
  {
    id: "javascript-protocol",
    pattern: /href\s*=\s*["']javascript:/i,
    title: 'href com javascript: protocol — vetor de XSS',
    severity: "critical" as const,
    rule_id: "18.4",
  },
];

// ============================================================================
// Analyzer
// ============================================================================

export const xssAnalyzer: Analyzer = {
  name: "xss",
  section: "18",

  async analyze(context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let counter = 0;

    const patterns = XSS_PATTERNS.map((p) => ({
      id: p.id,
      pattern: p.pattern,
    }));

    const results = await grepMulti(context.project_path, patterns, {
      extensions: [".ts", ".tsx", ".js", ".jsx", ".vue", ".svelte", ".html", ".ejs", ".hbs", ".pug", ".php", ".erb"],
    });

    for (const xp of XSS_PATTERNS) {
      const matches = results.get(xp.id) ?? [];

      for (const match of matches) {
        // Ignorar testes e configs
        if (match.file.includes("test") || match.file.includes("spec")) continue;
        if (match.content.trimStart().startsWith("//") || match.content.trimStart().startsWith("*")) continue;

        counter++;
        findings.push({
          id: `SENT-XSS-${String(counter).padStart(3, "0")}`,
          rule_id: xp.rule_id,
          severity: xp.severity,
          category: "xss",
          title: xp.title,
          description: `Padrão inseguro encontrado que pode permitir Cross-Site Scripting (XSS). Dados do usuário renderizados sem sanitização podem executar scripts maliciosos no navegador.`,
          file: match.file,
          line: match.line,
          evidence: match.content,
          recommendation: "Usar output escapado por default do framework. Se HTML é necessário, sanitizar com DOMPurify (frontend) ou sanitize-html/bleach (backend).",
          confidence: "high",
          detection_method: "deterministic",
          cwe: "CWE-79",
          owasp: "A03:2021",
        });
      }
    }

    return findings;
  },
};
