/**
 * Sentinela — Timing Attacks Analyzer
 *
 * Detecta comparações inseguras de secrets e timing leaks em login.
 *
 * Referência: context.md — Seção 29
 * CWE-208: Observable Timing Discrepancy
 * OWASP: A02:2021 — Cryptographic Failures
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { grepMulti } from "../core/grep.js";

const PATTERNS = [
  {
    id: "direct-secret-compare",
    pattern: /(?:token|secret|api_?key|signature|hash)\s*(?:===|!==|==|!=)\s*/i,
    title: "Comparação direta de secret com === (timing leak)",
    severity: "medium" as const,
    rule_id: "29.1",
  },
  {
    id: "if-secret-equals",
    pattern: /if\s*\(\s*(?:req\.(?:headers|query|body|params))\.[^\s]+\s*===?\s/,
    title: "Header/param comparado diretamente — pode vazar timing",
    severity: "medium" as const,
    rule_id: "29.1",
  },
  {
    id: "webhook-sig-compare",
    pattern: /(?:signature|x-hub-signature|x-webhook)\s*===\s/i,
    title: "Assinatura de webhook comparada com === (timing leak)",
    severity: "high" as const,
    rule_id: "29.1",
  },
];

export const timingAnalyzer: Analyzer = {
  name: "timing",
  section: "29",

  async analyze(context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let counter = 0;

    const grepPatterns = PATTERNS.map((p) => ({ id: p.id, pattern: p.pattern }));
    const results = await grepMulti(context.project_path, grepPatterns, {
      extensions: [".ts", ".tsx", ".js", ".jsx", ".py", ".rb", ".php", ".go"],
    });

    for (const pat of PATTERNS) {
      const matches = results.get(pat.id) ?? [];
      for (const match of matches) {
        if (match.file.includes("test") || match.file.includes("spec")) continue;
        if (match.content.trimStart().startsWith("//") || match.content.trimStart().startsWith("#")) continue;
        // Ignorar se já usa timingSafeEqual
        if (match.content.includes("timingSafeEqual") || match.content.includes("compare_digest")) continue;

        counter++;
        findings.push({
          id: `SENT-TIM-${String(counter).padStart(3, "0")}`,
          rule_id: pat.rule_id,
          severity: pat.severity,
          category: "timing",
          title: pat.title,
          description: "Comparação de tempo variável permite a um atacante inferir caracteres corretos de um secret medindo o tempo de resposta.",
          file: match.file,
          line: match.line,
          evidence: match.content,
          recommendation: "Usar crypto.timingSafeEqual (Node.js) ou hmac.compare_digest (Python) para comparar secrets.",
          confidence: "medium",
          detection_method: "deterministic",
          cwe: "CWE-208",
          owasp: "A02:2021",
        });
      }
    }

    return findings;
  },
};
