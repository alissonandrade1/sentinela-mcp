/**
 * Sentinela — SSRF Analyzer
 *
 * Detecta Server-Side Request Forgery — fetch/axios com URL do usuário.
 *
 * Referência: context.md — Seção 23
 * CWE-918: Server-Side Request Forgery (SSRF)
 * OWASP: A10:2021 — Server-Side Request Forgery
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { grepMulti } from "../core/grep.js";

const PATTERNS = [
  {
    id: "fetch-user-url",
    pattern: /fetch\s*\(\s*(?:req\.(?:body|query|params)|body|data)\.\w*(?:url|link|href|endpoint|target|src)/i,
    title: "fetch() com URL do usuário — SSRF possível",
    severity: "critical" as const,
  },
  {
    id: "axios-user-url",
    pattern: /axios\.\w+\s*\(\s*(?:req\.(?:body|query|params)|body|data)\.\w*(?:url|link|href|endpoint|target|src)/i,
    title: "axios com URL do usuário — SSRF possível",
    severity: "critical" as const,
  },
  {
    id: "got-user-url",
    pattern: /got\s*\(\s*(?:req\.(?:body|query)|body|data)\.\w*(?:url|link|href)/i,
    title: "got() com URL do usuário — SSRF possível",
    severity: "critical" as const,
  },
  {
    id: "urllib-user-url",
    pattern: /(?:urllib|requests|httpx)\.\w+\s*\(\s*(?:request\.\w+|data)\[?\s*["']?(?:url|link|href)/i,
    title: "Python HTTP request com URL do usuário — SSRF possível",
    severity: "critical" as const,
  },
  {
    id: "image-proxy",
    pattern: /(?:fetch|axios|got|request)\s*\(\s*(?:imageUrl|imgUrl|avatarUrl|photoUrl|image_url)/i,
    title: "Proxy de imagem com URL do usuário — vetor comum de SSRF",
    severity: "high" as const,
  },
  {
    id: "webhook-fetch",
    pattern: /(?:fetch|axios)\s*\(\s*(?:webhook_?[Uu]rl|callback_?[Uu]rl|endpoint)/,
    title: "Fetch para webhook_url configurável — verificar validação de URL",
    severity: "high" as const,
  },
];

export const ssrfAnalyzer: Analyzer = {
  name: "ssrf",
  section: "23",

  async analyze(context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let counter = 0;

    const grepPatterns = PATTERNS.map((p) => ({ id: p.id, pattern: p.pattern }));
    const results = await grepMulti(context.project_path, grepPatterns, {
      extensions: [".ts", ".tsx", ".js", ".jsx", ".py", ".rb", ".php", ".java", ".go"],
    });

    for (const pat of PATTERNS) {
      const matches = results.get(pat.id) ?? [];
      for (const match of matches) {
        if (match.file.includes("test") || match.file.includes("spec")) continue;
        if (match.content.trimStart().startsWith("//") || match.content.trimStart().startsWith("#")) continue;

        counter++;
        findings.push({
          id: `SENT-SSR-${String(counter).padStart(3, "0")}`,
          rule_id: "23.1",
          severity: pat.severity,
          category: "ssrf",
          title: pat.title,
          description: "SSRF permite que um atacante force o servidor a fazer requests para IPs internos (169.254.169.254, localhost, rede interna), acessando metadata de cloud, serviços internos, etc.",
          file: match.file,
          line: match.line,
          evidence: match.content,
          recommendation: "Validar URL: 1) Apenas http/https, 2) Não permitir IPs privados/localhost, 3) Resolver DNS e verificar IP resultante, 4) Usar whitelist de domínios se possível.",
          confidence: "high",
          detection_method: "deterministic",
          cwe: "CWE-918",
          owasp: "A10:2021",
        });
      }
    }

    return findings;
  },
};
