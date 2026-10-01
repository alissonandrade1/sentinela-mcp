/**
 * Sentinela — Mutations Analyzer
 *
 * Detecta mutations diretas do client ao banco de dados.
 *
 * Referência: context.md — Seção 2.2 (Zero Trust do Frontend)
 * CWE-639: Authorization Bypass Through User-Controlled Key
 * OWASP: A01:2021 — Broken Access Control
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { grepMulti } from "../core/grep.js";

const PATTERNS = [
  {
    id: "supabase-client-mutation",
    pattern: /(?:supabase|client)\s*\.\s*from\s*\([^)]+\)\s*\.\s*(?:insert|update|delete|upsert)\s*\(/,
    title: "Mutation direta ao banco via Supabase client — deve ser server-side",
    severity: "high" as const,
  },
  {
    id: "firebase-client-write",
    pattern: /(?:firebase|db|firestore)\s*\.\s*(?:collection|ref)\s*\([^)]+\)\s*\.\s*(?:add|set|update|delete)\s*\(/,
    title: "Write direto ao Firebase/Firestore — verificar rules",
    severity: "high" as const,
  },
  {
    id: "fetch-mutation-no-auth",
    pattern: /fetch\s*\(\s*['"`][^'"]+['"`]\s*,\s*\{\s*method\s*:\s*['"`](?:POST|PUT|PATCH|DELETE)['"`]/i,
    title: "Fetch com mutation — verificar se inclui token de autenticação",
    severity: "low" as const,
  },
];

export const mutationsAnalyzer: Analyzer = {
  name: "mutations",
  section: "2",

  async analyze(context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let counter = 0;

    const grepPatterns = PATTERNS.map((p) => ({ id: p.id, pattern: p.pattern }));

    // Buscar apenas em arquivos client-side (components, pages, hooks)
    const results = await grepMulti(context.project_path, grepPatterns, {
      extensions: [".tsx", ".jsx", ".vue", ".svelte"],
    });

    for (const pat of PATTERNS) {
      const matches = results.get(pat.id) ?? [];
      for (const match of matches) {
        if (match.file.includes("test") || match.file.includes("spec")) continue;
        // Ignorar se está em api/ ou server/ (é server-side)
        if (match.file.includes("/api/") || match.file.includes("/server/") || match.file.includes("server.")) continue;
        if (match.content.trimStart().startsWith("//")) continue;

        counter++;
        findings.push({
          id: `SENT-MUT-${String(counter).padStart(3, "0")}`,
          rule_id: "2.2",
          severity: pat.severity,
          category: "mutations",
          title: pat.title,
          description: "Mutations (INSERT/UPDATE/DELETE) nunca devem ser feitas diretamente do frontend. Devem passar por uma API route server-side que valida autenticação, autorização e input.",
          file: match.file,
          line: match.line,
          evidence: match.content,
          recommendation: "Mover a mutation para uma API route/server action. O frontend deve chamar a API, nunca o banco diretamente.",
          confidence: "medium",
          detection_method: "deterministic",
          cwe: "CWE-639",
          owasp: "A01:2021",
        });
      }
    }

    return findings;
  },
};
