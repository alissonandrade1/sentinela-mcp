/**
 * Sentinela — File Uploads Analyzer
 *
 * Detecta upload de arquivos sem validação de tipo, tamanho ou magic bytes.
 *
 * Referência: context.md — Seção 10
 * CWE-434: Unrestricted Upload of File with Dangerous Type
 * OWASP: A04:2021 — Insecure Design
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { grepMulti } from "../core/grep.js";

const PATTERNS = [
  {
    id: "multer-no-filter",
    pattern: /multer\s*\(\s*\{[^}]*(?:dest|storage)\s*:/,
    title: "Multer upload sem fileFilter — aceita qualquer tipo de arquivo",
    severity: "high" as const,
  },
  {
    id: "formidable-no-filter",
    pattern: /(?:formidable|IncomingForm)\s*\(\s*\{/,
    title: "Formidable configurado — verificar se valida tipo de arquivo",
    severity: "medium" as const,
  },
  {
    id: "file-write-user-name",
    pattern: /(?:writeFile|createWriteStream)\s*\([^)]*(?:req\.|file\.)(?:name|originalname|filename)/,
    title: "Arquivo salvo com nome do upload original — path traversal possível",
    severity: "critical" as const,
  },
  {
    id: "no-size-limit",
    pattern: /multer\s*\(\s*\{(?:(?!limits).)*\}\s*\)/s,
    title: "Multer sem limits.fileSize — upload sem limite de tamanho",
    severity: "high" as const,
  },
  {
    id: "django-upload-no-validator",
    pattern: /FileField\s*\((?:(?!validators).)*\)/,
    title: "Django FileField sem validators — aceita qualquer arquivo",
    severity: "medium" as const,
  },
  {
    id: "express-fileupload-default",
    pattern: /fileUpload\s*\(\s*\)/,
    title: "express-fileupload com config default — sem validação de tipo/tamanho",
    severity: "high" as const,
  },
];

export const uploadsAnalyzer: Analyzer = {
  name: "uploads",
  section: "10",

  async analyze(context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let counter = 0;

    const grepPatterns = PATTERNS.map((p) => ({ id: p.id, pattern: p.pattern }));
    const results = await grepMulti(context.project_path, grepPatterns, {
      extensions: [".ts", ".tsx", ".js", ".jsx", ".py", ".rb", ".php"],
    });

    for (const pat of PATTERNS) {
      const matches = results.get(pat.id) ?? [];
      for (const match of matches) {
        if (match.file.includes("test") || match.file.includes("spec")) continue;
        if (match.content.trimStart().startsWith("//") || match.content.trimStart().startsWith("#")) continue;

        counter++;
        findings.push({
          id: `SENT-UPL-${String(counter).padStart(3, "0")}`,
          rule_id: "10.1",
          severity: pat.severity,
          category: "uploads",
          title: pat.title,
          description: "Upload sem validação permite que atacantes enviem arquivos executáveis (.php, .js, .exe) ou arquivos enormes para denial of service.",
          file: match.file,
          line: match.line,
          evidence: match.content,
          recommendation: "Validar: 1) Magic bytes (não confiar em extensão/MIME), 2) Tamanho máximo, 3) Whitelist de tipos permitidos, 4) Gerar nome aleatório (UUID) para o arquivo.",
          confidence: "medium",
          detection_method: "deterministic",
          cwe: "CWE-434",
          owasp: "A04:2021",
        });
      }
    }

    return findings;
  },
};
