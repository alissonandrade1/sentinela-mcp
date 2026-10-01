/**
 * Sentinela — Secrets Analyzer
 *
 * Detecta credenciais hardcoded, API keys em código, connection strings com senha.
 *
 * Referência: context.md — Seção 13 (Auditoria de Credenciais)
 * CWE-798: Use of Hard-coded Credentials
 * OWASP: A07:2021 — Identification and Authentication Failures
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { grep } from "../core/grep.js";
import { fileExists } from "../core/filesystem.js";
import { readFileContent } from "../core/filesystem.js";
import { join } from "node:path";

// ============================================================================
// Patterns
// ============================================================================

const SECRET_PATTERNS = [
  {
    id: "hardcoded-api-key",
    pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*["'][a-zA-Z0-9_\-]{16,}["']/i,
    title: "API key hardcoded em código",
    severity: "critical" as const,
  },
  {
    id: "hardcoded-secret",
    pattern: /(?:secret|password|passwd|pwd|token|auth_token|access_token|private_key)\s*[:=]\s*["'][^"']{8,}["']/i,
    title: "Secret/senha hardcoded em código",
    severity: "critical" as const,
  },
  {
    id: "hardcoded-connection-string",
    pattern: /(?:postgres|mysql|mongodb|redis|mssql|oracle):\/\/[^"'\s]+:[^"'\s@]+@[^"'\s]+/i,
    title: "Connection string com credenciais em código",
    severity: "critical" as const,
  },
  {
    id: "aws-key",
    pattern: /AKIA[0-9A-Z]{16}/,
    title: "AWS Access Key ID hardcoded",
    severity: "critical" as const,
  },
  {
    id: "private-key",
    pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/,
    title: "Chave privada em código",
    severity: "critical" as const,
  },
  {
    id: "jwt-secret-inline",
    pattern: /jwt\.sign\s*\([^)]*["'][a-zA-Z0-9_\-]{16,}["']/i,
    title: "JWT secret hardcoded em jwt.sign()",
    severity: "critical" as const,
  },
  {
    id: "github-token",
    pattern: /ghp_[a-zA-Z0-9]{36}/,
    title: "GitHub Personal Access Token hardcoded",
    severity: "critical" as const,
  },
  {
    id: "stripe-key",
    pattern: /sk_(?:live|test)_[a-zA-Z0-9]{24,}/,
    title: "Stripe Secret Key hardcoded",
    severity: "critical" as const,
  },
];

// ============================================================================
// Analyzer
// ============================================================================

export const secretsAnalyzer: Analyzer = {
  name: "secrets",
  section: "13",

  async analyze(context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let counter = 0;

    // 1. Buscar credenciais hardcoded em código
    for (const sp of SECRET_PATTERNS) {
      const matches = await grep(context.project_path, {
        pattern: sp.pattern,
        extensions: [".ts", ".tsx", ".js", ".jsx", ".py", ".rb", ".php", ".java", ".cs", ".go"],
      });

      for (const match of matches) {
        // Ignorar .env.example, tests, e comentários
        if (match.file.includes(".example") || match.file.includes("test")) continue;
        if (match.content.trimStart().startsWith("//") || match.content.trimStart().startsWith("#")) continue;

        counter++;
        findings.push({
          id: `SENT-SEC-${String(counter).padStart(3, "0")}`,
          rule_id: "13.1",
          severity: sp.severity,
          category: "secrets",
          title: sp.title,
          description: `Credencial encontrada hardcoded no código. Isso pode ser explorado se o código for exposto (git público, build artifacts, etc.).`,
          file: match.file,
          line: match.line,
          evidence: match.content,
          recommendation: "Mover para variável de ambiente (.env) e carregar via process.env ou equivalente.",
          confidence: "high",
          detection_method: "deterministic",
          cwe: "CWE-798",
          owasp: "A07:2021",
        });
      }
    }

    // 2. Verificar se .env está no .gitignore
    const gitignoreContent = await readFileContent(join(context.project_path, ".gitignore"));
    if (gitignoreContent) {
      const hasEnvIgnore = gitignoreContent.split("\n").some(
        (line) => line.trim() === ".env" || line.trim() === ".env*" || line.trim() === ".env.local",
      );

      if (!hasEnvIgnore) {
        counter++;
        findings.push({
          id: `SENT-SEC-${String(counter).padStart(3, "0")}`,
          rule_id: "13.2",
          severity: "critical",
          category: "secrets",
          title: ".env NÃO está no .gitignore",
          description: "O arquivo .env contém credenciais e pode ser commitado acidentalmente ao repositório.",
          file: ".gitignore",
          recommendation: 'Adicionar ".env" ao .gitignore imediatamente.',
          confidence: "high",
          detection_method: "deterministic",
          cwe: "CWE-798",
          owasp: "A07:2021",
        });
      }
    } else {
      // Não tem .gitignore — ainda pior
      if (await fileExists(join(context.project_path, ".git"))) {
        counter++;
        findings.push({
          id: `SENT-SEC-${String(counter).padStart(3, "0")}`,
          rule_id: "13.2",
          severity: "high",
          category: "secrets",
          title: ".gitignore ausente em projeto git",
          description: "Projeto usa git mas não tem .gitignore. Arquivos sensíveis podem ser commitados.",
          recommendation: "Criar .gitignore com .env, node_modules, dist, e outros diretórios sensíveis.",
          confidence: "high",
          detection_method: "deterministic",
          cwe: "CWE-798",
          owasp: "A07:2021",
        });
      }
    }

    return findings;
  },
};
