/**
 * Sentinela — Rules Engine
 *
 * Consulta regras de segurança do knowledge base (context.md).
 * Permite ao agente buscar regras por categoria, seção ou termo.
 */

import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileContent } from "./filesystem.js";

// ============================================================================
// Section Index — mapeamento de seções do context.md
// ============================================================================

const SECTION_INDEX: Record<string, { section: string; title: string; keywords: string[] }> = {
  "defense-in-depth": { section: "1", title: "Defense in Depth", keywords: ["camada", "waf", "middleware", "rls"] },
  "zero-trust": { section: "2", title: "Zero Trust / Identity", keywords: ["identity", "user_id", "jwt", "session", "frontend", "mutations"] },
  "input-validation": { section: "3", title: "Input Validation", keywords: ["validação", "maxlength", "schema", "zod", "yup", "joi", "sanitize"] },
  "error-messages": { section: "4", title: "Mensagens de Erro", keywords: ["erro", "error", "stack trace", "mensagem", "debug"] },
  "rate-limiting": { section: "5", title: "Rate Limiting", keywords: ["rate limit", "brute force", "throttle", "login", "ddos"] },
  "idor": { section: "6", title: "IDOR", keywords: ["idor", "direct object", "ownership", "owner_id", "autorização"] },
  "access-control": { section: "7", title: "Database Access Control", keywords: ["rls", "policy", "row level", "acl", "permissão"] },
  "auth": { section: "8", title: "Authentication", keywords: ["auth", "login", "password", "hash", "bcrypt", "jwt", "sessão", "cookie"] },
  "honeypots": { section: "9", title: "Honeypots", keywords: ["honeypot", "bot", "spam", "form"] },
  "uploads": { section: "10", title: "File Uploads", keywords: ["upload", "file", "arquivo", "multer", "mime", "magic bytes"] },
  "headers": { section: "11", title: "Security Headers", keywords: ["header", "hsts", "csp", "x-frame", "content-security"] },
  "plans": { section: "12", title: "Plan Separation", keywords: ["plano", "plan", "tier", "billing", "limite", "subscription"] },
  "secrets": { section: "13", title: "Secrets & Credentials", keywords: ["secret", "credential", "api key", "password", "hardcoded", "env"] },
  "tests": { section: "14", title: "Security Tests", keywords: ["test", "teste", "segurança", "ci", "coverage"] },
  "sql-constraints": { section: "15", title: "SQL Constraints", keywords: ["sql", "constraint", "varchar", "not null", "foreign key", "check"] },
  "csrf": { section: "16", title: "CSRF", keywords: ["csrf", "cross-site request forgery", "token", "form"] },
  "xss": { section: "18", title: "XSS Prevention", keywords: ["xss", "cross-site scripting", "innerhtml", "dangerously", "sanitize", "dompurify"] },
  "cors": { section: "19", title: "CORS", keywords: ["cors", "origin", "cross-origin", "access-control"] },
  "mass-assignment": { section: "20", title: "Mass Assignment", keywords: ["mass assignment", "spread", "req.body", "whitelist", "permit"] },
  "dependencies": { section: "21", title: "Dependency Security", keywords: ["dependency", "dependência", "npm audit", "lock", "dependabot", "renovate"] },
  "logging": { section: "22", title: "Logging & Monitoring", keywords: ["log", "logging", "monitor", "audit trail", "redact"] },
  "ssrf": { section: "23", title: "SSRF", keywords: ["ssrf", "server-side request", "fetch", "proxy", "interno"] },
  "redirects": { section: "24", title: "Open Redirect", keywords: ["redirect", "open redirect", "phishing", "url"] },
  "privacy": { section: "25", title: "Privacy (LGPD/GDPR)", keywords: ["lgpd", "gdpr", "privacy", "privacidade", "exclusão", "export"] },
  "secrets-mgmt": { section: "26", title: "Secrets Management", keywords: ["secrets management", "vault", "env", "rotation"] },
  "webhooks": { section: "27", title: "Webhook Security", keywords: ["webhook", "hmac", "signature", "idempotency"] },
  "deserialization": { section: "28", title: "Secure Deserialization", keywords: ["deserialization", "eval", "pickle", "unserialize", "marshal"] },
  "timing": { section: "29", title: "Timing Attacks", keywords: ["timing", "constant-time", "timingsafeequal", "compare_digest"] },
  "dns": { section: "30", title: "DNS & Subdomain Security", keywords: ["dns", "subdomain", "cname", "spf", "dmarc", "dkim"] },
  "error-handling": { section: "31", title: "Error Handling", keywords: ["error handling", "try-catch", "exception", "global handler"] },
  "request-limits": { section: "32", title: "Request Limits", keywords: ["request limit", "body size", "timeout", "payload"] },
};

// ============================================================================
// Path Resolution
// ============================================================================

export function resolveContextPath(customPath?: string): string | null {
  if (customPath && existsSync(customPath)) return customPath;
  if (process.env.SENTINELA_CONTEXT_PATH && existsSync(process.env.SENTINELA_CONTEXT_PATH)) {
    return process.env.SENTINELA_CONTEXT_PATH;
  }
  const cwdPath = join(process.cwd(), "context.md");
  if (existsSync(cwdPath)) return cwdPath;

  try {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);
    const candidate1 = join(__dirname, "../../context.md");
    if (existsSync(candidate1)) return candidate1;
    const candidate2 = join(__dirname, "../context.md");
    if (existsSync(candidate2)) return candidate2;
  } catch {
    // fallback
  }

  return null;
}

// ============================================================================
// Functions
// ============================================================================

/**
 * Busca regras por categoria ou termo.
 * Retorna o mapeamento de seções relevantes.
 */
export function searchRules(query: string): { section: string; title: string; category: string }[] {
  const q = query.toLowerCase();
  const results: { section: string; title: string; category: string }[] = [];

  for (const [category, info] of Object.entries(SECTION_INDEX)) {
    const matchesCategory = category.includes(q);
    const matchesTitle = info.title.toLowerCase().includes(q);
    const matchesKeyword = info.keywords.some((k) => k.includes(q));
    const matchesSection = info.section === q;

    if (matchesCategory || matchesTitle || matchesKeyword || matchesSection) {
      results.push({ section: info.section, title: info.title, category });
    }
  }

  return results;
}

/**
 * Retorna todas as categorias disponíveis.
 */
export function listAllRules(): { section: string; title: string; category: string }[] {
  return Object.entries(SECTION_INDEX).map(([category, info]) => ({
    section: info.section,
    title: info.title,
    category,
  }));
}

/**
 * Lê o conteúdo de uma seção específica do context.md.
 * Retorna o texto da seção ou null se não encontrada.
 */
export async function getRuleContent(
  sectionNumber: string,
  knowledgeBasePath?: string,
): Promise<string | null> {
  const targetPath = resolveContextPath(knowledgeBasePath);
  if (!targetPath) return null;

  const content = await readFileContent(targetPath);
  if (!content) return null;

  // Buscar a seção pelo número
  const sectionPattern = new RegExp(
    `## ${sectionNumber}\\.\\s+[^\\n]+\\n([\\s\\S]*?)(?=\\n## \\d+\\.\\s|$)`,
  );

  const match = content.match(sectionPattern);
  if (match?.[1]) {
    return match[1].trim();
  }

  // Tentar formato alternativo
  const altPattern = new RegExp(
    `## Seção ${sectionNumber}[^\\n]*\\n([\\s\\S]*?)(?=\\n## |$)`,
  );
  const altMatch = content.match(altPattern);
  return altMatch?.[1]?.trim() ?? null;
}
