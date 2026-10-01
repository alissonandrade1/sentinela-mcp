/**
 * Sentinela — Auth Analyzer
 *
 * Detecta práticas inseguras de autenticação (hashing manual, JWT manual, etc.)
 *
 * Referência: context.md — Seção 8
 * CWE-916: Use of Password Hash With Insufficient Computational Effort
 * OWASP: A07:2021 — Identification and Authentication Failures
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { grepMulti } from "../core/grep.js";

const PATTERNS = [
  {
    id: "md5-hash",
    pattern: /(?:md5|MD5)\s*\(\s*(?:password|passwd|pwd|senha)/i,
    title: "MD5 usado para hash de senha — inseguro",
    severity: "critical" as const,
    rule_id: "8.1",
  },
  {
    id: "sha1-hash",
    pattern: /(?:sha1|SHA1|sha-1)\s*\(\s*(?:password|passwd|pwd)/i,
    title: "SHA1 usado para hash de senha — inseguro",
    severity: "critical" as const,
    rule_id: "8.1",
  },
  {
    id: "sha256-password",
    pattern: /(?:createHash|sha256|SHA256)\s*\([^)]*["']sha256["'][^)]*\)[\s\S]*?(?:password|passwd|pwd)/i,
    title: "SHA256 para senha sem salt/bcrypt — insuficiente",
    severity: "high" as const,
    rule_id: "8.1",
  },
  {
    id: "jwt-sign-manual",
    pattern: /jwt\.sign\s*\(\s*\{[^}]*(?:role|isAdmin|is_admin|permissions)/i,
    title: "Role/permissions incluídos no JWT payload — verificar se é validado no server",
    severity: "medium" as const,
    rule_id: "8.3",
  },
  {
    id: "jwt-no-expiry",
    pattern: /jwt\.sign\s*\([^)]+\)\s*$/,
    title: "JWT sign sem expiresIn — token nunca expira",
    severity: "high" as const,
    rule_id: "8.3",
  },
  {
    id: "plaintext-compare",
    pattern: /(?:password|passwd|pwd|senha)\s*(?:===|==)\s*(?:req\.body|body|data)\.\s*(?:password|passwd|pwd)/i,
    title: "Comparação de senha em plaintext — sem hash",
    severity: "critical" as const,
    rule_id: "8.1",
  },
  {
    id: "session-no-httponly",
    pattern: /(?:cookie|session)\s*[:=]\s*\{[^}]*(?:httpOnly\s*:\s*false)/i,
    title: "Cookie de sessão sem httpOnly — acessível por JavaScript (XSS)",
    severity: "high" as const,
    rule_id: "8.4",
  },
  {
    id: "session-no-secure",
    pattern: /(?:cookie|session)\s*[:=]\s*\{[^}]*(?:secure\s*:\s*false)/i,
    title: "Cookie de sessão sem secure — enviado sem HTTPS",
    severity: "high" as const,
    rule_id: "8.4",
  },
];

export const authAnalyzer: Analyzer = {
  name: "auth",
  section: "8",

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
          id: `SENT-AUT-${String(counter).padStart(3, "0")}`,
          rule_id: pat.rule_id,
          severity: pat.severity,
          category: "auth",
          title: pat.title,
          description: "Práticas inseguras de autenticação permitem que atacantes comprometam contas de usuários.",
          file: match.file,
          line: match.line,
          evidence: match.content,
          recommendation: "Usar bcrypt/argon2 para hash de senhas. Usar auth providers (Supabase Auth, Clerk, NextAuth). Configurar cookies com httpOnly, secure, sameSite=strict.",
          confidence: "high",
          detection_method: "deterministic",
          cwe: "CWE-916",
          owasp: "A07:2021",
        });
      }
    }

    return findings;
  },
};
