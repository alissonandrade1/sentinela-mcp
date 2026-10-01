import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { detectStack } from "../src/analyzers/detect-stack.js";
import { secretsAnalyzer } from "../src/analyzers/secrets.js";
import { xssAnalyzer } from "../src/analyzers/xss.js";
import { headersAnalyzer } from "../src/analyzers/headers.js";
import { calculateScore, summarizeFindings } from "../src/core/scoring.js";
import { generateMarkdownReport, generateChecklist, compareReports } from "../src/core/report.js";
import { searchRules, listAllRules, getRuleContent } from "../src/core/rules.js";
import { suggestFix } from "../src/core/fix-suggester.js";
import type { Finding, StackInfo, AuditReport } from "../src/core/types.js";

const FIXTURE_PATH = resolve(import.meta.dirname!, "fixtures/vulnerable-nextjs");

describe("Sentinela Test Suite", () => {
  describe("Stack Detection", () => {
    it("should accurately detect Next.js, TypeScript, and Supabase stack", async () => {
      const stack = await detectStack(FIXTURE_PATH);
      expect(stack.language).toBe("TypeScript");
      expect(stack.framework).toBe("Next.js");
      expect(stack.database).toBe("PostgreSQL (Supabase)");
    });
  });

  describe("Analyzers", () => {
    it("secrets analyzer should find hardcoded secrets in fixture", async () => {
      const stack = await detectStack(FIXTURE_PATH);
      const findings = await secretsAnalyzer.analyze({ project_path: FIXTURE_PATH, stack });
      expect(findings.length).toBeGreaterThan(0);
      expect(findings.some((f) => f.category === "secrets")).toBe(true);
    });

    it("xss analyzer should find dangerouslySetInnerHTML without DOMPurify", async () => {
      const stack = await detectStack(FIXTURE_PATH);
      const findings = await xssAnalyzer.analyze({ project_path: FIXTURE_PATH, stack });
      expect(findings.length).toBeGreaterThan(0);
      expect(findings.some((f) => f.category === "xss")).toBe(true);
    });

    it("headers analyzer should identify missing security headers", async () => {
      const stack = await detectStack(FIXTURE_PATH);
      const findings = await headersAnalyzer.analyze({ project_path: FIXTURE_PATH, stack });
      expect(findings.length).toBeGreaterThan(0);
      expect(findings.some((f) => f.category === "headers")).toBe(true);
    });
  });

  describe("Scoring & Summary", () => {
    it("should summarize findings and calculate penalty score correctly", () => {
      const mockFindings: Finding[] = [
        {
          id: "SENT-SEC-001",
          analyzer: "secrets",
          category: "secrets",
          section: "13",
          title: "Hardcoded Secret",
          description: "Found secret",
          severity: "critical",
          confidence: "high",
          recommendation: "Use env",
        },
        {
          id: "SENT-XSS-001",
          analyzer: "xss",
          category: "xss",
          section: "18",
          title: "XSS detected",
          description: "InnerHTML used",
          severity: "high",
          confidence: "high",
          recommendation: "Sanitize input",
        },
      ];

      const summary = summarizeFindings(mockFindings);
      expect(summary.total).toBe(2);
      expect(summary.critical).toBe(1);
      expect(summary.high).toBe(1);

      const score = calculateScore(mockFindings);
      // 100 - (1 * 25) - (1 * 15) = 60
      expect(score).toBe(60);
    });
  });

  describe("Rules Engine", () => {
    it("should list all registered rules", () => {
      const rules = listAllRules();
      expect(rules.length).toBeGreaterThanOrEqual(24);
    });

    it("should find rules by query", () => {
      const xssRules = searchRules("xss");
      expect(xssRules.length).toBeGreaterThanOrEqual(1);
      expect(xssRules[0].section).toBe("18");
    });

    it("should fetch rule content from context.md", async () => {
      const content = await getRuleContent("18");
      expect(content).toBeTruthy();
      expect(content).toContain("XSS");
    });
  });

  describe("Reports & Diff", () => {
    const mockStack: StackInfo = {
      language: "TypeScript",
      framework: "Next.js",
      database: "PostgreSQL",
      sql_dialect: "PostgreSQL",
    };

    const mockReport: AuditReport = {
      project: { name: "test-app", path: "/test", stack: mockStack },
      timestamp: new Date().toISOString(),
      duration_ms: 50,
      summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, by_category: { secrets: 1 } },
      findings: [
        {
          id: "SENT-SEC-001",
          analyzer: "secrets",
          category: "secrets",
          section: "13",
          title: "Mock Secret",
          description: "Secret leak",
          severity: "critical",
          confidence: "high",
          recommendation: "Use env",
        },
      ],
      checklist: [],
      score: 75,
    };

    it("should generate markdown report containing key sections", () => {
      const md = generateMarkdownReport(mockReport);
      expect(md).toContain("Relatório de Segurança");
      expect(md).toContain("Score: 75/100");
      expect(md).toContain("SENT-SEC-001");
    });

    it("should compare before and after reports accurately", () => {
      const resolvedReport: AuditReport = {
        ...mockReport,
        findings: [],
        score: 100,
      };

      const diff = compareReports(mockReport, resolvedReport);
      expect(diff.resolved_findings.length).toBe(1);
      expect(diff.new_findings.length).toBe(0);
      expect(diff.score_change).toBe(25);
    });

    it("should generate checklist with appropriate pass/fail status", () => {
      const checklist = generateChecklist(mockReport.findings);
      expect(checklist.length).toBeGreaterThan(10);
      const secretItem = checklist.find((c) => c.item.includes("credencial hardcoded"));
      expect(secretItem?.status).toBe("fail");
    });
  });

  describe("Fix Suggester", () => {
    it("should suggest remediation code for secrets finding", () => {
      const mockStack: StackInfo = {
        language: "TypeScript",
        framework: "Next.js",
        database: "PostgreSQL",
        sql_dialect: "PostgreSQL",
      };

      const finding: Finding = {
        id: "SENT-SEC-001",
        analyzer: "secrets",
        category: "secrets",
        section: "13",
        title: "Hardcoded secret",
        description: "API key hardcoded",
        severity: "critical",
        confidence: "high",
        recommendation: "Use env var",
      };

      const fix = suggestFix(finding, mockStack);
      expect(fix.description).toContain("variável de ambiente");
      expect(fix.code).toContain("process.env");
    });
  });
});
