/**
 * Sentinela — Core Types
 *
 * Schema de dados padronizado para findings, relatórios e stack detection.
 * Todas as ferramentas MCP usam estes tipos.
 */

// ============================================================================
// Severity & Confidence
// ============================================================================

export type Severity = "critical" | "high" | "medium" | "low";

export type Confidence = "high" | "medium" | "low";

export type DetectionMethod = "deterministic" | "heuristic" | "ai_assisted";

// ============================================================================
// Finding — Unidade fundamental de resultado
// ============================================================================

export interface Finding {
  /** ID único do finding (ex: "SENT-AUTH-001") */
  id: string;

  /** Regra do knowledge base (ex: "2.1", "6.1", "18.2") */
  rule_id: string;

  /** Severidade do finding */
  severity: Severity;

  /** Categoria (ex: "authentication", "xss", "idor") */
  category: string;

  /** Título curto e descritivo */
  title: string;

  /** Explicação do problema */
  description: string;

  /** Arquivo afetado (caminho relativo ao projeto) */
  file?: string;

  /** Linha do arquivo */
  line?: number;

  /** Linha final (para ranges) */
  end_line?: number;

  /** Trecho de código ou config que evidencia o problema */
  evidence?: string;

  /** Como corrigir */
  recommendation: string;

  /** Exemplo de código corrigido */
  fix_example?: string;

  /** Confiança do finding */
  confidence: Confidence;

  /** Método de detecção usado */
  detection_method: DetectionMethod;

  /** CWE ID (ex: "CWE-79" para XSS) */
  cwe?: string;

  /** OWASP Top 10 (ex: "A03:2021") */
  owasp?: string;

  /** Links de referência */
  references?: string[];
}

// ============================================================================
// Stack Detection
// ============================================================================

export interface StackInfo {
  language: string;
  framework: string;
  orm?: string;
  database: string;
  sql_dialect: string;
  auth_provider?: string;
  hosting?: string;
}

// ============================================================================
// Checklist
// ============================================================================

export type ChecklistStatus = "pass" | "fail" | "skip" | "manual";

export interface ChecklistResult {
  /** Descrição do item verificado */
  item: string;

  /** Seção do knowledge base */
  section: string;

  /** Resultado da verificação */
  status: ChecklistStatus;

  /** Referência ao finding se falhou */
  finding_id?: string;
}

// ============================================================================
// Audit Report — Resultado completo de uma auditoria
// ============================================================================

export interface AuditReport {
  project: {
    name: string;
    path: string;
    stack: StackInfo;
  };

  /** ISO 8601 timestamp */
  timestamp: string;

  /** Duração da auditoria em ms */
  duration_ms: number;

  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    by_category: Record<string, number>;
  };

  findings: Finding[];
  checklist: ChecklistResult[];

  /** Score de segurança 0-100 */
  score: number;
}

// ============================================================================
// Analyzer — Interface base para todos os analyzers
// ============================================================================

export interface AnalyzerContext {
  /** Caminho raiz do projeto sendo auditado */
  project_path: string;

  /** Stack detectada */
  stack: StackInfo;
}

export interface Analyzer {
  /** Nome do analyzer (ex: "xss", "idor", "auth") */
  name: string;

  /** Seção do knowledge base que referencia */
  section: string;

  /** Executa a análise e retorna findings */
  analyze(context: AnalyzerContext): Promise<Finding[]>;
}
