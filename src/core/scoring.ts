/**
 * Sentinela — Scoring Engine
 *
 * Calcula score de segurança 0-100 baseado nos findings.
 */

import type { Finding, Severity } from "./types.js";

// ============================================================================
// Weights
// ============================================================================

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
};

const MAX_PENALTY = 100;

// ============================================================================
// Scoring
// ============================================================================

/**
 * Calcula score de segurança de 0 (inseguro) a 100 (seguro).
 * Começa em 100 e desconta por cada finding.
 */
export function calculateScore(findings: Finding[]): number {
  if (findings.length === 0) return 100;

  let totalPenalty = 0;

  for (const finding of findings) {
    totalPenalty += SEVERITY_WEIGHTS[finding.severity];
  }

  // Cap no máximo
  totalPenalty = Math.min(totalPenalty, MAX_PENALTY);

  return Math.max(0, 100 - totalPenalty);
}

/**
 * Retorna um resumo por severidade.
 */
export function summarizeFindings(findings: Finding[]): {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  by_category: Record<string, number>;
} {
  const summary = {
    total: findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    by_category: {} as Record<string, number>,
  };

  for (const f of findings) {
    summary[f.severity]++;
    summary.by_category[f.category] = (summary.by_category[f.category] ?? 0) + 1;
  }

  return summary;
}
