/**
 * Sentinela — Webhooks Analyzer
 *
 * Detecta webhooks sem verificação de assinatura e sem idempotência.
 *
 * Referência: context.md — Seção 27
 * CWE-345: Insufficient Verification of Data Authenticity
 * OWASP: A08:2021 — Software and Data Integrity Failures
 */

import type { Finding, AnalyzerContext, Analyzer } from "../core/types.js";
import { grep } from "../core/grep.js";



export const webhooksAnalyzer: Analyzer = {
  name: "webhooks",
  section: "27",

  async analyze(context: AnalyzerContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let counter = 0;

    // Buscar rotas de webhook
    const webhookRoutes = await grep(context.project_path, {
      pattern: /(?:\/(?:api\/)?webhooks?|\/hooks?\/|\/callback)\b/i,
      extensions: [".ts", ".tsx", ".js", ".jsx", ".py", ".rb", ".php"],
      maxMatches: 20,
    });

    if (webhookRoutes.length === 0) return findings;

    // Verificar se existe verificação de assinatura no projeto
    const signatureChecks = await grep(context.project_path, {
      pattern: /(?:constructEvent|verify_signature|hmac|createHmac|compare_digest|timingSafeEqual|x-hub-signature|x-webhook-signature|svix\.verify|webhook_secret)/i,
      maxMatches: 5,
    });

    if (webhookRoutes.length > 0 && signatureChecks.length === 0) {
      counter++;
      findings.push({
        id: `SENT-WHK-${String(counter).padStart(3, "0")}`,
        rule_id: "27.1",
        severity: "critical",
        category: "webhooks",
        title: "Webhook endpoints encontrados sem verificação de assinatura",
        description: "Sem verificação de assinatura, qualquer pessoa pode enviar payloads falsos ao endpoint de webhook, podendo alterar estado da aplicação.",
        recommendation: "Verificar assinatura HMAC do webhook antes de processar. Ex: stripe.webhooks.constructEvent(body, sig, secret). Usar timingSafeEqual para comparação.",
        confidence: "medium",
        detection_method: "heuristic",
        cwe: "CWE-345",
        owasp: "A08:2021",
      });
    }

    // Verificar idempotência
    const idempotencyCheck = await grep(context.project_path, {
      pattern: /(?:idempoten|event_?id|webhook_?id|already.*processed|duplicate.*check|processed_events)/i,
      maxMatches: 3,
    });

    if (webhookRoutes.length > 0 && idempotencyCheck.length === 0) {
      counter++;
      findings.push({
        id: `SENT-WHK-${String(counter).padStart(3, "0")}`,
        rule_id: "27.2",
        severity: "medium",
        category: "webhooks",
        title: "Webhook sem verificação de idempotência",
        description: "Sem idempotência, webhooks reenviados (retry) podem executar a mesma ação múltiplas vezes (ex: cobrar 2x).",
        recommendation: "Armazenar event_id de webhooks processados e ignorar duplicatas.",
        confidence: "medium",
        detection_method: "heuristic",
      });
    }

    return findings;
  },
};
