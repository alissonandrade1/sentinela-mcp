/**
 * Sentinela — Fix Suggester
 *
 * Sugere correções para findings baseado na categoria e stack.
 */

import type { Finding, StackInfo } from "./types.js";

// ============================================================================
// Fix templates por categoria
// ============================================================================

const FIX_TEMPLATES: Record<string, (finding: Finding, stack: StackInfo) => { description: string; code?: string }> = {

  secrets: (_f, _s) => ({
    description: "Mover o valor para variável de ambiente e carregar via process.env.",
    code: `// ❌ Antes
const API_KEY = "sk_live_hardcoded_value";

// ✅ Depois
const API_KEY = process.env.API_KEY;

// Em .env (NUNCA commitar):
// API_KEY=sk_live_hardcoded_value

// Em .env.example (commitar):
// API_KEY=your_api_key_here`,
  }),

  xss: (_f, s) => ({
    description: "Sanitizar HTML antes de renderizar. Usar DOMPurify no frontend.",
    code: s.framework === "Next.js" || s.language === "TypeScript"
      ? `// ❌ Antes
<div dangerouslySetInnerHTML={{ __html: userContent }} />

// ✅ Depois
import DOMPurify from "dompurify";
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />`
      : `// ❌ Antes
element.innerHTML = userContent;

// ✅ Depois
import DOMPurify from "dompurify";
element.innerHTML = DOMPurify.sanitize(userContent);`,
  }),

  deserialization: (_f, s) => ({
    description: "Substituir eval/pickle por JSON.parse ou alternativa segura.",
    code: s.language === "Python"
      ? `# ❌ Antes
data = pickle.loads(user_input)
config = eval(user_string)

# ✅ Depois
import json
data = json.loads(user_input)
config = json.loads(user_string)`
      : `// ❌ Antes
const data = eval(userString);

// ✅ Depois
const data = JSON.parse(userString);`,
  }),

  logging: (_f, _s) => ({
    description: "Redactar campos sensíveis antes de logar.",
    code: `// ❌ Antes
console.log("Login:", req.body);
console.log("Token:", user.token);

// ✅ Depois
console.log("Login attempt for:", req.body.email);
// Nunca logar: password, token, api_key, credit card`,
  }),

  "error-messages": (_f, _s) => ({
    description: "Retornar mensagem genérica ao cliente, logar detalhes no servidor.",
    code: `// ❌ Antes
catch (error) {
  return Response.json({ error: error.message, stack: error.stack });
}

// ✅ Depois
catch (error) {
  console.error("[API Error]", error);
  return Response.json(
    { error: "Ocorreu um erro. Tente novamente." },
    { status: 500 }
  );
}`,
  }),

  identity: (_f, _s) => ({
    description: "Extrair user_id do JWT/session, nunca do req.body.",
    code: `// ❌ Antes
const { user_id, data } = await req.json();
await db.update({ user_id, ...data });

// ✅ Depois
const session = await getSession(req);
const user_id = session.user.id; // Vem do JWT
const { data } = await req.json();
await db.update({ user_id, ...data });`,
  }),

  cors: (_f, _s) => ({
    description: "Configurar whitelist explícita de origens.",
    code: `// ❌ Antes
cors({ origin: "*", credentials: true })

// ✅ Depois
cors({
  origin: [
    "https://meuapp.com",
    "https://www.meuapp.com",
  ],
  credentials: true,
})`,
  }),

  idor: (_f, _s) => ({
    description: "Adicionar filtro de ownership em todas as queries de mutação.",
    code: `// ❌ Antes
await db.post.update({ where: { id }, data });

// ✅ Depois
await db.post.update({
  where: { id, user_id: session.user.id },
  data,
});`,
  }),

  "mass-assignment": (_f, _s) => ({
    description: "Extrair apenas campos permitidos com destructuring.",
    code: `// ❌ Antes
await db.user.create({ data: { ...req.body } });

// ✅ Depois
const { name, email } = await req.json();
await db.user.create({ data: { name, email } });`,
  }),

  "input-validation": (_f, _s) => ({
    description: "Validar todo input com schema antes de usar.",
    code: `import { z } from "zod";

const CreateUserSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
  age: z.number().int().min(0).max(150).optional(),
});

// Na rota:
const body = CreateUserSchema.parse(await req.json());`,
  }),

  "rate-limiting": (_f, s) => ({
    description: "Aplicar rate limiting em rotas de autenticação.",
    code: s.framework === "Express"
      ? `import rateLimit from "express-rate-limit";

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5, // 5 tentativas
  message: { error: "Muitas tentativas. Tente novamente em 15 minutos." },
});

app.post("/api/login", loginLimiter, loginHandler);`
      : `// Instalar: npm install @upstash/ratelimit @upstash/redis
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, "15 m"),
});`,
  }),

  auth: (_f, _s) => ({
    description: "Usar bcrypt/argon2 para hash. Configurar cookies com httpOnly + secure.",
    code: `// ❌ Antes
import crypto from "crypto";
const hash = crypto.createHash("md5").update(password).digest("hex");

// ✅ Depois
import bcrypt from "bcrypt";
const hash = await bcrypt.hash(password, 12);
const valid = await bcrypt.compare(inputPassword, hash);

// Cookies:
res.cookie("session", token, {
  httpOnly: true,
  secure: true,
  sameSite: "strict",
  maxAge: 7 * 24 * 60 * 60 * 1000,
});`,
  }),

  ssrf: (_f, _s) => ({
    description: "Validar URL: apenas http/https, sem IPs privados.",
    code: `function isValidUrl(urlStr: string): boolean {
  try {
    const url = new URL(urlStr);
    if (!["http:", "https:"].includes(url.protocol)) return false;
    // Bloquear IPs privados
    const hostname = url.hostname;
    if (hostname === "localhost" || hostname === "127.0.0.1") return false;
    if (hostname.startsWith("10.") || hostname.startsWith("192.168.")) return false;
    if (hostname.startsWith("169.254.")) return false; // metadata
    return true;
  } catch {
    return false;
  }
}`,
  }),
};

// ============================================================================
// Suggest Fix
// ============================================================================

export function suggestFix(
  finding: Finding,
  stack: StackInfo,
): { description: string; code?: string } {
  const template = FIX_TEMPLATES[finding.category];
  if (template) {
    return template(finding, stack);
  }

  // Fallback genérico
  return {
    description: finding.recommendation,
  };
}
