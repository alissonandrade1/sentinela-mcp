# 🛡️ Sentinela — Infraestrutura de Segurança para Agentes de IA

> **Sentinela** é uma infraestrutura de segurança baseada em **MCP (Model Context Protocol)** que permite a qualquer agente de IA (Claude, Gemini, ChatGPT, e outros) auditar a segurança de projetos de software de forma estruturada, determinística e acionável.

---

## 🎯 Visão do Produto

O Sentinela **não é um chatbot de segurança**. Não é um prompt que recebe código e devolve texto.

O Sentinela é uma **camada de segurança que agentes de IA conseguem utilizar** para auditar, compreender e melhorar a segurança de aplicações — começando como um servidor MCP e evoluindo para uma plataforma completa.

### Evolução do produto

```
Hoje          → Documento com conhecimento e regras de segurança.

Fase 1 (MCP)  → Servidor MCP que expõe ferramentas de auditoria de segurança.
                Qualquer agente de IA conecta e utiliza.
                Análises determinísticas (grep, AST, filesystem, config, deps).
                Retorno de findings estruturados.
                A inteligência é do agente — o Sentinela fornece as ferramentas.

Fase 2 (Dash) → MCP + infraestrutura online + dashboard de segurança.
                Findings enviados para plataforma web.
                Visualização, histórico, evolução, acompanhamento.

Fase 3 (IA)   → MCP + Dashboard + IA especializada em segurança.
                Análise profunda, redução de falsos positivos,
                geração de patches, validação de correções.
```

### Princípios de produto

| Princípio | Detalhe |
|---|---|
| **Determinístico primeiro** | Sempre que uma verificação puder ser feita via análise de código, AST, config, filesystem, dependências ou outro mecanismo determinístico, essa abordagem tem prioridade sobre depender de IA. |
| **A IA é do agente** | Na Fase 1, o Sentinela NÃO possui IA própria. A inteligência de raciocínio e contextualização vem do agente que utiliza o MCP. O Sentinela fornece ferramentas, regras, análises e evidências. |
| **Findings estruturados** | Toda saída é estruturada em schema definido — nunca texto livre. Isso permite integração com dashboards, CI/CD, e outros sistemas. |
| **Knowledge base viva** | As regras de segurança (Seções 1-32 deste documento) são a base de conhecimento do Sentinela. Toda ferramenta MCP referencia essas regras. |
| **Universalidade** | Funciona com qualquer stack, framework, linguagem e dialeto SQL. |

---

## 🏗️ Arquitetura MCP

### O que é o MCP

O **Model Context Protocol (MCP)** é um protocolo aberto que permite que agentes de IA se conectem a serviços externos e utilizem ferramentas (tools). O Sentinela expõe suas capacidades como um servidor MCP.

### Como funciona

```
┌─────────────────────────┐
│   Agente de IA          │
│  (Claude, Gemini, etc.) │
│                         │
│  "Audite este projeto   │
│   com o Sentinela."     │
└──────────┬──────────────┘
           │ MCP Protocol
           ▼
┌─────────────────────────────────────────────────┐
│  Sentinela MCP Server                           │
│                                                 │
│  ┌──────────────┐  ┌──────────────────────────┐ │
│  │  Tools       │  │  Knowledge Base          │ │
│  │  (25+ tools) │  │  (Seções 1-32 deste doc) │ │
│  └──────┬───────┘  └────────────┬─────────────┘ │
│         │                       │               │
│  ┌──────▼───────────────────────▼─────────────┐ │
│  │  Analyzers (determinísticos)               │ │
│  │                                            │ │
│  │  • Grep / Regex patterns                   │ │
│  │  • AST parsing                             │ │
│  │  • Config file analysis                    │ │
│  │  • Filesystem checks                       │ │
│  │  • Dependency audit (npm/pip/etc.)         │ │
│  │  • SQL schema analysis                     │ │
│  │  • Security header checks                  │ │
│  └──────┬────────────────────────────────────┘ │
│         │                                       │
│  ┌──────▼────────────────────────────────────┐ │
│  │  Structured Findings                       │ │
│  │  (JSON schema padronizado)                 │ │
│  └──────┬────────────────────────────────────┘ │
└─────────┼───────────────────────────────────────┘
          │
          ▼
┌─────────────────────────┐    ┌──────────────────────┐
│  Agente recebe findings │───▶│  (Fase 2) Dashboard  │
│  e raciocina sobre eles │    │  Histórico, evolução │
└─────────────────────────┘    └──────────────────────┘
```

### Schema de Finding

Toda saída do Sentinela segue este schema:

```typescript
interface Finding {
  id: string;                          // ID único do finding (ex: "SENT-AUTH-001")
  rule_id: string;                     // Regra do knowledge base (ex: "2.1", "6.1", "18.2")
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;                    // Categoria (ex: "authentication", "xss", "idor")
  title: string;                       // Título curto e descritivo
  description: string;                 // Explicação do problema
  file?: string;                       // Arquivo afetado (caminho relativo)
  line?: number;                       // Linha do arquivo
  end_line?: number;                   // Linha final (para ranges)
  evidence?: string;                   // Trecho de código ou config que evidencia o problema
  recommendation: string;              // Como corrigir
  fix_example?: string;                // Exemplo de código corrigido
  confidence: 'high' | 'medium' | 'low';  // Confiança do finding
  detection_method: 'deterministic' | 'heuristic' | 'ai_assisted';
  cwe?: string;                        // CWE ID (ex: "CWE-79" para XSS)
  owasp?: string;                      // OWASP Top 10 (ex: "A03:2021")
  references?: string[];               // Links de referência
}

interface AuditReport {
  project: {
    name: string;
    path: string;
    stack: StackInfo;
  };
  timestamp: string;                   // ISO 8601
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
  checklist: ChecklistResult[];        // Seção 33 aplicada
  score: number;                       // 0-100 (postura de segurança)
}

interface StackInfo {
  language: string;
  framework: string;
  orm?: string;
  database: string;
  sql_dialect: string;
  auth_provider?: string;
  hosting?: string;
}

interface ChecklistResult {
  item: string;
  section: string;
  status: 'pass' | 'fail' | 'skip' | 'manual';
  finding_id?: string;                 // Referência ao finding se falhou
}
```

### Catálogo de ferramentas MCP

O Sentinela expõe as seguintes ferramentas via MCP:

#### Ferramentas de descoberta

| Ferramenta | Descrição | Seção de referência |
|---|---|---|
| `sentinela_detect_stack` | Detecta linguagem, framework, ORM, banco, auth, hosting do projeto | Stack Detection |
| `sentinela_get_rules` | Retorna as regras de segurança para uma categoria específica | Seções 1-32 |
| `sentinela_get_checklist` | Retorna o checklist completo de segurança | Seção 33 |

#### Ferramentas de auditoria (uma por domínio de segurança)

| Ferramenta | O que audita | Seção | Método |
|---|---|---|---|
| `sentinela_audit_identity` | Identidade aceita do frontend em mutações | 2.1 | Grep patterns |
| `sentinela_audit_mutations` | Mutations diretas client→banco | 2.2 | Grep/AST |
| `sentinela_audit_input_validation` | Limites de campo, schemas, constraints | 3 | Config + grep + SQL |
| `sentinela_audit_error_messages` | Mensagens que revelam estado interno | 4 | Grep patterns |
| `sentinela_audit_rate_limiting` | Rate limit em rotas sensíveis | 5 | Config + grep |
| `sentinela_audit_idor` | UPDATE/DELETE sem filtro de ownership | 6 | Grep/AST |
| `sentinela_audit_access_control` | RLS, policies, views, ownership queries | 7 | SQL schema + grep |
| `sentinela_audit_auth` | Auth customizada, hashing manual, JWT manual | 8 | Grep patterns |
| `sentinela_audit_honeypots` | Honeypots em formulários públicos | 9 | HTML/template grep |
| `sentinela_audit_uploads` | Upload sem validação de magic bytes/MIME/size | 10 | Grep/AST |
| `sentinela_audit_headers` | Security headers ausentes | 11 | Config + grep |
| `sentinela_audit_plans` | Limites de plano verificados server-side | 12 | Grep/AST |
| `sentinela_audit_secrets` | Credenciais hardcoded, .env no .gitignore | 13 | Grep + filesystem |
| `sentinela_audit_tests` | Existência de testes de segurança | 14 | Filesystem |
| `sentinela_audit_sql_constraints` | Colunas TEXT sem limite, FK ausentes | 15 | SQL schema |
| `sentinela_audit_csrf` | CSRF em formulários com cookies de sessão | 16 | Config + grep |
| `sentinela_audit_xss` | innerHTML, v-html, dangerouslySetInnerHTML, CSP | 18 | Grep patterns |
| `sentinela_audit_cors` | CORS com origin: *, wildcard, reflect | 19 | Config + grep |
| `sentinela_audit_mass_assignment` | Spread de body em queries, $fillable ausente | 20 | Grep/AST |
| `sentinela_audit_dependencies` | CVEs em dependências, lock files | 21 | npm audit + filesystem |
| `sentinela_audit_logging` | Senhas/tokens em logs, logging ausente | 22 | Grep patterns |
| `sentinela_audit_ssrf` | Fetch de URL do usuário sem validação | 23 | Grep/AST |
| `sentinela_audit_redirects` | Redirect aberto com input do usuário | 24 | Grep patterns |
| `sentinela_audit_privacy` | Endpoints de exclusão/exportação, LGPD | 25 | Filesystem + grep |
| `sentinela_audit_secrets_mgmt` | .env.example com valores reais, env check | 26 | Grep + filesystem |
| `sentinela_audit_webhooks` | Webhook sem verificação de assinatura | 27 | Grep/AST |
| `sentinela_audit_deserialization` | eval(), pickle.loads(), unserialize() | 28 | Grep patterns |
| `sentinela_audit_timing` | Comparação de secrets com ===, login timing | 29 | Grep patterns |
| `sentinela_audit_dns` | CNAME órfão, SPF, DMARC | 30 | DNS queries |
| `sentinela_audit_error_handling` | Routes sem try-catch, errors expostos | 31 | Grep/AST |
| `sentinela_audit_request_limits` | Body size, timeout, JSON depth | 32 | Config + grep |

#### Ferramentas de relatório

| Ferramenta | Descrição |
|---|---|
| `sentinela_audit_full` | Executa TODAS as auditorias acima e retorna `AuditReport` completo |
| `sentinela_generate_report` | Gera relatório formatado a partir de findings coletados |
| `sentinela_compare_reports` | Compara dois relatórios e mostra evolução (novos/resolvidos/pendentes) |

#### Ferramentas de correção (Fase 1 — assistidas pelo agente)

| Ferramenta | Descrição |
|---|---|
| `sentinela_suggest_fix` | Dado um finding, retorna sugestão de correção com código |
| `sentinela_validate_fix` | Dado um finding e o código corrigido, valida se a correção é suficiente |

### Método de detecção

Cada ferramenta de auditoria opera com um ou mais métodos determinísticos:

| Método | Como funciona | Quando usar |
|---|---|---|
| **Grep patterns** | Busca por padrões regex em arquivos de código | Padrões inseguros conhecidos (innerHTML, eval, etc.) |
| **AST analysis** | Parse da árvore sintática do código | Fluxo de dados, chamadas de função com argumentos específicos |
| **Config analysis** | Leitura e parse de arquivos de configuração | next.config.js, package.json, settings.py, etc. |
| **Filesystem checks** | Verificação de existência/ausência de arquivos | .gitignore, lock files, tests/, .env.example |
| **SQL schema analysis** | Parse de migrations e schema files | Constraints, RLS, VARCHAR limits |
| **Dependency audit** | Execução de `npm audit`, `pip audit`, etc. | CVEs conhecidas em dependências |
| **DNS queries** | Consultas DNS para verificar registros | SPF, DMARC, CNAME órfãos |
| **HTTP probing** | Verificação de headers em respostas HTTP | Security headers, CORS |

---

## 📋 Detecção Automática de Stack

Antes de aplicar qualquer regra, o Sentinela DEVE detectar:

| Aspecto | Exemplos | Como detectar |
|---|---|---|
| **Linguagem** | TypeScript, Python, Go, Ruby, PHP, Java, C# | Extensões de arquivo, `package.json`, `pyproject.toml`, `go.mod`, `Gemfile`, `pom.xml`, `*.csproj` |
| **Framework** | Next.js, Nuxt, SvelteKit, Express, FastAPI, Django, Rails, Laravel, Spring Boot, ASP.NET | Dependências, estrutura de diretórios, arquivos de config |
| **ORM / Query Builder** | Prisma, Drizzle, TypeORM, Sequelize, Knex, SQLAlchemy, Django ORM, ActiveRecord, Eloquent, Hibernate, Entity Framework | Dependências, schema files, migrations |
| **Banco de dados** | PostgreSQL (Supabase, Neon, Railway), MySQL (PlanetScale), MariaDB, SQLite (Turso, Litestream), SQL Server, Oracle | `.env`, config de conexão, SDK imports, connection strings |
| **Provedor de Auth** | Supabase Auth, Auth0, Clerk, NextAuth, Firebase Auth, Keycloak, Django Auth, Devise, Spring Security | Dependências, config files, imports |
| **Hosting / Deploy** | Vercel, Netlify, Railway, Fly.io, AWS, Azure, GCP, Docker | Config files (`vercel.json`, `Dockerfile`, etc.) |

### Detecção do dialeto SQL

O Sentinela DEVE identificar o dialeto SQL para adaptar a sintaxe das correções:

| Dialeto | Indicadores | UUID nativo | Timestamps | Auto-increment |
|---|---|---|---|---|
| **PostgreSQL** | `pg`, `@supabase`, `@neondatabase`, `postgres://` | `gen_random_uuid()` | `TIMESTAMPTZ` | `SERIAL` / `GENERATED` |
| **MySQL** | `mysql2`, `@planetscale`, `mysql://` | `UUID()` (string) | `DATETIME` / `TIMESTAMP` | `AUTO_INCREMENT` |
| **MariaDB** | `mariadb`, `mysql://` | `UUID()` | `DATETIME` / `TIMESTAMP` | `AUTO_INCREMENT` |
| **SQLite** | `better-sqlite3`, `@libsql`, `turso` | Gerar no app (UUID lib) | `TEXT` (ISO 8601) | `INTEGER PRIMARY KEY` |
| **SQL Server** | `mssql`, `tedious`, `sqlserver://` | `NEWID()` | `DATETIME2` / `DATETIMEOFFSET` | `IDENTITY` |
| **Oracle** | `oracledb`, `oracle://` | `SYS_GUID()` | `TIMESTAMP WITH TIME ZONE` | `GENERATED AS IDENTITY` |

> O Sentinela adapta a sintaxe das correções à stack e ao dialeto SQL detectados, mas as **regras de segurança são universais**.

---

## 📚 Knowledge Base — Regras de Segurança (Seções 1-32)

> As seções a seguir constituem a **base de conhecimento** do Sentinela.
> Cada seção define regras, padrões inseguros a detectar, e critérios de severidade.
> As ferramentas MCP de auditoria referenciam diretamente estas seções.
> Toda verificação marcada como "O que o Sentinela verifica" é um **contrato de implementação** para os analyzers do MCP.

---

## 1. Princípio Fundamental: Defense in Depth

Cada camada de segurança é **independentemente segura**. Se uma falhar, as demais ainda protegem.

```
Camada 1: WAF / CDN / Proxy Reverso
         → DDoS, bots conhecidos, geo-blocking
         → Exemplos: Cloudflare, AWS WAF, Fastly

Camada 2: Middleware / Edge
         → Security headers, rate limit inicial, CSRF, honeypot
         → Exemplos: middleware do framework, nginx config, edge functions

Camada 3: Rotas / Controllers server-side
         → Autenticação JWT, validação de schema, lógica de negócio
         → Exemplos: API Routes (Next.js), Views (Django), Controllers (Rails/Laravel)

Camada 4: Banco de dados (Policies / Constraints / Triggers / Views)
         → Última linha de defesa, independente de qualquer camada acima
         → RLS nativo (PostgreSQL/Supabase), Views filtradas, Triggers de validação

Camada 5: Testes automatizados
         → Valida as 4 camadas acima continuamente
```

### Regra de auditoria

O Sentinela DEVE verificar que **pelo menos 3 camadas** estão implementadas em qualquer projeto.
A ausência de qualquer camada é reportada como 🟠 Alta.

---

## 2. Zero Trust do Frontend

> **O usuário é tratado como adversário. Todo input é suspeito até ser validado no servidor.**

### 2.1 Identidade — NUNCA aceitar do frontend

**🔴 Crítica:** Campos de identidade (`user_id`, `owner_id`, `profile_id`, `auth_id`, `tenant_id`, `org_id`)
**NUNCA** podem vir do body, params, query string ou headers manipuláveis do cliente.

| Stack | ✅ Correto (server-side) | ❌ Incorreto (do cliente) |
|---|---|---|
| **Supabase** | `supabase.auth.getUser()` → `user.id` | `supabase.auth.getSession()` → `session.user.id` |
| **NextAuth** | `getServerSession(authOptions)` → `session.user.id` | `useSession()` → `session.user.id` (em API Route) |
| **Clerk** | `auth()` ou `currentUser()` server-side | `useUser()` para derivar ID em mutações |
| **Auth0** | Decodificar e validar JWT no backend | `user.sub` do frontend SDK |
| **Django** | `request.user` (após middleware de auth) | Campo `user_id` no POST body |
| **Rails** | `current_user` (via Devise/sessão server) | Parâmetro `user_id` na request |
| **FastAPI** | Dependência que valida JWT → `current_user` | `user_id` no body do request |
| **Express** | Middleware JWT → `req.user.id` | `req.body.userId` |
| **Laravel** | `Auth::id()` ou `$request->user()->id` | `$request->input('user_id')` |
| **Spring Boot** | `SecurityContextHolder` → `Authentication` | `@RequestParam userId` em endpoints de mutação |
| **ASP.NET** | `User.FindFirst(ClaimTypes.NameIdentifier)` | `[FromBody] userId` em endpoints de mutação |

#### O que o Sentinela verifica:

```
BUSCAR em todo o código:
  - req.body.user_id, req.body.userId, req.body.owner_id
  - req.params.userId, req.query.userId
  - request.data['user_id'], request.POST['user_id']
  - $request->input('user_id'), $_POST['user_id']
  - params[:user_id] (em contexto de mutação)
  - @RequestParam userId, @RequestBody contendo userId (em mutações)
  
QUALQUER ocorrência usada para identificar o autor de uma mutação = 🔴 Crítica
```

### 2.2 Mutations — Sempre via servidor

- **Nenhuma mutation** (INSERT / UPDATE / DELETE) deve ir diretamente do cliente para o banco.
- Toda mutation passa por uma rota/controller server-side.
- A rota: (1) autentica via JWT/sessão, (2) valida input com schema, (3) deriva identidade do token, (4) executa query.

| Stack | Camada de mutation |
|---|---|
| **Next.js** | `app/api/` routes ou Server Actions |
| **Nuxt** | `server/api/` routes |
| **SvelteKit** | `+server.ts` / `+page.server.ts` actions |
| **Express / Fastify** | Route handlers com middleware de auth |
| **Django** | Views com `@login_required` / DRF ViewSets |
| **Rails** | Controllers com `before_action :authenticate_user!` |
| **FastAPI** | Endpoints com `Depends(get_current_user)` |
| **Laravel** | Controllers com middleware `auth` |
| **Spring Boot** | `@RestController` com `@PreAuthorize` |
| **ASP.NET** | Controllers com `[Authorize]` attribute |

#### O que o Sentinela verifica:

```
BUSCAR por chamadas diretas do cliente ao banco:
  - supabase.from('...').insert/update/delete  (fora de server context)
  - prisma.*.create/update/delete              (em arquivos client-side)
  - fetch direto a endpoint externo de banco
  - Qualquer ORM call em arquivo marcado como 'use client' ou equivalente
  - Conexão direta ao banco exposta ao frontend (connection string no client)

QUALQUER mutation client-side direta ao banco = 🔴 Crítica
```

---

## 3. Validação de Input — Obrigatória em TODAS as camadas

### 3.1 Tripla validação

| Camada | Onde | Como | Propósito |
|---|---|---|---|
| **Frontend** | Componentes de formulário | `maxLength`, `min`, `max`, `pattern`, `required` | UX — feedback imediato |
| **Server-side** | Rotas / Controllers | Schema de validação (Zod, Yup, Joi, Pydantic, Marshmallow, Bean Validation, etc.) | Segurança — rejeitar payloads maliciosos |
| **Banco de dados** | Colunas / Constraints | `VARCHAR(n)`, `CHECK`, `NOT NULL`, `DEFAULT` | Integridade — última barreira |

### 3.2 Limites de campo padrão

Estes limites DEVEM ser definidos em um **arquivo central de constantes** no projeto:

| Campo | Min | Max | Regex / Formato |
|---|---|---|---|
| `name` / `nome` | 2 | 100 | `/^[\p{L}\s'\-\.]{2,100}$/u` |
| `email` | 5 | 254 | Validação RFC 5321 (usar lib) |
| `password` / `senha` | 8 | 128 | — |
| `title` / `titulo` | 2 | 200 | — |
| `description` / `descricao` | 0 | 500 | — |
| `phone` / `telefone` | 0 | 20 | `/^[+\d\s().-]{0,20}$/` |
| `slug` | 3 | 80 | `/^[a-z0-9-]+$/` |
| `url` / `image_url` | 10 | 2048 | Validação de URL (usar lib) |
| `notes` / `notas` | 0 | 300 | — |
| `address` / `endereco` | 0 | 300 | — |
| `uuid` / `id` | 36 | 36 | `/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i` |
| `time` / `horario` | 5 | 5 | `/^([01]\d|2[0-3]):([0-5]\d)$/` |
| `date` / `data` | 10 | 10 | `/^\d{4}-\d{2}-\d{2}$/` |

### 3.3 Arquivo central de constantes — Exemplo universal

```javascript
// lib/security/constants.js (ou .ts, .py, .rb, .java, .cs, etc.)

export const FIELD_LIMITS = {
  name:        { min: 2,  max: 100 },
  email:       { min: 5,  max: 254 },
  password:    { min: 8,  max: 128 },
  title:       { min: 2,  max: 200 },
  description: { min: 0,  max: 500 },
  phone:       { min: 0,  max: 20  },
  slug:        { min: 3,  max: 80  },
  url:         { min: 10, max: 2048 },
  notes:       { min: 0,  max: 300 },
  address:     { min: 0,  max: 300 },
};

export const FIELD_PATTERNS = {
  slug:    /^[a-z0-9-]+$/,
  time:    /^([01]\d|2[0-3]):([0-5]\d)$/,
  date:    /^\d{4}-\d{2}-\d{2}$/,
  uuid:    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  phone:   /^[+\d\s().-]{0,20}$/,
  name:    /^[\p{L}\s'\-\.]{2,100}$/u,
};
```

```python
# lib/security/constants.py (equivalente Python)

FIELD_LIMITS = {
    "name":        {"min": 2,  "max": 100},
    "email":       {"min": 5,  "max": 254},
    "password":    {"min": 8,  "max": 128},
    "title":       {"min": 2,  "max": 200},
    "description": {"min": 0,  "max": 500},
    "phone":       {"min": 0,  "max": 20},
    "slug":        {"min": 3,  "max": 80},
    "url":         {"min": 10, "max": 2048},
    "notes":       {"min": 0,  "max": 300},
    "address":     {"min": 0,  "max": 300},
}
```

#### O que o Sentinela verifica:

```
1. Existe arquivo central de constantes com limites de campo?
   NÃO = 🟠 Alta — criar arquivo e migrar limites

2. Todo input HTML tem maxLength definido?
   NÃO = 🟡 Média — adicionar maxLength

3. Todo schema server-side referencia os limites centralizados?
   NÃO = 🟡 Média — refatorar para usar constantes

4. Toda coluna VARCHAR/TEXT no banco tem limite definido?
   NÃO = 🟠 Alta — adicionar constraints via migration

5. Algum campo novo não tem limite definido?
   SIM = 🟠 Alta — definir limite antes de prosseguir
```

---

## 4. Mensagens de Erro — SEMPRE Genéricas

> **NUNCA revelar estado interno do sistema ao usuário.**

### 4.1 Mapeamento de mensagens seguras

| Situação real (interna, só logs) | Mensagem ao usuário (externa) |
|---|---|
| Usuário não encontrado no banco | "Credenciais inválidas." |
| Senha incorreta | "Credenciais inválidas." |
| E-mail já cadastrado | "Ocorreu um erro. Tente novamente." |
| Erro de constraint do banco | "Ocorreu um erro. Tente novamente." |
| Exceção não tratada / stack trace | "Ocorreu um erro. Tente novamente." |
| Violação de política de acesso | "Recurso não encontrado." |
| Token expirado | "Sessão expirada. Faça login novamente." |
| Rate limit atingido | "Muitas tentativas. Aguarde alguns minutos." |

### 4.2 Constantes de mensagem padronizadas

```javascript
// lib/security/constants.js

export const ERROR_MESSAGES = {
  INVALID_CREDENTIALS: "Credenciais inválidas.",
  GENERIC_ERROR:       "Ocorreu um erro. Tente novamente mais tarde.",
  TOO_MANY_REQUESTS:   "Muitas tentativas. Aguarde alguns minutos.",
  VALIDATION_ERROR:    "Dados inválidos. Verifique os campos.",
  UNAUTHORIZED:        "Acesso não autorizado.",
  FORBIDDEN:           "Sem permissão para esta ação.",
  NOT_FOUND:           "Recurso não encontrado.",
  SESSION_EXPIRED:     "Sessão expirada. Faça login novamente.",
  INVALID_FILE:        "Arquivo inválido. Verifique formato e tamanho.",
};
```

```python
# lib/security/constants.py

ERROR_MESSAGES = {
    "INVALID_CREDENTIALS": "Credenciais inválidas.",
    "GENERIC_ERROR":       "Ocorreu um erro. Tente novamente mais tarde.",
    "TOO_MANY_REQUESTS":   "Muitas tentativas. Aguarde alguns minutos.",
    "VALIDATION_ERROR":    "Dados inválidos. Verifique os campos.",
    "UNAUTHORIZED":        "Acesso não autorizado.",
    "FORBIDDEN":           "Sem permissão para esta ação.",
    "NOT_FOUND":           "Recurso não encontrado.",
    "SESSION_EXPIRED":     "Sessão expirada. Faça login novamente.",
    "INVALID_FILE":        "Arquivo inválido. Verifique formato e tamanho.",
}
```

### 4.3 Helpers de resposta padronizada

```javascript
// lib/security/responses.js

import { ERROR_MESSAGES } from './constants.js';

export function unauthorizedResponse() {
  return Response.json({ error: ERROR_MESSAGES.UNAUTHORIZED }, { status: 401 });
}

export function forbiddenResponse() {
  return Response.json({ error: ERROR_MESSAGES.FORBIDDEN }, { status: 403 });
}

export function notFoundResponse() {
  // Usar 404 para IDOR — não revelar existência do recurso
  return Response.json({ error: ERROR_MESSAGES.NOT_FOUND }, { status: 404 });
}

export function validationErrorResponse(fields = []) {
  // Lista APENAS os nomes dos campos com erro, NUNCA os valores enviados
  return Response.json(
    { error: ERROR_MESSAGES.VALIDATION_ERROR, fields },
    { status: 400 }
  );
}

export function rateLimitResponse() {
  return Response.json(
    { error: ERROR_MESSAGES.TOO_MANY_REQUESTS },
    { status: 429 }
  );
}

export function genericErrorResponse() {
  return Response.json(
    { error: ERROR_MESSAGES.GENERIC_ERROR },
    { status: 500 }
  );
}
```

#### O que o Sentinela verifica:

```
BUSCAR em todo o código:
  - error.message enviado ao cliente diretamente
  - stack traces em respostas HTTP
  - Mensagens que revelam existência de usuário/recurso
  - catch(err) { res.json({ error: err.message }) }
  - "Usuário não encontrado", "Senha incorreta", "E-mail já existe"
  - SQLException.getMessage() exposto ao cliente
  - PDOException message exposto ao cliente

QUALQUER mensagem que revela estado interno = 🟠 Alta
QUALQUER stack trace em resposta HTTP = 🔴 Crítica
```

---

## 5. Rate Limiting — Toda rota sensível

### 5.1 Configuração centralizada

```javascript
// lib/security/constants.js

export const RATE_LIMITS = {
  login: {
    window: 15 * 60,   // 15 minutos (em segundos)
    max: 5,
    hardStop: true,     // Bloqueia completamente após atingir
    identifier: 'ip',   // 'ip', 'user', 'ip+route'
  },
  register: {
    window: 60 * 60,   // 1 hora
    max: 3,
    hardStop: false,
    identifier: 'ip',
  },
  password_reset: {
    window: 60 * 60,
    max: 3,
    hardStop: true,
    identifier: 'ip',
  },
  mutation_authenticated: {
    window: 60,         // 1 minuto
    max: 60,
    hardStop: false,
    identifier: 'user',
  },
  public_action: {
    window: 60 * 60,
    max: 10,
    hardStop: true,
    identifier: 'ip',
  },
  global_catchall: {
    window: 60,
    max: 120,
    hardStop: false,
    identifier: 'ip',
  },
};
```

### 5.2 Persistência no banco de dados

O rate limiting DEVE ser persistido no banco para não resetar entre deploys/restarts.

#### PostgreSQL

```sql
CREATE TABLE IF NOT EXISTS rate_limits (
  id            UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  identifier    TEXT NOT NULL,
  route_key     TEXT NOT NULL,
  attempts      INTEGER DEFAULT 1,
  window_start  TIMESTAMPTZ DEFAULT NOW(),
  blocked_until TIMESTAMPTZ,
  UNIQUE(identifier, route_key)
);

CREATE INDEX idx_rate_limits_lookup
  ON rate_limits(identifier, route_key, window_start);

-- Limpeza periódica (executar via pg_cron ou cron externo)
CREATE OR REPLACE FUNCTION cleanup_expired_rate_limits()
RETURNS void AS $$
BEGIN
  DELETE FROM rate_limits
  WHERE window_start < NOW() - INTERVAL '2 hours'
    AND (blocked_until IS NULL OR blocked_until < NOW());
END;
$$ LANGUAGE plpgsql;
```

#### MySQL / MariaDB

```sql
CREATE TABLE IF NOT EXISTS rate_limits (
  id            CHAR(36) DEFAULT (UUID()) PRIMARY KEY,
  identifier    VARCHAR(255) NOT NULL,
  route_key     VARCHAR(100) NOT NULL,
  attempts      INT DEFAULT 1,
  window_start  DATETIME DEFAULT CURRENT_TIMESTAMP,
  blocked_until DATETIME NULL,
  UNIQUE KEY uq_rate_limit (identifier, route_key)
) ENGINE=InnoDB;

CREATE INDEX idx_rate_limits_lookup
  ON rate_limits(identifier, route_key, window_start);

-- Limpeza via EVENT SCHEDULER ou cron externo
CREATE EVENT IF NOT EXISTS cleanup_rate_limits
ON SCHEDULE EVERY 1 HOUR
DO
  DELETE FROM rate_limits
  WHERE window_start < DATE_SUB(NOW(), INTERVAL 2 HOUR)
    AND (blocked_until IS NULL OR blocked_until < NOW());
```

#### SQLite

```sql
CREATE TABLE IF NOT EXISTS rate_limits (
  id            TEXT PRIMARY KEY,       -- UUID gerado pela aplicação
  identifier    TEXT NOT NULL,
  route_key     TEXT NOT NULL,
  attempts      INTEGER DEFAULT 1,
  window_start  TEXT DEFAULT (datetime('now')),
  blocked_until TEXT,
  UNIQUE(identifier, route_key)
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_lookup
  ON rate_limits(identifier, route_key, window_start);

-- Limpeza via aplicação (SQLite não tem cron nativo)
-- DELETE FROM rate_limits
-- WHERE window_start < datetime('now', '-2 hours')
--   AND (blocked_until IS NULL OR blocked_until < datetime('now'));
```

#### SQL Server

```sql
CREATE TABLE rate_limits (
  id            UNIQUEIDENTIFIER DEFAULT NEWID() PRIMARY KEY,
  identifier    NVARCHAR(255) NOT NULL,
  route_key     NVARCHAR(100) NOT NULL,
  attempts      INT DEFAULT 1,
  window_start  DATETIMEOFFSET DEFAULT SYSDATETIMEOFFSET(),
  blocked_until DATETIMEOFFSET NULL,
  CONSTRAINT uq_rate_limit UNIQUE (identifier, route_key)
);

CREATE INDEX idx_rate_limits_lookup
  ON rate_limits(identifier, route_key, window_start);

-- Limpeza via SQL Server Agent Job ou cron externo
```

### 5.3 Implementação genérica de rate limit

```javascript
// lib/security/ratelimit.js

import { RATE_LIMITS } from './constants.js';

/**
 * Verifica e incrementa rate limit.
 * @param {object} db         - Cliente do banco (qualquer ORM ou query builder)
 * @param {string} identifier - IP ou user_id
 * @param {string} routeKey   - Chave do rate limit (ex: 'login')
 * @returns {{ allowed: boolean, remaining: number, retryAfter?: number }}
 */
export async function checkRateLimit(db, identifier, routeKey) {
  const config = RATE_LIMITS[routeKey] || RATE_LIMITS.global_catchall;
  const windowStart = new Date(Date.now() - config.window * 1000);

  // Implementação depende do ORM/driver usado
  // O Sentinela DEVE adaptar esta função à stack e dialeto SQL detectados
  // Exemplo conceitual com query parametrizada:

  const existing = await db.query(
    `SELECT attempts, window_start, blocked_until
     FROM rate_limits
     WHERE identifier = ?
       AND route_key = ?
       AND window_start > ?`,
    [identifier, routeKey, windowStart]
  );

  if (existing?.blocked_until && new Date(existing.blocked_until) > new Date()) {
    const retryAfter = Math.ceil(
      (new Date(existing.blocked_until) - new Date()) / 1000
    );
    return { allowed: false, remaining: 0, retryAfter };
  }

  if (existing && existing.attempts >= config.max) {
    if (config.hardStop) {
      const blockedUntil = new Date(Date.now() + config.window * 1000);
      await db.query(
        `UPDATE rate_limits SET blocked_until = ?
         WHERE identifier = ? AND route_key = ?`,
        [blockedUntil, identifier, routeKey]
      );
    }
    return { allowed: false, remaining: 0 };
  }

  // Upsert: adaptar ao dialeto SQL
  // PostgreSQL: ON CONFLICT ... DO UPDATE
  // MySQL:      ON DUPLICATE KEY UPDATE
  // SQLite:     ON CONFLICT ... DO UPDATE (v3.24+)
  // SQL Server: MERGE ... WHEN MATCHED ... WHEN NOT MATCHED ...
  // Ou usar lógica INSERT + UPDATE no código da aplicação

  const used = existing ? existing.attempts + 1 : 1;
  return { allowed: true, remaining: config.max - used };
}
```

> **Nota sobre placeholders:**
> - PostgreSQL usa `$1, $2, $3`
> - MySQL / MariaDB / SQLite usam `?`
> - SQL Server usa `@param1, @param2`
> - ORMs (Prisma, Sequelize, etc.) abstraem isso

#### O que o Sentinela verifica:

```
1. Rotas de login/registro/reset têm rate limiting?
   NÃO = 🔴 Crítica

2. Rate limit é persistido no banco (não em memória)?
   NÃO = 🟠 Alta

3. Configurações estão centralizadas em constantes?
   NÃO = 🟡 Média

4. Rate limit nativo do provedor de auth está ativo?
   NÃO = 🟡 Média
```

---

## 6. Proteção contra IDOR (Insecure Direct Object Reference)

### 6.1 Regra universal

Toda query de UPDATE / DELETE DEVE filtrar por **owner_id** (derivado do JWT) **além de** `id` do recurso.

```sql
-- ❌ INSEGURO — qualquer user pode alterar qualquer recurso (vale para TODO dialeto SQL)
UPDATE services SET name = ? WHERE id = ?;

-- ✅ SEGURO — só o dono pode alterar (vale para TODO dialeto SQL)
UPDATE services SET name = ? WHERE id = ? AND owner_id = ?;
-- owner_id = user_id extraído do JWT server-side
```

### 6.2 Regras complementares

- Retornar **404** (não 403) quando recurso não existe OU não pertence ao usuário
  → Não revelar existência de recursos de outros usuários
- Validar que `id` de parâmetro é **UUID válido** (ou formato correto do ID) antes de qualquer query
- Proteção de acesso no banco (RLS, views, triggers) é a última camada, mas verificação server-side é obrigatória (defense in depth)

### 6.3 Helper de verificação de ownership

```javascript
// lib/security/auth.js

/**
 * Verifica se o recurso pertence ao usuário autenticado.
 * Usar ANTES de executar UPDATE/DELETE.
 */
export function assertOwnership(resourceOwnerId, currentUserId) {
  if (!resourceOwnerId || !currentUserId) {
    return false;
  }
  return resourceOwnerId === currentUserId;
}

/**
 * Valida que um string é UUID válido.
 */
export function isValidUUID(value) {
  if (!value || typeof value !== 'string') return false;
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
}

/**
 * Valida que um string é ID inteiro válido (para bancos com auto-increment).
 */
export function isValidIntId(value) {
  const num = Number(value);
  return Number.isInteger(num) && num > 0;
}
```

#### O que o Sentinela verifica:

```
BUSCAR em todo o código:
  - UPDATE ... WHERE id = (sem filtro de owner_id)
  - DELETE ... WHERE id = (sem filtro de owner_id)
  - .update({ where: { id } })  sem owner_id
  - .delete({ where: { id } })  sem owner_id

QUALQUER mutation sem filtro de ownership = 🔴 Crítica (exceto tabelas públicas documentadas)

BUSCAR por respostas 403 em verificação de ownership:
  - status: 403, "Forbidden", "Sem permissão" em contexto de recurso não encontrado
  
QUALQUER 403 que deveria ser 404 = 🟡 Média (revela existência)
```

---

## 7. Controle de Acesso no Banco de Dados

O controle de acesso no banco é a **última linha de defesa**. A implementação varia por dialeto SQL.

### 7.1 Estratégias por dialeto

| Dialeto | Mecanismo nativo | Alternativa quando ausente |
|---|---|---|
| **PostgreSQL** | ✅ Row Level Security (RLS) nativo | — |
| **Supabase** | ✅ RLS + `auth.uid()` built-in | — |
| **MySQL 8+** | ⚠️ Sem RLS nativo | Views filtradas + stored procedures + app-level enforcement |
| **MariaDB** | ⚠️ Sem RLS nativo | Views filtradas + stored procedures + app-level enforcement |
| **SQLite** | ⚠️ Sem RLS nativo | App-level enforcement obrigatório (queries sempre com owner_id) |
| **SQL Server** | ✅ Row Level Security (via security policies) | — |
| **Oracle** | ✅ Virtual Private Database (VPD) | — |

### 7.2 PostgreSQL — Row Level Security (RLS)

Para projetos com PostgreSQL (incluindo Supabase, Neon, etc.):

```sql
-- ==========================================
-- RLS Templates — Adaptar para cada tabela
-- ==========================================

-- 1. Habilitar RLS
ALTER TABLE <table_name> ENABLE ROW LEVEL SECURITY;

-- 2. Forçar RLS mesmo para o dono da tabela (Supabase recomenda)
ALTER TABLE <table_name> FORCE ROW LEVEL SECURITY;

-- 3. Política de SELECT (apenas owner)
CREATE POLICY "select_own_<table>"
  ON <table_name> FOR SELECT
  USING (owner_id = auth.uid());
  -- Em PostgreSQL puro (sem Supabase): usar current_setting('app.current_user_id')::uuid

-- 4. Política de INSERT
CREATE POLICY "insert_own_<table>"
  ON <table_name> FOR INSERT
  WITH CHECK (owner_id = auth.uid());

-- 5. Política de UPDATE (USING + WITH CHECK obrigatório)
CREATE POLICY "update_own_<table>"
  ON <table_name> FOR UPDATE
  USING (owner_id = auth.uid())
  WITH CHECK (owner_id = auth.uid());

-- 6. Política de DELETE
CREATE POLICY "delete_own_<table>"
  ON <table_name> FOR DELETE
  USING (owner_id = auth.uid());
```

> **Nota:** Em PostgreSQL puro (sem Supabase), usar `current_setting('app.current_user_id')` como alternativa a `auth.uid()`, setando o valor na conexão via `SET app.current_user_id = '<uuid>'`.

### 7.3 SQL Server — Row Level Security

```sql
-- 1. Criar função de predicado
CREATE FUNCTION dbo.fn_security_predicate(@owner_id UNIQUEIDENTIFIER)
RETURNS TABLE
WITH SCHEMABINDING
AS
  RETURN SELECT 1 AS result
  WHERE @owner_id = CAST(SESSION_CONTEXT(N'user_id') AS UNIQUEIDENTIFIER);

-- 2. Criar política de segurança
CREATE SECURITY POLICY dbo.policy_<table_name>
  ADD FILTER PREDICATE dbo.fn_security_predicate(owner_id) ON dbo.<table_name>,
  ADD BLOCK PREDICATE dbo.fn_security_predicate(owner_id) ON dbo.<table_name>
  WITH (STATE = ON);

-- 3. Na aplicação, setar contexto antes de cada query:
-- EXEC sp_set_session_context @key = N'user_id', @value = @current_user_id;
```

### 7.4 Oracle — Virtual Private Database (VPD)

```sql
-- 1. Criar função de política
CREATE OR REPLACE FUNCTION vpd_owner_policy(
  p_schema IN VARCHAR2,
  p_table  IN VARCHAR2
) RETURN VARCHAR2 AS
BEGIN
  RETURN 'owner_id = SYS_CONTEXT(''APP_CTX'', ''USER_ID'')';
END;

-- 2. Aplicar política
BEGIN
  DBMS_RLS.ADD_POLICY(
    object_schema   => 'APP_SCHEMA',
    object_name     => '<TABLE_NAME>',
    policy_name     => 'owner_access_policy',
    function_schema => 'APP_SCHEMA',
    policy_function => 'vpd_owner_policy',
    statement_types => 'SELECT, INSERT, UPDATE, DELETE'
  );
END;
```

### 7.5 MySQL / MariaDB / SQLite — Alternativas sem RLS nativo

Para bancos **sem RLS nativo**, a proteção de acesso DEVE ser implementada em **múltiplas camadas**:

#### Estratégia 1: Views filtradas (MySQL / MariaDB)

```sql
-- View que filtra por owner_id (requer setar variável de sessão na app)
CREATE VIEW v_my_services AS
  SELECT * FROM services
  WHERE owner_id = @current_user_id;

-- Na aplicação, antes de cada query:
-- SET @current_user_id = '<uuid-do-usuario>';
-- SELECT * FROM v_my_services;  -- já filtrado
```

#### Estratégia 2: Stored Procedures (MySQL / MariaDB)

```sql
-- Toda mutação via procedure que recebe user_id como parâmetro
DELIMITER //
CREATE PROCEDURE sp_update_service(
  IN p_user_id CHAR(36),
  IN p_service_id CHAR(36),
  IN p_name VARCHAR(100)
)
BEGIN
  UPDATE services
  SET name = p_name
  WHERE id = p_service_id AND owner_id = p_user_id;

  IF ROW_COUNT() = 0 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Not found';
  END IF;
END //
DELIMITER ;
```

#### Estratégia 3: Enforcement na aplicação (todos os bancos)

```javascript
// Para bancos sem RLS, TODA query DEVE incluir owner_id

// ❌ INSEGURO
const service = await db.query('SELECT * FROM services WHERE id = ?', [serviceId]);

// ✅ SEGURO — sempre filtrar por owner_id
const service = await db.query(
  'SELECT * FROM services WHERE id = ? AND owner_id = ?',
  [serviceId, currentUserId]
);
```

> **Regra:** Para bancos sem RLS nativo, o Sentinela DEVE verificar que **100% das queries** de dados de usuário incluem filtro `owner_id`. Esta verificação é 🔴 Crítica.

### 7.6 Variações comuns (multi-dialeto)

```sql
-- Tabela com dados públicos para leitura (ex: perfis públicos)
-- PostgreSQL RLS:
CREATE POLICY "public_select" ON profiles FOR SELECT USING (is_public = true);
CREATE POLICY "owner_select" ON profiles FOR SELECT USING (owner_id = auth.uid());

-- MySQL/MariaDB/SQLite (na aplicação):
-- IF (is_public) → permitir SELECT sem owner_id
-- ELSE → exigir owner_id no WHERE

-- Tabela multi-tenant (filtro por organização)
-- Válido para TODOS os dialetos:
SELECT * FROM resources
WHERE org_id IN (
  SELECT org_id FROM org_members WHERE user_id = ?
);
```

### 7.7 Auditoria de acesso no banco

```sql
-- PostgreSQL: verificar quais tabelas têm RLS ativo
SELECT schemaname, tablename, rowsecurity
FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;

-- MySQL: listar views de segurança
SELECT table_name, view_definition
FROM information_schema.views WHERE table_schema = DATABASE();

-- SQL Server: verificar security policies
SELECT name, is_enabled FROM sys.security_policies;

-- Para TODOS: listar tabelas que contêm owner_id
SELECT table_name
FROM information_schema.columns
WHERE column_name = 'owner_id' AND table_schema = 'public';
-- Toda tabela com owner_id DEVE ter proteção de acesso ativa
```

#### O que o Sentinela verifica:

```
1. Identificar o dialeto SQL do projeto
2. Para cada tabela com dados de usuário:

   SE PostgreSQL:
   - RLS está habilitado? NÃO = 🔴 Crítica
   - Tem política de SELECT? NÃO = 🔴 Crítica
   - Tem política de INSERT com WITH CHECK? NÃO = 🟠 Alta
   - Tem política de UPDATE com USING + WITH CHECK? NÃO = 🟠 Alta
   - Tem política de DELETE? NÃO = 🟠 Alta
   - Políticas usam auth.uid() ou current_setting? NÃO = 🔴 Crítica
   
   SE SQL Server:
   - Security Policy existe? NÃO = 🔴 Crítica
   - Filter + Block predicate configurados? NÃO = 🟠 Alta
   
   SE Oracle:
   - VPD policy existe? NÃO = 🔴 Crítica
   
   SE MySQL / MariaDB / SQLite:
   - Views filtradas OU stored procedures existem? RECOMENDADO (🟡 Média se ausente)
   - TODAS as queries incluem owner_id no WHERE? NÃO = 🔴 Crítica
   - Enforcement na aplicação está documentado? NÃO = 🟠 Alta

3. Role anônimo / sem autenticação pode acessar dados protegidos? SIM = 🔴 Crítica
```

---

## 8. Autenticação — Diretrizes Universais

### 8.1 Regra fundamental

> **ZERO código customizado de autenticação.** Usar provedor gerenciado.

| Provedor | Integração |
|---|---|
| **Supabase Auth** | SDK nativo, RLS integrado |
| **Auth0** | SDK + middleware de validação JWT |
| **Clerk** | SDK + middleware |
| **NextAuth / Auth.js** | Providers + adapters |
| **Firebase Auth** | Admin SDK para validação server-side |
| **Keycloak** | OIDC + middleware |
| **Django Auth** | Built-in, com middleware de sessão |
| **Devise (Rails)** | Gem com configuração |
| **Spring Security** | Configuração + JWT filters |
| **ASP.NET Identity** | Middleware + claims-based auth |

### 8.2 Configurações obrigatórias

| Configuração | Status | Onde configurar |
|---|---|---|
| Confirmação de e-mail | ✅ Obrigatório | Dashboard do provedor |
| Rate limiting nativo | ✅ Obrigatório | Dashboard do provedor |
| Access Token — expiração curta | ✅ 1 hora ou menos | Dashboard do provedor |
| Refresh Token — rotativo | ✅ Obrigatório | Dashboard do provedor |
| Proteção contra senhas vazadas (HIBP) | ✅ Quando disponível | Dashboard do provedor |
| MFA / 2FA | 🟡 Recomendado | Dashboard do provedor |
| Passwordless / Magic Link | 🔵 Opcional | Dashboard do provedor |

### 8.3 Anti-patterns de autenticação

```
🔴 Crítica — O Sentinela DEVE reportar:
  - Hashing manual de senhas (bcrypt.hash, argon2, etc. fora do provedor)
  - Geração manual de JWT (jwt.sign, jose.sign, etc. fora do provedor)
  - Sessões manuais em banco sem provedor
  - Comparação de senhas em texto plano
  - Token de sessão em localStorage (XSS)
  - Cookies de auth sem flags HttpOnly, Secure, SameSite
  - Queries SQL com senha em texto plano:
    SELECT * FROM users WHERE email = ? AND password = ?
```

#### O que o Sentinela verifica:

```
BUSCAR por:
  - bcrypt, argon2, scrypt (fora de dependência do provedor)
  - jwt.sign, jwt.verify (fora de middleware do provedor)
  - localStorage.setItem('token'  ou  sessionStorage.setItem('token'
  - cookie sem HttpOnly/Secure/SameSite
  - Formulário de login sem CSRF token
  - SELECT ... WHERE password = (comparação de senha em SQL)
  - MD5(), SHA1(), SHA2() usados para hashing de senhas

QUALQUER auth customizada = 🔴 Crítica
```

---

## 9. Honeypots — Proteção contra Bots

### 9.1 Campo honeypot em formulários

```html
<!-- Campo oculto via CSS — bots preenchem, humanos não veem -->
<!-- NÃO usar type="hidden" — bots detectam. Usar CSS para ocultar -->
<div style="position: absolute; left: -9999px; opacity: 0; height: 0; overflow: hidden;"
     aria-hidden="true">
  <label for="_hp_field">Deixe vazio</label>
  <input
    id="_hp_field"
    name="_hp"
    type="text"
    tabindex="-1"
    autocomplete="off"
  />
</div>
```

### 9.2 Verificação server-side

```javascript
// lib/security/honeypot.js

/**
 * Verifica se o campo honeypot foi preenchido.
 * Se foi, a request veio de um bot — ignorar silenciosamente.
 */
export function isBot(body, fieldName = '_hp') {
  const value = body?.[fieldName];
  return value !== undefined && value !== null && value !== '';
}

/**
 * Middleware/handler: se bot, retornar 200 falso (não alertar o bot)
 */
export function handleHoneypot(body, fieldName = '_hp') {
  if (isBot(body, fieldName)) {
    return {
      isBot: true,
      response: { success: true, message: "Operação realizada." }
    };
  }
  return { isBot: false };
}
```

### 9.3 Rotas honeypot (decoy routes)

```javascript
// Rotas falsas que atacantes/scanners procuram
const DECOY_ROUTES = [
  '/admin', '/wp-admin', '/wp-login.php', '/.env',
  '/config.php', '/phpinfo.php', '/api/debug', '/api/test',
  '/.git/config', '/backup.sql', '/phpmyadmin',
];

// Para cada rota, o handler deve:
// 1. Retornar status 200 (não alertar o atacante)
// 2. Retornar dados falsos verossímeis
// 3. Logar IP + rota + timestamp + user-agent em tabela security_events
```

### 9.4 Tabela de eventos de segurança (multi-dialeto)

#### PostgreSQL
```sql
CREATE TABLE IF NOT EXISTS security_events (
  id          UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  event_type  TEXT NOT NULL,
  ip_address  INET,
  route       TEXT,
  user_agent  TEXT,
  payload     JSONB,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_security_events_type_date ON security_events(event_type, created_at DESC);
ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
```

#### MySQL / MariaDB
```sql
CREATE TABLE IF NOT EXISTS security_events (
  id          CHAR(36) DEFAULT (UUID()) PRIMARY KEY,
  event_type  VARCHAR(50) NOT NULL,
  ip_address  VARCHAR(45),       -- Suporta IPv6
  route       VARCHAR(500),
  user_agent  VARCHAR(500),
  payload     JSON,
  created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_security_events_type_date (event_type, created_at DESC)
) ENGINE=InnoDB;
```

#### SQLite
```sql
CREATE TABLE IF NOT EXISTS security_events (
  id          TEXT PRIMARY KEY,    -- UUID gerado pela app
  event_type  TEXT NOT NULL,
  ip_address  TEXT,
  route       TEXT,
  user_agent  TEXT,
  payload     TEXT,                -- JSON como string
  created_at  TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_security_events_type_date
  ON security_events(event_type, created_at DESC);
```

#### SQL Server
```sql
CREATE TABLE security_events (
  id          UNIQUEIDENTIFIER DEFAULT NEWID() PRIMARY KEY,
  event_type  NVARCHAR(50) NOT NULL,
  ip_address  NVARCHAR(45),
  route       NVARCHAR(500),
  user_agent  NVARCHAR(500),
  payload     NVARCHAR(MAX),     -- JSON como string
  created_at  DATETIMEOFFSET DEFAULT SYSDATETIMEOFFSET()
);
CREATE INDEX idx_security_events_type_date
  ON security_events(event_type, created_at DESC);
```

#### O que o Sentinela verifica:

```
1. Formulários públicos (login, registro, contato) têm campo honeypot?
   NÃO = 🟡 Média

2. Rotas decoy estão configuradas?
   NÃO = 🔵 Baixa (recomendado, não obrigatório)

3. Eventos de segurança estão sendo logados?
   NÃO = 🟡 Média
```

---

## 10. Upload de Arquivos — Validação Completa

### 10.1 Checklist de validação (quando upload existir)

| Etapa | Verificação | Onde |
|---|---|---|
| 1 | Tamanho máximo (ex: 5MB) | Server-side, ANTES de ler buffer |
| 2 | Extensão permitida (.jpg, .jpeg, .png) | Server-side |
| 3 | MIME type real | Server-side (magic bytes) |
| 4 | Magic bytes do arquivo | Server-side |
| 5 | Dimensões máximas (ex: 4096×4096px) | Server-side |
| 6 | Comprimir / reprocessar | Server-side (Sharp, Pillow, etc.) |
| 7 | Nome seguro gerado pelo servidor | Server-side (UUID + extensão) |
| 8 | Size lock no banco | Banco (salvar tamanho, verificar em acesso) |

### 10.2 Magic bytes de referência

| Formato | Magic bytes (hex) | Offset |
|---|---|---|
| JPEG | `FF D8 FF` | 0 |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | 0 |
| GIF | `47 49 46 38` | 0 |
| WebP | `52 49 46 46 ?? ?? ?? ?? 57 45 42 50` | 0 |
| PDF | `25 50 44 46` | 0 |
| SVG | `3C 3F 78 6D 6C` ou `3C 73 76 67` | 0 |

### 10.3 Implementação de referência

```javascript
// lib/security/image-validator.js

const ALLOWED_TYPES = {
  'image/jpeg': { extensions: ['.jpg', '.jpeg'], magic: [0xFF, 0xD8, 0xFF] },
  'image/png':  { extensions: ['.png'],          magic: [0x89, 0x50, 0x4E, 0x47] },
};

const IMAGE_LIMITS = {
  maxSizeBytes: 5 * 1024 * 1024,  // 5MB
  maxWidth:     4096,
  maxHeight:    4096,
  allowedTypes: Object.keys(ALLOWED_TYPES),
};

export function validateImage(buffer, originalName, mimeType) {
  if (buffer.length > IMAGE_LIMITS.maxSizeBytes) {
    return { valid: false, error: 'size_exceeded' };
  }
  if (!IMAGE_LIMITS.allowedTypes.includes(mimeType)) {
    return { valid: false, error: 'invalid_type' };
  }
  const ext = '.' + originalName.split('.').pop().toLowerCase();
  const typeConfig = ALLOWED_TYPES[mimeType];
  if (!typeConfig.extensions.includes(ext)) {
    return { valid: false, error: 'extension_mismatch' };
  }
  const magic = typeConfig.magic;
  for (let i = 0; i < magic.length; i++) {
    if (buffer[i] !== magic[i]) {
      return { valid: false, error: 'magic_bytes_mismatch' };
    }
  }
  return { valid: true };
}

export function generateSafeFilename(mimeType) {
  const ext = ALLOWED_TYPES[mimeType]?.extensions[0] || '.bin';
  return `${crypto.randomUUID()}${ext}`;
}
```

#### O que o Sentinela verifica:

```
SE o projeto tem upload de arquivos:

1. Validação de magic bytes existe? NÃO = 🔴 Crítica
2. Tamanho verificado ANTES de processar? NÃO = 🟠 Alta
3. Nome do arquivo gerado pelo servidor? NÃO = 🟠 Alta
4. MIME type verificado contra magic bytes? NÃO = 🟠 Alta
5. Imagem reprocessada/comprimida server-side? NÃO = 🟡 Média
6. Extensões permitidas são restritas? NÃO = 🟠 Alta
```

---

## 11. Security Headers

### 11.1 Headers obrigatórios

```javascript
const SECURITY_HEADERS = {
  'X-Content-Type-Options':    'nosniff',
  'X-Frame-Options':           'DENY',
  'X-XSS-Protection':          '1; mode=block',
  'Referrer-Policy':           'strict-origin-when-cross-origin',
  'Permissions-Policy':        'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  // Content-Security-Policy — adaptar ao projeto
};
```

### 11.2 Onde configurar por stack

| Stack | Onde configurar |
|---|---|
| **Next.js** | `middleware.ts` ou `next.config.js` → `headers()` |
| **Nuxt** | `nuxt.config.ts` → `routeRules` ou server middleware |
| **SvelteKit** | `hooks.server.ts` → `handle()` |
| **Express** | Middleware `helmet` ou manual |
| **Django** | `SecurityMiddleware` + settings |
| **Rails** | `config.action_dispatch.default_headers` |
| **FastAPI** | Middleware customizado |
| **Spring Boot** | `SecurityFilterChain` / `WebSecurityConfigurerAdapter` |
| **ASP.NET** | Middleware ou `web.config` |
| **Nginx / Apache** | `add_header` / `Header set` no config |

#### O que o Sentinela verifica:

```
1. X-Content-Type-Options presente? NÃO = 🟡 Média
2. X-Frame-Options presente? NÃO = 🟡 Média
3. Strict-Transport-Security presente? NÃO = 🟠 Alta
4. Content-Security-Policy presente? NÃO = 🟡 Média
5. Permissions-Policy presente? NÃO = 🔵 Baixa
```

---

## 12. Separação por Planos (SaaS) — Quando aplicável

### 12.1 Regras

- Features por plano definidas em **arquivo central** de constantes
- Verificação em **server-side + banco** (nunca apenas frontend)
- **NUNCA** confiar em `plan_id` do frontend — verificar no banco via JWT

### 12.2 Implementação de referência

```javascript
// lib/security/constants.js

export const PLAN_LIMITS = {
  free: {
    maxServices: 3,
    maxCustomers: 50,
    maxBookingsPerDay: 10,
    features: ['basic_booking'],
  },
  pro: {
    maxServices: 20,
    maxCustomers: 500,
    maxBookingsPerDay: 100,
    features: ['basic_booking', 'analytics', 'custom_domain'],
  },
  enterprise: {
    maxServices: Infinity,
    maxCustomers: Infinity,
    maxBookingsPerDay: Infinity,
    features: ['basic_booking', 'analytics', 'custom_domain', 'api_access', 'white_label'],
  },
};
```

```javascript
// lib/security/plans.js

import { PLAN_LIMITS } from './constants.js';

/**
 * Verifica se o usuário tem acesso a uma feature.
 * O plano é buscado do BANCO (via user_id do JWT), nunca do frontend.
 */
export async function checkFeatureAccess(db, userId, featureName) {
  const user = await db.query(
    'SELECT plan FROM users WHERE id = ?',
    [userId]
  );
  if (!user) return { allowed: false, reason: 'user_not_found' };

  const planConfig = PLAN_LIMITS[user.plan];
  if (!planConfig) return { allowed: false, reason: 'invalid_plan' };

  return {
    allowed: planConfig.features.includes(featureName),
    plan: user.plan,
  };
}
```

#### O que o Sentinela verifica:

```
SE o projeto tem planos/tiers:

1. Limites definidos em arquivo central? NÃO = 🟠 Alta
2. Verificação é feita server-side? NÃO = 🔴 Crítica
3. Plano é buscado do banco (não do frontend)? NÃO = 🔴 Crítica
4. Banco tem constraint/trigger para limites? NÃO = 🟡 Média
```

---

## 13. Auditoria de Credenciais

### 13.1 Antes de qualquer commit

```bash
# 1. Verificar que .env está no .gitignore
git check-ignore -v .env .env.local .env.production .env.development

# 2. Buscar credenciais hardcoded nos arquivos rastreados
git grep -nI "eyJhbGci"           # JWT tokens
git grep -nI "password\s*[:=]"    # Passwords hardcoded
git grep -nI "secret\s*[:=]"      # Secrets hardcoded
git grep -nI "api[_-]key\s*[:=]"  # API keys hardcoded
git grep -nI "sk_live_"           # Stripe live keys
git grep -nI "sk_test_"           # Stripe test keys
git grep -nI "AKIA"               # AWS Access Key IDs
git grep -nI "ghp_"               # GitHub Personal Access Tokens
git grep -nI "gho_"               # GitHub OAuth Tokens
git grep -nI "mysql://\|postgres://\|mongodb://\|sqlserver://"  # Connection strings
git grep -nI "supabase.co"        # URLs de Supabase
git grep -nI "DATABASE_URL.*=.*@"  # Connection strings com credenciais

# 3. Listar arquivos que serão commitados e revisar
git diff --cached --name-only
```

### 13.2 Arquivos que JAMAIS devem ser commitados

```
.env
.env.*
*.pem
*.key
*.p12
*.pfx
id_rsa*
*.secret
credentials.json
service-account*.json
*.sqlite (bancos de desenvolvimento com dados sensíveis)
*.db (bancos SQLite de desenvolvimento)
```

### 13.3 .gitignore mínimo de segurança

```gitignore
# Variáveis de ambiente
.env
.env.*
!.env.example

# Chaves e certificados
*.pem
*.key
*.p12
*.pfx

# Credenciais
credentials.json
service-account*.json

# Bancos de dados locais
*.sqlite
*.sqlite3
*.db
*.mdb

# Backups de banco
*.sql.bak
*.dump
*.sql.gz
```

#### O que o Sentinela verifica:

```
1. .env está no .gitignore? NÃO = 🔴 Crítica
2. Há credenciais hardcoded no código? SIM = 🔴 Crítica
3. Há tokens/JWTs em arquivos commitados? SIM = 🔴 Crítica
4. Há connection strings com senha em arquivos commitados? SIM = 🔴 Crítica
5. Há arquivos de banco de dados (.sqlite, .db) no repositório? SIM = 🟠 Alta
6. .gitignore cobre todos os padrões sensíveis? NÃO = 🟠 Alta
```

---

## 14. Testes de Segurança

### 14.1 Regra: nova feature = novo teste

Todo novo endpoint/feature DEVE ter testes em `tests/security/`:

| Tipo de teste | O que valida | Exemplo |
|---|---|---|
| **IDOR** | Usuário A não acessa recurso do B | `PUT /api/services/:id` com token do user B |
| **Input overflow** | Campos acima do limite são rejeitados | `name` com 1000 chars → 400 |
| **Schema validation** | Payloads inválidos são rejeitados | Campo obrigatório ausente → 400 |
| **Error messages** | Mensagens são genéricas | Login falho → "Credenciais inválidas" (não "Senha incorreta") |
| **Access control** | Usuário sem auth / outro user não acessa dados | Query sem token → 401; query de outro user → 0 rows |
| **Rate limiting** | Excesso de requests é bloqueado | 10 requests de login → 429 |
| **Auth bypass** | Request sem token é rejeitada | `POST /api/services` sem header → 401 |
| **SQL Injection** | Inputs maliciosos não quebram queries | `'; DROP TABLE users; --` → tratado seguramente |

### 14.2 Estrutura de testes

```
tests/
├── security/
│   ├── input-validation.test.{js,ts,py}   — Limites de campo, schemas
│   ├── idor.test.{js,ts,py}               — Acesso cruzado entre usuários
│   ├── auth.test.{js,ts,py}               — Bypass de autenticação
│   ├── access-control.test.{js,ts,py}     — Políticas de acesso no banco
│   ├── error-messages.test.{js,ts,py}     — Mensagens genéricas
│   ├── rate-limiting.test.{js,ts,py}      — Rate limit funcional
│   └── sql-injection.test.{js,ts,py}      — Proteção contra injection
```

### 14.3 Comandos obrigatórios antes de commit

```bash
# AMBOS devem passar antes de qualquer commit
npm run test:security   # ou pytest tests/security/ ou equivalente
npm run build           # ou equivalente do framework
```

#### O que o Sentinela verifica:

```
1. Diretório tests/security/ existe? NÃO = 🟠 Alta
2. Há testes para cada endpoint de mutação? NÃO = 🟠 Alta
3. Testes de IDOR existem? NÃO = 🔴 Crítica
4. Testes de controle de acesso existem? NÃO = 🟠 Alta
5. Testes de SQL injection existem? NÃO = 🟠 Alta
6. Script de teste de segurança está configurado? NÃO = 🟡 Média
```

---

## 15. SQL — Constraints e Boas Práticas (Multi-Dialeto)

### 15.1 Toda coluna com input do usuário DEVE ter constraint

#### PostgreSQL
```sql
CREATE TABLE services (
  id          UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  owner_id    UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  name        VARCHAR(100) NOT NULL CHECK (char_length(name) >= 2),
  slug        VARCHAR(80) NOT NULL CHECK (slug ~ '^[a-z0-9-]+$'),
  description VARCHAR(500),
  phone       VARCHAR(20),
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  updated_at  TIMESTAMPTZ DEFAULT NOW()
);
```

#### MySQL / MariaDB
```sql
CREATE TABLE services (
  id          CHAR(36) DEFAULT (UUID()) PRIMARY KEY,
  owner_id    CHAR(36) NOT NULL,
  name        VARCHAR(100) NOT NULL,
  slug        VARCHAR(80) NOT NULL,
  description VARCHAR(500),
  phone       VARCHAR(20),
  created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT chk_name_min CHECK (CHAR_LENGTH(name) >= 2),
  CONSTRAINT chk_slug_format CHECK (slug REGEXP '^[a-z0-9-]+$'),
  FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY uq_slug (slug)
) ENGINE=InnoDB;
```

#### SQLite
```sql
CREATE TABLE services (
  id          TEXT PRIMARY KEY,       -- UUID gerado pela app
  owner_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name        TEXT NOT NULL CHECK (length(name) BETWEEN 2 AND 100),
  slug        TEXT NOT NULL UNIQUE CHECK (length(slug) BETWEEN 3 AND 80),
  description TEXT CHECK (length(description) <= 500),
  phone       TEXT CHECK (length(phone) <= 20),
  created_at  TEXT DEFAULT (datetime('now')),
  updated_at  TEXT DEFAULT (datetime('now'))
);
```

#### SQL Server
```sql
CREATE TABLE services (
  id          UNIQUEIDENTIFIER DEFAULT NEWID() PRIMARY KEY,
  owner_id    UNIQUEIDENTIFIER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name        NVARCHAR(100) NOT NULL CONSTRAINT chk_name_min CHECK (LEN(name) >= 2),
  slug        NVARCHAR(80) NOT NULL UNIQUE,
  description NVARCHAR(500),
  phone       NVARCHAR(20),
  created_at  DATETIMEOFFSET DEFAULT SYSDATETIMEOFFSET(),
  updated_at  DATETIMEOFFSET DEFAULT SYSDATETIMEOFFSET()
);
```

### ❌ INCORRETO — sem limites (vale para TODOS os dialetos)
```sql
CREATE TABLE services (
  id          ...,
  owner_id    ...,          -- sem FK / sem NOT NULL!
  name        TEXT,         -- sem limite!
  slug        TEXT,         -- sem validação!
  description TEXT,         -- sem limite!
  phone       TEXT,         -- sem limite!
  created_at  ...
);
```

### 15.2 Trigger de updated_at automático

#### PostgreSQL
```sql
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER set_updated_at
  BEFORE UPDATE ON <table_name>
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
```

#### MySQL / MariaDB
```sql
-- MySQL atualiza automaticamente com ON UPDATE CURRENT_TIMESTAMP na definição da coluna
-- Definir na criação da tabela:
--   updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
```

#### SQLite
```sql
CREATE TRIGGER set_updated_at_<table_name>
  AFTER UPDATE ON <table_name>
BEGIN
  UPDATE <table_name> SET updated_at = datetime('now')
  WHERE id = NEW.id;
END;
```

#### SQL Server
```sql
CREATE TRIGGER trg_updated_at_<table_name>
ON <table_name>
AFTER UPDATE
AS
BEGIN
  UPDATE <table_name>
  SET updated_at = SYSDATETIMEOFFSET()
  FROM <table_name> t
  INNER JOIN inserted i ON t.id = i.id;
END;
```

### 15.3 Auditoria de schema (multi-dialeto)

```sql
-- PostgreSQL / MySQL / MariaDB / SQL Server:
-- Listar colunas TEXT/VARCHAR sem limite
SELECT
  table_name,
  column_name,
  data_type,
  character_maximum_length
FROM information_schema.columns
WHERE table_schema = 'public'   -- PostgreSQL
  -- WHERE table_schema = DATABASE()  -- MySQL/MariaDB
  -- WHERE table_schema = 'dbo'       -- SQL Server
  AND data_type IN ('text', 'character varying', 'varchar', 'nvarchar', 'ntext')
  AND (character_maximum_length IS NULL OR character_maximum_length = -1)
ORDER BY table_name, column_name;

-- SQLite:
-- PRAGMA table_info(<table_name>);
-- Verificar manualmente se há CHECK constraints

-- Resultado: qualquer coluna sem limite DEVE ter um constraint adicionado
```

### 15.4 Proteção contra SQL Injection

> **Regra universal para TODOS os dialetos:** NUNCA concatenar input do usuário em queries SQL.

```javascript
// ❌ INSEGURO — SQL Injection (vale para TODO dialeto)
const query = `SELECT * FROM users WHERE email = '${email}'`;
const query = "SELECT * FROM users WHERE email = '" + email + "'";

// ✅ SEGURO — Queries parametrizadas
// PostgreSQL (pg): $1, $2
const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
// MySQL (mysql2): ?
const result = await db.query('SELECT * FROM users WHERE email = ?', [email]);
// SQLite (better-sqlite3): ?
const result = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
// SQL Server (tedious): @param
const result = await db.query('SELECT * FROM users WHERE email = @email', { email });
// ORMs: usam parametrização automaticamente
const user = await prisma.user.findUnique({ where: { email } });
```

#### O que o Sentinela verifica:

```
1. Colunas TEXT/VARCHAR sem limite? SIM = 🟠 Alta
2. owner_id tem FK para tabela de users? NÃO = 🟡 Média
3. CASCADE configurado em FK de owner_id? NÃO = 🟡 Média
4. Trigger de updated_at existe? NÃO = 🔵 Baixa
5. Índices em colunas de busca frequente? NÃO = 🔵 Baixa
6. Há concatenação de strings em queries SQL? SIM = 🔴 Crítica (SQL Injection)
7. Todas as queries usam parametrização? NÃO = 🔴 Crítica
```

---

## 16. CSRF (Cross-Site Request Forgery)

### 16.1 Proteção obrigatória

- Todo formulário que realiza mutação DEVE ter proteção CSRF
- APIs stateless (JWT bearer token) são naturalmente protegidas contra CSRF
- APIs com cookies de sessão DEVEM implementar CSRF token

### 16.2 Por stack

| Stack | Mecanismo |
|---|---|
| **Next.js** | Server Actions com CSRF built-in; API Routes com JWT |
| **Django** | `{% csrf_token %}` + middleware `CsrfViewMiddleware` |
| **Rails** | `protect_from_forgery` + `authenticity_token` |
| **Laravel** | `@csrf` directive + middleware `VerifyCsrfToken` |
| **Express** | Middleware `csurf` ou `csrf-csrf` |
| **SvelteKit** | CSRF built-in para form actions |
| **Spring Boot** | `CsrfFilter` (habilitado por default com Spring Security) |
| **ASP.NET** | `[ValidateAntiForgeryToken]` + `@Html.AntiForgeryToken()` |

#### O que o Sentinela verifica:

```
1. Formulários de mutação têm CSRF token? NÃO = 🟠 Alta
2. Cookies de sessão têm SameSite=Strict/Lax? NÃO = 🟠 Alta
3. Framework CSRF está ativo? NÃO = 🔴 Crítica (se usa cookies de sessão)
```

---

## 17. Estrutura de Arquivos de Segurança Recomendada

```
lib/security/                        (ou src/security/, app/security/, etc.)
├── constants.{js,ts,py,rb,java,cs}  — Limites de campo, mensagens, config de imagem, rate limits, planos
├── schemas.{js,ts,py,rb,java,cs}    — Schemas de validação de todos os inputs
├── ratelimit.{js,ts,py,rb,java,cs}  — Rate limiting persistente via banco de dados
├── honeypot.{js,ts,py,rb,java,cs}   — Campo honeypot + rotas decoy
├── auth.{js,ts,py,rb,java,cs}       — Helper: extrai user do JWT, verificação de ownership
├── responses.{js,ts,py,rb,java,cs}  — Respostas padronizadas (401, 403, 404, 500)
├── image-validator.{...}            — Validação de upload (magic bytes, MIME, size lock)
├── plans.{...}                      — Verificação de features/limites por plano
└── setup.sql                        — SQL: tabelas de segurança + constraints

tests/security/
├── input-validation.test.{js,ts,py}
├── idor.test.{js,ts,py}
├── auth.test.{js,ts,py}
├── access-control.test.{js,ts,py}
├── error-messages.test.{js,ts,py}
├── rate-limiting.test.{js,ts,py}
└── sql-injection.test.{js,ts,py}

sql/
├── migrations/                       — Migrations numeradas
│   ├── 001_create_tables.sql
│   ├── 002_add_constraints.sql
│   ├── 003_add_access_policies.sql   — RLS (PostgreSQL/SQL Server) ou views (MySQL)
│   └── 004_add_security_tables.sql
└── policies/                         — Políticas de acesso documentadas (quando aplicável)
    ├── users_policies.sql
    └── services_policies.sql
```

---

## 18. XSS (Cross-Site Scripting) — Prevenção Completa

> **XSS é a vulnerabilidade web mais explorada.** Permite ao atacante executar JavaScript arbitrário no navegador de outros usuários, roubar sessões, tokens e dados.

### 18.1 Tipos de XSS

| Tipo | Como acontece | Exemplo |
|---|---|---|
| **Stored XSS** | Dado malicioso salvo no banco e renderizado para outros usuários | Comentário com `<script>` exibido para todos |
| **Reflected XSS** | Input do URL refletido na resposta sem sanitização | `?search=<script>alert(1)</script>` renderizado na página |
| **DOM XSS** | JavaScript do cliente manipula DOM com dados não sanitizados | `document.getElementById('x').innerHTML = location.hash` |

### 18.2 Regras universais de prevenção

#### NUNCA usar renderização não-escapada de dados do usuário

| Stack | ❌ INSEGURO (output não-escapado) | ✅ SEGURO (escapado por default) |
|---|---|---|
| **React** | `dangerouslySetInnerHTML={{ __html: userInput }}` | `{userInput}` (escapa automaticamente) |
| **Vue** | `v-html="userInput"` | `{{ userInput }}` (escapa automaticamente) |
| **Angular** | `[innerHTML]="userInput"` | `{{ userInput }}` (escapa automaticamente) |
| **Svelte** | `{@html userInput}` | `{userInput}` (escapa automaticamente) |
| **EJS** | `<%- userInput %>` | `<%= userInput %>` (escapa) |
| **Jinja2 (Python)** | `{{ userInput \| safe }}`, `Markup(userInput)` | `{{ userInput }}` (escapa por default) |
| **Django** | `{{ userInput \| safe }}`, `mark_safe(userInput)` | `{{ userInput }}` (escapa por default) |
| **Rails (ERB)** | `<%= raw(userInput) %>`, `<%= userInput.html_safe %>` | `<%= userInput %>` (escapa por default) |
| **Laravel (Blade)** | `{!! $userInput !!}` | `{{ $userInput }}` (escapa por default) |
| **Thymeleaf (Java)** | `th:utext="${userInput}"` | `th:text="${userInput}"` (escapa) |
| **Razor (C#)** | `@Html.Raw(userInput)` | `@userInput` (escapa por default) |

#### NUNCA usar APIs DOM inseguras com dados do usuário

```javascript
// ❌ INSEGURO — injeta HTML diretamente
element.innerHTML = userInput;
element.outerHTML = userInput;
document.write(userInput);
document.writeln(userInput);
element.insertAdjacentHTML('beforeend', userInput);

// ✅ SEGURO — texto puro, sem interpretação HTML
element.textContent = userInput;
element.innerText = userInput;

// ✅ SEGURO — criar elementos via DOM API
const el = document.createElement('span');
el.textContent = userInput;
container.appendChild(el);
```

### 18.3 Sanitização quando HTML é necessário

Quando o projeto PRECISA renderizar HTML do usuário (ex: editor rich text, markdown):

```javascript
// lib/security/sanitize.js

// Usar biblioteca consolidada — NUNCA implementar regex manual de sanitização
// JavaScript: DOMPurify (browser + server)
import DOMPurify from 'dompurify';

const SANITIZE_CONFIG = {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'blockquote', 'code', 'pre'],
  ALLOWED_ATTR: ['href', 'title', 'target'],
  ALLOW_DATA_ATTR: false,
  ADD_ATTR: ['target'],  // Forçar target em links
  FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'form', 'input', 'textarea', 'select', 'button'],
  FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onblur', 'onsubmit', 'style'],
};

export function sanitizeHTML(dirty) {
  return DOMPurify.sanitize(dirty, SANITIZE_CONFIG);
}

// Sanitização de URL (previne javascript: protocol)
export function sanitizeURL(url) {
  if (!url || typeof url !== 'string') return '';
  const trimmed = url.trim().toLowerCase();
  if (trimmed.startsWith('javascript:') || trimmed.startsWith('data:') || trimmed.startsWith('vbscript:')) {
    return '';
  }
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:', 'mailto:'].includes(parsed.protocol)) {
      return '';
    }
    return url;
  } catch {
    // URL relativa — permitir
    if (url.startsWith('/') || url.startsWith('#') || url.startsWith('?')) {
      return url;
    }
    return '';
  }
}
```

```python
# Python: bleach
import bleach

ALLOWED_TAGS = ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'blockquote', 'code', 'pre']
ALLOWED_ATTRS = {'a': ['href', 'title', 'target']}

def sanitize_html(dirty: str) -> str:
    return bleach.clean(dirty, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
```

### 18.4 Content-Security-Policy (CSP) detalhado

CSP é a **segunda linha de defesa** contra XSS (após encoding). Mesmo que XSS passe, CSP bloqueia execução.

```javascript
// lib/security/constants.js

export const CSP_DIRECTIVES = {
  "default-src": ["'self'"],
  "script-src":  ["'self'"],                    // NUNCA adicionar 'unsafe-inline' ou 'unsafe-eval'
  "style-src":   ["'self'", "'unsafe-inline'"], // Inline styles podem ser necessários para frameworks CSS
  "img-src":     ["'self'", "data:", "https:"],
  "font-src":    ["'self'", "https://fonts.gstatic.com"],
  "connect-src": ["'self'"],                     // Adicionar URLs de API conforme necessário
  "frame-src":   ["'none'"],                     // Bloquear iframes
  "object-src":  ["'none'"],                     // Bloquear plugins (Flash, etc.)
  "base-uri":    ["'self'"],                     // Prevenir base tag injection
  "form-action": ["'self'"],                     // Prevenir form hijacking
  "frame-ancestors": ["'none'"],                 // Equivalente a X-Frame-Options: DENY
  "upgrade-insecure-requests": [],               // Forçar HTTPS
};

export function buildCSPHeader(directives = CSP_DIRECTIVES) {
  return Object.entries(directives)
    .map(([key, values]) => values.length ? `${key} ${values.join(' ')}` : key)
    .join('; ');
}
```

### 18.5 Proteções adicionais contra XSS

```javascript
// Sempre setar cookie de sessão com HttpOnly (JavaScript não acessa)
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/

// Sanitizar dados ANTES de salvar no banco (defense in depth)
// MAS o encoding principal deve ser no OUTPUT, não apenas no input
```

#### O que o Sentinela verifica:

```
BUSCAR em todo o código:
  - dangerouslySetInnerHTML, v-html, @html, {!! !!}
  - innerHTML, outerHTML, document.write
  - |safe, mark_safe, html_safe, raw(), @Html.Raw
  - th:utext
  - <%- (EJS unescaped)
  - Ausência de Content-Security-Policy header
  - 'unsafe-inline' ou 'unsafe-eval' em CSP script-src
  - javascript:, data: em URLs renderizadas
  - Event handlers inline com dados do usuário (onclick, onerror, etc.)

QUALQUER output não-escapado de dados do usuário = 🔴 Crítica
'unsafe-inline' em script-src do CSP = 🟠 Alta
Ausência de CSP = 🟡 Média
innerHTML com dados estáticos/seguros = 🔵 Baixa (documentar justificativa)
```

---

## 19. CORS (Cross-Origin Resource Sharing) — Configuração Segura

> **CORS mal configurado permite que qualquer site faça requests autenticados à sua API**, roubando dados dos seus usuários.

### 19.1 Regras fundamentais

| Regra | Detalhe |
|---|---|
| **NUNCA** usar `Access-Control-Allow-Origin: *` com credentials | Permite qualquer site acessar dados autenticados |
| **SEMPRE** usar whitelist de origens | Lista explícita de domínios confiáveis |
| **Restringir** methods ao necessário | Apenas GET, POST, PUT, DELETE que a API usa |
| **Restringir** headers ao necessário | Apenas os headers customizados que a API espera |
| **Cachear** preflight | `Access-Control-Max-Age` para reduzir requests OPTIONS |
| **NUNCA** refletir Origin do request | Não usar `req.headers.origin` como valor de `Allow-Origin` sem validação |

### 19.2 Implementação segura

```javascript
// lib/security/constants.js

export const CORS_CONFIG = {
  // Lista EXPLÍCITA de origens permitidas — NUNCA usar '*' com credentials
  allowedOrigins: [
    'https://meuapp.com',
    'https://www.meuapp.com',
    // Desenvolvimento (remover em produção)
    ...(process.env.NODE_ENV === 'development' ? ['http://localhost:3000', 'http://localhost:5173'] : []),
  ],
  allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-CSRF-Token'],
  exposedHeaders: ['X-Request-Id'],     // Headers que o frontend pode ler
  credentials: true,                     // Permitir cookies/auth
  maxAge: 86400,                         // Cache preflight por 24h (segundos)
};
```

```javascript
// lib/security/cors.js

import { CORS_CONFIG } from './constants.js';

/**
 * Middleware CORS seguro — validar contra whitelist, nunca refletir Origin cegamente.
 */
export function corsMiddleware(req, res, next) {
  const origin = req.headers.origin;

  if (origin && CORS_CONFIG.allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');  // OBRIGATÓRIO quando origin não é *
  }
  // Se origin não está na whitelist, NÃO setar Access-Control-Allow-Origin
  // O browser vai bloquear a request

  if (CORS_CONFIG.credentials) {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  // Preflight request
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', CORS_CONFIG.allowedMethods.join(', '));
    res.setHeader('Access-Control-Allow-Headers', CORS_CONFIG.allowedHeaders.join(', '));
    res.setHeader('Access-Control-Max-Age', String(CORS_CONFIG.maxAge));
    res.status(204).end();
    return;
  }

  next?.();
}
```

### 19.3 Configuração por stack

| Stack | Como configurar CORS |
|---|---|
| **Next.js** | `next.config.js` → `headers()` ou middleware |
| **Express** | `cors()` middleware com config ou manual |
| **Fastify** | `@fastify/cors` plugin |
| **Django** | `django-cors-headers` com `CORS_ALLOWED_ORIGINS` (NUNCA `CORS_ALLOW_ALL_ORIGINS=True` em prod) |
| **Rails** | `rack-cors` gem com `origins` explícitos |
| **FastAPI** | `CORSMiddleware` com `allow_origins` explícitos |
| **Laravel** | `config/cors.php` com `allowed_origins` explícitos |
| **Spring Boot** | `@CrossOrigin` ou `WebMvcConfigurer.addCorsMappings()` com origins explícitos |
| **ASP.NET** | `AddCors()` com `WithOrigins()` explícitos |

### 19.4 Anti-patterns de CORS

```javascript
// ❌ INSEGURO — permite qualquer origem com credentials
app.use(cors({ origin: '*', credentials: true }));

// ❌ INSEGURO — reflete qualquer origin sem validar
app.use(cors({ origin: (origin, cb) => cb(null, true), credentials: true }));

// ❌ INSEGURO — regex muito permissivo
app.use(cors({ origin: /.*\.com$/, credentials: true }));
// Permite evil-meuapp.com, attacker.com, etc.

// ❌ INSEGURO — Django com all origins
CORS_ALLOW_ALL_ORIGINS = True  # em produção

// ✅ SEGURO — whitelist explícita
app.use(cors({
  origin: ['https://meuapp.com', 'https://www.meuapp.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
}));
```

#### O que o Sentinela verifica:

```
BUSCAR:
  - Access-Control-Allow-Origin: * (com credentials) = 🔴 Crítica
  - cors({ origin: '*' }) com credentials = 🔴 Crítica
  - cors({ origin: true }) ou origin: (_, cb) => cb(null, true) = 🔴 Crítica
  - CORS_ALLOW_ALL_ORIGINS = True em produção = 🔴 Crítica
  - Origin refletido sem validação contra whitelist = 🔴 Crítica
  - Regex de origin muito permissivo = 🟠 Alta
  - CORS não configurado em API pública = 🟠 Alta
  - Vary: Origin ausente quando origin é dinâmico = 🟡 Média
  - Access-Control-Max-Age ausente = 🔵 Baixa
```

---

## 20. Mass Assignment / Over-posting — Proteção Obrigatória

> **Mass assignment** ocorre quando o atacante envia campos extras no body que o servidor aceita cegamente, podendo alterar `role`, `is_admin`, `plan`, `verified`, ou qualquer campo protegido.

### 20.1 Regra universal

> **NUNCA** fazer spread ou assign direto do body da request em queries de banco/ORM. **SEMPRE** usar allowlist explícita de campos.

### 20.2 Anti-patterns por stack

```javascript
// ❌ INSEGURO — JavaScript/TypeScript
const user = await prisma.user.create({ data: req.body });
const user = await prisma.user.create({ data: { ...req.body } });
await db.insert('users', req.body);
await db.insert('users', Object.assign({}, req.body));
await User.create(req.body);

// ❌ INSEGURO — Python
user = User(**request.data)
user = User.objects.create(**request.data)
serializer = UserSerializer(data=request.data)  # sem fields explícitos

// ❌ INSEGURO — Ruby on Rails (sem strong parameters)
User.create(params[:user])

// ❌ INSEGURO — PHP/Laravel (sem $fillable)
User::create($request->all());

// ❌ INSEGURO — Java/Spring (sem @JsonIgnoreProperties ou DTO)
@PostMapping public User create(@RequestBody User user) { return repo.save(user); }
```

### 20.3 Padrão seguro — Allowlist explícita

```javascript
// ✅ SEGURO — JavaScript/TypeScript — extrair apenas campos permitidos
export function pickAllowedFields(body, allowedFields) {
  const result = {};
  for (const field of allowedFields) {
    if (body[field] !== undefined) {
      result[field] = body[field];
    }
  }
  return result;
}

// Uso:
const ALLOWED_CREATE_USER = ['name', 'email'];
const ALLOWED_UPDATE_USER = ['name', 'phone', 'avatar_url'];

// Na API Route:
const data = pickAllowedFields(req.body, ALLOWED_CREATE_USER);
data.role = 'user';        // Sempre setar server-side
data.owner_id = userId;    // Sempre derivar do JWT
const user = await prisma.user.create({ data });
```

```python
# ✅ SEGURO — Python/Django — serializer com fields explícitos
class UserCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['name', 'email']  # APENAS campos permitidos
        read_only_fields = ['id', 'role', 'is_admin', 'created_at']

# ✅ SEGURO — Python/FastAPI — Pydantic model
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    # role NÃO está aqui — atacante não pode enviar
```

```ruby
# ✅ SEGURO — Rails — Strong Parameters
def user_params
  params.require(:user).permit(:name, :email)
  # :role, :is_admin NÃO estão permitidos
end
User.create(user_params)
```

```php
// ✅ SEGURO — Laravel — $fillable no Model
class User extends Model {
    protected $fillable = ['name', 'email'];
    // role, is_admin NÃO estão em $fillable — não podem ser mass-assigned
    protected $guarded = ['role', 'is_admin', 'plan_id'];
}
```

```java
// ✅ SEGURO — Spring Boot — DTO separado
public class UserCreateDTO {
    @NotBlank private String name;
    @Email private String email;
    // Sem campo role/isAdmin — atacante não pode enviar
}

@PostMapping
public User create(@Valid @RequestBody UserCreateDTO dto) {
    User user = new User();
    user.setName(dto.getName());
    user.setEmail(dto.getEmail());
    user.setRole("user");  // Sempre server-side
    return repo.save(user);
}
```

### 20.4 Campos que NUNCA devem ser aceitos do cliente

```javascript
// lib/security/constants.js

export const PROTECTED_FIELDS = [
  'id',
  'role',
  'is_admin',
  'is_verified',
  'email_verified',
  'plan',
  'plan_id',
  'subscription_status',
  'owner_id',
  'user_id',
  'auth_id',
  'created_at',
  'updated_at',
  'deleted_at',
  'password_hash',
  'stripe_customer_id',
  'credits',
  'balance',
  'permissions',
];

/**
 * Remove campos protegidos de um objeto.
 * Usar como safety net ALÉM da allowlist.
 */
export function stripProtectedFields(data) {
  const cleaned = { ...data };
  for (const field of PROTECTED_FIELDS) {
    delete cleaned[field];
  }
  return cleaned;
}
```

#### O que o Sentinela verifica:

```
BUSCAR em todo o código:
  - ...req.body / ...request.data / **request.data  (spread em query)
  - Object.assign({}, req.body) em mutação
  - Model.create(req.body) / Model.create(params[:model])
  - prisma.*.create({ data: req.body })
  - ORM.create(**request.data) sem fields explícitos
  - @RequestBody Entity (Spring sem DTO separado)
  - $request->all() em create/update (Laravel sem $fillable)

QUALQUER spread/assign direto do body em mutação = 🔴 Crítica
Modelo sem $fillable/$guarded (Laravel) = 🟠 Alta
Serializer sem fields explícitos (Django) = 🟠 Alta
Controller sem DTO separado (Spring/ASP.NET) = 🟠 Alta
Campos protegidos (role, is_admin) aceitos do cliente = 🔴 Crítica
```

---

## 21. Dependency Security (Supply Chain) — Auditoria Obrigatória

> **Ataques de supply chain** comprometem dependências legítimas. Uma dependência maliciosa em `node_modules` ou `pip` tem acesso total ao ambiente de execução.

### 21.1 Regras obrigatórias

| Regra | Detalhe | Severidade se ausente |
|---|---|---|
| Lock file commitado | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Gemfile.lock`, `composer.lock`, `go.sum` | 🟠 Alta |
| Auditoria de vulnerabilidades | `npm audit`, `yarn audit`, `pip audit`, `bundle audit`, `composer audit` | 🟠 Alta |
| Zero vulnerabilidades críticas | Nenhuma dependência com CVE crítica/alta sem correção | 🔴 Crítica |
| Dependabot / Renovate | Automação de updates de segurança | 🟡 Média |
| Review de novas dependências | Toda nova dependência precisa de justificativa (evitar typosquatting) | 🟡 Média |
| Não usar dependências abandonadas | Sem update há >2 anos + issues de segurança abertas | 🟡 Média |

### 21.2 Comandos de auditoria por stack

```bash
# JavaScript (npm)
npm audit
npm audit --audit-level=high    # Falhar apenas em high/critical
npm audit fix                   # Auto-fix quando possível

# JavaScript (yarn)
yarn audit
yarn audit --level high

# JavaScript (pnpm)
pnpm audit
pnpm audit --audit-level high

# Python (pip)
pip audit                       # Requer: pip install pip-audit
safety check                    # Requer: pip install safety

# Python (poetry)
poetry audit

# Ruby
bundle audit check --update     # Requer: gem install bundler-audit

# PHP (Composer)
composer audit

# Go
govulncheck ./...               # Requer: go install golang.org/x/vuln/cmd/govulncheck@latest

# Java (Maven)
mvn org.owasp:dependency-check-maven:check

# .NET
dotnet list package --vulnerable
```

### 21.3 Configuração de Dependabot / Renovate

```yaml
# .github/dependabot.yml (GitHub)
version: 2
updates:
  - package-ecosystem: "npm"  # ou pip, composer, bundler, maven, nuget, gomod
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    reviewers:
      - "security-team"
    labels:
      - "dependencies"
      - "security"
```

### 21.4 Prevenção de typosquatting

```bash
# Antes de instalar qualquer dependência nova, verificar:
# 1. Nome correto (ex: "lodash" e não "1odash" ou "lodas")
# 2. Autor/organização legítima (verificar npm/pypi page)
# 3. Número de downloads (suspeitar de <1000 downloads semanais)
# 4. Data do último update (suspeitar de packages muito novos)
# 5. Escopo limitado — preferir pacotes com escopo (@org/package)

# Nunca instalar com wildcard de versão em produção:
# ❌ "some-package": "*"
# ❌ "some-package": ">=1.0.0"
# ✅ "some-package": "^2.3.1"  (com lock file)
```

#### O que o Sentinela verifica:

```
1. Lock file existe e está commitado? NÃO = 🟠 Alta
2. `npm audit` / equivalente reporta CVEs críticas? SIM = 🔴 Crítica
3. `npm audit` reporta CVEs altas? SIM = 🟠 Alta
4. Dependabot/Renovate configurado? NÃO = 🟡 Média
5. Dependências com >2 anos sem update? SIM = 🟡 Média
6. Dependências com versão wildcard (*)? SIM = 🟠 Alta
```

---

## 22. Logging & Monitoring — Seguro e Estruturado

> **Logs são a memória do sistema.** Sem logs, incidentes são invisíveis. Com logs inseguros, logs SE TORNAM a vulnerabilidade.

### 22.1 O que NUNCA logar

```javascript
// lib/security/constants.js

export const NEVER_LOG_FIELDS = [
  'password',
  'senha',
  'token',
  'access_token',
  'refresh_token',
  'jwt',
  'api_key',
  'apiKey',
  'secret',
  'credit_card',
  'card_number',
  'cvv',
  'ssn',
  'cpf',
  'rg',
  'authorization',   // Header com Bearer token
];
```

```javascript
// ❌ INSEGURO — loga senhas, tokens, dados pessoais
console.log('Login attempt:', req.body);
console.log('User data:', user);
console.error('Auth failed:', error);  // error pode conter token
logger.info(`Request body: ${JSON.stringify(req.body)}`);  // body tem password

// ✅ SEGURO — log estruturado com dados sanitizados
logger.info({
  event: 'login_attempt',
  email: maskEmail(req.body.email),  // "a***@gmail.com"
  ip: req.ip,
  userAgent: req.headers['user-agent'],
  timestamp: new Date().toISOString(),
});
```

### 22.2 O que SEMPRE logar

| Evento | Dados a logar | Severidade do log |
|---|---|---|
| Login bem-sucedido | user_id, IP, user-agent, timestamp | INFO |
| Login falho | email mascarado, IP, user-agent, motivo genérico | WARN |
| Rate limit atingido | IP, rota, tentativas, timestamp | WARN |
| IDOR tentado | user_id (solicitante), resource_id, IP | ERROR |
| Erro 500 | request_id, rota, stack (apenas no servidor, NUNCA ao cliente) | ERROR |
| Permissão negada | user_id, recurso, ação, timestamp | WARN |
| Honeypot acionado | IP, rota/campo, user-agent, timestamp | WARN |
| Admin action | admin_id, ação, target, before/after | INFO |
| Dados deletados | user_id, tipo, quantidade, timestamp | INFO |
| Mudança de role/plano | user_id, old_value, new_value, admin_id | INFO |

### 22.3 Sanitização de logs

```javascript
// lib/security/logging.js

import { NEVER_LOG_FIELDS } from './constants.js';

/**
 * Remove campos sensíveis de um objeto antes de logar.
 */
export function sanitizeForLog(data, sensitiveFields = NEVER_LOG_FIELDS) {
  if (!data || typeof data !== 'object') return data;

  const sanitized = Array.isArray(data) ? [...data] : { ...data };
  for (const key of Object.keys(sanitized)) {
    const lowerKey = key.toLowerCase();
    if (sensitiveFields.some(f => lowerKey.includes(f.toLowerCase()))) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof sanitized[key] === 'object' && sanitized[key] !== null) {
      sanitized[key] = sanitizeForLog(sanitized[key], sensitiveFields);
    }
  }
  return sanitized;
}

/**
 * Mascara e-mail para logs.
 * "alisson@gmail.com" → "a***@gmail.com"
 */
export function maskEmail(email) {
  if (!email || typeof email !== 'string') return '[INVALID]';
  const [local, domain] = email.split('@');
  if (!local || !domain) return '[INVALID]';
  return `${local[0]}***@${domain}`;
}

/**
 * Mascara IP parcialmente para logs públicos.
 * "192.168.1.100" → "192.168.1.xxx"
 */
export function maskIP(ip) {
  if (!ip) return '[UNKNOWN]';
  const parts = ip.split('.');
  if (parts.length === 4) {
    parts[3] = 'xxx';
    return parts.join('.');
  }
  return ip; // IPv6 — retornar como está ou implementar mascaramento
}
```

### 22.4 Structured logging

```javascript
// Usar logger estruturado (JSON) — facilita busca e alertas
// Libs: pino (Node.js), winston (Node.js), structlog (Python), serilog (.NET), logback (Java)

import pino from 'pino';

const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  redact: {
    paths: ['req.headers.authorization', 'req.body.password', 'req.body.token'],
    censor: '[REDACTED]',
  },
  serializers: {
    req: (req) => ({
      method: req.method,
      url: req.url,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    }),
    err: pino.stdSerializers.err,
  },
});

export default logger;
```

### 22.5 Alertas obrigatórios

```javascript
// lib/security/constants.js

export const ALERT_THRESHOLDS = {
  failed_logins_per_ip:     { count: 10, window: '5m',  action: 'alert + block' },
  failed_logins_per_user:   { count: 5,  window: '15m', action: 'alert + lock' },
  idor_attempts:            { count: 3,  window: '1h',  action: 'alert + review' },
  error_500_spike:          { count: 50, window: '5m',  action: 'alert + page' },
  honeypot_triggers:        { count: 5,  window: '1h',  action: 'alert + monitor' },
  rate_limit_blocks:        { count: 100, window: '1h', action: 'alert' },
  new_admin_created:        { count: 1,  window: 'any', action: 'alert immediately' },
};
```

#### O que o Sentinela verifica:

```
BUSCAR:
  - console.log(req.body) / console.log(request.data) = 🟠 Alta (pode logar senhas)
  - console.log(...password...) / logger.info(...token...) = 🔴 Crítica
  - console.error(error) enviado sem sanitização = 🟡 Média
  - Ausência de logging em endpoints de auth = 🟠 Alta
  - Ausência de logging em mutações críticas = 🟡 Média
  - Logger sem redação de campos sensíveis = 🟠 Alta
  - Ausência de request_id para correlação = 🔵 Baixa
```

---

## 23. SSRF (Server-Side Request Forgery) — Proteção

> **SSRF** ocorre quando o servidor faz requests para URLs fornecidas pelo usuário, permitindo acesso a recursos internos (metadata de cloud, serviços internos, rede local).

### 23.1 Quando verificar

O Sentinela DEVE verificar SSRF sempre que:
- A aplicação faz fetch/request para URLs fornecidas pelo usuário
- Há funcionalidade de preview de link, scraping, webhook, ou import de URL
- Há proxy ou redirecionamento server-side
- Há geração de imagem/PDF a partir de URL externa

### 23.2 IPs e ranges bloqueados

```javascript
// lib/security/ssrf.js

import { URL } from 'url';
import dns from 'dns/promises';
import net from 'net';

const BLOCKED_IP_RANGES = [
  // Loopback
  '127.0.0.0/8',       // IPv4 loopback
  '::1/128',           // IPv6 loopback

  // Private networks
  '10.0.0.0/8',        // Class A private
  '172.16.0.0/12',     // Class B private
  '192.168.0.0/16',    // Class C private
  'fc00::/7',          // IPv6 private

  // Link-local
  '169.254.0.0/16',    // IPv4 link-local (AWS metadata!)
  'fe80::/10',         // IPv6 link-local

  // Cloud metadata endpoints
  // AWS: 169.254.169.254
  // GCP: metadata.google.internal (169.254.169.254)
  // Azure: 169.254.169.254

  // Outros
  '0.0.0.0/8',         // This network
  '100.64.0.0/10',     // Shared address space (CGNAT)
  '192.0.0.0/24',      // IETF protocol assignments
  '198.18.0.0/15',     // Benchmark testing
  '224.0.0.0/4',       // Multicast
  '240.0.0.0/4',       // Reserved
];

const BLOCKED_PROTOCOLS = ['file:', 'gopher:', 'dict:', 'ftp:', 'ldap:', 'telnet:', 'data:', 'javascript:'];

const ALLOWED_PROTOCOLS = ['http:', 'https:'];

/**
 * Valida se uma URL é segura para fetch server-side.
 * @param {string} urlString - URL fornecida pelo usuário
 * @param {string[]} allowedDomains - Whitelist de domínios (opcional, recomendado)
 * @returns {{ safe: boolean, reason?: string }}
 */
export async function validateURLForFetch(urlString, allowedDomains = null) {
  // 1. Parse da URL
  let parsed;
  try {
    parsed = new URL(urlString);
  } catch {
    return { safe: false, reason: 'invalid_url' };
  }

  // 2. Protocolo permitido
  if (!ALLOWED_PROTOCOLS.includes(parsed.protocol)) {
    return { safe: false, reason: 'blocked_protocol' };
  }

  // 3. Whitelist de domínios (se fornecida)
  if (allowedDomains && !allowedDomains.includes(parsed.hostname)) {
    return { safe: false, reason: 'domain_not_allowed' };
  }

  // 4. Resolver DNS e verificar IP
  try {
    const addresses = await dns.resolve4(parsed.hostname);
    for (const ip of addresses) {
      if (isPrivateIP(ip)) {
        return { safe: false, reason: 'private_ip' };
      }
    }
  } catch {
    return { safe: false, reason: 'dns_resolution_failed' };
  }

  // 5. Bloquear hostnames conhecidos de metadata
  const blockedHosts = ['metadata.google.internal', 'metadata.google.com', '169.254.169.254'];
  if (blockedHosts.includes(parsed.hostname)) {
    return { safe: false, reason: 'metadata_endpoint' };
  }

  return { safe: true };
}

/**
 * Verifica se um IP é privado/interno.
 */
function isPrivateIP(ip) {
  // IPv4 checks
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return true; // Tratar como inseguro se não é IPv4 válido

  // 127.0.0.0/8
  if (parts[0] === 127) return true;
  // 10.0.0.0/8
  if (parts[0] === 10) return true;
  // 172.16.0.0/12
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  // 192.168.0.0/16
  if (parts[0] === 192 && parts[1] === 168) return true;
  // 169.254.0.0/16 (link-local, cloud metadata)
  if (parts[0] === 169 && parts[1] === 254) return true;
  // 0.0.0.0/8
  if (parts[0] === 0) return true;
  // 100.64.0.0/10
  if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;

  return false;
}
```

### 23.3 Regras adicionais

```javascript
// Ao fazer fetch de URL do usuário:
// 1. SEMPRE resolver DNS e validar IP ANTES do fetch
// 2. NUNCA seguir redirects cegamente (atacante redireciona para IP interno)
// 3. Timeout curto (5-10 segundos)
// 4. Limitar tamanho da resposta
// 5. Não expor resposta interna ao usuário

const response = await fetch(validatedUrl, {
  redirect: 'manual',          // NÃO seguir redirects automaticamente
  signal: AbortSignal.timeout(10000),  // Timeout 10s
  headers: {
    'User-Agent': 'MyApp/1.0 (Link Preview)',  // Identificar-se
  },
});

// Verificar redirect
if (response.status >= 300 && response.status < 400) {
  const redirectUrl = response.headers.get('location');
  // Validar redirectUrl com validateURLForFetch antes de seguir!
}
```

#### O que o Sentinela verifica:

```
BUSCAR:
  - fetch(userInput), axios.get(userInput), requests.get(userInput)
  - http.get(userInput), urllib.request.urlopen(userInput)
  - URL do usuário usada em request server-side sem validação

SE encontrado:
  - Validação de IP/protocolo existe? NÃO = 🔴 Crítica
  - Redirect handling seguro? NÃO = 🟠 Alta
  - Timeout configurado? NÃO = 🟡 Média
  - Whitelist de domínios quando possível? NÃO = 🟡 Média
  - Resposta interna exposta ao cliente? SIM = 🟠 Alta
```

---

## 24. Open Redirect — Proteção

> **Open Redirect** permite que atacantes usem seu domínio confiável para redirecionar usuários a sites maliciosos (phishing).

### 24.1 Regra universal

> **NUNCA** redirecionar para URLs absolutas vindas de input do usuário sem validação. **SEMPRE** validar que o destino é interno ou está em whitelist.

### 24.2 Implementação segura

```javascript
// lib/security/redirect.js

/**
 * Valida URL de redirect — bloqueia open redirect.
 * @param {string} url - URL de redirect solicitada
 * @param {string[]} allowedDomains - Domínios permitidos para redirect externo
 * @returns {string} URL segura (ou fallback para '/')
 */
export function safeRedirectUrl(url, allowedDomains = []) {
  if (!url || typeof url !== 'string') return '/';

  const trimmed = url.trim();

  // Bloquear protocolos perigosos
  const lower = trimmed.toLowerCase();
  if (lower.startsWith('javascript:') || lower.startsWith('data:') || lower.startsWith('vbscript:')) {
    return '/';
  }

  // Permitir caminhos relativos (começando com / mas não //)
  if (trimmed.startsWith('/') && !trimmed.startsWith('//')) {
    return trimmed;
  }

  // Para URLs absolutas, validar domínio
  try {
    const parsed = new URL(trimmed);
    if (allowedDomains.includes(parsed.hostname)) {
      return trimmed;
    }
  } catch {
    // URL inválida
  }

  // Fallback seguro
  return '/';
}
```

### 24.3 Anti-patterns

```javascript
// ❌ INSEGURO — redirect aberto
res.redirect(req.query.next);
res.redirect(req.query.url);
res.redirect(req.query.redirect);
res.redirect(req.body.callback_url);
return redirect(request.GET['next']);  # Django
redirect_to params[:return_to]        # Rails

// ❌ INSEGURO — verificação insuficiente
const url = req.query.next;
if (url.startsWith('/')) { res.redirect(url); }
// Atacante envia: //evil.com (protocol-relative URL)

// ❌ INSEGURO — includes em vez de hostname exato
if (url.includes('meuapp.com')) { res.redirect(url); }
// Atacante envia: https://meuapp.com.evil.com

// ✅ SEGURO
res.redirect(safeRedirectUrl(req.query.next, ['meuapp.com']));
```

#### O que o Sentinela verifica:

```
BUSCAR:
  - res.redirect(req.query.*), res.redirect(req.body.*)
  - redirect(request.GET[*]), redirect(request.POST[*])
  - redirect_to params[:*]
  - Location header setado com valor do usuário
  - window.location = userInput (client-side)
  - window.location.href = userInput

SE redirect com input do usuário:
  - Validação de domínio existe? NÃO = 🟠 Alta
  - Protocolos perigosos bloqueados? NÃO = 🟠 Alta
  - Protocol-relative URLs (//) bloqueadas? NÃO = 🟡 Média
  - Whitelist de domínios usada? NÃO = 🟡 Média (recomendado)
```

---

## 25. Privacidade de Dados (LGPD / GDPR) — Conformidade

> **Conformidade com leis de proteção de dados** não é opcional. LGPD (Brasil), GDPR (Europa), CCPA (Califórnia) impõem multas pesadas.

### 25.1 Princípios obrigatórios

| Princípio | Implementação |
|---|---|
| **Minimização** | Coletar APENAS os dados necessários para a funcionalidade |
| **Finalidade** | Usar dados APENAS para o propósito informado ao usuário |
| **Consentimento** | Obter consentimento explícito antes de coletar dados não essenciais |
| **Transparência** | Política de privacidade clara e acessível |
| **Direito de acesso** | Endpoint para o usuário baixar seus dados |
| **Direito de exclusão** | Endpoint para o usuário deletar sua conta e todos os dados |
| **Portabilidade** | Exportar dados em formato padrão (JSON, CSV) |
| **Segurança** | Criptografia, controle de acesso, backups seguros |

### 25.2 Implementação obrigatória

```javascript
// API Routes mínimas para conformidade:

// GET /api/user/data — Exportar todos os dados do usuário
// Retorna JSON com todos os dados associados ao user_id

// DELETE /api/user/account — Deletar conta e todos os dados
// 1. Deletar dados em todas as tabelas (CASCADE ou manual)
// 2. Deletar arquivos/uploads associados
// 3. Revogar sessões ativas
// 4. Logar a ação (para auditoria)
// 5. Enviar e-mail de confirmação

// POST /api/user/consent — Registrar consentimento
// Salvar: user_id, tipo de consentimento, timestamp, IP, versão dos termos
```

### 25.3 Criptografia de dados sensíveis (field-level)

```javascript
// Para dados especialmente sensíveis (CPF, documentos, dados médicos):
// Criptografar no nível do campo, além da criptografia at-rest do banco

// Usar: AES-256-GCM para criptografia simétrica de campos
// Chave de criptografia em variável de ambiente (NUNCA no código)

// Exemplo conceitual:
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const KEY = Buffer.from(process.env.FIELD_ENCRYPTION_KEY, 'hex'); // 32 bytes

export function encryptField(plaintext) {
  const iv = randomBytes(16);
  const cipher = createCipheriv(ALGORITHM, KEY, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

export function decryptField(ciphertext) {
  const [ivHex, authTagHex, encrypted] = ciphertext.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const decipher = createDecipheriv(ALGORITHM, KEY, iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}
```

### 25.4 Tabela de consentimento

```sql
-- Multi-dialeto (adaptar tipos ao dialeto)
CREATE TABLE user_consents (
  id            UUID PRIMARY KEY,         -- ou CHAR(36), UNIQUEIDENTIFIER, etc.
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  consent_type  VARCHAR(50) NOT NULL,     -- 'terms', 'marketing', 'analytics', 'cookies'
  granted       BOOLEAN NOT NULL DEFAULT false,
  ip_address    VARCHAR(45),
  user_agent    VARCHAR(500),
  terms_version VARCHAR(20),              -- Versão dos termos aceitos
  granted_at    TIMESTAMP,                -- Quando consentiu (adaptar tipo ao dialeto)
  revoked_at    TIMESTAMP,                -- Quando revogou (NULL = ativo)
  created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 25.5 Retenção de dados

```javascript
// lib/security/constants.js

export const DATA_RETENTION = {
  security_events:   { days: 90,  action: 'delete' },
  rate_limits:       { days: 1,   action: 'delete' },
  user_sessions:     { days: 30,  action: 'invalidate + delete' },
  audit_logs:        { days: 365, action: 'archive' },
  deleted_accounts:  { days: 30,  action: 'hard_delete' },  // Após soft delete
  backups:           { days: 90,  action: 'rotate' },
};
```

#### O que o Sentinela verifica:

```
1. Endpoint de exportação de dados do usuário existe? NÃO = 🟠 Alta
2. Endpoint de exclusão de conta existe? NÃO = 🟠 Alta
3. Política de privacidade existe e é acessível? NÃO = 🟡 Média
4. Consentimento de cookies/analytics é coletado? NÃO = 🟡 Média
5. Dados sensíveis (CPF, docs) são criptografados field-level? NÃO = 🟠 Alta (se aplicável)
6. Política de retenção de dados definida? NÃO = 🟡 Média
7. Dados coletados são mínimos para a funcionalidade? EXCESSO = 🟡 Média
8. DELETE CASCADE configurado para dados do usuário? NÃO = 🟠 Alta
```

---

## 26. Secrets Management — Avançado

> **Além de `.env` no `.gitignore`**, gestão profissional de secrets inclui rotação, acesso controlado e auditoria.

### 26.1 Hierarquia de segurança de secrets

| Nível | Mecanismo | Quando usar |
|---|---|---|
| 🔴 Inaceitável | Hardcoded no código | **NUNCA** |
| 🟠 Básico | `.env` local + variáveis de ambiente em produção | Projetos pequenos, MVP |
| 🟡 Intermediário | Secrets do provedor de hosting (Vercel, Railway, etc.) | Projetos em produção |
| ✅ Recomendado | Secrets Manager (AWS SM, GCP SM, Azure KV, Vault) | Projetos sérios/enterprise |

### 26.2 Regras de secrets

```javascript
// lib/security/constants.js

export const SECRETS_POLICY = {
  rotation: {
    database_password:   { interval: '90 days',  alert_before: '14 days' },
    api_keys:            { interval: '180 days', alert_before: '30 days' },
    jwt_secret:          { interval: '90 days',  alert_before: '14 days' },
    encryption_keys:     { interval: '365 days', alert_before: '60 days' },
    service_accounts:    { interval: '90 days',  alert_before: '14 days' },
  },
  rules: [
    'NUNCA compartilhar secrets entre ambientes (dev/staging/prod)',
    'NUNCA logar secrets (nem parcialmente)',
    'NUNCA enviar secrets em respostas HTTP',
    'NUNCA armazenar secrets em banco sem criptografia',
    'NUNCA usar o mesmo secret para múltiplos propósitos',
    'SEMPRE usar scoped API keys (menor privilégio possível)',
    'SEMPRE revogar secrets comprometidos IMEDIATAMENTE',
    'SEMPRE ter processo documentado de rotação de secrets',
  ],
};
```

### 26.3 Verificação de variáveis de ambiente

```javascript
// lib/security/env-check.js

/**
 * Verifica que todas as variáveis de ambiente obrigatórias estão presentes.
 * Executar na inicialização da aplicação — falhar ANTES de aceitar requests.
 */
export function validateRequiredEnvVars(requiredVars) {
  const missing = [];
  const empty = [];

  for (const varName of requiredVars) {
    if (!(varName in process.env)) {
      missing.push(varName);
    } else if (!process.env[varName]?.trim()) {
      empty.push(varName);
    }
  }

  if (missing.length > 0 || empty.length > 0) {
    console.error('❌ Missing environment variables:', missing);
    console.error('❌ Empty environment variables:', empty);
    // NUNCA listar os VALORES, apenas os NOMES
    process.exit(1);  // Falhar na inicialização
  }
}

// Uso na inicialização:
validateRequiredEnvVars([
  'DATABASE_URL',
  'JWT_SECRET',
  'NEXT_PUBLIC_SUPABASE_URL',
  'SUPABASE_SERVICE_ROLE_KEY',
]);
```

### 26.4 .env.example seguro

```bash
# .env.example — commitado no repositório
# NUNCA conter valores reais — apenas placeholders descritivos

DATABASE_URL=postgresql://user:password@host:5432/dbname
JWT_SECRET=generate-a-random-64-char-hex-string
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key-from-supabase-dashboard
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
STRIPE_SECRET_KEY=sk_test_your-stripe-secret-key
FIELD_ENCRYPTION_KEY=generate-a-random-64-char-hex-string
```

#### O que o Sentinela verifica:

```
1. .env.example existe? NÃO = 🟡 Média
2. .env.example contém valores reais? SIM = 🔴 Crítica
3. Validação de env vars na inicialização existe? NÃO = 🟡 Média
4. Secrets compartilhados entre ambientes? SIM = 🟠 Alta
5. Secrets com mais de 90 dias sem rotação? SIM = 🟡 Média
6. JWT_SECRET com menos de 32 caracteres? SIM = 🟠 Alta
7. API keys com escopo excessivo? SIM = 🟡 Média
```

---

## 27. Webhook Security — Verificação de Integridade

> **Webhooks sem verificação de assinatura** permitem que qualquer atacante envie payloads falsos para sua aplicação, simulando eventos de pagamento, autenticação, etc.

### 27.1 Regra universal

> **TODO webhook recebido DEVE ter sua assinatura verificada** antes de qualquer processamento.

### 27.2 Verificação de assinatura HMAC

```javascript
// lib/security/webhook.js

import crypto from 'crypto';

/**
 * Verifica assinatura HMAC de um webhook.
 * Adaptar header e algoritmo conforme o provedor.
 *
 * @param {string|Buffer} payload - Body raw da request
 * @param {string} signature - Assinatura enviada no header
 * @param {string} secret - Webhook secret (do .env)
 * @param {string} algorithm - Algoritmo HMAC (default: sha256)
 * @returns {boolean} true se assinatura é válida
 */
export function verifyWebhookSignature(payload, signature, secret, algorithm = 'sha256') {
  if (!payload || !signature || !secret) return false;

  const expected = crypto
    .createHmac(algorithm, secret)
    .update(payload, 'utf8')
    .digest('hex');

  // Usar timingSafeEqual para prevenir timing attacks
  try {
    const sigBuffer = Buffer.from(signature, 'hex');
    const expectedBuffer = Buffer.from(expected, 'hex');
    if (sigBuffer.length !== expectedBuffer.length) return false;
    return crypto.timingSafeEqual(sigBuffer, expectedBuffer);
  } catch {
    return false;
  }
}
```

### 27.3 Verificação por provedor

```javascript
// Stripe
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function handleStripeWebhook(req) {
  const sig = req.headers['stripe-signature'];
  const event = stripe.webhooks.constructEvent(
    req.body,                              // Raw body (Buffer/string)
    sig,
    process.env.STRIPE_WEBHOOK_SECRET
  );
  // event é seguro — assinatura verificada
}

// GitHub
export function verifyGitHubWebhook(payload, signature) {
  // Header: X-Hub-Signature-256
  const expected = 'sha256=' + crypto
    .createHmac('sha256', process.env.GITHUB_WEBHOOK_SECRET)
    .update(payload)
    .digest('hex');
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

// Generic (Supabase, custom, etc.)
export function verifyGenericWebhook(payload, signature, secret) {
  return verifyWebhookSignature(payload, signature, secret);
}
```

### 27.4 Idempotência obrigatória

```javascript
// Webhooks podem ser enviados MÚLTIPLAS VEZES pelo provedor.
// O handler DEVE ser idempotente — processar o mesmo evento 2x sem efeito duplicado.

// Estratégia: salvar event_id no banco e verificar antes de processar
export async function handleWebhookIdempotent(db, eventId, eventType, handler) {
  // 1. Verificar se já processamos este evento
  const existing = await db.query(
    'SELECT id FROM webhook_events WHERE event_id = ?',
    [eventId]
  );
  if (existing) {
    return { status: 200, message: 'Already processed' };
  }

  // 2. Registrar o evento ANTES de processar (prevenir race condition)
  await db.query(
    'INSERT INTO webhook_events (event_id, event_type, status) VALUES (?, ?, ?)',
    [eventId, eventType, 'processing']
  );

  // 3. Processar
  try {
    await handler();
    await db.query(
      'UPDATE webhook_events SET status = ? WHERE event_id = ?',
      ['completed', eventId]
    );
  } catch (error) {
    await db.query(
      'UPDATE webhook_events SET status = ?, error = ? WHERE event_id = ?',
      ['failed', error.message, eventId]
    );
    throw error;
  }
}
```

```sql
-- Tabela de idempotência de webhooks (multi-dialeto)
CREATE TABLE webhook_events (
  id          VARCHAR(36) PRIMARY KEY,    -- Adaptar tipo ao dialeto
  event_id    VARCHAR(255) UNIQUE NOT NULL,
  event_type  VARCHAR(100),
  status      VARCHAR(20) DEFAULT 'processing',
  error       VARCHAR(500),
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### O que o Sentinela verifica:

```
SE o projeto recebe webhooks:

1. Assinatura verificada antes de processar? NÃO = 🔴 Crítica
2. Usa timing-safe comparison? NÃO = 🟠 Alta
3. Handler é idempotente? NÃO = 🟠 Alta
4. Webhook secret está em variável de ambiente? NÃO = 🔴 Crítica
5. Raw body preservado para verificação (não parsed)? NÃO = 🟠 Alta
6. Timeout e retry handling implementado? NÃO = 🟡 Média
7. IP de origem validado (quando possível)? NÃO = 🔵 Baixa
```

---

## 28. Secure Deserialization — Prevenção

> **Desserialização insegura** pode levar a execução remota de código (RCE) quando dados não confiáveis são desserializados.

### 28.1 Regras

| Regra | Detalhe |
|---|---|
| **NUNCA** desserializar dados do usuário com formatos que executam código | `eval()`, `pickle.loads()`, `yaml.load()` (unsafe), `unserialize()` |
| **SEMPRE** usar formatos seguros | JSON (`JSON.parse`), YAML seguro (`yaml.safe_load`), MessagePack |
| **NUNCA** usar `eval()` para parse de dados | `eval(userInput)` é RCE |

### 28.2 Anti-patterns por linguagem

```javascript
// ❌ INSEGURO — JavaScript
eval(userInput);
new Function(userInput)();
setTimeout(userInput, 0);
setInterval(userInput, 1000);
vm.runInNewContext(userInput);

// ✅ SEGURO
JSON.parse(userInput);  // Apenas dados, nunca executa código
```

```python
# ❌ INSEGURO — Python
import pickle
data = pickle.loads(user_input)      # RCE!
data = yaml.load(user_input)         # RCE com yaml.FullLoader!
eval(user_input)                      # RCE!
exec(user_input)                      # RCE!

# ✅ SEGURO
import json, yaml
data = json.loads(user_input)         # Apenas dados
data = yaml.safe_load(user_input)     # Sem execução de código
```

```php
// ❌ INSEGURO — PHP
$data = unserialize($user_input);     // Object injection!
eval($user_input);                     // RCE!

// ✅ SEGURO
$data = json_decode($user_input, true);
$data = unserialize($user_input, ['allowed_classes' => false]);  // Bloquear classes
```

```java
// ❌ INSEGURO — Java
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(userInput));
Object obj = ois.readObject();        // Deserialization attack!

// ✅ SEGURO — usar filtros ou JSON
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter("!*");
// Ou usar Jackson/Gson para JSON
```

```ruby
# ❌ INSEGURO — Ruby
Marshal.load(user_input)              # RCE!
YAML.load(user_input)                 # RCE com Psych!

# ✅ SEGURO
JSON.parse(user_input)
YAML.safe_load(user_input)
```

#### O que o Sentinela verifica:

```
BUSCAR:
  - eval(userInput), eval($variable), exec(user)
  - pickle.loads, pickle.load (com dados do usuário)
  - yaml.load (sem Loader=yaml.SafeLoader)
  - unserialize() em PHP (com dados do usuário)
  - Marshal.load em Ruby (com dados do usuário)
  - ObjectInputStream.readObject (com dados do usuário)
  - new Function(userInput), setTimeout(stringInput)

QUALQUER desserialização insegura de dados do usuário = 🔴 Crítica
eval() com qualquer input externo = 🔴 Crítica
```

---

## 29. Timing Attacks — Prevenção

> **Timing attacks** exploram diferenças de tempo de resposta para extrair informações (ex: descobrir se um e-mail existe comparando tempos de resposta do login).

### 29.1 Regras

```javascript
// 1. Usar comparação constant-time para tokens, senhas, assinaturas
// NUNCA usar === para comparar secrets

// ❌ INSEGURO — tempo de comparação varia com posição do erro
if (token === expectedToken) { ... }
if (apiKey === validApiKey) { ... }

// ✅ SEGURO — tempo constante
import crypto from 'crypto';

function safeCompare(a, b) {
  if (!a || !b) return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// 2. Login: tempo de resposta constante
// Mesmo quando usuário não existe, executar hash dummy para equalizar tempo
export async function loginHandler(email, password) {
  const user = await db.findUserByEmail(email);

  if (!user) {
    // Executar hash dummy para equalizar tempo de resposta
    await dummyHash(password);
    return { error: 'Credenciais inválidas.' };
  }

  const valid = await verifyPassword(password, user.password_hash);
  if (!valid) {
    return { error: 'Credenciais inválidas.' };
  }

  return { success: true, user };
}
```

```python
# Python — timing-safe comparison
import hmac

def safe_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
```

#### O que o Sentinela verifica:

```
BUSCAR:
  - === ou == usado para comparar tokens/secrets/API keys = 🟡 Média
  - Login com tempo de resposta diferente para "user not found" vs "wrong password" = 🟡 Média
  - Webhook signature comparada com === = 🟠 Alta (timing leak)

Usar crypto.timingSafeEqual ou hmac.compare_digest para TODA comparação de secrets.
```

---

## 30. Subdomain Takeover & DNS Security

> **Subdomain takeover** ocorre quando um subdomínio aponta para um serviço que não está mais configurado (ex: CNAME para Heroku/S3/GitHub Pages abandonado).

### 30.1 Regras

| Verificação | Detalhe |
|---|---|
| DNS records sem serviço ativo | CNAME para serviço desativado = takeover possível |
| Wildcards DNS | `*.meuapp.com` pode ser explorado |
| SPF/DKIM/DMARC | Proteção contra e-mail spoofing |
| CAA records | Restringe quais CAs podem emitir certificados |

### 30.2 Verificações

```bash
# Verificar CNAME records órfãos
dig CNAME subdomain.meuapp.com
# Se aponta para serviço que retorna 404/não existe = 🔴 Crítica

# Verificar SPF
dig TXT meuapp.com | grep spf
# Deve existir: "v=spf1 include:_spf.google.com ~all" (ou equivalente)

# Verificar DMARC
dig TXT _dmarc.meuapp.com
# Deve existir: "v=DMARC1; p=reject; ..." (ou quarantine)

# Verificar CAA
dig CAA meuapp.com
# Deve existir: 0 issue "letsencrypt.org" (ou CA usada)
```

#### O que o Sentinela verifica:

```
SE o projeto tem domínio customizado:

1. CNAME records apontam para serviços ativos? NÃO = 🔴 Crítica
2. SPF configurado? NÃO = 🟡 Média
3. DMARC configurado? NÃO = 🟡 Média
4. DKIM configurado? NÃO = 🟡 Média
5. CAA record configurado? NÃO = 🔵 Baixa
6. Wildcard DNS configurado? SIM = 🟡 Média (avaliar necessidade)
```

---

## 31. Error Handling Patterns — Tratamento Seguro de Exceções

> **Tratamento inconsistente de erros** é uma das maiores fontes de vazamento de informação e crashes em produção.

### 31.1 Padrão universal: try-catch em toda rota

```javascript
// lib/security/error-handler.js

import { genericErrorResponse } from './responses.js';
import logger from './logging.js';

/**
 * Wrapper para API routes que garante tratamento seguro de erros.
 * Captura QUALQUER exceção e retorna resposta genérica.
 */
export function withErrorHandler(handler) {
  return async (req, res) => {
    try {
      return await handler(req, res);
    } catch (error) {
      // Logar erro completo no servidor (stack trace, detalhes)
      logger.error({
        event: 'unhandled_error',
        route: req.url,
        method: req.method,
        error: error.message,
        stack: error.stack,
        requestId: req.headers['x-request-id'],
      });

      // NUNCA enviar detalhes do erro ao cliente
      return genericErrorResponse();
    }
  };
}

// Uso:
export const POST = withErrorHandler(async (req) => {
  // Lógica da rota — se qualquer erro não tratado ocorrer,
  // o wrapper retorna resposta genérica segura
});
```

```python
# Python — decorator equivalente
import functools
import logging

logger = logging.getLogger(__name__)

def with_error_handler(func):
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Unhandled error in {func.__name__}: {e}", exc_info=True)
            return JsonResponse({"error": "Ocorreu um erro. Tente novamente."}, status=500)
    return wrapper
```

### 31.2 Regras de tratamento

| Cenário | Ação correta |
|---|---|
| Erro esperado (validação, not found) | Retornar status HTTP correto + mensagem genérica |
| Erro inesperado (exceção) | Logar no servidor + retornar 500 genérico |
| Erro de banco/ORM | Capturar, logar, retornar genérico (NUNCA expor SQL error) |
| Promise rejection sem catch | Global handler (unhandledRejection) deve logar e NÃO crashar |
| Timeout de serviço externo | Retornar 503/504 genérico, não expor qual serviço falhou |

### 31.3 Global handlers

```javascript
// Capturar erros não tratados globalmente
process.on('unhandledRejection', (reason, promise) => {
  logger.error({ event: 'unhandled_rejection', reason: String(reason) });
  // NÃO crashar em produção — logar e continuar
});

process.on('uncaughtException', (error) => {
  logger.fatal({ event: 'uncaught_exception', error: error.message, stack: error.stack });
  // Em caso de uncaught exception, shutdown graceful é recomendado
  process.exit(1);
});
```

#### O que o Sentinela verifica:

```
BUSCAR:
  - API routes sem try-catch = 🟠 Alta
  - catch(err) { res.json({ error: err.message }) } = 🟠 Alta
  - catch(err) { res.json({ error: err }) } = 🔴 Crítica (expõe objeto inteiro)
  - unhandledRejection handler ausente = 🟡 Média
  - Promise sem .catch() em contexto server = 🟡 Média
  - SQL/ORM error message exposto ao cliente = 🔴 Crítica
```

---

## 32. Request Size & Complexity Limits — Anti-DoS

> **Sem limites de tamanho de request**, um atacante pode enviar payloads enormes para consumir memória/CPU do servidor.

### 32.1 Limites obrigatórios

```javascript
// lib/security/constants.js

export const REQUEST_LIMITS = {
  maxBodySize:         '1mb',     // Body JSON/form padrão
  maxUploadSize:       '5mb',     // Upload de arquivos (ver seção 10)
  maxUrlLength:        2048,      // Tamanho máximo de URL
  maxHeaderSize:       8192,      // Tamanho máximo de um header
  maxQueryParams:      50,        // Número máximo de query parameters
  maxJsonDepth:        10,        // Profundidade máxima de JSON aninhado
  maxArrayItems:       1000,      // Itens máximos em array no body
  requestTimeout:      30000,     // Timeout de request (ms)
  idleTimeout:         120000,    // Timeout de conexão idle (ms)
};
```

### 32.2 Configuração por stack

```javascript
// Express
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ limit: '1mb', extended: true }));

// Next.js (next.config.js)
export default {
  api: {
    bodyParser: {
      sizeLimit: '1mb',
    },
    responseLimit: '4mb',
  },
};

// Fastify
fastify.register(require('@fastify/multipart'), {
  limits: { fileSize: 5 * 1024 * 1024 }
});

// Nginx
client_max_body_size 5m;
client_header_buffer_size 8k;
large_client_header_buffers 4 16k;
```

```python
# Django
DATA_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024  # 1MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024  # 5MB
DATA_UPLOAD_MAX_NUMBER_FIELDS = 50

# FastAPI
from fastapi import Request
@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 1_048_576:  # 1MB
        return JSONResponse({"error": "Payload too large"}, status_code=413)
    return await call_next(request)
```

### 32.3 JSON depth/complexity protection

```javascript
// Prevenir JSON bombs ({a:{b:{c:{d:{e:...}}}}} — profundidade infinita)
export function parseJSONSafe(jsonString, maxDepth = 10) {
  let depth = 0;
  const result = JSON.parse(jsonString, (key, value) => {
    if (typeof value === 'object' && value !== null) {
      depth++;
      if (depth > maxDepth) {
        throw new Error('JSON too deep');
      }
    }
    return value;
  });
  return result;
}

// Prevenir arrays enormes
export function validateArraySize(arr, maxItems = 1000) {
  if (Array.isArray(arr) && arr.length > maxItems) {
    throw new Error('Array too large');
  }
  return arr;
}
```

#### O que o Sentinela verifica:

```
1. Body size limit configurado? NÃO = 🟠 Alta
2. Upload size limit configurado? NÃO = 🟠 Alta
3. Request timeout configurado? NÃO = 🟡 Média
4. JSON depth limit configurado? NÃO = 🟡 Média
5. Query param limit configurado? NÃO = 🔵 Baixa
6. Nginx/proxy com client_max_body_size? NÃO = 🟡 Média
```

---

## 33. Checklist Final do Sentinela — Completo (Seções 1-32)

O checklist abaixo é exposto pela ferramenta `sentinela_get_checklist` e executado automaticamente por `sentinela_audit_full`.
Cada item referencia a ferramenta MCP que o verifica e a seção do knowledge base com a regra.

### Identidade e Autenticação (Seções 2, 8) → `sentinela_audit_identity`, `sentinela_audit_auth`
- [ ] Identidade derivada do JWT/sessão server-side (NUNCA do frontend)
- [ ] Provedor de auth gerenciado (zero auth customizado)
- [ ] Confirmação de e-mail ativa
- [ ] Tokens com expiração curta
- [ ] NENHUM hashing manual de senhas, NENHUMA geração manual de JWT
- [ ] Cookies de auth com HttpOnly, Secure, SameSite

### Input e Validação (Seções 3, 15) → `sentinela_audit_input_validation`, `sentinela_audit_sql_constraints`
- [ ] `maxLength` em todos os inputs HTML
- [ ] Limites definidos em arquivo central de constantes
- [ ] Schema de validação na rota/controller server-side
- [ ] `VARCHAR(n)` / `CHECK` constraint no banco (adaptado ao dialeto SQL)
- [ ] Todas as queries parametrizadas (zero concatenação — anti SQL injection)

### Mutations e Acesso (Seções 2, 6, 16, 20) → `sentinela_audit_mutations`, `sentinela_audit_idor`, `sentinela_audit_csrf`, `sentinela_audit_mass_assignment`
- [ ] Mutations via server-side (nunca client direto ao banco)
- [ ] Proteção IDOR (filtro por owner_id + id em UPDATE/DELETE)
- [ ] CSRF ativo em formulários com cookies de sessão
- [ ] Mass assignment protegido (allowlist de campos, NUNCA spread de body)
- [ ] Campos protegidos (role, is_admin, plan) NUNCA aceitos do cliente

### Controle de Acesso no Banco (Seção 7) → `sentinela_audit_access_control`
- [ ] **PostgreSQL:** RLS habilitado + políticas com auth.uid()
- [ ] **SQL Server:** Security Policies configuradas com SESSION_CONTEXT
- [ ] **Oracle:** VPD policies configuradas
- [ ] **MySQL/MariaDB/SQLite:** Owner_id filtrado em 100% das queries
- [ ] UPDATE policies verificam ownership na entrada E na saída
- [ ] Acesso anônimo não retorna dados protegidos

### Mensagens e Respostas (Seções 4, 31) → `sentinela_audit_error_messages`, `sentinela_audit_error_handling`
- [ ] Mensagens de erro genéricas (sem revelar estado interno)
- [ ] Respostas padronizadas via helpers centralizados
- [ ] NENHUM stack trace em respostas HTTP
- [ ] NENHUM erro de SQL/ORM exposto ao cliente
- [ ] Try-catch em toda API route/controller
- [ ] Global error handlers configurados

### Rate Limiting (Seção 5) → `sentinela_audit_rate_limiting`
- [ ] Rate limit em rotas sensíveis (login, registro, reset)
- [ ] Persistido no banco (não em memória)
- [ ] Configurações centralizadas

### Uploads (Seção 10) → `sentinela_audit_uploads`
- [ ] Magic bytes verificados
- [ ] MIME type validado contra magic bytes
- [ ] Tamanho verificado antes de processar
- [ ] Nome de arquivo gerado pelo servidor

### XSS (Seção 18) → `sentinela_audit_xss`
- [ ] NENHUM output não-escapado de dados do usuário (innerHTML, v-html, etc.)
- [ ] Sanitização via DOMPurify/bleach quando HTML é necessário
- [ ] Content-Security-Policy configurado (sem unsafe-inline em script-src)
- [ ] URLs sanitizadas (bloquear javascript:, data:)

### CORS (Seção 19) → `sentinela_audit_cors`
- [ ] Whitelist explícita de origens (NUNCA `*` com credentials)
- [ ] Origin NUNCA refletido sem validação
- [ ] Vary: Origin presente quando origin é dinâmico

### Dependency Security (Seção 21) → `sentinela_audit_dependencies`
- [ ] Lock file commitado
- [ ] `npm audit` / equivalente sem CVEs críticas/altas
- [ ] Dependabot/Renovate configurado

### Logging (Seção 22) → `sentinela_audit_logging`
- [ ] NENHUMA senha/token/secret em logs
- [ ] Logging em endpoints de auth e mutações críticas
- [ ] Logger com redação automática de campos sensíveis

### SSRF (Seção 23) → `sentinela_audit_ssrf`
- [ ] URLs do usuário validadas antes de fetch server-side
- [ ] IPs privados/internos bloqueados
- [ ] Redirects não seguidos automaticamente

### Open Redirect (Seção 24) → `sentinela_audit_redirects`
- [ ] Redirect URLs validadas contra whitelist/domínio interno
- [ ] Protocolos perigosos bloqueados (javascript:, data:)

### Privacidade (Seção 25) → `sentinela_audit_privacy`
- [ ] Endpoint de exportação de dados do usuário
- [ ] Endpoint de exclusão de conta
- [ ] Dados sensíveis criptografados field-level (se aplicável)
- [ ] DELETE CASCADE configurado para dados do usuário

### Secrets (Seção 26) → `sentinela_audit_secrets`, `sentinela_audit_secrets_mgmt`
- [ ] `.env` no `.gitignore`
- [ ] NENHUMA credencial hardcoded
- [ ] NENHUMA connection string com senha em código
- [ ] .env.example sem valores reais
- [ ] Validação de env vars na inicialização

### Webhooks (Seção 27) → `sentinela_audit_webhooks`
- [ ] Assinatura verificada com timing-safe comparison
- [ ] Handler idempotente
- [ ] Webhook secret em variável de ambiente

### Deserialization (Seção 28) → `sentinela_audit_deserialization`
- [ ] NENHUM eval(), pickle.loads(), unserialize() com dados do usuário
- [ ] Apenas JSON.parse / json.loads / formatos seguros

### Timing Attacks (Seção 29) → `sentinela_audit_timing`
- [ ] Comparação de secrets com timingSafeEqual / compare_digest
- [ ] Login com tempo de resposta constante

### DNS / Subdomain (Seção 30) → `sentinela_audit_dns`
- [ ] Nenhum CNAME órfão apontando para serviço desativado
- [ ] SPF/DMARC configurados

### Request Limits (Seção 32) → `sentinela_audit_request_limits`
- [ ] Body size limit configurado
- [ ] Request timeout configurado
- [ ] JSON depth limit configurado

### Testes e Auditoria (Seção 14) → `sentinela_audit_tests`
- [ ] Diretório tests/security/ existe com testes para cada área
- [ ] Testes de IDOR, SQL injection, XSS, auth bypass escritos
- [ ] Script de teste de segurança configurado e passando
- [ ] Honeypot em formulários públicos

---

## 34. Níveis de Severidade

Mapeamento usado em todo `Finding.severity`:

| Ícone | Nível | `severity` value | Significado | Ação |
|---|---|---|---|---|
| 🔴 | **Crítica** | `critical` | Vulnerabilidade explorável, risco imediato de comprometimento | Bloquear deploy. Corrigir AGORA. |
| 🟠 | **Alta** | `high` | Falha significativa de segurança, requer correção antes de produção | Corrigir antes do próximo deploy. |
| 🟡 | **Média** | `medium` | Melhoria importante de segurança, defense in depth | Corrigir em até 1 sprint. |
| 🔵 | **Baixa** | `low` | Recomendação de hardening, boa prática | Planejar correção futura. |

### Mapeamento CWE / OWASP

Cada finding inclui referências CWE e OWASP quando aplicável:

| Categoria Sentinela | CWE | OWASP Top 10 2021 |
|---|---|---|
| Identity (Seção 2) | CWE-639 (Authorization Bypass) | A01: Broken Access Control |
| Input Validation (Seção 3) | CWE-20 (Improper Input Validation) | A03: Injection |
| Error Messages (Seção 4) | CWE-209 (Info Exposure via Error) | A04: Insecure Design |
| Rate Limiting (Seção 5) | CWE-307 (Brute Force) | A07: Identification Failures |
| IDOR (Seção 6) | CWE-639 (IDOR) | A01: Broken Access Control |
| Access Control (Seção 7) | CWE-862 (Missing Authorization) | A01: Broken Access Control |
| Auth (Seção 8) | CWE-287 (Improper Authentication) | A07: Identification Failures |
| Uploads (Seção 10) | CWE-434 (Unrestricted Upload) | A04: Insecure Design |
| Headers (Seção 11) | CWE-693 (Protection Mechanism Failure) | A05: Security Misconfiguration |
| Secrets (Seção 13) | CWE-798 (Hardcoded Credentials) | A07: Identification Failures |
| SQL Constraints (Seção 15) | CWE-89 (SQL Injection) | A03: Injection |
| CSRF (Seção 16) | CWE-352 (CSRF) | A01: Broken Access Control |
| XSS (Seção 18) | CWE-79 (XSS) | A03: Injection |
| CORS (Seção 19) | CWE-942 (Overly Permissive CORS) | A05: Security Misconfiguration |
| Mass Assignment (Seção 20) | CWE-915 (Mass Assignment) | A04: Insecure Design |
| Dependencies (Seção 21) | CWE-1104 (Unmaintained Component) | A06: Vulnerable Components |
| Logging (Seção 22) | CWE-532 (Info Exposure via Logs) | A09: Logging Failures |
| SSRF (Seção 23) | CWE-918 (SSRF) | A10: SSRF |
| Open Redirect (Seção 24) | CWE-601 (Open Redirect) | A01: Broken Access Control |
| Privacy (Seção 25) | CWE-359 (Privacy Violation) | A04: Insecure Design |
| Deserialization (Seção 28) | CWE-502 (Deserialization) | A08: Software/Data Integrity |
| Timing (Seção 29) | CWE-208 (Timing Side Channel) | A02: Cryptographic Failures |

---

## 35. Modo de Operação do Sentinela (MCP)

O Sentinela opera através de ferramentas MCP que o agente invoca conforme necessário.

### 🔍 Auditoria completa — `sentinela_audit_full`

O agente solicita: "Audite este projeto com o Sentinela."

Fluxo:
```
1. sentinela_detect_stack      → Identifica stack, framework, DB, auth
2. sentinela_audit_*           → Executa TODOS os analyzers relevantes
3. sentinela_generate_report   → Consolida findings em AuditReport
4. Agente recebe AuditReport   → Raciocina sobre findings
5. (Opcional) sentinela_suggest_fix → Sugere correções para findings críticos
```

Output: `AuditReport` com findings estruturados, score de segurança, e checklist.

### 🎯 Auditoria focada — `sentinela_audit_{domain}`

O agente solicita: "Verifique a segurança de autenticação deste projeto."

Fluxo:
```
1. sentinela_detect_stack       → Identifica stack
2. sentinela_audit_auth         → Executa analyzer específico
3. Agente recebe Finding[]      → Raciocina sobre findings específicos
```

Output: `Finding[]` apenas do domínio solicitado.

### 📋 Consulta de regras — `sentinela_get_rules`

O agente solicita: "Quais são as regras de XSS do Sentinela?"

Fluxo:
```
1. sentinela_get_rules({ category: 'xss' })  → Retorna regras da Seção 18
```

Output: Regras formatadas com padrões a buscar, severidades, e exemplos.

### 🔧 Correção assistida — `sentinela_suggest_fix` + `sentinela_validate_fix`

O agente solicita: "Corrija a vulnerabilidade SENT-XSS-003."

Fluxo:
```
1. sentinela_suggest_fix({ finding_id: 'SENT-XSS-003' })  → Sugestão de código
2. Agente aplica a correção
3. sentinela_validate_fix({ finding_id: 'SENT-XSS-003' }) → Confirma ou rejeita
```

Output: Código sugerido + resultado da validação.

### 📊 Comparação de relatórios — `sentinela_compare_reports`

O agente solicita: "Compare com a auditoria anterior."

Fluxo:
```
1. sentinela_compare_reports({ before: report1, after: report2 })
```

Output: Findings novos, resolvidos, e pendentes. Evolução do score.

---

## 36. Estrutura do Projeto Sentinela

### Repositório do produto (Sentinela MCP)

```
sentinela/
├── context.md                          — Este documento (knowledge base + product spec)
│
├── src/                                — Código-fonte do MCP Server
│   ├── server.ts                       — Entry point do MCP server
│   ├── tools/                          — Definições de ferramentas MCP
│   │   ├── detect-stack.ts             — sentinela_detect_stack
│   │   ├── audit-full.ts               — sentinela_audit_full (orquestrador)
│   │   ├── get-rules.ts                — sentinela_get_rules
│   │   ├── get-checklist.ts            — sentinela_get_checklist
│   │   ├── suggest-fix.ts              — sentinela_suggest_fix
│   │   ├── validate-fix.ts             — sentinela_validate_fix
│   │   ├── generate-report.ts          — sentinela_generate_report
│   │   └── compare-reports.ts          — sentinela_compare_reports
│   │
│   ├── analyzers/                      — Analyzers determinísticos (um por domínio)
│   │   ├── identity.ts                 — Seção 2.1: user_id do frontend
│   │   ├── mutations.ts                — Seção 2.2: mutations client→banco
│   │   ├── input-validation.ts         — Seção 3: limites, schemas, constraints
│   │   ├── error-messages.ts           — Seção 4: mensagens que revelam estado
│   │   ├── rate-limiting.ts            — Seção 5: rate limit em rotas sensíveis
│   │   ├── idor.ts                     — Seção 6: UPDATE/DELETE sem ownership
│   │   ├── access-control.ts           — Seção 7: RLS, policies, views
│   │   ├── auth.ts                     — Seção 8: auth customizada
│   │   ├── honeypots.ts                — Seção 9: honeypots em formulários
│   │   ├── uploads.ts                  — Seção 10: upload sem validação
│   │   ├── headers.ts                  — Seção 11: security headers
│   │   ├── plans.ts                    — Seção 12: limites de plano
│   │   ├── secrets.ts                  — Seção 13: credenciais hardcoded
│   │   ├── tests.ts                    — Seção 14: testes de segurança
│   │   ├── sql-constraints.ts          — Seção 15: colunas sem limite
│   │   ├── csrf.ts                     — Seção 16: CSRF
│   │   ├── xss.ts                      — Seção 18: XSS
│   │   ├── cors.ts                     — Seção 19: CORS
│   │   ├── mass-assignment.ts          — Seção 20: mass assignment
│   │   ├── dependencies.ts             — Seção 21: CVEs em deps
│   │   ├── logging.ts                  — Seção 22: dados sensíveis em logs
│   │   ├── ssrf.ts                     — Seção 23: SSRF
│   │   ├── redirects.ts                — Seção 24: open redirect
│   │   ├── privacy.ts                  — Seção 25: LGPD/GDPR
│   │   ├── secrets-mgmt.ts             — Seção 26: secrets management
│   │   ├── webhooks.ts                 — Seção 27: webhook security
│   │   ├── deserialization.ts          — Seção 28: desserialização insegura
│   │   ├── timing.ts                   — Seção 29: timing attacks
│   │   ├── dns.ts                      — Seção 30: subdomain takeover
│   │   ├── error-handling.ts           — Seção 31: tratamento de erros
│   │   └── request-limits.ts           — Seção 32: limites de request
│   │
│   ├── knowledge/                      — Knowledge base estruturado
│   │   ├── rules.ts                    — Regras das Seções 1-32 em formato queryable
│   │   ├── patterns.ts                 — Grep patterns por categoria
│   │   ├── checklist.ts                — Checklist da Seção 33
│   │   ├── severity.ts                 — Mapeamento de severidades
│   │   └── cwe-owasp.ts                — Mapeamento CWE/OWASP
│   │
│   ├── core/                           — Infraestrutura compartilhada
│   │   ├── types.ts                    — Finding, AuditReport, StackInfo, etc.
│   │   ├── grep.ts                     — Wrapper para busca em arquivos
│   │   ├── ast.ts                      — Helpers de análise AST
│   │   ├── config-parser.ts            — Parse de configs (package.json, etc.)
│   │   ├── sql-parser.ts               — Parse de SQL/migrations
│   │   ├── filesystem.ts               — Checks de filesystem
│   │   └── scoring.ts                  — Cálculo de score de segurança
│   │
│   └── utils/                          — Utilitários
│       ├── logger.ts
│       └── errors.ts
│
├── tests/                              — Testes do Sentinela
│   ├── analyzers/                      — Testes unitários de cada analyzer
│   ├── tools/                          — Testes de integração das ferramentas MCP
│   ├── fixtures/                       — Projetos de exemplo para testar
│   │   ├── vulnerable-nextjs/          — Projeto Next.js com vulnerabilidades conhecidas
│   │   ├── vulnerable-django/          — Projeto Django com vulnerabilidades conhecidas
│   │   ├── secure-express/             — Projeto Express seguro (baseline)
│   │   └── ...                         — Outros fixtures por stack
│   └── e2e/                            — Testes end-to-end do MCP
│
├── package.json
├── tsconfig.json
├── README.md
└── LICENSE
```

### Estrutura de segurança recomendada para projetos auditados

Quando o Sentinela audita um projeto, ele recomenda esta estrutura:

```
lib/security/                          (ou src/security/, app/security/, etc.)
├── constants.{ext}                    — Limites, mensagens, rate limits, CORS, CSP, planos
├── schemas.{ext}                      — Schemas de validação de todos os inputs
├── ratelimit.{ext}                    — Rate limiting persistente via banco de dados
├── honeypot.{ext}                     — Campo honeypot + rotas decoy
├── auth.{ext}                         — Extrai user do JWT, ownership, mass assignment guard
├── responses.{ext}                    — Respostas padronizadas (401, 403, 404, 429, 500)
├── cors.{ext}                         — Middleware CORS seguro com whitelist
├── sanitize.{ext}                     — Sanitização de HTML (XSS), URLs, redirects
├── ssrf.{ext}                         — Validação de URLs para fetch server-side
├── image-validator.{ext}              — Validação de upload (magic bytes, MIME, size lock)
├── webhook.{ext}                      — Verificação de assinatura + idempotência
├── logging.{ext}                      — Logger estruturado com sanitização
├── crypto.{ext}                       — Field-level encryption, timing-safe comparison
├── plans.{ext}                        — Verificação de features/limites por plano
├── error-handler.{ext}                — Wrapper de tratamento seguro de erros
├── env-check.{ext}                    — Validação de variáveis de ambiente
├── redirect.{ext}                     — Validação anti open redirect
└── setup.sql                          — Tabelas de segurança + constraints + políticas

tests/security/
├── input-validation.test.{ext}
├── idor.test.{ext}
├── auth.test.{ext}
├── access-control.test.{ext}
├── xss.test.{ext}
├── cors.test.{ext}
├── mass-assignment.test.{ext}
├── error-messages.test.{ext}
├── rate-limiting.test.{ext}
├── sql-injection.test.{ext}
├── ssrf.test.{ext}
├── open-redirect.test.{ext}
├── webhook.test.{ext}
├── deserialization.test.{ext}
└── timing.test.{ext}
```

---

> **Este documento é a fonte de verdade do Sentinela.**
>
> Cobre **36 seções** e **32 domínios de segurança** com verificações, implementações e exemplos multi-stack/multi-dialeto.
>
> **Fase 1:** As seções "O que o Sentinela verifica" são contratos de implementação para os analyzers do MCP.
>
> **Fase 2:** Os `AuditReport` gerados pelo MCP alimentarão o dashboard de segurança.
>
> **Fase 3:** Os findings e o knowledge base serão consumidos pela IA especializada.
>
> O Sentinela DEVE adaptar a sintaxe ao dialeto SQL e à stack detectados no projeto-alvo.
>
> Atualizações devem ser versionadas e documentadas.
