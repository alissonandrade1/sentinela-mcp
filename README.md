<div align="center">

# Sentinela

**Infraestrutura de segurança para agentes de IA via Model Context Protocol (MCP)**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-blue?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20+-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![MCP](https://img.shields.io/badge/MCP-Protocol-8B5CF6)](https://modelcontextprotocol.io/)
[![Vitest](https://img.shields.io/badge/Tests-Vitest-green?logo=vitest)](https://vitest.dev/)
[![License](https://img.shields.io/badge/License-Proprietary-red)](#licença)

</div>

---

## 🎯 Sobre o Sentinela

O **Sentinela** é uma camada de segurança determinística baseada no **Model Context Protocol (MCP)**. Ele permite que qualquer agente de IA (Claude, Gemini, Antigravity, Cursor, Windsurf) audite repositórios de código, detecte vulnerabilidades reais, extraia evidências precisas com números de linha, gere checklists de conformidade e valide correções automaticamente.

- **32 ferramentas MCP disponíveis** (24 analyzers especializados + 8 ferramentas de orquestração e remediação).
- **Zero IA embutida na Fase 1**: auditorias rápidas, determinísticas e reprodutíveis (análise léxica, regex otimizado e inspeção de configurações/arquivos).
- **Knowledge Base viva**: mapeamento direto das 32 diretrizes de segurança do `context.md`.

---

## 🚀 Instalação & Uso

### Pré-requisitos
- Node.js 20+
- npm

### 1. Instalar dependências e compilar

```bash
git clone https://github.com/alissonandrade1/sentinela-mcp.git
cd sentinela
npm install
npm run build
```

### 2. Configurar no seu Cliente MCP

#### Claude Desktop (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "sentinela": {
      "command": "node",
      "args": ["C:/sentinela/dist/server.js"]
    }
  }
}
```

#### Cursor / Antigravity / Windsurf
Adicione às configurações de MCP:
```json
{
  "name": "sentinela",
  "command": "node",
  "args": ["C:/sentinela/dist/server.js"]
}
```

---

## 🛠️ Ferramentas Disponíveis (32 Tools)

### 1. Orquestração e Auditoria
| Ferramenta | Descrição |
|---|---|
| `sentinela_detect_stack` | Identifica linguagem, framework, ORM, banco de dados, auth provider e hosting. |
| `sentinela_audit_full` | Executa todos os 24 analyzers em paralelo/sequencial e retorna o `AuditReport` completo com score (0-100). |
| `sentinela_generate_report` | Transforma o relatório de auditoria em um documento Markdown formatado com sumário, severidades e evidências. |
| `sentinela_compare_reports` | Compara dois relatórios (antes vs depois), calculando findings novos, corrigidos e variação do score. |
| `sentinela_get_checklist` | Avalia 24 itens de conformidade essenciais com status `pass` ou `fail`. |
| `sentinela_get_rules` | Consulta a base de regras (`context.md`) por termo, categoria ou seção, com opção de extrair o texto explicativo. |

### 2. Correção e Validação
| Ferramenta | Descrição |
|---|---|
| `sentinela_suggest_fix` | Sugere correções seguras com exemplos práticos antes/depois ajustados à stack do projeto. |
| `sentinela_validate_fix` | Re-executa o analyzer específico para verificar se o finding foi resolvido sem introduzir regressões. |

### 3. Analyzers Especializados (24 Tools)
Cada categoria pode ser executada isoladamente ou através do `sentinela_audit_full`:

1. **`sentinela_analyze_secrets`** (Seção 13): Chaves de API, tokens JWT, senhas e hashes hardcoded.
2. **`sentinela_analyze_xss`** (Seção 18): `dangerouslySetInnerHTML`, `innerHTML`, `v-html` sem DOMPurify.
3. **`sentinela_analyze_deserialization`** (Seção 28): `eval()`, `Function()`, `pickle.loads()`, `unserialize()`.
4. **`sentinela_analyze_logging`** (Seção 22): Vazamento de credenciais, senhas e tokens em `console.log` e loggers.
5. **`sentinela_analyze_error_messages`** (Seção 4): Stack traces e mensagens de erro brutas retornadas para clientes HTTP.
6. **`sentinela_analyze_timing`** (Seção 29): Comparações de tokens/senhas com `===` ao invés de `timingSafeEqual`.
7. **`sentinela_analyze_identity`** (Seção 2): Parâmetros `user_id` recebidos no body/query em vez de extraídos da sessão/JWT.
8. **`sentinela_analyze_mutations`** (Seção 2): Operações de mutação sem validação de identidade do usuário.
9. **`sentinela_analyze_dependencies`** (Seção 21): Falta de lock files (`package-lock.json`, etc.) e ausência de Dependabot.
10. **`sentinela_analyze_headers`** (Seção 11): Falta de Helmet, HSTS, CSP, X-Frame-Options, X-Content-Type-Options.
11. **`sentinela_analyze_cors`** (Seção 19): `Access-Control-Allow-Origin: *` combinado com credenciais ativas.
12. **`sentinela_analyze_tests`** (Seção 14): Ausência de diretórios ou suites de testes unitários/integração.
13. **`sentinela_analyze_secrets_mgmt`** (Seção 26): Ausência de `.env.example` e verificação de `.env` rastreado pelo git.
14. **`sentinela_analyze_request_limits`** (Seção 32): Ausência de limites de payload (`limit: '10mb'`, etc.) e timeouts.
15. **`sentinela_analyze_idor`** (Seção 6): `UPDATE` e `DELETE` em ORMs/SQL sem filtro de ownership (`where: { id }` sem `userId`).
16. **`sentinela_analyze_mass_assignment`** (Seção 20): `...req.body` repassado diretamente para `create()` ou `update()`.
17. **`sentinela_analyze_error_handling`** (Seção 31): Handlers assíncronos sem `try-catch` e ausência de middleware global de erros.
18. **`sentinela_analyze_uploads`** (Seção 10): Upload de arquivos sem validação de mimetype, tamanho ou sanitização de nome.
19. **`sentinela_analyze_ssrf`** (Seção 23): Requisições HTTP (`fetch`, `axios`) disparadas com URLs controladas pelo usuário sem validação.
20. **`sentinela_analyze_redirects`** (Seção 24): Redirecionamentos HTTP baseados em parâmetros do usuário (Open Redirect).
21. **`sentinela_analyze_rate_limiting`** (Seção 5): Rotas sensíveis (login, register, reset-password) sem rate limit.
22. **`sentinela_analyze_auth`** (Seção 8): Hashing fraco (MD5, SHA1), JWTs sem expiração configurada e cookies sem flag segura.
23. **`sentinela_analyze_webhooks`** (Seção 27): Handlers de webhook sem conferência de assinatura criptográfica (HMAC) e idempotência.
24. **`sentinela_analyze_input_validation`** (Seção 3): Rotas e endpoints sem esquemas de validação de payload (Zod, Yup, Joi).

---

## 🧪 Testes

```bash
# Executar a suite de testes unitários (Vitest)
npm test

# Executar o teste smoke contra fixture vulnerável
npx tsx tests/smoke.ts
```

---

## 📄 Licença

Proprietário. Todos os direitos reservados.
