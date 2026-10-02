<div align="center">

# 🛡️ Sentinela

**Infraestrutura de Segurança e Auditoria de Código para Agentes de IA via Model Context Protocol (MCP)**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-blue?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20+-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![MCP](https://img.shields.io/badge/MCP-Protocol-8B5CF6)](https://modelcontextprotocol.io/)
[![Security](https://img.shields.io/badge/Privacy-100%25%20Local-success)](#-privacidade--segurança)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## 🎯 Visão Geral

O **Sentinela** é uma solução corporativa de auditoria estática de segurança e conformidade arquitetural projetada para ser consumida diretamente por agentes de IA (Claude, Gemini, Cursor, Antigravity, Windsurf).

Operando via protocolo padrão **MCP (Model Context Protocol)**, ele atua como um inspetor de segurança determinístico: analisa código, configurações e dependências em milissegundos, gerando relatórios de risco, checklists de conformidade e sugestões acionáveis de remediação.

- **32 Ferramentas MCP**: 24 analisadores especializados por categoria de vulnerabilidade + 8 ferramentas de orquestração, diff e validação de correções.
- **Auditoria 100% Determinística**: Sem alucinações ou variações estocásticas — regras precisas com extração de arquivo, linha e snippet de evidência.
- **Stack-Aware**: Identifica automaticamente a linguagem, framework, ORM e banco de dados do projeto auditado para adaptar diagnósticos e recomendações.
- **Privacidade Absoluta**: Nenhuma linha de código ou metadado sai da sua infraestrutura ou máquina local.

---

## 🔒 Privacidade & Segurança

O Sentinela foi desenvolvido especificamente para atender requisitos corporativos e ambientes restritos:

- **Execução Local (On-Premise / Stdio)**: Todas as análises ocorrem localmente no processo do servidor MCP via `stdio`.
- **Zero Telemetria / Sem Conexões Externas**: Não envia dados para nuvens de terceiros ou servidores externos.
- **Seguro para Código Proprietário**: Totalmente compatível com projetos confidenciais e ambientes com políticas rígidas de compliance (LGPD, GDPR, SOC 2).

---

## 🚀 Como Configurar no seu Cliente MCP

O Sentinela conecta-se diretamente ao seu agente ou IDE compatível com MCP através do comando `sentinela`.

### Claude Desktop
No seu arquivo de configuração `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sentinela": {
      "command": "sentinela"
    }
  }
}
```

### Cursor / Antigravity / Windsurf / VS Code
Adicione às configurações de MCP do seu ambiente:

```json
{
  "name": "sentinela",
  "command": "sentinela"
}
```

---

## ⚡ Prompts & Slash Commands (`/`)

Clientes que suportam MCP Prompts (como **Claude Desktop**) expõem fluxos prontos que podem ser acionados diretamente no chat via `/`:

| Comando | Descrição |
|---|---|
| `/audit` | Auditoria completa de segurança no projeto com relatório detalhado e score. |
| `/audit_category` | Análise focada em uma vulnerabilidade ou categoria específica (ex: `xss`, `secrets`, `auth`, `idor`, `rate-limiting`, etc.). |
| `/fix_finding` | Orienta a correção de um finding e executa a validação determinística para confirmar que o problema foi eliminado. |
| `/checklist` | Gera a matriz de conformidade com 24 verificações essenciais e status `pass` / `fail`. |
| `/security_rules` | Consulta as diretrizes e regras arquiteturais de segurança da base de conhecimento (`context.md`). |

---

## 🛠️ Ferramentas Disponíveis (32 Tools)

### 1. Orquestração e Auditoria
| Ferramenta | Descrição |
|---|---|
| `sentinela_detect_stack` | Identifica linguagem, framework, ORM, banco de dados, auth provider e hosting da aplicação. |
| `sentinela_audit_full` | Executa todos os 24 analisadores em lote e retorna o `AuditReport` completo com score de risco (0-100). |
| `sentinela_generate_report` | Converte a auditoria em um relatório detalhado formatado em Markdown pronto para documentação e entrega. |
| `sentinela_compare_reports` | Compara dois relatórios (antes vs depois) detalhando vulnerabilidades corrigidas, novos riscos e evolução de pontuação. |
| `sentinela_get_checklist` | Gera checklist de 24 pontos de segurança com verificação binária de conformidade (`pass` / `fail`). |
| `sentinela_get_rules` | Consulta a base de diretrizes e regras de segurança por termo, categoria ou seção. |

### 2. Remediação & Validação
| Ferramenta | Descrição |
|---|---|
| `sentinela_suggest_fix` | Sugere implementações seguras com exemplos práticos antes/depois ajustados à stack tecnológica do projeto. |
| `sentinela_validate_fix` | Re-executa o analisador correspondente para validar de forma determinística se a correção eliminou a vulnerabilidade. |

### 3. Analisadores Especializados (24 Tools)
Cada analisador pode ser invocado de forma granular pelo agente:

1. **`sentinela_analyze_secrets`**: Chaves de API, segredos, senhas e tokens expostos no código.
2. **`sentinela_analyze_xss`**: Vulnerabilidades de Cross-Site Scripting (`dangerouslySetInnerHTML`, `innerHTML`, `v-html`).
3. **`sentinela_analyze_deserialization`**: Desserialização e execução de código insegura (`eval`, `Function`, `pickle`, `unserialize`).
4. **`sentinela_analyze_logging`**: Vazamento de credenciais, PII ou informações sensíveis em logs.
5. **`sentinela_analyze_error_messages`**: Exposição de stack traces ou mensagens técnicas em respostas de API.
6. **`sentinela_analyze_timing`**: Comparações de segredos suscetíveis a ataques de temporização (Timing Attacks).
7. **`sentinela_analyze_identity`**: Parâmetros de identidade (`user_id`) confiados a partir de payload do cliente.
8. **`sentinela_analyze_mutations`**: Operações de mutação de dados sem validação de identidade do usuário.
9. **`sentinela_analyze_dependencies`**: Ausência de lockfiles imutáveis e configurações de monitoramento automatizado.
10. **`sentinela_analyze_headers`**: Ausência de cabeçalhos de segurança HTTP essenciais (CSP, HSTS, X-Frame-Options, etc.).
11. **`sentinela_analyze_cors`**: Configurações de CORS permissivas com credenciais ativas.
12. **`sentinela_analyze_tests`**: Verificação de cobertura e existência de testes de segurança.
13. **`sentinela_analyze_secrets_mgmt`**: Gestão segura de variáveis de ambiente e modelos de `.env.example`.
14. **`sentinela_analyze_request_limits`**: Limites de tamanho de payload HTTP e proteção contra exaustão de recursos.
15. **`sentinela_analyze_idor`**: Vulnerabilidades de referência direta insegura a objetos em mutações (UPDATE/DELETE).
16. **`sentinela_analyze_mass_assignment`**: Injeção de propriedades não autorizadas via espalhamento de payload (`...req.body`).
17. **`sentinela_analyze_error_handling`**: Rotas assíncronas desprotegidas e ausência de manipuladores globais de exceção.
18. **`sentinela_analyze_uploads`**: Upload de arquivos sem validação rigorosa de tipo MIME, extensão ou tamanho.
19. **`sentinela_analyze_ssrf`**: Requisições de rede originadas no servidor com destinos controlados pelo usuário.
20. **`sentinela_analyze_redirects`**: Redirecionamentos abertos baseados em entradas não validadas (Open Redirect).
21. **`sentinela_analyze_rate_limiting`**: Ausência de limitação de taxa em endpoints sensíveis (autenticação, recuperação).
22. **`sentinela_analyze_auth`**: Algoritmos fracos de hash, tokens JWT sem expiração ou cookies sem flags de segurança.
23. **`sentinela_analyze_webhooks`**: Endpoints de webhook sem conferência de assinatura criptográfica (HMAC) e idempotência.
24. **`sentinela_analyze_input_validation`**: Endpoints de API sem esquemas rigorosos de validação de entrada (Zod, Yup, Joi).

---

## 💻 Desenvolvimento Local & Contribuição

Para clonar e testar o projeto localmente:

```bash
# 1. Clonar o repositório
git clone https://github.com/alissonandrade1/sentinela-mcp.git
cd sentinela-mcp

# 2. Instalar dependências
npm install

# 3. Rodar a suíte de testes
npm test

# 4. Executar em modo watch (desenvolvimento)
npm run dev

# 5. Compilar o bundle de produção
npm run build
```

Para diretrizes de contribuição, padrões de código e convenções de commit, consulte o arquivo [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 📄 Licenciamento

Distribuído sob a licença **MIT**. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

