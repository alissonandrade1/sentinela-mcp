# 🤝 Guia de Contribuição — Sentinela

Obrigado pelo interesse em contribuir com o **Sentinela**! Este é um projeto open source voltado para criar uma infraestrutura robusta e determinística de segurança para agentes de IA via Model Context Protocol (MCP).

---

## 📌 Código de Conduta

Ao participar deste projeto, você concorda em manter um ambiente respeitoso, colaborativo e livre de assédio para todos os contribuidores. Consulte o arquivo [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) para detalhes.

---

## 🛠️ Configuração do Ambiente Local

### Pré-requisitos

- **Node.js** >= 20.0.0
- **npm** >= 10.0.0
- **Git**

### Passo a Passo

```bash
# 1. Faça o fork do repositório no GitHub e clone o seu fork:
git clone https://github.com/SEU_USUARIO/sentinela-mcp.git
cd sentinela-mcp

# 2. Instale as dependências:
npm install

# 3. Rode os testes para certificar que tudo está funcionando:
npm test

# 4. Inicie o servidor em modo de observação (watch):
npm run dev
```

---

## 🧪 Scripts Disponíveis

| Comando | Descrição |
|---|---|
| `npm run dev` | Executa o servidor via `tsx` com recarga automática ao alterar arquivos. |
| `npm test` | Executa os testes unitários via Vitest. |
| `npm run test:watch` | Executa os testes em modo interativo/watch. |
| `npm run typecheck` | Executa a validação de tipos TypeScript (`tsc --noEmit`). |
| `npm run lint` | Executa o linter ESLint no diretório `src/`. |
| `npm run build` | Compila os arquivos TypeScript para ESM em `dist/` usando `tsup`. |

---

## 📐 Adicionando um Novo Analisador de Segurança

Se você deseja adicionar um novo analisador ou regra de segurança:

1. **Crie o analisador** em `src/analyzers/<categoria>.ts`.
2. **Implemente a interface `Analyzer`** (`src/core/types.ts`):
   - Deve retornar findings determinísticos com `id`, `category`, `severity`, `title`, `description`, `file`, `line`, `snippet` e `recommendation`.
3. **Registre a ferramenta** em `src/server.ts` na lista de ferramentas e analyzers.
4. **Adicione testes** em `tests/` comprovando detecção e ausência de falsos positivos óbvios.
5. **Atualize o `context.md`** caso novas diretrizes ou regras sejam introduzidas.

---

## 🔄 Fluxo de Pull Requests

1. Crie uma branch a partir da `main`:
   ```bash
   git checkout -b feat/meu-novo-recurso
   ```
2. Escreva código limpo, tipado e com testes cobrindo as alterações.
3. Garanta que todas as verificações passam:
   ```bash
   npm run typecheck
   npm run lint
   npm test
   npm run build
   ```
4. Siga as convenções de **Conventional Commits**:
   - `feat:` Novos recursos, analisadores ou ferramentas
   - `fix:` Correção de bugs ou falsos positivos
   - `docs:` Alterações na documentação
   - `test:` Adição ou melhoria de testes
   - `refactor:` Refatoração de código sem alteração funcional
   - `chore:` Tarefas de manutenção ou dependências
5. Envie seu Pull Request no GitHub com uma descrição clara do objetivo da mudança.

---

## 🔒 Segurança & Vulnerabilidades

Para reportar vulnerabilidades encontradas no próprio Sentinela, consulte nossa política de segurança em [SECURITY.md](SECURITY.md).
