/**
 * Sentinela — Grep Engine
 *
 * Busca de padrões regex em arquivos de projeto.
 * Base para todos os analyzers de grep pattern.
 */

import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative, extname } from "node:path";

// ============================================================================
// Types
// ============================================================================

export interface GrepMatch {
  file: string;       // caminho relativo ao projeto
  line: number;       // número da linha (1-indexed)
  column: number;     // coluna do match (0-indexed)
  content: string;    // conteúdo da linha
  match: string;      // texto que deu match
}

export interface GrepOptions {
  /** Padrão regex para buscar */
  pattern: RegExp;

  /** Extensões de arquivo para incluir (ex: [".ts", ".js", ".tsx"]) */
  extensions?: string[];

  /** Diretórios para ignorar */
  ignoreDirs?: string[];

  /** Globs de arquivo para incluir (ex: ["*.ts", "*.js"]) — alternativa a extensions */
  includeGlobs?: string[];

  /** Máximo de matches para retornar (default: 200) */
  maxMatches?: number;

  /** Arquivos específicos para buscar (ignora extensions/globs) */
  files?: string[];
}

// ============================================================================
// Defaults
// ============================================================================

const DEFAULT_IGNORE_DIRS = [
  "node_modules",
  ".git",
  ".next",
  ".nuxt",
  ".svelte-kit",
  "dist",
  "build",
  "out",
  ".output",
  "coverage",
  "__pycache__",
  ".pytest_cache",
  "venv",
  ".venv",
  "env",
  ".env",
  "vendor",
  "target",
  "bin",
  "obj",
  ".idea",
  ".vscode",
];

const DEFAULT_EXTENSIONS = [
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".py",
  ".rb",
  ".php",
  ".java",
  ".cs",
  ".go",
  ".rs",
  ".vue", ".svelte",
  ".html", ".htm",
  ".ejs", ".hbs", ".pug",
  ".json",
  ".yaml", ".yml",
  ".toml",
  ".sql",
  ".env.example",
  ".gitignore",
];

const MAX_FILE_SIZE = 1024 * 1024; // 1MB — ignorar arquivos maiores

// ============================================================================
// Core
// ============================================================================

/**
 * Busca por padrões em arquivos de um projeto.
 * Retorna matches com arquivo, linha, coluna e conteúdo.
 */
export async function grep(
  projectPath: string,
  options: GrepOptions,
): Promise<GrepMatch[]> {
  const matches: GrepMatch[] = [];
  const maxMatches = options.maxMatches ?? 200;
  const ignoreDirs = options.ignoreDirs ?? DEFAULT_IGNORE_DIRS;
  const extensions = options.extensions ?? DEFAULT_EXTENSIONS;

  // Se arquivos específicos foram fornecidos, buscar apenas neles
  if (options.files && options.files.length > 0) {
    for (const file of options.files) {
      if (matches.length >= maxMatches) break;
      const fullPath = join(projectPath, file);
      await searchFile(fullPath, file, options.pattern, matches, maxMatches);
    }
    return matches;
  }

  // Caso contrário, caminhar pelo diretório
  await walkAndSearch(
    projectPath,
    projectPath,
    options.pattern,
    extensions,
    ignoreDirs,
    matches,
    maxMatches,
  );

  return matches;
}

/**
 * Busca por múltiplos padrões de uma vez.
 * Mais eficiente que chamar grep() N vezes (lê cada arquivo apenas 1x).
 */
export async function grepMulti(
  projectPath: string,
  patterns: { id: string; pattern: RegExp }[],
  options?: Omit<GrepOptions, "pattern">,
): Promise<Map<string, GrepMatch[]>> {
  const results = new Map<string, GrepMatch[]>();
  for (const p of patterns) {
    results.set(p.id, []);
  }

  const maxMatches = options?.maxMatches ?? 200;
  const ignoreDirs = options?.ignoreDirs ?? DEFAULT_IGNORE_DIRS;
  const extensions = options?.extensions ?? DEFAULT_EXTENSIONS;

  async function processFile(fullPath: string, relativePath: string) {
    let content: string;
    try {
      const fileStat = await stat(fullPath);
      if (fileStat.size > MAX_FILE_SIZE) return;
      content = await readFile(fullPath, "utf-8");
    } catch {
      return;
    }

    const lines = content.split("\n");

    for (const { id, pattern } of patterns) {
      const patternMatches = results.get(id)!;
      if (patternMatches.length >= maxMatches) continue;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        const regex = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g");
        let m: RegExpExecArray | null;

        while ((m = regex.exec(line)) !== null) {
          patternMatches.push({
            file: relativePath,
            line: i + 1,
            column: m.index,
            content: line.trimEnd(),
            match: m[0],
          });
          if (patternMatches.length >= maxMatches) break;
        }
        if (patternMatches.length >= maxMatches) break;
      }
    }
  }

  await walkDir(projectPath, projectPath, extensions, ignoreDirs, processFile);

  return results;
}

// ============================================================================
// Internal helpers
// ============================================================================

async function walkAndSearch(
  rootPath: string,
  currentPath: string,
  pattern: RegExp,
  extensions: string[],
  ignoreDirs: string[],
  matches: GrepMatch[],
  maxMatches: number,
): Promise<void> {
  if (matches.length >= maxMatches) return;

  let entries;
  try {
    entries = await readdir(currentPath, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (matches.length >= maxMatches) return;

    const fullPath = join(currentPath, entry.name);

    if (entry.isDirectory()) {
      if (!ignoreDirs.includes(entry.name)) {
        await walkAndSearch(rootPath, fullPath, pattern, extensions, ignoreDirs, matches, maxMatches);
      }
    } else if (entry.isFile()) {
      if (shouldIncludeFile(entry.name, extensions)) {
        const relativePath = relative(rootPath, fullPath).replace(/\\/g, "/");
        await searchFile(fullPath, relativePath, pattern, matches, maxMatches);
      }
    }
  }
}

async function walkDir(
  rootPath: string,
  currentPath: string,
  extensions: string[],
  ignoreDirs: string[],
  callback: (fullPath: string, relativePath: string) => Promise<void>,
): Promise<void> {
  let entries;
  try {
    entries = await readdir(currentPath, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = join(currentPath, entry.name);

    if (entry.isDirectory()) {
      if (!ignoreDirs.includes(entry.name)) {
        await walkDir(rootPath, fullPath, extensions, ignoreDirs, callback);
      }
    } else if (entry.isFile()) {
      if (shouldIncludeFile(entry.name, extensions)) {
        const relativePath = relative(rootPath, fullPath).replace(/\\/g, "/");
        await callback(fullPath, relativePath);
      }
    }
  }
}

async function searchFile(
  fullPath: string,
  relativePath: string,
  pattern: RegExp,
  matches: GrepMatch[],
  maxMatches: number,
): Promise<void> {
  let content: string;
  try {
    const fileStat = await stat(fullPath);
    if (fileStat.size > MAX_FILE_SIZE) return;
    content = await readFile(fullPath, "utf-8");
  } catch {
    return;
  }

  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    if (matches.length >= maxMatches) return;

    const line = lines[i]!;
    const regex = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g");
    let m: RegExpExecArray | null;

    while ((m = regex.exec(line)) !== null) {
      matches.push({
        file: relativePath,
        line: i + 1,
        column: m.index,
        content: line.trimEnd(),
        match: m[0],
      });
      if (matches.length >= maxMatches) return;
    }
  }
}

function shouldIncludeFile(filename: string, extensions: string[]): boolean {
  // Arquivos sem extensão que devem ser incluídos
  if (filename === ".gitignore" || filename === ".env.example" || filename === "Dockerfile") {
    return true;
  }
  const ext = extname(filename).toLowerCase();
  return extensions.includes(ext);
}
