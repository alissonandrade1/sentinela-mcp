/**
 * Sentinela — Filesystem Helpers
 *
 * Operações de filesystem usadas por analyzers e tools.
 */

import { readdir, readFile, stat, access } from "node:fs/promises";
import { join, relative, extname } from "node:path";
import { constants } from "node:fs";

// ============================================================================
// File existence & reading
// ============================================================================

/** Verifica se um arquivo ou diretório existe */
export async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

/** Verifica se é um diretório */
export async function isDirectory(filePath: string): Promise<boolean> {
  try {
    const s = await stat(filePath);
    return s.isDirectory();
  } catch {
    return false;
  }
}

/** Lê arquivo como string. Retorna null se não existir. */
export async function readFileContent(filePath: string): Promise<string | null> {
  try {
    return await readFile(filePath, "utf-8");
  } catch {
    return null;
  }
}

/** Lê e parseia JSON. Retorna null se falhar. */
export async function readJSON<T = unknown>(filePath: string): Promise<T | null> {
  const content = await readFileContent(filePath);
  if (!content) return null;
  try {
    return JSON.parse(content) as T;
  } catch {
    return null;
  }
}

// ============================================================================
// Directory listing
// ============================================================================

/** Lista arquivos em um diretório (não recursivo) */
export async function listFiles(dirPath: string): Promise<string[]> {
  try {
    const entries = await readdir(dirPath, { withFileTypes: true });
    return entries
      .filter((e) => e.isFile())
      .map((e) => e.name);
  } catch {
    return [];
  }
}

/** Lista subdiretórios (não recursivo) */
export async function listDirs(dirPath: string): Promise<string[]> {
  try {
    const entries = await readdir(dirPath, { withFileTypes: true });
    return entries
      .filter((e) => e.isDirectory())
      .map((e) => e.name);
  } catch {
    return [];
  }
}

// ============================================================================
// File finding
// ============================================================================

const DEFAULT_IGNORE = [
  "node_modules", ".git", ".next", ".nuxt", "dist", "build",
  "out", "coverage", "__pycache__", "venv", ".venv", "vendor",
  "target", "bin", "obj",
];

/**
 * Encontra arquivos recursivamente por extensão ou nome.
 * Retorna caminhos relativos ao rootPath.
 */
export async function findFiles(
  rootPath: string,
  options?: {
    extensions?: string[];
    names?: string[];
    ignoreDirs?: string[];
    maxResults?: number;
  },
): Promise<string[]> {
  const results: string[] = [];
  const maxResults = options?.maxResults ?? 500;
  const ignoreDirs = options?.ignoreDirs ?? DEFAULT_IGNORE;

  async function walk(currentPath: string): Promise<void> {
    if (results.length >= maxResults) return;

    let entries;
    try {
      entries = await readdir(currentPath, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (results.length >= maxResults) return;
      const fullPath = join(currentPath, entry.name);

      if (entry.isDirectory()) {
        if (!ignoreDirs.includes(entry.name)) {
          await walk(fullPath);
        }
      } else if (entry.isFile()) {
        let include = false;

        if (options?.names && options.names.includes(entry.name)) {
          include = true;
        }

        if (!include && options?.extensions) {
          const ext = extname(entry.name).toLowerCase();
          if (options.extensions.includes(ext)) {
            include = true;
          }
        }

        // Se nenhum filtro especificado, incluir tudo
        if (!options?.names && !options?.extensions) {
          include = true;
        }

        if (include) {
          results.push(relative(rootPath, fullPath).replace(/\\/g, "/"));
        }
      }
    }
  }

  await walk(rootPath);
  return results;
}

/**
 * Encontra o primeiro arquivo que corresponde a um dos nomes.
 * Útil para encontrar configs (package.json, settings.py, etc.)
 */
export async function findFirstFile(
  rootPath: string,
  names: string[],
): Promise<string | null> {
  // Primeiro, verificar na raiz
  for (const name of names) {
    if (await fileExists(join(rootPath, name))) {
      return name;
    }
  }

  // Depois, buscar recursivamente (max 1 resultado)
  const found = await findFiles(rootPath, { names, maxResults: 1 });
  return found[0] ?? null;
}
