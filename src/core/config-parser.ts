/**
 * Sentinela — Config Parser
 *
 * Parseia arquivos de configuração de projetos para extrair
 * informações de stack, dependências e configurações.
 */

import { join } from "node:path";
import { readJSON, readFileContent, fileExists } from "./filesystem.js";

// ============================================================================
// Types
// ============================================================================

export interface PackageJSON {
  name?: string;
  version?: string;
  private?: boolean;
  type?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  [key: string]: unknown;
}

export interface EnvVars {
  [key: string]: string;
}

// ============================================================================
// Package.json
// ============================================================================

/** Lê e parseia package.json */
export async function parsePackageJSON(projectPath: string): Promise<PackageJSON | null> {
  return readJSON<PackageJSON>(join(projectPath, "package.json"));
}

/** Retorna todas as dependências (deps + devDeps + peerDeps) */
export function getAllDependencies(pkg: PackageJSON): Record<string, string> {
  return {
    ...pkg.dependencies,
    ...pkg.devDependencies,
    ...pkg.peerDependencies,
  };
}

/** Verifica se uma dependência existe */
export function hasDependency(pkg: PackageJSON, name: string): boolean {
  const allDeps = getAllDependencies(pkg);
  return name in allDeps;
}

/** Verifica se alguma das dependências existe */
export function hasAnyDependency(pkg: PackageJSON, names: string[]): boolean {
  const allDeps = getAllDependencies(pkg);
  return names.some((name) => name in allDeps);
}

/** Retorna qual das dependências existe (primeira encontrada) */
export function findDependency(pkg: PackageJSON, names: string[]): string | null {
  const allDeps = getAllDependencies(pkg);
  return names.find((name) => name in allDeps) ?? null;
}

// ============================================================================
// Python configs
// ============================================================================

export interface PythonProject {
  name?: string;
  dependencies: string[];
  framework?: string;
}

/** Parseia requirements.txt */
export async function parseRequirements(projectPath: string): Promise<string[]> {
  const content = await readFileContent(join(projectPath, "requirements.txt"));
  if (!content) return [];

  return content
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => line.split(/[=<>!~]/)[0]!.trim().toLowerCase());
}

/** Parseia pyproject.toml de forma simplificada */
export async function parsePyProject(projectPath: string): Promise<PythonProject | null> {
  const content = await readFileContent(join(projectPath, "pyproject.toml"));
  if (!content) return null;

  const deps: string[] = [];

  // Extrair dependências básicas
  const depsMatch = content.match(/dependencies\s*=\s*\[([\s\S]*?)\]/);
  if (depsMatch?.[1]) {
    const depLines = depsMatch[1].match(/"([^"]+)"/g);
    if (depLines) {
      for (const d of depLines) {
        const name = d.replace(/"/g, "").split(/[=<>!~]/)[0]!.trim().toLowerCase();
        deps.push(name);
      }
    }
  }

  return { dependencies: deps };
}

// ============================================================================
// .env files
// ============================================================================

/** Parseia arquivo .env (key=value). NÃO lê secrets reais — apenas keys. */
export async function parseEnvFile(filePath: string): Promise<EnvVars> {
  const content = await readFileContent(filePath);
  if (!content) return {};

  const vars: EnvVars = {};
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const eqIndex = trimmed.indexOf("=");
    if (eqIndex > 0) {
      const key = trimmed.substring(0, eqIndex).trim();
      const value = trimmed.substring(eqIndex + 1).trim();
      vars[key] = value;
    }
  }
  return vars;
}

// ============================================================================
// Generic config detection
// ============================================================================

/** Verifica se um arquivo de config existe no projeto */
export async function hasConfig(
  projectPath: string,
  filename: string,
): Promise<boolean> {
  return fileExists(join(projectPath, filename));
}

/** Lê e retorna o conteúdo de um arquivo de config */
export async function readConfig(
  projectPath: string,
  filename: string,
): Promise<string | null> {
  return readFileContent(join(projectPath, filename));
}

/** Lê e parseia um JSON config */
export async function readJSONConfig<T = unknown>(
  projectPath: string,
  filename: string,
): Promise<T | null> {
  return readJSON<T>(join(projectPath, filename));
}
