/**
 * Sentinela — Stack Detector
 *
 * Detecta linguagem, framework, ORM, banco de dados, auth provider e hosting
 * de um projeto analisando arquivos de configuração e dependências.
 *
 * Referência: context.md — Seção "Detecção Automática de Stack"
 */

import type { StackInfo } from "../core/types.js";
import {
  parsePackageJSON,
  parseRequirements,
  parsePyProject,
  hasDependency,
  findDependency,
  type PackageJSON,
} from "../core/config-parser.js";
import { fileExists, findFiles } from "../core/filesystem.js";
import { join } from "node:path";

// ============================================================================
// Main
// ============================================================================

export async function detectStack(projectPath: string): Promise<StackInfo> {
  const stack: StackInfo = {
    language: "unknown",
    framework: "unknown",
    database: "unknown",
    sql_dialect: "unknown",
  };

  // Tentar Node.js / JavaScript / TypeScript primeiro
  const pkg = await parsePackageJSON(projectPath);
  if (pkg) {
    stack.language = await detectLanguageFromPkg(pkg, projectPath);
    stack.framework = detectFramework(pkg);
    stack.orm = detectORM(pkg);
    stack.database = detectDatabase(pkg);
    stack.sql_dialect = detectSQLDialect(pkg);
    stack.auth_provider = detectAuth(pkg);
    stack.hosting = await detectHosting(projectPath);
    return stack;
  }

  // Tentar Python
  const pyDeps = await detectPython(projectPath);
  if (pyDeps) {
    stack.language = "Python";
    stack.framework = detectPythonFramework(pyDeps);
    stack.orm = detectPythonORM(pyDeps);
    stack.database = detectPythonDatabase(pyDeps);
    stack.sql_dialect = mapDatabaseToDialect(stack.database);
    stack.auth_provider = detectPythonAuth(pyDeps);
    stack.hosting = await detectHosting(projectPath);
    return stack;
  }

  // Tentar outras linguagens por extensões de arquivo
  stack.language = await detectLanguageByFiles(projectPath);
  stack.hosting = await detectHosting(projectPath);

  return stack;
}

// ============================================================================
// Language Detection
// ============================================================================

async function detectLanguageFromPkg(pkg: PackageJSON, projectPath: string): Promise<string> {
  if (hasDependency(pkg, "typescript") || await fileExists(join(projectPath, "tsconfig.json"))) {
    return "TypeScript";
  }
  return "JavaScript";
}

async function detectLanguageByFiles(projectPath: string): Promise<string> {
  const checks: [string, string[]][] = [
    ["Go", ["go.mod", "go.sum"]],
    ["Ruby", ["Gemfile", "Rakefile"]],
    ["PHP", ["composer.json"]],
    ["Java", ["pom.xml", "build.gradle", "build.gradle.kts"]],
    ["C#", ["*.csproj", "*.sln"]],
    ["Rust", ["Cargo.toml"]],
  ];

  for (const [lang, files] of checks) {
    for (const file of files) {
      if (file.includes("*")) {
        const found = await findFiles(projectPath, { extensions: [file.replace("*", "")], maxResults: 1 });
        if (found.length > 0) return lang;
      } else {
        if (await fileExists(join(projectPath, file))) return lang;
      }
    }
  }

  return "unknown";
}

// ============================================================================
// Framework Detection (Node.js)
// ============================================================================

function detectFramework(pkg: PackageJSON): string {
  const frameworkMap: [string[], string][] = [
    [["next"], "Next.js"],
    [["nuxt", "nuxt3"], "Nuxt"],
    [["@sveltejs/kit"], "SvelteKit"],
    [["@remix-run/node", "@remix-run/react"], "Remix"],
    [["astro"], "Astro"],
    [["express"], "Express"],
    [["fastify"], "Fastify"],
    [["hono"], "Hono"],
    [["koa"], "Koa"],
    [["@nestjs/core"], "NestJS"],
    [["@adonisjs/core"], "AdonisJS"],
  ];

  for (const [deps, name] of frameworkMap) {
    const found = findDependency(pkg, deps);
    if (found) return name;
  }

  return "unknown";
}

// ============================================================================
// ORM Detection (Node.js)
// ============================================================================

function detectORM(pkg: PackageJSON): string | undefined {
  const ormMap: [string[], string][] = [
    [["prisma", "@prisma/client"], "Prisma"],
    [["drizzle-orm"], "Drizzle"],
    [["typeorm"], "TypeORM"],
    [["sequelize"], "Sequelize"],
    [["knex"], "Knex"],
    [["kysely"], "Kysely"],
    [["@mikro-orm/core"], "MikroORM"],
    [["mongoose"], "Mongoose"],
  ];

  for (const [deps, name] of ormMap) {
    const found = findDependency(pkg, deps);
    if (found) return name;
  }

  return undefined;
}

// ============================================================================
// Database Detection (Node.js)
// ============================================================================

function detectDatabase(pkg: PackageJSON): string {
  const dbMap: [string[], string][] = [
    [["@supabase/supabase-js", "@supabase/ssr"], "PostgreSQL (Supabase)"],
    [["@neondatabase/serverless"], "PostgreSQL (Neon)"],
    [["pg", "postgres", "@vercel/postgres"], "PostgreSQL"],
    [["mysql2", "@planetscale/database"], "MySQL"],
    [["mariadb"], "MariaDB"],
    [["better-sqlite3", "@libsql/client", "@turso/client"], "SQLite"],
    [["mssql", "tedious"], "SQL Server"],
    [["oracledb"], "Oracle"],
    [["mongodb", "mongoose"], "MongoDB"],
    [["redis", "ioredis"], "Redis"],
  ];

  for (const [deps, name] of dbMap) {
    const found = findDependency(pkg, deps);
    if (found) return name;
  }

  return "unknown";
}

// ============================================================================
// SQL Dialect Detection
// ============================================================================

function detectSQLDialect(pkg: PackageJSON): string {
  const db = detectDatabase(pkg);
  return mapDatabaseToDialect(db);
}

function mapDatabaseToDialect(database: string): string {
  if (database.includes("PostgreSQL")) return "PostgreSQL";
  if (database.includes("MySQL")) return "MySQL";
  if (database.includes("MariaDB")) return "MariaDB";
  if (database.includes("SQLite")) return "SQLite";
  if (database.includes("SQL Server")) return "SQL Server";
  if (database.includes("Oracle")) return "Oracle";
  return "unknown";
}

// ============================================================================
// Auth Detection (Node.js)
// ============================================================================

function detectAuth(pkg: PackageJSON): string | undefined {
  const authMap: [string[], string][] = [
    [["@supabase/supabase-js", "@supabase/auth-helpers-nextjs", "@supabase/ssr"], "Supabase Auth"],
    [["@clerk/nextjs", "@clerk/clerk-js"], "Clerk"],
    [["next-auth", "@auth/core"], "NextAuth / Auth.js"],
    [["@auth0/nextjs-auth0", "auth0"], "Auth0"],
    [["firebase", "firebase-admin"], "Firebase Auth"],
    [["passport"], "Passport.js"],
    [["lucia"], "Lucia Auth"],
    [["better-auth"], "Better Auth"],
  ];

  for (const [deps, name] of authMap) {
    const found = findDependency(pkg, deps);
    if (found) return name;
  }

  return undefined;
}

// ============================================================================
// Hosting Detection
// ============================================================================

async function detectHosting(projectPath: string): Promise<string | undefined> {
  const hostingMap: [string, string][] = [
    ["vercel.json", "Vercel"],
    ["netlify.toml", "Netlify"],
    ["fly.toml", "Fly.io"],
    ["railway.json", "Railway"],
    ["render.yaml", "Render"],
    ["Dockerfile", "Docker"],
    ["docker-compose.yml", "Docker"],
    ["docker-compose.yaml", "Docker"],
    [".github/workflows", "GitHub Actions"],
    ["appspec.yml", "AWS"],
    ["app.yaml", "GCP"],
  ];

  for (const [file, hosting] of hostingMap) {
    if (await fileExists(join(projectPath, file))) {
      return hosting;
    }
  }

  return undefined;
}

// ============================================================================
// Python Detection
// ============================================================================

async function detectPython(projectPath: string): Promise<string[] | null> {
  const requirements = await parseRequirements(projectPath);
  if (requirements.length > 0) return requirements;

  const pyProject = await parsePyProject(projectPath);
  if (pyProject) return pyProject.dependencies;

  // Verificar se existe manage.py (Django)
  if (await fileExists(join(projectPath, "manage.py"))) {
    return ["django"];
  }

  return null;
}

function detectPythonFramework(deps: string[]): string {
  if (deps.includes("django")) return "Django";
  if (deps.includes("fastapi")) return "FastAPI";
  if (deps.includes("flask")) return "Flask";
  if (deps.includes("starlette")) return "Starlette";
  if (deps.includes("tornado")) return "Tornado";
  if (deps.includes("sanic")) return "Sanic";
  return "unknown";
}

function detectPythonORM(deps: string[]): string | undefined {
  if (deps.includes("sqlalchemy")) return "SQLAlchemy";
  if (deps.includes("django")) return "Django ORM";
  if (deps.includes("tortoise-orm")) return "Tortoise ORM";
  if (deps.includes("peewee")) return "Peewee";
  if (deps.includes("prisma")) return "Prisma (Python)";
  return undefined;
}

function detectPythonDatabase(deps: string[]): string {
  if (deps.includes("psycopg2") || deps.includes("psycopg") || deps.includes("asyncpg")) return "PostgreSQL";
  if (deps.includes("mysqlclient") || deps.includes("pymysql") || deps.includes("aiomysql")) return "MySQL";
  if (deps.includes("pyodbc") || deps.includes("pymssql")) return "SQL Server";
  if (deps.includes("cx-oracle") || deps.includes("oracledb")) return "Oracle";
  if (deps.includes("aiosqlite") || deps.includes("sqlite3")) return "SQLite";
  return "unknown";
}

function detectPythonAuth(deps: string[]): string | undefined {
  if (deps.includes("django-allauth")) return "Django Allauth";
  if (deps.includes("python-jose") || deps.includes("pyjwt")) return "JWT Manual";
  if (deps.includes("authlib")) return "Authlib";
  return undefined;
}
