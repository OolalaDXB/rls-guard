#!/usr/bin/env node
/**
 * GitHub Action entrypoint.
 *
 * The blocking mechanism is this process's EXIT CODE, surfaced as the check
 * conclusion and wired into a required status check. Any PR comment is UX on
 * top — never the gate.
 *
 * Security guardrails are ENFORCED here, not just documented:
 *
 *   G1  Refuses to run on pull_request_target. Untrusted PR code combined
 *       with an elevated token is exactly the situation a security tool must
 *       never create — replay works on plain pull_request with contents: read.
 *   G2  Accepts live-url ONLY on an allowlist of trusted events (schedule,
 *       workflow_dispatch). Fork-submitted code must never see a live
 *       database credential; replay needs no secret at all.
 *   G3  On pull_request events, database-url may only point at loopback
 *       (a job service container). Anything else risks handing a real
 *       database to fork code.
 *
 * Modes:
 *   replay (default) — boot an ephemeral Postgres (or reuse database-url),
 *     apply bootstrap + migrations in order, run `check`. Zero secrets.
 *   drift (live-url set) — run `drift` against a real database, from the
 *     allowlisted events only, with a read-only credential.
 */
import { readdirSync, readFileSync, existsSync, appendFileSync } from "node:fs";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { loadConfig, ConfigError } from "../src/config.mjs";

const ACTION_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ACTION_ROOT, "src", "cli.mjs");

const LIVE_EVENTS = new Set(["schedule", "workflow_dispatch"]);
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

const event = process.env.GITHUB_EVENT_NAME ?? "";
const input = (name, fallback = "") => (process.env[`INPUT_${name}`] ?? "").trim() || fallback;

const configPath = input("CONFIG", "rls-guard.yml");
const migrationsDir = input("MIGRATIONS_DIR", "supabase/migrations");
const bootstrapSql = input("BOOTSTRAP_SQL"); // "" = bundled default, "none" = skip
const databaseUrl = input("DATABASE_URL");
const liveUrl = input("LIVE_URL");
const reportDir = input("REPORT_DIR"); // "" = no evidence report

/* ---------------------- guardrails (G1, G2, G3) ---------------------- */
/* All guards fire before any container exists — exiting here leaks nothing. */

if (event === "pull_request_target") {
  console.error("✗ rls-guard refuses to run on pull_request_target.");
  console.error("  pull_request_target executes untrusted PR code with an elevated token.");
  console.error("  Use the plain `pull_request` event — replay needs no secret and contents: read only.");
  process.exit(2);
}

if (liveUrl && !LIVE_EVENTS.has(event)) {
  console.error(`✗ rls-guard refuses live-url on the "${event || "unknown"}" event.`);
  console.error("  A live database credential is only accepted on: schedule, workflow_dispatch.");
  console.error("  Everything else — pull_request included — must never reach a credential;");
  console.error("  PR gating works entirely in replay mode, without any secret.");
  process.exit(2);
}

if (databaseUrl && event.startsWith("pull_request") && !isLoopback(databaseUrl)) {
  console.error("✗ rls-guard refuses a non-loopback database-url on a pull_request event.");
  console.error("  On PR events, database-url may only point at localhost / 127.0.0.1 (a job");
  console.error("  service container). Anything else risks handing a real database to fork code.");
  console.error("  Omit database-url to let the action boot its own ephemeral container.");
  process.exit(2);
}

/* -------------------------------- main ------------------------------- */

class Fail extends Error {}

let container = null;
let url = databaseUrl;
let code = 2;
try {
  if (liveUrl) {
    code = runCli(["drift", "--config", configPath, "--url", liveUrl]);
  } else {
    let postgresVersion = "16";
    try {
      ({ config: { postgres_version: postgresVersion } } = loadConfig(configPath));
    } catch (err) {
      if (err instanceof ConfigError) throw new Fail(`✗ Configuration error: ${err.message}`);
      throw err;
    }

    if (!url) {
      container = `rls-guard-pg-${process.pid}`;
      console.log(`Booting ephemeral postgres:${postgresVersion} (${container})…`);
      run("docker", ["run", "-d", "--rm", "--name", container,
        "-e", "POSTGRES_PASSWORD=postgres", "-p", "127.0.0.1::5432",
        `postgres:${postgresVersion}`]);
      const portLine = run("docker", ["port", container, "5432/tcp"]).stdout.trim().split("\n")[0];
      const port = portLine.split(":").pop();
      url = `postgres://postgres:postgres@127.0.0.1:${port}/postgres`;
      await waitForReady(container);
    } else if (!hasHostPsql()) {
      throw new Fail(
        "✗ database-url was provided but no `psql` client is available to apply migrations.\n" +
          "  Install postgresql-client on the runner, or omit database-url to let the action\n" +
          "  boot its own container (psql then runs inside it)."
      );
    }

    const bootstrapPath =
      bootstrapSql === "none" ? null : bootstrapSql ? resolve(bootstrapSql) : join(ACTION_ROOT, "sql", "bootstrap-replay.sql");
    if (bootstrapPath) {
      console.log(`Applying bootstrap: ${bootstrapPath}`);
      applySql(bootstrapPath);
    }

    if (!existsSync(migrationsDir)) {
      throw new Fail(`✗ Migrations directory not found: ${migrationsDir} (set the migrations-dir input).`);
    }
    const migrations = readdirSync(migrationsDir).filter((f) => f.endsWith(".sql")).sort();
    if (migrations.length === 0) {
      throw new Fail(`✗ No .sql migrations in ${migrationsDir} — nothing to replay.`);
    }
    for (const f of migrations) {
      console.log(`==> ${f}`);
      applySql(join(migrationsDir, f));
    }

    const checkArgs = ["check", "--config", configPath, "--url", url];
    if (reportDir) checkArgs.push("--report-dir", reportDir);
    code = runCli(checkArgs);
  }
} catch (err) {
  console.error(err instanceof Fail ? err.message : `✗ ${err.message}`);
  code = 2;
} finally {
  if (container) spawnSync("docker", ["rm", "-f", container], { stdio: "ignore" });
}

// A verdict only exists for real check outcomes — never for config/runtime
// errors (code 2), which must fail the job without pretending to attest.
if (code === 0 || code === 1) {
  const verdict = code === 0 ? "pass" : "block";
  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(process.env.GITHUB_OUTPUT, `verdict=${verdict}\n`);
  }
  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(
      process.env.GITHUB_STEP_SUMMARY,
      code === 0
        ? "### ✅ RLS Guard — PASS\n\nReplay of the migrations satisfies every invariant.\n"
        : "### ❌ RLS Guard — BLOCK\n\nInvariant violations detected (see the job log). The non-zero exit code fails this check; wire it as a required status check to block the merge.\n"
    );
  }
}
process.exit(code);

/* ------------------------------ helpers ------------------------------ */

function isLoopback(rawUrl) {
  try {
    return LOOPBACK_HOSTS.has(new URL(rawUrl).hostname.toLowerCase());
  } catch {
    return false; // unparseable → fail closed
  }
}

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: "utf8", ...opts });
  if (r.status !== 0) {
    throw new Error(`${cmd} ${args.join(" ")} failed (${r.status}): ${r.stderr || r.stdout}`);
  }
  return r;
}

function runCli(args) {
  const r = spawnSync(process.execPath, [CLI, ...args], { stdio: "inherit" });
  return r.status ?? 2;
}

function hasHostPsql() {
  return spawnSync("psql", ["--version"], { stdio: "ignore" }).status === 0;
}

function applySql(path) {
  const sql = readFileSync(path);
  const argv = container
    ? ["exec", "-i", container, "psql", "-q", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-f", "-"]
    : ["-q", "-v", "ON_ERROR_STOP=1", "-d", url, "-f", "-"];
  const r = spawnSync(container ? "docker" : "psql", argv, { input: sql, encoding: "utf8" });
  if (r.status !== 0) {
    throw new Fail(`✗ applying ${path} failed: ${r.stderr || r.stdout}`);
  }
}

async function waitForReady(name) {
  for (let i = 0; i < 60; i++) {
    const r = spawnSync("docker", ["exec", name, "pg_isready", "-U", "postgres"], { stdio: "ignore" });
    if (r.status === 0) return;
    await new Promise((res) => setTimeout(res, 1000));
  }
  throw new Error("ephemeral postgres did not become ready within 60s");
}
