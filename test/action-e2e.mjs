#!/usr/bin/env node
/**
 * End-to-end test of the action entrypoint's replay path.
 *
 * Always tested (needs only the test Postgres): the database-url path —
 * bootstrap + migrations applied via host psql, then check, PASS and BLOCK.
 *
 * Tested when a docker daemon is reachable (e.g. GitHub runners): the
 * self-boot path — the entrypoint boots its own postgres container.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, cpSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");
const ENTRYPOINT = join(ROOT, "action", "entrypoint.mjs");
const FIXTURES = join(__dirname, "fixtures");

const ADMIN_URL = process.env.RLS_GUARD_TEST_URL ?? "postgres://postgres:postgres@localhost:5432/postgres";

let passed = 0;
let failed = 0;
const assertThat = (name, cond, detail) => {
  if (cond) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    console.error(`  ✗ ${name}\n    ${detail}`);
  }
};

function entry(env, cwd) {
  const r = spawnSync(process.execPath, [ENTRYPOINT], {
    cwd,
    encoding: "utf8",
    env: { ...process.env, GITHUB_EVENT_NAME: "pull_request", INPUT_LIVE_URL: "", ...env },
  });
  return { code: r.status ?? -1, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

/** Build a fake project dir: migrations/ + summary/output capture files. */
function project(migrationSets) {
  const dir = mkdtempSync(join(tmpdir(), "rlsguard-action-"));
  const mig = join(dir, "migrations");
  for (const set of migrationSets) cpSync(set, mig, { recursive: true });
  writeFileSync(join(dir, "gh_output"), "");
  writeFileSync(join(dir, "gh_summary"), "");
  return dir;
}

const admin = new pg.Client({ connectionString: ADMIN_URL });
await admin.connect();
await admin.query("drop database if exists rls_guard_action with (force)");
await admin.query("create database rls_guard_action");
await admin.end();
const dbUrl = (() => {
  const u = new URL(ADMIN_URL);
  u.pathname = "/rls_guard_action";
  return u.toString();
})();

console.log("[A1] database-url path — clean migrations must PASS");
const passDir = project([join(FIXTURES, "base")]);
{
  const r = entry(
    {
      INPUT_DATABASE_URL: dbUrl,
      INPUT_MIGRATIONS_DIR: "migrations",
      GITHUB_OUTPUT: join(passDir, "gh_output"),
      GITHUB_STEP_SUMMARY: join(passDir, "gh_summary"),
    },
    passDir
  );
  assertThat("exit 0", r.code === 0, `code=${r.code}\n${r.out}`);
  assertThat("verdict=pass in GITHUB_OUTPUT", readFileSync(join(passDir, "gh_output"), "utf8").includes("verdict=pass"), r.out);
  assertThat("PASS summary written", readFileSync(join(passDir, "gh_summary"), "utf8").includes("PASS"), r.out);
}

console.log("\n[A2] database-url path — violations must BLOCK");
{
  const admin2 = new pg.Client({ connectionString: ADMIN_URL });
  await admin2.connect();
  await admin2.query("drop database if exists rls_guard_action with (force)");
  await admin2.query("create database rls_guard_action");
  await admin2.end();

  const blockDir = project([join(FIXTURES, "base"), join(FIXTURES, "block")]);
  const r = entry(
    {
      INPUT_DATABASE_URL: dbUrl,
      INPUT_MIGRATIONS_DIR: "migrations",
      GITHUB_OUTPUT: join(blockDir, "gh_output"),
      GITHUB_STEP_SUMMARY: join(blockDir, "gh_summary"),
    },
    blockDir
  );
  assertThat("exit 1", r.code === 1, `code=${r.code}\n${r.out}`);
  assertThat("all four invariants fire", ["[I1]", "[I2]", "[I3]", "[I4]"].every((m) => r.out.includes(m)), r.out);
  assertThat("verdict=block in GITHUB_OUTPUT", readFileSync(join(blockDir, "gh_output"), "utf8").includes("verdict=block"), r.out);
  assertThat("BLOCK summary written", readFileSync(join(blockDir, "gh_summary"), "utf8").includes("BLOCK"), r.out);
  rmSync(blockDir, { recursive: true, force: true });
}

console.log("\n[A2b] report-dir input flows through to the evidence report");
{
  const admin3 = new pg.Client({ connectionString: ADMIN_URL });
  await admin3.connect();
  await admin3.query("drop database if exists rls_guard_action with (force)");
  await admin3.query("create database rls_guard_action");
  await admin3.end();

  const repDir = project([join(FIXTURES, "base")]);
  const r = entry(
    {
      INPUT_DATABASE_URL: dbUrl,
      INPUT_MIGRATIONS_DIR: "migrations",
      INPUT_REPORT_DIR: "evidence",
      GITHUB_OUTPUT: join(repDir, "gh_output"),
      GITHUB_STEP_SUMMARY: join(repDir, "gh_summary"),
    },
    repDir
  );
  assertThat("exit 0 with report", r.code === 0, `code=${r.code}\n${r.out}`);
  assertThat(
    "evidence.json + evidence.html written by the action",
    existsSync(join(repDir, "evidence", "evidence.json")) && existsSync(join(repDir, "evidence", "evidence.html")),
    r.out
  );
  rmSync(repDir, { recursive: true, force: true });
}

console.log("\n[A4] a config/runtime error yields NO verdict — errors never attest");
{
  const errDir = project([join(FIXTURES, "base")]);
  const r = entry(
    {
      INPUT_DATABASE_URL: dbUrl,
      INPUT_MIGRATIONS_DIR: "does-not-exist",
      GITHUB_OUTPUT: join(errDir, "gh_output"),
      GITHUB_STEP_SUMMARY: join(errDir, "gh_summary"),
    },
    errDir
  );
  assertThat("exit 2 on missing migrations dir", r.code === 2, `code=${r.code}\n${r.out}`);
  assertThat("no verdict written", !readFileSync(join(errDir, "gh_output"), "utf8").includes("verdict="), r.out);
  rmSync(errDir, { recursive: true, force: true });
}

const dockerUp = spawnSync("docker", ["info"], { stdio: "ignore" }).status === 0;
if (dockerUp) {
  console.log("\n[A3] self-boot path — the entrypoint boots its own container (docker available)");
  const bootDir = project([join(FIXTURES, "base")]);
  const r = entry(
    {
      INPUT_MIGRATIONS_DIR: "migrations",
      GITHUB_OUTPUT: join(bootDir, "gh_output"),
      GITHUB_STEP_SUMMARY: join(bootDir, "gh_summary"),
    },
    bootDir
  );
  assertThat("exit 0 with self-booted postgres", r.code === 0, `code=${r.code}\n${r.out}`);
  assertThat("container was booted", r.out.includes("Booting ephemeral postgres"), r.out);
  rmSync(bootDir, { recursive: true, force: true });
} else {
  console.log("\n[A3] self-boot path — SKIPPED (no docker daemon here; covered on GitHub runners)");
}

rmSync(passDir, { recursive: true, force: true });
console.log(`\n${passed} passed, ${failed} failed.`);
process.exit(failed > 0 ? 1 : 0);
