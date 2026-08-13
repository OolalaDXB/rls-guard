#!/usr/bin/env node
/**
 * End-to-end test harness.
 *
 * Mirrors the real replay flow: create a throwaway database, apply the
 * bootstrap + fixture SQL in order (like migrations), then drive the CLI and
 * assert exit codes and output. Needs a reachable Postgres superuser URL:
 *
 *   RLS_GUARD_TEST_URL (default postgres://postgres:postgres@localhost:5432/postgres)
 */
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");
const CLI = resolve(ROOT, "src", "cli.mjs");
const FIXTURES = resolve(__dirname, "fixtures");

const ADMIN_URL = process.env.RLS_GUARD_TEST_URL ?? "postgres://postgres:postgres@localhost:5432/postgres";

let passed = 0;
let failed = 0;
const fail = (name, detail) => {
  failed++;
  console.error(`  ✗ ${name}\n    ${detail}`);
};
const ok = (name) => {
  passed++;
  console.log(`  ✓ ${name}`);
};
const assertThat = (name, cond, detail) => (cond ? ok(name) : fail(name, detail));

/* ------------------------------ helpers ------------------------------ */

function dbUrl(name) {
  const u = new URL(ADMIN_URL);
  u.pathname = `/${name}`;
  return u.toString();
}

async function recreateDb(admin, name) {
  await admin.query(`drop database if exists ${name} with (force)`);
  await admin.query(`create database ${name}`);
}

function applySql(url, files) {
  for (const f of files) {
    execFileSync("psql", [url, "-q", "-v", "ON_ERROR_STOP=1", "-f", f], { stdio: ["ignore", "pipe", "pipe"] });
  }
}

/** Run the CLI; return { code, out } with stdout+stderr merged. */
function cli(cmdArgs, { url, cwd, config }) {
  const argv = [CLI, ...cmdArgs, "--url", url];
  if (config) argv.push("--config", config);
  const r = spawnSync(process.execPath, argv, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  return { code: r.status ?? -1, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

/* -------------------------------- run -------------------------------- */

const admin = new pg.Client({ connectionString: ADMIN_URL });
await admin.connect();

const BOOTSTRAP = resolve(ROOT, "sql", "bootstrap-replay.sql");
const BASE = [resolve(FIXTURES, "base", "001_schema.sql"), resolve(FIXTURES, "base", "002_policies.sql")];
const VIOLATIONS = [resolve(FIXTURES, "block", "010_violations.sql")];
const CONFIG = resolve(FIXTURES, "config", "default.yml");
const CONFIG_EXCEPTIONS = resolve(FIXTURES, "config", "with-exceptions.yml");
const CONFIG_EXPIRED = resolve(FIXTURES, "config", "expired-exception.yml");

console.log("Preparing databases…");
await recreateDb(admin, "rls_guard_pass");
await recreateDb(admin, "rls_guard_block");
const PASS_URL = dbUrl("rls_guard_pass");
const BLOCK_URL = dbUrl("rls_guard_block");
applySql(PASS_URL, [BOOTSTRAP, ...BASE]);
applySql(BLOCK_URL, [BOOTSTRAP, ...BASE, ...VIOLATIONS]);

const passDir = mkdtempSync(join(tmpdir(), "rlsguard-pass-"));
const blockDir = mkdtempSync(join(tmpdir(), "rlsguard-block-"));
const snapshotOf = (dir) => join(dir, "db", "rls-snapshot.json");

console.log("\n[1] check — clean schema must PASS");
{
  const r = cli(["check"], { url: PASS_URL, cwd: passDir, config: CONFIG });
  assertThat("exit 0 on clean schema", r.code === 0, `code=${r.code}\n${r.out}`);
  assertThat("mentions no-baseline warning", r.out.includes("No baseline"), r.out);
}

console.log("\n[2] check — violating schema must BLOCK with all four invariants");
{
  const r = cli(["check"], { url: BLOCK_URL, cwd: blockDir, config: CONFIG });
  assertThat("exit 1 on violations", r.code === 1, `code=${r.code}\n${r.out}`);
  assertThat("I1 flags leaky_notes", /\[I1\].*leaky_notes/.test(r.out), r.out);
  assertThat("I2 flags gadgets_public_read", /\[I2\].*gadgets_public_read/.test(r.out), r.out);
  assertThat("I3 flags widgets_admin_insert", /\[I3\].*widgets_admin_insert/.test(r.out), r.out);
  assertThat("I3 flags UPDATE tenant re-assignment (widgets_sneaky_update)", /\[I3\].*widgets_sneaky_update.*re-assign/.test(r.out), r.out);
  assertThat("I3 flags identity-only INSERT (gadgets_identity_insert)", /\[I3\].*gadgets_identity_insert/.test(r.out), r.out);
  assertThat("I4 flags process_widget", /\[I4\].*process_widget/.test(r.out), r.out);
  assertThat("clean policies not flagged", !/widgets_tenant_select|widgets_service_all|count_visible_widgets|my_gadget_count|gadgets_owner_update/.test(r.out), r.out);
  assertThat("deny-all / global-read / trigger definer not flagged", !/widgets_deny_delete|app_settings_public_read|touch_widget_payload/.test(r.out), r.out);
  assertThat("excluded side schema not scanned by default config", !r.out.includes("side_notes"), r.out);
}

console.log("\n[3] init — must REFUSE to bless a violating baseline");
{
  const r = cli(["init"], { url: BLOCK_URL, cwd: blockDir, config: CONFIG });
  assertThat("exit 1 (refused)", r.code === 1, `code=${r.code}\n${r.out}`);
  assertThat("no snapshot written", !existsSync(snapshotOf(blockDir)), "snapshot file exists");
  assertThat("refusal is explained", r.out.includes("refused") && r.out.includes("--accept-violations"), r.out);
}

console.log("\n[4] init --accept-violations — explicit act writes the baseline, loudly");
{
  const r = cli(["init", "--accept-violations"], { url: BLOCK_URL, cwd: blockDir, config: CONFIG });
  assertThat("exit 0 (explicit accept)", r.code === 0, `code=${r.code}\n${r.out}`);
  assertThat("snapshot written", existsSync(snapshotOf(blockDir)), "snapshot file missing");
  assertThat("still loud about violations", r.out.includes("does NOT silence"), r.out);
}

console.log("\n[5] init — clean schema baselines silently");
{
  const r = cli(["init"], { url: PASS_URL, cwd: passDir, config: CONFIG });
  assertThat("exit 0", r.code === 0, `code=${r.code}\n${r.out}`);
  assertThat("snapshot written", existsSync(snapshotOf(passDir)), "snapshot file missing");
}

console.log("\n[6] check — clean schema + baseline (state comparison) must PASS");
{
  const r = cli(["check"], { url: PASS_URL, cwd: passDir, config: CONFIG });
  assertThat("exit 0 with baseline", r.code === 0, `code=${r.code}\n${r.out}`);
  assertThat("no baseline warning anymore", !r.out.includes("No baseline"), r.out);
}

console.log("\n[7] check — RLS disabled after baseline must BLOCK (I1 + STATE)");
{
  const tamper = new pg.Client({ connectionString: PASS_URL });
  await tamper.connect();
  await tamper.query("alter table gadgets disable row level security");
  const r = cli(["check"], { url: PASS_URL, cwd: passDir, config: CONFIG });
  assertThat("exit 1 after tamper", r.code === 1, `code=${r.code}\n${r.out}`);
  assertThat("I1 fires", /\[I1\].*gadgets/.test(r.out), r.out);
  assertThat("STATE mismatch fires", /\[STATE\].*gadgets/.test(r.out), r.out);
  await tamper.query("alter table gadgets enable row level security");
  await tamper.end();
}

console.log("\n[8] drift — dropped policy must be detected, then clean again");
{
  const tamper = new pg.Client({ connectionString: PASS_URL });
  await tamper.connect();
  await tamper.query("drop policy widgets_tenant_select on widgets");
  const r1 = cli(["drift", "--artifact-dir", join(passDir, "drift-report")], { url: PASS_URL, cwd: passDir, config: CONFIG });
  assertThat("exit 1 on drift", r1.code === 1, `code=${r1.code}\n${r1.out}`);
  assertThat("names the missing policy", r1.out.includes("widgets_tenant_select"), r1.out);
  assertThat("artifacts written", existsSync(join(passDir, "drift-report", "drift.json")) && existsSync(join(passDir, "drift-report", "drift.html")), "missing artifacts");
  await tamper.query("create policy widgets_tenant_select on widgets for select using (tenant_id = current_tenant_id())");
  await tamper.end();
  const r2 = cli(["drift", "--artifact-dir", join(passDir, "drift-report")], { url: PASS_URL, cwd: passDir, config: CONFIG });
  assertThat("exit 0 once restored", r2.code === 0, `code=${r2.code}\n${r2.out}`);
}

console.log("\n[9] exceptions — documented exceptions neutralize, stay visible, stale ones warn");
{
  const dir = mkdtempSync(join(tmpdir(), "rlsguard-exc-"));
  const r = cli(["check"], { url: BLOCK_URL, cwd: dir, config: CONFIG_EXCEPTIONS });
  assertThat("exit 0 with full exceptions", r.code === 0, `code=${r.code}\n${r.out}`);
  assertThat("exceptions listed as in effect", r.out.includes("exception(s) in effect"), r.out);
  assertThat("each reason surfaced", r.out.includes("reviewed and accepted definer function"), r.out);
  assertThat("stale exception reported", r.out.includes("ghost_function_matching_nothing"), r.out);
  rmSync(dir, { recursive: true, force: true });
}

console.log("\n[10] exceptions — an expired exception re-enforces the invariant");
{
  const dir = mkdtempSync(join(tmpdir(), "rlsguard-exp-"));
  const r = cli(["check"], { url: BLOCK_URL, cwd: dir, config: CONFIG_EXPIRED });
  assertThat("exit 1 despite expired exception", r.code === 1, `code=${r.code}\n${r.out}`);
  assertThat("expiry surfaced", r.out.includes("expired"), r.out);
  assertThat("I2 fires again", /\[I2\].*gadgets_public_read/.test(r.out), r.out);
  rmSync(dir, { recursive: true, force: true });
}

console.log("\n[11] schemas.exclude is enforced, not decorative");
{
  const dir = mkdtempSync(join(tmpdir(), "rlsguard-schemas-"));
  const rIncluded = cli(["check"], { url: BLOCK_URL, cwd: dir, config: resolve(FIXTURES, "config", "include-side.yml") });
  assertThat("side schema scanned when included", /\[I1\].*side\.side_notes/.test(rIncluded.out), rIncluded.out);
  const rExcluded = cli(["check"], { url: BLOCK_URL, cwd: dir, config: resolve(FIXTURES, "config", "include-side-excluded.yml") });
  assertThat("side schema skipped when excluded", !rExcluded.out.includes("side_notes"), rExcluded.out);
  rmSync(dir, { recursive: true, force: true });
}

await admin.end();
rmSync(passDir, { recursive: true, force: true });
rmSync(blockDir, { recursive: true, force: true });

console.log(`\n${passed} passed, ${failed} failed.`);
process.exit(failed > 0 ? 1 : 0);
