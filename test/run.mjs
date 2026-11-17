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
import { mkdtempSync, existsSync, rmSync, writeFileSync, readFileSync } from "node:fs";
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

console.log("\n[12] tenant.fence: restrictive — a real fence clears permissive findings, a fake one does not");
{
  await recreateDb(admin, "rls_guard_fence");
  const FENCE_URL = dbUrl("rls_guard_fence");
  applySql(FENCE_URL, [BOOTSTRAP, resolve(FIXTURES, "fence", "001_fence.sql")]);
  const dir = mkdtempSync(join(tmpdir(), "rlsguard-fence-"));
  const off = cli(["check"], { url: FENCE_URL, cwd: dir, config: CONFIG });
  assertThat("fence off by default: the `true` policy behind a fence is still reported", /\[I2\].*notes_rw/.test(off.out), off.out);
  const r = cli(["check"], { url: FENCE_URL, cwd: dir, config: resolve(FIXTURES, "config", "fence.yml") });
  assertThat("exit 1 (the fixture keeps real holes)", r.code === 1, `code=${r.code}\n${r.out}`);
  assertThat("permissive `true` behind a fence (USING form with SELECT) not reported", !/notes_rw/.test(r.out), r.out);
  assertThat("permissive write behind a fence (plain call form) not reported", !/cards_admin_write/.test(r.out), r.out);
  assertThat("a loose fence (IS NOT NULL) is no fence: I1 + I2 still fire", /\[I1\].*public\.loose/.test(r.out) && /\[I2\].*loose_rw/.test(r.out), r.out);
  assertThat("a table without a fence is reported under fence mode", /\[I1\].*public\.unfenced/.test(r.out), r.out);
  assertThat("definer owned by a non-bypassing role, tables fenced: not reported", !/fenced_note_count/.test(r.out), r.out);
  assertThat("definer owned by the superuser: reported", /\[I4\].*superuser_note_count/.test(r.out), r.out);
  assertThat("definer that moves the tenant setting: reported", /\[I4\].*hop_note_count/.test(r.out), r.out);
  assertThat("definer owning its table without FORCE RLS: reported", /\[I4\].*owner_owned_count/.test(r.out), r.out);
  assertThat("definer EXECUTEing its text argument: reported as caller-supplied SQL", /\[I4\].*caller-supplied SQL.*run_sql/.test(r.out), r.out);
  assertThat("bound (USING) and %L-quoted arguments are not dynamic SQL", !/safe_dynamic/.test(r.out), r.out);
  const bad = cli(["check"], { url: FENCE_URL, cwd: dir, config: resolve(FIXTURES, "config", "fence-invalid.yml") });
  assertThat("an unknown fence mode is a config error", bad.code === 2 && /tenant\.fence must be/.test(bad.out), bad.out);
  rmSync(dir, { recursive: true, force: true });
  await admin.query("drop database if exists rls_guard_fence with (force)");
}

console.log("\n[13] coverage — a check that inspected nothing is not a pass");
{
  const dir = mkdtempSync(join(tmpdir(), "rlsguard-coverage-"));
  const writeCfg = (name, body) => {
    const f = join(dir, name);
    writeFileSync(f, body);
    return f;
  };
  const HEAD = `privileged_roles: [service_role]\npostgres_version: "16"\n`;

  // (a) The tenant column of the config exists nowhere: before, every invariant passed vacuously.
  const wrongCol = writeCfg("wrong-col.yml", `tenant:\n  columns: [organisation_id]\n  scope_functions: [current_tenant_id]\nschemas:\n  include: [public]\n${HEAD}`);
  const a = cli(["check"], { url: BLOCK_URL, cwd: dir, config: wrongCol });
  assertThat("no tenant-scoped table → exit 1, not a hollow pass", a.code === 1 && /\[COVERAGE\].*Only 0 tenant-scoped table/.test(a.out), `code=${a.code}\n${a.out}`);
  assertThat("the violating schema was indeed invisible to I1–I4 (the false reassurance)", !/\[I[1-4]\]/.test(a.out), a.out);

  // (b) Explicit opt-out keeps the old behaviour, visibly.
  const optOut = writeCfg("opt-out.yml", `tenant:\n  columns: [organisation_id]\n  scope_functions: [current_tenant_id]\nschemas:\n  include: [public]\ncoverage:\n  min_tenant_tables: 0\n${HEAD}`);
  const b = cli(["check"], { url: BLOCK_URL, cwd: dir, config: optOut });
  assertThat("min_tenant_tables: 0 opts out (exit 0) and the scope line says 0 tables", b.code === 0 && /Scope: 0 tenant-scoped table/.test(b.out), `code=${b.code}\n${b.out}`);

  // (c) A schema that does not exist (typo, replay not done) is never silently skipped.
  const typo = writeCfg("typo.yml", `tenant:\n  columns: [tenant_id]\n  scope_functions: [current_tenant_id]\nschemas:\n  include: [public, personnal_finance]\n${HEAD}`);
  const c = cli(["check"], { url: PASS_URL, cwd: dir, config: typo });
  assertThat("empty/missing schema → exit 1 naming the schema", c.code === 1 && /\[COVERAGE\].*"personnal_finance".*no table/.test(c.out), `code=${c.code}\n${c.out}`);

  // (d) Project-specific minimum.
  const min = writeCfg("min.yml", `tenant:\n  columns: [tenant_id]\n  scope_functions: [current_tenant_id]\nschemas:\n  include: [public]\ncoverage:\n  min_tenant_tables: 500\n${HEAD}`);
  const d = cli(["check"], { url: PASS_URL, cwd: dir, config: min });
  assertThat("below the configured minimum → exit 1", d.code === 1 && /coverage\.min_tenant_tables requires 500/.test(d.out), `code=${d.code}\n${d.out}`);

  // (e) Required tables: present and scoped passes; absent or not tenant-scoped blocks.
  const reqOk = writeCfg("req-ok.yml", `tenant:\n  columns: [tenant_id]\n  scope_functions: [current_tenant_id]\nschemas:\n  include: [public]\ncoverage:\n  required_tables: [public.widgets, gadgets]\n${HEAD}`);
  const e1 = cli(["check"], { url: PASS_URL, cwd: dir, config: reqOk });
  assertThat("required tables present and tenant-scoped → exit 0", e1.code === 0, `code=${e1.code}\n${e1.out}`);
  const reqKo = writeCfg("req-ko.yml", `tenant:\n  columns: [tenant_id]\n  scope_functions: [current_tenant_id]\nschemas:\n  include: [public]\ncoverage:\n  required_tables: [public.invoices, public.app_settings]\n${HEAD}`);
  const e2 = cli(["check"], { url: PASS_URL, cwd: dir, config: reqKo });
  assertThat("required table absent → blocks", e2.code === 1 && /\[COVERAGE\].*public\.invoices does not exist/.test(e2.out), `code=${e2.code}\n${e2.out}`);
  assertThat("required table without tenant column → blocks", /\[COVERAGE\].*public\.app_settings is not tenant-scoped/.test(e2.out), e2.out);

  // (f) Tables no invariant applies to: reported by default, blocking on demand, cleared by a declared exception.
  const def = cli(["check"], { url: PASS_URL, cwd: dir, config: CONFIG });
  assertThat("untracked tables are counted in the scope line by default", def.code === 0 && /carry no tenant column and are outside every invariant/.test(def.out), def.out);
  const strict = writeCfg("strict.yml", `tenant:\n  columns: [tenant_id]\n  scope_functions: [current_tenant_id]\nschemas:\n  include: [public]\ncoverage:\n  untracked_tables: fail\n${HEAD}`);
  const f1 = cli(["check"], { url: PASS_URL, cwd: dir, config: strict });
  assertThat("untracked_tables: fail → blocks and names the table", f1.code === 1 && /\[COVERAGE\].*public\.app_settings carries no tenant column/.test(f1.out), `code=${f1.code}\n${f1.out}`);
  const untrackedNames = [...f1.out.matchAll(/\[COVERAGE\] Table (\S+) carries no tenant column/g)].map((m) => m[1]);
  const declared = writeCfg("declared.yml", `tenant:\n  columns: [tenant_id]\n  scope_functions: [current_tenant_id]\nschemas:\n  include: [public]\ncoverage:\n  untracked_tables: fail\nexceptions:\n  global_tables:\n${untrackedNames.map((n) => `    - name: ${n}\n      reason: "reference data, no tenant"`).join("\n")}\n${HEAD}`);
  const f2 = cli(["check"], { url: PASS_URL, cwd: dir, config: declared });
  assertThat("each untracked table declared global with a reason → exit 0", f2.code === 0, `code=${f2.code}\n${f2.out}`);

  // (g) pass / FAIL / NOT RUN are three different things.
  assertThat("summary distinguishes STATE NOT RUN from pass", /Checks: I1 pass · I2 pass · I3 pass · I4 pass · STATE NOT RUN · COVERAGE pass/.test(def.out), def.out);
  assertThat("pass message says STATE is not part of the verdict", /STATE not run \(no baseline\)/.test(def.out), def.out);
  const needState = writeCfg("need-state.yml", `tenant:\n  columns: [tenant_id]\n  scope_functions: [current_tenant_id]\nschemas:\n  include: [public]\ncoverage:\n  required_checks: [STATE]\n${HEAD}`);
  const g = cli(["check"], { url: PASS_URL, cwd: dir, config: needState });
  assertThat("required check not run → exit 1", g.code === 1 && /\[STATE\] Required check STATE did not run/.test(g.out), `code=${g.code}\n${g.out}`);
  const badCheck = writeCfg("bad-check.yml", `tenant:\n  columns: [tenant_id]\n  scope_functions: [current_tenant_id]\nschemas:\n  include: [public]\ncoverage:\n  required_checks: [I9]\n${HEAD}`);
  const g2 = cli(["check"], { url: PASS_URL, cwd: dir, config: badCheck });
  assertThat("unknown required check is a config error (exit 2)", g2.code === 2 && /coverage\.required_checks/.test(g2.out), `code=${g2.code}\n${g2.out}`);

  // (h) Exceptions are explicit: motivated, and not left behind.
  const noReason = writeCfg("no-reason.yml", `tenant:\n  columns: [tenant_id]\n  scope_functions: [current_tenant_id]\nschemas:\n  include: [public]\nexceptions_policy:\n  require_reason: true\nexceptions:\n  global_tables:\n    - name: public.app_settings\n${HEAD}`);
  const h1 = cli(["check"], { url: PASS_URL, cwd: dir, config: noReason });
  assertThat("require_reason: an exception without a reason is a config error (exit 2)", h1.code === 2 && /have no reason/.test(h1.out), `code=${h1.code}\n${h1.out}`);
  const staleBody = `tenant:\n  columns: [tenant_id]\n  scope_functions: [current_tenant_id]\nschemas:\n  include: [public]\nexceptions:\n  tenant_blind_writes:\n    - name: policy_that_was_removed\n      reason: "left behind"\n${HEAD}`;
  const h2 = cli(["check"], { url: PASS_URL, cwd: dir, config: writeCfg("stale-warn.yml", staleBody) });
  assertThat("stale exception: reported, not blocking by default", h2.code === 0 && /policy_that_was_removed/.test(h2.out), `code=${h2.code}\n${h2.out}`);
  const h3 = cli(["check"], { url: PASS_URL, cwd: dir, config: writeCfg("stale-fail.yml", staleBody + "exceptions_policy:\n  fail_on_stale: true\n") });
  assertThat("fail_on_stale: a stale exception blocks", h3.code === 1 && /\[EXCEPTIONS\].*policy_that_was_removed/.test(h3.out), `code=${h3.code}\n${h3.out}`);

  // (i) Evidence carries the scope, so a consumer can assert it without a script of its own.
  const rdir = join(dir, "ev");
  cli(["check", "--report-dir", rdir], { url: PASS_URL, cwd: dir, config: CONFIG });
  const ev = JSON.parse(readFileSync(join(rdir, "evidence.json"), "utf8"));
  assertThat("evidence keeps its format id", ev.format === "rls-guard-evidence/1", ev.format);
  assertThat("evidence lists checks not run", Array.isArray(ev.checks_not_run) && ev.checks_not_run.includes("STATE"), JSON.stringify(ev.checks_not_run));
  assertThat("evidence lists untracked tables", ev.inventory.tables_untracked.includes("public.app_settings"), JSON.stringify(ev.inventory.tables_untracked));
  assertThat("evidence has a COVERAGE result", ev.invariants.find((i) => i.id === "COVERAGE")?.status === "pass", JSON.stringify(ev.invariants.map((i) => [i.id, i.status])));
  const bdir = join(dir, "ev-block");
  cli(["check", "--report-dir", bdir], { url: BLOCK_URL, cwd: dir, config: wrongCol });
  const evb = JSON.parse(readFileSync(join(bdir, "evidence.json"), "utf8"));
  assertThat("empty-scope evidence: verdict block, COVERAGE fail", evb.verdict === "block" && evb.invariants.find((i) => i.id === "COVERAGE")?.status === "fail", JSON.stringify(evb.verdict));
  rmSync(dir, { recursive: true, force: true });
}

await admin.end();
rmSync(passDir, { recursive: true, force: true });
rmSync(blockDir, { recursive: true, force: true });

console.log(`\n${passed} passed, ${failed} failed.`);
process.exit(failed > 0 ? 1 : 0);
