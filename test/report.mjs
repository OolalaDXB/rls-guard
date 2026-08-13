#!/usr/bin/env node
/**
 * Evidence report tests: the report renders the ENGINE's output (never its
 * own verdicts), carries the proof boundary verbatim, surfaces exceptions,
 * and is written both on PASS and on BLOCK.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");
const CLI = resolve(ROOT, "src", "cli.mjs");
const FIXTURES = resolve(__dirname, "fixtures");

const ADMIN_URL = process.env.RLS_GUARD_TEST_URL ?? "postgres://postgres:postgres@localhost:5432/postgres";
const dbUrl = (name) => {
  const u = new URL(ADMIN_URL);
  u.pathname = `/${name}`;
  return u.toString();
};

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

function cli(args, { url, cwd, config, env = {} }) {
  const argv = [CLI, ...args, "--url", url];
  if (config) argv.push("--config", config);
  const r = spawnSync(process.execPath, argv, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, ...env },
  });
  return { code: r.status ?? -1, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

// The run.mjs suite leaves rls_guard_pass / rls_guard_block behind? No — it
// recreates them at start. This suite runs after it in `npm test`, so the
// databases exist in their end-of-suite state (pass restored clean; block
// with all violations).
const PASS_URL = dbUrl("rls_guard_pass");
const BLOCK_URL = dbUrl("rls_guard_block");
const CONFIG = resolve(FIXTURES, "config", "default.yml");
const CONFIG_EXCEPTIONS = resolve(FIXTURES, "config", "with-exceptions.yml");

console.log("[R1] PASS report — verdict, invariants, coverage, boundary");
{
  const dir = mkdtempSync(join(tmpdir(), "rlsguard-report-"));
  const r = cli(["check", "--report-dir", "evidence"], { url: PASS_URL, cwd: dir, config: CONFIG });
  assertThat("check still exits 0", r.code === 0, `code=${r.code}\n${r.out}`);
  const jsonPath = join(dir, "evidence", "evidence.json");
  const htmlPath = join(dir, "evidence", "evidence.html");
  assertThat("evidence.json + evidence.html written", existsSync(jsonPath) && existsSync(htmlPath), r.out);
  const rep = JSON.parse(readFileSync(jsonPath, "utf8"));
  assertThat("format + verdict pass", rep.format === "rls-guard-evidence/1" && rep.verdict === "pass", JSON.stringify(rep).slice(0, 300));
  assertThat("I1–I4 pass", rep.invariants.filter((i) => i.id !== "STATE").every((i) => i.status === "pass"), JSON.stringify(rep.invariants));
  assertThat("STATE is not-run without a baseline (JSON)", rep.invariants.find((i) => i.id === "STATE").status === "not-run", JSON.stringify(rep.invariants));
  assertThat("attestation metadata present", !!rep.config_hash && !!rep.tool_version && !!rep.postgres_server_version, JSON.stringify(rep).slice(0, 300));
  const widgets = rep.inventory.coverage.find((c) => c.table_fqn === "public.widgets");
  assertThat("coverage lists widgets policies per op", widgets && widgets.SELECT.length > 0 && widgets.INSERT.length > 0, JSON.stringify(widgets));
  assertThat("proof boundary carried verbatim", rep.proof_boundary.proves.length >= 5 && rep.proof_boundary.does_not_prove.length >= 6, JSON.stringify(rep.proof_boundary));
  const html = readFileSync(htmlPath, "utf8");
  assertThat("HTML shows PASS, no undefined", html.includes("PASS") && !html.includes("undefined"), html.slice(0, 500));
  assertThat("STATE is NOT RUN without a baseline (HTML)", html.includes("NOT RUN") && html.includes("comparison not run"), html.slice(0, 500));
  rmSync(dir, { recursive: true, force: true });
}

console.log("\n[R4] with a committed baseline, STATE runs and passes");
{
  const dir = mkdtempSync(join(tmpdir(), "rlsguard-report-"));
  cli(["init"], { url: PASS_URL, cwd: dir, config: CONFIG });
  const r = cli(["check", "--report-dir", "evidence"], { url: PASS_URL, cwd: dir, config: CONFIG });
  assertThat("check exits 0", r.code === 0, `code=${r.code}\n${r.out}`);
  const rep = JSON.parse(readFileSync(join(dir, "evidence", "evidence.json"), "utf8"));
  assertThat("STATE pass with baseline", rep.invariants.find((i) => i.id === "STATE").status === "pass", JSON.stringify(rep.invariants));
  rmSync(dir, { recursive: true, force: true });
}

console.log("\n[R5] commit SHA — present when provided, honest when absent");
{
  const dir = mkdtempSync(join(tmpdir(), "rlsguard-report-"));
  const sha = "deadbeefcafe0000000000000000000000000000";
  cli(["check", "--report-dir", "with-sha"], { url: PASS_URL, cwd: dir, config: CONFIG, env: { GITHUB_SHA: sha } });
  const withSha = JSON.parse(readFileSync(join(dir, "with-sha", "evidence.json"), "utf8"));
  const withShaHtml = readFileSync(join(dir, "with-sha", "evidence.html"), "utf8");
  assertThat("commit_sha carried from GITHUB_SHA", withSha.commit_sha === sha, String(withSha.commit_sha));
  assertThat("commit-based reproducibility sentence", withShaHtml.includes("from the same commit"), withShaHtml.slice(0, 800));

  cli(["check", "--report-dir", "no-sha"], { url: PASS_URL, cwd: dir, config: CONFIG, env: { GITHUB_SHA: "" } });
  const noSha = JSON.parse(readFileSync(join(dir, "no-sha", "evidence.json"), "utf8"));
  const noShaHtml = readFileSync(join(dir, "no-sha", "evidence.html"), "utf8");
  assertThat("commit_sha null outside a repo", noSha.commit_sha === null, String(noSha.commit_sha));
  assertThat('HTML shows "Not available", never "unknown"', noShaHtml.includes("Not available") && !noShaHtml.includes("unknown"), noShaHtml.slice(0, 800));
  assertThat("no commit claim without a SHA", noShaHtml.includes("No commit SHA was available") && !noShaHtml.includes("from the same commit"), noShaHtml.slice(0, 800));
  rmSync(dir, { recursive: true, force: true });
}

console.log("\n[R2] BLOCK report — failures rendered from the engine's findings");
{
  const dir = mkdtempSync(join(tmpdir(), "rlsguard-report-"));
  const r = cli(["check", "--report-dir", "evidence"], { url: BLOCK_URL, cwd: dir, config: CONFIG });
  assertThat("check still exits 1", r.code === 1, `code=${r.code}\n${r.out}`);
  const rep = JSON.parse(readFileSync(join(dir, "evidence", "evidence.json"), "utf8"));
  assertThat("verdict block", rep.verdict === "block", rep.verdict);
  const failing = rep.invariants.filter((i) => i.status === "fail").map((i) => i.id);
  assertThat("I1–I4 fail with findings", ["I1", "I2", "I3", "I4"].every((id) => failing.includes(id)), JSON.stringify(failing));
  const flagged = rep.definer_inventory.filter((d) => d.status === "flagged");
  assertThat("definer inventory marks the flagged function", flagged.some((d) => d.signature.includes("process_widget")), JSON.stringify(rep.definer_inventory));
  const html = readFileSync(join(dir, "evidence", "evidence.html"), "utf8");
  assertThat("HTML shows BLOCK", html.includes("BLOCK"), html.slice(0, 500));
  rmSync(dir, { recursive: true, force: true });
}

console.log("\n[R3] exceptions surface in the report as out-of-attestation");
{
  const dir = mkdtempSync(join(tmpdir(), "rlsguard-report-"));
  const r = cli(["check", "--report-dir", "evidence"], { url: BLOCK_URL, cwd: dir, config: CONFIG_EXCEPTIONS });
  assertThat("check exits 0 under exceptions", r.code === 0, `code=${r.code}\n${r.out}`);
  const rep = JSON.parse(readFileSync(join(dir, "evidence", "evidence.json"), "utf8"));
  assertThat("verdict pass with exceptions in effect", rep.verdict === "pass" && rep.exceptions.in_effect.length >= 4, JSON.stringify(rep.exceptions));
  assertThat("excepted definer marked excepted", rep.definer_inventory.some((d) => d.status === "excepted" && d.signature.includes("process_widget")), JSON.stringify(rep.definer_inventory));
  assertThat("global table listed out of tenant scope", rep.inventory.tables_declared_global.some((t) => t.includes("leaky_notes")), JSON.stringify(rep.inventory.tables_declared_global));
  assertThat("stale exception surfaced", rep.exceptions.stale.some((e) => e.name === "ghost_function_matching_nothing"), JSON.stringify(rep.exceptions.stale));
  rmSync(dir, { recursive: true, force: true });
}

console.log(`\n${passed} passed, ${failed} failed.`);
process.exit(failed > 0 ? 1 : 0);
