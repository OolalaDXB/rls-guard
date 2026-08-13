#!/usr/bin/env node
/**
 * The action's security guardrails must be enforced in code, not documented.
 * These tests run the real entrypoint and assert it refuses:
 *   G1  pull_request_target, in every mode.
 *   G2  live-url on pull_request events (fork code must never see a live
 *       credential).
 * They need no database — the refusals fire before anything connects.
 */
import { spawnSync } from "node:child_process";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ENTRYPOINT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "action", "entrypoint.mjs");

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

function entry(env) {
  const r = spawnSync(process.execPath, [ENTRYPOINT], {
    encoding: "utf8",
    env: { ...process.env, GITHUB_EVENT_NAME: "", INPUT_LIVE_URL: "", INPUT_DATABASE_URL: "", ...env },
  });
  return { code: r.status ?? -1, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

console.log("[G1] pull_request_target is refused, in every mode");
{
  const r1 = entry({ GITHUB_EVENT_NAME: "pull_request_target" });
  assertThat("refused (exit 2)", r1.code === 2, `code=${r1.code}\n${r1.out}`);
  assertThat("names the event and the fix", /pull_request_target/.test(r1.out) && /pull_request/.test(r1.out), r1.out);
  const r2 = entry({ GITHUB_EVENT_NAME: "pull_request_target", INPUT_LIVE_URL: "postgres://x" });
  assertThat("refused even with live-url", r2.code === 2 && /pull_request_target/.test(r2.out), `code=${r2.code}\n${r2.out}`);
}

console.log("\n[G2] live-url on pull_request events is refused");
{
  const r = entry({ GITHUB_EVENT_NAME: "pull_request", INPUT_LIVE_URL: "postgres://user:pw@prod.example/db" });
  assertThat("refused (exit 2)", r.code === 2, `code=${r.code}\n${r.out}`);
  assertThat("explains the credential rule", /credential/.test(r.out) && /replay/.test(r.out), r.out);
  assertThat("the credential value is not echoed", !r.out.includes("prod.example"), r.out);
}

console.log("\n[G2] live-url is allowlist-gated — every non-allowlisted event is refused");
{
  for (const evt of ["issue_comment", "workflow_run"]) {
    const r = entry({ GITHUB_EVENT_NAME: evt, INPUT_LIVE_URL: "postgres://x" });
    assertThat(`refused on ${evt}`, r.code === 2 && /refuses live-url/.test(r.out), `code=${r.code}\n${r.out}`);
  }
}

console.log("\n[G3] non-loopback database-url on pull_request is refused");
{
  const r = entry({ GITHUB_EVENT_NAME: "pull_request", INPUT_DATABASE_URL: "postgres://u:pw@db.internal.example:5432/prod" });
  assertThat("refused (exit 2)", r.code === 2, `code=${r.code}\n${r.out}`);
  assertThat("explains the loopback rule", /loopback|localhost/.test(r.out), r.out);
  assertThat("the URL is not echoed", !r.out.includes("db.internal.example"), r.out);
  // Loopback database-url must get PAST the guard on pull_request (service
  // containers are the legitimate use). Unreachable port → fails later on
  // apply, never on policy.
  const r2 = entry({ GITHUB_EVENT_NAME: "pull_request", INPUT_DATABASE_URL: "postgres://postgres:x@127.0.0.1:1/x", INPUT_MIGRATIONS_DIR: "does-not-exist" });
  assertThat("loopback passes the guard", !/refuses/.test(r2.out), `code=${r2.code}\n${r2.out}`);
}

console.log("\n[G2bis] live-url on schedule is allowed through the guards");
{
  // Unreachable host: must get PAST the guardrails and fail on connection
  // (exit 2 from the CLI), with no guard message.
  const r = entry({ GITHUB_EVENT_NAME: "schedule", INPUT_LIVE_URL: "postgres://postgres:x@127.0.0.1:1/x" });
  assertThat("no guard refusal", !/refuses/.test(r.out), `code=${r.code}\n${r.out}`);
  assertThat("proceeds to drift (fails on connect, not on policy)", /drift failed|No baseline/.test(r.out), r.out);
}

console.log(`\n${passed} passed, ${failed} failed.`);
process.exit(failed > 0 ? 1 : 0);
