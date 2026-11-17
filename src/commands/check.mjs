/**
 * `rls-guard check` — the CI gate.
 *
 * Runs the invariants against DATABASE_URL (typically the ephemeral replay
 * database rebuilt from migrations — no production secret involved). If a
 * committed baseline exists, also asserts the replayed RLS state matches it.
 *
 * The blocking mechanism is the exit code (0 pass / 1 violation / 2 config
 * error) wired into a required status check. Any PR comment is UX on top,
 * never the gate.
 */
import { introspect } from "../introspect.mjs";
import { runInvariants } from "../invariants.mjs";
import { readSnapshot, compareRlsState } from "../snapshot.mjs";
import { usedExceptions, unusedExceptions } from "../config.mjs";
import { writeEvidenceReport } from "../report.mjs";
import { evaluateCoverage } from "../coverage.mjs";
import { appendFileSync } from "node:fs";
import { printViolations, printExceptionReport } from "./output.mjs";

export async function check(client, config, { snapshotPath, reportDir }) {
  const { violations } = await runInvariants(client, config);

  const live = await introspect(client, config);
  const baseline = readSnapshot(snapshotPath);
  const notRun = [];
  if (baseline) {
    violations.push(...compareRlsState(baseline, live));
  } else {
    notRun.push("STATE");
    console.warn(`⚠ No baseline at ${snapshotPath} — the replay-vs-baseline RLS state comparison (STATE) did NOT run. Run \`rls-guard init\` once and commit it.`);
  }

  // What was actually inspected. An empty or partial scope is a result of its
  // own (COVERAGE), never folded into a pass.
  const coverage = evaluateCoverage(config, live.tables, { notRun });
  violations.push(...coverage.violations);

  const stale = unusedExceptions(config);
  if (config.exceptions_policy.fail_on_stale) {
    for (const e of stale) {
      violations.push({
        invariant: "EXCEPTIONS",
        message: `Stale exception ${e.kind}: ${e.name} matches nothing (exceptions_policy.fail_on_stale) — remove it or fix it.`,
      });
    }
  }

  printExceptionReport(usedExceptions(config), stale);
  printScope(coverage.summary, violations, notRun);
  writeActionOutputs(coverage.summary, notRun);

  if (reportDir) {
    const { jsonPath, htmlPath } = await writeEvidenceReport(client, config, {
      violations,
      reportDir,
      baselinePresent: !!baseline,
      coverage: coverage.summary,
    });
    console.log(`ℹ Evidence report written: ${jsonPath}, ${htmlPath}`);
  }

  if (violations.length === 0) {
    console.log(
      `✓ Check passed on ${coverage.summary.tenant_tables} tenant-scoped table(s) — RLS enabled on each, no reachable \`true\` permissive policy, ` +
        "no tenant-blind write policy, no unguarded SECURITY DEFINER touching tenant tables" +
        (baseline ? ", RLS state matches the baseline." : ". STATE not run (no baseline): not part of this verdict.")
    );
    return 0;
  }

  printViolations(violations);
  return 1;
}

/** One line per check: pass, FAIL, or NOT RUN — never a hollow pass. */
function printScope(summary, violations, notRun) {
  const ids = ["I1", "I2", "I3", "I4", "STATE", "COVERAGE", "EXCEPTIONS"];
  const status = (id) =>
    violations.some((v) => v.invariant === id) ? "FAIL" : notRun.includes(id) ? "NOT RUN" : "pass";
  console.log(
    `\nℹ Scope: ${summary.tenant_tables} tenant-scoped table(s) out of ${summary.tables_total} in [${summary.schemas_scanned.join(", ")}]` +
      (summary.tables_untracked.length > 0
        ? `; ${summary.tables_untracked.length} table(s) carry no tenant column and are outside every invariant` +
          (summary.untracked_tables_mode === "report" ? " (coverage.untracked_tables: report)" : "")
        : "") +
      "."
  );
  console.log(`ℹ Checks: ${ids.map((id) => `${id} ${status(id)}`).join(" · ")}`);
}

/** GitHub Action outputs beyond the verdict, so a workflow can assert scope. */
function writeActionOutputs(summary, notRun) {
  if (!process.env.GITHUB_OUTPUT) return;
  appendFileSync(
    process.env.GITHUB_OUTPUT,
    `tenant-tables=${summary.tenant_tables}\nuntracked-tables=${summary.tables_untracked.length}\nchecks-not-run=${notRun.join(",")}\n`
  );
}
