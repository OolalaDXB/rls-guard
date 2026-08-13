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
import { printViolations, printExceptionReport } from "./output.mjs";

export async function check(client, config, { snapshotPath, reportDir }) {
  const { violations } = await runInvariants(client, config);

  const baseline = readSnapshot(snapshotPath);
  if (baseline) {
    const live = await introspect(client, config);
    violations.push(...compareRlsState(baseline, live));
  } else {
    console.warn(`⚠ No baseline at ${snapshotPath} — skipping replay-vs-baseline RLS state comparison. Run \`rls-guard init\` once and commit it.`);
  }

  printExceptionReport(usedExceptions(config), unusedExceptions(config));

  if (reportDir) {
    const { jsonPath, htmlPath } = await writeEvidenceReport(client, config, {
      violations,
      reportDir,
      baselinePresent: !!baseline,
    });
    console.log(`ℹ Evidence report written: ${jsonPath}, ${htmlPath}`);
  }

  if (violations.length === 0) {
    console.log(
      "✓ Check passed — every tenant-scoped table has RLS enabled, no reachable `true` permissive policy, " +
        "no tenant-blind write policy, no unguarded SECURITY DEFINER touching tenant tables" +
        (baseline ? ", RLS state matches the baseline." : ".")
    );
    return 0;
  }

  printViolations(violations);
  return 1;
}
