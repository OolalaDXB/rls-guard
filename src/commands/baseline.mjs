/**
 * Shared baseline capture used by `init` and `snapshot`.
 *
 * THE BASELINE TRAP, by design: capturing a baseline NEVER silently blesses
 * the current state. The invariants run first; if the state violates them,
 * the capture is refused (exit 1, nothing written) unless the operator
 * explicitly passes --accept-violations — an explicit, logged act, never a
 * default.
 */
import { introspect } from "../introspect.mjs";
import { runInvariants } from "../invariants.mjs";
import { writeSnapshot } from "../snapshot.mjs";
import { configHash, usedExceptions, unusedExceptions } from "../config.mjs";
import { printViolations, printExceptionReport, hr } from "./output.mjs";

export async function captureBaseline(client, config, { snapshotPath, acceptViolations, label }) {
  const snapshot = await introspect(client, config);
  const { violations } = await runInvariants(client, config);

  console.log(
    `${label}: introspected ${snapshot.tables.length} table(s), ${snapshot.policies.length} polic(ies), ${snapshot.functions.length} function(s).`
  );
  printExceptionReport(usedExceptions(config), unusedExceptions(config));

  if (violations.length > 0) {
    printViolations(violations);
    if (!acceptViolations) {
      hr();
      console.error(`✗ ${label} refused: the current state already violates ${violations.length} invariant(s).`);
      console.error("  A baseline that leaks must not become the blessed reference. Either:");
      console.error("    1. fix the violations (see each finding above), or");
      console.error("    2. declare documented exceptions in rls-guard.yml (each needs a reason), or");
      console.error("    3. re-run with --accept-violations to write the baseline anyway — an explicit,");
      console.error("       visible act; the violations will keep failing `check` until fixed or excepted.");
      return { written: false, violations };
    }
    hr();
    console.error(`⚠ --accept-violations: writing a baseline that violates ${violations.length} invariant(s).`);
    console.error("  This does NOT silence them — `check` will keep failing until they are fixed or excepted.");
  }

  const doc = writeSnapshot(snapshotPath, snapshot, { configHash: configHash(config) });
  console.log(`✓ Baseline written to ${snapshotPath} (config ${doc.config_hash}).`);
  return { written: true, violations };
}
