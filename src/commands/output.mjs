/** Shared console output helpers — one voice across commands. */

export function printViolations(violations) {
  console.error(`\n✗ ${violations.length} invariant violation(s):\n`);
  for (const v of violations) console.error(`  • [${v.invariant}] ${v.message}`);
}

export function printExceptionReport(used, unused) {
  if (used.length > 0) {
    console.log(`\nℹ ${used.length} documented exception(s) in effect (excluded from attestation):`);
    for (const e of used) console.log(`  • ${e.kind}: ${e.name} — ${e.reason}`);
  }
  if (unused.length > 0) {
    console.warn(`\n⚠ ${unused.length} exception(s) matched nothing (stale config — remove or fix):`);
    for (const e of unused) console.warn(`  • ${e.kind}: ${e.name}`);
  }
}

export function printWarnings(warnings) {
  for (const w of warnings) console.warn(`⚠ ${w}`);
}

export function hr() {
  console.error("");
}
