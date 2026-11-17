/**
 * COVERAGE — a check that looked at nothing must not read as a pass.
 *
 * The invariants (I1–I4) only apply to tenant-scoped tables: tables carrying a
 * configured tenant column. That makes three reassuring-but-empty results
 * possible, all observed on real projects:
 *
 *   1. the configured tenant column does not exist yet (or is misspelled):
 *      zero tables are in scope, every invariant passes vacuously;
 *   2. a schema listed in `schemas.include` does not exist or is empty (typo,
 *      migration not replayed): nothing is scanned there, silently;
 *   3. a table has no tenant column at all: it is out of scope for every
 *      invariant, whatever its RLS state.
 *
 * This module turns those into explicit results:
 *
 *   coverage.min_tenant_tables   (default 1)   fewer tables in scope → block
 *   coverage.required_tables     (default [])  each must be tenant-scoped
 *   coverage.untracked_tables    report|fail   tables without a tenant column,
 *                                              not declared in
 *                                              exceptions.global_tables
 *   coverage.required_checks     (default [])  e.g. [STATE]: a required check
 *                                              that did not run → block
 *
 * A scanned schema with no table is always a violation: it is either a typo
 * or a replay that did not happen.
 *
 * Pure function of the introspected tables — no query of its own.
 */
import { effectiveSchemas, matchTableException } from "./config.mjs";

/**
 * @param tables  [{ table_fqn, has_tenant_column }] for the effective schemas
 * @returns { violations, summary }
 */
export function evaluateCoverage(config, tables, { notRun = [] } = {}) {
  const violations = [];
  const cov = config.coverage;
  const push = (message, extra = {}) => violations.push({ invariant: "COVERAGE", message, ...extra });

  const schemas = effectiveSchemas(config);
  const bySchema = new Map(schemas.map((s) => [s, 0]));
  for (const t of tables) {
    const s = t.table_fqn.split(".")[0];
    bySchema.set(s, (bySchema.get(s) ?? 0) + 1);
  }
  for (const [schema, n] of bySchema) {
    if (n === 0) {
      push(`Schema "${schema}" is listed in schemas.include but contains no table — nothing was checked there (typo, or migrations not replayed).`);
    }
  }

  // Same rule as the invariants: a tenant-column table declared global is out of scope.
  const tenantTables = tables.filter(
    (t) => t.has_tenant_column && !isDeclaredGlobal(config, t.table_fqn)
  );
  const tenantFqns = new Set(tenantTables.map((t) => t.table_fqn));

  if (tenantTables.length < cov.min_tenant_tables) {
    push(
      `Only ${tenantTables.length} tenant-scoped table(s) found (columns: ${config.tenant.columns.join(", ")}; schemas: ${schemas.join(", ")}) — ` +
        `coverage.min_tenant_tables requires ${cov.min_tenant_tables}. The invariants would pass without inspecting anything.`
    );
  }

  for (const name of cov.required_tables) {
    const hit = tables.find((t) => t.table_fqn === name || t.table_fqn.split(".").pop() === name);
    if (!hit) push(`Required table ${name} does not exist in the scanned schemas.`, { table: name });
    else if (!tenantFqns.has(hit.table_fqn)) {
      push(
        `Required table ${hit.table_fqn} is not tenant-scoped (no column among ${config.tenant.columns.join(", ")}, or declared global) — no invariant applies to it.`,
        { table: hit.table_fqn }
      );
    }
  }

  // Tables no invariant looks at. Declaring one in exceptions.global_tables
  // (with a reason) is the explicit way to say "out of tenant scope on purpose".
  const untracked = tables
    .filter((t) => !t.has_tenant_column)
    .filter((t) => !matchTableException(config.exceptions.global_tables, t.table_fqn))
    .map((t) => t.table_fqn);
  if (cov.untracked_tables === "fail") {
    for (const fqn of untracked) {
      push(
        `Table ${fqn} carries no tenant column and is not declared in exceptions.global_tables — no invariant applies to it.`,
        { table: fqn }
      );
    }
  }

  for (const id of cov.required_checks) {
    if (notRun.includes(id)) {
      violations.push({
        invariant: id,
        message: `Required check ${id} did not run (coverage.required_checks) — a check that did not run is not a pass.`,
      });
    }
  }

  return {
    violations,
    summary: {
      schemas_scanned: schemas,
      tables_total: tables.length,
      tenant_tables: tenantTables.length,
      tables_untracked: untracked,
      min_tenant_tables: cov.min_tenant_tables,
      required_tables: cov.required_tables,
      untracked_tables_mode: cov.untracked_tables,
      required_checks: cov.required_checks,
    },
  };
}

function isDeclaredGlobal(config, fqn) {
  const bare = fqn.split(".").pop();
  return config.exceptions.global_tables.some((e) => !e.expired && (e.name === fqn || e.name === bare));
}
