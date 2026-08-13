# Known limitations — false positives & false negatives

RLS Guard's invariants are catalog-level checks over normalized policy
expressions (`pg_get_expr`) and function definitions, using word-boundary
pattern matching — not a SQL semantic analyzer. That choice keeps the engine
fast, dependency-free and schema-agnostic, and it was validated against a
real production-scale schema (126 tables, 320 policies), but it has known
edges. They are listed here so nobody discovers them in an incident.

## Textual expression analysis (I2, I3)

- **FN — vacuous tenant reference.** `WITH CHECK (tenant_id IS NOT NULL)`
  textually binds the tenant column but constrains nothing meaningful. The
  invariant accepts it. Writing a vacuous check is a deliberate act; code
  review remains responsible for expression *quality*.
- **FN/FP — wrapper functions.** A policy calling `my_tenant_guard()` that
  internally checks the tenant is flagged (false positive) until the wrapper
  is declared in `tenant.scope_functions`; conversely, declaring a wrapper
  that does NOT validate the caller creates a false negative. The
  presumption on scope functions is documented in
  [`configuration.md`](configuration.md).
- **FP — references inside literals.** A tenant column name appearing inside
  a string literal or quoted identifier in the expression counts as a
  reference.
- **Restrictive policies are skipped.** They can only narrow access, never
  grant it, so I2/I3 ignore them. They appear in the coverage matrix marked
  `(restrictive)`.

## SECURITY DEFINER heuristics (I4)

- **Absence, not correctness.** I4 detects functions with *no* detectable
  caller-identity guard. A guard that exists but is wrong (checks the wrong
  thing, validates caller-supplied input) passes. The proof boundary states
  this; nothing in the report claims otherwise.
- **Trigger functions are out of scope.** Functions returning
  `trigger`/`event_trigger` cannot be invoked directly with caller-chosen
  arguments, so they are outside I4's attack class. A definer *trigger* that
  misbehaves on legitimate DML is not covered.
- **Body matching is textual.** Tenant-table references in function bodies
  are word-boundary matches: dynamic SQL that concatenates table names can
  evade detection (FN); an unrelated identifier spelled like a tenant table
  can flag a function (FP → `exceptions.definer_functions` with a reason).

## Structural scope

- **`FORCE ROW LEVEL SECURITY` is reported, not enforced.** I1 requires RLS
  *enabled*; table owners bypass RLS unless FORCE is set. The
  enabled/forced state of every tenant table is captured in the snapshot,
  compared by STATE, and shown in the evidence report — but a missing FORCE
  is not, by itself, a violation.
- **Grants and column privileges are not analyzed.** RLS Guard covers the
  policy layer; `GRANT`-level exposure, column grants, and
  `security_barrier` views are outside scope.
- **The coverage matrix is inventory, not verdict.** An empty cell means
  default-deny (when RLS is enabled) — informative, not a finding.

## Attestation scope

- **Replay attests migrations, not production.** Without live drift, a
  database mutated outside migrations is not covered — that is precisely
  what `drift` exists for.
- **STATE compares RLS posture only** (enabled/forced per table). The full
  three-family diff (policies, functions, tables) is the `drift` command's
  job.
- **An error is never an attestation.** Config or runtime errors exit 2 and
  produce no verdict and no report.

## Real-world validation note (anonymized)

Run against a production-scale multi-tenant schema (126 tables, 320
policies, 173 functions), the engine surfaced findings in every invariant
class — including one confirmed cross-tenant P0 in the definer class and a
family of owner-scoped UPDATE policies whose new-row clause did not bind the
tenant. The obvious-false-positive classes found during that validation
(trigger functions, deny-all `false` policies, intentionally-global
reference tables) were each turned into engine rules or documented
exception paths, with dedicated fixtures.
