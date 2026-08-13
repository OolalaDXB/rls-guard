# Demo — PASS, then BLOCK

Two migration sets for the same toy multi-tenant schema (zero business
semantics):

- **`migrations-pass/`** — fully scoped RLS posture. Every invariant holds.
- **`migrations-block/`** — the same schema plus one deliberate violation
  per invariant: a tenant table with RLS left off (I1), a permissive `true`
  policy (I2), a tenant-blind INSERT keyed on a global helper *and* an
  UPDATE whose WITH CHECK only anchors identity — the tenant-reassignment
  class (I3) — and an unguarded SECURITY DEFINER function taking the target
  row from a caller-supplied id (I4).

## On GitHub (the real gate)

The [Demo workflow](../.github/workflows/demo.yml) runs both sets through
the real action: the `demo-pass` job must end green with `verdict=pass` and
uploads the evidence report as an artifact; the `demo-block` job runs the
action with `continue-on-error` and then **asserts the step really failed**
with `verdict=block` — proving the gate blocks, without leaving the
repository red. Trigger it manually with *Actions → Demo → Run workflow*.

## Locally

```sh
createdb rlsguard_demo
psql -d rlsguard_demo -v ON_ERROR_STOP=1 -f sql/bootstrap-replay.sql
for f in demo/migrations-pass/*.sql;  do psql -d rlsguard_demo -v ON_ERROR_STOP=1 -f "$f"; done
npx rls-guard check --url postgres://localhost/rlsguard_demo --report-dir evidence
# → exit 0, evidence/evidence.html shows PASS

psql -d rlsguard_demo -v ON_ERROR_STOP=1 -f demo/migrations-block/010_violations.sql
npx rls-guard check --url postgres://localhost/rlsguard_demo --report-dir evidence-block
# → exit 1, one finding per invariant, evidence-block/evidence.html shows BLOCK
```
