# RLS Guard

**Security CI for multi-tenant Postgres, initially proven on Supabase/Postgres.**

RLS Guard keeps your Row Level Security posture from silently regressing: it
replays your migrations on an ephemeral Postgres, asserts four anti-leak
invariants, and **blocks the merge** (non-zero exit code → required status
check) when isolation would break. **No production secret is ever needed** —
the replay reads only your repository. A **tenant isolation evidence report**
(JSON + self-contained HTML) turns every green run into an attestation you
can hand to a security questionnaire.

## The four invariants

| | Invariant |
|---|---|
| **I1** | Every table carrying a tenant column (`tenant.columns`) has RLS enabled. |
| **I2** | No permissive `true` policy on a tenant table is reachable by non-privileged roles. |
| **I3** | No permissive write policy on a tenant table is blind to the tenant. Clauses are analyzed per command: INSERT's WITH CHECK and the new-row clause of UPDATE/ALL (WITH CHECK, or USING as fallback) must **bind the tenant** — an identity anchor alone still allows `UPDATE … SET tenant_id = …`. DELETE and the USING side accept owner-scoping. Permissive policies OR together, so one blind policy defeats every scoped one. |
| **I4** | No `SECURITY DEFINER` function touching a tenant table, executable by non-privileged roles, lacks a caller-identity guard — and none executable by them runs SQL built from its own text argument (`EXECUTE p_sql`), whatever the tables. |

Plus **STATE**: when a committed baseline exists, the replayed RLS posture
must match it.

## Quickstart — GitHub Action (under 10 minutes, zero secrets)

1. Copy this workflow to `.github/workflows/rls-guard.yml`:

```yaml
name: RLS Guard
on:
  pull_request:            # never pull_request_target — the action refuses it
    paths:
      - "supabase/migrations/**"
      - "db/rls-snapshot.json"
      - "rls-guard.yml"
  workflow_dispatch:
permissions:
  contents: read           # minimal; no secret of any kind is needed
jobs:
  replay:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: guard
        uses: OolalaDXB/rls-guard@main    # pin a tag or SHA in production
        with:
          report-dir: evidence
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: tenant-isolation-evidence
          path: evidence/
```

2. Commit, open a PR touching your migrations. The action boots an ephemeral
   Postgres, replays the migrations, runs the invariants, fails the check on
   violation, and attaches the evidence report as an artifact.
3. Make the job a **required status check** (Settings → Branches). The exit
   code is the gate; a PR comment is optional UX on top, never the mechanism.

Your schema uses other conventions? Add an `rls-guard.yml`
([full reference](docs/configuration.md)) — changing `tenant.columns`,
`schemas` or `privileged_roles` is all it takes; the engine never needs
patching.

**Wired-in guardrails** (enforced by the entrypoint, tested in CI, not just
documented): the action **refuses `pull_request_target`**; **`live-url` is
only accepted on `schedule`/`workflow_dispatch`**; on PR events,
**`database-url` may only point at loopback** (a job service container).
Fork-submitted code can never reach a credential — replay needs none.

## Quickstart — CLI

```sh
npm install -D github:OolalaDXB/rls-guard   # no npm release yet
export DATABASE_URL=postgres://…           # an ephemeral/local DB, never prod
npx rls-guard init                         # writes rls-guard.yml + captures the baseline
npx rls-guard check --report-dir evidence  # invariants → exit 0/1 + evidence report
```

`init` **refuses to bless a baseline that already violates the invariants**:
it prints the violations and exits 1 without writing anything. Fix them,
declare documented exceptions, or pass `--accept-violations` — an explicit
act; `check` keeps failing until the state is actually clean or excepted.

## See it PASS, then BLOCK

The [`demo/`](demo/) directory contains two migration sets for the same toy
multi-tenant schema — one clean, one carrying one violation per invariant
(including the UPDATE-tenant-reassignment and unguarded-definer classes).
The [Demo workflow](.github/workflows/demo.yml) runs both through the real
action on every push: the clean set must come back `verdict=pass`, the
violating set must make the action step **actually fail** with
`verdict=block`. Run it yourself with *Actions → Demo → Run workflow*.

## The evidence report

`check --report-dir <dir>` (CLI) or `report-dir:` (Action) writes:

- `evidence.json` — machine-readable: attestation metadata (commit SHA,
  config hash, tool version, Postgres version), scope, tenant-table
  inventory, per-table × per-operation policy coverage, the five invariant
  results with findings, the exposed SECURITY DEFINER inventory, exceptions
  in effect (each with its reason, explicitly out of attestation), and the
  proof boundary verbatim.
- `evidence.html` — the same content as a single-file, print-friendly page.

Verdicts come from the engine only — the report never re-decides. Errors
never attest: a config or runtime failure produces exit 2 and **no report,
no verdict**.

## Commands

| Command | Needs | Purpose |
|---|---|---|
| `rls-guard init` | ephemeral DB | write config + capture baseline (anti-blessing) |
| `rls-guard check` | ephemeral DB | the CI gate: invariants + baseline state comparison (+ `--report-dir`) |
| `rls-guard snapshot` | ephemeral DB | human-gated baseline refresh (same refusal rule) |
| `rls-guard drift` | **live DB credential** | diff a real database against the baseline (schedule/dispatch workflows only) |

Exit codes: `0` pass · `1` violation/drift · `2` configuration or runtime
error (never attests).

## What RLS Guard proves — and does not prove

Policy-level invariants on the schema **as your migrations build it** (and,
with `drift`, that the live database matches the baseline). It does **not**
prove that your application sets the tenant context at runtime, that a
present `SECURITY DEFINER` guard is semantically correct, what privileged
roles do, or anything outside the database. Normative statement:
[`docs/proof-boundary.md`](docs/proof-boundary.md). Known
false-positive/false-negative classes of the heuristics:
[`docs/limitations.md`](docs/limitations.md).

> RLS Guard guarantees your policy layer never regresses. It replaces
> neither a review of your application code, nor a pentest.

## Documentation

- [Configuration reference](docs/configuration.md) — every supported option.
- [Proof boundary](docs/proof-boundary.md) — normative.
- [Known limitations](docs/limitations.md) — FP/FN classes, stated plainly.
- [`examples/`](examples/) — replay gate and live-drift workflows.

## Tests

```sh
RLS_GUARD_TEST_URL=postgres://postgres:postgres@localhost:5432/postgres npm test
```

Toy-schema PASS/BLOCK suites (one violation per invariant), init-refusal,
tamper, drift, exception lifecycle, evidence report content, the action's
security guardrails, and entrypoint end-to-end runs.

## License

RLS Guard is **source-available**, not open source. It is licensed under
[PolyForm Shield 1.0.0](https://polyformproject.org/licenses/shield/1.0.0/).
You may use, modify and self-host RLS Guard freely — including to secure your
own applications and inside your own CI. You may not use it to build or offer
a product that competes with RLS Guard.
