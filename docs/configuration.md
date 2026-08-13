# Configuration reference

Everything platform-specific is configuration. Covering another schema or
another set of conventions never requires touching the engine — only
`rls-guard.yml`. Every option below is read by the engine; there are no
decorative keys.

```yaml
tenant:
  columns: [tenant_id]
  scope_functions: [current_tenant_id]
identity_anchors: ["auth.uid()", "auth.jwt()", "auth.role()"]
privileged_roles: [service_role]
schemas:
  include: [public]
  exclude: [auth, storage]
definer:
  identity_guards: []
exceptions:
  global_tables: []
  public_policies: []
  tenant_blind_writes: []
  definer_functions: []
postgres_version: "16"
paths:
  snapshot: db/rls-snapshot.json
```

## `tenant.columns` — default `[tenant_id]`

Column names that mark a table as **tenant-scoped**. A table carrying any of
these columns enters the scope of invariants I1 (RLS enabled), I3
(tenant-blind writes), I4 (definer functions touching it), and the coverage
matrix of the evidence report. Multiple conventions are fine:
`[tenant_id, org_id, workspace_id]`.

## `tenant.scope_functions` — default `[current_tenant_id]`

Function names whose presence in a policy expression **counts as tenant
scoping**, and whose presence in a SECURITY DEFINER body counts as a
caller-identity guard (I4).

> **Heuristic, stated plainly:** these functions are *presumed* to derive the
> tenant from the **caller's identity** (JWT, session), never from
> caller-supplied input. If one of yours takes the tenant from a request
> parameter, the presumption is wrong and the guarantee is void — fix the
> function before declaring it here.

## `identity_anchors` — default `["auth.uid()", "auth.jwt()", "auth.role()"]`

Expressions anchoring a policy on the **caller's identity**. Accepted as
scoping for row-access clauses (a `USING (user_id = auth.uid())` DELETE is
owner-scoped, fine), and as guards in definer bodies. **Not** accepted as
tenant binding for new-row clauses — `WITH CHECK (auth.uid() IS NOT NULL)`
still lets an UPDATE re-assign `tenant_id`; only `tenant.columns` /
`tenant.scope_functions` bind the tenant there (see I3 in the README).
Extend for non-Supabase stacks (e.g. `["current_setting('app.user_id')"]`).

## `privileged_roles` — default `[service_role]`

Roles that bypass tenant isolation **by design** (backend-only credentials).
A policy whose role list is a subset of these is exempt from I2/I3
(unreachable by tenant users), and EXECUTE grants limited to these roles do
not count as exposure for I4. Never list a role that end-user requests can
assume.

## `schemas.include` / `schemas.exclude`

The scanned set is `include` **minus** `exclude`, applied to every catalog
query (tables, policies, functions, snapshot). Defaults: include `public`,
exclude `auth, storage`.

## `definer.identity_guards` — default `[]`

Extra **regexes** recognized as caller-identity guards inside SECURITY
DEFINER bodies, on top of the built-ins: your `identity_anchors`, your
`tenant.scope_functions`, `has_role(`, `has_any_role(`, and
`current_setting('request.jwt…`. Example: `["\\bassert_caller_is_member\\b"]`.

## `exceptions.*` — declared, motivated, visible; never silent

Four kinds, one shape:

```yaml
exceptions:
  global_tables:            # tables intentionally outside tenant scope
    - name: fx_rates        # bare name or schema-qualified
      reason: "Global reference data, no tenant rows"
  public_policies:          # intentionally-public `true` policies (I2)
    - name: directory_read
      table: directory      # optional: pin to a table
      reason: "Anonymous read of the public directory is intended"
      expires: 2027-01-01   # optional: re-enforced after this date
  tenant_blind_writes: []   # documented I3 exceptions (same shape)
  definer_functions: []     # reviewed I4 functions (name or full signature)
```

Rules, all enforced: an entry without `reason` warns (undocumented
exception); every exception **in effect is printed by every run** and listed
in the evidence report as *excluded from attestation*; an exception matching
nothing is reported as stale; an expired exception re-enforces the invariant.
A bare string is tolerated as shorthand for `{name: …}` and warns.

## `postgres_version` — default `"16"`

Image tag of the ephemeral Postgres the GitHub Action boots for replay.
Align it with your production target.

## `paths.snapshot` — default `db/rls-snapshot.json`

Location of the committed baseline, relative to the working directory.
Captured by `init`/`snapshot` (both refuse to bless a violating state —
see the README), consumed by `check` (state comparison) and `drift`
(full diff).

---

## CLI flags

| Flag | Commands | Meaning |
|---|---|---|
| `--config <path>` | all | config file (default `rls-guard.yml`) |
| `--url <postgres url>` | all | database (fallback: `DATABASE_URL`) |
| `--accept-violations` | `init`, `snapshot` | write a violating baseline anyway — explicit, loud, and `check` keeps failing |
| `--report-dir <dir>` | `check` | write `evidence.json` + `evidence.html` |
| `--artifact-dir <dir>` | `drift` | drift artifacts (default `drift-report`) |

## GitHub Action inputs

| Input | Default | Meaning |
|---|---|---|
| `config` | `rls-guard.yml` | config path |
| `migrations-dir` | `supabase/migrations` | `.sql` files applied in alphabetical order |
| `bootstrap-sql` | bundled stubs | platform emulation SQL; `none` to skip; or your own file |
| `database-url` | *(empty)* | reuse a job **service container** instead of self-booting; on `pull_request` events only loopback hosts are accepted (enforced) |
| `report-dir` | *(empty)* | write the evidence report there (pair with `upload-artifact`) |
| `live-url` | *(empty)* | live drift instead of replay; only accepted on `schedule` / `workflow_dispatch` (enforced) |

Outputs: `verdict` = `pass` or `block` (only for real check outcomes — an
error produces no verdict).
