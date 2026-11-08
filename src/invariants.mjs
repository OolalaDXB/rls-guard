/**
 * The invariant engine — the defensible core.
 *
 * Four hard invariants, all evaluated against pg_catalog (no data access):
 *
 *   I1  Every table carrying a configured tenant column has RLS enabled.
 *   I2  No PERMISSIVE policy on a tenant-scoped table whose USING / WITH
 *       CHECK is literally `true` is reachable by non-privileged roles.
 *   I3  No PERMISSIVE write policy (INSERT/UPDATE/DELETE/ALL) on a
 *       tenant-scoped table is blind to the tenant. Clauses are analyzed
 *       PER COMMAND, never concatenated: INSERT's WITH CHECK and the
 *       new-row clause of UPDATE/ALL (WITH CHECK, falling back to USING per
 *       Postgres semantics) must be TENANT-BOUND — a caller identity anchor
 *       alone is not enough, since `auth.uid() IS NOT NULL` still lets
 *       UPDATE … SET tenant_id = … re-assign rows across tenants. DELETE and
 *       the USING side of UPDATE/ALL accept owner-scoping (identity anchor),
 *       because they only gate access to existing rows. Permissive policies
 *       OR together, so a single blind policy defeats every scoped one.
 *   I4  No SECURITY DEFINER function that touches a tenant-scoped table and
 *       is executable by non-privileged roles lacks a caller-identity guard.
 *       This detects the ABSENCE of any guard (the real-world cross-tenant
 *       hole class); it does not prove a present guard is correct.
 *
 * Everything platform-specific (role names, identity anchors, scope
 * functions) comes from config — the engine itself is schema-agnostic.
 */
import {
  matchTableException,
  matchPolicyException,
  matchFunctionException,
  effectiveSchemas,
} from "./config.mjs";

const WRITE_CMDS = new Set(["a", "w", "d", "*"]);

// Built-in caller-identity guard patterns for SECURITY DEFINER bodies.
// Extensible via definer.identity_guards in config.
const BUILTIN_DEFINER_GUARDS = [
  /\bhas_role\s*\(/i,
  /\bhas_any_role\s*\(/i,
  /current_setting\s*\(\s*'request\.jwt/i,
];

export async function runInvariants(client, config) {
  const violations = [];

  const tenantTables = await fetchTenantTables(client, config);
  const effectiveTenantTables = tenantTables.filter(
    (t) => !matchTableException(config.exceptions.global_tables, t.table_fqn)
  );
  const tenantFqns = new Set(effectiveTenantTables.map((t) => t.table_fqn));

  // I1 — RLS enabled on every tenant-scoped table.
  for (const t of effectiveTenantTables) {
    if (!t.rls_enabled) {
      violations.push({
        invariant: "I1",
        table: t.table_fqn,
        message: `RLS disabled on tenant-scoped table: ${t.table_fqn}`,
      });
    }
  }

  const policies = await fetchPolicies(client, config);

  // Restrictive tenant fence (opt-in, tenant.fence: restrictive). A fenced
  // table carries a RESTRICTIVE policy for every role and every command whose
  // USING and WITH CHECK are exactly `tenant column = scope function()`.
  // Restrictive policies are ANDed with the permissive ones, so no permissive
  // policy on that table can reach or write another tenant's rows.
  const fenced = new Map(); // table_fqn -> fence policy name
  if (config.tenant.fence === "restrictive") {
    for (const p of policies) {
      if (p.permissive || p.polcmd !== "*" || !tenantFqns.has(p.table_fqn)) continue;
      const roles = p.roles?.length ? p.roles : ["public"];
      if (!roles.includes("public")) continue;
      if (isFenceClause(p.using_expr, config) && isFenceClause(p.with_check_expr, config)) {
        fenced.set(p.table_fqn, p.polname);
      }
    }
    for (const t of effectiveTenantTables) {
      if (t.rls_enabled && !fenced.has(t.table_fqn)) {
        violations.push({
          invariant: "I1",
          table: t.table_fqn,
          message: `Tenant-scoped table has no restrictive tenant fence (tenant.fence: restrictive): ${t.table_fqn}`,
        });
      }
    }
  }

  for (const p of policies) {
    const roles = p.roles?.length ? p.roles : ["public"];
    const privilegedOnly =
      !roles.includes("public") && roles.every((r) => config.privileged_roles.includes(r));
    if (privilegedOnly) continue; // unreachable by tenant users — not a leak
    if (!p.permissive) continue; // restrictive policies only narrow access

    // A policy whose predicate is literally `false` grants nothing — it is a
    // deny-all written in permissive form, not a leak.
    if (isLiterally(p.using_expr, "false") || isLiterally(p.with_check_expr, "false")) continue;

    // I2 and I3 are tenant-isolation invariants: they apply to tenant-scoped
    // tables. A `true` policy on a global reference table (config, registry)
    // is a deliberate publication, not a tenant leak.
    if (!tenantFqns.has(p.table_fqn)) continue;

    // Under a restrictive fence, a permissive policy only chooses WHICH of the
    // tenant's own rows a role sees; the fence already keeps other tenants out.
    if (fenced.has(p.table_fqn)) continue;

    // I2 — permissive `true` policy reachable by non-privileged roles.
    if (isLiterallyTrue(p.using_expr) || isLiterallyTrue(p.with_check_expr)) {
      const exception = matchPolicyException(config.exceptions.public_policies, p.polname, p.table_fqn);
      if (!exception) {
        violations.push({
          invariant: "I2",
          table: p.table_fqn,
          policy: p.polname,
          message: `Permissive "true" policy on ${p.table_fqn}: ${p.polname} [${p.cmd}] (roles: ${roles.join(",")})`,
        });
      }
      continue; // a `true` policy is already maximally blind — don't double-report via I3
    }

    // I3 — tenant-blind write policy on a tenant-scoped table.
    if (WRITE_CMDS.has(p.polcmd)) {
      const problem = tenantBlindProblem(p, config);
      if (problem) {
        const exception = matchPolicyException(config.exceptions.tenant_blind_writes, p.polname, p.table_fqn);
        if (!exception) {
          violations.push({
            invariant: "I3",
            table: p.table_fqn,
            policy: p.polname,
            message: `Tenant-blind write policy on ${p.table_fqn}: ${p.polname} [${p.cmd}] — ${problem}`,
          });
        }
      }
    }
  }

  // I4 — unguarded SECURITY DEFINER functions touching tenant tables.
  const definers = await fetchExposedDefiners(client, config);
  // I4 (dynamic SQL) — a definer that EXECUTEs a string built from its own text
  // argument runs the caller's SQL as its owner: no table name in the body, no
  // guard that matters. Reported whatever the tables, since the SQL is the caller's.
  const dynamicSql = new Set();
  for (const fn of definers) {
    const arg = executesTextArgument(fn);
    if (!arg) continue;
    const exception = matchFunctionException(config.exceptions.definer_functions, fn.proname, fn.signature);
    if (exception) continue;
    dynamicSql.add(fn.signature);
    violations.push({
      invariant: "I4",
      function: fn.signature,
      message: `SECURITY DEFINER executes caller-supplied SQL: ${fn.signature} — EXECUTE builds its statement from the argument "${arg}", and non-privileged roles can call it`,
    });
  }

  const tenantNamePattern = buildTenantTablePattern(effectiveTenantTables);
  if (tenantNamePattern) {
    for (const fn of definers) {
      if (dynamicSql.has(fn.signature)) continue; // already reported above
      if (!tenantNamePattern.test(fn.def)) continue; // touches no tenant table
      if (hasDefinerGuard(fn.def, config)) continue;
      if (fenced.size && fenceBindsDefiner(fn, effectiveTenantTables, fenced)) continue;
      const exception = matchFunctionException(config.exceptions.definer_functions, fn.proname, fn.signature);
      if (exception) continue;
      violations.push({
        invariant: "I4",
        function: fn.signature,
        message: `Unguarded SECURITY DEFINER touching tenant-scoped table(s): ${fn.signature} — executable by non-privileged roles, body has no caller-identity guard`,
      });
    }
  }

  return { violations, tenantTables: effectiveTenantTables };
}

/* ------------------------------ queries ------------------------------ */

async function fetchTenantTables(client, config) {
  const { rows } = await client.query({
    text: `
      select
        n.nspname || '.' || c.relname as table_fqn,
        c.relname                     as relname,
        c.relrowsecurity              as rls_enabled,
        c.relforcerowsecurity         as rls_forced,
        c.relowner::int               as owner_oid
      from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = any($1)
        and c.relkind = 'r'
        and c.relpersistence = 'p'
        and exists (
          select 1 from pg_attribute a
           where a.attrelid = c.oid
             and a.attname  = any($2)
             and a.attnum > 0
             and not a.attisdropped
        )
      order by table_fqn;
    `,
    values: [effectiveSchemas(config), config.tenant.columns],
  });
  return rows;
}

async function fetchPolicies(client, config) {
  const { rows } = await client.query({
    text: `
      select
        n.nspname || '.' || c.relname  as table_fqn,
        p.polname,
        p.polpermissive                as permissive,
        p.polcmd,
        case p.polcmd when 'r' then 'SELECT' when 'a' then 'INSERT'
                      when 'w' then 'UPDATE' when 'd' then 'DELETE'
                      when '*' then 'ALL' end as cmd,
        coalesce((
          select array_agg(rolname::text order by rolname)
            from pg_roles where oid = any(p.polroles)
        ), '{}'::text[])                as roles,
        coalesce(pg_get_expr(p.polqual,      p.polrelid), '') as using_expr,
        coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '') as with_check_expr
      from pg_policy p
      join pg_class c     on c.oid = p.polrelid
      join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = any($1)
      order by table_fqn, p.polname;
    `,
    values: [effectiveSchemas(config)],
  });
  return rows;
}

/**
 * SECURITY DEFINER functions whose EXECUTE is reachable by roles outside
 * privileged_roles. proacl NULL means the default ACL, which grants EXECUTE
 * to PUBLIC — Postgres's default is open, so an absent ACL is an exposed one.
 */
async function fetchExposedDefiners(client, config) {
  const { rows } = await client.query({
    text: `
      select
        n.nspname || '.' || p.proname || '(' ||
          pg_get_function_identity_arguments(p.oid) || ')' as signature,
        p.proname,
        pg_get_functiondef(p.oid)                          as def,
        p.proowner::int                                    as owner_oid,
        (r.rolsuper or r.rolbypassrls)                     as owner_bypasses_rls,
        coalesce((
          select array_agg(nm order by nm)
            from unnest(p.proargnames, p.proargtypes::oid[]) as a(nm, typ)
           where nm <> '' and typ in ('pg_catalog.text'::regtype, 'pg_catalog.varchar'::regtype, 'pg_catalog.bpchar'::regtype)
        ), '{}'::text[])                                   as text_args
      from pg_proc p
      join pg_namespace n on n.oid = p.pronamespace
      join pg_roles r     on r.oid = p.proowner
      where n.nspname = any($1)
        and p.prokind = 'f'
        and p.prosecdef
        -- Trigger functions cannot be invoked directly with caller-chosen
        -- arguments ("trigger functions can only be called as triggers") —
        -- they are outside I4's direct-invocation attack class.
        and p.prorettype not in ('pg_catalog.trigger'::regtype, 'pg_catalog.event_trigger'::regtype)
        and exists (
          select 1
          from aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
          where a.privilege_type = 'EXECUTE'
            and a.grantee <> p.proowner
            and (
              a.grantee = 0  -- PUBLIC
              or exists (
                select 1 from pg_roles r
                 where r.oid = a.grantee and r.rolname <> all($2::name[])
              )
            )
        )
      order by signature;
    `,
    values: [effectiveSchemas(config), config.privileged_roles],
  });
  return rows;
}

/* ----------------------------- heuristics ---------------------------- */

/**
 * Per-command clause analysis — clauses are never concatenated.
 *   INSERT ('a'): only WITH CHECK exists; it constrains the NEW row and must
 *     be tenant-bound (an identity anchor alone lets the caller pick any
 *     tenant_id).
 *   DELETE ('d'): only USING matters (no new row); owner-scoping is enough.
 *   UPDATE ('w') / ALL ('*'): USING gates which existing rows are reachable
 *     (owner-scoping accepted), AND the new-row clause — WITH CHECK, falling
 *     back to USING when absent, per Postgres semantics — must be
 *     tenant-bound, or UPDATE … SET tenant_id = … crosses tenants.
 * Returns null when the policy is sound, else the reason string.
 */
function tenantBlindProblem(p, config) {
  const usingExpr = p.using_expr ?? "";
  const checkExpr = p.with_check_expr ?? "";
  switch (p.polcmd) {
    case "a":
      return isTenantBound(checkExpr, config)
        ? null
        : "WITH CHECK does not bind the tenant — new rows can target any tenant";
    case "d":
      return isScoped(usingExpr, config)
        ? null
        : "USING references no tenant column, no tenant scope function, no identity anchor";
    case "w":
    case "*": {
      if (!isScoped(usingExpr, config)) {
        return "USING references no tenant column, no tenant scope function, no identity anchor";
      }
      const newRowExpr = checkExpr || usingExpr;
      return isTenantBound(newRowExpr, config)
        ? null
        : "new-row clause (WITH CHECK, or USING fallback) does not bind the tenant — UPDATE can re-assign rows across tenants";
    }
    default:
      return null;
  }
}

/** STRICT tenant binding: tenant column or tenant scope function only.
 *  An identity anchor is deliberately NOT accepted here. */
function isTenantBound(expr, config) {
  if (!expr) return false;
  for (const col of config.tenant.columns) {
    if (new RegExp(`\\b${escapeRegex(col)}\\b`, "i").test(expr)) return true;
  }
  for (const fn of config.tenant.scope_functions) {
    if (new RegExp(`\\b${escapeRegex(fn)}\\s*\\(`, "i").test(expr)) return true;
  }
  return false;
}

function isLiterallyTrue(expr) {
  return isLiterally(expr, "true");
}

function isLiterally(expr, literal) {
  if (!expr) return false;
  let s = expr.trim().toLowerCase();
  while (s.startsWith("(") && s.endsWith(")")) s = s.slice(1, -1).trim();
  return s === literal;
}

/** A policy predicate is scoped if it references a tenant column, a tenant
 *  scope function, or a caller identity anchor (owner-based policies). */
function isScoped(expr, config) {
  for (const col of config.tenant.columns) {
    if (new RegExp(`\\b${escapeRegex(col)}\\b`, "i").test(expr)) return true;
  }
  for (const fn of config.tenant.scope_functions) {
    if (new RegExp(`\\b${escapeRegex(fn)}\\s*\\(`, "i").test(expr)) return true;
  }
  for (const anchor of config.identity_anchors) {
    if (anchorRegex(anchor).test(expr)) return true;
  }
  return false;
}

function hasDefinerGuard(body, config) {
  for (const re of BUILTIN_DEFINER_GUARDS) {
    if (re.test(body)) return true;
  }
  for (const anchor of config.identity_anchors) {
    if (anchorRegex(anchor).test(body)) return true;
  }
  // Scope functions are presumed identity-validating (they must derive the
  // tenant from the caller, not from caller-supplied input) — heuristic,
  // documented as such.
  for (const fn of config.tenant.scope_functions) {
    if (new RegExp(`\\b${escapeRegex(fn)}\\s*\\(`, "i").test(body)) return true;
  }
  for (const pattern of config.definer.identity_guards) {
    if (new RegExp(pattern, "i").test(body)) return true;
  }
  return false;
}

/**
 * A fence clause is exactly `<tenant column> = <scope function>()`, possibly
 * wrapped in the `(SELECT fn() AS fn)` form Postgres prints for an initPlan.
 * Anything looser (IS NOT NULL, OR …, a second condition) is not a fence.
 */
function isFenceClause(expr, config) {
  if (!expr) return false;
  let s = expr.trim();
  while (s.startsWith("(") && s.endsWith(")") && balanced(s.slice(1, -1))) s = s.slice(1, -1).trim();
  const cols = config.tenant.columns.map(escapeRegex).join("|");
  const fns = config.tenant.scope_functions.map(escapeRegex).join("|");
  const call = `(?:\\w+\\.)?(?:${fns})\\(\\)`;
  const rhs = `(?:${call}|\\(\\s*SELECT\\s+${call}(?:\\s+AS\\s+\\w+)?\\s*\\))`;
  return new RegExp(`^(?:${cols})\\s*=\\s*${rhs}$`, "i").test(s);
}

function balanced(s) {
  let depth = 0;
  for (const ch of s) {
    if (ch === "(") depth++;
    else if (ch === ")" && --depth < 0) return false;
  }
  return depth === 0;
}

/**
 * A SECURITY DEFINER function runs as its owner, so the fence holds inside it
 * only if RLS applies to that owner: the owner is neither superuser nor
 * BYPASSRLS, and for every tenant table the body names, the table is fenced
 * and the owner does not own it (an owner skips RLS unless FORCE ROW LEVEL
 * SECURITY is on). A body that sets a setting (set_config, SET LOCAL/SESSION)
 * could move the scope function to another tenant: it is not trusted.
 */
function fenceBindsDefiner(fn, tenantTables, fenced) {
  if (fn.owner_bypasses_rls) return false;
  if (/\bset_config\s*\(|\bset\s+(?:local|session)\s/i.test(fn.def)) return false;
  for (const t of tenantTables) {
    if (!new RegExp(`\\b${escapeRegex(t.relname)}\\b`, "i").test(fn.def)) continue;
    if (!fenced.has(t.table_fqn)) return false;
    if (t.owner_oid === fn.owner_oid && !t.rls_forced) return false;
  }
  return true;
}

/**
 * The text argument a PL/pgSQL EXECUTE builds its statement from, or null.
 * Only the statement part counts: what follows USING is bound as a value, and a
 * format() whose placeholders are all %I / %L quotes what it inserts.
 */
function executesTextArgument(fn) {
  const args = fn.text_args ?? [];
  if (!args.length) return null;
  const body = fn.def.replace(/--[^\n]*/g, "");
  for (const m of body.matchAll(/\bexecute\s+([^;]*)/gi)) {
    let stmt = m[1].split(/\busing\b/i)[0];
    const fmt = stmt.match(/^\s*format\s*\(\s*'((?:[^']|'')*)'/i);
    if (fmt) {
      const placeholders = fmt[1].match(/%[^%]/g) ?? [];
      if (placeholders.every((ph) => /%[IL]/i.test(ph))) continue;
    }
    for (const a of args) {
      if (new RegExp(`(^|[^\\w.])${escapeRegex(a)}(?![\\w])`, "i").test(stmt)) return a;
    }
  }
  return null;
}

function buildTenantTablePattern(tenantTables) {
  if (tenantTables.length === 0) return null;
  const names = tenantTables.map((t) => escapeRegex(t.relname));
  return new RegExp(`\\b(${names.join("|")})\\b`, "i");
}

function anchorRegex(anchor) {
  // "auth.uid()" → /auth\.uid\s*\(\s*\)/i  (tolerates whitespace inside the call)
  const escaped = escapeRegex(anchor).replace(/\\\(\\\)$/, "\\s*\\(\\s*\\)");
  return new RegExp(escaped, "i");
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
