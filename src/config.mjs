/**
 * Configuration loader for rls-guard.yml.
 *
 * Every platform-specific convention lives HERE as a default value, never in
 * the engine code: privileged role names, excluded schemas, identity anchors.
 * Covering another schema or another set of conventions must never require
 * touching the engine — only this file's defaults or the user's rls-guard.yml.
 *
 * Exceptions model: an exception is declared, motivated and visible — never
 * silent. Entries may be a bare string (tolerated, warns) or an object with a
 * mandatory `reason`. An optional `expires: YYYY-MM-DD` re-enforces the
 * invariant after that date. Unused exceptions are reported so the config
 * cannot rot.
 */
import { readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import YAML from "yaml";

export const DEFAULT_CONFIG_PATH = "rls-guard.yml";

const DEFAULTS = {
  tenant: {
    columns: ["tenant_id"],
    // Functions whose presence in a policy expression counts as tenant
    // scoping. Presumed identity-validating (they must derive the tenant from
    // the caller's identity, not from caller-supplied input) — documented
    // heuristic, see docs.
    scope_functions: ["current_tenant_id"],
  },
  // Expressions anchoring a policy or function on the caller's identity.
  // A write policy referencing one of these is owner-scoped, not tenant-blind.
  identity_anchors: ["auth.uid()", "auth.jwt()", "auth.role()"],
  privileged_roles: ["service_role"],
  schemas: { include: ["public"], exclude: ["auth", "storage"] },
  definer: {
    // Extra regexes (strings) recognized as caller-identity guards inside
    // SECURITY DEFINER function bodies, on top of the built-in set.
    identity_guards: [],
  },
  exceptions: {
    global_tables: [],
    public_policies: [],
    tenant_blind_writes: [],
    definer_functions: [],
  },
  postgres_version: "16",
  paths: { snapshot: "db/rls-snapshot.json" },
};

const EXCEPTION_KINDS = ["global_tables", "public_policies", "tenant_blind_writes", "definer_functions"];

export function loadConfig(path = DEFAULT_CONFIG_PATH) {
  const warnings = [];
  let user = {};
  if (existsSync(path)) {
    user = YAML.parse(readFileSync(path, "utf8")) ?? {};
  } else {
    warnings.push(`No ${path} found — running with built-in defaults (tenant.columns=[tenant_id], privileged_roles=[service_role]).`);
  }
  const config = deepMerge(structuredClone(DEFAULTS), user);

  for (const kind of EXCEPTION_KINDS) {
    config.exceptions[kind] = (config.exceptions[kind] ?? []).map((raw) =>
      normalizeException(raw, kind, warnings)
    );
  }

  validate(config);
  return { config, warnings };
}

function normalizeException(raw, kind, warnings) {
  const entry = typeof raw === "string" ? { name: raw } : { ...raw };
  if (!entry.name) {
    throw new ConfigError(`exceptions.${kind}: every entry needs a "name" (got: ${JSON.stringify(raw)})`);
  }
  if (!entry.reason) {
    warnings.push(`exceptions.${kind}: "${entry.name}" has no reason — undocumented exception (add "reason:").`);
  }
  if (entry.expires) {
    const d = new Date(String(entry.expires));
    if (Number.isNaN(d.getTime())) {
      throw new ConfigError(`exceptions.${kind}: "${entry.name}" has an invalid expires date "${entry.expires}" (use YYYY-MM-DD).`);
    }
    if (d.getTime() < Date.now()) {
      warnings.push(`exceptions.${kind}: "${entry.name}" expired on ${entry.expires} — the invariant is re-enforced.`);
      entry.expired = true;
    }
  }
  entry.used = false;
  return entry;
}

function validate(config) {
  if (!Array.isArray(config.tenant.columns) || config.tenant.columns.length === 0) {
    throw new ConfigError("tenant.columns must be a non-empty list of column names.");
  }
  if (!Array.isArray(config.schemas.include) || config.schemas.include.length === 0) {
    throw new ConfigError("schemas.include must be a non-empty list of schema names.");
  }
  for (const pattern of config.definer.identity_guards) {
    try {
      new RegExp(pattern);
    } catch {
      throw new ConfigError(`definer.identity_guards: "${pattern}" is not a valid regex.`);
    }
  }
}

/** The schemas actually scanned: include minus exclude. Every catalog query
 *  goes through this — exclude is enforced, not decorative. */
export function effectiveSchemas(config) {
  return config.schemas.include.filter((s) => !config.schemas.exclude.includes(s));
}

/** Stable hash of the effective config — stamped into snapshots and reports. */
export function configHash(config) {
  const canonical = JSON.stringify(config, (key, value) => {
    if (key === "used" || key === "expired") return undefined; // runtime state, not config
    return value;
  });
  return createHash("sha256").update(canonical).digest("hex").slice(0, 16);
}

/** Table-kind exception matcher (fqn "schema.table" or bare table name). */
export function matchTableException(list, tableFqn) {
  const bare = tableFqn.split(".").pop();
  const hit = list.find((e) => !e.expired && (e.name === tableFqn || e.name === bare));
  if (hit) hit.used = true;
  return hit;
}

/** Policy-kind exception matcher (policy name, optionally pinned to a table). */
export function matchPolicyException(list, policyName, tableFqn) {
  const bare = tableFqn.split(".").pop();
  const hit = list.find(
    (e) => !e.expired && e.name === policyName && (!e.table || e.table === tableFqn || e.table === bare)
  );
  if (hit) hit.used = true;
  return hit;
}

/** Function-kind exception matcher (bare name or full signature). */
export function matchFunctionException(list, proname, signature) {
  const hit = list.find((e) => !e.expired && (e.name === proname || e.name === signature));
  if (hit) hit.used = true;
  return hit;
}

export function unusedExceptions(config) {
  const out = [];
  for (const kind of EXCEPTION_KINDS) {
    for (const e of config.exceptions[kind]) {
      if (!e.used && !e.expired) out.push({ kind, name: e.name });
    }
  }
  return out;
}

export function usedExceptions(config) {
  const out = [];
  for (const kind of EXCEPTION_KINDS) {
    for (const e of config.exceptions[kind]) {
      if (e.used) out.push({ kind, name: e.name, reason: e.reason ?? "(no reason given)" });
    }
  }
  return out;
}

function deepMerge(base, extra) {
  if (extra === null || extra === undefined) return base;
  for (const [k, v] of Object.entries(extra)) {
    if (v && typeof v === "object" && !Array.isArray(v) && base[k] && typeof base[k] === "object" && !Array.isArray(base[k])) {
      base[k] = deepMerge(base[k], v);
    } else {
      base[k] = v;
    }
  }
  return base;
}

export class ConfigError extends Error {}
