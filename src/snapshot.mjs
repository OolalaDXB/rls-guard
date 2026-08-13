/**
 * Baseline snapshot: normalize, read/write, and diff.
 *
 * The snapshot is the committed reference of the RLS posture. Refreshing it
 * is always human-gated and always re-runs the invariants first (a baseline
 * that violates the invariants is never silently blessed — see init/snapshot
 * commands).
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname } from "node:path";

export const SNAPSHOT_FORMAT = "rls-guard/1";

export function normalizeSnapshot(s) {
  return {
    policies: [...(s.policies ?? [])].sort(cmpBy((p) => `${p.table_fqn}::${p.name}`)),
    functions: [...(s.functions ?? [])].sort(cmpBy((f) => f.signature)),
    tables: [...(s.tables ?? [])].sort(cmpBy((t) => t.table_fqn)),
  };
}

export function writeSnapshot(path, snapshot, { configHash }) {
  const normalized = normalizeSnapshot(snapshot);
  const doc = {
    format: SNAPSHOT_FORMAT,
    generated_at: new Date().toISOString(),
    config_hash: configHash,
    ...normalized,
  };
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(doc, null, 2) + "\n");
  return doc;
}

export function readSnapshot(path) {
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8"));
}

/* -------------------------------- diff ------------------------------- */

export function diffSnapshots(expected, actual) {
  const e = normalizeSnapshot(expected);
  const a = normalizeSnapshot(actual);
  const out = [];
  out.push(
    ...diffSet(
      "policy",
      indexBy(e.policies, (p) => `${p.table_fqn} :: ${p.name}`),
      indexBy(a.policies, (p) => `${p.table_fqn} :: ${p.name}`),
      ["permissive", "cmd", "roles", "using_expr", "with_check_expr"]
    )
  );
  out.push(
    ...diffSet(
      "function",
      indexBy(e.functions, (f) => f.signature),
      indexBy(a.functions, (f) => f.signature),
      ["security", "volatility", "config", "body_md5"]
    )
  );
  out.push(
    ...diffSet(
      "table-rls",
      indexBy(e.tables, (t) => t.table_fqn),
      indexBy(a.tables, (t) => t.table_fqn),
      ["rls_enabled", "rls_forced", "has_tenant_column"]
    )
  );
  return out;
}

/** Replay-vs-baseline RLS state comparison: does a rebuild from migrations
 *  reproduce the committed posture? (Missing/added tables surface in the full
 *  drift diff — here only the RLS state of tables present in both.) */
export function compareRlsState(expected, actual) {
  const violations = [];
  const exp = new Map((expected.tables ?? []).map((t) => [t.table_fqn, t]));
  const act = new Map((actual.tables ?? []).map((t) => [t.table_fqn, t]));
  for (const [fqn, e] of exp) {
    const a = act.get(fqn);
    if (!a) continue;
    if (!!a.rls_enabled !== !!e.rls_enabled) {
      violations.push({
        invariant: "STATE",
        table: fqn,
        message: `Replay RLS mismatch on ${fqn}: enabled baseline=${e.rls_enabled} replay=${a.rls_enabled}`,
      });
    }
    if (!!a.rls_forced !== !!e.rls_forced) {
      violations.push({
        invariant: "STATE",
        table: fqn,
        message: `Replay RLS FORCE mismatch on ${fqn}: baseline=${e.rls_forced} replay=${a.rls_forced}`,
      });
    }
  }
  return violations;
}

function indexBy(list, keyFn) {
  const m = new Map();
  for (const item of list) m.set(keyFn(item), item);
  return m;
}

function diffSet(kind, expected, actual, fields) {
  const out = [];
  const keys = new Set([...expected.keys(), ...actual.keys()]);
  for (const key of [...keys].sort()) {
    const e = expected.get(key);
    const a = actual.get(key);
    if (!e) {
      out.push({ kind, key, change: "added", line: `+ ${kind} added in DB: ${key}`, after: a });
      continue;
    }
    if (!a) {
      out.push({ kind, key, change: "removed", line: `- ${kind} missing from DB: ${key}`, before: e });
      continue;
    }
    for (const f of fields) {
      if (String(e[f] ?? "") !== String(a[f] ?? "")) {
        out.push({
          kind,
          key,
          change: "modified",
          field: f,
          line: `~ ${kind} ${key} :: ${f} changed`,
          before: e[f],
          after: a[f],
        });
      }
    }
  }
  return out;
}

function cmpBy(fn) {
  return (a, b) => (fn(a) < fn(b) ? -1 : fn(a) > fn(b) ? 1 : 0);
}
