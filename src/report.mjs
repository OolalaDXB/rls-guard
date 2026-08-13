/**
 * Tenant isolation evidence report — JSON + self-contained HTML.
 *
 * The report is an attestation artifact for security questionnaires and
 * audits: reproducible (commit SHA + config hash + tool version), explicit
 * about scope and exceptions, and carrying the proof boundary verbatim.
 *
 * VERDICTS COME FROM THE ENGINE ONLY. This module never re-decides an
 * invariant: it inventories the catalog (tables, policies, definer
 * functions) and cross-references the violations and exceptions produced by
 * the frozen engine. An error is never an attestation: callers only invoke
 * this after a real check run (exit 0 or 1).
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { configHash, effectiveSchemas, usedExceptions, unusedExceptions } from "./config.mjs";

export const REPORT_FORMAT = "rls-guard-evidence/1";

const PKG = JSON.parse(readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "..", "package.json"), "utf8"));

const INVARIANTS = [
  { id: "I1", title: "RLS enabled on every tenant-scoped table" },
  { id: "I2", title: "No permissive `true` policy reachable by non-privileged roles on tenant tables" },
  { id: "I3", title: "No tenant-blind write policy (per-clause analysis: new-row clauses must bind the tenant)" },
  { id: "I4", title: "No unguarded SECURITY DEFINER function touching tenant tables, executable by non-privileged roles" },
  { id: "STATE", title: "Replayed RLS state matches the committed baseline" },
];

export const PROOF_BOUNDARY = {
  proves: [
    "Every table carrying a configured tenant column has Row Level Security enabled, in the schema as the migrations build it.",
    "No permissive policy whose predicate is literally `true` is reachable by non-privileged roles on a tenant-scoped table.",
    "No permissive write policy on a tenant-scoped table is blind to the tenant: INSERT's WITH CHECK and the new-row clause of UPDATE/ALL bind the tenant (a caller identity anchor alone is not accepted there).",
    "No SECURITY DEFINER function that touches a tenant-scoped table and is executable by non-privileged roles lacks a detectable caller-identity guard.",
    "When a committed baseline exists, the replayed RLS state (enabled/forced) matches it.",
  ],
  does_not_prove: [
    "That the application sets the tenant context correctly at runtime (headers, session variables, JWT claims).",
    "That a guard present in a SECURITY DEFINER function is semantically correct — the invariant detects the ABSENCE of any guard, not the correctness of one.",
    "Anything about code paths running as privileged roles (they bypass RLS by design).",
    "The absence of leaks outside the database: logs, caches, exports, object storage, application endpoints.",
    "That the live production database matches these migrations, unless live drift detection was run against it.",
    "Behavior on real data: these are catalog-level invariants, not data-access tests or a penetration test.",
  ],
};

/** Generate and write evidence.json + evidence.html. Returns their paths. */
export async function writeEvidenceReport(client, config, { violations, reportDir, baselinePresent = false }) {
  const report = await buildReport(client, config, violations, baselinePresent);
  mkdirSync(reportDir, { recursive: true });
  const jsonPath = join(reportDir, "evidence.json");
  const htmlPath = join(reportDir, "evidence.html");
  writeFileSync(jsonPath, JSON.stringify(report, null, 2) + "\n");
  writeFileSync(htmlPath, renderHtml(report));
  return { jsonPath, htmlPath };
}

async function buildReport(client, config, violations, baselinePresent) {
  const schemas = effectiveSchemas(config);
  const { rows: [{ server_version }] } = await client.query("select current_setting('server_version') as server_version");

  const tables = await queryTables(client, schemas, config.tenant.columns);
  const policies = await queryPolicies(client, schemas);
  const definers = await queryExposedDefiners(client, schemas, config.privileged_roles);

  const globalNames = new Set(
    config.exceptions.global_tables.filter((e) => !e.expired).map((e) => e.name)
  );
  const isGlobal = (t) => globalNames.has(t.table_fqn) || globalNames.has(t.table_fqn.split(".").pop());
  const tenantTables = tables.filter((t) => t.has_tenant_column && !isGlobal(t));
  const excludedGlobal = tables.filter((t) => t.has_tenant_column && isGlobal(t));

  const coverage = buildCoverage(tenantTables, policies);

  const i4Flagged = new Set(violations.filter((v) => v.invariant === "I4").map((v) => v.function));
  const exceptedDefiners = new Set(
    config.exceptions.definer_functions.filter((e) => e.used).map((e) => e.name)
  );
  const definerInventory = definers.map((d) => ({
    signature: d.signature,
    status: i4Flagged.has(d.signature)
      ? "flagged"
      : exceptedDefiners.has(d.proname) || exceptedDefiners.has(d.signature)
        ? "excepted"
        : "no-finding",
  }));

  // Invariant status enum: "pass" | "fail" | "not-run".
  // STATE only runs when a committed baseline exists — without one it must
  // report not-run, never a hollow pass.
  const invariants = INVARIANTS.map(({ id, title }) => {
    if (id === "STATE" && !baselinePresent) {
      return { id, title, status: "not-run", violations: [] };
    }
    const found = violations.filter((v) => v.invariant === id);
    return { id, title, status: found.length === 0 ? "pass" : "fail", violations: found.map((v) => v.message) };
  });

  return {
    format: REPORT_FORMAT,
    generated_at: new Date().toISOString(),
    tool_version: PKG.version,
    commit_sha: commitSha(),
    config_hash: configHash(config),
    postgres_server_version: server_version,
    verdict: violations.length === 0 ? "pass" : "block",
    scope: {
      schemas_scanned: schemas,
      tenant_columns: config.tenant.columns,
      tenant_scope_functions: config.tenant.scope_functions,
      identity_anchors: config.identity_anchors,
      privileged_roles: config.privileged_roles,
    },
    inventory: {
      tenant_tables: tenantTables.map(({ table_fqn, rls_enabled, rls_forced }) => ({ table_fqn, rls_enabled, rls_forced })),
      tables_declared_global: excludedGlobal.map((t) => t.table_fqn),
      policies_total: policies.length,
      coverage,
    },
    invariants,
    definer_inventory: definerInventory,
    exceptions: {
      in_effect: usedExceptions(config),
      stale: unusedExceptions(config),
    },
    proof_boundary: PROOF_BOUNDARY,
  };
}

function commitSha() {
  if (process.env.GITHUB_SHA) return process.env.GITHUB_SHA;
  const r = spawnSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" });
  return r.status === 0 ? r.stdout.trim() : null;
}

/* --------------------------- catalog inventory --------------------------- */
/* Inventory only — every verdict in the report comes from the engine's
 * violations, never from these queries. */

async function queryTables(client, schemas, tenantColumns) {
  const { rows } = await client.query({
    text: `
      select n.nspname || '.' || c.relname as table_fqn,
             c.relrowsecurity as rls_enabled,
             c.relforcerowsecurity as rls_forced,
             exists (
               select 1 from pg_attribute a
                where a.attrelid = c.oid and a.attname = any($2)
                  and a.attnum > 0 and not a.attisdropped
             ) as has_tenant_column
      from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = any($1) and c.relkind = 'r' and c.relpersistence = 'p'
      order by table_fqn;
    `,
    values: [schemas, tenantColumns],
  });
  return rows;
}

async function queryPolicies(client, schemas) {
  const { rows } = await client.query({
    text: `
      select n.nspname || '.' || c.relname as table_fqn,
             p.polname,
             p.polpermissive as permissive,
             p.polcmd
      from pg_policy p
      join pg_class c on c.oid = p.polrelid
      join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = any($1)
      order by table_fqn, p.polname;
    `,
    values: [schemas],
  });
  return rows;
}

async function queryExposedDefiners(client, schemas, privilegedRoles) {
  const { rows } = await client.query({
    text: `
      select n.nspname || '.' || p.proname || '(' ||
               pg_get_function_identity_arguments(p.oid) || ')' as signature,
             p.proname
      from pg_proc p
      join pg_namespace n on n.oid = p.pronamespace
      where n.nspname = any($1)
        and p.prokind = 'f'
        and p.prosecdef
        and p.prorettype not in ('pg_catalog.trigger'::regtype, 'pg_catalog.event_trigger'::regtype)
        and exists (
          select 1
          from aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
          where a.privilege_type = 'EXECUTE'
            and a.grantee <> p.proowner
            and (a.grantee = 0 or exists (
              select 1 from pg_roles r where r.oid = a.grantee and r.rolname <> all($2::name[])
            ))
        )
      order by signature;
    `,
    values: [schemas, privilegedRoles],
  });
  return rows;
}

const OPS = { SELECT: ["r"], INSERT: ["a"], UPDATE: ["w"], DELETE: ["d"] };

function buildCoverage(tenantTables, policies) {
  return tenantTables.map((t) => {
    const mine = policies.filter((p) => p.table_fqn === t.table_fqn);
    const row = { table_fqn: t.table_fqn };
    for (const [op, cmds] of Object.entries(OPS)) {
      row[op] = mine
        .filter((p) => cmds.includes(p.polcmd) || p.polcmd === "*")
        .map((p) => p.polname + (p.permissive ? "" : " (restrictive)"));
    }
    return row;
  });
}

/* -------------------------------- HTML -------------------------------- */

function renderHtml(r) {
  const ok = r.verdict === "pass";
  const invRows = r.invariants
    .map((i) => {
      const label = i.status === "pass" ? "PASS" : i.status === "fail" ? "FAIL" : "NOT RUN";
      const cls = i.status === "pass" ? "ok" : i.status === "fail" ? "bad" : "muted";
      const findings =
        i.status === "not-run"
          ? '<span class="none">no committed baseline — comparison not run</span>'
          : i.violations.length
            ? `<ul>${i.violations.map((v) => `<li>${esc(v)}</li>`).join("")}</ul>`
            : "—";
      return `
    <tr>
      <td><code>${esc(i.id)}</code></td>
      <td>${esc(i.title)}</td>
      <td class="${cls}">${label}</td>
      <td>${findings}</td>
    </tr>`;
    })
    .join("");

  const covRows = r.inventory.coverage
    .map(
      (c) => `
    <tr>
      <td><code>${esc(c.table_fqn)}</code></td>
      ${["SELECT", "INSERT", "UPDATE", "DELETE"]
        .map((op) => `<td>${c[op].length ? c[op].map(esc).join("<br>") : '<span class="none">none</span>'}</td>`)
        .join("")}
    </tr>`
    )
    .join("");

  const defRows = r.definer_inventory.length
    ? r.definer_inventory
        .map(
          (d) => `
    <tr>
      <td><code>${esc(d.signature)}</code></td>
      <td class="${d.status === "flagged" ? "bad" : d.status === "excepted" ? "warn" : "ok"}">${esc(d.status)}</td>
    </tr>`
        )
        .join("")
    : `<tr><td colspan="2">No exposed SECURITY DEFINER function in scope.</td></tr>`;

  const excRows = r.exceptions.in_effect.length
    ? r.exceptions.in_effect
        .map((e) => `<tr><td>${esc(e.kind)}</td><td><code>${esc(e.name)}</code></td><td>${esc(e.reason)}</td></tr>`)
        .join("")
    : `<tr><td colspan="3">None.</td></tr>`;

  return `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Tenant isolation evidence — RLS Guard</title>
<style>
  :root { --ink:#1c1c1c; --muted:#6b6b6b; --line:#e4e2de; --paper:#ffffff; --wash:#faf9f7;
          --ok:#176b3a; --bad:#a4232f; --warn:#8a6207; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--wash); color:var(--ink);
         font:15px/1.55 -apple-system, "Segoe UI", Roboto, "Helvetica Neue", sans-serif; }
  main { max-width: 920px; margin: 0 auto; padding: 40px 24px 64px; }
  header { border-bottom: 1px solid var(--line); padding-bottom: 20px; margin-bottom: 28px; }
  h1 { font-size: 22px; font-weight: 650; margin: 0 0 4px; letter-spacing: -0.01em; }
  h2 { font-size: 16px; font-weight: 650; margin: 36px 0 10px; }
  .sub { color: var(--muted); font-size: 13.5px; }
  .verdict { display:inline-block; margin-top:14px; padding: 6px 14px; border-radius: 4px;
             font-weight: 700; letter-spacing: .04em; font-size: 14px;
             color:#fff; background: ${ok ? "var(--ok)" : "var(--bad)"}; }
  table { width:100%; border-collapse: collapse; background: var(--paper);
          border: 1px solid var(--line); font-size: 13.5px; }
  th, td { text-align:left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { background: var(--wash); font-weight: 600; }
  tr:last-child td { border-bottom: none; }
  code { font: 12.5px/1.4 ui-monospace, "SF Mono", Menlo, Consolas, monospace; }
  ul { margin: 0; padding-left: 18px; }
  .ok { color: var(--ok); font-weight: 650; }
  .bad { color: var(--bad); font-weight: 650; }
  .warn { color: var(--warn); font-weight: 650; }
  .muted { color: var(--muted); font-weight: 650; }
  .none { color: var(--muted); font-style: italic; }
  .meta { display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px 24px;
          background: var(--paper); border: 1px solid var(--line); padding: 14px 16px; }
  .meta div b { display:block; font-size: 11.5px; text-transform: uppercase; letter-spacing:.06em;
                color: var(--muted); font-weight: 600; margin-bottom: 1px; }
  .boundary { background: var(--paper); border: 1px solid var(--line); padding: 16px 18px; }
  .boundary h3 { font-size: 13.5px; margin: 0 0 6px; }
  .boundary ul { margin-bottom: 14px; }
  .boundary li { margin: 3px 0; }
  footer { margin-top: 40px; color: var(--muted); font-size: 12.5px; }
  @media print { body { background:#fff; } main { padding: 0; } }
</style>
<main>
  <header>
    <h1>Tenant isolation evidence</h1>
    <div class="sub">Generated by RLS Guard v${esc(r.tool_version)} — ${esc(r.generated_at)}</div>
    <div class="verdict">${ok ? "PASS" : "BLOCK"}</div>
  </header>

  <h2>Attestation</h2>
  <div class="meta">
    <div><b>Commit</b>${r.commit_sha ? `<code>${esc(r.commit_sha)}</code>` : '<span class="none">Not available</span>'}</div>
    <div><b>Config hash</b><code>${esc(r.config_hash)}</code></div>
    <div><b>Postgres</b>${esc(r.postgres_server_version)}</div>
    <div><b>Report format</b><code>${esc(r.format)}</code></div>
  </div>
  <p class="sub">${
    r.commit_sha
      ? `This report attests that, at the commit above and under the configuration hashed above,
  the schema produced by a full replay of the migrations ${ok ? "satisfies" : "VIOLATES"} the invariants below.
  Anyone can reproduce this verdict from the same commit and configuration.`
      : `This report attests that, under the configuration hashed above and RLS Guard v${esc(r.tool_version)},
  the schema produced by a full replay of the migrations ${ok ? "satisfies" : "VIOLATES"} the invariants below.
  No commit SHA was available at generation time — reproduce from the same source tree and configuration.`
  }</p>

  <h2>Scope</h2>
  <div class="meta">
    <div><b>Schemas scanned</b>${r.scope.schemas_scanned.map(esc).join(", ")}</div>
    <div><b>Tenant columns</b>${r.scope.tenant_columns.map(esc).join(", ")}</div>
    <div><b>Scope functions</b>${r.scope.tenant_scope_functions.map(esc).join(", ")}</div>
    <div><b>Privileged roles</b>${r.scope.privileged_roles.map(esc).join(", ")}</div>
  </div>

  <h2>Invariants</h2>
  <table>
    <thead><tr><th></th><th>Invariant</th><th>Status</th><th>Findings</th></tr></thead>
    <tbody>${invRows}</tbody>
  </table>

  <h2>Coverage — ${r.inventory.tenant_tables.length} tenant-scoped table(s), ${r.inventory.policies_total} polic(ies)</h2>
  <table>
    <thead><tr><th>Table</th><th>SELECT</th><th>INSERT</th><th>UPDATE</th><th>DELETE</th></tr></thead>
    <tbody>${covRows}</tbody>
  </table>
  ${r.inventory.tables_declared_global.length ? `<p class="sub">Declared global (documented exceptions, out of tenant scope): ${r.inventory.tables_declared_global.map((t) => `<code>${esc(t)}</code>`).join(", ")}</p>` : ""}

  <h2>SECURITY DEFINER inventory (exposed to non-privileged roles)</h2>
  <table>
    <thead><tr><th>Function</th><th>Status</th></tr></thead>
    <tbody>${defRows}</tbody>
  </table>

  <h2>Exceptions in effect — excluded from this attestation</h2>
  <table>
    <thead><tr><th>Kind</th><th>Name</th><th>Reason</th></tr></thead>
    <tbody>${excRows}</tbody>
  </table>

  <h2>Proof boundary</h2>
  <div class="boundary">
    <h3>This report proves</h3>
    <ul>${r.proof_boundary.proves.map((p) => `<li>${esc(p)}</li>`).join("")}</ul>
    <h3>This report does NOT prove</h3>
    <ul>${r.proof_boundary.does_not_prove.map((p) => `<li>${esc(p)}</li>`).join("")}</ul>
  </div>

  <footer>RLS Guard — security CI for multi-tenant Postgres, initially proven on Supabase/Postgres.
  The verdict above is produced by the invariant engine; this document is a rendering of its output.</footer>
</main>
</html>`;
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
