/**
 * `rls-guard drift` — live drift detection (optional, off by default).
 *
 * Diffs a REAL database (prod/staging) against the committed baseline. This
 * is the only command that needs a database credential; it must never run on
 * fork PRs and belongs in a scheduled or manually dispatched workflow with a
 * read-only role. Replay (`check`) needs none of this.
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { introspect } from "../introspect.mjs";
import { readSnapshot, diffSnapshots } from "../snapshot.mjs";

export async function drift(client, config, { snapshotPath, artifactDir }) {
  const baseline = readSnapshot(snapshotPath);
  if (!baseline) {
    console.error(`✗ No baseline at ${snapshotPath}. Run \`rls-guard init\` once and commit it.`);
    return 2;
  }

  const live = await introspect(client, config);
  const changes = diffSnapshots(baseline, live);

  const report = {
    generated_at: new Date().toISOString(),
    baseline_config_hash: baseline.config_hash ?? null,
    summary: {
      total_changes: changes.length,
      by_kind: changes.reduce((acc, d) => ({ ...acc, [d.kind]: (acc[d.kind] ?? 0) + 1 }), {}),
    },
    changes,
  };

  mkdirSync(artifactDir, { recursive: true });
  writeFileSync(resolve(artifactDir, "drift.json"), JSON.stringify(report, null, 2) + "\n");
  writeFileSync(resolve(artifactDir, "drift.md"), renderMarkdown(report));
  writeFileSync(resolve(artifactDir, "drift.html"), renderHtml(report));

  if (process.env.GITHUB_OUTPUT) {
    const { appendFileSync } = await import("node:fs");
    appendFileSync(
      process.env.GITHUB_OUTPUT,
      `drift_count=${changes.length}\nhas_drift=${changes.length > 0 ? "true" : "false"}\n`
    );
  }

  if (changes.length === 0) {
    console.log("✓ No RLS drift. Policies, functions, and table RLS state match the baseline.");
    return 0;
  }

  console.error(`✗ RLS drift detected (${changes.length} change${changes.length > 1 ? "s" : ""}):\n`);
  for (const d of changes) console.error("  " + d.line);
  console.error(`\nArtifacts written to ${artifactDir}/ (drift.json, drift.md, drift.html).`);
  console.error("If intentional, capture the change in a migration, then refresh the baseline via");
  console.error("`rls-guard snapshot` (human-gated: it re-runs the invariants first).");
  return 1;
}

/* ----------------------------- renderers ----------------------------- */

function renderMarkdown(report) {
  if (report.summary.total_changes === 0) {
    return `### ✅ RLS drift check — no drift\n\nLive database matches the committed baseline.\n`;
  }
  const counts = Object.entries(report.summary.by_kind)
    .map(([k, v]) => `**${k}** ×${v}`)
    .join(" · ");
  let md = `### ❌ RLS drift detected — ${report.summary.total_changes} change(s)\n\n${counts}\n\n`;
  const sections = groupBy(report.changes, (c) => c.kind);
  for (const [kind, items] of Object.entries(sections)) {
    md += `<details><summary><strong>${kind}</strong> (${items.length})</summary>\n\n`;
    for (const it of items) {
      if (it.change === "modified") {
        md += `- \`${it.key}\` — field \`${it.field}\` changed\n`;
        md += `  - **before:** \`${truncate(String(it.before ?? ""))}\`\n`;
        md += `  - **after:**  \`${truncate(String(it.after ?? ""))}\`\n`;
      } else {
        md += `- ${it.change === "added" ? "🟢 added in DB" : "🔴 missing from DB"}: \`${it.key}\`\n`;
      }
    }
    md += `\n</details>\n\n`;
  }
  return md;
}

function renderHtml(report) {
  const rows = report.changes
    .map(
      (c) => `
    <tr>
      <td>${esc(c.kind)}</td>
      <td>${esc(c.change)}</td>
      <td><code>${esc(c.key)}</code></td>
      <td>${esc(c.field ?? "")}</td>
      <td><pre>${esc(truncate(String(c.before ?? ""), 400))}</pre></td>
      <td><pre>${esc(truncate(String(c.after ?? ""), 400))}</pre></td>
    </tr>`
    )
    .join("");
  return `<!doctype html><meta charset="utf-8"><title>RLS drift report</title>
<style>
  body{font:14px/1.45 -apple-system,Segoe UI,Roboto,sans-serif;margin:24px;color:#1a1a1a;background:#fff}
  h1{margin:0 0 8px;font-weight:600}
  .meta{color:#666;margin-bottom:16px}
  table{border-collapse:collapse;width:100%}
  th,td{border:1px solid #e2e2e2;padding:6px 8px;vertical-align:top;text-align:left}
  th{background:#f7f7f5}
  pre{margin:0;white-space:pre-wrap;word-break:break-word;font:12px/1.35 ui-monospace,Menlo,monospace}
  .ok{color:#0a7c2f} .bad{color:#b00020}
</style>
<h1>RLS drift report</h1>
<div class="meta">Generated ${esc(report.generated_at)} — <strong class="${report.summary.total_changes ? "bad" : "ok"}">${report.summary.total_changes}</strong> change(s)</div>
<table><thead><tr><th>kind</th><th>change</th><th>key</th><th>field</th><th>before</th><th>after</th></tr></thead><tbody>${rows || `<tr><td colspan="6">No drift.</td></tr>`}</tbody></table>`;
}

function groupBy(list, fn) {
  return list.reduce((a, x) => (((a[fn(x)] ??= []).push(x)), a), {});
}
function truncate(s, n = 200) {
  return s.length > n ? s.slice(0, n) + "…" : s;
}
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
