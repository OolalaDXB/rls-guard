#!/usr/bin/env node
/**
 * rls-guard — Security CI for multi-tenant Postgres.
 *
 *   rls-guard init      write rls-guard.yml (if absent) + capture the baseline
 *                       (refuses to bless a state that violates the invariants)
 *   rls-guard check     run the invariants against DATABASE_URL (replay gate)
 *                       --report-dir <dir> also writes the tenant isolation
 *                       evidence report (evidence.json + evidence.html)
 *   rls-guard snapshot  refresh the baseline (human-gated, same refusal rule)
 *   rls-guard drift     diff a live database against the committed baseline
 *
 * Flags: --config <path>  --url <postgres url>  --accept-violations
 *        --report-dir <dir> (check)  --artifact-dir <dir> (drift)
 * Env:   DATABASE_URL (fallback for --url), DRIFT_ARTIFACT_DIR
 *
 * Exit codes: 0 = pass, 1 = violation / drift, 2 = configuration error.
 */
import { existsSync, writeFileSync, readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { loadConfig, ConfigError, DEFAULT_CONFIG_PATH } from "./config.mjs";
import { captureBaseline } from "./commands/baseline.mjs";
import { check } from "./commands/check.mjs";
import { drift } from "./commands/drift.mjs";
import { printWarnings } from "./commands/output.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));

const args = process.argv.slice(2);
const command = args[0];
const flag = (name) => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] && !args[i + 1].startsWith("--") ? args[i + 1] : undefined;
};
const has = (name) => args.includes(name);

if (!command || has("--help") || command === "help") {
  console.log(readFileSync(fileURLToPath(import.meta.url), "utf8").split("*/")[0].replace(/^#!.*\n\/\*\*\n/, "").replace(/^ \* ?/gm, ""));
  process.exit(command ? 0 : 2);
}

const configPath = flag("--config") ?? DEFAULT_CONFIG_PATH;

let loaded;
try {
  if (command === "init" && !existsSync(configPath)) {
    writeFileSync(configPath, readFileSync(resolve(__dirname, "..", "rls-guard.yml.example"), "utf8"));
    console.log(`✓ Wrote ${configPath} — review it (tenant.columns, privileged_roles, schemas) before trusting the baseline.`);
  }
  loaded = loadConfig(configPath);
} catch (err) {
  if (err instanceof ConfigError) {
    console.error(`✗ Configuration error: ${err.message}`);
    process.exit(2);
  }
  throw err;
}
const { config, warnings } = loaded;
printWarnings(warnings);

const url = flag("--url") ?? process.env.DATABASE_URL;
if (!url) {
  console.error("✗ No database URL: set DATABASE_URL or pass --url.");
  process.exit(2);
}

const snapshotPath = resolve(process.cwd(), config.paths.snapshot);

// Live databases (drift) usually require TLS; ephemeral replay containers
// usually don't support it at all. Try TLS first for drift, fall back when
// the server declines — the URL's own sslmode still wins if present.
async function connect(preferSsl) {
  const make = (ssl) => new pg.Client({ connectionString: url, ssl });
  let c = make(preferSsl ? { rejectUnauthorized: false } : false);
  try {
    await c.connect();
    return c;
  } catch (err) {
    if (preferSsl && /does not support SSL/i.test(err.message)) {
      c = make(false);
      await c.connect();
      return c;
    }
    throw err;
  }
}

let client;
let code = 2;
try {
  client = await connect(command === "drift" && !/[?&]sslmode=/.test(url));
  switch (command) {
    case "init":
    case "snapshot": {
      const { written } = await captureBaseline(client, config, {
        snapshotPath,
        acceptViolations: has("--accept-violations"),
        label: command === "init" ? "init" : "snapshot refresh",
      });
      code = written ? 0 : 1;
      break;
    }
    case "check": {
      const reportDir = flag("--report-dir");
      code = await check(client, config, {
        snapshotPath,
        reportDir: reportDir ? resolve(process.cwd(), reportDir) : undefined,
      });
      break;
    }
    case "drift": {
      const artifactDir = resolve(
        process.cwd(),
        flag("--artifact-dir") ?? process.env.DRIFT_ARTIFACT_DIR ?? "drift-report"
      );
      code = await drift(client, config, { snapshotPath, artifactDir });
      break;
    }
    default:
      console.error(`✗ Unknown command "${command}". Run rls-guard --help.`);
      code = 2;
  }
} catch (err) {
  console.error(`✗ ${command} failed: ${err.message}`);
  code = 2;
} finally {
  await client?.end().catch(() => {});
}
process.exit(code);
