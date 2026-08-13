/**
 * Canonical introspection of RLS state. Pure pg_catalog — schema-agnostic.
 *
 * Returns ONE object with deterministic, sorted content:
 *   policies  : every policy on the included schemas (qual + with_check via pg_get_expr)
 *   functions : every function in the included schemas (signature, security, volatility, config, body MD5)
 *   tables    : RLS state of every included table (rls_enabled, rls_forced, has_tenant_column)
 *
 * Function bodies are never stored in snapshots — only their MD5, so a
 * committed baseline leaks no implementation detail while still detecting
 * any body change.
 *
 * $1 = text[] of schemas to scan (include minus exclude), $2 = text[] of
 * tenant column names.
 */
import { effectiveSchemas } from "./config.mjs";

export const INTROSPECT_SQL = `
with pol as (
  select
    n.nspname || '.' || c.relname                                   as table_fqn,
    p.polname                                                        as name,
    case p.polpermissive when true then 'permissive' else 'restrictive' end as permissive,
    case p.polcmd
      when 'r' then 'SELECT'
      when 'a' then 'INSERT'
      when 'w' then 'UPDATE'
      when 'd' then 'DELETE'
      when '*' then 'ALL'
    end                                                              as cmd,
    coalesce((
      select string_agg(rolname, ',' order by rolname)
        from pg_roles
       where oid = any(p.polroles)
    ), 'public')                                                     as roles,
    coalesce(pg_get_expr(p.polqual,     p.polrelid), '')             as using_expr,
    coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '')            as with_check_expr
  from pg_policy p
  join pg_class c     on c.oid = p.polrelid
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = any($1)
),
fn as (
  select
    n.nspname || '.' || p.proname || '(' ||
      pg_get_function_identity_arguments(p.oid) || ')'              as signature,
    case p.prosecdef when true then 'definer' else 'invoker' end    as security,
    p.provolatile                                                    as volatility,
    coalesce(
      (select string_agg(cfg, ',' order by cfg) from unnest(p.proconfig) cfg),
      ''
    )                                                                as config,
    md5(pg_get_functiondef(p.oid))                                   as body_md5
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = any($1)
    and p.prokind = 'f'
),
tbl as (
  select
    n.nspname || '.' || c.relname                                   as table_fqn,
    c.relrowsecurity                                                 as rls_enabled,
    c.relforcerowsecurity                                            as rls_forced,
    exists (
      select 1 from pg_attribute a
       where a.attrelid = c.oid
         and a.attname  = any($2)
         and a.attnum > 0
         and not a.attisdropped
    )                                                                as has_tenant_column
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = any($1)
    and c.relkind = 'r'
    and c.relpersistence = 'p'
)
select jsonb_build_object(
  'policies',  coalesce((select jsonb_agg(to_jsonb(pol) order by table_fqn, name) from pol),  '[]'::jsonb),
  'functions', coalesce((select jsonb_agg(to_jsonb(fn)  order by signature)        from fn),   '[]'::jsonb),
  'tables',    coalesce((select jsonb_agg(to_jsonb(tbl) order by table_fqn)        from tbl),  '[]'::jsonb)
) as snapshot;
`;

export async function introspect(client, config) {
  const { rows } = await client.query({
    text: INTROSPECT_SQL,
    values: [effectiveSchemas(config), config.tenant.columns],
  });
  return rows[0].snapshot;
}
