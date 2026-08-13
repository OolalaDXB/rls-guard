-- Toy multi-tenant schema — deliberately free of any business semantics.
create table tenants (
  id    uuid primary key default gen_random_uuid(),
  label text
);

create table widgets (
  id        uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  owner_id  uuid,
  payload   text
);

create table gadgets (
  id        uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id),
  payload   text
);

-- Global reference table: no tenant column, intentionally outside tenant scope.
create table app_settings (
  key   text primary key,
  value text
);

-- Toy tenant-scope function (stands in for a real identity-validating one).
create or replace function current_tenant_id() returns uuid
language sql stable as $$
  select nullif(current_setting('app.tenant_id', true), '')::uuid
$$;
