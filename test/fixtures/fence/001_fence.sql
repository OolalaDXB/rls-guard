-- Restrictive tenant fence (tenant.fence: restrictive). Toy schema, no business semantics.
-- Fenced tables keep permissive `true` policies on purpose: the restrictive fence ANDs with them.
do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'fence_owner') then create role fence_owner nologin nobypassrls; end if;
end $$;

create table tenants (id uuid primary key default gen_random_uuid(), label text);
create or replace function current_tenant_id() returns uuid language sql stable as $$
  select nullif(current_setting('app.tenant_id', true), '')::uuid $$;

create table notes (id serial primary key, tenant_id uuid not null default current_tenant_id(), body text);
alter table notes enable row level security;
create policy notes_fence on notes as restrictive for all to public
  using (tenant_id = (select current_tenant_id())) with check (tenant_id = (select current_tenant_id()));
create policy notes_rw on notes for all to authenticated using (true) with check (true);

create table cards (id serial primary key, tenant_id uuid not null default current_tenant_id(), body text);
alter table cards enable row level security;
create policy cards_fence on cards as restrictive for all to public
  using (tenant_id = current_tenant_id()) with check (tenant_id = current_tenant_id());
create policy cards_admin_write on cards for insert to authenticated with check (true);

-- A fence in name only: `is not null` binds nothing.
create table loose (id serial primary key, tenant_id uuid not null, body text);
alter table loose enable row level security;
create policy loose_fence on loose as restrictive for all to public
  using (tenant_id is not null) with check (tenant_id is not null);
create policy loose_rw on loose for all to authenticated using (true) with check (true);

-- RLS on, but no fence at all (only a scoped permissive policy).
create table unfenced (id serial primary key, tenant_id uuid not null, body text);
alter table unfenced enable row level security;
create policy unfenced_read on unfenced for select to authenticated using (tenant_id = current_tenant_id());

grant select, insert, update, delete on notes, cards, loose, unfenced to authenticated, fence_owner;

-- Definers run as fence_owner, who neither bypasses RLS nor owns the tables: the fence holds inside.
create function fenced_note_count() returns bigint language sql security definer as $$ select count(*) from public.notes $$;
alter function fenced_note_count() owner to fence_owner;

-- Same body, owned by the superuser: the fence does not apply to its owner.
create function superuser_note_count() returns bigint language sql security definer as $$ select count(*) from public.notes $$;

-- Owned by fence_owner, but moves the scope function to a tenant the caller names.
create function hop_note_count(p_tenant uuid) returns bigint language plpgsql security definer as $$
begin perform set_config('app.tenant_id', p_tenant::text, true); return (select count(*) from public.notes); end $$;
alter function hop_note_count(uuid) owner to fence_owner;

-- Owned by the table's owner without FORCE ROW LEVEL SECURITY: the owner skips RLS.
create table owned (id serial primary key, tenant_id uuid not null default current_tenant_id(), body text);
alter table owned enable row level security;
create policy owned_fence on owned as restrictive for all to public
  using (tenant_id = current_tenant_id()) with check (tenant_id = current_tenant_id());
alter table owned owner to fence_owner;
create function owner_owned_count() returns bigint language sql security definer as $$ select count(*) from public.owned $$;
alter function owner_owned_count() owner to fence_owner;

-- Dynamic SQL: the caller's string, executed as the owner — flagged whatever the tables.
create function run_sql(p_sql text) returns void language plpgsql security definer as $$
begin execute p_sql; end $$;
alter function run_sql(text) owner to fence_owner;

-- Not dynamic SQL from the caller: the argument is bound (USING) or quoted (%I / %L).
create function safe_dynamic(p_name text, p_val text) returns bigint language plpgsql security definer as $$
declare n bigint;
begin
  execute 'select count(*) from public.notes where body = $1' into n using p_name;
  execute format('select count(*) from public.notes where body = %L', p_val) into n;
  return n;
end $$;
alter function safe_dynamic(text, text) owner to fence_owner;
