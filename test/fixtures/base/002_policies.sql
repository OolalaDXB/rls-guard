-- Clean, fully scoped RLS posture — the PASS case.
alter table widgets enable row level security;
alter table gadgets enable row level security;

create policy widgets_tenant_select on widgets
  for select using (tenant_id = current_tenant_id());
create policy widgets_tenant_insert on widgets
  for insert with check (tenant_id = current_tenant_id());
create policy widgets_tenant_update on widgets
  for update using (tenant_id = current_tenant_id())
  with check (tenant_id = current_tenant_id());

create policy gadgets_tenant_all on gadgets
  for all using (tenant_id = current_tenant_id())
  with check (tenant_id = current_tenant_id());

-- UPDATE without WITH CHECK: Postgres applies USING to new rows too, and the
-- USING is tenant-bound — must PASS (I3 fallback path).
create policy gadgets_owner_update on gadgets
  for update using (tenant_id = current_tenant_id());

-- Privileged-role-only `true` policy: NOT a violation (unreachable by tenant
-- users) — proves the privileged_roles exemption.
create policy widgets_service_all on widgets
  for all to service_role using (true) with check (true);

-- Deny-all written in permissive form: grants nothing — must NOT flag (I3).
create policy widgets_deny_delete on widgets
  for delete using (false);

-- Global reference table published on purpose: not tenant-scoped — must NOT
-- flag (I2 applies to tenant tables only).
alter table app_settings enable row level security;
create policy app_settings_public_read on app_settings
  for select using (true);

-- SECURITY DEFINER trigger function without guard: not directly invocable —
-- must NOT flag (I4 targets the direct-invocation attack class).
create or replace function touch_widget_payload() returns trigger
language plpgsql security definer as $$
begin
  update widgets set payload = coalesce(new.payload, payload) where id = new.id;
  return new;
end
$$;

-- Guarded SECURITY DEFINER functions: caller-identity anchored — must pass I4.
create or replace function count_visible_widgets() returns bigint
language sql stable security definer set search_path = public as $$
  select count(*) from widgets where tenant_id = current_tenant_id()
$$;

create or replace function my_gadget_count() returns bigint
language sql stable security definer set search_path = public as $$
  select count(*) from gadgets
   where tenant_id = current_tenant_id() and auth.uid() is not null
$$;
