-- Deliberate violations — the BLOCK case. One per invariant.

-- I1: tenant-scoped table with RLS left disabled.
create table leaky_notes (
  id        uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  note      text
);

-- I2: permissive `true` SELECT policy reachable by everyone.
create policy gadgets_public_read on gadgets for select using (true);

-- I3: tenant-blind write — keyed on a global helper, never tenant-scoped.
-- Permissive policies OR together: this single policy defeats the scoped ones.
create or replace function is_global_admin() returns boolean
language sql stable as $$ select true $$;

create policy widgets_admin_insert on widgets
  for insert with check (is_global_admin());

-- I3 (UPDATE tenant re-assignment): USING is properly tenant-scoped but the
-- WITH CHECK only anchors identity — UPDATE … SET tenant_id = '…' crosses
-- tenants. The clauses must be analyzed separately to catch this.
create policy widgets_sneaky_update on widgets
  for update using (tenant_id = current_tenant_id())
  with check (auth.uid() is not null);

-- I3 (INSERT identity-only): the new row can target any tenant.
create policy gadgets_identity_insert on gadgets
  for insert with check (auth.uid() is not null);

-- Side schema with a leaky tenant table: only flagged when its schema is
-- scanned — exercised by the schemas.include/exclude tests.
create schema side;
create table side.side_notes (
  id        uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  note      text
);

-- I4: SECURITY DEFINER touching a tenant table, executable by anyone, with no
-- caller-identity guard — the tenant is taken from a caller-supplied id.
create or replace function process_widget(p_widget uuid) returns void
language sql security definer as $$
  update widgets set payload = 'processed' where id = p_widget
$$;
