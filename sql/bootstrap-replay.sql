-- Bootstrap for the ephemeral replay database (stock postgres image).
--
-- Recreates just enough of a Supabase-flavoured environment for migrations to
-- apply on a vanilla Postgres: auth/storage schemas, identity function stubs,
-- the three conventional roles, and shims for managed extensions. The stubs
-- return inert values — the replay checks CATALOG state (policies, RLS,
-- function definitions), never query results, so inert stubs are sufficient.
--
-- Non-Supabase stacks: replace or extend this file; the engine itself makes
-- no assumption about what is in here.

create extension if not exists pgcrypto;
create extension if not exists "uuid-ossp";
create extension if not exists pg_trgm;

create schema if not exists auth;
create schema if not exists storage;
create schema if not exists extensions;
create schema if not exists vault;

-- pg_net is a managed extension, absent from stock Postgres. Migrations only
-- reference net.* inside function bodies (created with
-- check_function_bodies=false, so not validated) — a schema + shims suffice.
create schema if not exists net;
create or replace function net.http_post(url text, body jsonb default '{}', params jsonb default '{}', headers jsonb default '{}', timeout_milliseconds int default 5000) returns bigint language sql as $$ select 1::bigint $$;
create or replace function net.http_get(url text, params jsonb default '{}', headers jsonb default '{}', timeout_milliseconds int default 5000) returns bigint language sql as $$ select 1::bigint $$;

create table if not exists auth.users (
  id uuid primary key default gen_random_uuid(),
  email text,
  raw_app_meta_data jsonb default '{}'::jsonb,
  raw_user_meta_data jsonb default '{}'::jsonb,
  created_at timestamptz default now()
);

create or replace function auth.uid()  returns uuid  language sql stable as $$ select null::uuid $$;
create or replace function auth.role() returns text  language sql stable as $$ select 'anon'::text $$;
create or replace function auth.jwt()  returns jsonb language sql stable as $$ select '{}'::jsonb $$;

do $$ begin
  create role anon;
exception when duplicate_object then null; end $$;
do $$ begin
  create role authenticated;
exception when duplicate_object then null; end $$;
do $$ begin
  create role service_role;
exception when duplicate_object then null; end $$;
