# Provenance

RLS Guard was generalized from PostgreSQL multi-tenant security tooling
built, hardened and battle-tested in continuous integration on an internal
production application.

During extraction, every platform- and project-specific convention (tenant
column names, privileged roles, schema lists, identity functions) was moved
into configuration; invariant I4 (unguarded SECURITY DEFINER detection) was
added based on a real vulnerability class observed in production. No code,
schema, fixture or identifier from the source project is present in this
repository: test fixtures and demo migrations are synthetic toy schemas.
