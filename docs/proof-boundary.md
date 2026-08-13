# Proof boundary

This page is normative. The same text ships verbatim inside every evidence
report, and any marketing claim beyond it is wrong.

## What RLS Guard proves

At a given commit, under a given configuration (both hashed into the
report), on the schema **as your migrations build it**:

1. Every table carrying a configured tenant column has Row Level Security
   enabled.
2. No permissive policy whose predicate is literally `true` is reachable by
   non-privileged roles on a tenant-scoped table.
3. No permissive write policy on a tenant-scoped table is blind to the
   tenant — clauses are analyzed per command, and the new-row clauses
   (INSERT's WITH CHECK, UPDATE/ALL's WITH CHECK or USING fallback) must
   bind the tenant; a caller identity anchor alone is not accepted there.
4. No SECURITY DEFINER function that touches a tenant-scoped table and is
   executable by non-privileged roles lacks a detectable caller-identity
   guard.
5. When a committed baseline exists, the replayed RLS state
   (enabled/forced) matches it — and with live drift enabled, the live
   database matches the baseline in full (policies, functions, RLS state).

## What RLS Guard does NOT prove

1. That your **application sets the tenant context** correctly at runtime
   (headers, session variables, JWT claims). A perfect policy with a
   spoofable or absent context still leaks.
2. That a guard **present** in a SECURITY DEFINER function is semantically
   correct. Invariant I4 detects the *absence* of any guard — the
   real-world cross-tenant hole class — not the correctness of one.
3. Anything about code running as a **privileged role**: `service_role`
   bypasses RLS by design; those code paths need their own review.
4. The absence of leaks **outside the database**: logs, caches, exports,
   object storage, application endpoints.
5. That your **live production database** matches these migrations — unless
   you run live drift against it.
6. Behavior on real data. These are catalog-level invariants, not
   data-access tests, and not a penetration test.

## The honest sales line

> RLS Guard guarantees your policy layer never regresses. It replaces
> neither a review of your application code, nor a pentest.

See also [`limitations.md`](limitations.md) for the known false-positive /
false-negative classes of the detection heuristics themselves.
