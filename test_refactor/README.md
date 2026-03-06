# Test Refactor Summary

## Scope
This document summarizes the acceptance-test refactor work completed to improve reliability and enable higher parallelism in CI.

## What Was Broken

### Flaky resource behavior and state drift
- `cloudsmith_repository_retention_rule`: update checks intermittently read stale values (for example `retention_count_limit` reported `100` when config expected `0`).
- `cloudsmith_repository_upstream` (for example Conda/Huggingface): `is_active` sometimes read as `false` immediately after create when tests expected `true`.
- `cloudsmith_saml_auth`: `saml_metadata_inline` intermittently read back as empty string during update checks.
- `cloudsmith_manage_team`: create path could fail from duplicate auto-membership behavior.
- `cloudsmith_oidc`: update polling only covered top-level fields and did not verify `mapping_claim`, `service_accounts`, or dynamic mappings had converged.
- `cloudsmith_list_org_members`: pagination reused the last page number instead of the current page number, which could duplicate the final page and skip earlier pages when more than one page existed.

### Name collisions and nondeterministic org-level tests
- OIDC tests reused fixed names and could fail with uniqueness errors (`name` must be unique).
- OIDC resource tests and OIDC data-source tests were generating the same computed names from identical base strings, causing parallel collisions.
- Multiple acceptance resources were using shared/static naming patterns in one org, increasing collision risk.

### Parallel execution instability
- At higher `go test -parallel` values, tests failed early with provider reattach startup timeouts (`timeout waiting on reattach config`).
- The test suite used shared provider instances (`Providers: testAccProviders`), which was not robust under concurrency.

### Over-strict data source assertion
- `TestAccOrganization_data` expected optional org profile fields (for example `location`) to always be non-empty.

## How It Was Fixed

### Provider/resource fixes
- Added post-update read polling for OIDC to wait for updated fields before state assertions.
- Expanded OIDC update polling to verify `mapping_claim`, `service_accounts`, and dynamic mappings, not just top-level fields.
- Added retention-rule update polling to ensure zero/non-zero transitions settle before read.
- Updated upstream create behavior to wait for expected default activation for non-Docker types.
- Replaced the SAML auth custom polling loop with the standard `waiter()` utility, using `defaultUpdateTimeout` and `defaultUpdateInterval` for consistent behavior with other resources.
- Stabilized SAML auth resource ID to use the organization slug (singleton per org) instead of a content hash that changed on every state update.
- Made manage-team create idempotent by using replace-members behavior.
- Rewrote organization-member pagination with clearer variable naming and a simpler page-iteration loop. Added `formatTimeOrEmpty()` helper to prevent nil-time panics in member flattening.

### Acceptance test hardening
- Added unique test naming helper (`testAccUniqueName`) and adopted it across ALL test files to eliminate name collisions at any parallelism level.
- Increased OIDC test-name uniqueness entropy (longer hash + random suffix) and separated OIDC data-source name bases from resource test name bases.
- Updated brittle attribute checks to compare service slugs via attribute pairing where needed.
- Replaced all acceptance test cases from shared `Providers` to `ProviderFactories` to create isolated provider instances.
- Added a dedicated check-time provider-config helper so destroy/existence checks no longer depend on shared `testAccProvider.Meta()`.
- Relaxed `TestAccOrganization_data` to assert only reliably populated attributes.

### CI workflow changes
- Acceptance workflow triggers on both `master` and `main` branches plus all pull requests.
- Concurrency group scoped per-ref with `cancel-in-progress: true` to avoid resource contention from duplicate runs.
- Test parallelism set to `-parallel=16` (validated safe level) with `-count=1` and `-timeout=45m`.

## Validation Evidence
- Targeted reruns for known flaky cases were repeated and passed.
- Resource acceptance matrix passed repeatedly at `-parallel=6`.
- Resource acceptance matrix passed repeatedly at `-parallel=8`.
- Full workflow-equivalent command passed at `-parallel=10`.
- Full workflow-equivalent command passed at `-parallel=12`.
- Full workflow-equivalent command passed repeatedly at `-parallel=16`.
- Full workflow-equivalent command passed at `-parallel=32`.
- Full workflow-equivalent command passed at `-parallel=48`.
- Full workflow-equivalent command passed repeatedly at `-parallel=64` (`-count=3`).
- Full workflow-equivalent command passed again at `-parallel=64` after the review-driven SAML, OIDC, and org-members fixes.
- Exact workflow-style command succeeded:
  - `TF_ACC=1 go test -v ./... -parallel=64 -count=3 -timeout=45m`

## Review-Driven Improvements (second pass)
- **SAML auth polling**: Replaced custom `waitForSAMLAuthState` loop (1s sleep, 30s deadline) with the standard `waiter()` utility used by all other resources. This ensures the initial replication-delay sleep and consistent 2-second polling intervals.
- **SAML auth ID stability**: Changed `generateSAMLAuthID` from a content-based SHA256 hash to using the organization slug directly. SAML auth is a singleton per org, so the ID should not change on every state update.
- **Unique naming across all tests**: Extended `testAccUniqueName()` adoption from just OIDC/retention to every test file (repository, entitlement, webhook, upstream, team, service, SAML group sync, policies, privileges, data sources). This eliminates the remaining name collision vectors.
- **Organization members pagination**: Rewrote `retrieveOrgMemeberListPages` as `retrieveAllOrgMembers` with clearer variable names (`page` vs `pageCurrentCount`) and a straightforward for-loop. Added `formatTimeOrEmpty()` to guard against zero-time panics in `flattenOrganizationMembers`.
- **CI parallelism**: Reduced from `-parallel=64` to `-parallel=16` for CI. While 64 passed locally, CI environments have different networking characteristics and API rate-limit exposure. 16 is the highest level with repeated validation and provides a safe margin.
- **CI workflow triggers**: Added `master` branch to push triggers (the repo default branch). Added `cancel-in-progress: true` to prevent duplicate acceptance runs from competing for the same org resources.

## Current Outcome
- Acceptance stability is significantly improved.
- Parallel execution is now validated at a conservative but practical level.
- All test resources use unique names, eliminating collision risk at any parallelism level.
- Branch is cleaned of generated test artifacts and temporary local scripts.
