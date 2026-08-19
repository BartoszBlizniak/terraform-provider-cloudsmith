# Changelog

## Unreleased

### Added

* **provider:** Native OIDC authentication. Enable it with an `oidc` block or `CLOUDSMITH_USE_OIDC=true`. The provider mints GitHub Actions tokens (GET) and Azure DevOps tokens (POST to `SYSTEM_OIDCREQUESTURI`), and reads HCP Terraform, CircleCI, Bitbucket, `CLOUDSMITH_OIDC_TOKEN`, and `CLOUDSMITH_OIDC_TOKEN_FILE`. It exchanges that token for a Cloudsmith JWT, refreshes it before expiry, and retries once on 401. No `local-exec` or `external` data source. ([#128](https://github.com/cloudsmith-io/terraform-provider-cloudsmith/issues/128))
* **provider:** The `User-Agent` now identifies the provider release, the auth mode, and - on the OIDC token exchange - which CI system the identity token was discovered from (for example `terraform-provider-cloudsmith/1.4.0 (linux amd64) Terraform/1.9.0 auth:oidc/github`). Detector ids match `cloudsmith-cli`.
