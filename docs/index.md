# Cloudsmith Provider

This provider allows Cloudsmith users to automate the provisioning of resources using Terraform. Users can create and manage repositories, along with entitlement tokens to grant access to repository contents.

See [docs.cloudsmith.com](https://docs.cloudsmith.com/) for full documentation (including an API reference).

## Example Usage

```hcl
provider "cloudsmith" {
    api_key = "my-api-key"
}

data "cloudsmith_namespace" "my_namespace" {
    slug = "my-namespace"
}

resource "cloudsmith_repository" "my_repository" {
    description = "A certifiably-awesome private package repository"
    name        = "My Repository"
    namespace   = "${data.cloudsmith_namespace.my_namespace.slug_perm}"
    slug        = "my-repository"
}

resource "cloudsmith_entitlement" "my_entitlement" {
    name       = "Test Entitlement"
    namespace  = "${cloudsmith_repository.test.namespace}"
    repository = "${cloudsmith_repository.test.slug_perm}"
}
```

## Authenticate with OIDC

Use an `oidc` block, or set `CLOUDSMITH_USE_OIDC=true`. Do not set `api_key` in HCL. The identity token never lands in Terraform state.

This is provider login. It is not the [`cloudsmith_oidc`](resources/oidc.md) resource. That resource configures which identity providers Cloudsmith trusts. You still create that trust (or equivalent settings in the Cloudsmith UI) before Terraform can exchange a token.

An `oidc` block (or `CLOUDSMITH_USE_OIDC`) ignores leftover `CLOUDSMITH_API_KEY`. An HCL `api_key` argument still conflicts with `oidc`. An empty `provider "cloudsmith" {}` block does not enable OIDC unless `CLOUDSMITH_USE_OIDC` is true.

The provider takes the first identity token it can get, in this order:

1. `CLOUDSMITH_OIDC_TOKEN`
2. the file at `CLOUDSMITH_OIDC_TOKEN_FILE`
3. `TFC_WORKLOAD_IDENTITY_TOKEN_CLOUDSMITH`
4. `TFC_WORKLOAD_IDENTITY_TOKEN`
5. A CI identity-token request:
   - GitHub Actions: GET `ACTIONS_ID_TOKEN_REQUEST_URL` with `ACTIONS_ID_TOKEN_REQUEST_TOKEN`. Audience defaults to `cloudsmith` (`CLOUDSMITH_OIDC_AUDIENCE`).
   - Azure DevOps: POST `SYSTEM_OIDCREQUESTURI` with `SYSTEM_ACCESSTOKEN`. This is not a GitHub request. The JWT `aud` is `api://AzureADTokenExchange`.
   - GitHub-shaped generic pair: GET `CLOUDSMITH_OIDC_REQUEST_URL` with `CLOUDSMITH_OIDC_REQUEST_TOKEN` and the same audience default. Do not point this pair at Azure DevOps unless the URL is an Azure DevOps `/oidctoken` endpoint (then the provider POSTs).
6. `CIRCLE_OIDC_TOKEN_V2`, then `CIRCLE_OIDC_TOKEN`
7. `BITBUCKET_STEP_OIDC_TOKEN`

Note that `CLOUDSMITH_OIDC_TOKEN` wins over CI auto-discovery here, so it can be used to override a detected token. `cloudsmith-cli` treats it as a last-resort fallback instead, so the same environment can resolve a different token under the CLI than under the provider.

It POSTs that token to `https://api.cloudsmith.io/openid/{organization}/` and uses the returned Cloudsmith JWT as `X-Api-Key`. The provider refreshes that JWT a minute before its `exp` claim, or every 15 minutes if it carries no readable expiry. A 401 retries the exchange once.

The identity token `aud` must match the Cloudsmith OIDC claims. That is `cloudsmith` for GitHub Actions and HCP Terraform in the examples below. Azure DevOps, CircleCI, and Bitbucket use platform audiences, not `cloudsmith`.

You can omit `organization` and `service_slug` when `CLOUDSMITH_ORG` and `CLOUDSMITH_SERVICE_SLUG` are set.

```hcl
provider "cloudsmith" {
    oidc {
        organization = "acme-org"
        service_slug = "tfc-prod"
    }
}
```

### HCP Terraform / Terraform Cloud

This is the path that replaces `local-exec` and `data.external` workarounds.

1. In Cloudsmith, create a service account and an OIDC provider for `https://app.terraform.io`. Require claims that match the workspace, at least `aud` and `terraform_organization_name`.
2. On the HCP Terraform workspace, set `TFC_WORKLOAD_IDENTITY_AUDIENCE` as an **environment** variable (not a Terraform variable) to the same `aud` value (for example `cloudsmith`). For a tagged audience, set `TFC_WORKLOAD_IDENTITY_AUDIENCE_CLOUDSMITH` instead. HCP Terraform then injects `TFC_WORKLOAD_IDENTITY_TOKEN` or `TFC_WORKLOAD_IDENTITY_TOKEN_CLOUDSMITH`.
3. Do not set `api_key` in HCL. You can leave a leftover `CLOUDSMITH_API_KEY` workspace variable. The `oidc` block ignores it. Delete that variable if you no longer want a static key in the workspace.
4. Configure the provider with the `oidc` block shown above, or set `CLOUDSMITH_USE_OIDC=true` with `CLOUDSMITH_ORG` and `CLOUDSMITH_SERVICE_SLUG`.

See [Manually generate workload identity tokens](https://developer.hashicorp.com/terraform/cloud-docs/workspaces/dynamic-provider-credentials/manual-generation) and [Cloudsmith OpenID Connect](https://docs.cloudsmith.com/authentication/openid-connect).

### GitHub Actions

Grant `id-token: write`. The provider mints the GitHub JWT itself (GET, JSON field `value`). Do not curl the token, and do not pass it through `local-exec`.

```yaml
permissions:
  id-token: write
  contents: read

jobs:
  terraform:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: terraform apply -auto-approve
        env:
          CLOUDSMITH_ORG: acme-org
          CLOUDSMITH_SERVICE_SLUG: gha-prod
```

```hcl
provider "cloudsmith" {
    oidc {
        organization = "acme-org"
        service_slug = "gha-prod"
    }
}
```

Cloudsmith OIDC settings use provider URL `https://token.actions.githubusercontent.com` and claims that restrict the repository. Override the minted audience with `CLOUDSMITH_OIDC_AUDIENCE` if it is not `cloudsmith`.

### Azure DevOps

`SYSTEM_OIDCREQUESTURI` is set on the agent. `SYSTEM_ACCESSTOKEN` is not unless you map it. The provider POSTs to that URI (JSON field `oidcToken`) and adds `api-version` when the URI does not already have one.

The JWT audience is always `api://AzureADTokenExchange`. Set that as the Cloudsmith `aud` claim. Do not expect `aud=cloudsmith`. Issuer is `https://vstoken.dev.azure.com/{organization-guid}`.

```yaml
steps:
  - script: terraform apply -auto-approve
    env:
      SYSTEM_ACCESSTOKEN: $(System.AccessToken)
      CLOUDSMITH_ORG: acme-org
      CLOUDSMITH_SERVICE_SLUG: ado-prod
```

To mint a service-connection token (`sc://...` subject) instead of the pipeline token (`p://...`), set `CLOUDSMITH_ADO_SERVICE_CONNECTION_ID`. That is the only variable consulted: ambient ones such as `AZURESUBSCRIPTION_SERVICE_CONNECTION_ID` (set automatically by `AzureCLI@2`) are ignored, so they cannot silently change the token subject.

```hcl
provider "cloudsmith" {
    oidc {
        organization = "acme-org"
        service_slug = "ado-prod"
    }
}
```

### GitLab CI

`id_tokens` must be on the **job** (or under `default:`). At YAML root it is ignored, and `CLOUDSMITH_OIDC_TOKEN` is never set.

```yaml
variables:
  CLOUDSMITH_ORG: acme-org
  CLOUDSMITH_SERVICE_SLUG: gitlab-prod

terraform:
  id_tokens:
    CLOUDSMITH_OIDC_TOKEN:
      aud: cloudsmith
  script:
    - terraform apply -auto-approve
```

```hcl
provider "cloudsmith" {
    oidc {}
}
```

Set `aud` to the same value as the Cloudsmith OIDC `aud` claim. Cloudsmith's GitLab guide often uses `https://api.cloudsmith.io/openid/<organization>/` rather than `cloudsmith`. Provider URL is `https://gitlab.com` (or your GitLab host).

### CircleCI

Cloud jobs inject `CIRCLE_OIDC_TOKEN_V2` and `CIRCLE_OIDC_TOKEN`. You do not need to export them as `CLOUDSMITH_OIDC_TOKEN`.

The default `aud` is the CircleCI organization UUID, not `cloudsmith`. Issuer is `https://oidc.circleci.com/org/<org_id>`. Configure Cloudsmith claims to match that token. `circleci run oidc get` can mint a custom audience, but it does not write back into `CIRCLE_OIDC_TOKEN*`; put a custom token in `CLOUDSMITH_OIDC_TOKEN` if you use that path.

```hcl
provider "cloudsmith" {
    oidc {
        organization = "acme-org"
        service_slug = "circle-prod"
    }
}
```

### Bitbucket Pipelines

Set `oidc: true` on the step. Without it, `BITBUCKET_STEP_OIDC_TOKEN` is unset.

```yaml
pipelines:
  default:
    - step:
        oidc: true
        script:
          - terraform apply -auto-approve
```

Default `aud` is the workspace ARI (`ari:cloud:bitbucket::workspace/{uuid}`), not `cloudsmith`. Issuer is `https://api.bitbucket.org/2.0/workspaces/{workspace}/pipelines-config/identity/oidc`. Configure Cloudsmith claims to match.

### Explicit token or token file

Set `CLOUDSMITH_OIDC_TOKEN`, or point `CLOUDSMITH_OIDC_TOKEN_FILE` at a JWT file (the same idea as `AWS_WEB_IDENTITY_TOKEN_FILE`). An empty file is an error; the provider does not fall through to other sources.

`CLOUDSMITH_OIDC_REQUEST_URL` / `CLOUDSMITH_OIDC_REQUEST_TOKEN` is a GitHub-shaped GET mint (audience query, JSON `value`). It is not an Azure DevOps POST unless the URL is an Azure DevOps `/oidctoken` endpoint.

## Argument Reference

* `api_key` - (Optional) The API key for authenticating with the Cloudsmith API. If you omit it and do not set `oidc` or `CLOUDSMITH_USE_OIDC`, the provider reads `CLOUDSMITH_API_KEY`. Conflicts with `oidc`.
* `api_host` - (Optional) The API host to connect to (used to connect to a non-production Cloudsmith instance, mostly useful for testing).
* `oidc` - (Optional) Authenticate with a Cloudsmith OIDC service account. Conflicts with `api_key`. The identity token is not an argument. Ignores leftover `CLOUDSMITH_API_KEY`. Equivalent env: `CLOUDSMITH_USE_OIDC=true`.
  * `organization` - Organization slug. Defaults to `CLOUDSMITH_ORG`.
  * `service_slug` - Service account slug. Defaults to `CLOUDSMITH_SERVICE_SLUG`.
