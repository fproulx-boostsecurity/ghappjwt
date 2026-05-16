# ghappjwt

Small Python CLI for testing GitHub App installation token formats.

## Context

There are two different token shapes involved:

```text
GitHub App auth JWT          created locally by this CLI, used to call GitHub's API
Installation access token    returned by GitHub, may be classic opaque or stateless JWT-format
```

The changelog is about the returned installation access token format, not the local app-auth JWT.

GitHub's May 15, 2026 changelog introduced a temporary request override header for:

```text
POST /app/installations/:installation_id/access_tokens
```

Header behavior:

```text
X-GitHub-Stateless-S2S-Token: enabled   -> request stateless JWT-format token
X-GitHub-Stateless-S2S-Token: disabled  -> request classic opaque token
header absent or any other value         -> normal rollout behavior
```

Expected token shape from the changelog:

```text
stateless: ghs_ prefix, JWT-like, two dots after ghs_, roughly 520 chars
stateful:  ghs_ prefix, opaque, no dots, shorter
```

GitHub's recommended matcher for accepting both formats:

```regex
ghs_[A-Za-z0-9\._]{36,}
```

Application code should still treat installation tokens as opaque strings. The JWT shape is useful for format detection and compatibility testing, not for app-side trust decisions.

## CLI

`ghappjwt.py`:

1. Generates a short-lived GitHub App auth JWT with `RS256`.
2. Calls the installation-token endpoint with `X-GitHub-Stateless-S2S-Token: enabled`.
3. Calls the same endpoint with `X-GitHub-Stateless-S2S-Token: disabled`.
4. Prints redacted token metadata.
5. Decodes JWT header/payload only when the returned token is JWT-shaped.

It does not print or write full installation tokens.

## Install

```sh
python3 -m pip install -r requirements.txt
```

## Usage

Use flags:

```sh
python3 ghappjwt.py \
  --app-id 123456 \
  --installation-id 12345678 \
  --private-key /path/to/private-key.pem
```

Or use environment variables:

```sh
GITHUB_APP_ID=123456 \
GITHUB_INSTALLATION_ID=12345678 \
GITHUB_APP_PRIVATE_KEY=/path/to/private-key.pem \
python3 ghappjwt.py
```

Or copy `.ghappjwt.example.json` to `.ghappjwt.json` and edit:

```sh
python3 ghappjwt.py --config .ghappjwt.json
```

Useful options:

```sh
--override enabled     # only force stateless format
--override disabled    # only force classic opaque format
--override both        # default
--override absent      # no override header
--api-version 2026-03-10
--output capture-output.json
```

## GitHub Actions

The workflow at `.github/workflows/capture-token-format.yml` runs the same capture in GitHub Actions.

Triggers:

```text
workflow_dispatch  on demand, defaults to override=enabled
schedule           every 15 minutes
issues.opened      comments the sanitized result on the opened issue
```

Required repository secrets:

```text
GHAPPJWT_APP_ID           GitHub App ID
GHAPPJWT_INSTALLATION_ID  GitHub App installation ID
GHAPPJWT_PRIVATE_KEY      GitHub App private key PEM contents
```

Set them with the GitHub CLI:

```sh
gh secret set GHAPPJWT_APP_ID --body "123456"
gh secret set GHAPPJWT_INSTALLATION_ID --body "12345678"
gh secret set GHAPPJWT_PRIVATE_KEY < /path/to/private-key.pem
```

Manual runs can be started from the Actions tab. The workflow has an `override` input:

```text
enabled   force the stateless format path
disabled  force the classic opaque path
both      test enabled and disabled
absent    omit the override header
```

For on-demand hunting of the new token format, use `workflow_dispatch` with `override=enabled`. Optionally pass `comment_issue_number` to post the sanitized report to an existing issue.

## Local App Auth JWT Shape

The app-auth JWT generated locally by the CLI has this shape. This is the request credential used to authenticate to GitHub as the App:

```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT"
  },
  "payload": {
    "iat": "<now - 60 seconds>",
    "exp": "<now + 9 minutes>",
    "iss": "<GitHub App ID>"
  }
}
```

## Observation From 2026-05-16

Using a newly created test GitHub App and installation, both override requests returned HTTP `201`.

Observed result:

```text
enabled:  ghs_ token, length 40, no dots, not JWT-shaped
disabled: ghs_ token, length 40, no dots, not JWT-shaped
```

So, for this app at that time, the `enabled` override did not produce the stateless JWT-format installation access token described in the changelog. The locally generated app-auth JWT was still a normal JWT; the unexpected part was the response token format. The CLI remains useful for rerunning the check as the rollout changes.
