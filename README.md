# Kagi Secrets — GitHub Action

Fetch your [Kagi](https://kagi.pw) secrets into a GitHub Actions workflow using the workflow's own
identity. There is no token to store, rotate, or leak: GitHub mints a short-lived OIDC id-token for
the run, Kagi verifies it against a binding you configured, and returns exactly the secrets that
binding grants.

Nothing is downloaded and nothing is installed. The action is plain JavaScript with **zero
dependencies** — what you see in `src/` is exactly what runs on your runner and handles your
secrets.

## Quick start

```yaml
permissions:
  id-token: write   # required — this is what lets GitHub mint the id-token
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: senseylabs/kagi-action@v1
        with:
          binding-id: 3fa2c1e0-0000-4000-8000-000000000000

      - run: ./deploy.sh   # $DATABASE_URL, $STRIPE_KEY, ... are now in the environment
```

`binding-id` is the binding's routing id, shown in the Kagi portal under
**Integrations → CI Federation**. It is unguessable but it is **not** a credential: it only says
which binding to evaluate. Every grant is derived from the claims in the id-token, so a leaked
routing id on its own opens nothing.

Without `permissions: id-token: write` the runner exposes no token service at all and the step
fails immediately with that instruction. The action cannot grant the permission for you.

## How it works

1. GitHub mints an OIDC id-token for this workflow run at the requested audience
   (default `api.kagi.pw`).
2. The action POSTs it to `POST /kagi/auth/ci/fetch` on the Kagi API along with the routing id.
3. Kagi verifies the signature, audience, and replay guard, matches the token's claims (repository,
   ref, environment, workflow file) against the binding's predicates, and returns the granted
   secrets — and **no access token**. There is deliberately no bearer credential left in the runner
   for a later compromised step to steal.
4. The action masks every returned value, then exports it.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `binding-id` | yes | — | The binding's routing id (a UUID) from the Kagi portal. |
| `api-url` | no | `https://api.kagi.pw` | Kagi API root. Change only for a self-hosted (ENTERPRISE) deployment. |
| `audience` | no | `api.kagi.pw` | OIDC audience to mint the token at. Must match the binding's `expectedAudience` exactly when it pins one. |
| `export-env` | no | `true` | Write every secret into `$GITHUB_ENV` for later steps in the same job. |
| `env-file-path` | no | — | Also write a `.env` file at this path (e.g. `build/.env`), rendered and escaped by Kagi, written with mode `0600`. |
| `request-timeout-seconds` | no | `30` | Per-request timeout for the token mint and the fetch. |
| `mask` | no | `true` | **Deprecated and ignored.** See [Masking](#masking). |

Setting `export-env: false` with no `env-file-path` fails the step — the fetched secrets would go
nowhere, and a job that quietly runs without its secrets is exactly what this action exists to
prevent.

## Outputs

| Output | Description |
|---|---|
| `secret-count` | Number of distinct keys fetched. |
| `scope-count` | Number of (app, environment) scopes the binding granted. |
| `env-file` | Absolute path of the written `.env`, or empty. |

Secret **values** are never exposed as outputs. Step outputs are written to a file the whole job can
read and are easy to echo by accident; `$GITHUB_ENV` (or the 0600 `.env`) is the right channel.

## Writing a .env file

```yaml
      - uses: senseylabs/kagi-action@v1
        with:
          binding-id: 3fa2c1e0-0000-4000-8000-000000000000
          export-env: false
          env-file-path: apps/api/.env
```

The document is rendered **server-side** by Kagi, not by this action. Escaping a secret for a
shell-sourced file is exactly the thing that ends up subtly different in every reimplementation, and
a value containing a quote, a dollar sign, a backtick, or a newline is one divergence away from
breaking out of its assignment. If Kagi returns no rendered document, the step fails rather than
falling back to a hand-rolled one.

## Masking

Every returned value is registered with the runner's log scrubber (`::add-mask::`) **before** it is
written anywhere — `$GITHUB_ENV`, the `.env` file, or a log line. The runner cannot retroactively
redact a line it has already printed, so masking after a write would be the same as not masking.
That ordering is enforced structurally in the code (the delivery functions accept nothing that has
not been through the masker) and asserted by tests, not left to convention.

Three forms of each value are masked:

- the value itself;
- each substantial line of a multi-line value (a PEM key, a JSON blob), because the scrubber matches
  line by line;
- the dotenv-escaped form, which is what would appear if a later step printed the `.env` file.

The `mask` input exists only so older workflows do not break. It is ignored: Kagi has no per-secret
sensitivity flag today, so there is nothing that could safely be left unmasked. Setting it to
`false` logs a warning and changes nothing.

Masking is a guard against accidental disclosure in logs, not a security boundary. Anything running
in the job can still read the values — that is the point of fetching them.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `No OIDC token service is available to this job` | The job is missing `permissions: id-token: write`. Note that setting `permissions:` anywhere in a workflow drops every permission you did not list. |
| `Kagi denied the fetch (HTTP 401)` | Every pre-match failure collapses into one opaque 401, because this endpoint is unauthenticated and must not become an oracle for "is repository X registered with Kagi". Check the routing id, the audience, that the binding is enabled and `VERIFIED`, and that this run actually satisfies the binding's predicates (a `pull_request` run, or a ref the binding does not cover, is a denial). The precise reason is in your organization's Kagi logs. |
| `HTTP 403` | The identity was verified, but the organization's plan does not include the secrets library or the subscription is locked. This is a billing problem, not a workflow problem. |
| `Refusing to export the secret key '...'` | A key is not a valid environment variable name. Writing it would corrupt `$GITHUB_ENV` for the rest of the job. Rename it in Kagi, or use `env-file-path`. |
| `Secret key 'X' is granted by more than one scope` | Two granted scopes define the same key. The last one wins for the exported variable, both remain in the fetched scopes, and the collision is always warned about — never silently resolved. |

Transient failures (network errors, HTTP 429, 5xx) are retried up to three times. Each retry mints a
**fresh** id-token: the exchange spends the token's replay-guard id, so resending the same one would
be rejected as a replay.

## Versioning

| Reference | Meaning |
|---|---|
| `@v1` | Floating major tag. Moves to each new `v1.x.y` release. Recommended. |
| `@v1.2.0` | Exact release. Immutable. |
| `@<sha>` | Exact commit. Immutable, and what to use if your organization requires pinned actions. |

Breaking changes only ever ship in a new major tag, and the floating major tag is never moved onto a
prerelease.

## Development

```bash
npm test   # node --test, no install step — the action has no dependencies
```

`src/` is the shipped code: there is no build, no `dist/`, and no vendored `node_modules`. That is
deliberate for an action that handles secrets — a customer can read every line of what runs at the
tag they pinned, rather than a bundled artifact.

The action declares `runs.using: node24`, which needs runner v2.327.0 or newer (all GitHub-hosted
runners; self-hosted runners may need updating). The test suite also runs on Node 20.

## License

MIT — see [LICENSE](LICENSE).
