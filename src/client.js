/**
 * The Kagi CI secret-fetch client.
 *
 * One call, one round trip: POST /kagi/auth/ci/fetch presents the workflow's OIDC id-token and
 * returns the secrets directly. The endpoint mints no access token on purpose, so there is no
 * bearer credential left sitting in the runner for a later compromised step to steal. That also
 * means the presented id-token is SPENT by the time a response is written -- see the retry note in
 * main.js: a retry has to mint a fresh token, never resend this one.
 *
 * Shapes here are taken from the backend records, not from prose:
 *   request  KagiCiSecretFetchRequest  { provider, identity, token, format }
 *   response CustomResponse<KagiCiSecretFetchResponse>
 *            { success, message, data: { scopes: [...], dotenv }, pagination, error }
 *   scope    KagiCiSecretScopeResponse { appId, appPath, environmentSlug, secrets }
 */

import { ActionError } from './core.js';
import { describeCause } from './oidc.js';

/** Route on the Kagi API. Matches KagiCiExchangeController's @RequestMapping + @PostMapping. */
export const FETCH_PATH = '/kagi/auth/ci/fetch';

/** CiProvider enum value. GITHUB_ACTIONS is the only member today. */
export const PROVIDER = 'GITHUB_ACTIONS';

/** CiSecretFetchFormat enum value asked for when the caller wants a server-rendered .env. */
export const FORMAT_DOTENV = 'DOTENV';

const USER_AGENT = 'senseylabs/kagi-action';

const DENIED_HINT =
  'Kagi denied the fetch. The endpoint is unauthenticated, so it answers every pre-match failure ' +
  'with one opaque 401 rather than telling an anonymous caller which part was wrong. Check, in ' +
  'this order:\n' +
  '  - identity-public-id matches the binding shown in the Kagi portal\n' +
  "  - the binding's expected audience matches this step's `audience` input\n" +
  '  - the binding is enabled, its trust owner is active, and its verification status is VERIFIED\n' +
  "  - this workflow's repository, ref, environment and workflow file satisfy the binding's " +
  'predicates (a pull_request or a non-matching ref is a denial, not an error)\n' +
  'The precise reason is recorded in your organization\'s Kagi logs.';

/**
 * Performs one exchange attempt.
 *
 * Returns { scopes, dotenv } on success. Throws ActionError on every failure; errors that are worth
 * another attempt with a freshly minted token carry `transient = true`.
 */
export async function fetchSecrets({ apiUrl, identityPublicId, token, wantDotenv, timeoutMs }) {
  const url = `${trimTrailingSlash(apiUrl)}${FETCH_PATH}`;

  const body = {
    provider: PROVIDER,
    identity: identityPublicId,
    token,
  };
  // format is nullable on the request record and defaults to JSON; only send it when a rendered
  // .env is actually wanted, so the server pays nothing for rendering otherwise.
  if (wantDotenv) {
    body.format = FORMAT_DOTENV;
  }

  let response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
        'user-agent': USER_AGENT,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (cause) {
    const error = new ActionError(`Could not reach Kagi at ${url}: ${describeCause(cause)}`);
    error.cause = cause;
    error.transient = true;
    throw error;
  }

  if (!response.ok) {
    throw await buildHttpError(response, url);
  }

  let envelope;
  try {
    envelope = await response.json();
  } catch (cause) {
    // Deliberately does NOT echo the body: a 200 body carries decrypted secrets.
    const error = new ActionError(
      `Kagi returned HTTP ${response.status} with a body that is not JSON. The body is not shown ` +
        'here because a successful response carries secret values.'
    );
    error.cause = cause;
    throw error;
  }

  return readEnvelope(envelope);
}

/**
 * Unwraps CustomResponse and validates the payload before a single value is touched.
 *
 * A malformed 200 is treated as a failure rather than as "zero secrets": continuing would leave the
 * job running with the env vars it asked for silently absent, which is exactly the outcome this
 * action exists to prevent.
 */
export function readEnvelope(envelope) {
  if (envelope === null || typeof envelope !== 'object') {
    throw new ActionError('Kagi returned a malformed response envelope.');
  }
  if (envelope.success === false) {
    throw new ActionError(
      `Kagi reported failure: ${describeEnvelopeError(envelope) ?? 'no reason given'}`
    );
  }

  const data = envelope.data;
  if (data === null || typeof data !== 'object') {
    throw new ActionError('Kagi returned a response with no data payload.');
  }

  const scopes = data.scopes;
  if (!Array.isArray(scopes)) {
    throw new ActionError('Kagi returned a response whose scopes field is not a list.');
  }

  const parsedScopes = scopes.map((scope, index) => readScope(scope, index));

  const dotenv = data.dotenv;
  if (dotenv !== null && dotenv !== undefined && typeof dotenv !== 'string') {
    throw new ActionError('Kagi returned a response whose dotenv field is not a string.');
  }

  return { scopes: parsedScopes, dotenv: typeof dotenv === 'string' ? dotenv : null };
}

function readScope(scope, index) {
  if (scope === null || typeof scope !== 'object') {
    throw new ActionError(`Kagi returned a malformed scope at position ${index}.`);
  }
  const secrets = scope.secrets;
  if (secrets !== null && secrets !== undefined && typeof secrets !== 'object') {
    throw new ActionError(`Kagi returned a scope at position ${index} whose secrets are not a map.`);
  }
  const entries = Object.entries(secrets ?? {});
  for (const [key, value] of entries) {
    if (typeof value !== 'string') {
      // The value would be exported as the string "undefined"/"[object Object]" otherwise, i.e. a
      // corrupt secret that looks like a real one.
      throw new ActionError(
        `Kagi returned a non-string value for '${key}' in scope ${describeScope(scope)}.`
      );
    }
  }
  return {
    appId: typeof scope.appId === 'string' ? scope.appId : null,
    appPath: typeof scope.appPath === 'string' ? scope.appPath : null,
    environmentSlug: typeof scope.environmentSlug === 'string' ? scope.environmentSlug : null,
    secrets: entries,
  };
}

export function describeScope(scope) {
  const path = scope.appPath ?? scope.appId ?? 'unknown app';
  return scope.environmentSlug ? `${path} (${scope.environmentSlug})` : String(path);
}

async function buildHttpError(response, url) {
  // A non-2xx body is an ErrorResponse envelope, never secret material, so it is safe to surface.
  const raw = await response.text().catch(() => '');
  let envelope = null;
  try {
    envelope = raw ? JSON.parse(raw) : null;
  } catch {
    // eslint-disable-next-line no-empty -- reason: a non-JSON error body is expected from proxies
    // and gateways; the raw text is surfaced below instead, so nothing is being swallowed.
    envelope = null;
  }
  const detail = describeEnvelopeError(envelope) ?? truncate(raw, 300);

  let message;
  switch (response.status) {
    case 400:
      message =
        `Kagi rejected the fetch request as invalid (HTTP 400). ${detail ?? ''}\n` +
        'identity-public-id must be the binding UUID from the Kagi portal.';
      break;
    case 401:
      message = `Kagi denied the fetch (HTTP 401). ${detail ? detail + '\n' : ''}${DENIED_HINT}`;
      break;
    case 403:
      message =
        `Kagi verified this workflow but refused the secrets (HTTP 403). ${detail ?? ''}\n` +
        "This is a plan or subscription problem on the binding's organization, not a workflow " +
        'problem: the secrets library requires an entitled plan and an unlocked subscription.';
      break;
    case 404:
      message =
        `Kagi has no CI fetch endpoint at ${url} (HTTP 404). Check the api-url input; it must be ` +
        'the Kagi API root, e.g. https://api.kagi.pw.';
      break;
    default:
      message = `Kagi returned HTTP ${response.status}. ${detail ?? ''}`;
  }

  const error = new ActionError(message.trim());
  error.status = response.status;
  error.transient = response.status === 429 || response.status >= 500;
  return error;
}

function describeEnvelopeError(envelope) {
  const details = envelope?.error;
  if (details && typeof details === 'object') {
    const code = typeof details.code === 'string' ? details.code : null;
    const message = typeof details.message === 'string' ? details.message : null;
    if (code && message) return `${code}: ${message}`;
    if (code) return code;
    if (message) return message;
  }
  if (typeof envelope?.message === 'string' && envelope.message) return envelope.message;
  return null;
}

function truncate(text, max) {
  if (!text) return null;
  const collapsed = text.replace(/\s+/g, ' ').trim();
  return collapsed.length > max ? `${collapsed.slice(0, max)}...` : collapsed;
}

function trimTrailingSlash(value) {
  return value.endsWith('/') ? value.slice(0, -1) : value;
}
