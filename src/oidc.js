/**
 * Requests a GitHub-minted OIDC id-token for this workflow run.
 *
 * The runner exposes a per-job token service through two environment variables that only exist when
 * the job declares `permissions: id-token: write`. ACTIONS_ID_TOKEN_REQUEST_TOKEN is the bearer for
 * that service; ACTIONS_ID_TOKEN_REQUEST_URL already carries an api-version query string, so the
 * audience is appended with & rather than ?.
 *
 * The minted token IS the credential for the exchange, so it is masked by the caller the moment it
 * arrives and is never included in an error message.
 */

import { ActionError } from './core.js';

export const MISSING_PERMISSION_HINT =
  'No OIDC token service is available to this job. Add\n\n  permissions:\n    id-token: write\n\n' +
  'to the job (or workflow) that uses senseylabs/kagi-action. This is what lets GitHub mint the ' +
  'id-token the action exchanges for your secrets; the action has no other credential and cannot ' +
  'add the permission itself.';

export async function mintIdToken(audience, timeoutMs) {
  const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  const requestUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;

  if (!requestToken || !requestUrl) {
    throw new ActionError(MISSING_PERMISSION_HINT);
  }

  const url = `${requestUrl}&audience=${encodeURIComponent(audience)}`;

  let response;
  try {
    response = await fetch(url, {
      method: 'GET',
      headers: {
        authorization: `Bearer ${requestToken}`,
        accept: 'application/json;api-version=2.0',
      },
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (cause) {
    // Rethrown as an ActionError so the step fails with a readable reason. The cause is attached
    // rather than dropped so debug mode can still surface the transport-level detail.
    const error = new ActionError(
      `Could not reach the GitHub OIDC token service: ${describeCause(cause)}`
    );
    error.cause = cause;
    error.transient = true;
    throw error;
  }

  if (!response.ok) {
    const error = new ActionError(
      `GitHub refused to mint an OIDC id-token (HTTP ${response.status}). ` +
        (response.status === 403 || response.status === 401
          ? MISSING_PERMISSION_HINT
          : 'This is a GitHub-side failure, not a Kagi one.')
    );
    error.transient = response.status >= 500 || response.status === 429;
    throw error;
  }

  let payload;
  try {
    payload = await response.json();
  } catch (cause) {
    const error = new ActionError(
      'The GitHub OIDC token service returned a body that is not JSON. The response is not echoed ' +
        'here because it may contain the token itself.'
    );
    error.cause = cause;
    throw error;
  }

  const token = payload?.value;
  if (typeof token !== 'string' || token.length === 0) {
    throw new ActionError(
      'The GitHub OIDC token service returned no token value. The response is not echoed here ' +
        'because it may contain the token itself.'
    );
  }
  return token;
}

export function describeCause(cause) {
  if (cause instanceof Error) {
    if (cause.name === 'TimeoutError') return 'the request timed out';
    return `${cause.name}: ${cause.message}`;
  }
  return String(cause);
}
