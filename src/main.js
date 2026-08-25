/**
 * kagi-action entry point.
 *
 * Mint an OIDC id-token for this workflow run, exchange it for the secrets its Kagi binding grants,
 * mask every value, then export them. No stored credential, no token minted back into the runner,
 * no binary downloaded.
 */

import {
  ActionError,
  getInput,
  getBooleanInput,
  getNumberInput,
  setSecret,
  setOutput,
  setFailed,
  warning,
  info,
  debug,
} from './core.js';
import { mintIdToken } from './oidc.js';
import { fetchSecrets, describeScope } from './client.js';
import { collectEntries, mask, exportToEnv, writeEnvFile, reportCollisions } from './secrets.js';

/** Kagi's public API root. Overridable for a self-hosted (ENTERPRISE) deployment. */
export const DEFAULT_API_URL = 'https://api.kagi.pw';

/**
 * Audience the id-token is requested at.
 *
 * Mirrors KagiCiExchangeConstant.DEFAULT_EXPECTED_AUDIENCE, which is what the verifier requires
 * when a binding pins no expectedAudience of its own. The verifier demands an exact, single-valued
 * audience, so this is never "unconstrained" -- it has to be a concrete string on both sides.
 */
export const DEFAULT_AUDIENCE = 'api.kagi.pw';

const DEFAULT_TIMEOUT_SECONDS = 30;

/**
 * A transient failure is retried with a FRESHLY minted id-token, never the same one.
 *
 * The exchange spends the token's jti through the replay guard before it can fail late, so
 * resending the identical token would be rejected as a replay. Minting again is cheap and is the
 * only correct way to retry this endpoint.
 */
const MAX_ATTEMPTS = 3;
const RETRY_BACKOFF_MS = [1000, 3000];

const UUID_PATTERN = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export async function run() {
  const identityPublicId = getInput('identity-public-id', { required: true });
  if (!UUID_PATTERN.test(identityPublicId)) {
    throw new ActionError(
      `identity-public-id must be the binding's routing UUID from the Kagi portal, got ` +
        `'${identityPublicId}'.`
    );
  }

  const apiUrl = getInput('api-url', { fallback: DEFAULT_API_URL });
  const audience = getInput('audience', { fallback: DEFAULT_AUDIENCE });
  const exportEnv = getBooleanInput('export-env', true);
  const envFilePath = getInput('env-file-path');
  const timeoutMs = getNumberInput('request-timeout-seconds', DEFAULT_TIMEOUT_SECONDS) * 1000;

  // Accepted for compatibility with the published input surface, but masking cannot be turned off:
  // Kagi has no per-secret sensitivity flag, so every value is treated as sensitive. Warning rather
  // than failing keeps an existing workflow running while telling its author the input is inert.
  if (getBooleanInput('mask', true) === false) {
    warning(
      'The `mask` input is accepted but ignored: every fetched value is always masked. Kagi has no ' +
        'per-secret sensitivity flag, so there is nothing that could safely be left unmasked.'
    );
  }

  if (!exportEnv && !envFilePath) {
    throw new ActionError(
      'Nothing to do: export-env is false and env-file-path is unset, so the fetched secrets would ' +
        'go nowhere. Set one of them.'
    );
  }

  const wantDotenv = Boolean(envFilePath);

  info(`Fetching Kagi secrets for binding ${identityPublicId} (audience ${audience}).`);

  const result = await exchangeWithRetry({
    apiUrl,
    identityPublicId,
    audience,
    wantDotenv,
    timeoutMs,
  });

  const { entries, collisions } = collectEntries(result.scopes);
  reportCollisions(collisions);

  for (const scope of result.scopes) {
    info(
      `  ${describeScope(scope)}: ${scope.secrets.length} key(s) [` +
        `${scope.secrets.map(([key]) => key).join(', ')}]`
    );
  }

  // MASK FIRST. Every sink below only accepts the sealed carrier this returns.
  const masked = mask(entries, result.dotenv);

  if (exportEnv) {
    exportToEnv(masked);
  }

  let writtenPath = '';
  if (envFilePath) {
    writtenPath = writeEnvFile(masked, envFilePath);
  }

  setOutput('secret-count', entries.length);
  setOutput('scope-count', result.scopes.length);
  setOutput('env-file', writtenPath);
}

async function exchangeWithRetry({ apiUrl, identityPublicId, audience, wantDotenv, timeoutMs }) {
  let lastError;

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
    try {
      // Minted inside the loop on purpose: the previous attempt's token is spent (see MAX_ATTEMPTS).
      const token = await mintIdToken(audience, timeoutMs);
      // The id-token is the entire credential on this path; mask it before it can reach a log.
      setSecret(token);

      return await fetchSecrets({ apiUrl, identityPublicId, token, wantDotenv, timeoutMs });
    } catch (error) {
      lastError = error;
      if (!error?.transient || attempt === MAX_ATTEMPTS) {
        throw error;
      }
      const waitMs = RETRY_BACKOFF_MS[attempt - 1] ?? RETRY_BACKOFF_MS.at(-1);
      warning(
        `Attempt ${attempt} of ${MAX_ATTEMPTS} failed: ${error.message.split('\n')[0]} ` +
          `Retrying in ${waitMs}ms with a freshly minted id-token.`
      );
      await sleep(waitMs);
    }
  }

  /* c8 ignore next -- the loop either returns or throws; this is belt and braces. */
  throw lastError ?? new ActionError('The Kagi fetch failed for an unknown reason.');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Only the real action run has a side effect; importing this module from a test does not.
 * Every failure path ends here, and every one of them fails the step -- there is no branch that
 * continues the job with the secrets missing.
 */
const isDirectRun = process.env.KAGI_ACTION_TEST !== '1';
if (isDirectRun) {
  run().catch((error) => {
    if (error?.cause) {
      debug(`Underlying cause: ${error.cause.stack ?? error.cause}`);
    }
    if (!(error instanceof ActionError)) {
      debug(error?.stack ?? String(error));
    }
    setFailed(error?.message ?? String(error));
  });
}
