/**
 * Masking and delivery of fetched values.
 *
 * The ordering rule this file exists to enforce: EVERY value is registered with the runner's log
 * scrubber before it is written to any sink. The runner cannot retroactively redact a line it has
 * already printed, so masking after a write is the same as not masking at all.
 *
 * The rule is structural, not conventional: mask() returns a sealed carrier and the delivery
 * functions accept nothing else, so there is no ordering for a future edit to get wrong. Kagi has
 * no SECRET/PUBLIC sensitivity attribute on a secret today, so masking is unconditional -- there is
 * nothing to key an exemption off, and guessing would be guessing about a customer's data.
 */

import { ActionError, setSecret, exportVariable, warning, info } from './core.js';
import { describeScope } from './client.js';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

/**
 * Environment variable names this action is willing to write into $GITHUB_ENV.
 *
 * Kagi's own API already constrains a secret key to ^[A-Z0-9_]+$ (KagiSecretCreateRequest), so this
 * is a deliberately wider superset -- it is a second, independent guard rather than a copy of the
 * server's rule. It exists because $GITHUB_ENV is line-oriented: a key containing a newline or an
 * equals sign could inject additional variables into every later step of the job. If the server
 * rule is ever loosened, this fails the step loudly instead of writing something exploitable.
 */
const EXPORTABLE_KEY = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Shortest line of a multi-line value that gets its own mask.
 *
 * A multi-line value (a PEM key, a JSON blob) is masked as a whole by the runner, but the runner
 * scrubs line by line, so the individual lines need registering too. Very short lines are skipped:
 * masking a 1-3 character line would replace that fragment everywhere it occurs in the log and turn
 * unrelated output into confetti.
 */
const MIN_LINE_MASK_LENGTH = 4;

const SEAL = Symbol('kagi.masked');

/**
 * Flattens the response scopes into export entries, resolving key collisions.
 *
 * Last scope wins -- which is also what a shell sourcing the rendered .env does, so the two
 * delivery mechanisms agree -- but never silently: each collision is warned about by name.
 */
export function collectEntries(scopes) {
  const byKey = new Map();
  const collisions = [];

  for (const scope of scopes) {
    for (const [key, value] of scope.secrets) {
      const previous = byKey.get(key);
      if (previous) {
        collisions.push({ key, from: previous.scopeLabel, to: describeScope(scope) });
      }
      byKey.set(key, { key, value, scopeLabel: describeScope(scope) });
    }
  }

  return { entries: [...byKey.values()], collisions };
}

/**
 * Registers every value with the runner's log scrubber.
 *
 * Masks three forms of each value:
 *  1. the value itself;
 *  2. each sufficiently long line of a multi-line value, because the scrubber matches per line;
 *  3. the dotenv-escaped form, which is what lands in the .env file and is therefore what would
 *     appear if a later step cats that file.
 *
 * @returns a sealed carrier accepted by the delivery functions. Nothing else can be delivered.
 */
export function mask(entries, dotenv) {
  for (const { value } of entries) {
    setSecret(value);

    if (value.includes('\n') || value.includes('\r')) {
      for (const line of value.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (trimmed.length >= MIN_LINE_MASK_LENGTH) {
          setSecret(trimmed);
        }
      }
    }

    const escaped = dotenvEscape(value);
    if (escaped !== value) {
      setSecret(escaped);
    }
  }

  return { [SEAL]: true, entries, dotenv };
}

function unseal(masked, caller) {
  if (!masked || masked[SEAL] !== true) {
    throw new ActionError(
      `${caller} was given values that have not been masked. This is a bug in kagi-action; ` +
        'fetched values must pass through mask() before any write.'
    );
  }
  return masked;
}

/** Writes every entry into $GITHUB_ENV so later steps in the job see them as env vars. */
export function exportToEnv(masked) {
  const { entries } = unseal(masked, 'exportToEnv');
  for (const { key, value } of entries) {
    assertExportableKey(key);
    exportVariable(key, value);
  }
  info(`Exported ${entries.length} secret${entries.length === 1 ? '' : 's'} to the job environment.`);
}

/**
 * Writes the server-rendered .env document to disk.
 *
 * The document is rendered by Kagi (KagiCiDotenvRenderer), not here: escaping a secret for a
 * shell-sourced file is exactly the thing that ends up subtly different in every reimplementation,
 * and a value containing a quote, a dollar sign or a newline is one divergence away from breaking
 * out of its assignment.
 */
export function writeEnvFile(masked, path) {
  const { dotenv } = unseal(masked, 'writeEnvFile');
  if (typeof dotenv !== 'string') {
    throw new ActionError(
      'Kagi returned no rendered .env document even though DOTENV was requested. Refusing to ' +
        'write a partial or hand-rendered file.'
    );
  }
  const target = resolve(path);
  mkdirSync(dirname(target), { recursive: true });
  // 0600: the file holds plaintext secrets and nothing else on the runner needs to read it.
  writeFileSync(target, dotenv, { encoding: 'utf8', mode: 0o600 });
  info(`Wrote ${target} (mode 0600).`);
  return target;
}

export function assertExportableKey(key) {
  if (!EXPORTABLE_KEY.test(key)) {
    throw new ActionError(
      `Refusing to export the secret key '${key}': it is not a valid environment variable name. ` +
        'Writing it would corrupt $GITHUB_ENV for the rest of the job. Rename the key in Kagi, or ' +
        'use env-file-path instead of export-env.'
    );
  }
}

export function reportCollisions(collisions) {
  for (const { key, from, to } of collisions) {
    warning(
      `Secret key '${key}' is granted by more than one scope (${from}, then ${to}). ` +
        'The last scope wins for the exported variable; both values remain in the fetched scopes.'
    );
  }
}

/**
 * Mirrors KagiCiDotenvRenderer.escape exactly, in the same order (backslash first, so the escapes
 * introduced afterwards are not escaped a second time).
 *
 * Used ONLY to compute an additional mask string. The .env file itself is always the server's
 * rendering -- this must never become a second, drifting implementation of it.
 */
export function dotenvEscape(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replaceAll('\\', '\\\\')
    .replaceAll('"', '\\"')
    .replaceAll('$', '\\$')
    .replaceAll('`', '\\`')
    .replaceAll('\n', '\\n');
}
