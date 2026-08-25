/**
 * A hand-written, zero-dependency subset of @actions/core.
 *
 * Why not depend on @actions/core: a JavaScript action must ship its dependencies inside the repo,
 * either as a committed node_modules or as a bundled dist/index.js produced by ncc. Both mean the
 * code that handles a customer's secrets is not the code a customer can read in this repo. This
 * action fetches and exports secrets, so being auditable line by line at the tag they pin is worth
 * more than reusing a 4-function subset of a toolkit. Everything below mirrors @actions/core's
 * observable behaviour (workflow command escaping, the GITHUB_ENV heredoc, boolean input parsing)
 * and is covered by tests.
 */

import { appendFileSync } from 'node:fs';
import { EOL } from 'node:os';
import { randomUUID } from 'node:crypto';

/** Error whose message is safe to show the user verbatim via setFailed. */
export class ActionError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ActionError';
  }
}

/**
 * Escapes a workflow command's message payload.
 * Identical to the toolkit's escapeData: a raw newline would terminate the command early, and a
 * raw % would corrupt the runner's own unescaping.
 */
export function escapeData(value) {
  return toCommandValue(value)
    .replace(/%/g, '%25')
    .replace(/\r/g, '%0D')
    .replace(/\n/g, '%0A');
}

/** Escapes a workflow command's property value (also the property separators). */
export function escapeProperty(value) {
  return escapeData(value).replace(/:/g, '%3A').replace(/,/g, '%2C');
}

function toCommandValue(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  return JSON.stringify(value);
}

/**
 * Writes one workflow command to stdout.
 *
 * Exposed as a swappable sink so the tests can record the exact ORDER of every command relative to
 * every file write. The mask-before-write guarantee is an ordering property, so it has to be
 * testable as one.
 */
export const sinks = {
  stdout: (line) => process.stdout.write(line + EOL),
  appendFile: (file, contents) => appendFileSync(file, contents, { encoding: 'utf8' }),
};

export function issueCommand(command, properties, message) {
  let line = `::${command}`;
  const entries = Object.entries(properties ?? {}).filter(([, v]) => v !== undefined && v !== '');
  if (entries.length > 0) {
    line += ' ' + entries.map(([k, v]) => `${k}=${escapeProperty(v)}`).join(',');
  }
  line += `::${escapeData(message)}`;
  sinks.stdout(line);
}

/**
 * Registers a value as a secret so the runner replaces it with *** in every subsequent log line.
 *
 * "Subsequent" is the whole point: the runner cannot retroactively scrub a line it has already
 * written, so this must run before the value reaches any other sink.
 */
export function setSecret(secret) {
  if (typeof secret !== 'string' || secret.length === 0) return;
  issueCommand('add-mask', {}, secret);
}

export function info(message) {
  sinks.stdout(message);
}

export function warning(message) {
  issueCommand('warning', {}, message);
}

export function debug(message) {
  issueCommand('debug', {}, message);
}

export function setFailed(message) {
  issueCommand('error', {}, message);
  process.exitCode = 1;
}

/** Reads an action input from its INPUT_* environment variable. */
export function getInput(name, { required = false, fallback = '' } = {}) {
  const key = `INPUT_${name.replace(/ /g, '_').toUpperCase()}`;
  const raw = process.env[key];
  const value = typeof raw === 'string' ? raw.trim() : '';
  if (value === '') {
    if (required) {
      throw new ActionError(`Input required and not supplied: ${name}`);
    }
    return fallback;
  }
  return value;
}

/**
 * Reads a boolean input, accepting only the YAML 1.2 core-schema spellings the toolkit accepts.
 * Anything else throws rather than being coerced: silently reading a typo'd "yes" as false would
 * turn `export-env: yes` into a job whose env vars are quietly missing.
 */
export function getBooleanInput(name, fallback) {
  const value = getInput(name);
  if (value === '') return fallback;
  if (['true', 'True', 'TRUE'].includes(value)) return true;
  if (['false', 'False', 'FALSE'].includes(value)) return false;
  throw new ActionError(
    `Input ${name} does not meet YAML 1.2 "Core Schema" specification: got '${value}', expected true or false`
  );
}

export function getNumberInput(name, fallback) {
  const value = getInput(name);
  if (value === '') return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new ActionError(`Input ${name} must be a positive number, got '${value}'`);
  }
  return parsed;
}

/**
 * Appends KEY=value to a runner file (GITHUB_ENV / GITHUB_OUTPUT) using the heredoc form.
 *
 * The delimiter is a fresh UUID per write, and a value that somehow contains it is a hard error:
 * writing it anyway would let a crafted value close the heredoc early and inject arbitrary
 * environment variables into every later step of the job.
 */
function appendKeyValue(file, key, value) {
  const delimiter = `ghadelimiter_${randomUUID()}`;
  if (key.includes(delimiter) || value.includes(delimiter)) {
    throw new ActionError(`Unexpected delimiter collision while writing '${key}'`);
  }
  sinks.appendFile(file, `${key}<<${delimiter}${EOL}${value}${EOL}${delimiter}${EOL}`);
}

export function exportVariable(key, value) {
  const file = process.env.GITHUB_ENV;
  if (!file) {
    throw new ActionError('GITHUB_ENV is not set; this action must run inside GitHub Actions.');
  }
  appendKeyValue(file, key, value);
  process.env[key] = value;
}

export function setOutput(key, value) {
  const file = process.env.GITHUB_OUTPUT;
  if (!file) {
    throw new ActionError('GITHUB_OUTPUT is not set; this action must run inside GitHub Actions.');
  }
  appendKeyValue(file, key, String(value));
}
