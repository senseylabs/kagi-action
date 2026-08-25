/**
 * Test harness.
 *
 * Records every sink write -- workflow commands on stdout and appends to the runner files -- into
 * ONE ordered log. The mask-before-write guarantee is an ordering property between two different
 * sinks, so it can only be asserted if both are recorded on the same timeline.
 */

import { sinks } from '../src/core.js';
import { mkdtempSync, readFileSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * Sets an action input the way the runner does: the name is uppercased and SPACES become
 * underscores, but dashes are preserved (INPUT_ENV-FILE-PATH, not INPUT_ENV_FILE_PATH).
 */
export function setInput(name, value) {
  process.env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`] = String(value);
}

export function createHarness(inputs = {}) {
  const events = [];
  const originalEnv = { ...process.env };
  const originalStdout = sinks.stdout;
  const originalAppend = sinks.appendFile;
  const originalFetch = globalThis.fetch;

  const dir = mkdtempSync(join(tmpdir(), 'kagi-action-'));
  const envFile = join(dir, 'github_env');
  const outputFile = join(dir, 'github_output');

  process.env.GITHUB_ENV = envFile;
  process.env.GITHUB_OUTPUT = outputFile;
  process.exitCode = 0;

  for (const [name, value] of Object.entries(inputs)) {
    setInput(name, value);
  }

  sinks.stdout = (line) => events.push({ sink: 'stdout', text: line });
  sinks.appendFile = (file, contents) => {
    events.push({ sink: file === envFile ? 'github_env' : 'github_output', text: contents });
  };

  return {
    dir,
    events,
    /** All text ever written to any sink, in order. */
    log: () => events.map((event) => event.text),
    masks: () =>
      events
        .filter((event) => event.sink === 'stdout' && event.text.startsWith('::add-mask::'))
        .map((event) => event.text.slice('::add-mask::'.length)),
    warnings: () =>
      events
        .filter((event) => event.sink === 'stdout' && event.text.startsWith('::warning::'))
        .map((event) => event.text.slice('::warning::'.length)),
    errors: () =>
      events
        .filter((event) => event.sink === 'stdout' && event.text.startsWith('::error::'))
        .map((event) => event.text.slice('::error::'.length)),
    envWrites: () => events.filter((event) => event.sink === 'github_env').map((e) => e.text),
    outputWrites: () => events.filter((event) => event.sink === 'github_output').map((e) => e.text),
    /** Index of the first event whose text contains the needle, or -1. */
    indexOf: (needle) => events.findIndex((event) => event.text.includes(needle)),
    indexOfMask: (value) =>
      events.findIndex(
        (event) => event.sink === 'stdout' && event.text === `::add-mask::${escapeData(value)}`
      ),
    indexOfWriteContaining: (needle) =>
      events.findIndex((event) => event.sink !== 'stdout' && event.text.includes(needle)),
    readFile: (path) => readFileSync(path, 'utf8'),
    exists: (path) => existsSync(path),
    mode: (path) => statSync(path).mode & 0o777,
    path: (name) => join(dir, name),
    restore() {
      sinks.stdout = originalStdout;
      sinks.appendFile = originalAppend;
      globalThis.fetch = originalFetch;
      for (const key of Object.keys(process.env)) {
        if (!(key in originalEnv)) delete process.env[key];
      }
      Object.assign(process.env, originalEnv);
      process.exitCode = 0;
    },
  };
}

function escapeData(value) {
  return String(value).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

/** Minimal Response stand-in; enough for the client and the OIDC minter. */
export function jsonResponse(status, body, { contentType = 'application/json' } = {}) {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Map([['content-type', contentType]]),
    async json() {
      return JSON.parse(text);
    },
    async text() {
      return text;
    },
  };
}

/**
 * Installs a fetch stub that answers the OIDC token service and the Kagi API separately.
 * Returns the recorded calls so a test can assert the exact request that went out.
 */
export function stubFetch({ oidc, kagi }) {
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), options });
    if (String(url).includes('token-service')) {
      return typeof oidc === 'function' ? oidc(String(url), options) : oidc;
    }
    return typeof kagi === 'function' ? kagi(String(url), options) : kagi;
  };
  return calls;
}

export const OIDC_ENV = {
  ACTIONS_ID_TOKEN_REQUEST_URL: 'https://token-service.example/token?api-version=2.0',
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'runner-bearer',
};

export function withOidcEnv() {
  Object.assign(process.env, OIDC_ENV);
}
