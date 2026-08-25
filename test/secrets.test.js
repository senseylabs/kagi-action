import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHarness } from './helpers.js';
import {
  collectEntries,
  mask,
  exportToEnv,
  writeEnvFile,
  reportCollisions,
  assertExportableKey,
  dotenvEscape,
} from '../src/secrets.js';
import { ActionError } from '../src/core.js';

let harness;
afterEach(() => harness?.restore());

const scope = (label, secrets) => ({
  appId: null,
  appPath: label,
  environmentSlug: 'production',
  secrets: Object.entries(secrets),
});

describe('masking', () => {
  test('every value is masked', () => {
    harness = createHarness();
    const { entries } = collectEntries([scope('/a', { A: 'alpha-value', B: 'beta-value' })]);

    mask(entries, null);

    assert.deepEqual(harness.masks().sort(), ['alpha-value', 'beta-value']);
  });

  test('a multi-line value masks the whole value and each substantial line', () => {
    harness = createHarness();
    const pem = '-----BEGIN KEY-----\nMIIEabcdef\nqrstuv\n-----END KEY-----';
    const { entries } = collectEntries([scope('/a', { KEY: pem })]);

    mask(entries, null);

    const masks = harness.masks();
    // The runner scrubs line by line, so the individual lines have to be registered as well.
    assert.ok(masks.includes('-----BEGIN KEY-----'));
    assert.ok(masks.includes('MIIEabcdef'));
    assert.ok(masks.includes('qrstuv'));
    assert.ok(masks.some((m) => m.includes('%0A')), 'the whole value is masked too');
  });

  test('trivially short lines are not masked, so unrelated log output survives', () => {
    harness = createHarness();
    const { entries } = collectEntries([scope('/a', { KEY: 'ok\nreal-line-here' })]);

    mask(entries, null);

    assert.ok(!harness.masks().includes('ok'));
    assert.ok(harness.masks().includes('real-line-here'));
  });

  test('the dotenv-escaped form is masked too, since that is what lands in the .env file', () => {
    harness = createHarness();
    const { entries } = collectEntries([scope('/a', { KEY: 'pa$$"word' })]);

    mask(entries, null);

    assert.ok(harness.masks().includes('pa$$"word'));
    assert.ok(harness.masks().includes('pa\\$\\$\\"word'));
  });

  test('dotenvEscape mirrors KagiCiDotenvRenderer.escape, backslash first', () => {
    assert.equal(dotenvEscape('a\\b"c$d`e\nf'), 'a\\\\b\\"c\\$d\\`e\\nf');
    assert.equal(dotenvEscape(null), '');
  });
});

describe('mask-before-write is structural', () => {
  test('exportToEnv refuses values that did not pass through mask()', () => {
    harness = createHarness();
    assert.throws(() => exportToEnv({ entries: [{ key: 'A', value: 'b' }] }), ActionError);
    assert.equal(harness.envWrites().length, 0);
  });

  test('writeEnvFile refuses values that did not pass through mask()', () => {
    harness = createHarness();
    assert.throws(() => writeEnvFile({ dotenv: 'A="b"\n' }, harness.path('.env')), ActionError);
    assert.equal(harness.exists(harness.path('.env')), false);
  });

  test('every mask precedes every write of that value', () => {
    harness = createHarness();
    const { entries } = collectEntries([scope('/a', { A: 'alpha-value' })]);

    exportToEnv(mask(entries, null));

    const maskIndex = harness.indexOfMask('alpha-value');
    const writeIndex = harness.indexOfWriteContaining('alpha-value');
    assert.ok(maskIndex >= 0 && writeIndex >= 0);
    assert.ok(maskIndex < writeIndex, 'the value was written before it was masked');
  });
});

describe('exporting', () => {
  test('writes each key into GITHUB_ENV', () => {
    harness = createHarness();
    const { entries } = collectEntries([scope('/a', { A: '1', B: '2' })]);

    exportToEnv(mask(entries, null));

    const written = harness.envWrites().join('');
    assert.match(written, /^A<</);
    assert.ok(written.includes('B<<'));
  });

  test('a key that is not a valid env var name fails the step instead of corrupting GITHUB_ENV', () => {
    harness = createHarness();
    // Kagi's own API constrains keys to ^[A-Z0-9_]+$; this is the independent second guard.
    assert.throws(() => assertExportableKey('A=B\nEVIL'), ActionError);
    assert.throws(() => assertExportableKey('9LEADING'), ActionError);
    assert.throws(() => assertExportableKey('has-dash'), ActionError);
    assert.doesNotThrow(() => assertExportableKey('DATABASE_URL'));
  });
});

describe('collisions', () => {
  test('the last scope wins and every collision is warned about by name', () => {
    harness = createHarness();
    const { entries, collisions } = collectEntries([
      scope('/a', { SHARED: 'first' }),
      scope('/b', { SHARED: 'second' }),
    ]);
    reportCollisions(collisions);

    assert.deepEqual(entries, [{ key: 'SHARED', value: 'second', scopeLabel: '/b (production)' }]);
    assert.equal(harness.warnings().length, 1);
    assert.match(harness.warnings()[0], /SHARED/);
  });
});

describe('.env file', () => {
  test('writes the server-rendered document at mode 0600', () => {
    harness = createHarness();
    const target = harness.path('nested/dir/.env');
    const masked = mask([{ key: 'A', value: 'b' }], 'A="b"\n');

    const written = writeEnvFile(masked, target);

    assert.equal(written, target);
    assert.equal(harness.readFile(target), 'A="b"\n');
    assert.equal(harness.mode(target), 0o600);
  });

  test('a missing dotenv document fails rather than writing a hand-rendered file', () => {
    harness = createHarness();
    assert.throws(() => writeEnvFile(mask([], null), harness.path('.env')), ActionError);
  });
});
