import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { EOL } from 'node:os';
import { createHarness, setInput } from './helpers.js';
import {
  escapeData,
  escapeProperty,
  getInput,
  getBooleanInput,
  getNumberInput,
  exportVariable,
  setOutput,
  setSecret,
  ActionError,
} from '../src/core.js';

let harness;
afterEach(() => harness?.restore());

describe('workflow command escaping', () => {
  test('escapes the characters that would terminate or corrupt a command', () => {
    assert.equal(escapeData('a%b\rc\nd'), 'a%25b%0Dc%0Ad');
    assert.equal(escapeProperty('a:b,c'), 'a%3Ab%2Cc');
  });

  test('a multi-line secret is masked as a single, escaped command', () => {
    harness = createHarness();
    setSecret('line-one\nline-two');
    assert.deepEqual(harness.log(), ['::add-mask::line-one%0Aline-two']);
  });

  test('an empty value issues no mask command', () => {
    harness = createHarness();
    setSecret('');
    assert.deepEqual(harness.log(), []);
  });
});

describe('inputs', () => {
  test('reads and trims INPUT_* variables', () => {
    harness = createHarness({ 'binding-id': '  abc  ' });
    assert.equal(getInput('binding-id'), 'abc');
  });

  test('a required input that is absent fails loudly', () => {
    harness = createHarness();
    assert.throws(() => getInput('binding-id', { required: true }), ActionError);
  });

  test('an absent optional input falls back', () => {
    harness = createHarness();
    assert.equal(getInput('api-url', { fallback: 'https://api.kagi.pw' }), 'https://api.kagi.pw');
  });

  test('boolean inputs accept only the YAML core-schema spellings', () => {
    harness = createHarness({ 'export-env': 'False' });
    assert.equal(getBooleanInput('export-env', true), false);
    setInput('export-env', 'yes');
    assert.throws(() => getBooleanInput('export-env', true), ActionError);
  });

  test('a non-numeric or non-positive timeout fails rather than being coerced', () => {
    harness = createHarness({ 'request-timeout-seconds': 'soon' });
    assert.throws(() => getNumberInput('request-timeout-seconds', 30), ActionError);
    setInput('request-timeout-seconds', '0');
    assert.throws(() => getNumberInput('request-timeout-seconds', 30), ActionError);
  });
});

describe('runner file writes', () => {
  test('exportVariable uses a heredoc so a multi-line value cannot corrupt the file', () => {
    harness = createHarness();
    exportVariable('MULTI', 'a\nb');
    const [written] = harness.envWrites();
    const match = written.match(/^MULTI<<(ghadelimiter_[0-9a-f-]+)/);
    assert.ok(match, `unexpected heredoc: ${written}`);
    const delimiter = match[1];
    assert.equal(written, `MULTI<<${delimiter}${EOL}a\nb${EOL}${delimiter}${EOL}`);
    assert.equal(process.env.MULTI, 'a\nb');
  });

  test('setOutput writes to GITHUB_OUTPUT, not GITHUB_ENV', () => {
    harness = createHarness();
    setOutput('secret-count', 3);
    assert.equal(harness.envWrites().length, 0);
    assert.match(harness.outputWrites()[0], /^secret-count<<ghadelimiter_[0-9a-f-]+\n3\n/);
  });

  test('writing outside GitHub Actions fails instead of silently dropping the value', () => {
    harness = createHarness();
    delete process.env.GITHUB_ENV;
    assert.throws(() => exportVariable('K', 'v'), ActionError);
  });
});
