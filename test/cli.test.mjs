import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, writeFile, readdir, rm, open } from 'node:fs/promises';
import { resolve, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { renderReport } from '../src/report.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const temporaryRoot = resolve(root, '.test-tmp');
const cli = resolve(root, 'bin/evidence-scrub.mjs');
const run = (...args) => spawnSync(process.execPath, [cli, ...args], { cwd: root, encoding: 'utf8', timeout: 20000 });

async function sandbox(t) {
  await mkdir(temporaryRoot, { recursive: true });
  const directory = await mkdtemp(join(temporaryRoot, 'cli-'));
  t.after(async () => {
    const checked = resolve(directory);
    assert.ok(checked.startsWith(temporaryRoot + sep), 'cleanup must remain inside the dedicated test directory');
    await rm(checked, { recursive: true, force: true });
  });
  return directory;
}

test('HAR CLI builds a complete bundle without fixture secrets or original file name', async (t) => {
  const directory = await sandbox(t);
  const input = join(directory, 'PRIVATE_SOURCE_FILE_NAME.har');
  const original = await readFile(resolve(root, 'fixtures/demo.har'));
  await writeFile(input, original);
  const output = join(directory, 'clean');
  const result = run(input, '--out', output);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /none \(offline\)/);
  const names = (await readdir(output)).sort();
  assert.deepEqual(names, ['report.md', 'sanitized.har', 'summary.json']);
  const text = (await Promise.all(names.map(name => readFile(join(output, name), 'utf8')))).join('\n');
  assert.doesNotMatch(text, /DEMO_(?:PASSWORD|ACCOUNT|QUERY_TOKEN|FRAGMENT|BEARER_TOKEN|API_KEY|COOKIE|CUSTOMER|BODY_PASSWORD|RESPONSE_COOKIE|RESPONSE_SECRET|UNKNOWN_SECRET|REDIRECT|ENTRY_SECRET|PRIVATE_PAGE_TITLE)/);
  assert.doesNotMatch(text, /PRIVATE_SOURCE_FILE_NAME|tenant\.example/);
  const summary = JSON.parse(await readFile(join(output, 'summary.json'), 'utf8'));
  assert.match(summary.source.sha256, /^[a-f0-9]{64}$/);
  assert.equal(summary.source.bytes, original.length);
  assert.equal(summary.policy.networkOptIn, false);
  assert.deepEqual(await readFile(input), original, 'source must remain unchanged');
});

test('raw HTTP CLI removes body and credentials', async (t) => {
  const directory = await sandbox(t);
  const output = join(directory, 'clean');
  const result = run('fixtures/demo.http', '--out', output);
  assert.equal(result.status, 0, result.stderr);
  const text = await readFile(join(output, 'sanitized.http'), 'utf8');
  assert.doesNotMatch(text, /DEMO_|tenant\.example/);
  assert.match(text, /POST /);
  const summary = JSON.parse(await readFile(join(output, 'summary.json'), 'utf8'));
  assert.equal(summary.stats.entries, 1, 'one HTTP message must count as one processed entry');
});

test('existing output directories and files are never overwritten', async (t) => {
  const directory = await sandbox(t);
  await writeFile(join(directory, 'marker.txt'), 'KEEP_THIS_FILE');
  const result = run('fixtures/demo.har', '--out', directory);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Nothing was overwritten/);
  assert.equal(await readFile(join(directory, 'marker.txt'), 'utf8'), 'KEEP_THIS_FILE');
  assert.deepEqual(await readdir(directory), ['marker.txt']);
});

test('invalid captures fail without echoing raw values or creating output', async (t) => {
  const directory = await sandbox(t);
  const input = join(directory, 'invalid.har');
  await writeFile(input, '{"DO_NOT_ECHO_CANARY":');
  const result = run(input, '--out', join(directory, 'clean'));
  assert.equal(result.status, 1);
  assert.doesNotMatch(result.stderr + result.stdout, /DO_NOT_ECHO_CANARY/);
  assert.deepEqual(await readdir(directory), ['invalid.har']);
});

test('input larger than 20 MiB fails before processing', async (t) => {
  const directory = await sandbox(t);
  const input = join(directory, 'large.har');
  const file = await open(input, 'w');
  await file.truncate(20 * 1024 * 1024 + 1);
  await file.close();
  const result = run(input, '--out', join(directory, 'clean'));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /at most 20 MiB/);
});

test('keep-paths is an explicit, recorded choice', async (t) => {
  const directory = await sandbox(t);
  const output = join(directory, 'clean');
  const result = run('fixtures/demo.har', '--out', output, '--keep-paths');
  assert.equal(result.status, 0, result.stderr);
  const har = await readFile(join(output, 'sanitized.har'), 'utf8');
  assert.match(har, /DEMO_ACCOUNT/);
  assert.doesNotMatch(har, /DEMO_QUERY_TOKEN|DEMO_PASSWORD|tenant\.example/);
  const summary = JSON.parse(await readFile(join(output, 'summary.json'), 'utf8'));
  assert.equal(summary.policy.keepPaths, true);
});

test('raw HTTP has a clear 2 MiB byte limit, including multibyte input', async (t) => {
  const directory = await sandbox(t);
  const input = join(directory, 'oversized.http');
  await writeFile(input, 'POST / HTTP/1.1\r\n\r\n' + 'é'.repeat(1_100_000));
  const result = run(input, '--out', join(directory, 'clean'));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /HTTP captures are limited to 2 MiB/);
  assert.deepEqual(await readdir(directory), ['oversized.http']);
});

test('unknown flags are rejected without echoing their values', () => {
  const result = run('--DO_NOT_ECHO_CANARY');
  assert.equal(result.status, 1);
  assert.doesNotMatch(result.stderr, /DO_NOT_ECHO_CANARY/);
});

test('report escapes metadata rather than creating injected Markdown or HTML', () => {
  const report = renderReport({ format: 'http', source: { bytes: 1, sha256: 'a'.repeat(64) }, stats: {}, policy: {},
    github: { repository: 'test/repo', url: 'https://github.com/test/repo', defaultBranch: '<script>\n|x|', commitSha: 'b'.repeat(40), license: null } });
  assert.doesNotMatch(report, /<script>/);
  assert.match(report, /&lt;script&gt;/);
});
