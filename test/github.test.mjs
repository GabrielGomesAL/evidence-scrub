import test from 'node:test';
import assert from 'node:assert/strict';
import { fetchGitHubMetadata } from '../src/github.mjs';

const sha = 'a'.repeat(40);
const repoData = (overrides = {}) => ({
  default_branch: 'main', stargazers_count: 7, license: { spdx_id: 'MIT' }, ...overrides,
});
const json = (value, init = {}) => new Response(JSON.stringify(value), init);

test('returns only the six public fields and encodes the branch as one path segment', async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    return calls.length === 1 ? json(repoData({
      default_branch: 'release/next#é',
      html_url: 'https://untrusted.invalid/path',
      token: 'DO-NOT-RETURN',
      owner: { email: 'private@example.test' },
    })) : json({ sha, files: [{ patch: 'DO-NOT-RETURN' }], author: { email: 'private@example.test' } });
  };
  assert.deepEqual(await fetchGitHubMetadata('Example-Org/repo.name_v2', { fetchImpl }), {
    repository: 'Example-Org/repo.name_v2',
    url: 'https://github.com/Example-Org/repo.name_v2',
    defaultBranch: 'release/next#é', commitSha: sha, license: 'MIT', stars: 7,
  });
  assert.deepEqual(calls.map(call => call.url), [
    'https://api.github.com/repos/Example-Org/repo.name_v2',
    'https://api.github.com/repos/Example-Org/repo.name_v2/commits/release%2Fnext%23%C3%A9',
  ]);
  for (const { options } of calls) {
    assert.equal(options.method, 'GET');
    assert.equal(options.redirect, 'error');
    assert.equal(options.credentials, 'omit');
    assert.equal('body' in options, false);
    assert.equal(new Headers(options.headers).has('authorization'), false);
    assert.equal(new Headers(options.headers).has('proxy-authorization'), false);
    assert.deepEqual([...new Headers(options.headers).keys()].sort(), [
      'accept', 'user-agent', 'x-github-api-version',
    ]);
    assert.ok(options.signal instanceof AbortSignal);
  }
});

test('rejects URLs, credentials, traversal, controls, and invalid names before any request', async () => {
  let calls = 0;
  const invalid = [
    undefined, null, {}, '', 'owner', 'owner/repo/extra', 'https://github.com/owner/repo',
    'owner@host/repo', 'owner/repo?token=SECRET', 'owner/repo#fragment', 'owner/repo%2Fother',
    'owner/..', 'owner/.', 'owner/../repo', 'owner\\repo', '-owner/repo', 'owner-/repo',
    'two--hyphens/repo', 'own_er/repo', 'owner/repo\n', 'owner/ space',
    `${'a'.repeat(40)}/repo`, `owner/${'a'.repeat(101)}`,
  ];
  for (const value of invalid) {
    await assert.rejects(fetchGitHubMetadata(value, { fetchImpl: async () => { calls += 1; } }), {
      name: 'TypeError', message: 'Repository must use the owner/repo format.',
    });
  }
  assert.equal(calls, 0);
});

test('HTTP and network failures disclose no upstream body or error text', async () => {
  for (const status of [301, 302, 403, 404, 429, 500]) {
    let calls = 0;
    await assert.rejects(fetchGitHubMetadata('owner/repo', {
      fetchImpl: async () => { calls += 1; return new Response('SECRET response', { status }); },
    }), { message: 'Unable to fetch public GitHub metadata.' });
    assert.equal(calls, 1);
  }
  await assert.rejects(fetchGitHubMetadata('owner/repo', {
    fetchImpl: async () => { throw new Error('Network SECRET token'); },
  }), { message: 'Unable to fetch public GitHub metadata.' });
});

test('rejects a followed or redirected response even if the transport ignores redirect:error', async () => {
  for (const properties of [{ redirected: true }, { url: 'https://untrusted.invalid/repository' }]) {
    await assert.rejects(fetchGitHubMetadata('owner/repo', {
      fetchImpl: async () => {
        const response = json(repoData());
        for (const [name, value] of Object.entries(properties)) Object.defineProperty(response, name, { value });
        return response;
      },
    }), { message: 'Unable to fetch public GitHub metadata.' });
  }
});

test('bounds response bytes and rejects malformed metadata instead of guessing values', async () => {
  const oversized = 'x'.repeat(1024 * 1024 + 1);
  for (const response of [
    new Response(oversized), new Response('{}', { headers: { 'Content-Length': String(oversized.length) } }),
    new Response('not json'), json(repoData({ stargazers_count: -1 })),
    json(repoData({ stargazers_count: 1.5 })), json(repoData({ default_branch: '' })),
    json(repoData({ default_branch: '.' })), json(repoData({ default_branch: '..' })),
    json(repoData({ default_branch: 'main\r\nSECRET' })), json(repoData({ private: true })),
    json(repoData({ visibility: 'private' })), json(null),
  ]) {
    await assert.rejects(fetchGitHubMetadata('owner/repo', { fetchImpl: async () => response }), {
      message: 'Unable to fetch public GitHub metadata.',
    });
  }
  let calls = 0;
  await assert.rejects(fetchGitHubMetadata('owner/repo', {
    fetchImpl: async () => ++calls === 1 ? json(repoData()) : json({ sha: 'bad SHA SECRET' }),
  }), { message: 'Unable to fetch public GitHub metadata.' });
});

test('unknown licenses are null and unused caller options cannot inject headers or hosts', async () => {
  for (const license of [null, { spdx_id: 'NOASSERTION' }, { spdx_id: 'SECRET\nvalue' }]) {
    let calls = 0;
    const metadata = await fetchGitHubMetadata('owner/repo', {
      headers: { Authorization: 'SECRET' }, host: 'https://untrusted.invalid', capture: 'SECRET',
      fetchImpl: async (url, options) => {
        assert.ok(url.startsWith('https://api.github.com/repos/owner/repo'));
        assert.equal(JSON.stringify(options).includes('SECRET'), false);
        return ++calls === 1 ? json(repoData({ license })) : json({ sha });
      },
    });
    assert.equal(metadata.license, null);
  }
});

test('enforces the deadline even when an injected fetch ignores cancellation', async () => {
  let signal;
  await assert.rejects(fetchGitHubMetadata('owner/repo', {
    timeoutMs: 20,
    fetchImpl: async (_url, options) => { signal = options.signal; return new Promise(() => {}); },
  }), { message: 'GitHub metadata request timed out.' });
  assert.equal(signal.aborted, true);
});

test('validates timeout and transport options without starting a request', async () => {
  for (const timeoutMs of [0, -1, Infinity, NaN, 1.5, 60_001]) {
    await assert.rejects(fetchGitHubMetadata('owner/repo', {
      timeoutMs, fetchImpl: () => { throw new Error('must not be called'); },
    }), { name: 'TypeError', message: 'GitHub metadata timeout must be between 1 and 60000 milliseconds.' });
  }
  await assert.rejects(fetchGitHubMetadata('owner/repo', { fetchImpl: null }), {
    name: 'TypeError', message: 'GitHub metadata fetch is unavailable.',
  });
});
