#!/usr/bin/env node
import { open, mkdir, writeFile, unlink, rmdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { sanitizeHar, sanitizeHttp } from '../src/sanitize.mjs';
import { fetchGitHubMetadata } from '../src/github.mjs';
import { renderReport } from '../src/report.mjs';

const MAX_BYTES = 20 * 1024 * 1024;
const HELP = `evidence-scrub 0.1.0
Conservative HAR / HTTP evidence cleaning. Node.js 22+, no dependencies.

Usage:
  node bin/evidence-scrub.mjs INPUT --out NEW_DIRECTORY [options]

Options:
  --out PATH           New output directory; existing paths are never overwritten
  --format har|http    Select format (otherwise detect HAR JSON or HTTP text)
  --keep-paths         Preserve URL paths; review identifiers before sharing
  --github OWNER/REPO  Add public repository revision metadata (network opt-in)
  --help              Show this help
  --version           Show version

Default processing is offline. No raw captures are copied into the bundle.
Output: sanitized.har or sanitized.http, report.md, summary.json,
and optional github.json. Maximum input size: 20 MiB.
Review all output before sharing; this is not a complete PII detector.
`;

async function readBounded(file) {
  const handle = await open(file, 'r');
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size > MAX_BYTES) throw new Error('Input must be a regular file of at most 20 MiB.');
    const chunks = [];
    let total = 0;
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      total += chunk.length;
      if (total > MAX_BYTES) throw new Error('Input exceeds the 20 MiB limit.');
      chunks.push(chunk);
    }
    if (total === 0) throw new Error('Input file is empty.');
    return Buffer.concat(chunks);
  } finally {
    await handle.close();
  }
}

async function main() {
  let args;
  try {
    args = parseArgs({ options: {
      out: { type: 'string' }, format: { type: 'string' },
      'keep-paths': { type: 'boolean', default: false },
      github: { type: 'string' }, help: { type: 'boolean' }, version: { type: 'boolean' },
    }, allowPositionals: true, strict: true });
  } catch {
    throw new Error('Invalid command line. Run with --help for usage.');
  }
  if (args.values.help) { process.stdout.write(HELP); return; }
  if (args.values.version) { process.stdout.write('0.1.0\n'); return; }
  if (args.positionals.length !== 1 || !args.values.out?.trim()) throw new Error('Provide one input file and a new --out directory. Run with --help.');
  if (args.values.format && !['har', 'http'].includes(args.values.format)) throw new Error('Format must be har or http.');
  let raw;
  try { raw = await readBounded(args.positionals[0]); } catch (error) {
    if (['Input must be a regular file of at most 20 MiB.', 'Input exceeds the 20 MiB limit.', 'Input file is empty.'].includes(error.message)) throw error;
    throw new Error('Cannot read the input file. Check that it exists and is accessible.');
  }
  const text = raw.toString('utf8').replace(/^\uFEFF/, '');
  const format = args.values.format ?? (text.trimStart().startsWith('{') ? 'har' : 'http');
  const options = { keepPaths: args.values['keep-paths'] };
  let result;
  try {
    result = format === 'har' ? sanitizeHar(JSON.parse(text), options) : sanitizeHttp(text, options);
  } catch {
    throw new Error('Input is not a supported HAR or HTTP capture. No output was written.');
  }
  let github;
  if (args.values.github) github = await fetchGitHubMetadata(args.values.github);
  const source = { sha256: createHash('sha256').update(raw).digest('hex'), bytes: raw.length };
  const evidenceName = format === 'har' ? 'sanitized.har' : 'sanitized.http';
  const files = [evidenceName, 'report.md', 'summary.json', ...(github ? ['github.json'] : [])];
  const summary = { tool: 'evidence-scrub', version: '0.1.0', format, source,
    policy: { keepPaths: options.keepPaths, networkOptIn: Boolean(github) }, stats: result.stats, files };
  const artifacts = new Map([
    [evidenceName, format === 'har' ? JSON.stringify(result.har, null, 2) + '\n' : result.text],
    ['report.md', renderReport({ format, source, stats: result.stats, policy: options, har: result.har, github })],
    ['summary.json', JSON.stringify(summary, null, 2) + '\n'],
  ]);
  if (github) artifacts.set('github.json', JSON.stringify(github, null, 2) + '\n');
  const directory = resolve(args.values.out);
  try { await mkdir(directory, { mode: 0o700 }); } catch {
    throw new Error('Output directory must be new and its parent must exist. Nothing was overwritten.');
  }
  const written = [];
  try {
    for (const [name, content] of artifacts) {
      const destination = resolve(directory, name);
      await writeFile(destination, content, { flag: 'wx', mode: 0o600 });
      written.push(destination);
    }
  } catch {
    for (const destination of written) await unlink(destination).catch(() => {});
    await rmdir(directory).catch(() => {});
    throw new Error('Could not write the bundle. Check destination permissions.');
  }
  process.stdout.write(`Created ${files.length} output files.\nFormat: ${format.toUpperCase()} | Entries: ${result.stats.entries} | Bodies removed: ${result.stats.bodiesRemoved}\n`);
  process.stdout.write(`Network: ${github ? 'public GitHub metadata only (explicit --github)' : 'none (offline)'}\nReview the generated report and sanitized capture before sharing.\n`);
}

main().catch((error) => {
  // Only controlled, content-free messages reach stderr. Never echo raw captures.
  const safe = typeof error?.message === 'string' && !error.message.includes('\n')
    ? error.message : 'Operation failed. No capture contents were printed.';
  process.stderr.write(`evidence-scrub: ${safe}\n`);
  process.exitCode = 1;
});
