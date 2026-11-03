const cell = (value) => String(value ?? '').replace(/[\r\n\t]/g, ' ').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/[\\|`*_{}\[\]]/g, '\\$&').slice(0, 1000);

export function renderReport({ format, source, stats, policy, har, github }) {
  const lines = [
    '# Evidence review bundle', '',
    'Generated locally with evidence-scrub 0.1.0. Review all output before sharing.', '',
    '## Provenance', '',
    `- Input format: ${format === 'har' ? 'HAR' : 'HTTP text'}`,
    `- Input bytes: ${source.bytes}`,
    `- Input SHA-256: \`${source.sha256}\``,
    '- The original capture is not included.', '',
    '## Redaction policy', '',
    '- Request and response bodies: removed.',
    '- Cookie values and credential headers: removed or replaced.',
    '- URL origins, query parameters, and fragments: redacted.',
    `- URL paths: ${policy.keepPaths ? 'PRESERVED by explicit --keep-paths; inspect for identifiers and secrets.' : 'redacted by default.'}`,
    '- Unknown HAR fields and unrecognized header names: discarded or replaced.',
    '- This is a conservative transformation, not a complete detector of personal information.', '',
    '## Transformation counts', '',
    '| Category | Count |', '| --- | ---: |',
    ...Object.entries(stats).map(([key, value]) => `| ${cell(key)} | ${Number.isFinite(value) ? value : 0} |`), '',
  ];
  if (format === 'har') {
    lines.push('## Sanitized request overview', '', '| Method | Status | URL |', '| --- | ---: | --- |');
    for (const entry of har.log.entries.slice(0, 40)) {
      lines.push(`| ${cell(entry.request.method)} | ${entry.response.status} | ${cell(entry.request.url)} |`);
    }
    if (har.log.entries.length > 40) lines.push('', 'Only the first 40 entries are listed here; see sanitized.har for the complete transformed capture.');
    lines.push('');
  }
  if (github) {
    lines.push('## Optional public GitHub metadata', '',
      `- Repository: [${cell(github.repository)}](${github.url})`,
      `- Default branch at collection time: ${cell(github.defaultBranch)}`,
      `- Commit: \`${github.commitSha}\``,
      `- License identifier: ${cell(github.license ?? 'not reported')}`,
      '- Only the selected public repository name was sent to GitHub. Capture contents were not sent.',
      '- Metadata identifies a public revision; it does not prove that the capture came from that revision.', '');
  }
  lines.push('## Finding draft', '',
    '**Title:** [describe the observed behavior]', '',
    '**Authorized scope and tested version:** [fill in]', '',
    '**Preconditions:** [fill in]', '',
    '**Reproduction steps:**', '',
    '1. [fill in a minimal, authorized reproduction]',
    '2. [describe the observed result]', '',
    '**Expected behavior:** [fill in]', '',
    '**Observed impact:** [state only what was demonstrated]', '',
    '**Limitations and controls:** [fill in]', '',
    '**Suggested remediation:** [fill in]', '',
    '## Before sharing', '',
    '- Inspect retained methods, statuses, timestamps, MIME types, timing, and sizes.',
    '- If paths were preserved, review every path and identifier.',
    '- Add context manually without restoring credentials or private captures.',
    '- Share only with the intended recipient and within your authorization.', '');
  return lines.join('\n');
}
