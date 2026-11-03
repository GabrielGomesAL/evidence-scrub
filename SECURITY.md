# Security policy

## Reporting a vulnerability

Send a private report to **ggoalmeidaa@gmail.com** if you find a security problem in `evidence-scrub`, including a redaction bypass that preserves data the documented policy promises to remove.

Include:

- The version or commit you tested and your Node.js version.
- The command and options you used.
- Expected and observed behavior.
- A minimal **synthetic** HAR or HTTP reproduction, with invented domains, identifiers, and secrets.
- The relevant output excerpt, after reviewing it yourself.

Do not attach production captures, credentials, access tokens, session cookies, private documents, or another person's personal data. An invented value that demonstrates the problem is enough. Avoid posting an unremediated disclosure in a public issue.

The maintainer will review the report and coordinate a response. There is no guaranteed response time or bounty program.

## Supported versions

Security fixes target the latest released version and the default branch. Update before checking whether a reported problem still applies.

## Intended behavior and boundaries

`evidence-scrub` reads a local capture and writes a new evidence bundle. Its conservative policy drops bodies and HAR cookie arrays, redacts cookie header values, absolute URL origins, query data, and fragments, and removes paths by default. `--keep-paths` explicitly retains URL pathnames.

The optional `--github owner/repo` lookup contacts the public GitHub API for repository metadata. It does not send the input capture or generated evidence.

The tool is not a complete detector of secrets or personal data. Sensitive information may appear in supported metadata or in a pathname retained with `--keep-paths`. Human review of every output is part of the intended workflow. The presence of a report or summary does not establish that evidence is safe to share or that disclosure is authorized.

For ordinary parser errors, usability problems, and documentation corrections, use the bug-report issue template with synthetic input.
