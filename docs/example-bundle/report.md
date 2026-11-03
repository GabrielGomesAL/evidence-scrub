# Evidence review bundle

Generated locally with evidence-scrub 0.1.0. Review all output before sharing.

## Provenance

- Input format: HAR
- Input bytes: 1863
- Input SHA-256: `2339cf069d314a484e0dda4915061834460ccc342d97d6b905ada80bd7ea3d40`
- The original capture is not included.

## Redaction policy

- Request and response bodies: removed.
- Cookie values and credential headers: removed or replaced.
- URL origins, query parameters, and fragments: redacted.
- URL paths: redacted by default.
- Unknown HAR fields and unrecognized header names: discarded or replaced.
- This is a conservative transformation, not a complete detector of personal information.

## Transformation counts

| Category | Count |
| --- | ---: |
| entries | 1 |
| urls | 1 |
| queryValues | 2 |
| headersRedacted | 3 |
| headersRemoved | 0 |
| cookiesRemoved | 3 |
| bodiesRemoved | 2 |
| pathsRedacted | 1 |

## Sanitized request overview

| Method | Status | URL |
| --- | ---: | --- |
| POST | 200 | https://redacted.invalid/\[REDACTED\_PATH\]?param1=\[REDACTED\] |

## Finding draft

**Title:** [describe the observed behavior]

**Authorized scope and tested version:** [fill in]

**Preconditions:** [fill in]

**Reproduction steps:**

1. [fill in a minimal, authorized reproduction]
2. [describe the observed result]

**Expected behavior:** [fill in]

**Observed impact:** [state only what was demonstrated]

**Limitations and controls:** [fill in]

**Suggested remediation:** [fill in]

## Before sharing

- Inspect retained methods, statuses, timestamps, MIME types, timing, and sizes.
- If paths were preserved, review every path and identifier.
- Add context manually without restoring credentials or private captures.
- Share only with the intended recipient and within your authorization.
