# Changelog

## 0.1.0

Initial release.

- Local CLI for HAR captures and individual raw HTTP request or response messages.
- Conservative reconstruction of supported metadata, with bodies and HAR cookie arrays removed and cookie header values redacted.
- URL origins, query data, and fragments redacted; URL paths redacted by default.
- Explicit `--keep-paths` option for retaining URL pathnames during review.
- Evidence bundle with a redacted capture, Markdown report, JSON summary, and source SHA-256 digest.
- Optional public GitHub repository metadata lookup through `--github owner/repo`, without transmitting capture contents.
- Input limit of 20 MiB and refusal to reuse an existing output directory.
- Synthetic examples, automated tests, and documentation in English and Brazilian Portuguese.

Review every output before sharing. This release is not a complete detector of secrets or personal data.
