# Contributing

Useful contributions make evidence easier to inspect while keeping the redaction policy clear and testable. Good starting points include synthetic parser fixtures, regression tests for redaction, clearer reports, and documentation corrections.

## Work locally

Use Node.js 22 or later. No package installation is required.

```sh
node --test
```

To inspect the synthetic demo, choose an output directory that does not exist:

```sh
node bin/evidence-scrub.mjs fixtures/demo.har --out ./clean-demo
```

Keep generated bundles and real captures outside commits. The repository ignores HAR and HTTP captures by default, with an exception for explicitly synthetic files under `fixtures/`.

## Issues and examples

Use invented domains such as `example.invalid`, invented names, and obviously fake credentials. Do not upload a real capture and rely on this tool to make it suitable for a public issue. Review text, screenshots, reports, paths, and attachments before submitting them.

For security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Pull requests

- Describe the concrete behavior before and after the change.
- Keep the change focused on one useful improvement.
- Include a synthetic regression case when changing parsing or redaction behavior.
- Check HAR and raw HTTP behavior when the change affects both formats.
- Keep the default output conservative. Preserving more information needs an explicit, documented choice.
- Keep core processing local. Network operations must be optional, documented, and separate from capture contents.
- Update both README languages when behavior or usage changes.
- Run `node --test` and report what you checked.

Do not add credentials or production evidence to tests, logs, issue descriptions, or commit history. Test output should be reproducible without access to a private account or service.

## License

By contributing, you agree that your contribution may be distributed under this repository's [MIT license](LICENSE). Only contribute material you have the right to share.
