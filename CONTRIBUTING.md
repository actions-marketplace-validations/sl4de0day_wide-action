# Contributing to Wide Action

Contributions that improve scanning precision, SARIF/PR reporting, OSV SCA coverage, or AI remediation reliability are welcome.

## Development Workflow

```bash
npm install
npm test
npm run build
```

When updating embedded rules from a sibling `wide-rules` checkout:

```bash
npm run sync:bundle
npm test
npm run build
```

Ensure both `npm test` and `npm run build` succeed cleanly and include updated `dist/` artifacts when source files change. Avoid using emojis in code, comments, PR titles, or documentation.
