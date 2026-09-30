# Contributing

Thank you for improving evidence quality, safety or usability. Start with a
small issue describing the problem and a synthetic reproduction. Significant
policy or interface changes should be discussed before implementation.

## Local checks

Use Node 22.13+, Python 3.11+, Git and ripgrep. From the checkout:

```bash
npm ci
npm run build
npm run lint
npm test
python3 -m unittest discover -s runtime -p 'test_*.py' -q
python3 -m compileall -q runtime
npm run check:public
git diff --check
```

Use an isolated `CODEX_HOME` for manual installation tests. Never point fixtures
at your real authentication or private state. The ordinary suite is offline and
uses mocked providers. Do not turn live Jev or native Codex comparisons into CI
tests, and never automatically retry a quota failure.

## Pull request contract

- Preserve model choice, native permissions, ownership and exact recovery rules.
- Add a regression that fails before your fix; keep protected entrypoints aligned.
- Retain omitted evidence references, source hashes and honest coverage notices.
- Preserve spending history and uncertain reservations through upgrades.
- Keep API keys, conversations, local paths and private reports out of patches.
- Document changes to defaults, MCP fields, private state or billing behavior.
- Distinguish retrieval-byte measurements from native-token or invoice savings.

Use clear, scoped commits. New code is contributed under this project's MIT
license; retain upstream attribution. Contributors are credited in Git history.
See SECURITY.md for confidential disclosures and CODE_OF_CONDUCT.md for conduct.
