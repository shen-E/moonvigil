# Contributing

Please keep each change focused and include tests for behavior changes.

Before opening a pull request, run:

```sh
moon fmt --check
moon check --target native --warn-list +73
moon test --target native
moon build --target native
python scripts/acceptance.py
```

Do not add private advisory feeds, credentials, generated build output, or
machine-specific paths to commits.

The Python script uses only the standard library. It runs the four checks
above, builds the release executable, and verifies the native CLI against
fixtures and temporary projects. Keep behavior checks in that script so local
validation and CI exercise the same assertions. Results under
`.acceptance-output/` are generated evidence and are ignored by Git.
