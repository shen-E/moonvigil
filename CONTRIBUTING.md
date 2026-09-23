# Contributing

Please keep each change focused and include tests for behavior changes.

Before opening a pull request, run:

```sh
moon fmt --check
moon check --target native --warn-list +73
moon test --target native
moon build --target native
```

Do not add private advisory feeds, credentials, generated build output, or
machine-specific paths to commits.
