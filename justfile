default: check test

fmt:
    moon fmt

fmt-check:
    moon fmt --check

check:
    moon check --target native --warn-list +73

test:
    moon test --target native

build:
    moon build --target native

validate-db:
    moon run cmd/main --target native -- db validate advisories.json

demo:
    moon run cmd/main --target native -- scan fixtures/affected --db advisories.json
