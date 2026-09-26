# CI policy

MoonVigil can apply a local severity gate, dependency-scope filter, and narrowly
scoped suppressions to a scan. Policy loading is opt-in: pass `--policy <file>`
to use a policy. The scanner never discovers `moonvigil.policy.json`
automatically. `--fail-on` and `--fail-on-scope` override the matching policy
settings for one invocation; either option can also be used alone.

```json
{
  "schema_version": "2",
  "fail_on": "high",
  "fail_on_scopes": ["runtime", "test"],
  "suppressions": [
    {
      "advisory_id": "MOONVIGIL-2026-0001",
      "package_name": "example/insecure-http",
      "version": "0.1.5",
      "reason": "Temporary compatibility exception while upgrading.",
      "expires_on": "2099-12-31"
    }
  ]
}
```

Policy schema v1 remains supported and defaults to all scopes, preserving its
previous behavior. Schema v2 requires a non-empty `fail_on_scopes` array.
Allowed scope names are `runtime`, `test`, `wbtest`, `other`, and
`unclassified`. A dependency with more than one recorded scope participates if
any one of those scopes is selected. Dependencies without scope metadata are
treated as `unclassified`. The special value `all` selects every scope and
must be the sole array entry.

The CLI override accepts a comma-separated list, for example
`--fail-on-scope runtime,test`. It replaces the policy's scope list for that
scan; `--fail-on-scope all` selects every scope. Duplicate, empty, or unknown
scope values are configuration errors. Scope selection affects only whether a
finding blocks: findings remain visible in terminal, JSON, and SARIF. Policy
summaries record the effective scopes and count of out-of-scope findings.

Allowed severity thresholds are `critical`, `high`, `medium`, `low`, and
`info`. A finding blocks when its severity equals or exceeds the configured
threshold and it is in a selected scope. Uncomparable versions are reported
but never block the gate.

Each suppression must identify an exact advisory ID, canonical package name,
and stable three-part version. The reason must be non-empty. `expires_on` must
be a real `YYYY-MM-DD` date and remains valid through that UTC date; an expired
rule makes the policy invalid. Duplicate exact-match keys are rejected.

Suppressed findings stay visible in all report formats. JSON records the
suppression on its finding and includes a policy summary. SARIF records an
external accepted suppression with its justification, following
[SARIF 2.1.0 §3.35](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).
Rules that match no finding generate a terminal warning and remain listed in
JSON/SARIF policy metadata; they do not suppress other packages or versions.

Without a baseline, exit codes retain their original meaning when no policy or
CLI threshold is supplied: `0` for no affected findings, `1` when affected
findings exist, and `2` for invalid arguments or inputs. With a policy, `1`
means at least one unsuppressed finding meets the gate; below-threshold and
suppressed findings do not block.

With `--baseline`, new findings and findings with changed advisory risk
evidence are eligible to block. A policy or `--fail-on` threshold is applied to
their current severity; existing findings and no-longer-detected snapshot
entries remain in reports but do not block. An active exact-match suppression
prevents a new or updated finding from blocking while retaining its evidence.
Without a policy or threshold, any new or updated affected finding blocks.
Invalid, malformed, or expired policies return `2` and prevent a scan report
from being produced.
