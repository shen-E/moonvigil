# CI policy

MoonVigil can apply a local severity gate and narrowly scoped suppressions to a
scan. Policy loading is opt-in: pass `--policy <file>` to use a policy. The
scanner never discovers `moonvigil.policy.json` automatically. `--fail-on`
overrides a policy's threshold for one invocation; it can also be used alone.

```json
{
  "schema_version": "1",
  "fail_on": "high",
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

Allowed thresholds are `critical`, `high`, `medium`, `low`, and `info`. A
finding blocks when its severity equals or exceeds the configured threshold.
Uncomparable versions are reported but never block the gate.

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

Without a policy or CLI threshold, exit codes retain their original meaning:
`0` for no affected findings, `1` when affected findings exist, and `2` for
invalid arguments or inputs. With a policy, `1` means at least one unsuppressed
finding meets the gate; below-threshold and suppressed findings do not block.
Invalid, malformed, or expired policies return `2` and prevent a scan report
from being produced.
