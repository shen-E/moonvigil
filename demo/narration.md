# One-minute demonstration script

Use a standard Ubuntu terminal at a readable font size. Record only relative
paths and real command output; prepare the MoonBit toolchain before recording.

1. **00–08 seconds — scope.** Start in an Ubuntu 24.04 WSL shell. Explain that
   MoonVigil reads local MoonBit JSON manifests against a local advisory file;
   it does not contact a vulnerability service or execute the target project.
2. **08–18 seconds — quality gate.** Run the db validate command against the
   demo advisory file, then start the WSL demonstration script. Mention that
   invalid advisory data is rejected before scanning.
3. **18–34 seconds — terminal evidence.** Point out the two affected
   dependencies: severity, affected range, fixed version, manifest source, and
   reference. Show that the branch dependency is uncomparable, not safe.
4. **34–48 seconds — machine-readable evidence.** Open the generated JSON,
   then SARIF report. Explain that both retain the same advisory and dependency
   evidence for CI.
5. **48–60 seconds — inventory and boundary.** Open the SBOM, state that the
   inventory is reproducible, then close with the offline boundary: no network
   advisory lookup, lock-file inference, or source-code SAST.
