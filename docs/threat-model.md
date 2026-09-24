# Threat model and boundaries

MoonVigil reads modern moon.mod / moon.pkg manifests, legacy JSON manifests,
and an operator-supplied local advisory database. Module manifests provide
direct dependency versions; package imports annotate runtime/test usage.
It does not execute application code, resolve packages from the network, or
send dependency metadata anywhere. A finding means that a declared dependency
version falls inside a locally defined range; it is not proof that a reachable
exploit exists in the application.

The scanner deliberately reports unparsable versions separately. This prevents
branches, tags, malformed strings, and non-SemVer schemes from being silently
classified as either safe or vulnerable. Operators are responsible for the
authenticity and freshness of `advisories.json`.

The WSL demonstration may download MoonBit only when the build toolchain is
absent. That bootstrap step is separate from scanning: the scanner itself reads
only local manifests and a local advisory database, and never executes code in
the scanned project.
