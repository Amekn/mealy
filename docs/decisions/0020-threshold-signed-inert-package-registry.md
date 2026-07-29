# ADR 0020: Threshold-signed inert package registry

Status: Accepted (2026-07-29)

## Context

Mealy already installs data-only skill packages and digest-pinned out-of-process extensions. Local
inspection retains complete package bytes, rejects undeclared files and symlinks, validates
manifests without importing code, and separates installation from an exact owner grant. Extension
upgrade disables prior authority and requires a fresh health proof and immutable grant.

Those controls do not provide public discovery, publisher identity, dependency locking,
withdrawal, or protection from a registry serving an older catalog. Trusting an HTTPS response or
a mutable version tag would let a mirror substitute bytes. Trusting only a publisher signature
would not let a registry withdraw a compromised release, constrain which key represents a
publisher, or prevent a freeze/rollback attack. Conversely, treating registry inclusion as owner
approval would bypass Mealy's least-authority lifecycle.

Current supply-chain practice separates these concerns. The Update Framework uses out-of-band root
trust, role/key thresholds, expiring metadata, and monotonic versions to limit key compromise,
rollback, and freeze attacks. OCI descriptors bind content by media type, byte length, and digest
before it is consumed. Sigstore/in-toto distinguish artifact identity and publisher/build
provenance from the policy that decides whether that identity is acceptable.

The design was checked against the current
[TUF specification](https://theupdateframework.github.io/specification/latest/), the
[HTTP semantics standard](https://www.rfc-editor.org/rfc/rfc9110), and IANA's
[IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/) and
[IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/) special-purpose address
registries. Mealy adopts TUF's separation of initial root trust, expiring monotonic metadata, and
hash/length-bound targets, while retaining its own smaller registry roles and least-authority
activation model.

## Decision

Mealy introduces a versioned registry contract in independent, inert layers.

1. A registry begins with an owner-configured, out-of-band trust root. The root binds one registry
   identity, a monotonic root version, an expiry, an ordered Ed25519 key set, and a threshold.
   Network-delivered metadata cannot bootstrap or replace that trust.
2. A bounded registry snapshot is signed by the configured threshold. It binds a strictly
   monotonic snapshot version, generation time, expiry of at most seven days, ordered publisher
   identities and keys, and ordered immutable release targets. A lower version is rejected. New
   bytes at an already accepted version are treated as equivocation. An exact same envelope is
   idempotent.
3. Each release target is a media-type/size/SHA-256 descriptor of a complete signed release
   envelope. The signed snapshot can withdraw a target with a bounded human-facing reason while
   retaining its immutable identity for audit.
4. Release metadata is independently signed by the threshold of publisher keys authorized in the
   verified snapshot. It binds registry/package/publisher identity, package class, exact version,
   host-API compatibility, manifest and archive descriptors, an exact dependency closure, and
   publication time.
5. Dependency locks name an exact package class, version, and signed-release-envelope digest. A
   missing, withdrawn, type-mismatched, or digest-mismatched dependency fails before package
   download or extraction.
6. Signed envelopes carry exact payload bytes as canonical unpadded base64url. Signatures cover a
   fixed domain-separation string, a zero delimiter, and those exact decoded bytes. Verification
   does not reserialize JSON or rely on a custom canonical-JSON dialect. Key IDs are SHA-256
   digests of raw public-key bytes, signatures are distinct and sorted, and strict Ed25519
   verification rejects weak/malleable encodings.
7. Snapshot and release inspection perform no network access, package extraction, code execution,
   configuration mutation, staging, or grant. Registry text never becomes model instructions.
   Discovery therefore creates no runtime authority.
8. After separately bounded download, the package inspector rechecks the manifest descriptor and
   complete archive inventory before existing skill/extension lifecycle code may see content.
   Update review computes a deterministic
   permission diff: extension capability contracts, logical filesystem access, exact network
   destinations, opaque secret references, process spawning, and data-only skill tool references.
   Any changed surface requires fresh owner review; installation never inherits an old grant.
9. Initial roots are inspected from exact owner-supplied out-of-band JSON. Network-delivered
   rotation accepts only the exact next root version when one envelope satisfies both the current
   and candidate key thresholds. Schema 24 atomically retains immutable exact root/snapshot bytes
   plus revision-fenced heads. Snapshot acceptance reloads the active root and durable prior head
   inside the write transaction, repeats verification, and rejects stale writers, rollback, root
   regression, and same-version equivocation across process restart. Replaying the exact
   already-active rotation envelope is current-threshold verified and idempotent.
10. The stopped-home CLI accepts only bounded no-follow root/rotation/snapshot files, requires
    explicit approval for durable changes, takes the daemon's exclusive home lock, and refuses
    database creation or implicit migration. It exposes root/snapshot inspection, root
    bootstrap/rotation, status, and monotonic snapshot acceptance while withholding key bodies and
    signed payloads from summary output. File-based operations remain offline.
11. Mirror transport accepts one canonical owner-selected HTTPS directory but never arbitrary
    request paths. Snapshot retrieval uses only `metadata/snapshot.json`; immutable content uses
    only `objects/sha256/DIGEST`, where `DIGEST` came from authenticated metadata. The adapter
    rejects credentials, query/fragment ambiguity, HTTP, redirects, proxies, referrers, ambient
    authentication, content decoding, non-public or mixed DNS answers, connected-peer drift,
    non-200 responses, media-type drift, timeouts, and body overflow. DNS is resolved once and
    pinned into TLS establishment. Snapshot fetch/refresh retains the stopped-home lock and repeats
    the complete local trust/anti-rollback verification before output or an approved atomic
    acceptance. Refresh requires the exact envelope digest printed by the reviewed fetch, so a
    mutable-current change between review and apply fails closed. Content requests additionally
    verify signed exact media type, length, and SHA-256 before parsing.
12. Schema 25 retains one exact publisher-signed release as immutable evidence only after the
    active root and current snapshot are revalidated at the acceptance clock. The immediate
    transaction repeats publisher threshold, withdrawal, exact dependency closure, host
    compatibility, and descriptor verification, and binds the first admitting root/snapshot and
    host API revision. Exact replay is idempotent; registry/package/version aliasing conflicts.
    Root rotation requires a newly authorized snapshot before admission, and later withdrawal
    blocks new acceptance without deleting history. `release-fetch` and `release-accept` use an
    exact review digest; `release-status` is offline.
13. `package-fetch` starts only from accepted release evidence, revalidates that exact envelope
    against the current unexpired snapshot and active root, and retrieves only its signed manifest
    and archive descriptors. Manifest identity is bound to package/publisher/version/host range.
    Archive inspection is in-memory and extraction-free: exact deterministic USTAR framing,
    regular-file-only type, canonical UTF-8 relative paths, zero ownership/time/padding, strict
    `0644`/declared-executable `0755` modes, exact manifest/inventory/content digests and sizes, and
    two terminal zero blocks. Links, devices, FIFOs, sparse/PAX/GNU extensions, duplicates,
    traversal, undeclared content, and trailing bytes fail closed. Output reports requested
    authority but creates no durable package row, file, stage, install, activation, or grant.
14. Download resumption, durable manifest/archive evidence, package publication tooling, staged
    activation, withdrawal propagation to installed revisions, and rollback orchestration remain
    later slices. Mirror retrieval still performs no package execution and grants no runtime
    authority.

## Consequences

- A compromised mirror cannot substitute an artifact without breaking an exact signed descriptor.
- A compromised publisher key alone cannot rewrite registry history or silently unwithdraw a
  release; a compromised registry key alone cannot forge a publisher release.
- Expiry and monotonic state turn stale catalogs into visible unavailability instead of silently
  accepted freeze/rollback.
- Registry discovery remains useful offline once exact metadata is available, but an expired
  snapshot cannot authorize a new install.
- Root, snapshot, and publisher-release history are append-only canonical evidence; only small
  root/snapshot head rows may advance, under exact monotonic SQLite triggers and application
  compare-and-swap fences.
- The first slices add verification, durable anti-rollback/release evidence, bounded mirror and
  package retrieval, and extraction-free review primitives, not a public marketplace or automatic
  update path.
- Ed25519 verification adds a small audited cryptographic dependency to the production graph and
  remains subject to the existing advisory, license, duplicate-version, SBOM, and provenance
  gates.
- The tar parser is used only for header interpretation and deterministic fixture construction;
  Mealy does not call its filesystem extraction helpers for registry content.

## Alternatives considered

### Trust HTTPS and package checksums

Rejected because a compromised registry or mirror could replace both mutable metadata and the
checksum, replay an older catalog, or erase withdrawal state.

### Accept a publisher signature as the only trust decision

Rejected because publisher identity still needs an out-of-band policy, key rotation, withdrawal,
expiry, and anti-rollback state. Signature validity answers who signed bytes, not whether the owner
currently authorizes installation.

### Sign reserialized JSON

Rejected because different serializers, field ordering, number handling, or future parser behavior
could cause inconsistent signature meaning. Exact payload bytes have one unambiguous identity.

### Execute package metadata to discover permissions

Rejected because discovery would then run code before the owner sees its requested authority.
Manifests and registry metadata remain strict data.

### Automatically preserve an existing grant across upgrade

Rejected because code, schemas, effect classification, network, secrets, mounts, or process
authority may change even when the package name is unchanged.
