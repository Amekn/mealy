# mealy-client

`mealy-client` is Mealy's stable, blocking Rust SDK for the authenticated owner API.
It reuses the exact versioned request and response types from `mealy-protocol`.

The client is intentionally fail-closed:

- clear-text HTTP is accepted only for literal IPv4 or IPv6 loopback addresses;
- HTTPS is required for any non-loopback endpoint;
- URL credentials, base paths, queries, and fragments are rejected;
- ambient HTTP proxies and redirects are disabled;
- bearer credentials are marked sensitive and redacted from debug output;
- typed JSON commands have a fixed 8 MiB pre-dispatch bound and use zeroizing source buffers;
- JSON responses have a configurable hard byte bound;
- every successful response and structured API error must declare the supported API version.

```rust,no_run
use mealy_client::{
    ClientError, MealyClient,
    protocol::LocalConnectionInfo,
};

fn daemon_is_ready(connection: &LocalConnectionInfo) -> Result<bool, ClientError> {
    let client = MealyClient::from_connection(connection)?;
    Ok(client.readiness()?.ready)
}
```

Use the OS-user-private connection descriptor emitted by `mealyd`; do not place bearer
tokens in source code, command-line arguments, logs, ambient environment, or shared
configuration. `from_connection` validates the descriptor's `v1` version, literal-loopback HTTP
origin with explicit port, and exact 32-byte base64url bearer. It intentionally does not open a
path: embedding applications must apply owner/private-mode and no-symlink checks before parsing
`$MEALY_HOME/connection.json`, or receive the descriptor through an equivalently trusted local
boundary.

The stable surface covers health and owner status, provider discovery, session creation,
search, titles, provider switching, checkpoints, forks, text/image admission and timelines; task
status, pause, resume, cancellation and recorded replay; approval resolution; governed extension
lifecycle and invocation; and webhook, Telegram, Discord, and Slack channel lifecycle. Methods
return the versioned DTO for successful responses and `ClientError` for local validation,
transport, compatibility, bounded-decoding, or structured daemon failures. Match specific
variants only when behavior needs to differ; the enum is non-exhaustive so compatible SDK releases
may add more precise failures.

Every v0.5-or-newer GitHub release publishes reproducible `mealy-domain`, `mealy-protocol`, and
`mealy-client` `.crate` archives with a pinned downstream-consumer lock, checksums, and retained
Sigstore provenance. The release workflow extracts those archives outside the workspace and
compiles a clean consumer through the public client surface before publication, then repeats the
same check from the downloaded public assets. Frozen v0.3.0, v0.4.0, and v0.5.0 daemon fixtures
prevent a compatible `v1` response or structured error from silently becoming unreadable. These
GitHub release packages are the supported v0.5 distribution boundary; they are intentionally not
represented as already published on crates.io.
