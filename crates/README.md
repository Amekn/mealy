# Crates

Dependency direction:

```text
domain <- application <- infrastructure
domain <- protocol <- api -> application
         protocol <- client
         observability -> OpenTelemetry/OTLP
```

`mealy-domain` has no infrastructure dependencies. `mealy-application` defines ports; infrastructure implements them. Transport DTOs do not become domain state. `mealy-testkit` is never a production dependency.
`mealy-client` is the independently reusable, fail-closed owner-API compatibility boundary and
depends only on versioned protocol DTOs plus its transport/serialization stack.
`mealy-observability` is a separate typed privacy boundary rather than a general log bridge. It
accepts only fixed allowlisted operational records and owns the bounded OTLP/HTTP protobuf
transport, so private application fields cannot enter telemetry accidentally.

Add a crate only for a real compatibility, trust, build, or ownership boundary. Prefer an internal module otherwise.
