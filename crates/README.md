# Crates

Dependency direction:

```text
domain <- application <- infrastructure
domain <- protocol <- api -> application
         protocol <- client
```

`mealy-domain` has no infrastructure dependencies. `mealy-application` defines ports; infrastructure implements them. Transport DTOs do not become domain state. `mealy-testkit` is never a production dependency.
`mealy-client` is the independently reusable, fail-closed owner-API compatibility boundary and
depends only on versioned protocol DTOs plus its transport/serialization stack.

Add a crate only for a real compatibility, trust, build, or ownership boundary. Prefer an internal module otherwise.
