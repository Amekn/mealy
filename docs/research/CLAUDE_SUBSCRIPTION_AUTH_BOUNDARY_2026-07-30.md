# Claude subscription authentication boundary

Status: accepted on 2026-07-30

## Decision

Mealy does not offer Claude.ai Free, Pro, Max, Team, or Enterprise subscription login, import a
Claude Code OAuth token, or route Mealy provider requests against Claude subscription rate limits.
Legacy Claude-subscription command names and configuration identities remain fail-closed migration
sentinels: they reject the route before home mutation, credential access, or client execution.

This is a provider-policy boundary, not a missing protocol adapter. Mealy continues to support the
independently implemented Anthropic Messages API adapter. Users who do not want a separately billed
Anthropic API key can instead select strict-free OpenRouter, a reviewed custom endpoint, a local
endpoint, or use the official Claude Code product directly.

## Primary-source review

The review used current first-party Anthropic material rather than third-party implementations:

- The [Claude Agent SDK overview](https://code.claude.com/docs/en/agent-sdk/overview) says that,
  without prior Anthropic approval, third-party developers may not offer Claude.ai login or
  Claude.ai plan rate limits in their products. It directs third-party agent products to API-key
  authentication instead.
- The [Agent SDK quickstart](https://code.claude.com/docs/en/agent-sdk/quickstart) repeats that
  boundary next to its supported Anthropic API and cloud-provider authentication methods.
- Anthropic's [Consumer Terms](https://www.anthropic.com/legal/consumer-terms) disallow automated
  or non-human access except through an Anthropic API key or where Anthropic otherwise explicitly
  permits it.
- Anthropic's
  [Claude Code authentication documentation](https://code.claude.com/docs/en/authentication)
  explicitly permits Claude Code to create a subscription-backed `CLAUDE_CODE_OAUTH_TOKEN` for its
  own CI pipelines and scripts. That first-party Claude Code permission does not override the
  separate third-party-product restriction in the Agent SDK documentation.
- The
  [Pro and Max setup guidance](https://support.claude.com/en/articles/11145838-use-claude-code-with-your-pro-or-max-plan)
  confirms that those subscriptions include official Claude Code usage, while Anthropic's
  [billing guidance](https://support.claude.com/en/articles/9876003-i-subscribe-to-a-paid-claude-ai-plan-why-do-i-have-to-pay-separately-for-api-usage-on-console)
  confirms that a Claude subscription does not include Anthropic API usage.

The combined result is precise: a user may authenticate Anthropic's own Claude Code client with a
subscription, including its documented script mode, but Mealy may not present that subscription as
a Mealy provider or plan limit without prior Anthropic approval.

## Security and product consequences

Mealy therefore must not:

1. read or copy Claude Code's credential store;
2. ask the user to paste a Claude subscription OAuth token;
3. invoke `claude setup-token` on the user's behalf;
4. advertise Claude subscription usage as a Mealy provider route;
5. use the official CLI or Agent SDK as a generic subscription-backed inference proxy; or
6. silently reinterpret a legacy Claude-subscription configuration as an Anthropic API route.

Keeping the legacy names as explicit rejected identities is safer than deleting them. Old homes
receive a deterministic remediation error instead of accidentally dispatching with a different
credential, billing boundary, or provider identity. Process tests prove both public legacy command
paths fail before configuration publication and before a fixture client can execute.

This boundary does not weaken provider neutrality. Anthropic Messages remains a native provider
protocol, and the same durable attempt, usage, retry, cancellation, approval, settlement, and replay
contracts apply to it as to other supported adapters.

## Reconsideration criteria

The decision can be revisited only if at least one of the following becomes available:

- Anthropic publishes a generally available third-party subscription-authentication contract;
- Anthropic gives Mealy explicit written approval covering Claude.ai login and plan rate limits; or
- Anthropic provides a new first-party gateway whose terms expressly support this use.

Any future implementation would still require a threat-model update, credential-containment review,
fail-closed migration, adversarial process tests, live acceptance, and a fresh exact-binary
qualification cycle. A change in the Claude Code CLI alone is not sufficient.
