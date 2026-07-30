# mealy-observability

`mealy-observability` is Mealy's deliberately narrow OpenTelemetry boundary.
It exports only typed, allowlisted operational metadata and never accepts
prompts, responses, tool arguments, file paths, search terms, arbitrary log
fields, environment-derived resource attributes, or exporter headers.

The crate uses OTLP/HTTP protobuf with:

- HTTPS for remote collectors and clear-text HTTP only for literal loopback
  addresses with an explicit port;
- no ambient proxy, redirects, exporter environment variables, or credentials;
- fixed queue, batch, request, response, timeout, and export-interval bounds;
- only `service.name`, `service.version`, and Mealy's telemetry schema as
  resource attributes;
- fixed low-cardinality metric labels and bounded canonical IDs only on traces.

The daemon keeps telemetry disabled unless the owner explicitly passes
`--otlp-endpoint`.
