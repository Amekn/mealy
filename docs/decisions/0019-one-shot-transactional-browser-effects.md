# ADR 0019: One-shot transactional browser effects

Status: Accepted (2026-07-29)

## Context

Mealy's existing `browser.snapshot` boundary is intentionally read-only. Every call starts a
fresh Chrome Headless Shell profile inside Bubblewrap, restricts the host proxy to one configured
origin, blocks state-changing page APIs, permits only bounded GET/HEAD navigation, and returns
normalized evidence. It is suitable for research but cannot submit a POST form, upload a file, or
retain a response download produced by a transaction.

Treating a state-changing browser action as another read tool would bypass the durable effect
ledger. Retrying an interrupted form submission could duplicate an order, message, registration,
or payment. Letting the model select a form from a page only after approval would also create a
time-of-check/time-of-use gap: the page could replace its action, hidden values, or controls
between the owner's decision and dispatch.

Persistent personal browser profiles are a different trust boundary. They contain ambient login
authority, cookies, history, and potentially payment credentials. The initial transactional
profile must not quietly introduce that authority.

## Decision

Mealy adds `browser.transact` as a separately activated, high-risk, non-idempotent effect. It
supports one exact same-origin POST form transaction in a fresh browser profile. A confirmed
response may include either bounded rendered evidence or one bounded download artifact.

1. Browser installation and read-only browser authority remain unchanged. Transactional authority
   is a second stopped-daemon configuration flag, disabled by default and changed only through an
   explicit approved owner command. Disabling transactions leaves `browser.snapshot` available.
2. `browser.snapshot` exposes a bounded inert form catalog. Each POST form record contains an
   opaque form digest, canonical same-origin action, encoding, bounded public control metadata,
   and digests—not plaintext—for hidden values. Password controls, cross-origin actions,
   unsupported encodings, ambiguous forms, and forms outside configured web authority are not
   actionable.
3. One `browser.transact` proposal binds the initial URL, exact origin, form digest, submitted
   public control values, submitter identity, ordered upload artifact identities and digests,
   browser/runtime identity, output ceilings, deadline, and current task/run authority. The model
   cannot override the action URL, method, encoding, redirect policy, output directory, or
   recovery strategy. The initial URL must already be canonical; only absent optional collections
   are normalized, and schema 23 preserves that bounded raw-model-to-intent proof.
4. The owner sees and approves that complete immutable subject. Policy always requires exact
   authenticated approval. Transactional browser authority is never inferred from a read-only
   web/browser grant, Slack message, provider annotation, page text, or previously approved
   transaction.
5. After approval, a fresh isolated worker loads the initial URL under the ordinary read-only
   protections and reconstructs the form catalog. It must find exactly one form with the approved
   digest and must revalidate the action, controls, hidden-value digests, upload acceptance, and
   same-origin destination before preparing an attempt. Page drift fails before dispatch.
6. Uploads come only from already committed owner-private artifacts. The daemon rechecks each
   artifact row and blob digest, copies only the approved bytes into a fresh read-only sandbox
   mount, and enforces per-file, aggregate-byte, count, filename, and media-type ceilings. Owner
   filesystem paths and model-supplied host paths never enter the worker.
7. Before dispatch the worker creates a separate controlled blank target, closes the hostile
   source target, and reconstructs only the approved action, hidden values, public values,
   submitter, and upload controls. The attempt is marked running before that clean target receives
   one native submission. Page handlers are absent; popups, additional state-changing
   fetch/XHR/beacon requests, service workers, cross-origin redirects, secondary submissions, and
   persistent storage are denied.
8. A success requires one observed matching POST request plus a bounded same-origin response.
   Evidence binds the approved request-contract digest, response status, final URL, form digest,
   browser/runtime identity, and either normalized rendered output or an atomically published
   download artifact. Remote response bodies, filenames, media types, and page text remain
   untrusted evidence.
9. The tool uses `NeverRetry`. A crash, cancellation, timeout, proxy failure, browser failure, or
   daemon restart after the running boundary produces an unknown outcome and parks for
   authenticated evidence-bound reconciliation. It never silently resubmits. Definite
   pre-dispatch rejection may prepare a fresh attempt only after the ordinary run resumes and
   proposes a new owner-approved transaction.
10. Recorded replay validates the complete intent, approval, attempt, request/response evidence,
    artifact graph, and blob digest without starting a browser or making a network call.
11. Every call uses a fresh profile and receives no ambient credentials. Cookies obtained during
    that same call may participate only when their exact browser-mediated form submission remains
    inside the approved origin. Persistent/personal profiles, arbitrary JavaScript execution,
    payments, WebAuthn, extension wallets, cross-origin identity flows, and unattended transaction
    batching require separate future contracts.

## Consequences

- Transactional actions reuse the existing approval, attempt, recovery, reconciliation, artifact,
  timeline, and replay machinery.
- Owners can retain the safer research profile while declining all state-changing browser
  authority.
- Exact form-digest revalidation prevents page drift from changing what an approval authorizes.
- Fresh profiles make the first release useful for public or same-call forms, but do not support
  sites that require an existing logged-in browser session.
- A transaction whose external result cannot be proven remains visibly unresolved instead of
  being retried.
- The browser conformance suite must cover form-catalog injection, page drift, hidden-value drift,
  upload substitution, extra POST attempts, cross-origin redirects, crash-after-dispatch,
  bounded downloads, reconciliation, and execution-free replay.

## Alternatives considered

### Extend `browser.snapshot` with a submit option

Rejected because a read-only retry contract cannot safely represent a non-idempotent POST and has
no exact approval or unknown-outcome state.

### Approve only the destination origin

Rejected because an origin-wide approval would let page drift change the form action, hidden
values, submitted controls, and transaction meaning.

### Retry when no response was observed

Rejected because lack of a response does not prove the server failed to commit the transaction.

### Reuse the owner's ordinary browser profile

Rejected for the initial contract because ambient cookies and saved credentials would grant
authority that is absent from the task ceiling and approval subject.

### Allow arbitrary page JavaScript after approval

Rejected because one approved click could then trigger unrelated background writes, popups, or
cross-origin actions that are not independently represented in the durable effect ledger.
