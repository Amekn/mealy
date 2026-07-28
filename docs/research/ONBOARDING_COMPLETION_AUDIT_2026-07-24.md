# Competitor-grade onboarding completion audit

Observed: 2026-07-24 (Pacific/Auckland)

Completion recheck: 2026-07-28 (Pacific/Auckland)

Standard: the ten-item definition in
[PRODUCT_OPERATIONS_BENCHMARK_2026-07-24.md](PRODUCT_OPERATIONS_BENCHMARK_2026-07-24.md#definition-of-competitor-grade-onboarding)

This audit separates implemented source behavior from a publicly usable production release. A
green pull-request check proves the exact source revision it tested; it does not prove that the
revision is merged, tagged, published, or installed by an ordinary user. “Source-ready” below
therefore remains distinct from “publicly complete.”

At the completion recheck, the onboarding goal is publicly complete for Mealy's documented Linux
contract. Immutable stable
[`v0.2.1`](https://github.com/Amekn/mealy/releases/tag/v0.2.1) points to exact release commit
`b8e9d8576f228fd43a523ad38704a86b4630b115`. Its promoted daemon is byte-identical to soaked
revision `eec96a8f91718679b258c754e00f04056e629430`, which completed 86,425.487 seconds,
19,248 turns, 48 hard restarts, 53 interrupted-provider recoveries, SQLite integrity `ok`, and
zero residue. Exact protected-main CI, owner-reviewed strictly free OpenRouter acceptance, the
private custom endpoint, native packaging, attestations, public rootless installation, and the
install-to-first-chat journey all passed.

The tag workflow published the immutable release and signed repositories, but its first
repository-verifier attempt raced the newly deployed manifest and ended red after publication.
That negative result is retained. The verifier was repaired through protected main CI, then
[`v0.2.1` post-publication acceptance](https://github.com/Amekn/mealy/actions/runs/30324688498)
verified the exact signed and attested manifest and installed the exact release through APT on
Ubuntu x86-64 and Debian ARM64, DNF on Fedora x86-64 and ARM64, and Pacman on Arch x86-64. The
live [version-matched repository page](https://amekn.github.io/mealy/) now carries the supported
install, onboarding, continuation, diagnostics, update, and independent trust-verification path.

## Requirement evidence

| # | Ordinary-user outcome | Authoritative evidence | Current conclusion |
| --- | --- | --- | --- |
| 1 | Obtain an attested package without Rust | `packaging/install-release.sh` verifies exact release-workflow Sigstore bundles and complete checksums; native packages and `packaging/build-signed-linux-repositories.sh` cover APT, DNF, and Pacman; package/repository clean-install tests cover every qualified family. | **Publicly complete.** v0.2.1 has attested rootless archives and signed APT, DNF, and Pacman repositories; post-publication acceptance installed the exact release on every qualified family/architecture lane. |
| 2 | Run one guided command | Bare terminal `mealyctl` selects onboarding for an unconfigured private home and a new chat for a configured home; `mealyctl onboard` composes provider selection, reviewed activation, service installation/start, health, `doctor`, and chat. A PTY process proof covers both bare-command journeys and proves non-terminal use fails without mutation. The verified interactive bootstrap hands off to the same installed command. The implicit private home is the stable `$HOME/.mealy`, not a directory-relative `.mealy`, and a process proof reuses it after changing working directories. | **Publicly complete.** Public release acceptance installed the downloaded payload and exercised the same one-command guided journey from a clean private home. |
| 3 | Choose free, subscription, local, custom, or advanced API routes without researching accounting | The `OnboardRouteArgument` command surface and provider-configuration process tests cover strict free OpenRouter, authenticated custom Responses, credentialless loopback, the official Codex subscription client, OpenAI API, and Anthropic API. The ChatGPT route uses bounded official app-server account/login/model methods: terminal users separately consent to browser or headless device login when needed, then onboarding selects the unique account-catalog default or validates an exact override. Mealy retains a conservative 128,000-token context ceiling without asking the user for internal model metadata. Browser/device, signed-in, non-terminal, decline, and missing-client process proofs cover credential containment, official prerequisite guidance, and no-mutation behavior; a live model-call-free run selected the installed Plus account's `gpt-5.6-sol` default. Claude subscription routing is excluded because Anthropic's current third-party terms prohibit it; legacy names fail before mutation/invocation and direct Anthropic API, OpenRouter, custom, or Claude Code alternatives are reported. Catalog routes derive limits/prices; advanced routes require explicit conservative values. When a remote route's named environment variable is absent, terminal onboarding captures one bounded credential with echo disabled, restores echo before the next prompt, and reuses the same zeroizing value through discovery/probe/broker activation. PTY tests cover OpenRouter and custom endpoints; non-terminal absence fails before mutation. | **Publicly complete for the supported routes.** The exact release commit passed strictly free OpenRouter and authenticated private-endpoint acceptance; the official ChatGPT account/catalog path passed live without a model call. Direct Claude subscription-token routing remains deliberately unsupported because it is not an authorized third-party integration. |
| 4 | See a bounded live route probe pass | Onboarding calls the existing byte-, event-, identity-, timeout-, and model-bounded provider probes before activation. Provider process tests cover each protocol and redaction; the private custom endpoint has separate live acceptance. | **Publicly complete.** Exact-release strictly free OpenRouter and private custom-provider runs each completed probe, run, settle, replay, and drain. |
| 5 | Have the owner service installed and running | `scripts/systemd-service-smoke.sh` starts from a clean home, uses the real generated enabled systemd user unit, requires health plus sandbox-conformant `doctor`, and executes a governed mutation. Protected Linux CI prepares a clean user manager with lingering enabled. The tag workflow repeats the proof from the exact public rootless download before accepting a release. | **Publicly complete.** Exact downloaded v0.2.1 payload acceptance left the generated owner unit enabled, healthy, and running the installed daemon. |
| 6 | Reach the first useful chat | The same installed-service journey drives onboarding through a real terminal input, requires the visible model response, verifies exact usage, and finds the committed durable task before accepting success. Public acceptance uses the downloaded installer without a repository override and reruns this journey through first chat, restart, `doctor`, durable continuation, and uninstall. | **Publicly complete.** Public release acceptance required the visible first response and the successful committed durable task. |
| 7 | Restart and resume | `chat --continue` selects the newest exact-binding session without creating another, while `chat --pick` provides a bounded terminal-only chooser for 20 recent exact-binding sessions and resumes only the selected one. The systemd journey captures the enabled installed service and its PID, restarts it, requires a distinct healthy daemon and passing `doctor`, then resumes the exact prior session and rechecks the one-session inventory. Login-manager lingering plus the generated enabled unit cover boot activation under the supported distro contract. | **Publicly complete at the controllable host boundary.** Exact release acceptance proves a distinct cold daemon, enabled unit, durable state, passing `doctor`, and exact-session continuation. A hosted runner cannot reboot its physical host, so the audit does not falsely claim a literal hardware reboot in CI; the qualified distro/systemd contract supplies that final host behavior. |
| 8 | Diagnose a failure with one command | `mealyctl doctor` checks API readiness, SQLite startup integrity, permissions, required system executables, and enforceability of every sandbox profile; onboarding will not report completion until it passes. | **Publicly complete.** The command is packaged, documented, and required after initial activation and cold restart in exact-release acceptance. |
| 9 | Update and roll back without losing state | `install-status`, no-mutation `update`, restartable approved archive update, pre-update backup, qualification, automatic same-schema slot rollback, repair, uninstall, and native manager handoffs are implemented. Installed failure injection requires the prior package, health, `doctor`, backup, and durable task to survive. | **Publicly complete.** v0.2.1 ships the lifecycle commands; protected installed-package failure injection proves automatic rollback, healthy service recovery, verified backup, and durable-task preservation. |
| 10 | Find the same short, version-matched workflow | `GETTING_STARTED.md` is bundled in every archive/native package. The signed repository landing page carries distro install, onboarding, continuation, diagnostics, update, fingerprint, and version-tagged detailed links inside the complete signed repository inventory. Documentation validation binds public CLI/API surfaces and local links. | **Publicly complete.** The signed live landing page identifies stable v0.2.1 and links its version-pinned guide; the same short guide is bundled in every qualified archive and native package. |

## Failure-behavior audit

The composed path also has direct negative evidence:

- credential values are imported once from the named environment variable or, only on terminal
  stdin/stderr, captured through an echo-disabled bounded prompt; they are excluded from plans,
  config, service environments, the supported official Codex subscription client, and diagnostics;
- a required shared Codex login starts only after separate terminal consent; signed-out automation
  and explicit decline start no login and mutate no Mealy state, while completed Codex login is
  accurately disclosed as external state that a later Mealy-plan cancellation does not undo;
- the free OpenRouter route admits only exact `:free`, tool/text-capable catalog entries whose
  complete token and auxiliary prices are zero;
- an existing `config.json` is never replaced without `--reconfigure` while stopped;
- service-start or bounded readiness failure preserves the configured home and reports the
  completed boundary;
- `--configure-only` makes an intentionally unstarted home explicit; and
- implicit state resolves to one absolute owner home across working directories, while absent or
  invalid `HOME` fails with an actionable override instead of creating state in the current
  directory;
- a bare invocation requires all three terminal streams, selects its journey only from a
  no-follow regular `config.json`, and requires explicit subcommands for automation;
- owner-service removal stops the still-reviewed loaded unit before disabling its links, avoiding
  the linked-unit `disable --now` ordering failure in systemd 257 while retaining systemd 255
  behavior; and
- release install, onboarding, service operations, provider activation, and update transactions
  either reuse stable identities or report their durable completion evidence.

## Completion finding

All three former delivery gates are satisfied:

1. exact report-bearing release commit
   [`b8e9d8576f228fd43a523ad38704a86b4630b115`](https://github.com/Amekn/mealy/commit/b8e9d8576f228fd43a523ad38704a86b4630b115)
   passed [protected main CI](https://github.com/Amekn/mealy/actions/runs/30312296096);
2. the same commit passed reviewed
   [strictly free OpenRouter](https://github.com/Amekn/mealy/actions/runs/30314579973) and
   [private custom-provider](https://github.com/Amekn/mealy/actions/runs/30313042644)
   acceptance; and
3. v0.2.1 is immutable, attested, publicly installable through the rootless bootstrap and native
   packages, and its signed repositories passed
   [protected post-publication acceptance](https://github.com/Amekn/mealy/actions/runs/30324688498).

The ten-item competitor-grade onboarding definition is therefore complete for the qualified
Ubuntu, Debian, Fedora, and Arch Linux release contract. Future product polish, additional
distributions, or a graphical installer can improve reach, but they are not unclosed requirements
in this definition. Mealy intentionally keeps inspect-before-privilege and attestation checks
instead of copying the shortest competitors' unauthenticated remote-script execution.
