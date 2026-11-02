# H3rm35 Push host extension

Directory-installed, opt-in Stock Hermes extension for the H3rm35 iPhone app.
It observes completed turns and human-input requests; it cannot submit messages,
answer questions, approve tools, change profiles or launch/restart Hermes.

**Early integration release:** the compatible H3rm35 flow is initially available
in internal Build 78 and the publisher enrollment service is enabled. This
repository publishes the host extension only; installing it alone does not
enable push. Complete enrollment and physical iPhone delivery through this new
extension remain separate acceptance checks, not implied by the CI results.

## Supported contract

The host must expose both public plugin hooks `post_llm_call` and
`on_human_input_request`. Older hosts return `host_update_required` rather than
advertising incomplete approval/question coverage. The source contract was
inspected read-only at Stock revision
`3d304a112b99b9cd56799d3b9f0ba50095fdda8c` on 2026-11-02:

- `agent/turn_finalizer.py:453–479`: completed-turn hook supplies persisted
  `agent.session_id`, `turn_id` and `platform`; persistence-disabled forks skip it.
- `tools/human_input_hooks.py:40–77`: human requests supply kind, unique request
  ID, stored session ID and platform separately from a live session key. Prompt
  content is deliberately ignored by this extension.
- `hermes_cli/profiles.py:2137–2160`: `current_profile_name` respects the
  task-local profile override rather than relabelling multiplexed profiles with
  the process launch profile.
- `hermes_constants.py:111–117,199–237`: current profile home is context scoped;
  `get_default_hermes_root(home=get_routing_process_hermes_home())` resolves the
  common installation root across default/routed profiles and custom roots.
  Registrations live there, separate from profile `state.db` files.
- `hermes_cli/web_server.py:650–683`: plugin APIs have enable/runtime gates and
  run behind Stock authentication. Every extension route additionally invokes
  Stock `_require_token`; there is no standalone HTTP server.

Private storage supports POSIX (macOS, Linux, WSL) and native Windows on a local
fixed NTFS volume with persistent ACLs. Native Windows was tested on Windows
Server 2022 with CPython 3.12.10 and 3.14.9, pywin32 311. Network drives, other
filesystems, unsafe ACLs, metadata junctions/reparse points and hardlinks fail
closed. Unix mode 0600 is never presented as a Windows ACL audit.

## Install once on your Hermes host

Use the same Hermes profile/environment that serves your phone connection:

```sh
hermes plugins install mauricemohr88-debug/h3rm35-push --enable
```

This is Hermes' standard Git plugin installer, not a downloaded shell script.
Review its normal security and permission prompts; `--enable` does not bypass
security scanning or any separate dependency consent. Do not overwrite an
existing installation or change another profile's home. Profile enablement still
follows Hermes' own opt-in rules; this extension does not enable other profiles.

Load/restart Hermes only at an explicitly chosen safe point with no running jobs;
the extension never launches or restarts it. Once the compatible publisher service
and app are available, open H3rm35, choose that authenticated host, tap **Push
aktivieren** and allow iOS notifications. No Apple key, QR code or credential file
transfer is required by this new path.

The command and consent behavior are documented in the
[official Hermes plugin guide](https://hermes-agent.nousresearch.com/docs/user-guide/features/plugins/).

FastAPI is supplied by the existing Hermes API host; SQLite, TLS and the worker
use Python's standard library. Native Windows additionally uses **pywin32 311**,
declared with a Windows-only dependency marker. Hermes' normal installer handles
dependency consent and resolution; this extension never runs pip or installs
packages from a callback. macOS/Linux/WSL do not import or require pywin32. Missing
native APIs fail closed before a worker starts. No Desktop application or separate
user-facing dashboard is required.

## Wire and trust boundaries

All paths are mounted by Stock under `/api/plugins/h3rm35-push`:

- `GET /capabilities`: schema 2, stable host UUID and the three event kinds.
- `POST /register`: schema 2, exact host UUID, binding UUID, device-scoped
  host-send capability and selected event kinds. Same binding/capability retries
  are idempotent; replacement with a different capability is rejected.
- `DELETE /registrations/{binding_id}`: removes only that device and its outbox.

No APNs token, publisher signing key or iPhone device-control secret is accepted
or stored. The iPhone sends only the host capability after the publisher has
verified actual APNs receipt. The database contains that capability in the
host account's private directory (0700/database0600, owned, no symlinks/hardlinks).
On macOS, the directory and database must additionally have **no extended ACL**:
the extension checks only their metadata using fixed `/bin/ls -lde` arguments,
no shell, no inherited environment/proxy settings, a two-second timeout and a
strict output-size/shape gate. Any ACL or unverifiable metadata fails closed;
the extension never strips user ACLs. Extended attributes alone are not an ACL.
This is not a whole-host ACL audit or protection against the host account/admin.

On native Windows, the owner must be the current account. New private storage is
created with a protected DACL granting only that account and SYSTEM; its directory
privately inherits permissions for child files. Existing ACLs are verified, never
repaired. Handle-based checks pin the canonical root, directory, lock, database
and permanent journal; handles deny deletion/replacement while SQLite is open.
Only local fixed NTFS is accepted. A native cross-process lock covers the full
connection lifetime. SQLite sets EXCLUSIVE before recovery, then PERSIST/FULL,
in-memory temporary storage and mmap disabled. WAL/SHM are rejected. This is not
a hardware power-loss guarantee or protection from an administrator/current user.

The extension reads publisher configuration from the fixed first-party URL
`https://kiablauf.de/h3rm35/push-service.json`, without credentials, redirects or
ambient proxies. Exact schema, HTTPS origin and 2 KB response limit are checked;
successful discovery is cached at most one hour. No URL comes from registration
input. No secrets are logged or included in error responses.
Both configuration reads and event delivery identify the extension honestly as
`H3rm35-Push/0.1`; they do not impersonate a browser or relax publisher security.

Before emitting, the extension verifies an exact session ID in the active
profile's read-only `state.db`; no prefix search, default-profile guess or message
content read. Subagent/curator events are skipped. Unknown/mismatched identity
does not produce a notification. Root-session events are metadata only:
kind, exact profile/session ID, timestamp and per-binding salted event ID.
The upstream completed-turn hook is emitted after a nonempty final assistant
response exists; that response is neither persisted nor sent by this extension.

Delivery happens in a background worker, never in the tool/response callback.
The durable outbox has 2,000 entries maximum, five-minute event TTL, five attempts
and short leases. HTTP 401/403/410 retires only the affected host registration;
429/5xx/network failures back off. It never retries a Hermes command. A relay
acceptance is not proof of iPhone receipt or correct notification tap routing.

## Validation

Run `python -m pytest -c tests/pytest.ini tests -q -p no:cacheprovider` with the
host test dependencies (pytest, FastAPI, httpx). The isolated tests cover strict
registration, private file checks, stable identity, per-device fan-out/revoke,
bounded retries/queue, exact profile ownership, fork/content exclusion, deterministic
SQLite closure, fixed publisher discovery and HTTP authentication/error handling.

Current results on 2026-11-02: **98 passed, 4 platform skips** on each real Windows
runner (CPython 3.12.10 and 3.14.9, Windows Server 2022/NTFS), and **60 passed,
42 Windows-only skips** on macOS/Python 3.14. The Windows skips are two actual
macOS ACL cases, the POSIX-mode case and the non-Windows import-boundary case;
no native Windows storage case was skipped. [Native CI evidence](https://github.com/mauricemohr88-debug/h3rm35-push/actions/runs/41515220833).
No live Hermes host, model API, Apple APNs service or user chat was used. Full
current gateway-process execution, real API-created response/question/approval
events, isolated-plugin-host IPC and physical iPhone delivery remain separate
acceptance checks. CI qualification is not installation on a user's running PC.

Four bounded tests execute **actual copied upstream source functions**, not
rewritten contract approximations: the directory API mounter/enabled gate; human
request context manager/identity plus completed-turn finalizer; and root/profile
home helpers. They mount this router through the source mounter, pass real hook
payloads with a deliberately different live session key into this observer, and
prove shared registration across default/research/custom-root profile homes.
Actual `PluginContext` initialization/register/on_unload methods additionally
register both callbacks and a real idle worker, then dispose all registrations
and stop that thread. Manager/other runtime components are test doubles; this is
not a whole-agent run. Missing native Windows APIs start no background thread.
The macOS ACL cases include real ACL additions to private pytest-only directory
and database fixtures plus subprocess failure/timeout/ambiguous-output cases.
No existing user path or ACL was changed for these checks.

Native Windows cases exercise actual DACLs (foreign/null/unprotected/owner and
inheritance checks without repair), generation-pinned handles, hardlinks,
junction aliases, journal/sidecar checks, simultaneous first publication, native
cross-process locks released by process exit, and rollback after an abruptly
terminated SQLite writer. The actual Store roundtrip covers all three event
kinds, registration/reopen/revoke and stable identity. API failures retain 503
storage semantics instead of mislabelling a lock or ACL failure as invalid input.
The Windows adapter reuses H3rm35's MIT-licensed atomic-storage implementation,
with a standalone lazy runtime rather than an SSH/Hermes-module dependency.

A read-only production check additionally verified the extension's actual urllib
opener and product User-Agent against both publisher configuration and relay
health: HTTP 200 JSON. Public v2 enrollment was subsequently enabled. This is endpoint
reachability, not APNs delivery or iPhone acceptance.

Read-only source copies under `tests/upstream-source-3d304a1/` retain the upstream
MIT license. SHA-256 source identities:

- `human_input_hooks.py`: `cb683ab73dc60f03d4ae98894287fa34c9769fda528d8fa05fbe8f2f111d58a5`
- `turn_finalizer.py`: `b9aa99de6a9613aee46048d78d2b58aebd0ef1a9b7fc1edb8ad1615fc36995fa`
- `web_server_dashboard.py`: `941d055c397e30c4e9805a3479068e717cdb1851480944305fac2f9ab21048fb`
- `hermes_constants.py`: `5d43e6102c69748a2e64fc91623a49e1b0d76623416ce4ec37f23f216c3ce91f`
- `plugins.py`: `b0f09d0004890ff0b2c07d17ee7c5688709162da4fd43d404cabbe13f1d9f59d`

An initial test invocation incorrectly collected the plugin root as a top-level
Python package and failed relative imports. The supplied `tests/pytest.ini`
provides the proper test-root/import mode; no product import workaround was added.
