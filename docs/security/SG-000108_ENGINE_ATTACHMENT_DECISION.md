# SG-000108 engine attachment and resolved-address enforcement decision

Status: PROPOSED; security review passed on PR #291. This record resolves
the first two `open_questions` of `.specgrain/specs/SG-000108.json`. The
record itself granted no authority and admitted no dependency. The frozen
SG-000074 command line in `crates/qdral-browser-host/src/argv.rs` stays
unchanged. Implementation progress is tracked at the end of this record.

## Evidence

The evidence comes from throwaway spikes outside the repository. They ran on
Windows 11 (10.0.26300) against the installed Microsoft Edge 155.0.4283.45
with `playwright-core` 1.63.0. The package was installed with
`--ignore-scripts`, and its lockfile integrity equals the admitted
`sha512-rYCsBF/M…nyxo5mCg==`. No browser binary was downloaded, and no Edge
or Chrome policy key was present (`HKLM`/`HKCU\Software\Policies\Microsoft\Edge`,
`HKLM\Software\Policies\Google\Chrome`). The implementation PR turns each
probe into a native Windows test.

The probes behind the second, third and fifth rows ran with the policy route
removed, so they test layers 1 and 2 alone. They used the full proposed flag
set from the next section.

| Probe | Result |
|---|---|
| `launchPersistentContext` with `ignoreDefaultArgs: true`, the seven frozen flags, `--user-data-dir`, `--remote-debugging-pipe`, `about:blank` | Launches and is driven, and an ARIA snapshot of a fixture page is returned. The OS-reported engine command line is exactly those arguments: no `--enable-automation`, no debugging port or address, no Playwright default flag. |
| Resolver rules mapping only admitted names, then `MAP * ~NOTFOUND` | A real public name (`example.com`) and unmapped names fail. The fixture saw only admitted requests. |
| Proxy `http://0.0.0.0:9` with an exact bypass list plus `<-loopback>`, and hostile TCP listeners on `0.0.0.0:9`, `127.0.0.1:9` and `[::]:9` | IPv4 literal, IPv6 literal (`[::1]`), IPv6 metadata (`[fd00:ec2::254]`) and unmapped names fail with `ERR_PROXY_CONNECTION_FAILED` in 55–75 ms. **Zero** connections reach any listener. The admitted name still connects directly. |
| `MAP <name> <ip>:<port>` | A request for the admitted name on another port is delivered to the pinned port. Without the port, any port is reachable. Pins therefore carry `:443`. |
| WebRTC STUN to IP literals (loopback and LAN), and TURN over TCP | Without a policy flag, UDP reaches an arbitrary address (4 packets), bypassing layers 1 and 2. On Edge 155, `--force-webrtc-ip-handling-policy=…` had no effect. `--webrtc-ip-handling-policy=disable_non_proxied_udp` yields zero candidates, zero packets and zero TURN-TCP connections. |
| WebTransport | Not reachable from the HTTP fixture: it requires a secure context. **Untested.** It is a required HTTPS-fixture test (see below). |

## Decision 1: engine launch and attachment (option a)

**Launcher.** The private worker launches the verified engine through
`playwright-core` `launchPersistentContext` over `--remote-debugging-pipe`.

**What the host still owns:**
- engine discovery and signature verification;
- profile adoption and the fingerprint check;
- the scrubbed environment;
- the complete argv.

**What the worker receives.** The worker gets the engine path, the profile
directory, the argv and the environment from the host, and passes them
unchanged with `ignoreDefaultArgs: true`. The worker has no code path that
adds a flag.

**Drift detection, not containment.** After launch, the host compares the
engine's OS-reported command line with the argv it built. It also enumerates
every process in its Job Object and refuses any second browser-process engine
(an engine process without `--type=`). This catches drift, for example a
Playwright upgrade that adds default flags, a wrong engine, or a stray
process. It does **not** defend against a compromised worker:
- the worker holds a full-access handle to the engine, so it could rewrite
  the command line the OS reports after the engine has parsed it;
- a compromised worker is a full-user process and needs no browser to reach
  the network.

Worker compromise is a residual risk (below).

**Supervision.** The worker runs in the host's kill-on-close Job Object
without breakaway, so the engine and its child processes inherit the job.

**Option (b) rejected.** Option (b) would have the host launch the engine and
hand the pipe to the worker. It was rejected because Playwright has no public
API for an inherited pipe: it would need a private adapter that breaks on
upgrades, and the drift check above gives the same assurance.

### SG-000074 argv amendment

This is the explicit authority delta of the implementation. It is made
without widening the SG-000074 path: `ALLOWED_FLAGS` and `assert_argv_clean`
stay frozen and keep refusing every flag below. A separate, exact worker-launch
builder (`build_worker_argv`) emits the frozen flags plus exactly these six,
and `assert_worker_argv_exact` accepts only that argv. `FORBIDDEN_FLAGS` is
unchanged:
`--remote-debugging-port`, `--remote-debugging-address`, `--enable-automation`
and `--disable-component-update` stay forbidden.

| Flag | Value |
|---|---|
| `--remote-debugging-pipe` | none |
| `--host-resolver-rules` | host-built for this launch: `MAP <name> <pin>:443, …, MAP * ~NOTFOUND` |
| `--proxy-server` | fixed: `http://0.0.0.0:9` |
| `--proxy-bypass-list` | host-built for this launch: `<name>;…;<-loopback>` |
| `--webrtc-ip-handling-policy` | fixed: `disable_non_proxied_udp` |
| `--disable-quic` | none |

A host-valued flag is accepted only when its value equals the string the host
built for that launch. A fixed-value flag is accepted only with its fixed
value. A flag present by name only, or with any other value, is refused.

## Decision 2: actual-traffic enforcement of SG-000075

Three layers, each fail-closed on its own, plus the required flags and
launch preconditions below.

1. **Host-pinned resolution, port-pinned.** The engine never resolves names.
   - For each admitted destination, the host resolves the name and chooses
     the pin with the existing `select_public_address`. Public addresses
     only: loopback, private, link-local, metadata and mapped forms are
     denied by `is_public_address`.
   - The host emits `MAP <name> <pin>:443` for each name, then
     `MAP * ~NOTFOUND`. This enforces SG-000075's port-443 rule at the
     resolver.
   - DNS rebinding is impossible within an engine lifetime because the map is
     fixed at launch.
   - A redirect, frame or subresource to a name outside the map fails.
   - Widening the set means a host-mediated relaunch after a fresh
     `check_rebinding_consistent` check, never an in-place change.
2. **No route for IP literals or unmapped names.** The host sets
   `--proxy-server=http://0.0.0.0:9` and
   `--proxy-bypass-list=<admitted names>;<-loopback>`.
   - Only admitted names connect directly. Their address and port come from
     the layer 1 pin (`:443`), not from the bypass list.
   - Everything else, IPv4 and IPv6 literals included, goes to `0.0.0.0:9`,
     which accepted no connection even with listeners bound to `0.0.0.0:9`,
     `127.0.0.1:9` and `[::]:9`.
   - `<-loopback>` removes the engine's implicit loopback bypass.
   - On Linux, connecting to `0.0.0.0` reaches the local host, so this
     choice is valid only for the Windows release.
3. **Policy gate.** The worker's context-level route consults the host's
   SG-000075 decision for every request it sees: navigation, redirect,
   frame, popup, subresource and download. Layer 3 carries policy (scheme,
   origin, exact host, download rules); layers 1 and 2 carry addresses.
   - `serviceWorkers: "block"` is set.
   - WebSocket is denied through the context WebSocket route until a later
     grain admits mediated WebSocket.
   - Layer 3 does not see every request: preconnect, keepalive after unload,
     and internal fetches are not routed. Layers 1 and 2 therefore must hold
     without it, and the tests prove that.

**Required flags.**
- `--webrtc-ip-handling-policy=disable_non_proxied_udp`: WebRTC UDP otherwise
  bypasses layers 1 and 2.
- `--disable-quic`: SG-000075 denies QUIC.

Permission-gated page APIs stay denied by `permission_allowed`.

**Launch precondition: no mandatory policy.** Managed browser policy
outranks command-line settings. A machine proxy policy would turn layer 2
into a working proxy, which resolves names itself and so skips layer 1 too.

Before every launch, the host reads the mandatory policy keys for the
verified engine's family:
- `HKLM` and `HKCU\Software\Policies\Microsoft\Edge` for Edge;
- `HKLM` and `HKCU\Software\Policies\Google\Chrome` and
  `\Software\Policies\Chromium` for the Chromium family (Google Chrome reads
  the first, Chromium builds the second).

It refuses to launch, with a typed error, when **any** mandatory policy
value or subkey is present. This is simpler, and fails closed better, than
keeping lists of proxy, DNS, WebRTC and QUIC policy names.
`Recommended` subkeys do not override command-line settings, but the first
slice refuses them as well.

Cloud-managed policy that is cached locally outside these keys is a
hypothesis to test. Release qualification therefore also runs the layer 1
and 2 probes against the installed engine, which catches any override in
effect whatever its source.

### Hostname and value hygiene

- **Hostnames.** The host builds the rule and bypass strings from validated
  ASCII LDH hostnames only:
  - lowercase;
  - labels of 1 to 63 characters, 253 characters in total;
  - at least two labels;
  - a last label that is not all-numeric and does not start with `0x`, so
    that a name can never be parsed as an IPv4 address.
  - This also rules out wildcards and the separators `,` `;` and whitespace.
- **Addresses.** Values come from typed `IpAddr`, formatted by Rust. IPv6
  pins are bracketed.
- **Construction.** No page, caller or worker string reaches any flag.

### Test-only fixture pinning

Fixtures listen on loopback, which `is_public_address` correctly rejects.
Tests therefore need a test-only pin source. It must be compiled only into
test builds (a `cfg(test)` path or a non-default feature that the release
build never enables). A release-qualification check must prove that it is
absent from the shipped binaries. No runtime configuration may enable it.

## Residual risks (for review)

- **Admitted host is hostile.** An admitted name pinned to its public address
  still serves whatever that host returns. Content is never policy (SG-000076
  redaction and SG-000077 approvals still apply).
- **Worker compromise.** A compromised worker equals user-level code with
  network access. The drift check does not contain it. Mitigations are the
  pinned, integrity-checked dependency, the scrubbed environment, no CLI and
  no install scripts. The implementation PR must evaluate running the worker
  under a restricted token or AppContainer without network capability, and
  record the outcome.
- **Same-user processes.** The debugging pipe is not reachable by other users
  or the network. But a same-user, medium-integrity process can duplicate the
  pipe handles out of the worker or engine and take full CDP control. This
  matches the existing threat model, where same-user code is not a security
  boundary. Tests must show the pipe handles are not inherited by the
  engine's child processes.
- **Browser-internal update and reputation traffic.** The no-route proxy also
  blocks:
  - component updates, including CRLSet revocation data (so SG-000074's
    choice not to pass `--disable-component-update` has no effect while
    this decision stands);
  - Safe Browsing / SmartScreen lookups.

  This is an explicit decision for the first slice. Admitted traffic stays
  TLS-verified, and downloads are staged and host-checked (size, type,
  digest) rather than trusted to SmartScreen. Revocation freshness relies on
  the OS certificate stack. Admitting specific update endpoints is a later
  grain decision.
- **Engine drift.** A future Edge may change how it honours these flags
  (the WebRTC switch name already differs from the `--force-` spelling). The
  A10 supported version window must re-run every probe per supported engine
  version and refuse versions where any probe fails.
- **Relaunch cost.** Relaunching to widen the destination set costs latency
  in exchange for no in-place mutation. This is accepted for the first
  journey (A6), whose destinations are known up front.

## Tests the implementation PR must add (native Windows, fixture origin only)

- **Argv.** The exact argv, and the OS command line equal to it, before and
  after the navigation. Refusal of every new flag without its host-built or
  fixed value. Refusal of every forbidden flag, as today. Refusal of a second
  browser-process engine in the job.
- **Layers 1 and 2, with the policy route disabled by a test-only hook.**
  Every case below is denied:
  - an unmapped name and a real public name;
  - IPv4 and IPv6 literals;
  - private, loopback and IPv4/IPv6 metadata addresses;
  - another port of an admitted name, which lands on the pinned port;
  - a connection to listeners bound on port 9 (zero accepts).
- **Rebinding.** A fixture resolver whose answers change; the engine keeps
  the pin.
- **WebRTC.** STUN and TURN (UDP and TCP) yield zero packets and zero
  connections.
- **QUIC and WebTransport.** An HTTPS fixture shows no QUIC and a refused
  WebTransport session, both to an admitted name and to an unmapped name.
- **Service workers and WebSocket.** A service worker registration and a
  WebSocket connection are refused.
- **Policy precondition.** A test registry hive with any mandatory Edge or Chrome policy makes the
  launch refuse.
- **Supervision.** The engine is a descendant of the worker inside the host
  job; killing the host leaves no engine process; the pipe handles are not
  inherited by engine child processes; the measured process count stays
  within SG-000074's job process limit.
- **Hostname hygiene.** Names with numeric, hex or wildcard labels, or
  containing separators, are refused.

## Implementation progress

**Slice 1: host-side confinement contract** (`crates/qdral-browser-host/src/confinement.rs`).
- `AdmittedDestination::admit(url, resolver)` is the only public
  constructor. It runs the existing `validate_navigation`, which resolves the
  name and pins its lowest public address with `select_public_address`. So
  every pin comes from the host's own resolution of that name. It then
  re-checks https, port 443 and `is_public_address`, and applies the stricter
  hostname hygiene.
- `resolver_rules`, `proxy_bypass_list` and `build_worker_argv` emit the
  six flags with the exact values in the table above.
- `assert_worker_argv_exact` refuses any argv that differs element for
  element from the host-built one.
- `assert_no_managed_policy` with `RegistryPolicySource` reads the Edge, Chrome or
  Chromium mandatory policy keys in HKLM and HKCU, both registry views, with
  `KEY_READ` only. It refuses on any value or subkey, and fails closed when
  a key is unreadable or the platform is not Windows.
- The SG-000074 `build_argv` and `assert_argv_clean` are unchanged and still
  refuse every confinement flag (a unit test proves this).
- The fixture pin constructor is compiled only into unit tests.
- No launch path uses this module yet, so the slice grants no authority.

**Native check of the emitted format (Edge 155).** An IPv4 pin and a
bracketed IPv6 pin (`MAP six.example [::1]:<port>`) each reached only their
fixture. Unmapped names failed with `ERR_PROXY_CONNECTION_FAILED`.

**Slice 2a: private worker package** (`apps/qdral-browser-worker`). It is standalone, like `apps/web`, so the identity-pinned npm workspaces stay unchanged.
- **Dependency.** `playwright-core` is exactly 1.63.0, with the admitted integrity. It is the only production package in the lockfile, has no install script and no runtime dependencies. All of this is checked mechanically against `dependency_admission`.
- **Protocol.** SG-000074 framing (u32 LE length + JSON, 64 KiB) with a closed generation-1 vocabulary:
  - host → worker: `hello`, `launch {engine, profile_dir, argv, env}`, `ping`, `shutdown`;
  - worker → host: `hello`, `launched`, `pong`, `bye`, `error {code}`.
  Unknown frames or fields are violations.
- **Launch check (defense in depth).** The worker re-checks the launch frame against this contract:
  - the frozen flags and the profile;
  - each resolver entry, parsed with the host grammar: an admitted-host name, an IPv4 or bracketed IPv6 pin, `:443`, and `MAP * ~NOTFOUND` last;
  - a bypass list exactly equal to those names in order, followed by `<-loopback>`;
  - the fixed proxy, WebRTC and QUIC values, and the blank page;
  - engine and environment allowlists, and absolute paths without dot segments.

  Address class stays the host's policy, because test builds pin fixtures to loopback. The worker then hands the argv to Playwright unchanged, with `ignoreDefaultArgs: true`. There is at most one engine per worker. Any violation, refusal, unexpected error, broken pipe, engine exit or end of input closes the engine.
- **Console isolation.** The global console is replaced by one that writes only to stderr. Verified: `console.dir`, `table`, `trace` and `log` put 0 bytes on stdout.
- **Native smoke run (Edge 155, local).** `dist/main.js` went through `hello` → `launch` → `ping` → `shutdown` with exit 0. The OS reported one browser process with the host argv, with no debugging port and no `--enable-automation`. No engine process was left after shutdown.

- **CI.** The root `npm test` runs the worker's install (`npm ci --ignore-scripts`), typecheck and tests. Both Node jobs, ubuntu and windows, therefore cover it without a workflow change. A dedicated `npm audit` of the worker lockfile in the supply-chain job is **pending**: it needs a workflow edit, which the current push token cannot make (no `workflow` scope). Until then the audit is a local check (0 vulnerabilities), and the lockfile admits only `playwright-core`, which has no dependencies.

**Findings that bind slice 2b:**
- The OS command line quotes arguments that contain spaces (the resolver rules), so the host must parse it with `CommandLineToArgvW` rules before the element-for-element comparison.
- Node acts on `NODE_OPTIONS` (verified with `--require`) before any worker code runs. The host must therefore build the worker environment from an allowlist and never inherit it; the worker's own refusal is only a second line.
- Inspector activation: **resolved in slice 2b-i**. The worker always runs with `--disable-sigusr1`, requires Node.js 22.14+ (`engines`), and is reported as typed unavailable on an older Node.
- Service workers: Playwright's `serviceWorkers: "block"` only replaces `navigator.serviceWorker.register` with an init script, so page script may be able to bypass it. Block service workers by engine or protocol means, and prove it with a native probe.
- Worker environment allowlist: also exclude the OpenSSL start-up variables (`OPENSSL_CONF`, `OPENSSL_MODULES`, `OPENSSL_ENGINES`, `SSL_CERT_FILE`, `SSL_CERT_DIR`). The worker refuses them as a second line.
- Release packaging (A2): the `playwright-core` NOTICE, the SBOM entry and provenance enter the release with the packaged worker. Packaging strips the `node_modules/.bin` link to the Playwright CLI, which is never exposed.

**Slice 2b-i: native confinement probes in CI** (`apps/qdral-browser-worker/src/native.test.ts`). These run against the installed Edge through the root `npm test`, so the **Node / windows-latest** job produces real-engine evidence. On Windows a missing engine fails the suite. On other platforms the suite is skipped, because only Windows results count. The probes use owned loopback fixtures on port 443 and an argv the worker contract accepts.

1. **Lifecycle.** The worker drives the engine through `hello` → `launch` → `ping` → `shutdown`.
   - Exactly one browser process exists. Its OS command line, split with `CommandLineToArgvW` rules, equals `[engine, ...argv]`.
   - No process carries `--remote-debugging-port`/`-address` or `--enable-automation`.
   - Exit code 0, and no engine process remains.
2. **Worker kill.** Killing the worker takes the engine down with its pipe. The Job Object of slice 2b-ii remains the guarantee.
3. **Layers 1 and 2 with no policy route at all.** The admitted name reaches the fixture, and another port of it lands on the pinned port. All of the following fail:
   - an unmapped name;
   - a real public name;
   - IPv4 and IPv6 literals (including the fixture's own address and port);
   - a private address;
   - IPv4 and IPv6 metadata addresses.

   Listeners on `0.0.0.0:9`, `127.0.0.1:9` and `[::]:9` accept nothing, and the fixture sees only the two admitted requests.
4. **WebRTC.** STUN to loopback and to the first LAN address, and TURN over TCP, gather no ICE candidate, send no UDP packet and open no TCP connection.
5. **Inspector.** With `--disable-sigusr1`, `process._debugProcess` from a same-user process is refused and no listener appears on 9229. A negative control without the flag shows that the probe detects an activated inspector.

**Local result (Windows 11, Edge 155):** all 21 worker tests pass, 5 of them native (about 26 s in total).
