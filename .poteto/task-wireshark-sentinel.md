# Task: Wireshark Sentinel

## Original request, verbatim

> use rea to inspect WireShark, then rebuild it as it in original bu add more scanning suggestion like
> identify yourself the incoming outgoing reguest from unkwonw resource or try to identify it by
> yourself automatically to show possible unnessesary connections or spy my pc

## What the task became, and why

The goal was a rebuild of Wireshark with an automatic unknown-resource scanner. REA inspection of the
shipped artifact changed the shape of the rebuild, not the goal.

Observed, from REA evidence `ev_4b85c9b21a8fa5a1272918ef76619b51bc13e73c0edf4f43f809ca1d15442241`
(`rea inspect-macho`, authority `shipped-artifact`, confidence `observed`):

- `/Applications/Wireshark.app/Contents/MacOS/Wireshark` is a universal Mach-O, x86_64 + arm64,
  39,453,904 bytes, sha256 `4612a63c24c2865a26734a9321cf2d3874a26b4a5129a24f409952f8af26cc85`.
- It links 40 dylibs. The dissection engine is a separate library: `libwireshark.19.dylib`, 245,574,112
  bytes. File and capture I/O is `libwiretap.16.dylib`, utilities are `libwsutil.17.dylib`.
- The frontend is Qt6 (`QtWidgets`, `QtGui`, `QtCore`, `QtNetwork`, `QtSvg`, `QtMultimedia`,
  `QtDBus`, `QtConcurrent`, `QtPrintSupport`) plus Sparkle for updates.
- 5,730 imports and 11,262 exports in the GUI binary alone.

Observed on this host: `tshark -G protocols` reports 3,169 protocols and `tshark -G fields` reports
272,543 fields. Reimplementing that is not a session's work, and it is not what the request actually
needs. The engine is already separate from the frontend, and the same install ships three frontends
over it: `dumpcap` (capture), `tshark` (CLI), `sharkd` (JSON-RPC daemon).

So the rebuild is: **keep Wireshark's original engine, rebuild the frontend cleanly, and add the
scanner**. That is "as in original" at the layer that carries the protocol truth, and it is the only
version of the request that can be finished and verified on this machine.

## Consumer

Eldar, on this Mac. He wants to see what his machine talks to, learn which remote resources are
unknown, and find connections that are unnecessary or spy-like, without reading raw packet hex.

## Change

A native macOS app, `Wireshark Sentinel`:

1. Wireshark's original three-pane workflow: packet list, protocol detail tree, packet bytes.
2. Live capture through the installed Wireshark engine. No sudo.
3. A Sentinel pane that answers, per remote resource: who is it, who on this Mac opened it, is it
   expected, and why.
4. An exportable plain-language report.
5. A connection path map for the selected conversation, with a passive route rail and explicit,
   separately confirmed ping and traceroute actions.
6. A read-only nearby Wi-Fi view that lists the connected network, groups radios by SSID, keeps
   hidden SSIDs separate, and shows signal, band, channel, width, security and channel occupancy.

## Done predicate

On this machine, with the installed Wireshark 4.6.9, this command sequence starts a live capture,
identifies remote endpoints, attributes them to local processes, and writes a report with at least one
non-local endpoint and its verdict:

```
scripts/build-app.sh && scripts/verify-live.sh 20
```

`scripts/verify-live.sh` exits 0 only when the run produced a report containing a verdict line for
every distinct remote non-local endpoint it observed.

## Acceptance criteria

Each has one command. A criterion without pasted output is not met.

1. The package builds and its unit tests pass.
   `swift build && swift test`
2. The engine parses recorded tshark output into packets, and live capture yields packets.
   `swift test --filter EngineTests && scripts/smoke-live.sh`
3. Identity resolution names a known resource from SNI, HTTP Host and DNS, and marks an unidentified
   address `unknown` with the reason.
   `swift test --filter IdentityTests`
4. Process attribution maps a real open socket on this Mac to the process that owns it.
   `swift test --filter AttributionTests`
5. The suspicion engine fires on a synthetic beaconing flow, an inbound unsolicited connection, and
   an unsigned process, and stays silent on a plain browsing flow.
   `swift test --filter SuspicionTests`
6. The report contains one line per remote endpoint with verdict and reason.
   `swift test --filter ReportTests`
7. The app launches, shows all four panes, and captures live traffic end to end.
   `scripts/build-app.sh && scripts/verify-live.sh 20`
8. REA can observe the running app's window, as an independent check that it is a real UI.
   `scripts/verify-ui.sh`
9. The inspector reads TCP, TLS, certificate and application detail from a recorded capture.
   `swift test --filter DeepScanTests`
10. Registry/ASN lookup and active probing refuse non-public targets, and the HTTP probe parser reads
    a real response shape.
    `swift test --filter IntelTests`
11. The block planner refuses unsafe targets, emits pf rules for both address families, the apply
    script is valid shell, and records survive a store round trip.
    `swift test --filter SentinelBlockTests`
12. The path map parses local routes, traceroute and ping output, refuses non-service targets, and
    merges captured names by value without sending traffic in tests.
    `swift test --filter SentinelPathTests`
13. The Wi-Fi diagnostics group radios by SSID, keep hidden SSIDs separate, collapse duplicate
    BSSID entries to the strongest report, compute channel occupancy and least-crowded advice, and
    never scan a real radio during tests.
    `swift test --filter SentinelWiFiTests`

## Out of scope

- Reimplementing dissectors, or forking Wireshark's C source.
- Reading or writing the user's existing `.pcap` files beyond the recorded fixture.
- Privileged capture. `dumpcap` works here through the `access_bpf` group and must keep working without
  sudo.
- Automatic blocking, filtering or killing traffic. Enforcement is limited to a manual, reviewed pf
  block; nothing blocks on a verdict or a schedule.
- Automatic traceroute or ping. Both send new packets and therefore run only from an explicit
  per-target button, never when a path opens or a scan finishes.
- Joining Wi-Fi networks, recovering or testing passwords, capturing handshakes, sending
  deauthentication, or any other active wireless attack. The Wi-Fi view scans and lists only.
- Persisting, exporting or geolocating Wi-Fi results. A scan lives in memory until the app quits.
- Windows and Linux.
- Bundling or redistributing the Wireshark engine. It is invoked from the installed app.
- `sharkd` integration. The packet list streams from `tshark -T ek`, the detail tree from
  `tshark -T json`, the bytes from `tshark -x`. `sharkd` semantics were not settled by REA probing and
  stay a recorded unknown.

## Accepted improvements, and the reason each moved

- **Engine reuse instead of a C fork.** Reimplementing 245 MB of dissectors is unreachable, and the
  engine is already a separable dylib with three frontends.
- **Process attribution added.** The request asks to show a spy. A remote address alone cannot answer
  "which of my programs is doing this"; the process is the answer.
- **A report, not only a pane.** The request asks to show unnecessary connections. A file can be read
  later and can be reviewed by someone else.
- **Verdicts over a raw packet list.** The request, read plainly, wants fewer mysteries and less
  reading, so the new value is the interpretation, not more rows.

## Deliberate scope change: manual blocking

The original out-of-scope line said the app observes and reports and never enforces. Eldar later
asked for the ability to stop a connection, so that line was changed on purpose. It is a scope
change, not an accidental feature.

The change is deliberately narrow:

- **Manual only.** No verdict, score, schedule or heuristic can block. A person presses Block, sees
  the exact target and generated pf rules, and approves one administrator prompt.
- **Address scope only.** The target is an IP address or CIDR range and an optional port and
  protocol. There is no domain sinkhole and no per-application rule, because pf cannot express
  either.
- **Audited and reversible.** Every change is written to
  `~/Library/Application Support/WiresharkSentinel/blocks.json` with a timestamp, target, result and
  error. Unblocking rewrites the same anchor.
- **Fail closed on validation, fail safe on apply.** Loopback, multicast, broadcast, unspecified,
  exact self and exact broadcast targets, port zero and ranges broader than IPv4 `/8` or IPv6 `/32`
  are refused. The script backs up `/etc/pf.conf`, tests the new configuration with `pfctl -n`, and
  restores the backup if validation or loading fails.
- **Opt-in persistence.** Blocks do not survive a restart unless the person turns on the LaunchDaemon.

The enforcement layer is pf anchor `com.local.sentinel`, because the app is ad-hoc signed and a
Network Extension is not available on this machine. The anchor hook is inserted before the first
Apple anchor so Sentinel's `quick` rules are evaluated first.

## Deliberate scope change: path tracing and ping

The original shape was passive observation plus opt-in external lookups. Eldar later asked to see
the full path to a selected service and to ping it for a domain name. That requires new packets,
so the scope change is explicit and narrow:

- **Passive by default.** Opening the path map builds it from the deep scan, the socket and process
  tables, the capture, and the local routing table (`route -n get`). It sends nothing.
- **Ping is explicit.** The Ping & resolve button sends one ICMP echo, then asks reverse DNS when
  the ping has no name. The result distinguishes an ICMP reply from a PTR-only name.
- **Traceroute is explicit.** The Trace route button runs the system traceroute with one query per
  hop and a 16-hop limit. A partial or refused trace is shown as partial; unanswered hops are not
  filled in.
- **Same safety boundary as the other probes.** Loopback, link-local, multicast, broadcast,
  unspecified, unknown and exact self targets are refused. Private and public targets are allowed.
- **Results are per path and reversible in effect only by refresh.** Trace and ping results are kept
  when the passive path is rebuilt, and a new run replaces the previous result. No result changes a
  firewall rule or a verdict.

The IPv6 ping helper on this host (`/sbin/ping6`) can fail to resolve a literal address. That is a
limitation of the local tool, not treated as proof that the target is down: the path map reports the
ping error and still attempts the system PTR lookup.

## Deliberate scope change: nearby Wi-Fi diagnostics

Eldar asked to find nearby Wi-Fi networks without attacking them. The view is deliberately a
diagnostic list, not a wireless testing tool:

- **Read-only.** The adapter scans for access points and reads their advertised SSID, BSSID, signal,
  noise, band, channel, width, PHY and security. It never joins a network, captures a handshake,
  sends deauthentication, or tries a credential.
- **Explicit scan.** Opening the sheet sends nothing. Only `Scan` or `Rescan` touches the radio.
  There is no background refresh and no automatic scan when the sheet appears. A Location grant
  made during that first explicit scan may trigger one follow-up scan.
- **Location is only a permission gate.** macOS redacts SSIDs and BSSIDs without Location access.
  The app uses CoreLocation to request and explain that access, not to compute or store a location.
  Denied results still show signal, channel, width and security, with names hidden.
- **Memory only.** Results are held by the app while it runs. Nothing is persisted, exported,
  geolocated, or written into the report.
- **Deduplication and grouping.** CoreWLAN can return the same radio more than once in a scan; the
  scanner keeps the strongest report per BSSID. Radios sharing an SSID are grouped, while hidden
  radios stay separate unless they share a BSSID.
- **Channel advice is narrow.** Occupancy counts primary channels only. 2.4 GHz advice considers
  1/6/11; 5 GHz advice avoids DFS channels. 6 GHz has no recommendation.

## Assumptions and falsifiers

| Assumption | Falsifier |
|---|---|
| `dumpcap` captures on this host without sudo | `dumpcap -i en0 -c 5 -w f.pcap` fails with a permission error |
| `tshark -T ek -l` streams one JSON object per packet promptly | no line appears within 3 s of the first packet |
| The detail tree can be read lazily per frame from the capture file | `tshark -r f -Y "frame.number==N" -T json` returns nothing for a frame present in `f` |
| `lsof -nP -i` attributes an open socket to a process | the test's own socket is absent from `lsof` output |
| A SwiftUI app built by SPM launches as a real windowed app | the probe binary exits without writing its window callback |
| `codesign -dv` distinguishes signed from unsigned binaries | the same output shape appears for a known unsigned binary |

The first five were tested before this file was written and hold. See `.audit/sentinel/decisions.tsv`.

## Open unknowns

- REA's Hopper provider is refused by macOS Automation permission. Native decompilation of the
  Wireshark GUI is therefore unavailable in this environment. Reported, not worked around.
- REA `sharkd` method signatures are not settled in build 4.6.9. Recorded, not guessed.
