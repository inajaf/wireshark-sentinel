## engine-stream
GOAL: recorded and live Wireshark output becomes CapturedPacket values through the installed engine
SCOPE: Sources/SentinelCore/Engine/*, Tests/SentinelCoreTests/EngineTests.swift, scripts/smoke-live.sh
ACCEPTANCE: fixture tshark output parses into packets with columns and fields; live capture on en0 yields packets; detail tree and bytes load per frame
VERIFY: swift test --filter EngineTests && bash scripts/smoke-live.sh

## identity-resolver
GOAL: every remote endpoint gets an EndpointIdentity from SNI, HTTP Host, DNS, PTR, port service and offline org data
SCOPE: Sources/SentinelCore/Identity/*, Tests/SentinelCoreTests/IdentityTests.swift
ACCEPTANCE: example.com resolves to a named fact from SNI and DNS; an address with no evidence is reported unidentified with a reason
VERIFY: swift test --filter IdentityTests

## process-attribution
GOAL: a flow on this Mac is attributed to the local process that owns the socket, with its signing status
SCOPE: Sources/SentinelCore/Attribution/*, Tests/SentinelCoreTests/AttributionTests.swift
ACCEPTANCE: a socket opened by the test process is attributed to that process; an unsigned binary is reported unsigned
VERIFY: swift test --filter AttributionTests

## suspicion-engine
GOAL: flows carry weighted signals and a verdict that a person can act on
SCOPE: Sources/SentinelCore/Suspicion/*, Tests/SentinelCoreTests/SuspicionTests.swift
ACCEPTANCE: beaconing, inbound unsolicited and unsigned-process flows are flagged; ordinary browsing flow stays known
VERIFY: swift test --filter SuspicionTests

## report-writer
GOAL: one readable report line per remote endpoint, plus a JSON form
SCOPE: Sources/SentinelCore/Report/*, Tests/SentinelCoreTests/ReportTests.swift
ACCEPTANCE: rendering an assessment set produces a line per endpoint carrying verdict, name and reason
VERIFY: swift test --filter ReportTests

## app-shell
GOAL: a launched app with packet list, detail tree, bytes and Sentinel panes over a live capture
SCOPE: Sources/WiresharkSentinel/*, scripts/build-app.sh, scripts/verify-ui.sh
ACCEPTANCE: the built bundle launches, all four panes exist, and captured packets appear in the list
VERIFY: bash scripts/build-app.sh && bash scripts/verify-ui.sh

## integration
GOAL: the four panes, the scanner and the report run as one live session against real traffic
SCOPE: Sources/WiresharkSentinel/CaptureController.swift, scripts/verify-live.sh, README.md
ACCEPTANCE: verify-live.sh exits 0 with a report carrying a verdict for every remote non-local endpoint
VERIFY: bash scripts/verify-live.sh 20

## Delivered, with the evidence that closed each unit

| unit | test id | gate | result |
|---|---|---|---|
| engine-stream | task-1 | swift test --filter SentinelEngineTests | 13 tests, 1 skipped, 0 failures; live smoke 7534 packets on en0 |
| identity-resolver | task-2 | swift test --filter SentinelIdentityTests | 9 tests, 0 failures |
| process-attribution | task-3 | swift test --filter SentinelAttributionTests | 8 tests, 0 failures, incl. a real loopback socket attributed to the test pid |
| suspicion-engine | task-4 | swift test --filter SentinelSuspicionTests | 17 tests, 0 failures, beaconing falsified by mutation |
| report-writer | task-5 | swift test --filter SentinelReportTests | 9 tests, 0 failures, JSON contract exercised with the real consumer |
| engine-flags | task-6 | swift test --filter SentinelEngineTests | 17 tests, 0 failures; flags proven on live en0 |
| suspicion-accuracy | task-7 | swift test --filter SentinelSuspicionTests | 24 tests, 0 failures; router false accusations removed |
| report-wording | task-8 | swift test --filter SentinelReportTests | 11 tests, 0 failures |
| integration | lead | scripts/verify-live.sh 25 | PASS, 21 conversations, all carrying a verdict |
| app-shell | lead | scripts/verify-ui.sh | PASS, four panes, 8489 packets, 1100x728 window |

## Lead fixes inside the integration unit, each measured

- Batched packet publishing: ingest went from 919 to 2135 packets against 2237 raw in the same window.
- Direction from the TCP handshake and port roles, via engine task-6.
- One conversation per connection: duplicate remote endpoints in the rendered report went from 7 to 0.
- Local listener table populated so inbound-un solicited is not over-eager; parser verified equal to the lsof port set.
