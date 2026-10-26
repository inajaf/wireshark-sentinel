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
