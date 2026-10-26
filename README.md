# Wireshark Sentinel

A macOS app that keeps Wireshark's original capture and dissection engine and rebuilds the
frontend around it, then adds the part Wireshark does not do for you: it works out who every
remote resource is, which program on this Mac opened the connection, and whether the connection
deserves your attention.

![packet list, details, bytes and the Sentinel pane](build/ui-evidence/window.png)

## Why this shape

The request was to rebuild Wireshark and add automatic unknown-resource scanning. Inspection of
the shipped app decided how far "rebuild" should go. Measured with REA on this machine:

| Fact | Value |
|---|---|
| Main executable | universal Mach-O, x86_64 + arm64, 39,453,904 bytes |
| sha256 | `4612a63c24c2865a26734a9321cf2d3874a26b4a5129a24f409952f8af26cc85` |
| Dissection engine | `libwireshark.19.dylib`, 245,574,112 bytes, linked separately |
| Capture and file I/O | `libwiretap.16.dylib`, `libwsutil.17.dylib` |
| Frontend | Qt6 Widgets over those libraries |
| Protocols known to the engine | 3,169 |
| Fields known to the engine | 272,543 |
| Signature | Developer ID, Wireshark Foundation, team `7Z6EMTD2C6`, hardened runtime |

The protocol truth lives in a shared library, not in the window. So this app drives the installed
engine instead of reimplementing it, and puts the new work where the request wanted it: the
interpretation.

Nothing is copied or redistributed. Wireshark must be installed, and this app invokes it.

## Requirements

- macOS 14 or later, Xcode command line tools with Swift 6.
- Wireshark 4.x installed in `/Applications` or `~/Applications`. Built and tested against 4.6.9.
- Membership of the `access_bpf` group, which the Wireshark installer sets up. Capture runs
  without `sudo`.

## Build and run

```sh
scripts/build-app.sh
open "build/Wireshark Sentinel.app"
```

## What you get

Four panes, laid out the way Wireshark lays them out.

1. **Packet list** carries Wireshark's own columns: No., Time, Source, Destination, Protocol,
   Length, Info.
2. **Packet details** is the protocol tree for the selected frame.
3. **Packet bytes** is the hex and ASCII dump.
4. **Sentinel** is the new pane. One card per conversation, and only the ones needing attention
   by default.

## What the Sentinel pane answers

For every remote resource:

- **Who is it.** Names come from TLS SNI, HTTP Host and DNS answers first, because those are what
  the remote party claims about itself. Reverse DNS, the port service table and the TLS
  certificate come next. Every name carries the source it came from, so you can judge it.
- **Who started it.** Outbound to a remote, or an inbound connection to this Mac. Inbound
  connections are called out, because a connection you did not open is the interesting case.
- **Which program.** The local process that owns the socket, with its pid and its code signing
  status. An unsigned or ad-hoc-signed program reaching out is called out on its own.
- **Whether it is expected.** Weighted signals become one of three verdicts: Expected, Not sure
  yet, or Possibly spying. Every verdict carries the sentence that produced it.

A name comes only from evidence: the TLS server name, the HTTP host header, a DNS question, reverse
DNS, or a certificate subject. Every name line says where it came from. A port number is never used
as a name. When the only thing known is the port, the report says so plainly: `unidentified, port 443
looks like https`. That distinction is the whole point, because "Google" guessed from a port number
is an accusation, not a fact.

What a 25 second capture on this Mac actually produced: 21 conversations, 15 expected, 5 it was
not sure about, and 1 worth a look. The identified ones carried real names and owners, such as
`172.217.16.142:443 (lcsofb-ac-in-f14.1e100.net)` opened by `Google Chrome Helper`, and
`17.248.211.20:443 (gateway.icloud.com)` opened by `cloudd`, signed by Apple. The uncertain ones were
mostly plaintext HTTP to Google download hosts. The one that earned the top verdict was a LAN device
broadcasting UDP from a high port, which nothing on this Mac could name.

Signals the engine looks for: unidentified destination, inbound connection to this Mac, regular
beaconing, unsigned or ad-hoc process, unusual remote port, plaintext protocol, high-volume DNS,
long-lived idle connection, and traffic carrying no application protocol at all.

It reports. It never blocks, filters, or kills traffic.

## Verification

Each command exits non-zero when its claim is false.

```sh
swift build && swift test                   # units and their behaviour
scripts/smoke-live.sh                       # the engine streams live packets
scripts/verify-ui.sh                        # four panes render in a real window
scripts/verify-live.sh 20                   # live capture, identification, attribution, report
```

`scripts/verify-ui.sh` also writes a screenshot of the app window to `build/ui-evidence/window.png`
and the rendered pane identifiers to `build/ui-evidence/ui.json`.

## Limitations, stated plainly

- The Sentinel pane explains what it can prove from the traffic and from `lsof`. A connection that is
  already closed before the process table is read may show as unattributed.
- Names are only as good as the traffic. A host that uses neither SNI nor DNS, and has no reverse
  record, stays unidentified, and the app says so rather than guessing.
- The capture is not decrypted. Content inside TLS is not read; identity comes from the handshake
  and the certificate, not from the payload.
- `sharkd` is not used. The packet list streams from `tshark -T ek`, the detail tree from
  `tshark -T json`, and the bytes from `tshark -x`.
