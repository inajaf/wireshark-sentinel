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

It is passive by default. Deep inspection, external registry lookups and active probing each happen
only when you ask for them. Blocks are manual and reversible; the app never decides to block on its
own.

## Deep inspection

Click a conversation card to open the inspector. It reads that one conversation out of the capture
file, on demand, not once per packet. The report includes:

- network scope (public, private, CGNAT, link-local, documentation and so on), TTL and estimated hops,
  fragmentation, DSCP/ECN and the IPv6 flow label;
- TCP state from the socket table, handshake counts, retransmissions, duplicate ACKs, out-of-order
  segments, zero-window events, keep-alives, RTT, MSS, window scale, SACK and timestamps;
- TLS version, cipher suite, ALPN, SNI, JA3/JA3S and JA4 where the dissector provides them;
- the certificate chain with subject, issuer, SANs, validity, serial, key algorithm and SHA-256
  fingerprint;
- HTTP hosts, methods, paths, status codes and user agents, DNS questions and answers, QUIC
  versions, SSH key exchange and DHCP hostnames when present;
- the owning process, signature and socket details when `lsof` still knows the connection.

Every value says where it came from: captured packets, the Wireshark dissector, a TLS certificate,
reverse DNS, `lsof`, the process table, an RDAP registry, an ASN lookup, your input, or an inference.
A certificate name and a port guess never look alike.

The inspector can also narrow the packet list to the frames behind that one conversation.

### Opt-in lookups

`Registry record (RDAP)` sends the remote IP address to `rdap.org` and shows the registry answer.
`ASN lookup` sends the address to Team Cymru's DNS service. Both are off by default, both are per
scan, and neither is used for private, loopback, link-local or other non-public addresses. Reverse
DNS is on by default and can be turned off.

`Verify the service` is separate from the scan because it sends new traffic. It opens one TCP
connection to the observed port, records whether it answers, and closes it. Loopback, multicast,
broadcast, unspecified and (unless explicitly allowed) private or CGNAT targets are refused. A TLS
certificate probe is not offered: the passive scan already reads the certificate from the capture.

## Connection path maps

The inspector's `Path map` action turns one selected conversation into a vertical rail:

```
local process → local socket → gateway (or direct route) → traceroute hops → service
```

Building the map is passive. It combines the socket and process from the deep scan, names from
SNI, certificates, HTTP Host, DNS and PTR, the local routing-table answer from
`route -n get <address>`, and the remote scope, ASN and registry values already collected. The same
name seen in more than one place is shown once, with every source that supports it. A name is never
invented from a port number, and a hop that does not answer stays a visible gap.

Two buttons send traffic, and only when pressed:

- **Ping & resolve** sends one ICMP echo. `ping` is run without `-n`, so its first line can carry the
  reverse-DNS name; if the ping has no name, the app asks the system resolver directly. The result
  says whether the reply came from ICMP or only from reverse DNS. This is how a selected IP can
  reveal a domain name when one exists.
- **Trace route** runs `/usr/sbin/traceroute` for IPv4 or `/usr/sbin/traceroute6` for IPv6 with
  `-n -w 1 -q 1 -m 16`. The answering hops are added to the rail. A partial trace is labelled as
  partial rather than extended with guesses. For an inbound conversation, the trace follows this
  Mac's outbound route, which can differ from the path the inbound packet took.

Both probes refuse loopback, link-local, multicast, broadcast, unspecified, unknown and the exact
addresses of this Mac. Private and public targets are allowed, because a LAN service has a real
path and a router can name it. Trace and ping results belong to the path and survive a refresh or a
rebuild; a new probe replaces the previous result for that path.

## Manual firewall blocks

The inspector's `Block…` action, or `Add Address…` in the Blocks manager, creates a pf block. The
scope is an IP address or CIDR range plus an optional port and protocol. It is not a domain
sinkhole, and it cannot target one application: pf sees addresses, not apps. Every block is manual,
shown before it is applied, and recorded in an audit log.

- One administrator prompt per change. The app writes a shell script and runs it once. It backs up
  `/etc/pf.conf`, installs `/etc/pf.anchors/com.local.sentinel`, inserts a hook before the first
  Apple anchor, validates the result with `pfctl -n`, and restores the backup if validation or
  loading fails.
- Existing connections to the target are killed after the rules load. pf can only kill states by
  address, so a port-specific block still closes every state to that address; the editor says so.
- `Unblock` rewrites the anchor without that target. `Remove All…` empties it. Inactive records and
  the audit log stay in `~/Library/Application Support/WiresharkSentinel/blocks.json`.
- `Keep these blocks after this Mac restarts` is off by default. Turning it on installs
  `/Library/LaunchDaemons/com.local.sentinel.pf.plist`, which loads `/etc/pf.conf` at boot. Turning it
  off removes the daemon. Either change asks for administrator approval.
- The planner refuses loopback, multicast, broadcast and unspecified addresses, the exact addresses
  of this Mac, port zero, zone suffixes and ranges broader than IPv4 `/8` or IPv6 `/32`. An ordinary
  CIDR range that happens to contain this Mac is allowed, with a warning; only the exact local
  address is a hard refusal.

The app is ad-hoc signed, so a Network Extension is not available. pf is the enforcement layer.

## Verification

Each command exits non-zero when its claim is false.

```sh
swift build && swift test                   # units and their behaviour
scripts/smoke-live.sh                       # the engine streams live packets
scripts/verify-ui.sh                        # four panes render in a real window
scripts/verify-live.sh 20                   # live capture, identification, attribution, report
```

`swift test --filter SentinelPathTests` exercises the route, traceroute and ping parsers, probe
safety, and the passive path builder without sending any network traffic.

`scripts/verify-ui.sh` also writes a screenshot of the app window to `build/ui-evidence/window.png`
and the rendered pane identifiers to `build/ui-evidence/ui.json`.

## Limitations, stated plainly

- The Sentinel pane explains what it can prove from the traffic and from `lsof`. A connection that is
  already closed before the process table is read may show as unattributed.
- Names are only as good as the traffic. A host that uses neither SNI nor DNS, and has no reverse
  record, stays unidentified, and the app says so rather than guessing.
- The capture is not decrypted. Content inside TLS is not read; identity comes from the handshake
  and the certificate, not from the payload. TLS 1.3 commonly encrypts certificates, so some
  connections have a handshake but no certificate to show.
- Deep inspection reads the capture file after the fact. It does not re-dissect every live packet.
- The path map is only as complete as the evidence. If the network drops traceroute probes, the
  intermediate hops are missing and the map says the path is partial. A ping that gets no reply does
  not prove the service is down; firewalls commonly drop ICMP. A PTR name can be stale or shared.
- RDAP and ASN lookups leave this Mac with the remote IP address. Active probing opens a new
  connection that the far end can see. Ping and traceroute send packets as well. All four are
  explicit, per-target actions.
- A block covers an address and optionally a port. It cannot name a domain or one application, and
  it requires administrator approval because pf rules belong to the system.
- The block script has been checked with `pfctl -n` and its unit tests, but applying it for real
  changes this Mac's firewall and cannot be exercised by an automated test.
- `sharkd` is not used. The packet list streams from `tshark -T ek`, the detail tree from
  `tshark -T json`, and the bytes from `tshark -x`.
