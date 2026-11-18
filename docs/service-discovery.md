# Service discovery over AWDL, and how Warlock does it

## How Apple does it

Two mechanisms run side by side on Apple devices. The captures in
[awdl-field-observations.md](awdl-field-observations.md) show both.

1. **In-frame records (D2D).**
   - mDNSResponder doesn't multicast records it scopes to AWDL. It hands them
     to Apple's private DeviceToDevice framework:
     `D2DStartAdvertisingPairOnTransport(key, value, D2DAWDLTransport)` to
     advertise, `D2DStartBrowsingForKeyOnTransport` to browse.
   - The key is the record's name and type and the value is its data, both
     compressed against a fixed "fake packet" containing `_tcp.local` and
     `_udp.local`.
   - Results come back as `D2DServiceFound` / `D2DServiceLost` and are inserted
     into mDNSResponder's cache as though received over mDNS.
   - The AWDL layer (today `wifip2pd`) carries these as Service Response TLVs
     in PSF/MIF action frames.
   - Source: `mDNSMacOSX/D2D.c`, last published in mDNSResponder-1310.140.1.
   - **Receiving, on macOS 11** (the IO80211Family kext, AirPortFamily-1852.4,
     which has symbols): `IO80211AWDLPeer::processServiceResponseTLV` queues
     each record a peer's frame carries, and
     `IO80211ServiceRequestDescriptor::buildmDNSFrame` turns it into an mDNS
     response fed into `awdl0`'s receive path, which is how mDNSResponder
     sees it:
     - from the peer's MAC and its EUI-64 link-local to
       `33:33:00:00:00:fb` / `ff02::fb`, UDP 5353, hop limit 255, flags
       `0x8400`, one record per packet;
     - an SRV gets a second answer: the AAAA of its target, the peer's
       link-local address. The ARPA TLV becomes the reverse PTR
       (`<link-local>.ip6.arpa` → host name);
     - cache-flush on everything but PTRs to services;
     - a peer's records are processed at most 4 times per 90 s (seen live:
       4 bursts, then one every 90 s).

     Warlock's browse does the same for Windows (below).
2. **Ordinary mDNS** (UDP 5353, `ff02::fb`) in AWDL multicast data frames:
   queries, answers, probing and announcements. Devices that are actively
   browsing or connecting use it, and peers answer it.

A device that's merely available (an idle Apple TV, an iPhone with AirDrop
open but nobody nearby looking) shows up **only** through the TLVs.

## Warlock's design

Warlock relies on Windows' built-in DNS-SD (`dnsapi.dll`, the DNS Client
service) for real mDNS, and adds only the AWDL-specific parts. Windows stays
the registrar; Warlock watches the service types it is told about with a
standing query, so nothing has to be sniffed back out of Windows.

- **Advertise** (decided by Parker, 2026-11-17). A client (Koala, the AirDrop
  app):
  - registers its service with Windows itself: `DnsServiceRegister` on the
    Warlock adapter's interface index. Windows answers real mDNS queries and
    handles probing;
  - names the service **type** (e.g. `_rdlink._tcp`) on its control API
    session, a WebSocket. Nothing else about the service goes through the API.
    The type stays watched only while that connection is open.

  For each named type, Warlock (`crates/warlock/src/advertise.rs`; named
  with `--advertise` until the API exists):
  - keeps a standing `DnsStartMulticastQuery` for the type's PTR on its
    adapter (verified below), and an AAAA query for each SRV target;
  - treats an instance as local when its SRV target resolves to the adapter's
    own address. The adapter has exactly one address, our EUI-64 link-local,
    and no AWDL peer can share it. Windows answers AAAA only for its own host
    name (`<computer>.local`), not for a host name a registration makes up,
    so **apps must give Windows' host name as the target**: a made-up one is
    unresolvable for everyone, and isn't advertised;
  - encodes local instances' PTR/SRV/TXT records as Apple devices do, with
    the target as our ARPA host name, into every MIF, and sets the Service
    Parameters' update counter and SSTH to match
    (`docs/awdl-field-observations.md`);
  - withdraws an instance from the TLVs on its goodbye (TTL 0).

  Verified on the adapter (2026-11-17): a registration targeting
  `winlite.local` was advertised and withdrawn with its registration; one
  targeting `made-up.local` was not.

  **Verified over the air (2026-11-18): a Mac finds the service through our
  TLVs alone.** Warlock ran with `--advertise _warlocktest._tcp
  --no-mdns-to-air`, so none of Windows' own mDNS (63 packets) went on the
  air. On a Mac (macOS 11.7), with its cache flushed:
  - `dns-sd -includeAWDL -B _warlocktest._tcp` listed `WarlockTest` on
    `awdl0` 0.7 s after Warlock began advertising;
  - `-L` resolved it at once (host, port 5555, TXT), and `-G v6` gave the
    host our adapter's address on `awdl0`;
  - every packet from our address on the Mac's `awdl0` (16) was one of the
    driver's synthesized answers above: the reverse PTR, PTR, SRV + AAAA and
    TXT, sizes Windows never sent.

  **And an iPhone (iOS 27), the same day.** Its AirDrop share sheet was
  open, so it browsed `_airdrop._tcp`. We registered a test receiver: a
  12-hex instance, TXT `flags=1019` (a Mac's), port 8770, target
  `winlite.local`. Warlock advertised it with `--advertise _airdrop._tcp
  --no-mdns-to-air` (72 packets of Windows' mDNS held):
  - 0.67 s after we began advertising, the iPhone sent a TCP SYN to our
    adapter's address on port 8770, both learned only from our frames;
  - its first mDNS query came 0.4 s after that SYN;
  - nothing listened, so it retried: 30 SYNs over 7 connections.

  How to repeat it, and two ways that don't work:
  - Hold Windows' mDNS back at Warlock (`--no-mdns-to-air`). Windows still
    answers its own standing queries, because it loops them back to itself.
  - A Windows Firewall rule blocking outbound mDNS on the adapter also
    blocks that loopback, so `--advertise` sees nothing.
  - A `pf` rule on the Mac dropping inbound mDNS on `awdl0` also drops the
    driver's synthesized answers, so nothing is found that way either.
- **Browse** (decided by Parker, 2026-11-17; done the same day). Apps browse
  with Windows' own DNS-SD and need nothing from Warlock's API. Peers that
  answer mDNS are found as on any network. For peers that advertise only in
  their frames, Warlock writes their Service Response TLVs onto its adapter
  as mDNS announcements, as Apple's D2D puts them in mDNSResponder's cache
  (`crates/warlock/src/discovery.rs`):
  - from the peer's link-local address to `ff02::fb`;
  - its PTR, SRV and TXT records, plus an AAAA giving its ARPA host name its
    link-local address (the ARPA TLV is the reverse of that address record);
  - TTL 120, D2D's own; everything is re-announced every 60 s;
  - goodbyes (TTL 0) for records the peer drops, and for all of them when the
    peer times out.

  How the TLVs are read (`docs/awdl-field-observations.md`, "Service records
  in TLVs"): a frame with records carries the peer's whole set; a frame
  without records keeps it, unless it's a MIF under a new service-update
  counter.
- **Carry mDNS.** Multicast mDNS frames move between the Warlock adapter and
  AWDL multicast slots in both directions:
  - accept `33:33:00:00:00:fb` and `33:33:80:00:00:fb` on receive;
  - transmit the standard address, as iOS 27 does;
  - Windows' other multicast (LLMNR, SSDP, WS-Discovery) goes out too:
    nothing known about AWDL forbids it (Parker, 2026-11-17).
- **No mDNS engine of our own.** Probing, caching and conflict handling stay
  in Windows. Warlock needs only a DNS wire-format codec for the TLV records.

### Limits
- Windows has no public API to inject records into its mDNS cache, or to
  enumerate services registered by other processes. A standing query sees
  them, but only for a service type you already know (next section). So:
  - an app that registers with Windows but never names its type to Warlock
    gets no TLV advertisement.
- **To verify:**
  - the goodbye on Warlock's adapter (seen on Wi-Fi only so far);
  - whether a registration on all interfaces (`InterfaceIndex` 0) is answered
    on the adapter.
- **Browsing peers that advertise only in frames (verified 2026-11-17).** A
  Mac (macOS 11, AirDrop discoverable by everyone, sharing a file) advertised
  `<12 hex>._airdrop._tcp` in its TLVs and had sent Windows no mDNS of
  its own. Warlock announced it, and then:
  - `DnsServiceBrowse` answered at once with PTR, SRV, TXT and AAAA, all with
    TTL 71: Warlock's 120 s, 49 s after its last re-announcement. The Mac's
    own answers, which came only later, carry TTL 4500 on PTR and TXT, and
    NSEC records;
  - `DnsServiceResolve` and WinRT's DNS-SD watcher gave the full instance:
    host, port, TXT and `fe80::…%<adapter>`.

  Earlier runs showed Windows accepting the announcements and goodbyes, and
  found two encoding bugs, now fixed: a PTR's `0xC000` (the record's own
  name) and empty MIFs.
- **Watching Windows' own registrations (verified 2026-11-17)**, with
  `warlock-tun`'s `dnssd mquery` and `dnssdwatch` examples, on Wi-Fi and on
  the Warlock adapter, against a `DnsServiceRegister` made by another process:
  - **`DnsStartMulticastQuery` (a standing PTR query) sees them.**
    - Windows' own responder answers the query within 0.02 s, including a
      query started 20 s after registration, once the announcements were over.
    - It answers again at every re-query (1, 3, 7 s, ...).
    - Deregistration arrives as a goodbye: the same records with TTL 0.
      So does the registering process dying: killed with no deregistration,
      its records went out with TTL 0 at that moment. A crashed client's
      service can't linger in our TLVs.
    - Each answer is delivered twice.
    - The answers don't say who answered: on the Warlock adapter the same
      query also returned the Apple TV's `_airplay._tcp`. Telling local from
      remote means checking whether the SRV target resolves to the adapter's
      own (only) address.
  - **Windows doesn't answer service-type enumeration**
    (`_services._dns-sd._udp.local`) for its own registrations, so the types
    to watch have to be known in advance.
  - **WinRT's DNS-SD `DeviceWatcher` doesn't report them.** It found the
    Apple TV over AWDL (instance, host, port, TXT, scoped address) but never
    the local registration, filtered by type or not. Its "enumeration
    complete" is a fixed 30 s timeout.
- **Verified (2026-11-17): Windows' DNS-SD works on the Warlock adapter**,
  which is IPv6 link-local only and in the Public firewall profile. Windows'
  "mDNS (UDP-In)" rule allows Public too. Tested with `warlock-tun`'s
  `dnssd` example and `warlock run --log-packets`:
  - **Register:** `DnsServiceRegister` on the adapter's interface index. A
    Mac (macOS 11) browsing over AWDL (`dns-sd -includeAWDL -B`) found the
    service within 0.5 s.
  - **Browse and resolve:** `DnsServiceBrowse` found a Mac's AWDL-registered
    test service, with SRV, TXT and the AAAA of its AWDL link-local. It also
    found an Apple TV's `_airplay._tcp`: the TV answered Windows' multicast
    query within 0.5 s by **unicast** mDNS to our link-local, which Windows
    accepts.
  - One early browse found nothing. It was most likely run before the TV,
    just woken, had joined our cluster. Two later browses found it.
  - Not yet tried: an iPhone's services, and TLV-only peers, which mDNS
    can't show by design.

## Rejected alternatives

| Alternative | Why not |
|---|---|
| Snoop Windows' announcements on the adapter and re-encode them | Windows announces a few times and stops, while TLVs must persist. A standing query gets the same records on demand |
| Clients push whole registrations through the control API, and Warlock registers them with Windows | Makes Warlock a second registrar and apps use a Warlock-only API for what Windows already does. Naming the type is enough (Parker, 2026-11-17) |
| Discover the types to watch automatically | Windows doesn't answer service-type enumeration (`_services._dns-sd._udp.local`) for its own registrations |
| WinRT's DNS-SD `DeviceWatcher` to watch local registrations | It never reports them (verified 2026-11-17) |
| TLVs only, no mDNS | Wrong: iOS browses and answers with real mDNS, including for `_companion-link._tcp` |
| Bonjour for Windows (mDNSResponder) | Optional third-party install, and on the test PC it bound only IPv4 while AWDL is IPv6-only |
| A hand-written mDNS stack | Unnecessary given the above |
