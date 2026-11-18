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

  For each named type, Warlock:
  - keeps a standing `DnsStartMulticastQuery` for the type's PTR on its
    adapter (verified below);
  - treats an instance as local when its SRV target resolves to the adapter's
    own address. The adapter has exactly one address, our EUI-64 link-local,
    and no AWDL peer can share it;
  - encodes local instances' PTR/SRV/TXT records (plus our ARPA host name)
    into our Service Response TLVs, so passive peers see them;
  - withdraws an instance from the TLVs on its goodbye (TTL 0).
- **Browse.** For a client's browse, Warlock:
  - runs `DnsServiceBrowse` / `DnsServiceResolve` (or `DnsStartMulticastQuery`)
    on its adapter;
  - merges the results with records learned from peers' TLVs;
  - delivers found/lost events on the control API.

  A TLV record is "lost" when its peer times out or its SUI changes.
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
    gets no TLV advertisement;
  - an app that browses Windows directly misses TLV-only peers.
- **To verify:**
  - the goodbye on Warlock's adapter (seen on Wi-Fi only so far);
  - whether a registration on all interfaces (`InterfaceIndex` 0) is answered
    on the adapter.

  Optional fallback: Warlock synthesizes mDNS responses for TLV-learned records
  onto its adapter.
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
