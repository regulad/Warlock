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
service) for real mDNS, and adds only the AWDL-specific parts. It is the
registrar for services on the AWDL link, so nothing has to be sniffed back out
of Windows.

- **Advertise.** A client (Koala, the AirDrop app) registers a service through
  Warlock's IPC. Warlock:
  - calls `DnsServiceRegister` with `InterfaceIndex` set to its own adapter,
    so Windows answers real mDNS queries and handles probing;
  - encodes the same PTR/SRV/TXT records (plus our ARPA host name) into our
    Service Response TLVs, so passive peers see them.
- **Browse.** For a client's browse, Warlock:
  - runs `DnsServiceBrowse` / `DnsServiceResolve` (or `DnsStartMulticastQuery`)
    on its adapter;
  - merges the results with records learned from peers' TLVs;
  - delivers found/lost events over IPC.

  A TLV record is "lost" when its peer times out or its SUI changes.
- **Carry mDNS.** Multicast mDNS frames move between the Warlock adapter and
  AWDL multicast slots in both directions:
  - accept `33:33:00:00:00:fb` and `33:33:80:00:00:fb` on receive;
  - transmit the standard address, as iOS 27 does;
  - keep Windows' other multicast chatter (LLMNR, SSDP) off the link.
- **No mDNS engine of our own.** Probing, caching and conflict handling stay
  in Windows. Warlock needs only a DNS wire-format codec for the TLV records.

### Limits
- Windows has no public API to inject records into its mDNS cache, or to list
  services registered by other processes. So:
  - a third-party app that registers directly with `DnsServiceRegister` on the
    adapter gets no TLV advertisement;
  - an app that browses Windows directly misses TLV-only peers.

  Optional fallback: Warlock synthesizes mDNS responses for TLV-learned records
  onto its adapter.
- **To verify (W4):** that Windows' DNS-SD behaves on a Wintun adapter (IPv6
  link-local only, no IPv4, Public firewall profile).

## Rejected alternatives

| Alternative | Why not |
|---|---|
| Snoop Windows' announcements on the adapter and re-encode them | Windows announces a few times and stops, while TLVs must persist; Warlock already knows what it registered |
| TLVs only, no mDNS | Wrong: iOS browses and answers with real mDNS, including for `_companion-link._tcp` |
| Bonjour for Windows (mDNSResponder) | Optional third-party install, and on the test PC it bound only IPv4 while AWDL is IPv6-only |
| A hand-written mDNS stack | Unnecessary given the above |
