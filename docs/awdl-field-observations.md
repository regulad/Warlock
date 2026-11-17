# AWDL in the field: what Apple devices actually send

Captured 2026-11-16 at a campus site. All test devices were associated to the
same campus Wi-Fi network, which appears to isolate clients from each other.

## Setup

| Vantage point | Tool | What it sees |
|---|---|---|
| Windows PC, TP-Link Archer T3U | `awdlcap` (devourer monitor RX, radiotap pcapng) | everything on one 20 MHz channel at a time |
| MacBook (2015), macOS 11.7.11 | `tcpdump -i awdl0`, mDNSResponder `log stream` | the Mac's own AWDL IP traffic, on every channel |
| Apple TV (3rd gen), iOS 8.4.4-based (12H1006), jailbroken | `tcpdump -i awdl0` | the TV's own AWDL IP traffic |
| iPhone, iOS 27 | (target only) | |

Decoding used Wireshark/tshark 4.6.9's AWDL dissector.

## The iPhone (iOS 27)

**Frames:** PSFs and MIFs (AWDL action subtypes 0 and 3). The action-frame
header still says AWDL version 1.0.

**TLVs:**
- PSF: 4, 18, 5, 6, 24, 12, 7, 17, 21, 33.
- MIF: the same plus 16 (ARPA) and N × 2 (Service Response).

| TLV | Content observed |
|---|---|
| 21 Version | **10.2**, device class **iOS (2)**. Published work stops at 3.x |
| 5 / 24 Election v1 / v2 | self-elected master; master and self metric **526**, counter 35 |
| 4 Sync Parameters | master channel 6; AW period 16 TU; extension counts 3 |
| 18 Channel Sequence | opclass encoding, 16 slots, step count 3 (below) |
| 12 Data Path State | flags `0x9f23`: infra BSSID+channel, infra address, dual-band, country code, social channels, AirPlay solo mode, UMI, unicast options, extension flags. Extended flags `0x197d`: log trigger, RLFC, social channel map, dynamic SDB, DFS proxy, **HE**, **Wi-Fi 6E**, **Ultra Low Latency Infra** |
| 7 / 17 | HT capabilities; VHT capabilities (element 191) inside the 802.11 container |
| 33 | **undecoded**, 14 bytes, e.g. `01 00 00 00 78 79 01 21 86 00 00 00 00 00` |
| 16 ARPA | host name is a **random UUID** `.local`. Two different UUIDs were seen across sessions |
| 6 Service Parameters | present; contents not decoded |

**Channel sequence** (one capture):

```
slot:  0    1  2    3  4  5  6  7  8  9  10   11 12 13 14 15
chan:  120  -  149  -  -  -  -  -  6  -  149  -  -  -  -  -
```

Slot 0 is the iPhone's infrastructure channel (here 120, 40 MHz). It visits
149 in slots 2 and 10 and channel 6 in slot 8, and is absent the rest of the
time. A sniffer parked on 44 never saw it. Others report that the sequence
widens during transfers.

**Service records in TLVs:**
- **Idle**, with AirDrop set to Everyone: AirDrop is *not* advertised as
  `_airdrop._tcp`. It appears as two Network.framework application services:
  - `_applicationservicepairing._tcp` → SRV (ephemeral port) and TXT
    `sn=com.apple.sharingd.AirDrop`, `at=<6-byte hex>`, `sid=<UUID>`;
  - `_appsvcprepair._tcp` → SRV and TXT with the same keys plus `dnm=<device name>`.
- **During an active AirDrop:** additionally `<12 hex>._airdrop._tcp` and
  `CLink-<12 hex>._companion-link._tcp` (Rapport).

## The Apple TV (iOS 8.4.4-based)

- **Idle:** PSFs only, no MIFs. It formed a one-device cluster, as master, on
  its infrastructure channel (44), separate from the iPhone's cluster.
- **Advertised services:** `_airplay._tcp` and `_raop._tcp` PTR/SRV/TXT, with
  the usual AirPlay TXT keys (`model`, `features`, `pk`, `pin=1`, `osvers`, …).
- **IP traffic:** its `awdl0` had no IPv6 address and carried **zero** IP
  packets until a peer connected.

## The Mac (macOS 11.7)

- Advertised `<12 hex>._airdrop._tcp` in TLVs.
- mDNSResponder logged `(awdl_d2d)` activity, which is its D2D bridge to the
  AWDL layer.

## mDNS over AWDL data frames

While AirDrop and AirPlay were active, all three devices sent **ordinary
multicast mDNS** (UDP 5353 to `ff02::fb`) in AWDL data frames:
- queries, responses, probes and announcements;
- including `_companion-link._tcp`, the AirDrop and application-service types,
  AAAA, reverse PTR and NSEC records.

| Sender | Destination MAC in its own stack | Destination MAC on the air |
|---|---|---|
| iPhone, iOS 27 | `33:33:00:00:00:fb` | `33:33:00:00:00:fb` |
| Mac, macOS 11.7 | `33:33:00:00:00:fb` | `33:33:80:00:00:fb` |
| another Apple device | — | `33:33:80:00:00:fb` |

The macOS 11 AWDL driver sets that extra bit itself when transmitting. Its
meaning is unknown. Receivers must accept both.

The Mac received 68 mDNS frames from the iPhone while the T3U, fixed on 149,
caught 19. Multicast goes out in each peer's multicast windows across *its*
channels, so following peers' schedules matters for multicast too.

## AirDrop over AWDL (iPhone → Mac)

- Discovery via TLVs and mDNS as above.
- The transfer was about 2.5 MB of TLS over TCP between the two link-local
  IPv6 addresses, on the AWDL link.

## AirPlay over AWDL (iPhone → Apple TV)

Even with both devices on the same Wi-Fi network, the iPhone used AWDL. The
TV's Wi-Fi interface carried no AirPlay traffic. Sequence, as seen on the TV's
`awdl0`:

1. The iPhone sent mDNS queries for `_airplay._tcp`, `_raop._tcp`,
   `_airplay-p2p._tcp`, and an `A` query for the TV's `.local` host name.
2. The TV answered with ordinary mDNS: PTR, TXT, SRV, AAAA (its EUI-64
   link-local) and NSEC. It had only advertised in TLVs until then.
3. TCP from the iPhone's link-local address to TV port 7000:
   - `GET /info RTSP/1.0` (`User-Agent: AirPlay/1005.13.1`, binary-plist
     body) got `403 Forbidden`, because the TV requires a PIN;
   - `POST /pair-pin-start` got `200 OK`.
4. **First-contact latency:** the iPhone's first SYN and its four
   retransmissions reached the TV together, about 1 s after the first was sent.
   AWDL holds frames until the peer's window and data path are ready.

## Synchronization

Measured on the capture corpus against the receiver's hardware TSF (the T3U),
2026-11-17. `crates/awdl-core/tests/replay.rs` re-checks it on every run.

- **When a sender's next AW starts:** on the receiver's clock, at
  `rx_tsf − (phy_tx_time − target_tx_time) + tx_counter × 1 TU`.
  - Subtracting the sender's own TX delay is essential. iPhone frames waited
    up to 31 ms between target time and air. Without the correction, claims
    scatter by up to 7 ms; with it, a master's claims fit one grid.
  - A single claim is good to ±½ TU, because `tx_counter` is whole TU.
  - The claimed boundary falls 1–4 AWs after the frame's target time, most
    often 3.
- **AWs are 16 TU, and clocks drift.** Relative to the T3U, an iOS 27 iPhone
  ran within ±2 ppm, and the Apple TV (3rd generation, iOS 8-based) at about
  −239 ppm, which is one TU every 4 s. Following a peer means fitting its
  drift.
- **The AW sequence counter counts AWs**, offset by a constant. A follower
  adopts its master's counter: the Mac's jumped by about 949 when it synced to
  the iPhone.
- **Followers sit about a TU off their master.** Against the iPhone's grid,
  the Mac (macOS 11) claimed boundaries 0.7–1.7 ms late (median 1.3 ms), and
  another iOS device between 0.4 ms early and 1.7 ms late.
- **Channel-sequence slot = (AW sequence / 4) mod 16.** Each of the 16 slots
  lasts one 64-TU extended AW, so a sequence spans 1024 TU. An empty slot
  repeats the last non-empty one when the fill channel is `0xffff`. With both
  rules, every frame from an iPhone master and its two followers was received
  on the channel the sender's own sequence gave.
- **The legacy encoding carries the 40 MHz centre channel.** Each entry is
  flags plus a channel, where the channel is the centre of a 40 MHz pair and
  the control-channel bits say whether the primary is 2 below ("lower") or 2
  above ("upper"):
  - the Apple TV on 44 advertises 46, lower;
  - the iPhone's infrastructure channel 120 appears as 118, upper.

  The opclass encoding (TLV 18 from iOS 27 and macOS 11) carries the primary
  channel directly. The Synchronization Parameters TLV embeds the legacy form
  even from senders that also send TLV 18.
- **The election ranks metric first.** The iPhone (metric 538) was master,
  and an iOS device (530) and the Mac (515) followed it at one hop.
- **Open:** in one capture taken while our receiver hopped channels, an
  iPhone sent most of its frames on channel 6 in slots its sequence didn't
  give channel 6. Only about 30 % matched.

## Wire format

The frame and TLV layouts are documented in one place: the module docs of
`crates/awdl-proto`. For example, `dns.rs` holds the name dictionary and
`tlv/service.rs` the Service Response layout. Those layouts follow
Wireshark's AWDL dissector (`epan/dissectors/packet-awdl.c`), and the
crate's `tests/tshark_oracle.rs` checks that our decoding agrees with it on
every captured frame. This document keeps only what we observed on the air.
