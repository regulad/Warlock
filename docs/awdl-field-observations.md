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
  - **`tx_counter` counts to the start of the next slot** (a 4-AW extended
    AW), not the next AW. In every capture, the AW that starts at a claimed
    boundary has `aw_seq ≡ 0 (mod 4)`: 5,639 of 5,641 frames, from every
    device. That's why claims land 1–4 AWs ahead. Warlock first claimed the
    next AW, which put its slot grid 0–3 AWs off where it really was.
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

## Joining a cluster (2026-11-17)

Warlock joined as a follower, sending PSFs and MIFs modelled on the macOS 11
Mac's (see `crates/awdl-core/src/active.rs`).

- **Witnesses.** macOS 11 logs AWDL in detail on the kernel's
  `com.apple.p2p` channel: `log stream --level debug --predicate
  'eventMessage CONTAINS "com.apple.p2p"'`. It prints the AWDL state and
  sequence, the peer count, and per-peer statistics such as
  `<mac (RSSI)> txQ[…] txOk[…] RxPkts[…] TxBytes`. `dns-sd -includeAWDL -B
  _airdrop._tcp local` keeps a Mac's AWDL active. The Apple TV (iOS 8-based)
  has a shell but no AWDL logs.
- **What acceptance looks like.**
  - Both the Mac and the Apple TV add an accepted peer to their neighbour
    table, as a *permanent* entry for its EUI-64 link-local address.
  - Once that entry existed, the Apple TV's multicast pings went out over
    AWDL, where before it sent nothing (its `awdl0` counters stayed at 0
    throughout).
  - Pinged at our link-local address, the Mac set up Block Ack first (ADDBA,
    TID 0), then sent QoS Data frames. Our hardware ACKed them, and the Mac
    counted them as acknowledged (`txOk`).
  - With an ICMPv6 echo responder behind the engine, the Mac's `ping6`
    succeeded, 7 of 8. Round trips started at 21 ms and grew by about 48 ms
    per ping: the 1048.6 ms sequence cycle minus the 1 s ping interval.
  - Instrumented, the Mac delivered its echo requests to us once per
    sequence cycle, in slot 0, about 8 ms into the AW. Our replies left 6–13
    ms after each request. So the wait is the Mac's: its AWDL was idle in
    "Low Power" state, with a sparse sequence.
  - **Control:** the Mac pinging genuine Apple peers the same way showed the
    same pattern, and worse. An iOS device: 62, 106, 147 ms, 50 % loss. An
    iPhone: 1009 ms, 75 % loss. Idle AWDL is like that. It should tighten when
    AWDL is busy (e.g. during a transfer), which is to be checked.
- **The Apple TV (iOS 8-based) never sends us unicast.** Our unicast reaches
  it: its `tcpdump` shows our echo requests and TCP SYNs to the AirPlay port
  (7000) arriving. Its kernel answers both, echo replies and SYN-ACKs from
  the opted-in AirPlay socket, but its AWDL driver never puts them on the
  air. While we ping it, it transmits nothing but broadcast and multicast
  (it does answer our mDNS queries, to `33:33:80:00:00:fb`).
  - Ruled out: our receive bandwidth (20 or 40 MHz); our clock (fixed); our
    slot claim (fixed); XNU's restricted AWDL sockets (the AirPlay socket's
    SYN-ACK was held too); being a follower rather than a master; and the
    iPhone's TLV choices (infrastructure channel 0, the data-path extension,
    HT40, an ARPA host name, version 10.2/iOS), alone or together.
  - When an iPhone visited it for AirPlay, the iPhone stayed master of its
    own cluster and alternated 149 and 44, 4 slots each. The Apple TV stayed
    its own master (metric 80).
  - Open: an over-the-air capture of a working iPhone → Apple TV unicast
    exchange, to compare against.
- **Masters change under us.** When an iPhone appeared during a join, it
  outranked the Mac and became master. We re-synced to it on our own.

## Wire format

The frame and TLV layouts are documented in one place: the module docs of
`crates/awdl-proto`. For example, `dns.rs` holds the name dictionary and
`tlv/service.rs` the Service Response layout. Those layouts follow
Wireshark's AWDL dissector (`epan/dissectors/packet-awdl.c`), and the
crate's `tests/tshark_oracle.rs` checks that our decoding agrees with it on
every captured frame. This document keeps only what we observed on the air.
