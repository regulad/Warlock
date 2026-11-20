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
- **Encoding** (captures and live, 2026-11-17):
  - every PTR's data is the instance label followed by `0xC000`, which
    stands for the record's own name (the service type); Wireshark shows it
    as nothing. Owner names use only codes `0xC001`, `0xC004`, `0xC007` and
    `0xC00A`; SRV targets end in `0xC00C` (`local`);
  - names are lowercased (`clink-…`), while the device's own mDNS uses
    `CLink-…`;
  - a frame with records carries the whole set: under one service-update
    counter, every frame with records held the same ones. iPhones and Macs
    send them in MIFs, the Apple TV in PSFs;
  - a frame without records doesn't mean "none": a Mac's MIFs had none under
    counters 0 and 2, then always its 3 under 5. Live, a lone empty MIF came
    between ones with records.
- **Service Parameters (TLV 6)**, named after iOS 27's `wifip2pd`
  (`AWDLActionFrame.ServiceParameter`): `flags` (u8), `dwellTime` (u16),
  `serviceUpdateIndicator` (the SUI) and the `SSTH`, a 256-bit table sent
  compressed (`ssthByteMap`, then the nonzero bytes):
  - a member per carried record's owner name: the CRC-8/SMBUS (polynomial
    0x07, init 0) of the name in DNS wire format, A–Z lowercased. Found by
    fitting the captures, then checked on every frame with records (8,379);
  - Macs (macOS 11) and the Apple TV also set their SRV target host's
    member: the owner of the address record D2D advertises for AWDL, which
    isn't a TLV. The iPhone (iOS 27) never does, and neither does Warlock;
  - empty while nothing is advertised;
  - `flags` and `dwellTime` were 0 from every device in our captures
    (`examples/svcbits.rs` prints them). In the macOS 11 kext, a flag in
    `flags` marks a MIF too full to carry all the records;
  - the name matches Wi-Fi Direct's "supported service type hash", a
    256-bit table of hashed Bonjour service types (wpa_supplicant's
    `README-P2P`);
  - `wifip2pd` also has an `ssthRequest`, and Service Request TLVs carry
    `requestedOffset`, `requestedLength` and `key`: presumably a peer checks
    the SSTH, then asks for records it lacks. No frame in our captures
    carries TLV 0 or 1, and a Mac took our records straight from our MIFs
    without asking (`docs/service-discovery.md`).
- **TLV order** in a Mac's MIF: 4, 5, 18, 24, 12, 7, 20, 17, 16, 21, 6, then
  the records (2). An iPhone's puts 18 before 5 and 33 after 17; the Apple
  TV's PSFs go 4, 5, 6, 12, 7, then the records. A Mac accepted records from
  Warlock's order (4, 5, 18, 24, 6, 12, 7, 21, 20, 16, then 2).
- **What triggers advertising:** a Mac sharing a file, AirDrop discoverable
  by everyone, advertised nothing in its frames until an iPhone appeared,
  then `_airdrop._tcp`. Two iOS devices nearby advertised
  `_companion-link._tcp` while it shared. The Apple TV advertised nothing
  while idle, whether it led or followed us.

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
  - **Why: the Apple TV has an idle and an active AWDL mode.**
    - Idle, it parks on its home channel (44 in all 16 slots) and sends PSFs
      only. It receives everything and sends multicast, but holds unicast
      for everyone.
    - In a session that got as far as AirPlay's PIN prompt, it switched at
      one moment to `6 149 149 – – – 44 44` (×2), adding AWDL's social
      channels. Later it sat on 149 for 6 slots while the iPhone was there.
    - Only in active mode did the iPhone's TCP SYNs get SYN-ACKs: the TV
      set up Block Ack with the iPhone (ADDBA, TID 0), then sent them.
    - Our presence on 44, mDNS queries, pings and SYNs never switched it out
      of idle.
    - Before that, its idle sequence briefly had 3 empty slots in each half
      (`44 ×5, – ×3`), which looks like scanning other channels.
  - **What wakes it is a Bluetooth LE "AirPlay source" advert**, not
    anything on AWDL. See [Waking AWDL over Bluetooth LE](#waking-awdl-over-bluetooth-le).
  - **Awake, it still holds our unicast while we're in its cluster.** With
    the TV woken by our own advert and Warlock following its active
    sequence:
    - Its `tcpdump` showed our echo requests and our SYNs to the AirPlay
      port arriving, and its kernel answering every one.
    - A Mac sniffing channel 44 saw our pings and the TV's hardware ACKs,
      but nothing from the TV to us: no ADDBA, no data. That's the channel
      where it served the iPhone, so its driver isn't trying at all.
  - **It served us once, when we both followed a third device.** A device
    with metric 532 (an iOS one, by its sequence) appeared and became master.
    The TV joined its cluster, and we followed. Within 0.4 s of our sync
    moving there:
    - the TV flushed the echo replies it had queued, up to 17.6 s old;
    - then set up Block Ack with us and sent QoS data;
    - live replies came back in 3–50 ms.

    It happened again when that device returned. Each time our sync went
    back to the TV, the replies stopped.
  - Ruled out, each tested with the TV awake:
    - every TLV of the iPhone's MIF, sent verbatim (the same changes as an
      iPhone, all at once);
    - TCP to AirPlay's own socket rather than ICMP;
    - our AW sequence label (shifted by a full sequence);
    - claiming mastership on the TV's grid, at metric 60 or 600 (at 600 the
      TV sometimes named us master);
    - our sync claims' accuracy. That one did need fixing: we reported zero
      TX latency, and frames built before a hop claimed a slot an AW late.
      After the fix, the Mac measured our claimed grid within 0.36 ms p50
      (max 4.2 ms) of the TV's, tighter than the TV's own claims.
  - **Reproduced on purpose** with an iPhone (AirDrop open) and a Mac nearby,
    both at metric 528. The TV's PSFs named the Mac as master: it had joined
    the Mac's cluster. It set up Block Ack with us and answered our pings
    4.4 s into the run, and kept answering: 22 replies in 46 s, 120–660 ms
    while we followed the Mac (its Low Power pattern), 8–25 ms while we
    followed another iOS master.
  - **So the rule, as observed:** while it is master, the TV holds unicast
    for its own followers. It serves peers when it follows a higher-metric
    master, and it served an iPhone that kept its own cluster.
  - **Warlock as master works.** On its own clock at metric 600 (the TV's is
    80), with an idle iPhone's sequence (6 in slots 0 and 8, 149 in 2 and
    10):
    - Warlock stood as master 2.1 s in, and the TV joined: its PSFs named us
      as master.
    - 5 s later it set up Block Ack and answered our pings: 41 of 68, p50
      84 ms, p90 304 ms.
    - As a follower, the TV took our timing but kept advertising its own
      sequence (`6 149 149 – – – 44 44`). Apple followers sync to the
      master's grid; they don't adopt its channels.

    (An earlier experiment that only *claimed* mastership kept the TV's
    grid, so once the TV followed us we were following it back; that
    failed.) The cross-band hops of our sequence, 6 ↔ 149, took 14–21 ms
    p50 in this run, longer than an AW: likely much of the loss.
  - **In active mode, its data frames carry TLVs.** They use the "long
    format" header: its HT capabilities and data path state, the latter
    with AirPlay Solo Mode set (flags `0x0763`, against `0x0363` in its
    PSFs). No iPhone or Mac data frame we have does this.
  - This doesn't constrain Koala, which plays the TV's role and is always
    active.
- **Masters change under us.** When an iPhone appeared during a join, it
  outranked the Mac and became master. We re-synced to it on our own.

## An iPhone (iOS 27) and Warlock (2026-11-17)

With AirDrop open on the iPhone (metric 530), a Mac (macOS 11) nearby, and
Warlock at 40 MHz:
- **Following the iPhone**, Warlock synced in 1 s, including its infra
  channel 120. The iPhone set up Block Ack with us at 4.2 s and answered 15
  of 59 pings (3.6–380 ms). It also served us from its own cluster while we
  led ours (12 of 59).
- **Leading needs an advancing election counter.** Apple devices put a
  counter in election parameters v2, and a master's advances about every
  3 s (an iPhone's: 130 → 143 in 40 s; 1278 → 1284 in 25 s). Ours stood
  still. Warlock leading at a metric above the iPhone's:

  | metric | counter | iPhone | Mac |
  |---|---|---|---|
  | 600 | 0, still | kept its own cluster | kept following the iPhone |
  | 600 | 20000, still | kept its own cluster | joined us |
  | 540 | 20000, still | joined, then left within 20 s | joined us |
  | 540 or 600 | from 0 or 20000, +1 every 3 s | joined, stayed | joined, stayed |

  With the counter advancing, the iPhone answered 15–19 of 39–49 pings.
  The engine now advances it every 3 s while master.
- **Which counter wins isn't "the higher one".** Two iOS devices both at
  metric 65: the one with counter 16163 joined the one with 130. The
  engine still ranks by metric, then counter (`election.rs`); only the
  metric case is confirmed.
- **Metrics seen:** iPhone 65 idle, 528–538 with AirDrop open or during
  AirPlay; Mac 65 idle, 513–515 active; Apple TV (iOS 8) 80; another iOS
  device 539. Warlock's default stays 60, so it follows any Apple device.
- About 60–75 % of our pings to the iPhone went unanswered, leading or
  following. Fixed; see the next section.

## Unicast only in explicit slots (2026-11-17)

Pinging the Apple TV as master, `awdljoin` logged each ping's slot, AW and
offset, and the TV's `tcpdump` showed which requests arrived:
- It received exactly the 33 of 58 requests that got replies, and every
  reply it made reached us: the loss was all ours → TV.
- On 149, pings got through in slots 2 and 10 and never in slots 3–5 and
  11–13. The TV's sequence is `6 149 149 – – – 44 44`: 149 is explicit in
  slots 1–2 and 9–10, and slots 3–5 are empty with "repeat current" fill.
  Its PSFs put it on 149 in those empty slots too, but it takes no unicast
  there.
- An apparent pattern by offset into the AW (0–2 ms: 2 of 25 answered,
  4–6 ms: 29 of 30) was a confound. Early sends landed in empty slots;
  sends in explicit slots came late, after the band-change hold.

Sending unicast only in a peer's explicit slots (`Engine::poll`): 58 of 58
answered, p50 6.9 ms, p90 12 ms, after waiting up to ~350 ms for the next
explicit slot.

**Apple devices apply the same rule to us.** Following, we advertised the
master's sequence verbatim: a Mac's, with 149 explicit only in slots 0, 9
and 10. An iPhone answered pings we sent in its explicit slot 2, but its
reply waited ~420 ms for one of *our* explicit 149 slots. As a follower, we
now advertise the master's sequence with its repeats written out
(`schedule::widen`). We hop those slots anyway.

With the iPhone (AirDrop open):

| Warlock | answered | reply p50 | p90 | max |
|---|---|---|---|---|
| following, verbatim sequence | 46 of 49 | 36 ms | 439 ms | 970 ms |
| following, widened | 47 of 49 | 4.7 ms | 21 ms | 50 ms |
| leading (metric 600) | 47 of 48 | 4.4 ms | 17 ms | 411 ms |

Widening didn't stop the iPhone from talking to us, contrary to the "pin"
warning in prior-art.md (that one was about pinning one channel in all 16
slots).

Since issue #15, Warlock no longer takes the master's sequence (see the
next section). It advertises its own, with every slot it's on named the
same way.

## How Apple devices choose their channel sequence (2026-11-20)

An iPhone scanning a Koala QR code never found Warlock: Warlock was
following an Apple TV (3rd generation) that stays on 44 in all 16 slots, and
had copied that sequence, while the iPhone and a Mac met on 6, 149 and their
infrastructure channel 120 and never visit 44 (issue #15). Static analysis
of macOS 11.7's IO80211Family (x86_64) and iOS 27.2.1's IO80211DriverKit
(the DriverKit shared cache of 24B156) shows how Apple devices build theirs.

- **A template per schedule state.** `IO80211AWDLPeerManager::
  setChannelSequenceByState` fills the 16 slots from a row of slot types
  for the current schedule state: macOS 11's table is at `0x11f080` (34
  states, copied into the peer manager by its constructor), iOS 27.2.1's is
  `_channelSeqSlotTypes` (56 states). Slot types include off AWDL, "master
  channel 1" (the 2.4 GHz social channel, 6), "master channel 2" (the 5 GHz
  one, 149, else 6), the infrastructure channel under conditions (else off),
  and, in realtime states, preferred and negotiated data channels. The
  social channels come from `configureValidAWDLChannels`: on minintosh,
  `social channel 2G: 6 on 5G: 149 5G Alt: 44 country code: US` and
  `strategy:AwdlStateMachine master channel 1=>6 master channel 2=>149`.
- **No slot type is "the master's channel".** A follower takes its master's
  timing and builds its channels from the same templates as a master: in
  `mac-iphone149.pcapng` the iPhone, master, sent `118 0 151 0 0 0 0 0 6 0
  151 …` (its infrastructure channel 120 in slot 0) while the Mac and an
  iOS device following it sent their own, without 118. Copying a peer's
  sequence happens only in `followPeerChannelSequence`: when AirPlaying to a
  peer whose data path state sets flag `0x0080` ("follow channel sequence",
  read in macOS 11's `parseAwdlDataPathTLVAndTakeAction`), and on iOS 27
  also in a ranging follow mode. Inside a realtime group, iOS 27's
  `RealTimeGroup` row is empty: `composeRTGChannelSequence` builds that
  sequence, which hasn't been analysed yet.
- **No device in our captures sets the follow bit.** None of the 13
  captures in `captures/air` (2026-11-20) has a data path state with
  `0x0080`, including the two where the iPhone AirPlays to the Apple TV.
  There the TV switches `0x0400` (AirPlay solo mode) on and off (`0x0363`,
  `0x0763`), and the iPhone, AirPlaying, sends its own sequence with the
  TV's channel in half its slots, `151 151 151 151 46 46 46 46 …` (149 and
  44 at 40 MHz), while the TV sends `46` in all 16 slots or `6 151 151 0 0 0
  46 46 6 151 151 0 0 0 46 46`. Warlock keeps the bit per peer
  (`Peer::follow_channel_sequence`) but doesn't AirPlay, so it doesn't
  follow anyone for it (issue #16).
- **The templates are what the devices log** (5 GHz social channel 149,
  2.4 GHz 6, `-` off AWDL):

  | State | Template | Logged |
  |---|---|---|
  | `Idle` (both) | `149 149 149 - - - - - 6 149 149 - - - - -`¹ | a Mac: `[149 149 149 0 0 0 0 0 6 149 149 0 0 0 0 0] Idle` |
  | `Low Power` (macOS 11) | `149 - - - - - - - 6 149 149 - - - - -`¹ | a Mac: `[149 0 0 0 0 0 0 0 6 149 149 0 0 0 0 0] Low Power` |
  | `Discovery` (both) | `149 149 149 149 - - - - 6 149 149 149 - - - -`¹ | an iOS device, on air: `151 151 151 151 0 0 0 0 6 151 151 151 0 0 0 0` |
  | 31 (iOS 27), "Infra BE RealTime + No Cached Peers + LP" | `infra - 149 - - - - - 6 - 149 - - - - -` | the iPhone, alone: `[120 0 149 0 0 0 0 0 6 0 149 0 0 0 0 0]` |

  ¹ Slots 6–7 and 14–15 hold the infrastructure channel only with AirPlay
  services.
- **Where unsynced devices meet.** The discovery, idle, low-power and data
  rows all keep 6 in slot 8 and 149 in slots 2 and 10.
- **Empty means off AWDL**, on the infrastructure network, though the fill
  is "repeat current" (`0xffff`): minintosh logged `AWDL ON:[infra(120)
  60%]` with 10 of 16 slots empty and `infra(120) 72%` with 12. That's why
  Apple devices take no unicast there ("Unicast only in explicit slots").
- **The social channel map says which social channels a device can use,
  not which it visits.** Every iPhone and Mac in our captures sends `0x0007`
  (6, 44 and 149), though none of their sequences visits 44.

So Warlock now builds its sequence the same way, as master and as a
follower: Apple's `Idle` plan on its social channels, 6 and 149
(`SocialChannels::idle_plan`). Warlock has no infrastructure network, so
its free slots stay on 149 and are named there (`SocialChannels::kept`):
`149 ×8, 6, 149 ×7`. Peers send unicast only in named slots, and naming
only the plan's would bring back the waits measured above. A free slot is
the place for anything Warlock later does away from AWDL (a visit to
another channel, say), which would leave it empty. Inside a realtime group
with the peer it syncs to, Warlock still takes that peer's sequence, as it
did every sync source's before: an iPhone's group sequence (149 in all 16
slots in Koala's trial 20) carried its Low-Latency Wi-Fi to us.

## Waking AWDL over Bluetooth LE (2026-11-17)

Apple devices bring AWDL up when a nearby device asks over Bluetooth LE, in
Apple's "Continuity" manufacturer data (company `0x004C`). That AirDrop
works this way is published: the MobiCom '18 paper, USENIX Security '19, and
OpenDrop's open issue #30 (see [prior-art.md](prior-art.md)). Here the same
held for AirPlay.

- **The trigger.** An iPhone opening the AirPlay picker sends an "AirPlay
  source" message (type `0x0a`). The Apple TV's power-save frames to its
  access point, which mark it leaving its home channel, began about 1.6 s
  before we first heard that advert. Our BLE watcher hears a given
  advertiser only every 1–3 s, so the timing alone can't decide it.
- **The test.** `blepublish` sent `0x0a` adverts from Windows' own Bluetooth
  radio while the iPhone was idle:
  - the iPhone's exact payload: the TV left its channel 63 ms after the
    advert started, and its next PSF carried the active sequence;
  - the minimal `0a 01 02` (flags only, no auth tag): active 0.55 s after
    the start.

  The TV went back to idle 30–40 s after the advert stopped.
- **Format** (iOS 27, 24B156: CoreBluetooth `-[CBDevice
  _parseAirPlaySourcePtr:end:]`, with bit names from the flags-description
  string in AirPlayReceiver's `-[APAdvertiserBTLEManager
  handleFoundDevice:]`):
  - a flags byte;
  - one byte of UWB config if bit 3 is set;
  - a 3-byte auth tag if bit 4 is set.

  | bit | name |
  |---|---|
  | 0 | ActivateNAN |
  | 1 | ActivateAWDLNormal |
  | 2 | ActivateAWDLAlternate |
  | 3 | ActivateUWB (adds the UWB byte) |
  | 4 | HasAuthTag (adds the auth tag) |
  | 7 | Goodbye |

  The iPhone sent `0x13` plus a tag for about 95 s from opening the picker,
  then a bare `0x80` (Goodbye) for about a minute. furiousMAC's Continuity
  notes have only ever seen a single `00` byte here.
- **Who listens** (iOS 27 AirPlayReceiver, AirPlaySupport):
  - `-[APAdvertiserBTLEManager handleFoundDevice:]` keeps a found source as
    a "Solo" device only if `APSShouldStartAdvertistingForAirPlaySourceBeacon`
    allows it.
  - That rejects a source without ActivateAWDLAlternate when the receiver
    requires it ("Alternate capable sender required").
  - Under restricted access control, it also rejects a source whose auth tag
    doesn't resolve to the same account ("SameAccount device required").
  - A source with no auth tag isn't checked for the account. "Solo" is
    AirPlay's peer-to-peer mode, which matches the Data Path State flag of
    that name.
- **For Warlock:** it can wake a receiver's AWDL from the host's own
  Bluetooth, through WinRT's `BluetoothLEAdvertisementPublisher`, with no
  extra hardware.

## Wire format

The frame and TLV layouts are documented in one place: the module docs of
`crates/awdl-proto`. For example, `dns.rs` holds the name dictionary and
`tlv/service.rs` the Service Response layout. Those layouts follow
Wireshark's AWDL dissector (`epan/dissectors/packet-awdl.c`), and the
crate's `tests/tshark_oracle.rs` checks that our decoding agrees with it on
every captured frame. This document keeps only what we observed on the air.
