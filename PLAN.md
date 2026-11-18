# Plan: Warlock (AWDL on Windows) → Koala (iPhone mic) → AirDrop, in Rust

> W0 bring-up started 2026-11-16 (T3U on-bus). The daemon was renamed from `wawdld` to **Warlock**.

## Context
Koala makes an unmodified iPhone work as a microphone on Windows. It does this by impersonating an Apple TV that hosts a guest, mic-only Continuity Camera session (tvOS's QR/PIN pairing, Rapport `SessionPaired` identity). Reverse-engineering macOS 27 showed that guest pairing runs **only over AWDL**. Windows has no AWDL and no raw 802.11 path.

So the foundation is **Warlock** (formerly `wawdld`): a Windows Service that implements AWDL in user space on a USB Realtek dongle, driven by OpenIPC **devourer** over WinUSB. It plays the role of Darwin's `wifip2pd`. Koala and a separate AirDrop app are clients that use the link through a virtual NIC.

Pinned decisions:
- All code in Rust, with a thin FFI shim down to devourer (C++20).
- Hardware: TP-Link Archer T3U (RTL8812BU, devourer's "Jaguar2" backend, USB `2357:012d`). Ordered.
- Audio sink: the existing VB-Audio virtual cable, fed from user space.
- Separate repos per license zone.
- Apps reach the link through a virtual NIC (Wintun).
- Koala UI is deferred until Warlock works.
- OWL, winawdl and owly (formerly omdrop-owl) are **references only**. None of their code is copied. owly's MIT crates look derived from GPLv3 OWL, so Warlock doesn't depend on them: see `docs/prior-art.md`, "Rust AWDL crates, and why Warlock implements its own".
- Wireshark's AWDL dissector (`epan/dissectors/packet-awdl.c`, GPL-2.0-or-later, so compatible) is the **layout reference and test oracle** for `awdl-proto`. Each module names the dissector function it follows and where it departs from it. Its code isn't reused, because a dissector only reads, into a display tree.
- **No heuristic filters (Parker, 2026-11-17).** Warlock carries what it's given. It doesn't drop, rewrite or hold back traffic because it looks like noise or seems unneeded. A filter goes in only when a specific, demonstrated reason shows the traffic breaks AWDL or a peer, and the code then cites that reason. What follows from AWDL itself isn't a heuristic, for example unicast going only in a peer's explicit slots. Neither is traffic that has nowhere to go, such as IPv4 with no AWDL address. (The adapter used to drop Windows' MLD, LLMNR, SSDP and WS-Discovery as "chatter"; that was removed.)

## Repos and licensing
| Repo | License | Contents |
|---|---|---|
| `Warlock` | GPL-2.0-only (decided 2026-11-16), matching devourer (GPL-2.0-only), which is linked in-process. License text: `LICENSE.md`, from the FSF | devourer submodule + FFI shim, radio, AWDL protocol + engine, service, CLI, control API (OpenAPI contract + server) |
| `koala` | AGPL-3.0-or-later | Rapport, Continuity Capture control, media pipeline, app |
| `airdrop` | AGPL-3.0-or-later | AirDrop over Warlock |

- Programs control Warlock through a **local HTTP REST API, Docker-style**, defined by an OpenAPI contract (`api/openapi.yaml`, see the API contract task under Milestones). Clients speak HTTP and link no Warlock code. License the contract MIT (planned) so anyone, including the AGPL apps, can generate a client from it.
- Enforce Warlock's license zone with **cargo-deny**. Allow MIT, BSD-2/3, ISC, Zlib, Unlicense, BSL-1.0, LGPL-2.1+, MPL-2.0 and Unicode-3.0. **Leave Apache-2.0 out** of the allow list, so dual MIT/Apache crates resolve to MIT and Apache-only crates (e.g. `ring`, `cpal`) are rejected. Never use `bincode` (its 3.0 release is a tombstone); use `postcard`. **Enforced since 2026-11-18** by `deny.toml` (cargo-deny 0.20.2), which pre-commit runs whenever a manifest or the lock file changes; it also allows our own GPL-2.0 crates and bans `bincode`.
- **`wintun.dll` (decided 2026-11-17).** It ships under WireGuard LLC's prebuilt-binaries license; its source is GPL-2.0.
  - **Decision:** Warlock loads it in-process. It is never bundled: Warlock downloads the pinned release from wintun.net at runtime, checks the zip's and the DLL's SHA-256, and keeps it in an admin-only directory (`crates/warlock-tun`).
  - **Why this works:** the GPL governs distribution. If we never distribute the DLL, the combination with GPL-2.0-only devourer exists only on the user's machine. WireGuard's license itself defines the software as the DLL "as downloaded from wintun.net/builds".
  - **Residual gray area:** the FSF holds that a GPL program designed to load an incompatible library needs permission from its copyright holders. We can't give that for devourer's authors.
  - **Rejected for now (Parker):** a separate MIT helper process owning the adapter, which would have avoided that gray area and allowed bundling.
  - Have counsel look before any public release.

## Warlock architecture (one process, Windows Service)
```
[devourer (C++, static)] ← extern "C" shim ← warlock-radio (safe Rust)
        │ RX: SpscFat consumer thread → rtrb ring (frame, tsfl, rssi)
        ▼
 engine thread (Win32 high-resolution waitable timer + WaitForMultipleObjects)
   owns awdl-core (sans-IO state machine), devourer TX/retune behind one mutex
        ▲                                  ▲
 Wintun session (IPv6 ⇄ AWDL data)     control channel
                                           ▲
              HTTP REST API on a local socket (OpenAPI contract, Docker-style)
```

### Crates (`Warlock` workspace)
- **`devourer-sys`**
  - Builds devourer from `third_party/devourer` (a git submodule pinned to a commit) via the `cmake` crate. Only the 8822B backend is enabled: `DEVOURER_JAGUAR1/8814/JAGUAR2_8821C/JAGUAR3_*/8733B/KESTREL_*=OFF`, `--target devourer`, `DEVOURER_LOG_MAX_LEVEL=WARN`. Force the `/MD` CRT so it matches Rust.
  - libusb comes from `libusb1-sys` with `features=["vendored"]` (LGPL-2.1, static). Its `DEP_USB_1.0_INCLUDE` is passed to CMake.
  - devourer's CMake insists on `pkg_check_modules(libusb-1.0)`. Handled by a `FindPkgConfig.cmake` stand-in, so devourer isn't patched for it.
  - Our fixes to devourer live on the `warlock` branch of our fork (`regulad/devourer`), one commit per fix on top of upstream, so each can become an upstream PR on its own. The submodule tracks that branch; remote `upstream` is OpenIPC.
  - The shim (`shim/dvr_shim.cpp`) is a narrow, hand-written `extern "C"` API. It catches every C++ exception and returns an error code, and it confines devourer's global macros (`ushort`, `rtw_read8`) to that one `.cpp`. Its surface:
    - `open(vid,pid)` → claim → `CreateRadio(handle, ctx, lock, cfg)`;
    - `init_write(ch)`;
    - `start_rx(cb)` / `stop_rx`;
    - `send(buf,len)` (radiotap + MPDU, no FCS);
    - `fast_retune(ch)` / `set_channel(ch,width)` / `reapply_txpower`;
    - `set_ack_responder(mac)` / `clear_ack_responder`;
    - `read_tsf`, `caps`;
    - `close`, with the mandated teardown order: StopRxLoop → ClearAckResponder → Stop → destroy → release → close → libusb_exit.
  - Models to follow: `examples/duplex/main.cpp:552-641` (InitWrite, then a TX thread plus StartRxLoop), `examples/rx/main.cpp:1581-1649` (open sequence), `examples/common/DeviceSession.h` (teardown), `src/UsbOpen.h` (claim/lock), `src/AckResponder.h`.
  - Logs: devourer's `Logger` has no callback hook, so route its diag stream to a `FILE*` pipe that Rust reads into `tracing`. Disable its JSON events.
- **`warlock-capture`** (done in W2): radiotap pcapng read/write over `pcap-file` (MIT) and `radiotap` (MIT/Apache), tolerant of captures cut off mid-write; locates the local corpus (`WARLOCK_CAPTURES` or `captures/air`). Every crate's tests and tools use it.
- **`warlock-radio`** (receive side done in W2; TX in W3)
  - Done: a `Radio` trait (`recv`, `channel`, `set_channel`) with `DevourerRadio` and `ReplayRadio` (via `warlock-capture`). `DevourerRadio` is `!Send`, so it is closed on the thread that opened it. It tears down in order (stop RX, join, close, free the callback context), hands frames over a bounded queue (drops counted), extends the 32-bit TSF, tags the channel, and holds `timeBeginPeriod(1)` while open. It uses devourer's default RX mode, which W0 validated, not SpscFat. A plain `mpsc` queue is enough so far; `rtrb` only if profiling says so.
  - Tools: `examples/awdlsync` (the engine live or on a capture, with W2's check) and `examples/awdlcap` (capture to pcapng).
  - Still planned:
  - Delivers RX as `RxFrame { bytes (FCS stripped), tsf_lo32 → extended u64, rssi_dbm, channel }`. C2H firmware reports (`pkt_rpt_type`) are filtered out. devourer's RX packets carry no channel field, so the channel is tagged from our own tune state.
  - Fixed DeviceConfig choices:
    - `tx.retry_limit` > 0 (the default 0 means unicast is sent once);
    - `tuning.fastretune_fw=2` (~1.9 ms cross-band hops ch6↔44/149);
    - an RX mode of `SpscFat`, so the callback runs on one thread and the ring stays single-producer;
    - thermal tracking kept but known to contend for `_reg_mu`.
  - Every frame carries an explicit RATE radiotap field: with none, devourer falls back to 1 Mbps CCK, which is invalid at 5 GHz.
  - Wrap retune and TSF calls in catch-and-retry, because devourer documents 1–26 register-read failures with `LIBUSB_ERROR_PIPE` per 60–90 s on a busy channel.
  - Call `timeBeginPeriod(1)`, because devourer's internal waits use `sleep_for`.
  - Hold the open/close on one long-lived thread: devourer's Win32 lock is a named mutex, and mutexes are owned by a thread.
- **`awdl-proto`** (done in W1; `no_std` + `alloc`)
  - Parses and builds action frames (PSF/MIF) and data-frame encapsulation (LLC/SNAP `00:17:f2`/0x0800, then `03 04`, seq, `00 00`, EtherType).
  - Typed TLVs: everything seen on the air: 2, 4, 5, 6, 7, 12, 16, 17, 18 (all three encodings), 20, 21, 24.
  - Service Request (1), Bloom Filter (22) and NAN Sync (23) never appeared in a capture. iOS 27's TLV 33 does appear, but its layout is unknown. All four stay raw until there's something to decode.
  - Unknown TLVs and bytes past known fields are kept, so every accepted frame re-emits byte-for-byte.
  - Layouts follow Wireshark's `epan/dissectors/packet-awdl.c` (see the provenance section in `src/lib.rs`), checked against it by `tests/tshark_oracle.rs`. Also the MobiCom'18 paper and our own captures.
  - Fuzzed with `cargo-fuzz`, with round-trip tests against captured frames.
- **`awdl-core`** (sans-IO, deterministic, uses the radio TSF as its clock; `std` for float maths, but no I/O and no clock)
  - Inputs: RX frames, timer ticks, host IPv6 packets, commands. Outputs: TX frames with a target time and channel, retunes, host deliveries, peer and service events.
  - Done in W2 (passive), from the measurements in `docs/awdl-field-observations.md`, "Synchronization":
    - **Sync:** an `AwClock` per peer. It does a least-squares fit of AW boundaries (phase and drift, over 256 claims) from `rx_tsf − (phy_tx − target_tx) + tx_counter·TU`, rejects outliers, and resets after 3 in a row. The channel-sequence slot is `(aw_seq / 4) mod 16`, and empty slots repeat the last channel when fill is `0xffff`.
    - **Election (passive):** the master is the best master any peer names, ranked metric, then counter, then address. We sync to it, or to the peer closest to it; the choice is sticky.
    - **Peer table:** a peer is valid after a MIF *and* a nonzero Version TLV; timeout 5 s (data frames count as activity).
    - `diag::SyncCheck` is W2's accuracy check, shared by the replay test and `awdlsync`.
  - Still to do (W3 onward):
    - **Channel-sequence strategy:** `verbatim` or `intersect`, never a constant ("pin" kills TX to iOS 26). Re-read peers' sequences continuously, because the iPhone widens its sequence during a transfer.
    - **TX scheduling:** unicast only when we and the peer share the slot's channel, with a guard; multicast only in slots 0 and 10, with a 16 TU guard.
    - **Advertised capabilities** must match what the dongle actually receives.
    - **BlockAck responder:** TID 0, 64-frame window, ~100 ms reorder buffer.
- **`warlock-usb`** (done in W0): claims the adapter for WinUSB with Windows' own Microsoft-signed `winusb.inf`, the way Device Manager's "Have Disk" does: a class driver list from that one INF, its generic `USB\MS_COMP_WINUSB` node, `DiInstallDevice`, after moving the device from the Net to the USBDevice setup class. No generated catalog and no certificate. `release` reinstalls the best store driver (`netrtwlanu.inf`).
- **`warlock`** (service binary; first version done 2026-11-17, see W3's progress notes)
  - Service host via `windows-service`; stop event for clean shutdown.
  - Claims the T3U at start and on device arrival (`CM_Register_Notification`) through `warlock-usb`; gives it back to Windows on uninstall or `warlock-ctl release`.
  - Engine thread with `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION` + QPC, deadline-based periodic timers, and MMCSS priority.
  - Wintun adapter via `wintun-bindings`, configured as follows:
    - fixed GUID;
    - exactly one address, `fe80::` + EUI-64 of our AWDL MAC; remove Windows' random link-local (`NotifyUnicastIpAddressChange`);
    - MTU 1450; no IPv4; router discovery off; DAD off; high metric.
  - IPv6 → MAC mapping:
    - `ff..` → `33:33:xx`;
    - EUI-64 link-local → MAC;
    - learn MACs from received frames;
    - answer neighbor solicitations for our own address.
  - Trim received buffers to 40 + the IPv6 payload length.
  - Drain the Wintun read event until empty (auto-reset lost-wakeup bug).
  - Coalesce TCP segments to cut Windows' ACK chatter.
  - Firewall rules: allow only what clients register. Windows' own multicast on the adapter (MLD, LLMNR, SSDP, WS-Discovery, mDNS) is carried, not filtered: nothing known about AWDL forbids it (Parker, 2026-11-17).
  - **Service discovery (critical for Koala; see `docs/service-discovery.md`):** AWDL carries records both as Service Response TLVs in action frames (Apple's D2D) and as ordinary multicast mDNS in data frames. Windows stays the registrar and Warlock doesn't sniff:
    - Advertise (Parker, 2026-11-17): clients register with Windows themselves (`DnsServiceRegister` on the adapter) and only **name the service type** through the control API. Warlock keeps a standing `DnsStartMulticastQuery` per named type on its adapter, which Windows' own responder answers. Instances whose SRV target resolves to the adapter's own address are ours; Warlock encodes their records into our TLVs and withdraws them on goodbye (TTL 0).
    - Browse (Parker, 2026-11-17; done and verified the same day): apps use Windows' own DNS-SD. Warlock writes peers' TLV records onto its adapter as mDNS announcements (from the peer's link-local, TTL 120, re-announced every 60 s, goodbyes when dropped or lost), so Windows also finds peers that advertise only in frames. A Mac's `_airdrop._tcp` was found by `DnsServiceBrowse`, `DnsServiceResolve` and WinRT's watcher from Warlock's announcements alone.
    - Carry mDNS frames between the adapter and AWDL multicast slots. Accept `33:33:00:00:00:fb` and `33:33:80:00:00:fb`; transmit the former.
- **Control API** (replaces the earlier postcard named-pipe IPC plan): an HTTP/1.1 REST API served on a local socket, specified first in `api/openapi.yaml`, with the server inside the `warlock` service. Scope and open decisions: the API contract task under Milestones.
- **`warlock-ctl`** (binary): a client of the control API, the way `docker` is of the Engine API. Status, peers, advertising and holds, live events. No capture command: Wireshark captures on the adapter (Parker, 2026-11-18).

### Key external crates (Warlock zone, all GPLv2-compatible)
`windows`/`windows-sys`, `windows-service`, `wintun-bindings`, `libusb1-sys` (vendored), `cmake`, `rtrb`, `tokio`, `hyper`/`axum` (control API), `serde`, `pcap-file`, `tracing` + `tracing-etw`, `simple-dns` (for the bridge's mDNS encoding).

## Koala (`koala` repo, AGPL) — starts once Warlock can carry IPv6 to an iPhone
- `opack` and `tlv8` codecs. Evaluate `apple-opack` (MIT) or write our own.
- `rapport`: framing (type u8 + len u24), pair-setup (SRP-6a 3072/SHA-512 with Apple's M1 — the released `srp` crate doesn't match it, so use a git dependency on RustCrypto PR #313 or compute M1 ourselves), pair-verify (X25519/Ed25519), ChaCha20-Poly1305 sessions, request/event layer (`_i/_x/_t/_c`).
- `ccapture`: the RemoteDisplay guest-pairing server and the Continuity Capture control protocol. Pairing-info JSON keys: `_pi`, `_pinC`, `_pubID`, `_rdsr`. Events: `kCMContinuityCaptureEvent*`.
- `avc-media`: AVConference negotiation blob, RTP/SRTP (`webrtc-srtp`), Opus (`opus`, libopus BSD). The Mac requests AVC codec 16 = Opus 48 kHz, 4 channels, in 'call' mode. AAC-ELD fallback is FFmpeg via `ffmpeg-next` with an LGPL build; FDK-AAC is GPL-incompatible. Add a gPTP/TimeSync responder only if captures show it's required.
- Audio out: `wasapi` → "CABLE Input", with `rubato` drift correction.
- UI: deferred. Until then, the CLI renders the QR to the terminal/PNG.

## Ground-truth tracks (start immediately; no Warlock code needed)
1. Photograph the Apple TV's guest QR (FaceTime → Other → QR) and decode its raw bytes.
2. When the T3U arrives: run `awdlsync` (WinUSB bound by `warlock-usb bind`; the T3U enumerates as a single-function device `USB\VID_2357&PID_012D`, no `MI_xx`) to confirm `00:17:f2` AWDL action frames on ch 6/44/149. Then capture an Apple TV ↔ iPhone guest session: AWDL TLVs and versions, sequences, Service Response records (`rpPI`), and pair-setup M1–M4.
3. RE the tvOS/iOS images with `ipsw` (the guest host logic, the QR parser, iPhone-side acceptance checks). Use the macOS binaries extracted on a lab Mac (rapportd, CMContinuityCaptureHost, AVConference) for the control and media formats. Findings so far: `docs/`.

## Milestones (exit criteria)
- **W0 Bring-up:** `devourer-sys` builds under MSVC. A Rust smoke binary receives frames with TSF from the T3U. *Measure:* sustained TX rate with RX running (devourer reports ~37 fps on Jaguar2 in this mode, which is a risk), hop latency, Windows timer jitter.
  - *Done 2026-11-16:* build, self-binding to WinUSB, and RX with TSF on ch 6/36/44/120/161; Apple AWDL PSFs seen on ch 44.
  - Bring-up took ~20 s with a 1 ms timer, ~7.5 s once Windows 11 honours it (2026-11-17). The rest is mostly the PHY-table writes, one synchronous WinUSB control transfer each. Optimize later.
  - *Done 2026-11-16:*
    - TX with RX running, confirmed on air through probe responses;
    - hops ~3 ms within a band, ~9–10 ms across bands (firmware, `fastretune_fw = 2`);
    - timer lateness p99 582 µs, max 947 µs at 16.384 ms;
    - devourer cross-band retune bug fixed on our fork's `warlock` branch.
  - Details: `docs/windows-bringup.md`.
  - *Remaining:* the true over-the-air TX rate, which needs an independent sniffer.
- **W1 Proto:** `awdl-proto` round-trips every TLV in our captures; fuzzing clean.
  - *Done 2026-11-17:*
    - **Corpus round-trip:** all 4,155 action and 76 data frames re-emit byte-for-byte, both raw and rebuilt from typed TLVs (`tests/corpus.rs`, needs the local `captures/`).
    - **Wireshark cross-check:** 638,263 field values across 4,231 frames agree with Wireshark's independent dissector (`tests/tshark_oracle.rs`).
    - **Always-run tests:** frames built from typed values parse back to the same values, and a committed 21-frame anonymized fixture from real devices (`examples/scrub.rs`) decodes and round-trips.
    - **Fuzzing** (cargo-fuzz, ASan, in a `wslc` Linux container): `frame` ran 3.06 M executions in 10 min and `tlv` 5.74 M in 5 min, with no failures. The exact re-emit property was asserted on every accepted input.
    - Not done: a clippy pass. The Scoop toolchain has no clippy.
- **W2 Passive engine:** peers tracked, synced to the master, AW boundaries predicted within ±1 TU of observed frames (replay + live).
  - *Done 2026-11-17:*
    - **Replay** (`awdl-core/tests/replay.rs`, local corpus): 3,643 frames from the peer we sync to; 100 % within ±1 TU; p50 69 µs, p95 463 µs, max 843 µs. That covers an Apple TV drifting −239 ppm and an iPhone master with two followers.
    - **Live** (`awdlsync` on the T3U, Apple TV on channel 44, 60 s): 1,437 frames; 100 % within ±1 TU; p50 101 µs, p95 460 µs, max 686 µs; drift fitted −235 to −242 ppm; 0 frames dropped.
    - Election agrees with Apple's: 586 of 607 frames name the master we elect, and the iPhone (metric 538) leads an iOS device (530) and a Mac (515).
    - Open: a recurring libusb message `windows_submit_transfer … transfer HANDLE is NULL` during live RX (no loss seen). The iPhone in one hopping capture transmitted on channel 6 outside its advertised slot; this matters for W3's TX scheduling.
    - **Live, iPhone** (iOS 27 with the AirDrop screen open, channel 149, 75 s): 139 MIFs; 100 % within ±1 TU; p50 24 µs, p95 103 µs, max 353 µs; drift +1 to +3 ppm; 0 frames dropped. The iPhone was master (metric 541, version 10.2) and a valid peer.
- **W3 Active link:** PSF/MIF TX, election, sequence strategy, ACK responder armed. iPhones list us as a valid peer (seen in their frames and sync tree). `ping6` to an iPhone's AWDL link-local works through Wintun. **Done 2026-11-17** (see the progress notes below).
  - *Progress 2026-11-17:*
    - **TX:** `warlock-radio` sends with a rate radiotap header, hops on the firmware path and arms the ACK responder. `awdl-core` active mode follows the sync source: it copies its channel sequence verbatim, sends one MIF per explicit slot and a PSF every 110 TU, both early in an AW. It accepts ADDBA for TID 0 and declines other TIDs. It delivers data frames to the host and sends host packets when the peer is on our channel. Offline (`tests/active.rs`), the frames follow the iPhone's sequence and Wireshark decodes them cleanly.
    - **Fixed:** `dvr_read_tsf` is a different counter from the RX timestamps (about 318 ms apart), so "now" comes from received frames (`RxClock`).
    - **Accepted by macOS 11:** permanent NDP entry, Block Ack set up, unicast QoS data received and hardware-ACKed. The Mac's `ping6` to our link-local address succeeded 7 of 8, answered by `awdljoin`'s in-process echo responder. Round trips grow about 48 ms per ping (once per sequence cycle; open).
    - **Apple TV (iOS 8):** while it is master, it holds unicast for its followers. It serves a peer when it follows a higher-metric master, so a Warlock following it never got unicast.
    - **Master mode (2026-11-17):** `awdl-core` elects itself after listening 2 s, when it outranks every master named by anyone it hears. It then runs its own AW grid (`OwnClock`) and its own sequence (`TxConfig::master_sequence`, Apple's legacy and opclass encodings), and yields to a better master. Live at metric 600, the Apple TV joined our cluster and answered 41 of 68 pings. Our default metric stays 60, so with Apple devices around we follow. Open: an Apple-like metric policy.
    - **Hops (2026-11-17):** cross-band hops went from 14–34 ms to 4.1 ms p50. The cause was Windows 11 ignoring our timer resolution, plus a full antenna re-grant (fixed in our devourer fork). After a band change we hold TX for 15 ms, because the firmware is still switching. See `docs/windows-bringup.md`.
    - **Sync claims fixed (2026-11-17):** a Mac sniffer showed ~10 % of our frames claiming a slot an AW late (frames built before a 3–28 ms hop) and the rest ~1.2 ms late (unreported TX latency). The engine now builds nothing until a hop finishes and reports PHY/target TX times properly. On air, our grid is within 0.36 ms p50 of the master's.
    - **Waking AWDL over BLE:** a Bluetooth LE "AirPlay source" advert switches a receiver's AWDL from idle to active. Windows' own Bluetooth can send it through WinRT (`blepublish`), and `0a 01 02` alone wakes the Apple TV. Even awake, the Apple TV still holds our unicast (open). Details in `docs/awdl-field-observations.md`. The service needs a BLE advertiser for this, and for AirDrop's wake later.
    - **iPhone (iOS 27), 2026-11-17:** it answers our pings, whether we follow it (15 of 59) or lead it. Leading works once our election counter advances, as an Apple master's does. iPhones and Macs then join our cluster and stay.
    - **Ping loss fixed (2026-11-17):** Apple devices take unicast only in a peer's *explicit* slots, and send to us only in ours. The engine now sends only in explicit slots, and as a follower advertises the master's sequence widened. iPhone: 47 of 49 answered, p50 4–5 ms, following or leading. Apple TV: 58 of 58.
    - **Wintun (2026-11-17):** `crates/warlock-tun` fetches the pinned Wintun 0.14.1 at runtime (zip and DLL SHA-256 checked; admin-only `%ProgramData%\Warlock`). It creates the "Warlock AWDL" adapter with only our EUI-64 link-local, no router discovery and no DAD, and maps IPv6 destinations to AWDL addresses. The bridge first ran as an `awdltun` example; it now lives in the `warlock` service. Windows' own `ping -6 fe80::…%<if>` to the Apple TV, with Warlock leading: 40 of 40, 6–474 ms. **To an iPhone (iOS 27, AirDrop open), with Warlock following it: 38 of 40, 5–387 ms. W3's exit criterion is met (2026-11-17).** The wait is the peer's explicit slots: this iPhone names 4 of 16, so a packet can wait ~380 ms.
    - **Service (2026-11-17):** `crates/warlock` holds the bridge.
      - Commands: `run` (foreground, Ctrl+C), `install`/`uninstall` (LocalSystem, manual start, options kept on its command line) and `service` (the service-manager entry).
      - At start it claims the T3U for WinUSB if needed, fetches Wintun, opens the radio and the adapter.
      - It runs one thread (the radio is `!Send`), waiting on the radio in 2 ms slices and polling the adapter between them.
      - It stops cleanly on Stop/Shutdown, logging to `%ProgramData%\Warlock\warlock.log`.
      - Still ahead: the event-driven engine thread, device arrival, the control API, ETW (W5).
- **Task: API contract (added 2026-11-17; drafted 2026-11-18 as `api/openapi.yaml`).** Write down the API Warlock exposes to programs that drive AWDL directly (Koala, AirDrop, `warlock-ctl`), as an **OpenAPI 3.2** document `api/openapi.yaml` for an HTTP REST API on a local socket, modelled on Docker's Engine API.
  - **Transport:** HTTP/1.1 on a named pipe `\\.\pipe\warlock`, as Docker on Windows serves `\\.\pipe\docker_engine`. Version in the path (`/v1/…`). The pipe:
    - rejects remote clients (`PIPE_REJECT_REMOTE_CLIENTS`; named pipes are otherwise reachable over SMB);
    - is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so nothing can squat the name before the service starts;
    - has a security descriptor allowing Administrators and a `warlock-users` group (like `docker-users`);
    - keeps a spare instance listening, so concurrent clients don't get `ERROR_PIPE_BUSY`.
  - **Locks (Parker, 2026-11-18; replaces the WebSocket session decided 2026-11-17):** whatever an app asks Warlock to keep doing lasts exactly as long as the request that asked for it. A lock is a plain HTTP request whose response never ends on its own:
    - `POST /v1/advertising {type}`: the service type is advertised in our frames (registration itself stays with Windows; `docs/service-discovery.md`);
    - `POST /v1/holds {reason}`: an activity hold ("I'm using AWDL now": the link kept active).

    The response streams the lock's state as JSON Lines (OpenAPI 3.2 `itemSchema`), on every change and at least every 2 s. That heartbeat is how a vanished client is noticed: a write to a closed pipe fails at once. When the connection closes, whether the app exits cleanly or crashes, the lock is released, so nothing can leak. Precedent: systemd's inhibitor locks are a file descriptor whose closing releases them. `GetNamedPipeClientProcessId` names the owning process in logs and `warlock-ctl`.
  - Why not a WebSocket: with only locks to hold, a session protocol was more machinery than needed. Each lock as its own request needs no message protocol, needs only HTTP over a named pipe from clients (what Docker clients already do), and fits in one OpenAPI document.
  - Plain HTTP endpoints, mostly for `warlock-ctl`: `GET /v1/info`, `/v1/peers`, `/v1/advertising`, `/v1/holds`; `GET /v1/events` streams events for as long as it's open, holding nothing. One error model (Docker's `{"message"}`).
  - No capture endpoint (Parker, 2026-11-18): capture on the "Warlock AWDL" adapter with Wireshark.
  - Browsing needs nothing in the API: Warlock writes peers' TLV records onto its adapter as mDNS, and apps browse with Windows' own DNS-SD (`docs/service-discovery.md`).
  - The data plane stays the Wintun NIC; the API is control only.
  - Server stack: tokio's named-pipe server behind axum 0.8 (a custom `Listener`). To check: whether hyper notices a closed connection during a streaming response before the next heartbeat.
  - Checking the server against the contract (proposed): the YAML is authoritative; tests validate every response, and every line of every stream, against its schemas.
  - Linted by Redocly CLI's recommended rules on every commit that touches it (`.pre-commit-config.yaml`, `redocly.yaml`).
- **W4 Service bridge:** browsing `_airdrop._tcp` / `_rdlink._tcp` on the NIC shows Apple devices; a test service we register appears on a Mac (verify on a lab Mac via `dns-sd -B` and `tcpdump -i awdl0`). **Exit criterion met 2026-11-18** (`docs/service-discovery.md`):
  - Browse: a Mac's in-frame-only `_airdrop._tcp` showed up in Windows' own DNS-SD (2026-11-17).
  - Advertise: a Windows registration named with `--advertise` reached a Mac (macOS 11.7) through our TLVs alone, with Windows' mDNS held back. The Mac browsed, resolved and got our address. An iPhone (iOS 27) with AirDrop open connected to a test `_airdrop._tcp` instance's port the same way. Until the control API exists, types are named on the command line.
- **W5 Service-grade:** control API + ctl, survives sleep/resume and dongle hot-unplug, clears the ACK responder on every exit path, ETW logging.
- **K1:** Rapport pair-setup/verify validated against the real Apple TV's `_companion-link._tcp` on the LAN (pyatv-style PIN pairing; no AWDL needed — can run in parallel with W1–W3).
- **K2 (moment of truth):** the iPhone scans our QR and completes guest pair-setup with Koala over Warlock.
- **K3:** mic-only Continuity Capture session negotiated.
- **K4:** iPhone mic audio plays through "CABLE Output" with stable latency and drift.
- **A1:** the AirDrop app (Everyone mode) receives and sends on top of Warlock (after W5).

## Risks
- Jaguar2 TX throughput with concurrent RX (~24 ms/frame reported). Mitigation: measure at W0; fallback dongle RTL8812CU (Jaguar3).
- Unicast TX lost at the start of windows (airdrop-mt7921 FINDINGS §28). Mitigation: per-peer TX guard tuning.
- iPhone rejects a non-genuine Apple TV host, or the QR format is unknown. Mitigation: ground-truth tracks 1 and 3 before K2.
- AVConference negotiation blob is opaque. Mitigation: RE from the macOS AVConference on a lab Mac.
- wintun.dll licensing on distribution (see above).

## Verification
- pre-commit hooks on every commit (`.pre-commit-config.yaml`, added 2026-11-18 at Parker's request): `cargo fmt` (`rustfmt.toml`: 120 columns, the code's existing style), `cargo clippy --workspace --all-targets -D warnings`, `cargo deny check` (`deny.toml`), clang-format on the C++ shim (`crates/devourer-sys/.clang-format`, LLVM style), Redocly's lint of `api/openapi.yaml`, and whitespace, line-ending, YAML and TOML checks. `pre-commit run --all-files` runs them all.
- Unit and fuzz tests on `awdl-proto`.
- Deterministic `awdl-core` tests driven by captured pcapngs through `PcapReplayRadio` with a simulated TSF clock.
- Hardware loops per milestone using the T3U, an iPhone, and lab Macs / a jailbroken Apple TV as witnesses (`tcpdump -i awdl0`, `dns-sd`, `ping6 %awdl0`). Tools: `awdlsync` (engine live or on a capture, with the W2 check), `awdlcap` (radiotap pcapng for Wireshark), `warlock-usb`.
- Wireshark for every interop bug: on the "Warlock AWDL" adapter for packets, on `awdlcap` output for frames.
