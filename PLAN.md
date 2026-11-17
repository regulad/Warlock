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
- OWL, winawdl, omdrop-owl and the Wireshark AWDL dissector are **references only**. None of their code is copied.

## Repos and licensing
| Repo | License | Contents |
|---|---|---|
| `Warlock` | GPL-2.0-only (decided 2026-11-16), matching devourer (GPL-2.0-only), which is linked in-process. License text: `LICENSE.md`, from the FSF | devourer submodule + FFI shim, radio, AWDL protocol + engine, service, CLI, control API (OpenAPI contract + server) |
| `koala` | AGPL-3.0-or-later | Rapport, Continuity Capture control, media pipeline, app |
| `airdrop` | AGPL-3.0-or-later | AirDrop over Warlock |

- Programs control Warlock through a **local HTTP REST API, Docker-style**, defined by an OpenAPI contract (`api/openapi.yaml`, see the API contract task under Milestones). Clients speak HTTP and link no Warlock code. License the contract MIT (planned) so anyone, including the AGPL apps, can generate a client from it.
- Enforce Warlock's license zone with **cargo-deny**. Allow MIT, BSD-2/3, ISC, Zlib, Unlicense, BSL-1.0, LGPL-2.1+, MPL-2.0 and Unicode-3.0. **Leave Apache-2.0 out** of the allow list, so dual MIT/Apache crates resolve to MIT and Apache-only crates (e.g. `ring`, `cpal`) are rejected. Never use `bincode` (its 3.0 release is a tombstone); use `postcard`.
- **Open licensing issue: `wintun.dll`.** It ships under a proprietary prebuilt-binaries license; its source is GPL-2.0. Loading it into a process that contains GPLv2-only devourer is a gray area only when we *distribute* the two together. Plan: don't bundle it. The installer or user fetches the unmodified DLL from wintun.net. Revisit before any public release. Fallbacks are TAP-Windows6 (GPLv2, driven over ioctl, so no linking) or building and signing Wintun from source.

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
- **`warlock-radio`**
  - A `Radio` trait with two backends: `DevourerRadio` (hardware) and `PcapReplayRadio` (reads pcapng captures, for tests and CI without hardware).
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
  - References: Wireshark `epan/dissectors/packet-awdl.c`, the MobiCom'18 paper, our own captures.
  - Fuzzed with `cargo-fuzz`, with round-trip tests against captured frames.
- **`awdl-core`** (sans-IO, deterministic, uses the radio TSF as its clock)
  - Inputs: RX frames, timer ticks, host IPv6 packets, commands. Outputs: TX frames with a target time and channel, retunes, host deliveries, peer and service events.
  - Components:
    - **Sync:** AW = 16 TU, EAW = 64 TU, 16-slot sequence. Index slots in the *master's* phase, using `sync_offset` taken from the Sync Params TLV.
    - **Election:** rank by **metric first**, then counter; log every peer's election fields whenever the master changes.
    - **Peer table:** a peer is valid after a MIF *and* a nonzero Version TLV; timeout 5 s (data frames count as activity).
    - **Channel-sequence strategy:** `verbatim` or `intersect`, never a constant ("pin" kills TX to iOS 26). Re-read peers' sequences continuously, because the iPhone widens its sequence during a transfer.
    - **TX scheduling:** unicast only when we and the peer share the slot's channel, with a guard; multicast only in slots 0 and 10, with a 16 TU guard.
    - **Advertised capabilities** must match what the dongle actually receives.
    - **BlockAck responder:** TID 0, 64-frame window, ~100 ms reorder buffer.
- **`warlock-usb`** (done in W0): claims the adapter for WinUSB with Windows' own Microsoft-signed `winusb.inf`, the way Device Manager's "Have Disk" does: a class driver list from that one INF, its generic `USB\MS_COMP_WINUSB` node, `DiInstallDevice`, after moving the device from the Net to the USBDevice setup class. No generated catalog and no certificate. `release` reinstalls the best store driver (`netrtwlanu.inf`).
- **`warlock`** (service binary)
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
  - Firewall rules: allow only what clients register; suppress Windows' own LLMNR/SSDP/mDNS chatter on the adapter.
  - **Service discovery (critical for Koala; see `docs/service-discovery.md`):** AWDL carries records both as Service Response TLVs in action frames (Apple's D2D) and as ordinary multicast mDNS in data frames. Warlock is the registrar and doesn't sniff:
    - Advertise: clients register through the control API → Warlock calls `DnsServiceRegister` on its adapter (Windows' built-in DNS-SD answers real mDNS) **and** encodes the records into our TLVs.
    - Browse: `DnsServiceBrowse`/`Resolve` on the adapter, merged with records learned from peers' TLVs → found/lost events on the control API.
    - Carry mDNS frames between the adapter and AWDL multicast slots. Accept `33:33:00:00:00:fb` and `33:33:80:00:00:fb`; transmit the former. Keep LLMNR/SSDP off the link.
- **Control API** (replaces the earlier postcard named-pipe IPC plan): an HTTP/1.1 REST API served on a local socket, specified first in `api/openapi.yaml`, with the server inside the `warlock` service. Scope and open decisions: the API contract task under Milestones.
- **`warlock-ctl`** (binary): a client of the control API, the way `docker` is of the Engine API. Status, peers, live log tail, `capture` to pcapng (`pcap-file`) for Wireshark.

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
2. When the T3U arrives: run `rxsmoke` (WinUSB bound by `warlock-usb bind`; the T3U enumerates as a single-function device `USB\VID_2357&PID_012D`, no `MI_xx`) to confirm `00:17:f2` AWDL action frames on ch 6/44/149. Then capture an Apple TV ↔ iPhone guest session: AWDL TLVs and versions, sequences, Service Response records (`rpPI`), and pair-setup M1–M4.
3. RE the tvOS/iOS images with `ipsw` (the guest host logic, the QR parser, iPhone-side acceptance checks). Use the macOS binaries extracted on a lab Mac (rapportd, CMContinuityCaptureHost, AVConference) for the control and media formats. Findings so far: `docs/`.

## Milestones (exit criteria)
- **W0 Bring-up:** `devourer-sys` builds under MSVC. A Rust smoke binary receives frames with TSF from the T3U. *Measure:* sustained TX rate with RX running (devourer reports ~37 fps on Jaguar2 in this mode, which is a risk), hop latency, Windows timer jitter.
  - *Done 2026-11-16:* build, self-binding to WinUSB, and RX with TSF on ch 6/36/44/120/161; Apple AWDL PSFs seen on ch 44.
  - Bring-up takes ~20 s with a 1 ms timer: the PHY-table writes are one synchronous WinUSB control transfer each. Optimize later.
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
- **W3 Active link:** PSF/MIF TX, election, sequence strategy, ACK responder armed. iPhones list us as a valid peer (seen in their frames and sync tree). `ping6` to an iPhone's AWDL link-local works through Wintun.
- **Task: API contract (added 2026-11-17; due before W4, its first consumer).** Write down the API Warlock exposes to programs that drive AWDL directly (Koala, AirDrop, `warlock-ctl`), as an **OpenAPI 3.1** document `api/openapi.yaml` for an HTTP REST API on a local socket, modelled on Docker's Engine API.
  - Decide the transport. Options: a named pipe `\\.\pipe\warlock` (Docker on Windows serves `\\.\pipe\docker_engine`) or an AF_UNIX socket. Access is controlled by the socket's security descriptor (e.g. a `warlock-users` group, like `docker-users`). Version in the path (`/v1/…`).
  - Resources to cover: daemon and radio status and control; peers; holding AWDL active and channel preference; service registration and browsing (the registrar design in `docs/service-discovery.md`); an event stream (Docker-style streamed JSON on `GET /events`); pcapng capture; one error model.
  - The data plane stays the Wintun NIC; the API is control only.
  - Pick the Rust server stack (hyper/axum over the chosen socket) and how the server is checked against the contract.
- **W4 Service bridge:** browsing `_airdrop._tcp` / `_rdlink._tcp` on the NIC shows Apple devices; a test service we register appears on a Mac (verify on a lab Mac via `dns-sd -B` and `tcpdump -i awdl0`).
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
- Unit and fuzz tests on `awdl-proto`.
- Deterministic `awdl-core` tests driven by captured pcapngs through `PcapReplayRadio` with a simulated TSF clock.
- Hardware loops per milestone using the T3U, an iPhone, and lab Macs / a jailbroken Apple TV as witnesses (`tcpdump -i awdl0`, `dns-sd`, `ping6 %awdl0`). Tools: `rxsmoke`, `awdlcap` (radiotap pcapng for Wireshark), `warlock-usb`.
- Wireshark on `warlock-ctl capture` output for every interop bug.
