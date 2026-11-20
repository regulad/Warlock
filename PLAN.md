# Plan: Warlock (AWDL on Windows) → Koala (iPhone mic) → AirDrop, in Rust

> W0 bring-up started 2026-11-16 (T3U on-bus). The daemon was renamed from `wawdld` to **Warlock**.

## Context
Koala makes an unmodified iPhone work as a microphone on Windows. It does this by impersonating an Apple TV that hosts a guest, mic-only Continuity Camera session (tvOS's QR/PIN pairing, Rapport `SessionPaired` identity). Reverse-engineering macOS 27 showed that guest pairing runs **only over AWDL**. Windows has no AWDL and no raw 802.11 path.

So the foundation is **Warlock** (formerly `wawdld`): a Windows Service that implements AWDL in user space on a USB Realtek dongle, driven by OpenIPC **devourer** over WinUSB. It plays the role of Darwin's `wifip2pd`. Koala and a separate AirDrop app are clients that use the link through a virtual NIC.

Pinned decisions:
- All code in Rust, with a thin FFI shim down to devourer (C++20).
- Hardware: TP-Link Archer T3U (RTL8812BU, devourer's "Jaguar2" backend, USB `2357:012d`). Ordered.
  - **Other adapters (Parker, 2026-11-18):** Warlock also tries any other RTL8812BU/RTL8822BU adapter, the 36 IDs of Linux's rtw88 table (`warlock_usb::MODELS`), with a warning that it isn't the T3U v1 it's tested with. When several are present it takes the T3U first. For a Wi-Fi + Bluetooth adapter (RTL8822BU, a composite USB device) it binds only the vendor-specific interface, which devourer claims, so Bluetooth keeps working.
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
| `Warlock` | GPL-2.0-only (decided 2026-11-16), matching devourer (GPL-2.0-only), which is linked in-process. License text: `LICENSE.md`, from the FSF | devourer submodule + FFI shim, radio, AWDL protocol + engine, service, CLI, control API server. Except: the API contract and `warlock-client` are GPL-2.0-only OR AGPL-3.0-or-later, and `warlockctl` is AGPL-3.0-only |
| `koala` | AGPL-3.0-or-later | Rapport, Continuity Capture control, media pipeline, app |
| `airdrop` | AGPL-3.0-or-later | AirDrop over Warlock |

- Programs control Warlock through a **local HTTP REST API, Docker-style**, defined by an OpenAPI contract (`api/openapi.yaml`, see the API contract task under Milestones). Clients speak HTTP and link no Warlock code. Licences around the API (Parker, 2026-11-18), since GPLv2 and AGPLv3 can't be combined with each other:
  - The contract (`api/openapi.yaml`) is **GPL-2.0-only OR AGPL-3.0-or-later** (briefly MIT, as first planned): Warlock takes it under GPLv2, the AGPL apps (Koala, AirDrop) under AGPLv3.
  - **`warlock-client`** (its wire types and HTTP client) is dual-licensed the same way, for Warlock's server and for any other program to import.
  - **`warlockctl`** is **AGPL-3.0-only** and links only `warlock-client` of ours. `deny.toml` allows AGPL for that crate alone, so no AGPL dependency can reach the GPL-2.0 daemon.
  - The other direction is a `deny.toml` ban rule: our GPL-2.0-only crates may be depended on only by our GPL-2.0-only crates (cargo-deny `wrappers`), so neither `warlockctl` nor `warlock-client` can link one, directly or indirectly. Checked by temporarily adding such dependencies: both were rejected.
  - Texts: `LICENSE.md` (GPLv2) and `LICENSE-AGPL-3.0.md`, both as the FSF publishes them.
- Enforce Warlock's license zone with **cargo-deny**. Allow MIT, BSD-2/3, ISC, Zlib, Unlicense, BSL-1.0, LGPL-2.1+, MPL-2.0 and Unicode-3.0. **Leave Apache-2.0 out** of the allow list, so dual MIT/Apache crates resolve to MIT and Apache-only crates (e.g. `ring`, `cpal`) are rejected. Never use `bincode` (its 3.0 release is a tombstone); use `postcard`. **Enforced since 2026-11-18** by `deny.toml` (cargo-deny 0.20.2), which pre-commit runs whenever a manifest or the lock file changes; it also allows our own GPL-2.0 crates and bans `bincode`.
- **`wintun.dll` (decided 2026-11-17).** It ships under WireGuard LLC's prebuilt-binaries license; its source is GPL-2.0.
  - **Decision:** Warlock loads it in-process. It is never bundled: Warlock downloads the pinned release from wintun.net at runtime, checks the zip's and the DLL's SHA-256, and keeps it in an admin-only directory (`crates/warlock-tun`).
  - **Why this works:** the GPL governs distribution. If we never distribute the DLL, the combination with GPL-2.0-only devourer exists only on the user's machine. WireGuard's license itself defines the software as the DLL "as downloaded from wintun.net/builds".
  - **Residual gray area:** the FSF holds that a GPL program designed to load an incompatible library needs permission from its copyright holders. We can't give that for devourer's authors.
  - **Rejected for now (Parker):** a separate MIT helper process owning the adapter, which would have avoided that gray area and allowed bundling.
  - **A Wintun exception for our own code (Parker, 2026-11-18):** [`LICENSE-WINTUN-EXCEPTION.md`](LICENSE-WINTUN-EXCEPTION.md), in the FSF's form for GPLv2 programs using an incompatible library. It covers everything outside `third_party/`, so the gray area is down to devourer's code, which we're leaving for now (no request to its authors). The MSI installs it with the licence texts.
  - No counsel review before going public (Parker, 2026-11-18). The repository went public that day.

## Versioning
- **Semver (Parker, 2026-11-18).** 1.0.0 is the first release with a stable API. Before it, `0.y.z` follows semver one place down, as Cargo reads it:
  - `y` goes up for a breaking change;
  - `z` covers new features and fixes alike.
  The first release is 0.1.0, and a patch to it is 0.1.1.
- **One version for everything**, set once in `Cargo.toml` (`[workspace.package]`). Every crate inherits it, `warlock info` reports it, and the MSI is built with it. The contract's `info.version` repeats it, and a test keeps the two equal.
- A breaking release also raises the requirement on our own crates under `[workspace.dependencies]` (`0.1.0` → `0.2.0`). Cargo rejects a path crate whose version falls outside it.
- **Paths stay under `/v1`** through 0.y. A break after 1.0.0 would come with 2.0.0 and `/v2`.
- **Releasing:**
  1. Set the version in `Cargo.toml` and commit it.
  2. Push an annotated tag: `git tag -a vX.Y.Z -m "<release notes>"`, then `git push origin vX.Y.Z`. git drops message lines starting with `#`, so Markdown headings need `--cleanup=verbatim`.
  3. `.github/workflows/build.yml` builds, signs from the `release` environment (every signature must be valid), and packages.
  4. It writes winget's manifests for that package, and publishes a GitHub release carrying the signed MSI and the three manifests, with the tag's message as its notes. It fails if the tag isn't the package's version.
  5. Parker submits the manifests to `microsoft/winget-pkgs` (`manifests/r/Regulad/Warlock/X.Y.Z/`).
  - A run started by hand signs from `testing` (a test certificate) and publishes nothing. Parker's homelab configuration manages both environments and their secrets. `.github/settings.yml` deliberately has no `environments` key: with one, the Settings app would delete every environment it doesn't list.
- No pre-release versions: an MSI's ProductVersion takes numbers only (at most 255.255.65535).
- **The API is what semver counts:** the control API contract and `warlock-client`'s Rust API.
- **Open event types and radio states (Parker, 2026-11-18, before 0.1.0).** Without a break, Warlock may add properties, event types and radio states: a `z` change. The contract's "Compatibility" section tells clients to ignore properties and event types they don't know, and to take an unknown radio state as not `up`.
  - In `warlock-client`, unknown event types and radio states parse as `Event::Unknown` and `RadioState::Unknown`. Both enums are `#[non_exhaustive]`, so adding a variant doesn't break Rust code either.
  - It had to come first: a 0.1.0 client without the catch-all would have failed on any later addition.

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
  - Claims the T3U at start and on device arrival (`CM_Register_Notification`) through `warlock-usb`; gives it back to Windows on uninstall or `warlockctl release`.
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
- **`warlockctl`** (binary, `crates/warlockctl`, AGPL-3.0-only, 2026-11-18): a client of the control API through `warlock-client`, the way `docker` is of the Engine API. `info`, `peers`, `peer`, `advertising`, `holds` print JSON; `advertise TYPE`, `hold REASON` and `events` hold their stream until Ctrl+C. No capture command: Wireshark captures on the adapter (Parker, 2026-11-18). *Reversed 2026-11-19 (W6):* frames Warlock doesn't deliver need a capture of the radio itself.

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
      - It stops cleanly on Stop/Shutdown, logging to `%ProgramData%\Warlock\warlock.log` (until 2026-11-18; now the Event Log, under W5).
      - Still ahead: the event-driven engine thread, device arrival, the control API, ETW (W5).
- **Task: API contract (added 2026-11-17; drafted 2026-11-18 as `api/openapi.yaml`).** Write down the API Warlock exposes to programs that drive AWDL directly (Koala, AirDrop, `warlockctl`), as an **OpenAPI 3.2** document `api/openapi.yaml` for an HTTP REST API on a local socket, modelled on Docker's Engine API.
  - **Transport:** HTTP/1.1 on a named pipe `\\.\pipe\warlock`, as Docker on Windows serves `\\.\pipe\docker_engine`. Version in the path (`/v1/…`). The pipe:
    - rejects remote clients (`PIPE_REJECT_REMOTE_CLIENTS`; named pipes are otherwise reachable over SMB);
    - is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so nothing can squat the name before the service starts;
    - has a security descriptor allowing Administrators and a `warlock-users` group (like `docker-users`);
    - keeps a spare instance listening, so concurrent clients don't get `ERROR_PIPE_BUSY`.
  - **Locks (Parker, 2026-11-18; replaces the WebSocket session decided 2026-11-17):** whatever an app asks Warlock to keep doing lasts exactly as long as the request that asked for it. A lock is a plain HTTP request whose response never ends on its own:
    - `POST /v1/advertising {type}`: the service type is advertised in our frames (registration itself stays with Windows; `docs/service-discovery.md`);
    - `POST /v1/holds {reason}`: an activity hold ("I'm using AWDL now": the link kept active);
    - `POST /v1/realtime {peer, reason}` (2026-11-19, issue #10): a Continuity Real Time Group with a peer, so an iPhone sends Low-Latency Wi-Fi. Warlock sends the peer a few UMIs (`0x17000000`) with TLV 31 in its slots, keeps TLV 31 in its frames while any lock is open, and sends a few stop UMIs (`0x18000000`) when the last closes. One peer at a time (Parker, 2026-11-19): while a lock on a peer is open, a request for another gets 409; requests for the same peer share its group. As an Apple host: an iPhone has one LLW peer on AWDL and one realtime group, and `wifip2pd` refuses a second Continuity Real Time Group peer (static analysis). Experimental: tried with one iPhone (iOS 27.2.1), trials 20–21.

    The response streams the lock's state as JSON Lines (OpenAPI 3.2 `itemSchema`), on every change and at least every 2 s. That heartbeat is how a vanished client is noticed: a write to a closed pipe fails at once. When the connection closes, whether the app exits cleanly or crashes, the lock is released, so nothing can leak. Precedent: systemd's inhibitor locks are a file descriptor whose closing releases them. `GetNamedPipeClientProcessId` names the owning process in logs and `warlockctl`.
  - Why not a WebSocket: with only locks to hold, a session protocol was more machinery than needed. Each lock as its own request needs no message protocol, needs only HTTP over a named pipe from clients (what Docker clients already do), and fits in one OpenAPI document.
  - Plain HTTP endpoints, mostly for `warlockctl`: `GET /v1/info`, `/v1/peers`, `/v1/advertising`, `/v1/holds`, `/v1/realtime`; `GET /v1/events` streams events for as long as it's open, holding nothing. One error model (Docker's `{"message"}`).
  - No capture endpoint (Parker, 2026-11-18): capture on the "Warlock AWDL" adapter with Wireshark. *Reversed 2026-11-19:* `GET /v1/capture` and a Wireshark extcap plugin (W6).
  - Browsing needs nothing in the API: Warlock writes peers' TLV records onto its adapter as mDNS, and apps browse with Windows' own DNS-SD (`docs/service-discovery.md`).
  - The data plane stays the Wintun NIC; the API is control only.
  - **Implemented 2026-11-18**: the server in `crates/warlock-api`; the wire types (one per contract schema) and a client in `crates/warlock-client`. The daemon starts the server before the radio, publishes state every 250 ms, forwards engine events, and applies the types and holds locks ask for (`Advertiser::set_types`).
    - Server stack: tokio's named-pipe server and hyper 1 directly. Not axum: it depends on `sync_wrapper`, which is Apache-2.0 only, and cargo-deny rejected it.
    - The pipe: first instance exclusive (a second Warlock fails to start), remote clients rejected, a spare instance listening, DACL for SYSTEM, Administrators and `warlock-users` when the group exists. Until the installer creates that group, only elevated clients get in.
    - Hyper notices a closed client at once: in tests a lock is released 13–23 ms after its client closes the connection, so the 2 s heartbeat is only a backstop.
  - Checking the server against the contract: the YAML is authoritative; `crates/warlock-api/tests/contract.rs` validates every response, and every line of every stream, against the contract's schemas (jsonschema), checks that every documented operation is served, and that the checks fail on a body that breaks the contract.
  - **Live (2026-11-18)**, radio up, `warlock run` and `warlockctl` both elevated:
    - `info` reported `opening`, adapter null, then `up` with the adapter, our address and the master;
    - an advertising lock picked up a Windows registration (`warlockctl advertising` listed the instance and its owner's PID and path);
    - its client force-killed, Warlock's log shows the lock released 1 ms later and the instance withdrawn from our frames;
    - `events` streamed radio, peer, service, master and advertising changes; `peers` listed an iPhone with its records;
    - a second Warlock was refused at the pipe before touching the dongle; a bad type got a 400.
    - Not exercised live: a hold (the test script mangled its argument). It's the same lock mechanism, and the contract tests cover it.
  - Linted by Redocly CLI's recommended rules on every commit that touches it (`.pre-commit-config.yaml`, `redocly.yaml`).
- **W4 Service bridge:** browsing `_airdrop._tcp` / `_rdlink._tcp` on the NIC shows Apple devices; a test service we register appears on a Mac (verify on a lab Mac via `dns-sd -B` and `tcpdump -i awdl0`). **Exit criterion met 2026-11-18** (`docs/service-discovery.md`):
  - Browse: a Mac's in-frame-only `_airdrop._tcp` showed up in Windows' own DNS-SD (2026-11-17).
  - Advertise: a Windows registration named with `--advertise` reached a Mac (macOS 11.7) through our TLVs alone, with Windows' mDNS held back. The Mac browsed, resolved and got our address. An iPhone (iOS 27) with AirDrop open connected to a test `_airdrop._tcp` instance's port the same way. Until the control API exists, types are named on the command line.
- **W5 Service-grade:** control API + ctl, survives sleep/resume and dongle hot-unplug, clears the ACK responder on every exit path, ETW logging.
  - *Decisions (Parker, 2026-11-18):*
    - **The goal:** a Windows service with the fewest privileges that still let it rebind the stick to WinUSB and load Wintun, which works whenever the stick is plugged in.
    - **Runs from boot** (automatic start), so the API is always there. With no stick, it reports `radio.state: "absent"`: holds stream `active: false`, and advertising locks stay held and apply once a stick comes up. These are states, not errors, so apps needn't reconnect after a replug.
    - **The adapter lives as long as the service**, disconnected while there's no stick. That's Apple's model: a Mac's `awdl0` stays up, with the same address, while AWDL itself is switched off and on on demand (six times in one morning: "Disabling AWDL due to no services and no active sockets"). An Apple TV's `awdl0` exists idle, without an IPv6 address.
    - **The AWDL address is random per service start** and kept across replugs within that run; nothing is stored. Apple randomizes AWDL identifiers: once per interface activation in 2018 ([Stute et al., MobiCom '18](https://arxiv.org/pdf/1808.03156)), on unsynchronised timers by 2021 ([USENIX Sec '21](https://www.usenix.org/system/files/sec21-stute.pdf)). Seen here: a Mac (macOS 11.7) kept its MAC for over 30 hours within one boot, through those on/off cycles, and an iPhone (iOS 27) for over a day, while both rotated their AWDL host names (UUIDs) within hours.
  - *Progress 2026-11-18:* the daemon now stays up without a stick. It starts the control API, picks its AWDL address and opens the adapter once, disconnected. Then it loops: wait for a supported adapter (waking on USB arrivals and removals through `CM_Register_Notification`, `warlock_usb::DeviceWatch`), claim it, open the radio, connect the adapter, run AWDL until the stick is unplugged, the radio ends or Warlock stops, then disconnect and close, back to `absent`. Locks and traffic counters carry across.
    - **Live, 2026-11-18:** with a hold open, the T3U came up, was unplugged, and came back in the same port. Warlock logged "the adapter was unplugged" at the removal notification, reported `absent` 40 ms later (the hold went `active: false`), found the stick again on arrival (still on WinUSB, no rebind), and was `up` again 7.3 s after that, with the same AWDL address and adapter index. Events and `info` followed each step.
    - **Live, another port (2026-11-18):** unplugged and plugged into a different port, the T3U kept its device instance (`USB\VID_2357&PID_012D\123456`) and so its WinUSB binding: no rebind. Windows keys a device that reports a serial number by that serial, not its port; the T3U's is "123456", likely the same on every unit. Up again 7.1 s after being found, with the same address and adapter index; the session after ran for over 3 minutes, following the master and finding peers and their services.
    - **Live, rebinding (2026-11-18):** with the T3U given back to Windows' own driver (`warlock-usb release`: `RtlWlanu`, Net class), Warlock found it there at start, bound WinUSB again in 1.5 s and was up 7 s later. Across service runs the adapter's interface index can change (74, then 81 after Windows' Realtek driver had held the stick); within a run it stays.
    - *Open:* a running service claims any supported stick as it appears, so it would take back a stick the user gives to Windows for ordinary Wi-Fi. Releasing it (`warlockctl release`, uninstall) is to be designed with the installer: "don't claim this stick" has to outlive a connection.
    - **Sleep and resume (2026-11-19).** This PC offers only hibernation (S4). `powercfg /a` lists no standby state: the firmware supports neither S3 nor S0 Low Power Idle (Modern Standby, S0ix).
      - **What happened before the fix:** a hibernation didn't look like an unplug.
        - Two seconds into it, devourer's sends failed ("send_packet returned false"), then a hop ("rtw_read: iostream stream error"). From then on, every send and hop failed with "resource deadlock would occur", for 10 hours across the resume, 2,200 warnings.
        - Windows reported no removal, so nothing ended the session. The radio heard nothing, and Warlock led a cluster of one.
        - After the resume, the stick was present on USB and healthy, but cold, its firmware gone.
        - Stopping the service hung while closing the radio, and the service went on reporting Running, so `Restart-Service` failed. Killing the process and starting it again brought the radio up in 7 s.
        - Why, inside devourer, wasn't found. MSVC reports a thread re-locking a `std::mutex` it already holds that way, yet every lock on that path is a `lock_guard`. A lock left held would also explain the hung close, with another devourer thread blocked on it; that is a guess.
      - **The fix,** in that order of defence:
        - `power.rs` follows `PowerRegisterSuspendResumeNotification`, which works for the service and a foreground run alike. On the suspend notice, the session closes the radio while the bus still answers; the callback holds the suspend up to 2 s for it. On wake, the radio opens afresh.
        - A resume without that notice also ends the session. So do devourer's RX loop ending, which `recv` now reports where before it timed out forever, and every send and hop failing for 3 s, 20 times at least.
        - Closing runs under a 20 s limit. Past it, Warlock reports a failure and terminates, for the service's recovery actions to start it again with a fresh USB session.
        - The service reports StopPending as soon as a stop arrives. A stop that hasn't finished in 30 s ends the same way, reported as Stopped.
      - **Live, a foreground run:**
        - It got the suspend notice at 20:09:18.397Z and closed the radio in 155 ms; Windows went down 5 s later.
        - It woke at 20:11:35.9Z, the radio was up 7.4 s later, the first frame came 1 s after that, and it was synced to the master again at 20:11:51.
        - No warning or error.
      - **Live, the 0.1.1 service, installed over 0.1.0 by its MSI:**
        - The first version upgrade: 0.1.0 stopped cleanly, `warlock setup` kept `warlock-users` and set the failure actions again, and 0.1.1 had the radio up 7 s after starting.
        - `sc stop` answered STOP_PENDING (checkpoint 1, a 30 s hint) at once, and the service was stopped 0.5 s later.
        - Hibernated: the suspend notice came at 20:32:33.904Z, and the radio closed in 235 ms; Windows went down 2 s later. It woke at 20:34:58.8Z; the radio was up 7.4 s later and synced again at 20:35:14. No warning or error.
      - **Untried:** the stop limit and the close limit (no way to wedge devourer on purpose).
      - **Untested: Modern Standby (S0ix), and S3 sleep,** since this PC supports neither. Only hibernation has been tried. Under S0ix, Windows may deliver the suspend and resume notices at different moments, and may keep the USB bus powered, so the fix may behave differently there. That needs a machine with Modern Standby.
  - **Installer (Parker, 2026-11-18):** Warlock is to be distributed through winget as `Regulad.Warlock`, so that Koala and the AirDrop app can declare it as a package dependency (stable in winget since 1.6; it must come from the same source). Its installer is an **MSI**: winget's `portable` and `zip` types only copy files, so they can't register a service, and MSIX needs a signing certificate and sandboxes the app.
    - **Built with Windows' own tools**, not WiX: WiX's binaries come with the "Open Source Maintenance Fee" EULA since v6, and Parker chose not to depend on an installer toolchain. `crates/warlock-msi` writes the database through the Windows Installer API (`msi.dll`), as `.idt` tables whose column definitions are copied from MSIs Windows itself installed, and packs the files with `makecab`.
    - **What it installs:** `warlock.exe`, `warlockctl.exe`, both licence texts and the Wintun exception in `C:\Program Files\Warlock`, which joins the system `PATH`. Also the Warlock service (LocalSystem, automatic delayed start, its own service SID, restarted on failure), all declared in MSI tables. `warlock setup` creates `warlock-users` after the files, and on an uninstall that isn't an upgrade, `warlock teardown` gives the adapter back to Windows' own driver and removes the group.
    - Versions: a newer one replaces an older (and a rebuild of the same version replaces itself); an older one is refused. The upgrade code and component GUIDs never change (their provenance is in `warlock-msi`).
    - **Its own pages (Parker, 2026-11-18),** for an install started by hand. Silent installs, winget's among them, skip them.
      - **Licences:** which part is under which licence, the source's address, then the GPL-2.0, Wintun exception and AGPL-3.0 texts, converted from the repository's Markdown into RTF at build time. It asks nothing ("Next", not "I accept"): GPLv2 §5 and AGPLv3 §9 don't require accepting them to install or run the program.
      - **Install folder:** with a folder browser, and a note that the service starts with Windows and takes over supported adapters.
      - Progress, then Done, Cancelled or Failed. Opened again, the package offers Repair or Remove.
      - All of it is ordinary Windows Installer UI tables (`warlock-msi`'s `ui`). A test checks each dialog's tab order forms one cycle, after Windows Installer refused one that didn't (error 2810).
      - Tried in Windows Sandbox by keystrokes, with a screenshot of every page: installed through the pages (exit 0), opened again and removed (exit 0).
    - Checked without installing: the package reads back with its tables, cabinet stream and summary; an administrative install (`msiexec /a`) unpacked all four files byte-identical to their sources.
    - **Installed, upgraded and uninstalled on this PC (2026-11-18),** silently as winget would:
      - The service runs automatic (delayed) as LocalSystem with an unrestricted service SID, restarting after 5 s, 10 s and 60 s (also on non-crash failures). It had the radio up 10 s after the install.
      - `warlock-users`, the `PATH` entry and the files were in place.
      - A rebuild of the same version replaced the first, leaving one Apps & Features entry.
      - The uninstall removed the service, group, `PATH` entry and files, and gave the stick back to Windows' Realtek driver.
    - Windows Installer can't set restart failure actions from `MsiServiceConfigFailureActions` (error 1939: they need the service opened with start access too), so `warlock setup` sets them, after `MsiConfigureServices` and before `StartServices`. A rollback action (`warlock setup --undo`) removes the group if a fresh install fails after it; the first, failed attempt had shown a rollback otherwise leaves it.
    - **Privileges (2026-11-18):** the service keeps one of LocalSystem's 28 privileges, `SeChangeNotifyPrivilege`, set by the MSI as its required-privileges list (`MsiServiceConfig`, `SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO`); the service manager strips the rest from its token. Found by trial on this PC: each start began with the stick on Windows' Realtek driver, and the token was read back from the running process. With a list of `SeChangeNotifyPrivilege` alone, as with the full set, it rebound the stick to WinUSB, created and addressed the Wintun adapter, opened the radio and followed the cluster. In Windows Sandbox (a fresh Windows), the installed service with that token also downloaded Wintun and installed its driver into an empty driver store before creating the adapter. Here that path couldn't be tried: Tailscale's adapter uses the Wintun driver already installed. It stays LocalSystem, the account allowed to rebind drivers and create adapters.
    - **Logging: the Event Log, through ETW (Parker, 2026-11-18).** It replaces `%ProgramData%\Warlock\warlock.log`, which only ever grew.
      - Warlock's events are a manifest-based ETW provider, `Regulad-Warlock` (`crates/warlock/events.man`).
      - Information, warnings and errors also go to the Event Log channel `Regulad-Warlock/Operational`, which Windows caps at 16 MB. Verbose events would go to ETW sessions only.
      - `build.rs` compiles the manifest with the Windows SDK's `mc.exe` and `rc.exe` into a resource of `warlock.exe`, and generates the provider GUID and event descriptors from `mc.exe`'s header.
      - `warlock setup` registers the manifest (`wevtutil im`, pointing at the installed `warlock.exe`), and `teardown` and `setup --undo` unregister it.
      - The `tracing` output is unchanged except for leaving out the time and level, which the Event Log records itself.
      - This completes W5's ETW item.
    - Found on a fresh Windows (Windows Sandbox, 2026-11-18):
      - **The Visual C++ runtime.** `warlock.exe` imports `VCRUNTIME140.dll`, `VCRUNTIME140_1.dll` and `MSVCP140.dll` (devourer's C++). A fresh Windows 11 has none of them, so `warlock setup` failed to start (`0xC0000135`), and the install failed (1721, then 1603) and rolled back cleanly.
        - *Decided (Parker, 2026-11-18):* a winget dependency on the runtime's package, `Microsoft.VCRedist.2015+.x64`, rather than linking it in, so Microsoft's runtime isn't ours to ship (as with `wintun.dll`).
        - The minimum version is the toolset that linked the binaries, read from their headers (now 14.50): Microsoft requires a runtime at least that new. The package searches System32 for the three DLLs at that version or later. Without them it refuses to install, naming the runtime and the winget command. `warlock-msi winget` writes winget's manifests from a finished package, dependency included (`winget validate` passes).
        - Tried in the sandbox: without the runtime, the package refused with that message and installed nothing. With Microsoft's current one (14.52), it found all three DLLs and installed.
      - **Smart App Control.** Where it is on, unsigned `warlock.exe` is blocked from running at all ("An Application Control policy has blocked this file"; Code Integrity events 3077 and 3033). The sandbox had it on. Running there takes a signature that chains to Microsoft's trusted root programme.
        - *Decided (Parker, 2026-11-18):* Azure Artifact Signing, from GitHub Actions authenticated with OIDC. Waiting on Parker to set it up. The release order it fits is in `warlock-msi`'s docs: sign the binaries, package them, sign the package, then write the manifests.
  - **The clock runs from the moment the radio opens (fixed 2026-11-18).** Warlock's clock is the radio's TSF as known from received frames (`RxClock`). Until one was heard it had no clock, so it couldn't transmit, and alone it could never start a cluster of its own. Seen 2026-11-18: after an upgrade, the radio was up for a minute on a channel where nothing was heard. (The daemon also stopped publishing to the API until then, which left it reporting `opening`; fixed first: everything but the engine runs without a clock.)
    - The fix: before the first frame, the clock is host time since the radio opened. The first frame fixes a constant that moves the hardware TSF onto it, so a grid started alone runs on without a jump. Peers can't tell, because a frame's timing is relative (`phy_tx_time − target_tx_time`). The daemon now also ticks the engine when no frame arrives, so a lone election and silent peers are reported on time, not at the next frame.
    - **Live, 2026-11-18:** opened on channel 165, the radio heard nothing there for 2 s. Warlock then stood as master and hopped to channel 6, the first slot of its own sequence, where it heard its first frame 2.14 s after coming up. An Apple device outranking metric 60 appeared and Warlock followed it. A second run logged `MasterChanged` to itself 2.01 s after the radio came up. Each run logs how long the first frame took.
  - **The AWDL host name stays Windows' computer name: a known limitation, documented (Parker, 2026-11-18).** It goes out in our ARPA TLV and as our services' SRV target: a stable identifier, which Apple stopped using after [Stute et al., USENIX Sec '19](https://www.usenix.org/system/files/sec19-stute.pdf) (Apple's AWDL host names are random UUIDs, rotated within hours). Windows' own mDNS also announces it on the adapter.
    - **Why:** Windows' mDNS stack answers address queries for the computer name only.
      - Checked 2026-11-18 on a host-only adapter. A service registered through `DnsServiceRegister` with another host name and the interface's own address was published with that name as its SRV target, but an AAAA query for the name went unanswered. The computer name's was answered.
      - A random name would mean Warlock answering for it itself, and changing which registrations the advertiser counts as ours.
    - The README says so, under Privacy, and suggests not giving the PC an identifying name: Windows' default `DESKTOP-…` names are meaningless.
- **W6 Frames in Wireshark, then LLW (Parker, 2026-11-19).** Koala's trial 17 found that Continuity Capture's audio travels over Apple's Low-Latency Wi-Fi (LLW, `llw0`), not AWDL. The iPhone sent about 900 kbps that Warlock never delivered, since it carries only AWDL-encapsulated data. No tool here could show those frames: Wireshark sees only what Warlock delivers on its adapter. This reverses the 2026-11-18 decision of no capture endpoint and no capture command. In order:
  1. **A capture endpoint.** `GET /v1/capture` streams radiotap pcapng (linktype 127) of the frames the radio hears, and optionally its own transmissions, until the client closes; like `/v1/events`, it holds nothing.
     - Filters: `peer=MAC` (repeatable), `kind=awdl|other|all`, `tx=true`.
     - It is a tap in the radio loop, costing one atomic check when no one captures. Each capture gets a bounded queue, so a slow client loses frames and never stalls the radio; drops are counted and logged.
     - Each capture is logged with its process, as locks are.
     - **Who may capture (Parker, 2026-11-19):** anyone who may use the API, `warlock-users` included. A `peer` filter is optional. *Reversed the same day for 0.2.0 (3b):* only Administrators and a new `warlock-admin` group, on a pipe of their own.
     - **Implemented 2026-11-19:**
       - `warlock-api`'s `capture` module. A frame matches a filter by its first three addresses (receiver, transmitter, BSSID or third address); `kind` comes from the daemon via `awdl_proto::parse`.
       - Each capture queues 4,096 frames. Frames dropped for a slow client are counted in the next frame's `epb_dropcount`, and the direction goes in `epb_flags` (`warlock-capture`'s `Writer::write_with`).
       - The daemon offers each received frame before the engine sees it, and each frame it sends once the radio accepted it.
       - `warlock-client`'s `capture`, and `warlockctl capture`.
       - Tested against the real server and client (`tests/contract.rs`) and by unit tests.
       - **Live, 2026-11-19:** `warlockctl capture --tx` for 20 s on the T3U, with the development build in the foreground.
         - It wrote 560 frames, none dropped (328 in, 232 out by `epb_flags`), on channels 149 and 6.
         - The TSF matched the capture times to the microsecond, and Wireshark dissected Warlock's own AWDL frames cleanly.
         - The 23 frames Wireshark called malformed were one nearby Apple device's MIFs, which its AWDL dissector doesn't fully parse.
         - Sent frames carried a made-up 0 dBm signal; they now carry no antenna-signal field at all.
  2. **A Wireshark extcap plugin.** It shows a "Warlock radio (802.11)" interface beside the Warlock AWDL adapter, with the filters in its options dialog, reading the capture endpoint. Wireshark looks for it in its own `extcap` folder or the per-user `%APPDATA%\Wireshark\extcap`.
     - **Installed by the MSI (Parker, 2026-11-19),** as a checkbox that is off by default, so installing it is a choice. It is greyed out, with a note that Wireshark was not detected, when there's no Wireshark.
     - **Implemented 2026-11-19:**
       - `warlock-extcap.exe`, a second binary of `warlockctl`'s package. It answers Wireshark's `--extcap-interfaces`, `--extcap-dlts` and `--extcap-config` (Peers, Frames, Warlock's own frames), then writes `GET /v1/capture` into Wireshark's pipe.
       - The options have no validation regex: extcap values are delimited by braces, so a quantifier such as `{2}` would end the field. Warlock's 400 reaches Wireshark instead.
       - **Tried with Wireshark 4.6.9 (`tshark`):** from the per-user `extcap` folder, `tshark -D` listed `warlock (Warlock radio (802.11))`. A capture against the 0.1.1 service showed the API's own error ("not allowed to use Warlock", since the user isn't in `warlock-users`).
       - **The MSI:**
         - Feature `WiresharkPlugin` (child of Warlock, level 1000, so off), raised to 1 by `WIRESHARKPLUGIN AND WIRESHARKDIR`.
         - `AppSearch` finds `WIRESHARKDIR` through `RegLocator`, from `App Paths\Wireshark.exe` `Path` (64-bit) or `SOFTWARE\Wireshark` `InstallDir` (32-bit view, where Wireshark's installer writes it). It's a directory search, so the folder must exist. The plugin goes into `[WIRESHARKDIR]extcap`.
         - A `CompLocator` on the plugin's component sets `WIRESHARKPLUGIN` when it's installed, so upgrades keep it.
         - The checkbox is on the install-folder page; `ControlCondition` disables it and shows "Wireshark was not detected." when `NOT WIRESHARKDIR`.
         - Both properties are secure custom properties.
       - **Checked without installing** (`OpenPackage` with machine state ignored, then `AppSearch` and costing):
         - here `WIRESHARKDIR` is `C:\Program Files\Wireshark\` and the plugin's target `…\extcap\`;
         - unticked, the plugin isn't requested; ticked, it is (local);
         - ticked with `WIRESHARKDIR` cleared, it isn't, and Warlock still is.
         - An administrative install unpacks `extcap\warlock-extcap.exe` with the other two binaries.
       - The release builds, uploads and signs it with the others, and checks the package and three binaries.
       - Not yet seen: the page itself with the checkbox, and an upgrade that keeps the plugin.
     - **Joining `warlock-users` from the installer (Parker, 2026-11-19):** the plugin is only usable without elevation by a member, so the same page has a second checkbox, "Add me to warlock-users", also off by default. A silent install takes `JOINWARLOCKUSERS=1`.
       - It adds the account running the install: `warlock setup --member [UserSID]`, as SYSTEM, after `warlock setup` has made the group. The target is formatted as the action is scheduled, so the SID is the installer's.
       - "Already a member" counts as success. A failure is only logged (`msidbCustomActionTypeContinue`), since the account can still join by hand.
       - It counts from that account's next sign-in, as the page says.
       - Nothing undoes it except an uninstall, which removes the group. Unticking the box on an upgrade leaves the membership as it is.
       - **Already a member (Parker, 2026-11-19):** the box shows ticked and greyed out, with "You're already in warlock-users." Windows Installer can't see group membership (its searches read files, folders, the registry and components; the SAM is SYSTEM's), so the package carries a custom action DLL, `warlock-msi-ca` (the Binary table's `WarlockCa`). Its `FindMembership` runs in the UI sequence after `LaunchConditions` (so the Visual C++ runtime it links is there), compares the group's members with `UserSID`, and sets `WARLOCKUSERSMEMBER` and `JOINWARLOCKUSERS`. The release builds and signs the DLL with the programs.
       - **Sign out after joining (Parker, 2026-11-19):** the Done page's Finish runs `FindJoined`, which asks the group again. When the account is in it now and wasn't before, a modal says so and offers "Sign out now" (`SignOut`, `ExitWindowsEx(EWX_LOGOFF)`: unsaved work can still hold it up) or "Later", the default. Since it asks the group itself, an install that failed to add the account doesn't ask it to sign out. Silent installs show nothing.
       - None of the DLL's actions fails the install; each logs what it found (`msiexec /l*v`).
       - Seen 2026-11-19, in the real UI of a local build without installing: `FindMembership` found this account already in the group, and the box showed ticked and greyed. In a preview copy that opened on the modal (installing nothing, its sign-out removed), `FindJoined` reported "joined", and Parker looked the modal over. A restricted engine (`OpenPackage` for inspection) won't run custom actions, so only the UI can try them.
  3. **Release 0.1.2** once 1 and 2 are done: a new endpoint is a feature, so the `z` goes up.
     - **Released 2026-11-19** ([v0.1.2](https://github.com/regulad/Warlock/releases/tag/v0.1.2), tag signed, at `2f9cd53`). Before the tag, "Build and sign" ran by hand on master, so the release path's third binary was built and signed once before it counted. The published MSI's signature is Valid.
     - Still to be seen in a real install of it: both checkboxes' effects (the plugin in Wireshark's `extcap` folder, the account in `warlock-users`), and an upgrade keeping the plugin.
     - **Installed by Parker, 2026-11-19:** the account joined `warlock-users`, so the elevated part formats `[UserSID]` to the installer's SID. **The plugin wasn't installed, a bug:** Windows Installer decides features in `CostFinalize`, before the pages, and a property the checkbox sets afterwards doesn't decide them again. The client then hands the server its feature choice (`ADDLOCAL`), which lacked the plugin. Silent installs weren't affected: `WIRESHARKPLUGIN=1` is there before costing. Reproduced without installing by costing first and ticking after. The plugin was then added to the installed 0.1.2 with `ADDLOCAL=WiresharkPlugin` from the signed package, and Wireshark listed "Warlock radio (802.11)".
  3a. **Release 0.1.3**, the installer's fixes:
     - Install publishes `AddLocal` or `Remove` for the plugin by the checkbox, before `EndDialog`. Unticked on an upgrade from a version with the plugin, it goes with that version, and the page says "The previous version of the plugin will be removed." (Parker, 2026-11-19). A second property from the same `CompLocator`, `WIRESHARKPLUGINFOUND`, tells it the plugin was there, since unticking clears `WIRESHARKPLUGIN`.
     - The page's conditional notes now hide again when their condition stops holding, as the checkbox changes.
     - The membership checkbox and the sign-out modal above.
     - **Released 2026-11-19** ([v0.1.3](https://github.com/regulad/Warlock/releases/tag/v0.1.3)). Its notes say that it lets every `warlock-users` member capture, and that a future version restricts capture to `warlock-admin` (Parker's wording).
  3b. **0.2.0: captures for `warlock-admin` only (Parker, 2026-11-19).** A capture hears every device near the radio, not only AWDL peers, and with `tx` Warlock's traffic for every user of the PC. That is more than `warlock-users` should get with the rest of the API, as Npcap's admin-only mode and Linux's `wireshark` group also judge.
     - **A second pipe, not a check in the server (Parker):** `\\.\pipe\warlock-admin` admits SYSTEM, Administrators and `warlock-admin`, and serves only `GET /v1/capture`. So Windows decides who may capture by the pipe's access list alone, with no impersonation or group check in Warlock's code. It also maps onto Unix sockets owned by different groups, should Warlock ever run on Linux.
     - `\\.\pipe\warlock` admits `warlock-admin` too, so that one group is enough for everything. It no longer has `/v1/capture` at all: 404, as for any route it doesn't serve. That's a break for clients that captured there, hence 0.2.0.
     - **Two contracts under the same licence:** `api/openapi.yaml` without capture, and `api/admin.yaml` with it, whose errors refer to the main contract's `Error`. The contract tests check both documents' operations and versions, and that neither pipe serves the other's routes. Redocly lints both.
     - `warlock-client` serves both: `ADMIN_PIPE` beside `PIPE`, and a connection error that names the pipe and the group it needs. `warlockctl capture` and `warlock-extcap` use the admin pipe; `--pipe` still overrides.
     - `warlock setup` creates both groups and `--member GROUP SID` adds to either; `warlock teardown` and the rollback remove both.
     - **The installer:** the options moved to a page of their own, Options, after the install folder, since a third checkbox and its notes don't fit under the folder. "Add me to warlock-admin" sits below "Add me to warlock-users", with the same stay-ticked logic (Parker); `JOINWARLOCKADMIN=1` when silent. `FindMembership` and `FindJoined` cover both groups, and the sign-out modal names the groups the install added. A test checks that the DLL, the server and the package spell the groups and properties the same.
     - **Tried before release,** with the release build in place of the service and no `warlock-admin` group yet. As a `warlock-users` member, unelevated: `warlockctl info` worked, `warlockctl capture` was refused by Windows ("not allowed to capture…"), and capture asked of the main pipe got 404. Elevated, the admin pipe streamed 129 frames in 5 s.
     - **Released 2026-11-19** ([v0.2.0](https://github.com/regulad/Warlock/releases/tag/v0.2.0), tag signed, at `e808abc`). Koala moved to `warlock-client` 0.2.0 (its `7580442`, local). The Options page is still to be seen in a real install.
  3c. **0.2.1: the sign-out prompt.** Parker installed 0.2.0, ticked `warlock-admin`, and was added, but setup never asked him to sign out.
     - Calling the DLL's `FindJoined` directly, on a package session with his install's properties, set `WARLOCKJOINED` and named `warlock-admin`: the DLL was right.
     - A preview copy that opened on the Done page (no install, no sign-out behind the button) logged `FindJoined` setting `WARLOCKJOINED` on Finish, and then no `SignOutDlg`. With `FindJoined` moved before the page, still none.
     - **The cause:** Finish published a SpawnDialog of the prompt and then an EndDialog, both conditions true, and a button changes dialogs once per press: Windows Installer did only the last, the end. (WiX's own pages pair such events under opposite conditions.)
     - **The fix:** Finish goes on to the prompt (NewDialog, in the Done page's place) when `WARLOCKJOINED`, and ends otherwise; the prompt's buttons end setup as Finish would. `FindJoined` runs once the install is done, in the UI sequence after `ExecuteAction`, so nothing depends on when conditions are read. A 0.2.0 copy changed the same way showed the prompt, and a test now checks that no control has two dialog events that can both happen.
     - Only the installer changes, so 0.2.1 needs no reinstall (Parker).
  4. **Reverse-engineer LLW,** from a capture made with 1 and 2 during a Continuity Capture session, and from prior art:
     - [Henri Jäger, "Cracking open what makes Apple's Low-Latency WiFi so fast", 39C3](https://events.ccc.de/congress/2025/hub/en/event/detail/cracking-open-what-makes-apple-s-low-latency-wifi-so-fast) (recorded, with an [HPI write-up](https://hpi.de/en/article/reverse-engineering-of-apples-low-latency-wi-fi/));
     - [US11184890, "Low-latency Wi-Fi MAC-layer protocol"](https://patents.google.com/patent/US11184890), with an LLW master scheduling channel access, and a schedule frame;
     - [The Apple Wiki's LLW page](https://theapplewiki.com/wiki/LLW);
     - [Wang Yu, Black Hat USA 2022](https://i.blackhat.com/USA-22/Wednesday/US-22-Wang-Dive-into-Apple-IO80211Family-Vol-II.pdf), where `llw0` is the "Low-latency WLAN Interface" of Skywalk;
     - [RTL8814Native](https://github.com/DrogaBox/RTL8814Native/releases/tag/awdl-preview-20261117), a macOS Realtek driver whose experimental `rtlawdl_llw=1` creates `llw0`. Its licence is unstated, so it is a reference only.
     - What's known from Koala's trials (its `docs/guest-pairing.md`, trial 17):
       - On a Mac, `llw0` is a standing interface with `awdl0`'s MAC and link-local address.
       - A Continuity Capture stream adds a per-session ULA on it, `fd…::N`.
       - The iPhone sends to the MAC the host gave it, with no neighbour discovery.
     - **Trial 19 (2026-11-19), with this capture running** (Koala's `docs/guest-pairing.md`):
       - **No `llw0` frame reached the air:** the iPhone never attached an LLW peer for Warlock, and kept its audio. LLW isn't a different encapsulation of the AWDL data Warlock carries.
       - **What the iPhone did send:** AWDL data as QoS Data (TID 6 for its gPTP, TID 0 for TCP), and 41 frames as A-MSDUs, which Warlock dropped (fixed, below).
       - **Two TLVs Warlock doesn't send:** 17 (HT/VHT capabilities) and an unknown 33. 98 of its action frames also end with 2 bytes after the TLVs, kept as a trailer.
       - **Static analysis of iOS 27.2.1:** an LLW peer (over AWDL or NAN) comes with a "Continuity Real Time Group", and with a Mac or Apple TV as host, the host starts one: a UMI with unicast options `0x17000000` and an RTG TLV (31). The iPhone's driver then adds the LLW peer itself. Warlock sent no UMI, so none started. The work is tracked in [#10](https://github.com/regulad/Warlock/issues/10) (start a realtime group) and [#11](https://github.com/regulad/Warlock/issues/11) (carry LLW), with [#5](https://github.com/regulad/Warlock/issues/5) (UMI) and [#9](https://github.com/regulad/Warlock/issues/9) (VHT).
     - **Capability audit (2026-11-19):** what Warlock tells its peers that isn't true, unknown or under-claimed, per `AGENTS.md`'s rule to describe Warlock truthfully: [#3](https://github.com/regulad/Warlock/issues/3)–[#9](https://github.com/regulad/Warlock/issues/9). Trial 19's capture also raised [#12](https://github.com/regulad/Warlock/issues/12) (TLV 33, a preferred channel) and [#13](https://github.com/regulad/Warlock/issues/13) (2-byte trailers).
     - **A-MSDUs (2026-11-19):** Warlock's Block Ack responses allow A-MSDUs (`0x1003`), yet `awdl-proto` refused them. It now parses one as `Frame::Amsdu`, a list of `Msdu`s (destination, source, AWDL data, padding kept), and the engine delivers each subframe as a data frame. Trial 19's capture agrees with Wireshark subframe by subframe (3,498 frames compared) and re-emits byte for byte.
  5. **An LLW interface in Warlock** beside AWDL, as on a Mac: a second adapter carrying LLW both ways. That includes reaching a peer's LLW ULA, which isn't derived from its MAC. Designed once 4 says what LLW needs.
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
- **CI (2026-11-18):** `.github/workflows/check.yml` runs those hooks over the whole tree, then the tests, on every pull request and every push to `master`. It uses the same pinned cargo-deny (0.20.2, by SHA-256) and pre-commit.
- **Dependabot (Parker, 2026-11-18):** `.github/dependabot.yml`, weekly, covering cargo, GitHub Actions, the pre-commit hooks and the devourer submodule.
  - Every update waits until its release is two weeks old (`cooldown`), the rule for new dependencies. Security updates don't wait, so review them by hand. The submodule, Parker's own fork, has no cooldown.
  - Its pull requests get the CI above, so cargo-deny holds them to the licence zone.
  - Alerts and security updates are on in `.github/settings.yml`, which also lists Dependabot's `dependencies` label: the Settings app deletes labels it doesn't list.
- Unit and fuzz tests on `awdl-proto`.
- Deterministic `awdl-core` tests driven by captured pcapngs through `PcapReplayRadio` with a simulated TSF clock.
- Hardware loops per milestone using the T3U, an iPhone, and lab Macs / a jailbroken Apple TV as witnesses (`tcpdump -i awdl0`, `dns-sd`, `ping6 %awdl0`). Tools: `awdlsync` (engine live or on a capture, with the W2 check), `awdlcap` (radiotap pcapng for Wireshark), `warlock-usb`.
- Wireshark for every interop bug: on the "Warlock AWDL" adapter for packets, on `awdlcap` output for frames.
