# Windows bring-up (W0)

## Hardware

- **TP-Link Archer T3U:** RTL8812BU, devourer's "Jaguar2" backend, USB
  `2357:012d`.
- It enumerates as a single-function device (`USB\VID_2357&PID_012D\<serial>`,
  no `MI_xx`, no Bluetooth interface).
- Out of the box Windows binds its in-box `netrtwlanu.inf` (Microsoft-signed,
  service `RtlWlanu`, class Net) and the dongle acts as a normal Wi-Fi adapter.
- devourer measures this chip as a working hardware ACK responder, with
  firmware-assisted channel hops of about 1.4–1.9 ms.

## Binding the dongle to WinUSB (`crates/warlock-usb`)

Warlock claims the adapter itself, using only Microsoft-signed parts, the way
Device Manager's "Have Disk" does:

1. Find the devnode by hardware ID (`SetupDiGetClassDevsW` over the USB
   enumerator).
2. Build a class driver list from `%windir%\INF\winusb.inf` alone
   (`DI_ENUMSINGLEINF` + `DI_FLAGSEX_ALLOWEXCLUDEDDRVS`) and pick the node whose
   hardware ID is `USB\MS_COMP_WINUSB` ("WinUsb Device").
3. SetupAPI only lists drivers of the device's current setup class, so first
   move the device from Net to USBDevice
   (`SetupDiSetDeviceRegistryPropertyW(SPDRP_CLASSGUID)`). Microsoft's docs list
   that property as reserved, but the call works.
4. `DiInstallDevice` with that node.

No catalog is generated, no certificate is installed, and no reboot was needed.
Verified result: class `USBDevice`, service `WINUSB`. libusb opens the device
with no `DeviceInterfaceGUIDs` added.

`release` calls `DiInstallDevice` with no driver, which reinstalls the best
match from the driver store (`netrtwlanu.inf`). It hasn't been run yet.

All mutating calls need administrator rights; the service runs as LocalSystem.
For development, `sudo warlock-usb bind` (Windows `sudo`, inline mode) works.

## Building devourer (`crates/devourer-sys`)

- devourer is a git submodule (`third_party/devourer`), built by `build.rs`
  through the `cmake` crate. Only the 8822B backend is enabled.
- The submodule points at our fork, `regulad/devourer`, on its `warlock`
  branch: upstream OpenIPC plus one commit per Warlock fix, so each fix can go
  upstream as its own PR. In the checkout, `origin` is the fork and `upstream`
  is OpenIPC.
- devourer's CMake requires `pkg_check_modules(libusb-1.0)`.
  `cmake/modules/FindPkgConfig.cmake` stands in for CMake's module and produces
  the `PkgConfig::libusb` target from the vendored `libusb1-sys` headers, so
  devourer needs no build change and no pkg-config binary is needed.
- `shim/dvr_shim.{h,cpp}` is a narrow, exception-free C ABI. It covers open
  (claim, reset, `CreateRadio`), bring-up, a blocking RX loop with stop,
  inject, fast/full retune, TX-power re-apply, ACK responder arm/disarm, TSF
  read, and close. It catches every C++ exception.
- Contract inherited from devourer:
  - open and close on the same thread (the Windows per-adapter lock is a named
    mutex, owned by the thread that took it);
  - run the RX loop on its own thread;
  - serialise TX and control calls (the shim holds a mutex the RX callback
    never takes);
  - tear down in order: stop RX, clear the ACK responder (it otherwise keeps
    ACKing after exit), `Stop`, destroy, release, close, `libusb_exit`.
- Builds under MSVC in about 40 s.

## Receive results

| Channel | Result |
|---|---|
| 6, 36, 120, 161 | frames received, hardware TSF on each |
| 44 | frames received, including AWDL PSFs from an Apple TV |
| 149 | idle when tested alone; AWDL from an iPhone and a Mac when they were active |
| 157 | idle at the test site |

## Timing and known issues

- **Bring-up takes about 20 s.**
  - It was ~25–33 s at Windows' default 15.6 ms timer resolution and ~19–21 s
    after `timeBeginPeriod(1)`, because devourer sleeps in many short steps.
  - Most of what's left is ~22k PHY/AGC/RF table register writes, each a
    synchronous WinUSB control transfer of about 1 ms.
  - Batching or pipelining those writes is the obvious fix.
- **Cross-band retune bug (fixed in our fork):** after any 2.4 GHz tune, a full
  retune to 5 GHz left receive dead.
  - Cause: `HalJaguar2::set_channel_bw` never set RF18's 5 GHz band bits
    (16 and 8). The 2.4 GHz branch clears them, and the 5 GHz branch only
    kept what it read back. rtw88 sets them explicitly.
  - Fix: commit "jaguar2: set the 5 GHz RF18 band bits on a 2.4 -> 5 GHz
    retune" on the fork's `warlock` branch. It sets the band bits, and it also
    re-applies the band-keyed WL-only antenna grant (`0xcbc[9:8]`) on every
    band change, as the vendor driver does. The two halves weren't tested
    separately.
  - Firmware hops (`fastretune_fw = 2`) don't go through `set_channel_bw`, but
    they were only measured with the fix applied. Whether they needed it is
    open; that's the check to make before an upstream PR.
  - Verified with `hoptest`: 6 → 44, 6 → 161 and 44 → 149 all receive, on both
    the full and the firmware paths.
- **One silent channel-6 run** went quiet after its first second. It didn't
  reproduce in a 10 s rerun.
- **Two TSFs.** `dvr_read_tsf` does not read the counter that stamps
  received frames. A register read came back about 318 ms *behind* the RX
  timestamps of frames that had already arrived. The two tick at the same
  rate (the gap was stable to 20 µs over 30 s) but started apart. Scheduling
  against AWs on the register value put every frame we sent about 7 ms off
  the AW grid. `warlock-radio`'s `RxClock` estimates "now" on the RX timebase
  instead: each frame is paired with the host instant it arrived, and the
  pairing with the least delay over the last 2 s wins.
- **libusb message during RX:** a long live run prints
  `libusb: error [windows_submit_transfer] program assertion failed - transfer HANDLE is NULL after transfer was submitted`
  every so often. Receiving carried on with no frames lost (60 s on channel
  44, 0 queue drops). Not yet investigated.
- Caveats from devourer's notes:
  - register reads occasionally fail with `LIBUSB_ERROR_PIPE` under load (retry);
  - transmit throughput with receive running is reportedly low on Jaguar2
    (still to measure);
  - the TSF resets at bring-up.

## Tools

On the safe radio (`warlock-radio`):
- `cargo run --release -p warlock-radio --example awdlsync -- [channel] [seconds]`,
  or `-- --replay <capture.pcapng>`: the AWDL engine live or on a capture. It
  shows the peer table, the master, the sync source with drift, and W2's
  prediction check.
- `cargo run --release -p warlock-radio --example awdljoin -- [channel] [seconds] [width 20|40]`:
  joins the cluster as a follower. It sends PSFs and MIFs, follows the
  channel sequence, accepts Block Ack setup, ACKs unicast in hardware, answers
  ICMPv6 echo on our EUI-64 link-local address, and reports everything
  addressed to us.
- `cargo run --release -p warlock-radio --example awdlcap -- <out.pcapng> [ch1,ch2,…] [seconds] [dwell]`:
  radiotap pcapng for Wireshark and replay. Creating `<out.pcapng>.stop` ends
  it cleanly.

On the raw FFI (`devourer-sys`), for W0-style measurements:
- `cargo run --release --example hoptest -- [full|fast] [fastretune_fw] [ch,ch,…] [dwell_ms]`:
  per-hop call time, first frame and frame counts.
- `cargo run --release --example timerjitter -- [periods] [period_us]`.
- `cargo run --release --example txtest -- [channel] [burst] [rate_500kbps]`:
  proof-of-air via probe responses, plus a burst rate.
- `warlock-usb status|bind|release`.

## W0 measurements (2026-11-16, T3U on USB, Windows 11)

### Channel hops (`hoptest`; host-side call duration)

| Path | Within a band | Across bands |
|---|---|---|
| Firmware hop (`fastretune_fw = 1` / `2`) | ~3 ms (2.8–5.2) | ~9–10 ms (`=2`) |
| Software fast retune (`fastretune_fw = 0`) | 4–13 ms | falls back to the full path |
| Full retune (`SetMonitorChannel`) | — | 90–576 ms across two runs (first run ~90–100 ms into 5 GHz, ~255 ms into ch 6, a spur channel whose full set runs a notch calibration; a rerun with identical code gave 134–576 ms). Not on Warlock's hop path |

Warlock should run `fastretune_fw = 2`. Dead air on the radio is shorter than
the call; measuring it needs a known transmitter. Time to first received frame
after a hop mostly reflects each channel's traffic.

### Timer jitter (`timerjitter`)
High-resolution waitable timer aimed at absolute deadlines every 16.384 ms
(one AWDL availability window), 600 waits:

| mean | p50 | p90 | p99 | max |
|---|---|---|---|---|
| 285 µs | 276 µs | 486 µs | 582 µs | 947 µs |

No wait was more than 1 ms late, which is under one TU and inside AWDL's 3 TU
unicast guard. Waking ~0.6 ms early and spinning would tighten it further.

### Transmit while receiving (`txtest`)
- **On air, confirmed:** broadcast probe requests from a random MAC drew
  probe responses addressed to it: 15 from 3 APs on ch 44, 18 from 6 APs on
  ch 6, with the RX loop running.
- **Accept rate:** 300 small frames at 6 Mb/s in ~15 ms (worst call 0.32 ms);
  3,000 at 24 Mb/s in 237 ms (~12.6k frames/s, worst call 3.5 ms). That
  exceeds what the air can carry, so the chip buffers or drops. The true air
  rate needs an independent sniffer (to do).
- Receive continued during the saturating burst at a reduced rate
  (half-duplex).
- devourer's reported Jaguar2 TX+RX stall (~24 ms per frame) did not appear.
