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

- devourer is a git submodule (`third_party/devourer`, pinned), built by
  `build.rs` through the `cmake` crate. Only the 8822B backend is enabled.
- devourer's CMake requires `pkg_check_modules(libusb-1.0)`.
  `cmake/modules/FindPkgConfig.cmake` stands in for CMake's module and produces
  the `PkgConfig::libusb` target from the vendored `libusb1-sys` headers, so
  devourer isn't patched and no pkg-config binary is needed.
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
- **Cross-band retune bug:** after a full `SetMonitorChannel` from 2.4 GHz back
  to 5 GHz, receive stays dead. 5 → 2.4 GHz works. Next to try: firmware hops
  (`fastretune_fw = 2`) and re-applying TX power after band changes.
- **One silent channel-6 run** went quiet after its first second. It didn't
  reproduce in a 10 s rerun.
- Caveats from devourer's notes:
  - register reads occasionally fail with `LIBUSB_ERROR_PIPE` under load (retry);
  - transmit throughput with receive running is reportedly low on Jaguar2
    (still to measure);
  - the TSF resets at bring-up.

## Tools

- `cargo run --release --example rxsmoke -- [channel] [seconds] [log level]`:
  frame counts, AWDL peers, PSF/MIF tallies.
- `cargo run --release --example awdlcap -- <out.pcapng> [ch1,ch2,…] [seconds] [dwell]`:
  radiotap pcapng for Wireshark. Creating `<out.pcapng>.stop` ends it cleanly.
- `warlock-usb status|bind|release`.

## Still to measure for W0

- Sustained transmit rate with the RX loop running.
- Hop latency, firmware vs software.
- Windows high-resolution timer jitter at AWDL's 16 TU windows.
