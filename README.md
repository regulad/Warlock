# Warlock

Apple Wireless Direct Link (AWDL) for Windows, on a USB Wi-Fi adapter.

AWDL is the Wi-Fi link Apple devices use with each other directly, with no
access point: AirDrop, Continuity, AirPlay to nearby devices. Windows has no
AWDL. Warlock implements it in user space on a USB Wi-Fi stick and gives
Windows a network adapter for it, so Windows programs can reach unmodified
Apple devices nearby as those devices reach each other: over IPv6, with
services found by DNS-SD.

Warlock is a foundation: it carries the link, and the programs that speak
Apple's protocols over it come separately.

**Status: experimental (0.x).** It works with the hardware below and has been
tried with Macs, an iPhone and an Apple TV. Expect rough edges, and breaking
changes to the API between 0.y versions.

Warlock was built with the assistance of Claude Opus 5.5.

## What you need

- **Windows 11, x64.** Windows 10 may work but hasn't been tried.
- **A USB Wi-Fi adapter on Realtek's RTL8812BU or RTL8822BU**, given to
  Warlock. Warlock is built and tested with the
  [**TP-Link Archer T3U (v1)**](https://link.amazon/B00RQheqL).
  It also uses the other adapters with those chips that Linux's `rtw88` driver
  lists (`MODELS` in [`crates/warlock-usb`](crates/warlock-usb/src/lib.rs)),
  with a warning, since none of them has been tried.

  While Warlock is installed, it takes every supported adapter it sees away
  from Windows' Wi-Fi driver. Don't install it if such an adapter is your
  only Wi-Fi. Uninstalling gives the adapter back.
- **A Bluetooth LE adapter, switched on**: the PC's own, built in or a USB
  dongle, left to Windows. Apple devices come onto AWDL when a nearby device
  asks them to over Bluetooth LE, and Warlock asks from this adapter
  (`warlockctl request`, `POST /v1/request`). Koala needs that to reach an
  iPhone. The AWDL link runs without Bluetooth, but nothing can be asked for.

  Warlock reads each advert's address from the extended-advertising commands
  Windows sends the controller, so the controller needs Bluetooth 5's LE
  extended advertising. With an older one, Warlock can't learn the address
  (untried). Warlock is tested with a MediaTek adapter (USB `13d3:3608`).
- **The Microsoft Visual C++ v14 Redistributable (x64)**, as new as the
  release was built with. winget installs it with Warlock; the MSI on its own
  says when it's missing.

## Install

Download `Warlock-<version>-x64.msi` from
[Releases](https://github.com/regulad/Warlock/releases) and run it. It shows
the licences and asks where to install, and run again, offers to repair or
remove Warlock. The packages are signed.

Once Warlock is in winget, `winget install Regulad.Warlock` will install it
and the Visual C++ runtime together.

The installer adds:

- the **Warlock** service, which starts with Windows and runs whether or not
  the adapter is plugged in;
- `warlock.exe` and `warlockctl.exe` in `C:\Program Files\Warlock`, which joins
  the system `PATH`;
- two groups (Administrators may always do what either allows):
  - **`warlock-users`**, whose members may use Warlock's control API;
  - **`warlock-admin`**, whose members may also capture the radio's frames.
    A capture hears every device nearby, and Warlock's traffic for every
    user of the PC, so it takes this second group.

  The installer's Options page can add you to either ("Add me to
  warlock-users", "Add me to warlock-admin"; a silent install:
  `JOINWARLOCKUSERS=1`, `JOINWARLOCKADMIN=1`). A group counts from your next
  sign-in, so the installer then offers to sign you out. A box shows ticked
  and greyed out when you're already a member.

## Use

Plug the adapter in. Within about ten seconds, Warlock has bound it to WinUSB,
brought the radio up, and connected the **Warlock AWDL** network adapter. It
then takes part in AWDL: it follows the cluster nearby Apple devices form, or
leads one of its own when there is none.

- **Reaching a peer:** every AWDL peer has an IPv6 link-local address made from
  its AWDL address. `ping -6 fe80::…%<index>` reaches it, where `<index>` is
  the Warlock AWDL adapter's interface index (`warlockctl info`).
- **Finding services:** Warlock writes the services its peers announce onto
  the adapter as mDNS, so Windows' own DNS-SD browsing finds them.
- **Offering services:** a program registers its service with Windows' DNS-SD
  on the adapter, and asks Warlock to advertise that type in its AWDL frames,
  where Apple devices look first.

`warlockctl` shows and steers what Warlock is doing:

```text
warlockctl info                  the adapter, the radio, Bluetooth and the cluster
warlockctl peers                 the Apple devices Warlock hears
warlockctl peer ADDRESS          one of them, with its services
warlockctl events                what happens, as it happens
warlockctl advertise TYPE        advertise a service type (e.g. _x._tcp) until Ctrl+C
warlockctl hold REASON           keep AWDL up until Ctrl+C
warlockctl realtime ADDRESS      run a realtime group with a peer until Ctrl+C (experimental)
warlockctl request TYPE          ask nearby devices to bring a service (e.g. _rdlink._tcp) up on AWDL
                                 until Ctrl+C, over this computer's Bluetooth (experimental)
warlockctl advertising | holds | realtime | request
                                 who is advertising, holding, running or asking for what
warlockctl capture -w FILE       the radio's 802.11 frames as pcapng until Ctrl+C
```

For packets, Wireshark captures on the Warlock AWDL adapter. For the frames
underneath, including those Warlock doesn't deliver to Windows, the installer
can add **Warlock radio (802.11)** to Wireshark's capture interfaces. Tick
"Also install the Wireshark plugin" on its Options page; it's greyed out when
Wireshark isn't installed. A silent install adds it with `WIRESHARKPLUGIN=1`.
Its options pick peers, AWDL or other frames, and Warlock's own. Without the
plugin, `warlockctl capture [--peer MAC]... [--kind awdl|other|all] [--tx]`
writes the same pcapng, to open in Wireshark or pipe in live:
`warlockctl capture -w - | wireshark -k -i -`. The radio hears every device
nearby, so a capture holds other devices' addresses and host names too.

To use `warlockctl` without elevation, be in `warlock-users`; to capture,
with `warlockctl capture` or the plugin, be in `warlock-admin`. Tick the
installer's boxes, or run `net localgroup warlock-admin <you> /add` (or
`warlock-users`) as Administrator, then sign in again.

Programs control Warlock the same way, through a local HTTP API on two named
pipes, each with its own contract:

- `\\.\pipe\warlock` ([`api/openapi.yaml`](api/openapi.yaml)): Warlock, its
  peers, advertising, holds and events, for `warlock-users` and
  `warlock-admin`;
- `\\.\pipe\warlock-admin` ([`api/admin.yaml`](api/admin.yaml)): captures,
  for `warlock-admin` only.

Windows enforces who may open each pipe, by its access list.
[`crates/warlock-client`](crates/warlock-client) is a Rust client for both.

Warlock logs to the Windows Event Log: in Event Viewer, *Applications and
Services Logs → Regulad → Warlock → Operational*; from a shell,
`Get-WinEvent -LogName Regulad-Warlock/Operational`. Windows caps the log at
16 MB. The same events are an ETW provider, `Regulad-Warlock`, for tracing
tools.

## Privacy

- Warlock's AWDL address is random, and new each time the service starts.
- **Its AWDL host name is this PC's Windows computer name**, and every nearby
  Apple device can read it. Apple devices use a random name instead.

  This is a known limitation of Windows' mDNS stack: it answers address
  queries for the computer name only, even for a service that registers
  another host name with an address. So that is the name services on the
  Warlock adapter can be reached by, and Windows announces it there itself,
  as on any network it joins.

  Windows' default computer names (`DESKTOP-` and random letters) say nothing
  about you. If you've renamed your PC to something that does, consider
  renaming it back (Settings → System → About → Rename this PC).
- **Warlock sends crash reports and diagnostics to Sentry**, without anything
  that identifies you, this computer or the devices nearby:
  [`PRIVACY.md`](PRIVACY.md) says what, and the installer puts it beside
  Warlock. To turn them off, set `DO_NOT_TRACK` for the whole computer, not
  just your account, since the service only sees system-wide settings, then
  restart it:

  ```text
  setx /M DO_NOT_TRACK 1
  ```

## Build

You need Rust (stable), Visual Studio's C++ build tools and CMake.

```text
git clone https://github.com/regulad/Warlock
cd Warlock
git submodule update --init
cargo build --release
cargo test --workspace
```

Fetch the submodules only, not recursively: devourer's own are reference
drivers Warlock doesn't build, and one of them pins a commit its repository no
longer has; sentry-native's are crash backends Warlock doesn't build either.

`warlock run`, as Administrator, runs Warlock in the foreground instead of as
a service. `cargo run -p warlock-msi` builds the MSI (see
[its docs](crates/warlock-msi/src/main.rs)). Windows' Smart App Control, where
it's on, blocks unsigned builds; releases are signed in GitHub Actions
([`.github/workflows/build.yml`](.github/workflows/build.yml)).

The pre-commit hooks ([`.pre-commit-config.yaml`](.pre-commit-config.yaml))
run rustfmt, Clippy, cargo-deny, clang-format and the API contracts' lint.

## Documentation

- [`PLAN.md`](PLAN.md): the design, the decisions and why, and where each part
  stands.
- [`docs/`](docs/README.md): the research behind it, from captures of Apple
  devices on the air to the Windows bring-up.

## Licence

Warlock is free software:

- **GPL-2.0-only** ([`LICENSE.md`](LICENSE.md)) for Warlock itself, matching
  [devourer](https://github.com/OpenIPC/devourer), the user-space Realtek
  driver it builds in.
- **GPL-2.0-only OR AGPL-3.0-or-later**, at your choice, for the API contracts
  and `warlock-client`, so programs under either licence can use them.
- **AGPL-3.0-only** ([`LICENSE-AGPL-3.0.md`](LICENSE-AGPL-3.0.md)) for
  `warlockctl`.

Warlock doesn't include [Wintun](https://www.wintun.net), the driver behind its
network adapter. It downloads the release it was built against from
wintun.net on first start, checks it against pinned hashes, and loads it,
under WireGuard LLC's own licence for it. Warlock's own code permits that
combination with an exception to its GPL
([`LICENSE-WINTUN-EXCEPTION.md`](LICENSE-WINTUN-EXCEPTION.md)).

Warlock is not affiliated with Apple. AWDL, AirDrop, AirPlay and Continuity
are Apple's.
