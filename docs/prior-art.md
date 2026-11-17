# Prior art and references

## AWDL protocol

| Source | License | Use |
|---|---|---|
| Stute, Kreitschmann, Hollick, "One Billion Apples' Secret Sauce: Recipe for the Apple Wireless Direct Link Ad hoc Protocol", ACM MobiCom 2018 | paper | protocol reference (timing, election, TLVs) |
| Wireshark AWDL dissector, `epan/dissectors/packet-awdl.c` | GPL-2.0-or-later | layout reference for `awdl-proto` (each module names its dissector function) and its test oracle (`tests/tshark_oracle.rs`); our capture analysis tool |
| [seemoo-lab/owl](https://github.com/seemoo-lab/owl) (archived 2026-10) | GPL-3.0-or-later | reference only. Its code can't be copied into GPL-2.0-only Warlock, and it is Linux nl80211/libpcap glue around ~1.3k lines of protocol logic |
| [jedbillyb/owl](https://github.com/jedbillyb/owl), [jedbillyb/airdrop-mt7921](https://github.com/jedbillyb/airdrop-mt7921) | — | iOS 26 findings (reported by the project, see below) |
| Stute et al., "A Billion Open Interfaces for Eve and Mallory", USENIX Security 2019 | paper | AWDL security background |
| Stute et al., "Disrupting Continuity of Apple's Wireless Ecosystem Security", USENIX Security 2021 | paper | Rapport/Continuity authentication (Ed25519 pair-verify, `RPIdentity-*` keychain items) |

**Reported by jedbillyb's AirDrop-on-Linux work** (we haven't verified these):
- advertising a channel sequence that "pins" one channel in all 16 slots stops
  iOS 26 from sending unicast to you;
- copying the peer's sequence works, as does widening it without touching slot 0;
- slot indexing has to follow the master's phase;
- HT/VHT capabilities must match what you actually receive;
- iOS requests BlockAck on TID 0.

## Other Windows AWDL projects (checked 2026-11)

| Project | Radio approach | Notes |
|---|---|---|
| [raph559/winawdl](https://github.com/raph559/winawdl) | built-in RTL8852CE via devourer's Windows PCIe backend + a UMDF2 driver; OWL in a separate process; Wintun | AirDrop both ways; research code tested on one machine |
| [dantdmdarealguy/omdrop-owl-windows](https://github.com/dantdmdarealguy/omdrop-owl-windows) | ESP32-S3 over USB serial as the radio | 2.4 GHz channel 6 only |
| [Dy1an-Zou/Airdrop-for-Windows](https://github.com/Dy1an-Zou/Airdrop-for-Windows) | MT7925 with a test-signed driver | channel 6 only |
| [parsakhaz/open-airdrop-windows](https://github.com/parsakhaz/open-airdrop-windows) | reverse-engineering the stock MT7925 driver | raw TX not achieved |

Useful operational lessons reported by these projects:
- Give the virtual adapter only its EUI-64 link-local address, and remove
  Windows' random one.
- Drain the Wintun read event until empty; it is auto-reset.
- Windows TCP sends many ACKs; coalescing received segments helped throughput.
- Use high-resolution waitable timers.
- Accept zero padding after the last TLV.
- Rank election by metric before counter.

## Radio driver

- [OpenIPC/devourer](https://github.com/OpenIPC/devourer): user-space Realtek
  Wi-Fi driver over libusb. GPL-2.0-only, and includes Realtek GPL-2.0-only HAL
  code and firmware. This is why Warlock is GPL-2.0-only.
- Linux `rtw88` (`GPL-2.0 OR BSD-3-Clause`) is the fallback base if devourer
  ever has to be replaced.

## Apple stacks

- [pyatv](https://pyatv.dev/documentation/protocols/): Companion (Rapport)
  framing, pair-setup and pair-verify, OPACK.
- [apple-oss-distributions/mDNSResponder](https://github.com/apple-oss-distributions/mDNSResponder),
  tag `mDNSResponder-1310.140.1`, `mDNSMacOSX/D2D.c`: the D2D bridge between
  mDNSResponder and AWDL.
- Google's Quick Share ↔ AirDrop interoperability (Pixel, 2025–2026) shows that
  third-party AWDL/AirDrop interoperation is viable in practice.

## Driver binding (contrast)

- libwdi / Zadig bind WinUSB by generating an INF and catalog, self-signing it
  and installing a single-use root certificate. Warlock instead uses the in-box,
  Microsoft-signed `winusb.inf` (see [windows-bringup.md](windows-bringup.md)).

## Licensing notes

- **Warlock is GPL-2.0-only.** It links devourer (GPL-2.0-only) in-process.
- **Clients:** Koala and the AirDrop app are separate AGPL-3.0 programs that
  talk to Warlock over its local HTTP control API, defined by an OpenAPI
  contract (planned MIT). They link no Warlock code.
- **Wintun:** the prebuilt `wintun.dll` ships under its own binary license while
  its source is GPL-2.0. Bundling it next to GPL-2.0-only code is a gray area,
  so plan to have it fetched separately rather than bundled.
