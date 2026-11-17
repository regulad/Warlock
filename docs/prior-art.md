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

## Bluetooth LE Continuity (waking AWDL)

| Source | Use |
|---|---|
| Stute et al., MobiCom 2018 and USENIX Security 2019 (above) | AirDrop turns AWDL on after a BLE advert carrying truncated contact hashes |
| [seemoo-lab/opendrop](https://github.com/seemoo-lab/opendrop) issue #30, "Triggering AWDL" | the AirDrop wake as a known, unimplemented limitation of OpenDrop |
| [furiousMAC/continuity](https://github.com/furiousMAC/continuity) | per-type message layouts (`messages/*.md`) and a Wireshark dissector for Continuity adverts |
| Martin et al., "Handoff All Your Privacy", PETS 2019; Celosia & Cunche, "Discontinued Privacy", PETS 2020 | Continuity message types and fields |

Nothing found ties the "AirPlay source" message (`0x0a`) to waking AirPlay
receivers, or decodes its iOS 27 form. Both came from our captures and the
iOS 27 binaries; see
[awdl-field-observations.md](awdl-field-observations.md#waking-awdl-over-bluetooth-le).

## Rust AWDL crates, and why Warlock implements its own (checked 2026-11-17)

| Crate | Label | Overlap | Decision |
|---|---|---|---|
| `owly-awdl` ([t4t5/owly](https://github.com/t4t5/owly), formerly omdrop-owl) | MIT | A sans-IO AWDL node: frames, sync, election, channel sequence, peer table, IPv6 data path. Most of W1–W3 | **Not used: its license situation is murky.** Warlock implements AWDL itself |
| `awdl-frame-parser` ([Frostie314159](https://github.com/Frostie314159/awdl-frame-parser)) | MIT OR Apache-2.0 | Reads and writes action frames and most TLVs. Most of W1 | Found only after `awdl-proto` was written and verified. Its provenance isn't vetted, and we keep `awdl-proto` |

**Why owly's license situation is murky.** The MIT label may not hold,
because the code looks derived from OWL, which is GPL-3.0-or-later. GPLv3
code can't be combined with GPL-2.0-only devourer, and Warlock can't move to
GPLv3 because of devourer. So depending on owly would risk Warlock's own
license. What we found:
- Owly began as a wrapper that built OWL's C and shipped patches to it. The
  Rust replaced that in a single commit (`2b8881c`, 38k lines). The crate's
  own docs call OWL's C "the reference for behaviour" and say "the layouts
  are OWL's".
- `owly-awdl`'s election code mirrors OWL's `election.c` closely: the same
  helper and assignment order, the same sequence of checks, OWL's constants,
  and paraphrased comments. Its TLV writers reproduce values from OWL's
  `tx.c` that OWL itself doesn't understand (sync flags `0x1800`, AP alignment
  set to the AW counter, data-path flags `0x8f24`).
- There's no clean-room statement, and OWL's authors aren't among the
  contributors, so the copyright holders haven't relicensed it.

Wire values Apple devices expect are facts, and any correct implementation
shares them. What makes owly look like a translation, rather than an
independent implementation, is that it mirrors choices the protocol doesn't
dictate, and that it describes itself as OWL-based. We treat it like OWL: a
source of facts and behaviour, never of code. Warlock's AWDL code is written
from the MobiCom paper, Wireshark's dissector (GPL-2.0-or-later, so
compatible) and our own captures, and each module cites its sources.

**For the AirDrop app** (AGPL-3.0-or-later), the question doesn't arise:
`owly-airdrop` is compatible there whether it's really MIT or GPLv3-derived.
It gets its own provenance check before use.

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
