# Warlock research notes

Warlock implements Apple Wireless Direct Link (AWDL) on Windows, so that
Windows software can talk to unmodified Apple devices the way they talk to each
other. These notes record what we have established so far: reverse engineering
of Apple's stacks, observations from live captures, and the Windows bring-up.
`../PLAN.md` holds the build plan; these documents hold the evidence behind it.

The motivating client is **Koala**, which makes an unmodified iPhone usable as a
Windows microphone by imitating the host side of Apple's Continuity Camera /
Continuity Sing. An AirDrop client is the second planned user.

| Document | What it covers |
|---|---|
| [macos-continuity-camera.md](macos-continuity-camera.md) | How macOS exposes an iPhone microphone: the HAL plug-in, ContinuityCaptureAgent, Rapport RemoteDisplay, the trust model, guest pairing, the media path |
| [tvos-ios-continuity-sing.md](tvos-ios-continuity-sing.md) | tvOS 27 / iOS 27 reverse engineering: acquiring the images, the Continuity Sing (karaoke) guest-mic path, Rapport flag tables, why the audio leg needs AWDL |
| [awdl-field-observations.md](awdl-field-observations.md) | What modern Apple devices actually put on the air: TLVs, versions, channel sequences, service records, AirDrop and AirPlay over AWDL |
| [service-discovery.md](service-discovery.md) | How DNS-SD works over AWDL (in-frame TLVs *and* real mDNS) and Warlock's resulting design |
| [windows-bringup.md](windows-bringup.md) | The TP-Link Archer T3U, binding it to WinUSB from code, building devourer, receive results, open issues, tools |
| [prior-art.md](prior-art.md) | Other projects and references, and how we use them |

## Status (2026-11-16)

- **Radio bring-up (W0):** done. The T3U runs from user space on Windows
  through devourer, bound to WinUSB by Warlock itself. It receives AWDL frames
  from nearby Apple devices with hardware timestamps, transmits while
  receiving, and hops channels in ~3 ms within a band and ~9–10 ms across
  (firmware hops). Windows timers are within 1 ms of target at AWDL's window
  period. A devourer cross-band retune bug is fixed by a carried patch.
- **Service discovery:** settled by captures. AWDL carries service records both
  inside its action frames and as ordinary multicast mDNS.
- **Open:** the true over-the-air transmit rate (needs an independent
  sniffer), and ~20 s bring-up time.

## Conventions

- *Confirmed* means seen on the wire or read directly from a binary. *Inferred*
  means derived from strings or control flow without a live test.
- Test hardware is described by model and OS version only. Device names,
  addresses and network identifiers from the captures are deliberately omitted.
- Apple binaries were examined with `ipsw` on a Mac and radare2; nothing from
  them is redistributed here.
