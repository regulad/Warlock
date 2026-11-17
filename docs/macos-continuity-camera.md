# How macOS uses an iPhone as a microphone

Source: static analysis of macOS 27.0.1 (26A434, arm64e) binaries:
`ContinuityCaptureAudioPlugin.driver`, `/usr/libexec/ContinuityCaptureAgent`,
`/usr/libexec/rapportd`, and the `CMContinuityCaptureHost`, `Rapport` and
`AVConference` frameworks extracted from the dyld shared cache. Apple's
internal codename for Continuity Camera is "Wombat".

## The pieces

```
iPhone ──(AWDL / Wi-Fi / USB-NCM)── rapportd ── ContinuityCaptureAgent ──XPC──▶ CoreAudio HAL plug-in ──▶ "iPhone Mic"
          Rapport control                         CMContinuityCaptureHost          (ContinuityCaptureAudioPlugin)
          AVConference media
```

### The audio device
- `/System/Library/Audio/Plug-Ins/HAL/ContinuityCaptureAudioPlugin.driver` is a
  user-mode AudioServerPlugIn. It publishes a CoreAudio input device named
  "iPhone Mic".
- It receives PCM from the agent over XPC (Mach services
  `com.apple.continuitycaptureaudio.receiverhelper.xpc` and
  `…provider.xpc`) into a ring buffer, and fills gaps with silence.
- Its clock is a network clock kept in sync with the phone (TimeSync / gPTP
  classes, `CMContinuityCaptureTimeSyncClock`), with a configurable transport
  latency.
- It reports its transport as wired or wireless. CoreAudio has matching
  transport types `ContinuityCaptureWired` and `…Wireless`.

### The agent
- `/usr/libexec/ContinuityCaptureAgent` (launchd label
  `com.apple.cmio.ContinuityCaptureAgent`) is a CoreMediaIO extension.
- launchd starts it through a `com.apple.rapport.matching` event when Rapport
  discovers a `_rdlink._tcp` peer.
- It links `CMContinuityCaptureHost`, which has three transport families:
  - **Rapport RemoteDisplay** (`CMContinuityCaptureRapportClient`, using
    `RPRemoteDisplaySession` and `RPStreamServer`);
  - **Sidecar** (`CMContinuityCaptureSidecarClient`);
  - a **Network.framework** path with QUIC application services (strings
    `applicationServiceQUIC`, `applicationServiceQUICCoupledDevices`; Swift
    distributed actors over `NetworkActorSystem`).

### The media path
- Audio and video are AVConference streams (`CMContinuityCaptureAVCMediaStream`
  wraps `AVCAudioStream`; parameters are negotiated with
  `AVCMediaStreamNegotiator` blobs relayed over the control channel).
- AVConference supports SRTP; whether and how Continuity Capture keys it was not
  traced.
- In the audio device's "call" mode the host configures:
  - client codec type 16 and 4 channels;
  - a fixed jitter buffer (size 20, mode 2);
  - `ptime` derived from the device's audio block size.

  *Inferred:* AVConference's own tables map codec 16 to Opus 48 kHz. Not yet
  confirmed on the wire.

## Trust

- `CMContinuityCaptureDiscoverySession` flags hosts that are not signed in or
  have iCloud Keychain off (`RPErrorFlagsNotSignedIn`,
  `RPErrorFlagsKeychainOff`). For a Mac host, the iPhone must therefore be a
  same-account device.
- Rapport identity types (`RPIdentity-*`) include SameAccountDevice,
  SessionPaired, AdHocPaired, SharedTVUser, Family and Friend. Same-account
  identities are synced through iCloud Keychain and tied to IDS registration.
- Wired (USB) mode is IP over the iPhone's USB-NCM interface. It does not relax
  the same-account requirement.

## Guest pairing (the Apple TV path)

tvOS lets a non-owner iPhone pair as a camera/mic by scanning a QR code. The
macOS `rapportd` contains the host side of this in `RPRemoteDisplayDaemon`:

- **Only on Apple TV.** `-[RPRemoteDisplayDaemon
  _startPairingServerWithPassword:startReason:completion:]` returns "Platform
  does not support pairing" unless `GestaltGetDeviceClass() == 4`.
- **Pairing-info JSON keys** published by the pairing server: `_pi` (pairing
  ID), `_pinC` (PIN), `_pubID`, `_rdsr`.
- **AWDL only.** `_rdlink._tcp` Bonjour TXT keys include `rpBA` (Bluetooth
  address), `rpAD` (auth tag), `rpFl` (flags), `rpVr` (`715.2`) and `rpPI`. The
  pairing ID `rpPI` is only advertised on the AWDL Bonjour advertisement, and
  `_clientAWDLPairingSessionWithDevice:` only connects to a device whose `rpPI`
  matches the session pairing ID.
- A successful guest pairing creates a SessionPaired identity. A log line
  ("Preserving session paired identity for guest mic-only teardown") shows a
  mic-only guest mode exists.

So a Windows host imitating an Apple TV needs AWDL for this path. tvOS 27 also
has a second guest-mic path, Continuity Sing, covered in
[tvos-ios-continuity-sing.md](tvos-ios-continuity-sing.md).

## Rapport wire format (from public work, for reference)

The companion-link protocol is documented by pyatv:
- framing is a 1-byte type plus a 3-byte length;
- pair-setup is HAP-style SRP-6a (3072-bit, SHA-512) carried in TLV8;
- pair-verify uses X25519 with Ed25519 signatures;
- sessions are ChaCha20-Poly1305 with HKDF-derived keys;
- messages are OPACK dictionaries (`_i`, `_x`, `_t`, `_c` …).
