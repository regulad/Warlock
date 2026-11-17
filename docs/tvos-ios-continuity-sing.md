# tvOS 27 / iOS 27: the Continuity Sing guest-mic path

Source: static analysis of iOS 27.2.1 (24B156, iPhone17,1) and tvOS 27.2
(24K122, AppleTV14,1): their arm64e dyld shared caches plus standalone
binaries (`rapportd`, `TVMusic.app`, launchd plists).

## Getting the images

- **iOS:** the public restore IPSW from Apple's CDN (12.1 GB).
- **tvOS:** there is no public IPSW for Apple TV 4K. The full OTA comes from
  Apple's asset server:
  - `POST https://gdmf.apple.com/v2/assets`, with tvOS release audience
    `356d9da0-eee4-4c6c-bbe5-99b60eadddf0`, `ProductType` `AppleTV14,1` and
    `HWModelStr` `J255AP`;
  - the response is a JWS whose payload lists OTA assets, including each
    archive's `ArchiveDecryptionKey`;
  - the server's certificate chains to Apple's own roots, which Windows does
    not trust by default, so pin Apple Root CA, G2 and G3 explicitly.
- **Extraction:** `ipsw ota extract … --key-val <key>` and `ipsw extract --dyld`,
  run on a Mac. `ipsw class-dump` and `ipsw dyld disass` for analysis.

## Continuity Sing (Apple Music karaoke)

tvOS 27's Sing app lets guests use their iPhone as a microphone.
`ContinuitySing.framework` exists on both tvOS and iOS.

### The QR code
`-[CSPairingServer generateURL]` on tvOS builds:

```
ContinuitySing://connect?h=<MediaRemote local deviceUID>&pw=<PIN>
```

The PIN is the first 8 characters of a fresh `NSUUID` string
(`-[CSPairingServer createNewPassword]`). Internal builds can override it with
the `overridePairingCode` default.

### Pairing (Rapport companion link, PIN)
- **TV side** (`-[CSPairingServer activateWithCompletion:]`): `RPServer`
  with `serviceType` `com.apple.ContinuitySingPairing`, `passwordType` 7, and
  `controlFlags |= 0x40c`. Its show-password handler deliberately does
  nothing ("Password should be shown in a QR code").
- **iPhone side** (`CSPairingMessagingClient`):
  - `RPCompanionLinkClient` with `controlFlags |= 0x18000000240C`;
  - finds the TV by the QR's `h` (media-route identifier);
  - pairs with `_pairWithDevice:password:` (same service type, `passwordType` 7,
    PIN from `pw`).

### Session messages
After pairing, ContinuitySing request/event messages travel over the companion
link: handshake, client check-in, `enableMicRequest`, microphone volume up/down
and queries, reverb level/state, vocal level, queue updates, reactions,
avatars, attributions, group-session tokens and disconnect. A handshake
carries IDS identifier, session-pairing identifier, participant info, OS
version and protocol version.

### Bringing the microphone up (iPhone side)
- `CSShieldManager _bootstrapSingConfiguration:` sets the capture UI
  configuration to `micOnly = 1` and `clientDeviceModel = 2`.
- `CMContinuityCaptureRemoteServer`:
  - `_setupSingSessionWithMediaRouteIdentifier:remoteDisplayIdentifier:`
    launches the shield UI as "Music", mic-only;
  - `_checkMusicAccount:` requires an Apple Music profile and privacy
    acknowledgement;
  - `_endpointToMediaRemoteIdentifier:` sends
    `MRUpdateActiveSystemEndpointRequest(outputDeviceUID: <h>, reason: "connect continuity sing")`.
- The mic itself is requested through MediaRemote:
  `MPAVRoutingController getActiveRouteWithCompletion:` → the route's endpoint
  → `requestMicrophoneConnection:completion:` (MRP
  `MicrophoneConnectionRequest`/`Response`). On tvOS, `TVMusic.app` handles it.
- `mediaremoted` can carry MRP over AirPlay or over Rapport
  (`MRDRapportRemoteControlService`).

## Rapport flag tables

Decoded from the bit-indexed name tables in `rapportd`.

**RPControlFlags** (bit: name): 0 NoIPv6, 1 BLE, 2 iWiFi (infrastructure Wi-Fi), 3 AWDL,
4 NAN, 5 BTPipe, 6 ForceRPI, 7 PreferRPI, 8 ForceL2CAP, 9 OnDemand, 10 Guest,
11 SharedHome, 12 Family, 13 Paired, 14 PreSecured, 15 ForceBLE,
16 BLEScreenOff, 17 ForceAWDL, 18 ForceUSB, 19 MoreComing, 20 Friends,
21 NoiWiFi, 22 NoAWDL, 23 Cloud, 24 NonCellular, 25 NonExpensive,
26 AppSignIn, 27 HKResolved, 28 ForceCloud, 29 PreferAESGCM, 30 OPACKNoCopy,
31 PairingMode, 32 Fitness, 33 Proximity, 34 HHDevice, 35 AWDLGuestDiscovery,
36 FitnessPairing, 37 CompanionAuthentication, 38 LaunchInstance,
39 ForcePairing, 40 Ensemble, 41 NoL2CAP, 42 NoUSB, 43 SharedTVUser,
44 SessionPaired, 45 AdHocPaired, 46 PreferSessionPaired,
47 CreateSessionPaired, 48 AuthAWDLPairingMode, 49 MultiUser,
50 RecvSiriInfo, 51 NeedsCLinkScreenOff, 52 EnableInfraWiFiOnWatch,
53 AlwaysOn.

So the TV's `0x40c` is iWiFi + AWDL + Guest. The iPhone's `0x18000000240C` is
iWiFi + AWDL + Guest + Paired + SharedTVUser + SessionPaired.

**RPStatusFlags** (bit: name): 3 AWDL, 4 NAN, 5 Asleep, 6 Companion,
7 Personal, … 12 Guest, … 15 Paired, 16 TV, … 20 Cloud, … 24 USB, …
31 PairingMode, … 35 CommunalDevice, 36 SharedTVUser, 37 SessionPaired,
38 AdHocPaired, 39 AirDropUsable, … 44 InternetRelay.

**Identity types** (bit: name): 0 Self, 1 SameAccountDevices, 2 FamilyAccounts,
3 FamilyDevices, 4 FriendAccounts, 5 FriendDevices, 6 PairedAccounts,
7 PairedDevices, 8 SharedHomeDevice, 9 HomeKitOwner, 10 SharedTVUserDevices,
11 SessionPairedDevices, 12 TemporarySelf, 13 AdHocPairedDevices.

## Does the audio leg work over plain Wi-Fi?

| Step | Over infrastructure Wi-Fi? | Basis |
|---|---|---|
| QR → PIN pairing | Yes | both ends' control flags include iWiFi |
| Sing control messages | Yes | same companion-link client |
| MediaRemote endpoint and mic request | Likely | MRP runs over Rapport too |
| Capture audio session | **AWDL by design** | see below |

On the iPhone (`rapportd` 24B156), the iPhone remains the RemoteDisplay server:
- `-[RPRemoteDisplayDaemon _serverBonjourEnsureStarted]` publishes
  `_rdlink._tcp` on `_serverDirectLinkInterfaceIndex`. That returns the USB
  DirectLink interface, or `0xFFFFFFFF` (local-only) when none exists. So
  without a cable, the advertisement is only visible over AWDL.
- The `CUTCPServer` labelled `RDLink` (flags 9, up to 8 connections) is bound to
  `awdl0` only in a pairing mode, and otherwise has no interface binding.
- rapportd's RemoteDisplay client paths resolve identities with type flags
  `0xC02` (SameAccount, SharedTVUser, SessionPaired). The Wi-Fi path sets aside
  peers without an IDS device ID as "unresolved".

A Wi-Fi-only host would therefore have to reach that listener without Bonjour.
That's plausible but unproven, so the project follows Apple's design and
implements AWDL.
