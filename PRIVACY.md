# Warlock privacy policy

*Effective 21 November 2026. Publisher: Parker Wahle, regulad@regulad.xyz.*

Warlock gives Windows Apple Wireless Direct Link (AWDL), so that programs on this computer can reach Apple devices nearby. It comes as four programs: the Warlock service; `warlockctl`, its command-line tool; its Wireshark plugin; and its installer.

## What crosses the link stays between the devices

Warlock carries traffic between this computer and the Apple devices it talks to, over Wi-Fi directly between them. It doesn't keep that traffic or send it anywhere else. It records the radio's frames only when an administrator asks it to, to a file they choose.

## Diagnostics

To find and fix problems, Warlock's releases send crash reports and diagnostics (a build of Warlock from its source code sends none) to Sentry (Functional Software, Inc., sentry.io), a service that stores them on our behalf, in the United States:

- **Errors and crash reports:** what went wrong and where in Warlock's code, crashes in its Wi-Fi driver included, with the warnings that came before. From `warlockctl` and the Wireshark plugin, only what points at a fault in them or in Warlock: not Warlock not running, not being allowed to use it, or a request it turned down.
- **Usage statistics:** when the Warlock service starts and stops, and the requests programs make of it (which kind, how long they took and how they went); and each install, upgrade, repair or removal: its steps, how it ended, whether it showed its pages, and the options chosen.
- **This computer:** Warlock's version, the Windows version, the processor, the amount of memory, the model of its Wi-Fi adapter, its radio's state and channel, and whether its Bluetooth is on and has the features Warlock needs.

Warlock doesn't send names (yours, this computer's or those of the devices nearby), user, account or device IDs, network (MAC or IP) addresses, your adapters' serial numbers, or anything else that identifies you or your devices, and our diagnostics service is set not to store IP addresses. It does note roughly where each report came from (the city, region and country), which it works out from the connection before discarding the address.

This is used only to diagnose and improve Warlock. It isn't sold, shared for advertising, or combined with other data. Sentry keeps it for up to 90 days.

## Turning diagnostics off

Set the environment variable `DO_NOT_TRACK` to `1` (any value but empty, `0` or `false` will do), and a program that sees it sends nothing. Each reads its own environment:

- **The Warlock service** runs as a Windows service, so it reads only settings made for the whole computer: set `DO_NOT_TRACK` system-wide, for instance with `setx /M DO_NOT_TRACK 1` as an administrator, then restart the service. One set for your user account alone doesn't reach it.
- **`warlockctl` and the Wireshark plugin** see your account's settings too: `setx DO_NOT_TRACK 1` is enough for them.
- **The installer** reads what Windows Installer runs it with: set `DO_NOT_TRACK` system-wide before installing, and it sends nothing either.

Set system-wide, it turns off all four.

## Children

Warlock isn't directed at children and doesn't knowingly collect children's personal information.

## Contact

Questions: regulad@regulad.xyz.

## Changes

We'll update this page, and its effective date, if any of this changes.
