# AGENTS.md

Conventions for anyone, person or agent, changing Warlock. `PLAN.md` holds the
design and its decisions; this file holds the rules that apply to every change.

## Describe Warlock truthfully to its peers

Every capability, flag, version and parameter Warlock sends to another device
must say what Warlock actually does, on the radio it actually has. That covers
AWDL TLVs (HT and VHT capabilities, the data path state's flags, sync and
election parameters, the version), Block Ack responses, and anything sent later
in a handshake.

**Why:** a peer adapts to what we claim. Described accurately, Apple devices
work around what Warlock can't do, with no configuration on either side.
Described wrongly, they rely on something Warlock doesn't do, and fail quietly.
Warlock's Block Ack responses echoed the iPhone's "A-MSDU allowed" while
`awdl-proto` dropped every A-MSDU, so the iPhone's aggregated Rapport TCP
arrived only by retransmission (Koala's trial 19, 2026-11-19; Parker: "we need
to avoid that as much as possible").

**How:**
- **Derive, don't copy.** Compute a value from Warlock's real state: the
  radio's width, the features implemented, the channels it can tune. Don't
  take a value from a captured Apple device, and don't echo a peer's request,
  unless Warlock does what it says.
- **Unknown means off.** If a bit or field's meaning isn't known, don't set
  it. Where a peer demonstrably needs a value whose meaning is unknown, keep
  it, and say in a comment where it came from and that it's unverified.
- **Under-claim rather than over-claim**, but treat under-claiming as a gap
  to close: an honest "can't" costs performance, a false "can" costs
  correctness.
- **If a peer needs a capability Warlock lacks, implement it;** don't
  advertise it first. Experiments that send another device's values go
  through `TxConfig::tlv_overrides` and are never the default.
- **Comment the evidence.** Each advertised value says in a comment why it's
  true, citing the code or measurement that backs it.
- **Identity claims** (the AWDL version and device class), which Warlock may
  have to make to be accepted at all, are the exception to argue in
  `PLAN.md`, not by default.

## Track pending work in GitHub issues

Pending work goes into issues on
[regulad/Warlock](https://github.com/regulad/Warlock/issues) where it can, one
task per issue, so several people can take tasks at once (Parker,
2026-11-19). `PLAN.md` keeps the design, the decisions and what was found, and
links the issues; it isn't the to-do list.

- A commit that completes an issue says so (`Fixes #N`).
- An issue, pull request or comment an agent drafts is posted only after
  Parker has reviewed it, and ends with a rule and his footer:
  `*Drafted by Claude (`claude-opus-5-5`); reviewed and signed off by
  @regulad.*`, naming the model that drafted it.

## Show drafts in quote blocks

When showing Parker a snippet of code, formatted data, or prose drafted for
submission (an issue, a commit message, release notes, a pull request, a
comment), put each in its own Markdown quote block, so what would be
submitted stands apart from the conversation around it (Parker, 2026-11-19).
