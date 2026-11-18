# Wintun exception

Warlock is free software, licensed under the GNU General Public License,
version 2 only ([LICENSE.md](LICENSE.md)), with the following exception. It
is in the form the Free Software Foundation suggests for GPL-2.0 programs
that use a GPL-incompatible library.

Linking Warlock statically or dynamically with other modules is making a
combined work based on Warlock. Thus, the terms and conditions of the GNU
General Public License cover the whole combination.

In addition, as a special exception, the copyright holders of Warlock give
you permission to combine Warlock with Wintun, the library `wintun.dll` as
WireGuard LLC releases it at <https://www.wintun.net>, under WireGuard LLC's
licence for it. You may copy and distribute such a combination following the
terms of the GNU GPL for Warlock and of WireGuard LLC's licence for
`wintun.dll`.

Note that people who make modified versions of Warlock are not obligated to
grant this special exception for their modified versions; it is their choice
whether to do so. The GNU General Public License gives permission to release
a modified version without this exception; this exception also makes it
possible to release a modified version which carries forward this exception.

## Scope

- Warlock loads `wintun.dll` for its network adapter. It doesn't include it:
  it downloads WireGuard LLC's release at runtime (`crates/warlock-tun`).
- This exception covers Warlock's own code: the files of this repository
  outside `third_party/`, as far as they are licensed under the GPL version 2,
  alone or as one choice of a dual licence.
- It doesn't cover devourer (`third_party/devourer`), which Warlock includes
  under its own authors' GPL version 2 only, with no such exception.
- The files' SPDX headers name their licence alone (`GPL-2.0-only`). SPDX
  lists no exception for Wintun.
