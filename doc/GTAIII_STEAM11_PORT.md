# GTA III 1.1 Steam compatibility: reverse-mapping checklist

This is an **in-progress port**, not an implementation of GTA III 1.1 support.
The existing version rejection must stay in place until the translation table
and all patches have been validated against the target game.

## Known executable

- GTA III 1.1 Steam, x86 PE32, SHA-256
  `9b1ddafadee27dca2970159be497c9a851061711ec79ec319340a1a35c0daa28`.
- Steam-protected entry point: `0x009912ED` (image base `0x00400000`).
- `.text` RVA `0x1000`, virtual size `0x1F2770`.
- The on-disk `.text` contents are encrypted. Static disassembly of the file
  cannot establish the target functions' addresses.
- The existing injector detects GTA III 1.1 Steam, but
  `src/translator/translator.cpp` initializes GTA III's address map only for
  version 1.0. Consequently the WinMain address translation fails in
  `src/core/loader.cpp`, reporting that the game is unsupported.
- `src/translator/gta3/3/10.hpp` contains 171 `map[...]` entries for GTA III
  1.0. These cannot be copied blindly to version 1.1.

## Read-only code capture

To prepare an address map, the owner of the installed game can capture the
**code section only** after the game has started:

1. Temporarily disable `modloader.asi` so the unsupported-version dialog does
   not prevent GTA III from reaching its main menu.
2. Start the same Steam installation and wait at the main menu.
3. In a separate Windows PowerShell session, run
   `tools/capture-gta3-steam11-text.ps1`.
4. Send the ZIP printed by the script privately to the maintainer. **Do not
   push it, the game executable or memory captures to a public repository.**
5. Restore `modloader.asi` after the capture.

The collector is limited to a single identified executable hash and reads only
the `.text` pages (`ReadProcessMemory`, without writing or injecting). It
rejects a capture if the first sample of bytes still matches the encrypted
on-disk section. Its output must be checked before any address table is added.

## Porting and validation steps

1. Establish deterministic x86 code signatures for the 1.0 mappings.
2. Resolve 1.1 counterparts for all core and plugin addresses, distinguishing
   code, data, call sites and emulator stubs; do not assume a single delta.
3. Implement a separate `III_11` translation table for the exact validated
   build. Unsupported editions must continue to fail safely.
4. Validate hook opcodes and calling conventions before modifying executable
   memory. Unit-test address translation and absent-address behavior.
5. Build a 32-bit release and exercise the actual Steam game: startup,
   textures, streamed models, menu, game load, new game, shutdown, disabling
   mods and conflict behavior.

The current repository supports GTA III 1.0 and explicitly documents only that
version. Shipping 1.1 compatibility solely by bypassing `try_address` would
turn a safe diagnostic into a crash or memory corruption risk.
