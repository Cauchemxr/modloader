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
- A privately captured runtime `.text` image has now been supplied (SHA-256
  `ec25e220f2d533ff9294e551adc397c7b8681e7dbb44e96999b397ccd5f148d7`).
  It is 2,041,712 bytes and contains valid x86 instructions. **This dump must
  not be stored in Git.**
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

To audit direct-call opcode locations in the private runtime capture:

```sh
python3 tools/audit-gta3-11-addresses.py /path/to/private-gta3-text.bin
```

If an independent `DK22Pac/plugin-sdk` checkout is available, additionally use
`--sdk-root /path/to/plugin-sdk` to compare documented 1.0 and Steam addresses.
That repository is only an optional external reference; do not vendor it or
assume its symbol mappings cover every Mod Loader patch site.

To save a per-address review queue (without any captured game code), run:

```sh
python3 tools/audit-gta3-11-addresses.py /path/to/private-gta3-text.bin \
  --sdk-root /path/to/plugin-sdk \
  --csv-report /path/to/local-address-audit.csv
```

The CSV explicitly labels direct SDK mappings, SDK metadata cross-references,
containing-function matches, and weaker neighboring-address projections.
It is **not** a ready-to-compile translation table.

The private dump audit found 88 annotated call sites, of which only 41 still
contain a call opcode at their original 1.0 address. The independent plugin-sdk
provides Steam equivalents for 21 of 156 simple literal targets, plus 10 more
via aligned references to their containing functions.

The SDK also explicitly pairs 41 of the annotated 1.0 call sites with Steam
call sites. Decoding the runtime call destinations agrees with SDK function
entry points for **39 of those 41**. Two still require manual review; one
has a call destination outside GTA III's `.text` range in the provided live
snapshot, so simply checking for opcode `E8` is insufficient.

The conservative CSV classifications currently break down as:

| Evidence category | Entries |
| --- | ---: |
| SDK cross-reference with matching destination | 39 |
| Independently inspected call with matching destination | 4 |
| Other explicit SDK address mapping | 21 |
| SDK containing-function mapping | 10 |
| SDK cross-reference needing manual review | 2 |
| SDK-neighbor projection with call opcode only | 17 |
| SDK-neighbor projection of non-call position | 5 |
| Unchanged location with call opcode only | 17 |
| Unresolved | 41 |
| **Total audited literal targets** | **156** |

These counts describe independent static evidence only. The stronger address
correspondences still need per-plugin patch-site and calling-convention review.
The many projection-only and unresolved entries mean **Steam 1.1 execution
support must remain disabled**.

**Important:** the SDK-neighbor estimator proposed *wrong* locations for
`Idle` and `FrontendIdle` despite finding valid call opcodes there. Their
independently verified call sites are `0x48E8FF` and `0x48E911`, respectively.
The audit now gives the four independently inspected anchors precedence over
every heuristic. Never treat a nearby call opcode alone as evidence of a safe
patch site.

This identifies places where a 1.0 `call` address no longer points to a call
instruction and lists nearby candidates. The tool verifies four independently
inspected 1.1 call-site anchors. **Opcode matching does not imply compatible
semantics or permission to apply a hook**; each candidate still needs review.

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
