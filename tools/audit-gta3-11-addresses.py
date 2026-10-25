#!/usr/bin/env python3
"""Audit GTA III 1.0 translation call sites against a private 1.1 code dump.

This script never modifies game files. An E8 at the expected location is only
an opcode-shape check, NOT proof that the call still has the same semantics.
"""

from __future__ import annotations

import argparse
from bisect import bisect_left
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import re
import struct

TEXT_BASE = 0x401000
EXPECTED_TEXT_SIZE = 0x1F2770


@dataclass(frozen=True)
class Translation:
    line: int
    original: str
    target: int
    comment: str
    group: str
    is_call_site: bool


def translations_from_source(path: Path) -> list[Translation]:
    rows: list[Translation] = []
    group = "unknown"
    matcher = re.compile(r"^\s*map\[([^]]+)\]\s*=\s*(.*?);\s*(?://\s*(.*))?$")
    group_matcher = re.compile(r"^\s*//\s*(Core|std\.[\w.]+|traits|AbstractFrontend.*)$")
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        matched_group = group_matcher.match(line)
        if matched_group:
            group = matched_group.group(1)
        matched = matcher.match(line)
        if not matched:
            continue
        original, raw_target, comment = matched.groups()
        # Only real absolute code/data addresses can be audited here; omit
        # nullptr, C++ emulator functions and expression-based targets.
        if not re.fullmatch(r"0x[\da-fA-F]+", raw_target.strip()):
            continue
        comment = (comment or "").strip()
        rows.append(
            Translation(
                line=line_no,
                original=original,
                target=int(raw_target, 16),
                comment=comment,
                group=group,
                is_call_site=bool(re.match(r"call\b", comment, re.IGNORECASE)),
            )
        )
    return rows


def opcode_kind(text: bytes, address: int) -> str:
    offset = address - TEXT_BASE
    if not 0 <= offset < len(text):
        return "outside-text"
    if text[offset] == 0xE8:
        return "call-rel32"
    if text[offset : offset + 2] == b"\xff\x15":
        return "call-absolute"
    return f"other-{text[offset]:02X}"


def relative_call_target(text: bytes, address: int) -> int | None:
    offset = address - TEXT_BASE
    if not 0 <= offset < len(text) - 4 or text[offset] != 0xE8:
        return None
    return address + 5 + struct.unpack_from("<i", text, offset + 1)[0]


def sdk_mappings(root: Path) -> dict[int, set[int]]:
    """Read public plugin-sdk's 1.0 / 1.1 / Steam ADDRESS_BY_VERSION triplets.

    These are address facts only; third-party source is not copied into the mod.
    """
    mappings: dict[int, set[int]] = {}
    triple = re.compile(
        r"(?:GLOBAL_)?ADDRESS_BY_VERSION\(\s*"
        r"(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)\s*,\s*"
        r"(0x[0-9a-fA-F]+)\s*\)"
    )
    for path in (root / "plugin_III/game_III").rglob("*"):
        if path.suffix not in {".cpp", ".h", ".hpp"} or not path.is_file():
            continue
        for match in triple.finditer(path.read_text(encoding="utf-8", errors="replace")):
            original, _retail11, steam = (int(raw, 16) for raw in match.groups())
            mappings.setdefault(original, set()).add(steam)
    return mappings


def project_from_nearby_sdk_anchors(
    address: int, sdk: dict[int, set[int]], max_distance: int = 1024
) -> int | None:
    """Suggest (never verify) an offset when two nearby SDK anchors agree."""
    anchors = sorted(
        (original, next(iter(mapped)))
        for original, mapped in sdk.items()
        if len(mapped) == 1
        and TEXT_BASE <= original < TEXT_BASE + EXPECTED_TEXT_SIZE
        and TEXT_BASE <= next(iter(mapped)) < TEXT_BASE + EXPECTED_TEXT_SIZE
    )
    keys = [old for old, _new in anchors]
    index = bisect_left(keys, address)
    if index == 0 or index == len(anchors):
        return None
    left_old, left_new = anchors[index - 1]
    right_old, right_new = anchors[index]
    if address - left_old > max_distance or right_old - address > max_distance:
        return None
    left_delta, right_delta = left_new - left_old, right_new - right_old
    if left_delta != right_delta:
        return None
    return address + left_delta


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dump", type=Path, help="Private decrypted .text capture")
    parser.add_argument(
        "--table",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "src/translator/gta3/3/10.hpp",
        help="Existing GTA III 1.0 mapping source",
    )
    parser.add_argument("--window", type=int, default=12)
    parser.add_argument(
        "--sdk-root",
        type=Path,
        help="Optional checkout of DK22Pac/plugin-sdk (for independent 1.0 => Steam mappings)",
    )
    args = parser.parse_args()

    text = args.dump.read_bytes()
    if len(text) != EXPECTED_TEXT_SIZE:
        parser.error(
            f"Unexpected .text size: {len(text)} bytes; "
            f"this audit expects {EXPECTED_TEXT_SIZE} bytes"
        )
    table = translations_from_source(args.table)
    call_sites = [entry for entry in table if entry.is_call_site]
    checked = [entry for entry in call_sites if opcode_kind(text, entry.target).startswith("call-")]
    failures = [entry for entry in call_sites if entry not in checked]

    print(f"Parsed {len(table)} literal targets, including {len(call_sites)} call sites.")
    print(f"Expected-call opcode at original mapped address: {len(checked)}/{len(call_sites)}")
    print("Call site counts by section:", dict(Counter(entry.group for entry in call_sites)))
    print("Possible shifted call sites (candidates are not verified equivalents):")
    for entry in failures:
        nearby = [
            address
            for address in range(entry.target - args.window, entry.target + args.window + 1)
            if opcode_kind(text, address).startswith("call-")
        ]
        candidate_str = ", ".join(f"0x{addr:X} ({addr - entry.target:+d})" for addr in nearby)
        print(f"  line {entry.line:3d} {entry.group:12s} 0x{entry.target:08X} "
              f"[{opcode_kind(text, entry.target)}] => {candidate_str or 'none'} | {entry.comment}")

    # Individually inspected GTA III 1.1 Steam anchors, independent of 1.0.
    anchors = {
        0x5C7099: 0x582940,  # Startup WinMain call
        0x48E8FF: 0x48D5D0,  # Idle hook site
        0x48E911: 0x48BF40,  # Frontend idle hook site
        0x48BF61: 0x5A0D40,  # Texture loading call site
    }
    for address, expected_target in anchors.items():
        actual_target = relative_call_target(text, address)
        if actual_target != expected_target:
            print(f"FAIL anchor 0x{address:X}: expected 0x{expected_target:X}, got {actual_target!r}")
            return 2
    print(f"Verified {len(anchors)} explicitly inspected 1.1 call-site anchors.")
    if args.sdk_root:
        sdk = sdk_mappings(args.sdk_root)
        matched = [row for row in table if row.target in sdk]
        print(f"Plugin-SDK supplies Steam addresses for {len(matched)}/{len(table)} literal targets.")
        for row in matched:
            candidates = sdk[row.target]
            if len(candidates) != 1:
                print(f"  CONFLICT: 1.0 0x{row.target:X} => {sorted(candidates)}")
                continue
            steam_addr = next(iter(candidates))
            if row.is_call_site and not opcode_kind(text, steam_addr).startswith("call-"):
                print(f"  SDK MISMATCH: {row.group} 0x{row.target:X} => "
                      f"0x{steam_addr:X} [{opcode_kind(text, steam_addr)}]")
        proposed_calls = [
            (row, project_from_nearby_sdk_anchors(row.target, sdk))
            for row in call_sites if row.target not in sdk
        ]
        proposed_calls = [(row, addr) for row, addr in proposed_calls if addr is not None]
        shape_matches = [(row, addr) for row, addr in proposed_calls
                         if opcode_kind(text, addr).startswith("call-")]
        print(f"Nearby SDK anchors suggest {len(proposed_calls)} other call-site locations; "
              f"{len(shape_matches)} have a call opcode at the proposed address.")
        for row, addr in proposed_calls:
            if opcode_kind(text, addr).startswith("call-") and addr != row.target:
                print(f"  PROJECTION ONLY: {row.group} 0x{row.target:X} => "
                      f"0x{addr:X} ({addr-row.target:+d}) | {row.comment}")
    print("WARNING: No 1.1 address table has been validated; do not enable 1.1 hooks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
