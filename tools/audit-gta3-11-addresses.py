#!/usr/bin/env python3
"""Audit GTA III 1.0 translation call sites against a private 1.1 code dump.

This script never modifies game files. An E8 at the expected location is only
an opcode-shape check, NOT proof that the call still has the same semantics.
"""

from __future__ import annotations

import argparse
from bisect import bisect_left
from collections import Counter
import csv
from dataclasses import dataclass
from pathlib import Path
import re
import subprocess
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
    """Read public plugin-sdk's 1.0 / 1.1 / Steam function/address triplets.

    These are address facts only; third-party source is not copied into the mod.
    """
    mappings: dict[int, set[int]] = {}
    triple = re.compile(
        r"(?:GLOBAL_)?ADDRESS_BY_VERSION\(\s*"
        r"(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)\s*,\s*"
        r"(0x[0-9a-fA-F]+)\s*\)"
    )
    meta_triple = re.compile(
        r"\bMvAddresses<\s*(0x[0-9a-fA-F]+)\s*,\s*"
        r"(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)\s*>"
    )
    for path in (root / "plugin_III/game_III").rglob("*"):
        if path.suffix not in {".cpp", ".h", ".hpp"} or not path.is_file():
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        for pattern in (triple, meta_triple):
            for match in pattern.finditer(content):
                original, _retail11, steam = (int(raw, 16) for raw in match.groups())
                if original and steam:
                    mappings.setdefault(original, set()).add(steam)
    return mappings


def sdk_function_targets(root: Path) -> dict[str, set[int]]:
    """Resolve SDK method names to Steam entry points, where documented."""
    functions: dict[str, set[int]] = {}
    triple = re.compile(
        r"\b(?:g?addrof|ctor_addr|dtor_addr)\(([^)]+)\)\s*=\s*"
        r"(?:GLOBAL_)?ADDRESS_BY_VERSION\(\s*(0x[0-9a-fA-F]+)\s*,\s*"
        r"(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)\s*\)"
    )
    for path in (root / "plugin_III/game_III").rglob("*"):
        if path.suffix not in {".cpp", ".h", ".hpp"} or not path.is_file():
            continue
        for match in triple.finditer(path.read_text(encoding="utf-8", errors="replace")):
            name = match.group(1).strip()
            functions.setdefault(name, set()).add(int(match.group(4), 16))
    return functions


def sdk_meta_reference_mappings(root: Path) -> dict[int, set[int]]:
    """Map code references using plugin-sdk's 1.0 and Steam RefList order.

    Only accept matching reference counts within the same method metadata;
    a missing/extra call would invalidate positional matching.
    """
    mapped: dict[int, set[int]] = {}
    ref_list = re.compile(r"\busing refs_t\s*=\s*RefList<([^>]+)>;", re.DOTALL)
    for path in (root / "plugin_III/game_III/meta").rglob("*.h"):
        content = path.read_text(encoding="utf-8", errors="replace")
        for match in ref_list.finditer(content):
            values = [part.strip() for part in match.group(1).split(",")]
            if len(values) % 5:
                continue
            refs: dict[int, list[int]] = {100: [], 110: [], 120: []}
            for i in range(0, len(values), 5):
                address_text, version_text = values[i : i + 2]
                if not re.fullmatch(r"0x[0-9a-fA-F]+", address_text):
                    continue
                if version_text not in {"100", "110", "120"}:
                    continue
                refs[int(version_text)].append(int(address_text, 16))
            if not refs[100] or len(refs[100]) != len(refs[120]):
                continue
            for old, steam in zip(refs[100], refs[120]):
                mapped.setdefault(old, set()).add(steam)
    return mapped


def sdk_meta_owner_mappings(root: Path) -> dict[int, set[int]]:
    """Extract containing-function entry addresses aligned across SDK versions.

    Each RefList tuple ends with a function start and reference index. When
    equal-length 1.0 and Steam lists align, those containing function starts
    provide another independent address mapping.
    """
    mapped: dict[int, set[int]] = {}
    ref_list = re.compile(r"\busing refs_t\s*=\s*RefList<([^>]+)>;", re.DOTALL)
    for path in (root / "plugin_III/game_III/meta").rglob("*.h"):
        content = path.read_text(encoding="utf-8", errors="replace")
        for match in ref_list.finditer(content):
            values = [part.strip() for part in match.group(1).split(",")]
            if len(values) % 5:
                continue
            refs: dict[int, list[tuple[int, int]]] = {100: [], 120: []}
            for i in range(0, len(values), 5):
                _address, version, _kind, owner, index = values[i:i+5]
                if version not in {"100", "120"} or not re.fullmatch(r"0x[0-9a-fA-F]+", owner):
                    continue
                if not index.isdecimal():
                    continue
                refs[int(version)].append((int(owner, 16), int(index)))
            if not refs[100] or len(refs[100]) != len(refs[120]):
                continue
            for (old_owner, old_index), (steam_owner, steam_index) in zip(refs[100], refs[120]):
                if old_index == steam_index and old_owner and steam_owner:
                    mapped.setdefault(old_owner, set()).add(steam_owner)
    return mapped


def merge_mappings(*groups: dict[int, set[int]]) -> dict[int, set[int]]:
    combined: dict[int, set[int]] = {}
    for group in groups:
        for key, values in group.items():
            combined.setdefault(key, set()).update(values)
    return combined


def sdk_meta_reference_targets(root: Path) -> dict[tuple[int, int], set[int]]:
    """Read Steam function targets alongside 1.0 -> Steam reference pairs.

    A call opcode alone could target the wrong function. The containing
    META_BEGIN block provides an independent destination for a direct call.
    """
    expected: dict[tuple[int, int], set[int]] = {}
    block_pattern = re.compile(r"META_BEGIN\(([^)]+)\)(.*?)META_END", re.DOTALL)
    addresses_pattern = re.compile(r"\busing mv_addresses_t\s*=\s*MvAddresses<([^>]+)>;")
    refs_pattern = re.compile(r"\busing refs_t\s*=\s*RefList<([^>]+)>;", re.DOTALL)
    for path in (root / "plugin_III/game_III/meta").rglob("*.h"):
        content = path.read_text(encoding="utf-8", errors="replace")
        for block in block_pattern.finditer(content):
            method, body = block.groups()
            addresses = addresses_pattern.search(body)
            refs_match = refs_pattern.search(body)
            if not addresses or not refs_match:
                continue
            targets = [part.strip() for part in addresses.group(1).split(",")]
            if len(targets) != 3 or not re.fullmatch(r"0x[0-9a-fA-F]+", targets[2]):
                continue
            steam_function = int(targets[2], 16)
            values = [part.strip() for part in refs_match.group(1).split(",")]
            if len(values) % 5:
                continue
            refs: dict[int, list[int]] = {100: [], 120: []}
            for index in range(0, len(values), 5):
                address_text, version_text = values[index : index + 2]
                if version_text not in {"100", "120"}:
                    continue
                if not re.fullmatch(r"0x[0-9a-fA-F]+", address_text):
                    continue
                refs[int(version_text)].append(int(address_text, 16))
            if not refs[100] or len(refs[100]) != len(refs[120]):
                continue
            for old, steam in zip(refs[100], refs[120]):
                expected.setdefault((old, steam), set()).add(steam_function)
    return expected


def demangled_method(comment: str) -> str | None:
    matched = re.search(r"(_Z[\w]+)", comment)
    if not matched:
        return None
    result = subprocess.run(
        ["c++filt", matched.group(1)], capture_output=True, text=True, check=True
    ).stdout.strip()
    if "(" not in result:
        return None
    return result.split("(", 1)[0]


def matching_calls_near(text: bytes, location: int, function_addr: int, span: int = 128) -> list[int]:
    return [
        addr for addr in range(location - span, location + span + 1)
        if relative_call_target(text, addr) == function_addr
    ]


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


def classify_mapping(
    row: Translation,
    text: bytes,
    sdk: dict[int, set[int]],
    owner_addresses: dict[int, set[int]],
    all_anchors: dict[int, set[int]],
    xrefs: dict[int, set[int]],
    meta_targets: dict[tuple[int, int], set[int]],
    methods: dict[str, set[int]],
) -> tuple[int | None, str, str]:
    """Classify independent evidence without silently elevating a guess."""
    if row.is_call_site and row.target in xrefs:
        equivalents = xrefs[row.target]
        if len(equivalents) != 1:
            return None, "sdk-xref-ambiguous", "Multiple SDK metadata equivalents"
        candidate = next(iter(equivalents))
        actual = relative_call_target(text, candidate)
        expected = meta_targets.get((row.target, candidate), set())
        if actual is not None and actual in expected:
            return candidate, "sdk-xref-target-match", f"Call destination 0x{actual:X}"
        return candidate, "sdk-xref-needs-review", (
            f"Call destination {hex(actual) if actual is not None else 'not-direct'}; "
            f"SDK targets {','.join(hex(value) for value in sorted(expected)) or 'unlisted'}"
        )

    explicit = sdk.get(row.target)
    if explicit and len(explicit) == 1:
        candidate = next(iter(explicit))
        if row.is_call_site:
            call_target = relative_call_target(text, candidate)
            return candidate, (
                "sdk-direct-call-opcode" if opcode_kind(text, candidate).startswith("call-")
                else "sdk-direct-needs-review"
            ), f"Decoded destination {hex(call_target) if call_target is not None else 'unknown'}"
        return candidate, "sdk-direct-address", "1.0/Steam address triple"

    owner = owner_addresses.get(row.target)
    if owner:
        if len(owner) != 1:
            return None, "sdk-owner-ambiguous", "Multiple containing-function equivalents"
        candidate = next(iter(owner))
        return candidate, "sdk-derived-function-entry", "Aligned owning functions in SDK metadata"

    if row.is_call_site:
        method = demangled_method(row.comment)
        method_targets = methods.get(method or "", set())
        if len(method_targets) == 1:
            target = next(iter(method_targets))
            start = project_from_nearby_sdk_anchors(row.target, all_anchors) or row.target
            candidates = matching_calls_near(text, start, target)
            if len(candidates) == 1:
                return candidates[0], "sdk-function-target-unique-nearby", (
                    f"Calls {method} at 0x{target:X}"
                )
            if len(candidates) > 1:
                return None, "sdk-function-target-ambiguous", (
                    f"Multiple calls to {method}: {','.join(hex(addr) for addr in candidates)}"
                )

    projected = project_from_nearby_sdk_anchors(row.target, all_anchors)
    if projected is not None:
        if row.is_call_site:
            if opcode_kind(text, projected).startswith("call-"):
                return projected, "neighbor-projection-call-opcode-only", "Function not verified"
            return projected, "neighbor-projection-needs-review", "No call opcode"
        return projected, "neighbor-projection-only", "Data/code position not verified"

    if row.is_call_site and opcode_kind(text, row.target).startswith("call-"):
        return row.target, "unchanged-call-opcode-only", "Function not verified"
    return None, "unresolved", "No supported mapping evidence"


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
    parser.add_argument(
        "--csv-report",
        type=Path,
        help="Optional CSV of every mapped 1.0 address, with evidence tier for manual review",
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
        sdk_direct = sdk_mappings(args.sdk_root)
        sdk_owners = sdk_meta_owner_mappings(args.sdk_root)
        sdk = merge_mappings(sdk_direct, sdk_owners)
        xrefs = sdk_meta_reference_mappings(args.sdk_root)
        meta_targets = sdk_meta_reference_targets(args.sdk_root)
        matched = [row for row in table if row.target in sdk_direct]
        owners_found = [row for row in table if row.target in sdk_owners and row.target not in sdk_direct]
        print(f"Plugin-SDK supplies explicit Steam addresses for {len(matched)}/{len(table)} "
              f"literal targets, plus {len(owners_found)} containing-function mappings.")
        direct_xrefs = [row for row in call_sites if row.target in xrefs]
        valid_xrefs = [row for row in direct_xrefs if len(xrefs[row.target]) == 1 and
                       opcode_kind(text, next(iter(xrefs[row.target]))).startswith("call-")]
        print(f"SDK method metadata explicitly maps {len(direct_xrefs)}/{len(call_sites)} "
              f"call-site references; {len(valid_xrefs)} target call opcodes.")
        verified_destinations = 0
        mismatched_destinations = []
        for row in direct_xrefs:
            mapped = xrefs[row.target]
            if len(mapped) != 1:
                continue
            steam = next(iter(mapped))
            actual = relative_call_target(text, steam)
            expected = meta_targets.get((row.target, steam), set())
            if actual is not None and actual in expected:
                verified_destinations += 1
            elif expected:
                mismatched_destinations.append((row, steam, actual, expected))
        print(f"SDK call-site references with matching decoded destination: "
              f"{verified_destinations}/{len(direct_xrefs)}.")
        for row, steam, actual, expected in mismatched_destinations:
            print(f"  XREF DESTINATION MISMATCH: 0x{row.target:X} -> 0x{steam:X}; "
                  f"decoded={actual!r} SDK={sorted(expected)}")
        for row in direct_xrefs:
            mapped = xrefs[row.target]
            if len(mapped) != 1 or not opcode_kind(text, next(iter(mapped))).startswith("call-"):
                print(f"  XREF CONFLICT: 1.0 0x{row.target:X} => {sorted(mapped)}")
        all_projections = [
            row for row in table if row.target not in sdk
            and project_from_nearby_sdk_anchors(row.target, sdk) is not None
        ]
        print(f"Concordant SDK neighbors suggest another {len(all_projections)}/{len(table)} "
              "literal target addresses (not validated).")
        for row in matched:
            candidates = sdk_direct[row.target]
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
        methods = sdk_function_targets(args.sdk_root)
        crossrefs = []
        for row in call_sites:
            method = demangled_method(row.comment)
            targets = methods.get(method or "", set())
            if len(targets) != 1:
                continue
            steam_function = next(iter(targets))
            guessed = sdk[row.target] if row.target in sdk else set()
            candidate_addr = (next(iter(guessed)) if len(guessed) == 1 else
                              project_from_nearby_sdk_anchors(row.target, sdk) or row.target)
            calls = matching_calls_near(text, candidate_addr, steam_function)
            if calls:
                crossrefs.append((row, method, steam_function, calls))
        print(f"Resolved {len(crossrefs)} annotated call sites by their actual "
              "Steam function destination (SDK cross-reference).")
        for row, method, target, calls in crossrefs:
            print(f"  TARGET-MATCH: {row.group} 0x{row.target:X} -> "
                  f"{', '.join(f'0x{addr:X}' for addr in calls)} "
                  f"(calls {method} at 0x{target:X})")
        classifications = [
            (row, *classify_mapping(
                row, text, sdk_direct, sdk_owners, sdk, xrefs, meta_targets, methods
            ))
            for row in table
        ]
        print("Evidence tiers for all literal translation entries:")
        for name, count in sorted(Counter(tier for _, _, tier, _ in classifications).items()):
            print(f"  {name}: {count}")
        if args.csv_report:
            with args.csv_report.open("w", newline="", encoding="utf-8") as dest:
                writer = csv.writer(dest)
                writer.writerow(
                    ("source_line", "section", "source_expression", "gta3_10",
                     "candidate_steam11", "evidence_tier", "details", "source_comment")
                )
                for row, candidate, tier, detail in classifications:
                    writer.writerow((row.line, row.group, row.original,
                                     f"0x{row.target:X}",
                                     f"0x{candidate:X}" if candidate is not None else "",
                                     tier, detail, row.comment))
            print(f"Created local audit CSV: {args.csv_report}")
    elif args.csv_report:
        parser.error("--csv-report requires --sdk-root")
    print("WARNING: No 1.1 address table has been validated; do not enable 1.1 hooks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
