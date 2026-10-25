"""Synthetic checks for the read-only GTA III Steam address auditor.

No copyrighted game executable or private memory dump is required.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "audit-gta3-11-addresses.py"
SPEC = importlib.util.spec_from_file_location("gta3_11_audit", SOURCE)
assert SPEC is not None and SPEC.loader is not None
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)


class AddressAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.working_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.working_dir.cleanup)
        self.sdk_root = Path(self.working_dir.name)
        meta = self.sdk_root / "plugin_III/game_III/meta"
        meta.mkdir(parents=True)
        (meta / "meta.CDemo.h").write_text(
            """META_BEGIN(CDemo::Open)
using mv_addresses_t = MvAddresses<0x401100, 0x402100, 0x403100>;
using refs_t = RefList<
    0x401120,100,0,0x401100,1,
    0x401128,100,0,0x401100,2,
    0x402120,110,0,0x402100,1,
    0x402128,110,0,0x402100,2,
    0x403122,120,0,0x403100,1,
    0x40312A,120,0,0x403100,2
>;
META_END
""",
            encoding="utf-8",
        )
        self.text = bytearray(0x4000)
        self.entry = audit.Translation(
            line=1, original="0x900000", target=0x401120,
            comment="call CDemo::Open", group="Core", is_call_site=True,
        )

    def classify(self) -> tuple[int | None, str, str]:
        sdk = audit.sdk_mappings(self.sdk_root)
        owners = audit.sdk_meta_owner_mappings(self.sdk_root)
        xrefs = audit.sdk_meta_reference_mappings(self.sdk_root)
        targets = audit.sdk_meta_reference_targets(self.sdk_root)
        return audit.classify_mapping(
            self.entry, bytes(self.text), sdk, owners,
            audit.merge_mappings(sdk, owners), xrefs, targets, {},
        )

    def write_call(self, address: int, target: int) -> None:
        offset = address - audit.TEXT_BASE
        self.text[offset] = 0xE8
        struct.pack_into("<i", self.text, offset + 1, target - address - 5)

    def test_sdk_pairs_reference_sites_and_owning_function(self) -> None:
        self.assertEqual(
            audit.sdk_meta_reference_mappings(self.sdk_root)[0x401120], {0x403122}
        )
        self.assertEqual(
            audit.sdk_meta_owner_mappings(self.sdk_root)[0x401100], {0x403100}
        )
        self.assertEqual(
            audit.sdk_meta_reference_targets(self.sdk_root)[(0x401120, 0x403122)],
            {0x403100},
        )

    def test_matching_destination_is_independent_evidence(self) -> None:
        self.write_call(0x403122, 0x403100)
        self.assertEqual(self.classify()[:2], (0x403122, "sdk-xref-target-match"))

    def test_valid_call_opcode_with_wrong_destination_stays_unverified(self) -> None:
        self.write_call(0x403122, 0x404000)
        self.assertEqual(self.classify()[:2], (0x403122, "sdk-xref-needs-review"))

    def test_inspected_anchor_overrides_nearby_sdk_projections(self) -> None:
        previous = audit.INSPECTED_CALL_SITES
        self.addCleanup(setattr, audit, "INSPECTED_CALL_SITES", previous)
        audit.INSPECTED_CALL_SITES = {0x401120: (0x403122, 0x403100)}
        self.write_call(0x403122, 0x403100)
        self.assertEqual(self.classify()[:2], (0x403122, "inspected-call-target-match"))

    def test_inspected_anchor_does_not_hide_runtime_mismatch(self) -> None:
        previous = audit.INSPECTED_CALL_SITES
        self.addCleanup(setattr, audit, "INSPECTED_CALL_SITES", previous)
        audit.INSPECTED_CALL_SITES = {0x401120: (0x403122, 0x403100)}
        self.write_call(0x403122, 0x404000)
        self.assertEqual(self.classify()[:2], (0x403122, "inspected-call-target-mismatch"))

    def test_unverified_neighbor_projection_is_not_promoted(self) -> None:
        projected = audit.project_from_nearby_sdk_anchors(
            0x401150,
            {0x401100: {0x401200}, 0x401200: {0x401300}},
        )
        self.assertEqual(projected, 0x401250)


if __name__ == "__main__":
    unittest.main()
