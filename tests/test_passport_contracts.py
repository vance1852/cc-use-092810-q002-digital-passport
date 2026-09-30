from __future__ import annotations

import unittest

from battery_passport.contracts import EvidenceRef, parse_refs, parse_requirements
from battery_passport.errors import ValidationFailed
from battery_passport.jsonio import canonical_json, content_digest


class ContractTests(unittest.TestCase):
    def test_evidence_ref_requires_pinned_version_and_digest(self) -> None:
        ref = EvidenceRef.from_dict(
            {"kind": "inspection", "record_id": "insp-1", "revision": 2,
             "sha256": "A" * 64}, "refs[0]")
        self.assertEqual(ref.sha256, "a" * 64)
        self.assertEqual(ref.revision, 2)

    def test_component_requires_role(self) -> None:
        with self.assertRaises(ValidationFailed):
            EvidenceRef.from_dict(
                {"kind": "component", "record_id": "p", "revision": 1, "sha256": "a" * 64},
                "refs[0]")

    def test_role_only_for_components(self) -> None:
        with self.assertRaises(ValidationFailed):
            EvidenceRef.from_dict(
                {"kind": "inspection", "record_id": "i", "revision": 1,
                 "sha256": "a" * 64, "role": "x"}, "refs[0]")

    def test_bad_digest_rejected(self) -> None:
        with self.assertRaises(ValidationFailed):
            EvidenceRef.from_dict(
                {"kind": "inspection", "record_id": "i", "revision": 1, "sha256": "abc"},
                "refs[0]")

    def test_unknown_kind_rejected(self) -> None:
        with self.assertRaises(ValidationFailed):
            EvidenceRef.from_dict(
                {"kind": "warranty", "record_id": "w", "revision": 1, "sha256": "a" * 64},
                "refs[0]")

    def test_parse_refs_rejects_duplicate_and_empty(self) -> None:
        one = {"kind": "inspection", "record_id": "i", "revision": 1, "sha256": "a" * 64}
        with self.assertRaises(ValidationFailed):
            parse_refs([], "refs")
        with self.assertRaises(ValidationFailed):
            parse_refs([one, dict(one)], "refs")

    def test_requirements_validation(self) -> None:
        parsed = parse_requirements({"inspection": False})
        self.assertFalse(parsed["inspection"])
        with self.assertRaises(ValidationFailed):
            parse_requirements({"unknown": True})
        with self.assertRaises(ValidationFailed):
            parse_requirements({"inspection": "yes"})


class JsonIoTests(unittest.TestCase):
    def test_canonical_json_is_deterministic(self) -> None:
        a = {"b": 1, "a": [1, 2, {"c": 3}]}
        b = {"a": [1, 2, {"c": 3}], "b": 1}
        self.assertEqual(canonical_json(a), canonical_json(b))

    def test_content_digest_stable(self) -> None:
        self.assertEqual(content_digest([{"x": 1}]), content_digest([{"x": 1}]))
        self.assertNotEqual(content_digest([{"x": 1}]), content_digest([{"x": 2}]))
        self.assertEqual(len(content_digest([{"x": 1}])), 64)


if __name__ == "__main__":
    unittest.main()
