import unittest
from actscope.store import read_json
from scripts.export_device_rules import export_rules


class RuleExportTests(unittest.TestCase):
    def test_export_preserves_exact_default_rule_count_and_file_semantics(self):
        config = export_rules(read_json("configs/f6.example.json"))
        self.assertEqual(config["rule_count"], 188)
        self.assertEqual(len(config["rule_manifest"]), 188)
        self.assertEqual(set(config["roots"]), {r["path"] for r in config["rule_manifest"]})
        self.assertTrue(any(r["kind"] == "file" for r in config["rule_manifest"]))
        self.assertTrue(all(r["source"].startswith("rules/") for r in config["rule_manifest"]))

    def test_missing_selection_is_not_silently_broadened(self):
        with self.assertRaises(ValueError):
            export_rules({"root": "/sdcard"})


if __name__ == "__main__":
    unittest.main()
