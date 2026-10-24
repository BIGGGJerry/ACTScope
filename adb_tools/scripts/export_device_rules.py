"""Convert the selected legacy F6 rules into the same device-side scan scope."""
from dataclasses import asdict
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from actscope.rules import parse_rules
from actscope.store import project_path, read_json, write_json


def export_rules(options: dict) -> dict:
    root = options.get("root", "/sdcard")
    if not isinstance(root, str) or not root.startswith("/"):
        raise ValueError("Device root must be absolute")
    rule_files = options.get("rules")
    if not isinstance(rule_files, list) or not rule_files:
        raise ValueError("Explicitly select rule files in the F6 options")
    records = []
    for name in rule_files:
        path = project_path(name, must_exist=True)
        for rule in parse_rules(path, root):
            entry = asdict(rule)
            entry["source"] = str(path.relative_to(project_path(".")))
            records.append(entry)
    roots = list(dict.fromkeys(row["path"] for row in records))
    if not 1 <= len(roots) <= 512:
        raise ValueError("Device F6 accepts 1–512 rule roots per scan; split larger sets")
    return {"roots": roots, "rule_manifest": records, "rule_count": len(records),
            "max_scan_entries": 50000, "max_results": 500, "hash_files": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--options", default="configs/f6.example.json")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        config = export_rules(read_json(args.options))
        output = project_path(args.output)
        write_json(output, config)
        print(json.dumps({"output": str(output), "rule_count": config["rule_count"],
                          "unique_roots": len(config["roots"])}, ensure_ascii=False))
        return 0
    except (ValueError, OSError) as error:
        print(f"Rule export: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
