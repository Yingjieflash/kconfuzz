#!/usr/bin/env python3
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

import argparse
import json
import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[3]


def read_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if raw:
                yield json.loads(raw)


def load_registry_mutator_params(path):
    if not path.exists():
        return set()
    ret = set()
    entry_re = re.compile(r'^\s*"([^"]+)":\s+\{(.+)\},$')
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            match = entry_re.match(line)
            if match and "Mutator: true" in match.group(2):
                ret.add(match.group(1))
    return ret


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--accurate-roots",
        type=Path,
        default=ROOT / "accurate_roots.conservative.jsonl",
    )
    parser.add_argument(
        "--mutator-table",
        type=Path,
        default=REPO / "tools/kconfuzz/value_domains/accurate458/parameter_mutator_table.simple.jsonl",
    )
    parser.add_argument(
        "--registry",
        type=Path,
        default=REPO / "pkg/kconfuzz/registry_gen.go",
    )
    args = parser.parse_args()

    roots = list(read_jsonl(args.accurate_roots))
    mutators = list(read_jsonl(args.mutator_table))
    root_params = {row.get("param") for row in roots}
    mutator_params = {row.get("param") for row in mutators}
    registry_mutator_params = load_registry_mutator_params(args.registry)

    summary = {
        "accurate_roots": str(args.accurate_roots),
        "accurate_root_count": len(roots),
        "root_var_type_counts": Counter(
            (row.get("conftainter_root_spec") or {}).get("var_type") for row in roots
        ),
        "root_accuracy_counts": Counter(row.get("mvp_root_accuracy") for row in roots),
        "root_status_counts": Counter(row.get("tfuzz_root_spec_status") for row in roots),
        "mutator_table": str(args.mutator_table),
        "mutator_row_count": len(mutators),
        "mutator_params_missing_from_accurate_roots": sorted(mutator_params - root_params),
        "accurate_roots_not_in_mutator_count": len(root_params - mutator_params),
        "registry": str(args.registry),
        "registry_mutator_param_count": len(registry_mutator_params),
        "mutator_params_missing_from_registry": sorted(mutator_params - registry_mutator_params),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))

    if summary["mutator_params_missing_from_accurate_roots"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
