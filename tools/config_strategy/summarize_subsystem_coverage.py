#!/usr/bin/env python3
import argparse
import csv
import json
from pathlib import Path


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if line:
                yield json.loads(line)


def build_excludes(prefix: str, paths):
    excludes = []
    for path in paths:
        if path.startswith("-") and path[1:].startswith(prefix):
            excludes.append(path[1:])
    return excludes


def is_excluded(file_path: str, excludes):
    return any(file_path.startswith(exclude) for exclude in excludes)


def matches_subsystem(file_path: str, subsystem):
    for path in subsystem["path"]:
        if path.startswith("-"):
            continue
        excludes = build_excludes(path, subsystem["path"])
        if file_path.startswith(path) and not is_excluded(file_path, excludes):
            return True
    return False


def main():
    parser = argparse.ArgumentParser(description="Summarize per-subsystem coverage from syz-cover jsonl output.")
    parser.add_argument("--manager-config", required=True)
    parser.add_argument("--cover-jsonl", required=True)
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-csv", required=True)
    args = parser.parse_args()

    config = load_json(Path(args.manager_config))
    subsystems = config.get("kernel_subsystem", [])
    stats = {
        subsystem["name"]: {
            "name": subsystem["name"],
            "covered_pcs": 0,
            "total_pcs": 0,
            "hit_count_sum": 0,
            "covered_files": set(),
            "touched_files": set(),
        }
        for subsystem in subsystems
    }

    for item in iter_jsonl(Path(args.cover_jsonl)):
        file_path = item["file_path"]
        hit_count = int(item.get("hit_count", 0))
        for subsystem in subsystems:
            if not matches_subsystem(file_path, subsystem):
                continue
            bucket = stats[subsystem["name"]]
            bucket["total_pcs"] += 1
            bucket["hit_count_sum"] += hit_count
            bucket["touched_files"].add(file_path)
            if hit_count > 0:
                bucket["covered_pcs"] += 1
                bucket["covered_files"].add(file_path)

    rows = []
    for subsystem in subsystems:
        bucket = stats[subsystem["name"]]
        total = bucket["total_pcs"]
        covered = bucket["covered_pcs"]
        rows.append(
            {
                "name": bucket["name"],
                "covered_pcs": covered,
                "total_pcs": total,
                "covered_pcs_pct": 0.0 if total == 0 else round(100.0 * covered / total, 2),
                "hit_count_sum": bucket["hit_count_sum"],
                "touched_file_count": len(bucket["touched_files"]),
                "covered_file_count": len(bucket["covered_files"]),
            }
        )

    rows.sort(key=lambda item: (-item["covered_pcs"], item["name"]))
    summary = {
        "source_jsonl": str(Path(args.cover_jsonl).resolve()),
        "subsystem_count": len(rows),
        "subsystems": rows,
        "top_by_covered_pcs": rows[:10],
    }

    out_json = Path(args.out_json)
    out_csv = Path(args.out_csv)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    with out_csv.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(
            fp,
            fieldnames=[
                "name",
                "covered_pcs",
                "total_pcs",
                "covered_pcs_pct",
                "hit_count_sum",
                "touched_file_count",
                "covered_file_count",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()
