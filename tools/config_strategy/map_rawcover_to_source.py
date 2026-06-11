#!/usr/bin/env python3
import argparse
import csv
import json
import re
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


def load_raw_pcs(path: Path) -> List[str]:
    pcs: List[str] = []
    seen = set()
    with path.open(encoding="utf-8") as fp:
        for line in fp:
            pc = line.strip()
            if not pc or pc in seen:
                continue
            seen.add(pc)
            pcs.append(pc)
    return pcs


def is_addr_line(line: str) -> bool:
    return line.startswith("0x")


def normalize_location(location: str, kernel_root: Path) -> Dict[str, object]:
    location = location.strip()
    if not location or location.startswith("??:"):
        return {
            "path": None,
            "line": 0,
            "resolved": False,
            "exists": False,
            "is_header": False,
        }

    path_text, _, line_text = location.rpartition(":")
    if not path_text:
        path_text = location
        line_text = "0"

    match = re.match(r"(\d+)", line_text)
    line_no = int(match.group(1)) if match else 0

    raw_path = Path(path_text)
    if raw_path.is_absolute():
        try:
            normalized_path = raw_path.resolve().relative_to(kernel_root.resolve()).as_posix()
            abs_path = kernel_root / normalized_path
        except ValueError:
            normalized_path = raw_path.resolve().as_posix()
            abs_path = raw_path.resolve()
    else:
        normalized_path = raw_path.as_posix()
        abs_path = (kernel_root / raw_path).resolve()

    return {
        "path": normalized_path,
        "line": line_no,
        "resolved": True,
        "exists": abs_path.exists(),
        "is_header": normalized_path.endswith(".h"),
    }


def parse_addr2line_output(stdout: str, kernel_root: Path) -> List[Dict[str, object]]:
    records: List[Dict[str, object]] = []
    current_pc: Optional[str] = None
    current_frames: List[Dict[str, object]] = []
    pending_func: Optional[str] = None

    def flush_current() -> None:
        nonlocal current_pc, current_frames
        if current_pc is None:
            return
        records.append({"raw_pc": current_pc, "frames": current_frames})
        current_pc = None
        current_frames = []

    for raw_line in stdout.splitlines():
        line = raw_line.rstrip("\n")
        if is_addr_line(line):
            flush_current()
            current_pc = line.strip()
            pending_func = None
            continue

        if current_pc is None:
            continue

        if pending_func is None:
            pending_func = line
            continue

        location = normalize_location(line, kernel_root)
        current_frames.append(
            {
                "function": pending_func.strip() or "??",
                "file_path": location["path"],
                "line": location["line"],
                "resolved": location["resolved"],
                "file_exists": location["exists"],
                "is_header": location["is_header"],
            }
        )
        pending_func = None

    flush_current()
    return records


def run_addr2line(addr2line_bin: str, vmlinux: Path, pcs: Iterable[str], kernel_root: Path) -> List[Dict[str, object]]:
    proc = subprocess.run(
        [addr2line_bin, "-afi", "-e", str(vmlinux)],
        input="".join(f"{pc}\n" for pc in pcs),
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"addr2line exited with code {proc.returncode}")
    return parse_addr2line_output(proc.stdout, kernel_root)


def choose_primary_frame(frames: List[Dict[str, object]]) -> Dict[str, object]:
    for frame in frames:
        if frame["resolved"]:
            return frame
    return frames[0] if frames else {}


def choose_context_frame(frames: List[Dict[str, object]]) -> Dict[str, object]:
    for frame in reversed(frames):
        if frame["resolved"]:
            return frame
    return frames[-1] if frames else {}


def choose_sample_indices(total: int, sample_size: int) -> List[int]:
    if total == 0:
        return []
    if sample_size >= total:
        return list(range(total))
    if sample_size <= 1:
        return [0]

    indices = set()
    for idx in range(sample_size):
        pos = round(idx * (total - 1) / (sample_size - 1))
        indices.add(pos)
    return sorted(indices)


def frames_signature(frames: List[Dict[str, object]]) -> List[Tuple[object, ...]]:
    return [
        (
            frame.get("function"),
            frame.get("file_path"),
            frame.get("line"),
            frame.get("resolved"),
            frame.get("file_exists"),
        )
        for frame in frames
    ]


def write_jsonl(path: Path, rows: Iterable[Dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8") as fp:
        for row in rows:
            fp.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_primary_csv(path: Path, rows: Iterable[Dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(
            fp,
            fieldnames=[
                "raw_pc",
                "resolved",
                "frame_count",
                "primary_function",
                "primary_file_path",
                "primary_line",
                "primary_file_exists",
                "primary_is_header",
                "context_function",
                "context_file_path",
                "context_line",
                "context_file_exists",
                "context_is_header",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def write_file_stats_csv(path: Path, rows: Iterable[Dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(
            fp,
            fieldnames=[
                "file_path",
                "primary_pc_count",
                "context_pc_count",
                "any_frame_pc_count",
                "is_header",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Map raw syzkaller PCs to kernel source files using addr2line.")
    parser.add_argument("--rawcover", required=True)
    parser.add_argument("--vmlinux", required=True)
    parser.add_argument("--kernel-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--addr2line-bin", default="addr2line")
    parser.add_argument("--verify-sample-size", type=int, default=32)
    args = parser.parse_args()

    rawcover = Path(args.rawcover).resolve()
    vmlinux = Path(args.vmlinux).resolve()
    kernel_root = Path(args.kernel_root).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    pcs = load_raw_pcs(rawcover)
    records = run_addr2line(args.addr2line_bin, vmlinux, pcs, kernel_root)
    if len(records) != len(pcs):
        raise RuntimeError(f"addr2line record count mismatch: expected {len(pcs)}, got {len(records)}")

    sample_indices = choose_sample_indices(len(pcs), args.verify_sample_size)
    sample_lookup = {pcs[idx]: idx for idx in sample_indices}
    sample_records: Dict[str, List[Dict[str, object]]] = {}

    primary_rows: List[Dict[str, object]] = []
    frame_rows: List[Dict[str, object]] = []
    primary_counts: Dict[str, int] = {}
    context_counts: Dict[str, int] = {}
    any_frame_counts: Dict[str, int] = {}

    mapped_pcs = 0
    pcs_with_primary_file = 0
    pcs_with_context_file = 0
    pcs_with_inline_frames = 0
    primary_header_pc_count = 0
    context_header_pc_count = 0
    total_frames = 0
    unresolved_samples: List[str] = []

    for record in records:
        raw_pc = str(record["raw_pc"])
        frames = list(record["frames"])
        total_frames += len(frames)
        if len(frames) > 1:
            pcs_with_inline_frames += 1
        if raw_pc in sample_lookup:
            sample_records[raw_pc] = frames

        primary = choose_primary_frame(frames)
        context = choose_context_frame(frames)
        primary_path = primary.get("file_path")
        context_path = context.get("file_path")
        primary_resolved = bool(primary.get("resolved"))
        context_resolved = bool(context.get("resolved"))

        if primary_resolved:
            mapped_pcs += 1
        elif len(unresolved_samples) < 20:
            unresolved_samples.append(raw_pc)

        if primary_path:
            primary_counts[primary_path] = primary_counts.get(primary_path, 0) + 1
        if context_path:
            context_counts[context_path] = context_counts.get(context_path, 0) + 1

        unique_frame_paths = {frame["file_path"] for frame in frames if frame.get("file_path")}
        for path_text in unique_frame_paths:
            any_frame_counts[path_text] = any_frame_counts.get(path_text, 0) + 1

        if primary.get("file_exists"):
            pcs_with_primary_file += 1
        if context.get("file_exists"):
            pcs_with_context_file += 1
        if primary.get("is_header"):
            primary_header_pc_count += 1
        if context.get("is_header"):
            context_header_pc_count += 1

        primary_rows.append(
            {
                "raw_pc": raw_pc,
                "resolved": primary_resolved,
                "frame_count": len(frames),
                "primary_function": primary.get("function"),
                "primary_file_path": primary_path,
                "primary_line": primary.get("line", 0),
                "primary_file_exists": bool(primary.get("file_exists")),
                "primary_is_header": bool(primary.get("is_header")),
                "context_function": context.get("function"),
                "context_file_path": context_path,
                "context_line": context.get("line", 0),
                "context_file_exists": bool(context.get("file_exists")),
                "context_is_header": bool(context.get("is_header")),
            }
        )
        frame_rows.append(
            {
                "raw_pc": raw_pc,
                "frame_count": len(frames),
                "resolved": primary_resolved,
                "frames": frames,
            }
        )

    verify_results: List[Dict[str, object]] = []
    if sample_indices:
        sample_pcs = [pcs[idx] for idx in sample_indices]
        verify_records = run_addr2line(args.addr2line_bin, vmlinux, sample_pcs, kernel_root)
        verify_by_pc = {str(item["raw_pc"]): item["frames"] for item in verify_records}
        for sample_pc in sample_pcs:
            expected_frames = sample_records.get(sample_pc, [])
            actual_frames = verify_by_pc.get(sample_pc, [])
            match = frames_signature(expected_frames) == frames_signature(actual_frames)
            verify_results.append(
                {
                    "raw_pc": sample_pc,
                    "match": match,
                    "expected_frame_count": len(expected_frames),
                    "actual_frame_count": len(actual_frames),
                    "expected_primary_file": expected_frames[0]["file_path"] if expected_frames else None,
                    "actual_primary_file": actual_frames[0]["file_path"] if actual_frames else None,
                }
            )

    file_rows = []
    all_files = sorted(set(primary_counts) | set(context_counts) | set(any_frame_counts))
    for file_path in all_files:
        file_rows.append(
            {
                "file_path": file_path,
                "primary_pc_count": primary_counts.get(file_path, 0),
                "context_pc_count": context_counts.get(file_path, 0),
                "any_frame_pc_count": any_frame_counts.get(file_path, 0),
                "is_header": file_path.endswith(".h"),
            }
        )
    file_rows.sort(key=lambda item: (-item["primary_pc_count"], item["file_path"]))

    summary = {
        "rawcover_path": str(rawcover),
        "vmlinux_path": str(vmlinux),
        "kernel_root": str(kernel_root),
        "addr2line_bin": args.addr2line_bin,
        "total_pcs": len(pcs),
        "mapped_pcs": mapped_pcs,
        "unresolved_pcs": len(pcs) - mapped_pcs,
        "total_frames": total_frames,
        "pcs_with_inline_frames": pcs_with_inline_frames,
        "pcs_with_existing_primary_file": pcs_with_primary_file,
        "pcs_with_existing_context_file": pcs_with_context_file,
        "primary_header_pc_count": primary_header_pc_count,
        "context_header_pc_count": context_header_pc_count,
        "unique_primary_files": len(primary_counts),
        "unique_context_files": len(context_counts),
        "unique_any_frame_files": len(any_frame_counts),
        "unresolved_sample": unresolved_samples,
        "sample_verification": {
            "requested": args.verify_sample_size,
            "checked": len(verify_results),
            "matched": sum(1 for item in verify_results if item["match"]),
            "mismatched": sum(1 for item in verify_results if not item["match"]),
            "samples": verify_results,
        },
        "top_primary_files": file_rows[:20],
        "top_context_files": sorted(file_rows, key=lambda item: (-item["context_pc_count"], item["file_path"]))[:20],
    }

    write_jsonl(output_dir / "pc_to_source_frames.jsonl", frame_rows)
    write_primary_csv(output_dir / "pc_to_source_primary.csv", primary_rows)
    write_file_stats_csv(output_dir / "file_pc_stats.csv", file_rows)
    (output_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
