#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_TEMPLATE = BASE_DIR / "configs" / "paper_48h.cfg"
DEFAULT_RELATION = (
    BASE_DIR
    / "tools/kconfuzz/relations/linked_exact_965/"
    / "param_syzkaller_call_relation.executor_current.jsonl"
)
EXECUTOR_LOG = Path("/tmp/syz-kconfuzz-config-actions.log")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch(url: str, timeout: float = 10.0) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return resp.read()


def count_nonempty_lines(data: bytes) -> int:
    return sum(1 for line in data.splitlines() if line.strip())


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def count_jsonl(path: Path) -> tuple[int, int]:
    total = 0
    dependent = 0
    if not path.exists():
        return total, dependent
    with path.open(encoding="utf-8", errors="replace") as f:
        for raw in f:
            if not raw.strip():
                continue
            total += 1
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if row.get("config_dependent"):
                dependent += 1
    return total, dependent


def action_stats_jsonl(path: Path) -> dict[str, int]:
    counts: list[int] = []
    params: set[int] = set()
    if not path.exists():
        return {
            "min": 0,
            "p50": 0,
            "p90": 0,
            "max": 0,
            "unique_params": 0,
        }
    with path.open(encoding="utf-8", errors="replace") as f:
        for raw in f:
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                continue
            actions = row.get("actions", [])
            counts.append(len(actions))
            for action in actions:
                param_id = action.get("param_id")
                if isinstance(param_id, int):
                    params.add(param_id)
    if not counts:
        return {
            "min": 0,
            "p50": 0,
            "p90": 0,
            "max": 0,
            "unique_params": 0,
        }
    counts.sort()
    return {
        "min": counts[0],
        "p50": counts[len(counts) // 2],
        "p90": counts[min(len(counts) - 1, int(len(counts) * 0.9))],
        "max": counts[-1],
        "unique_params": len(params),
    }


def count_statuses(path: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    if not path.exists():
        return counts
    with path.open(encoding="utf-8", errors="replace") as f:
        for raw in f:
            marker = "status="
            pos = raw.find(marker)
            if pos < 0:
                continue
            rest = raw[pos + len(marker) :].strip()
            status = rest.split(None, 1)[0]
            counts[status] = counts.get(status, 0) + 1
    return counts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template-cfg", type=Path, default=DEFAULT_TEMPLATE)
    parser.add_argument("--relation", type=Path, default=DEFAULT_RELATION)
    parser.add_argument("--duration-sec", type=int, default=300)
    parser.add_argument("--sample-interval-sec", type=int, default=30)
    parser.add_argument("--http-port", type=int, default=56743)
    parser.add_argument("--run-id", default=f"kconfuzz_paper_{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}")
    parser.add_argument("--result-dir", type=Path)
    parser.add_argument(
        "--max-actions",
        type=int,
        default=16,
        help="maximum config actions per generated program; 0 means unlimited",
    )
    parser.add_argument(
        "--random-actions",
        type=int,
        default=0,
        help="number of conservative random config actions to add before related actions",
    )
    parser.add_argument(
        "--related-actions",
        type=int,
        default=15,
        help="maximum syscall-sequence-related config actions; 0 means all related actions",
    )
    parser.add_argument("--debug-kconfuzz", action="store_true")
    parser.add_argument("--manager-debug", action="store_true")
    parser.add_argument("--disable-actions", action="store_true")
    parser.add_argument("--disable-choice", action="store_true")
    parser.add_argument("--disable-metadata", action="store_true")
    parser.add_argument("--manager-mode", default="fuzzing")
    parser.add_argument("--seed-corpus-dir", type=Path)
    parser.add_argument(
        "--rawcover-snapshot-sec",
        type=int,
        action="append",
        default=[],
        help="save a full rawcover snapshot after this elapsed second; may be repeated",
    )
    args = parser.parse_args()

    result_dir = args.result_dir or (BASE_DIR / "results" / args.run_id)
    syz_root = result_dir / "syzkaller"
    manager_workdir = syz_root / "manager-workdir"
    log_dir = syz_root / "logs"
    final_dir = syz_root / "final"
    for path in (manager_workdir, log_dir, final_dir):
        path.mkdir(parents=True, exist_ok=True)

    with args.template_cfg.open(encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["name"] = "kconfuzz-paper-clang18"
    cfg["http"] = f"127.0.0.1:{args.http_port}"
    cfg["workdir"] = str(manager_workdir)
    manager_cfg = syz_root / "manager-config.json"
    write_json(manager_cfg, cfg)

    syzkaller_dir = Path(cfg["syzkaller"])
    manager_bin = syzkaller_dir / "bin/syz-manager"
    syz_db_bin = syzkaller_dir / "bin/syz-db"
    if not manager_bin.exists():
        raise SystemExit(f"missing syz-manager: {manager_bin}")
    if not args.relation.exists():
        raise SystemExit(f"missing relation table: {args.relation}")

    executor_log_backup = None
    if EXECUTOR_LOG.exists():
        executor_log_backup = EXECUTOR_LOG.with_suffix(
            f".before-{args.run_id}.log"
        )
        EXECUTOR_LOG.rename(executor_log_backup)

    manager_log = log_dir / "syz-manager.log"
    session_log = log_dir / "session.log"
    coverage_csv = syz_root / "coverage_curve.csv"
    coverage_jsonl = syz_root / "coverage_curve.jsonl"
    latest_rawcover = syz_root / "latest_rawcover.txt"
    final_rawcover = final_dir / "rawcover-final.txt"
    final_stats = final_dir / "stats-final.txt"
    audit_file = log_dir / "kconfuzz-audit.jsonl"
    manager_url = f"http://127.0.0.1:{args.http_port}"
    snapshot_secs = sorted({sec for sec in args.rawcover_snapshot_sec if sec > 0})
    pending_snapshots = set(snapshot_secs)
    rawcover_snapshots: dict[str, str] = {}

    def log(msg: str) -> None:
        line = f"{utc_now()} {msg}\n"
        sys.stdout.write(line)
        sys.stdout.flush()
        with session_log.open("a", encoding="utf-8") as f:
            f.write(line)

    env = os.environ.copy()
    env.update(
        {
            "SYZ_KCONFUZZ_RELATION_TABLE": str(args.relation),
            "SYZ_KCONFUZZ_AUDIT_FILE": str(audit_file),
            "SYZ_KCONFUZZ_MAX_ACTIONS": str(args.max_actions),
            "SYZ_KCONFUZZ_RANDOM_ACTIONS": str(args.random_actions),
            "SYZ_KCONFUZZ_RELATED_ACTIONS": str(args.related_actions),
        }
    )
    if args.debug_kconfuzz:
        env["SYZ_KCONFUZZ_DEBUG"] = "1"
    else:
        env.pop("SYZ_KCONFUZZ_DEBUG", None)
    disable_envs = {
        "SYZ_KCONFUZZ_DISABLE_ACTIONS": args.disable_actions,
        "SYZ_KCONFUZZ_DISABLE_CHOICE": args.disable_choice,
        "SYZ_KCONFUZZ_DISABLE_METADATA": args.disable_metadata,
    }
    for key, disabled in disable_envs.items():
        if disabled:
            env[key] = "1"
        else:
            env.pop(key, None)

    with coverage_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["sample_time_utc", "elapsed_sec", "unique_pcs", "delta_pcs", "pcs_per_sec", "label"])
    coverage_jsonl.write_text("", encoding="utf-8")

    log(f"starting kconfuzz paper-style run_id={args.run_id} duration_sec={args.duration_sec}")
    log(f"manager_config={manager_cfg}")
    log(f"relation_table={args.relation}")
    if args.seed_corpus_dir:
        if not syz_db_bin.exists():
            raise SystemExit(f"missing syz-db: {syz_db_bin}")
        if not args.seed_corpus_dir.exists():
            raise SystemExit(f"missing seed corpus dir: {args.seed_corpus_dir}")
        corpus_db = manager_workdir / "corpus.db"
        subprocess.run(
            [str(syz_db_bin), "pack", str(args.seed_corpus_dir), str(corpus_db)],
            cwd=str(syzkaller_dir),
            check=True,
        )
        log(f"seed_corpus_dir={args.seed_corpus_dir}")
    manager_cmd = [str(manager_bin), "-config", str(manager_cfg), "-vv=2"]
    if args.manager_mode:
        manager_cmd.extend(["-mode", args.manager_mode])
    if args.manager_debug:
        manager_cmd.append("-debug")
    proc = subprocess.Popen(
        manager_cmd,
        cwd=str(syzkaller_dir),
        env=env,
        stdout=manager_log.open("wb"),
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    log(f"syz-manager pid={proc.pid}")

    status = "completed"
    start = time.time()
    last_pcs = 0
    last_sample = start
    samples = []
    try:
        ready = False
        for _ in range(120):
            if proc.poll() is not None:
                status = "manager_exited_during_startup"
                break
            try:
                fetch(f"{manager_url}/config?raw=1", timeout=2)
                ready = True
                break
            except (urllib.error.URLError, TimeoutError):
                time.sleep(1)
        if not ready:
            if status == "completed":
                status = "http_not_ready"
            raise RuntimeError(status)

        deadline = start + args.duration_sec
        next_sample = time.time()
        while proc.poll() is None and time.time() < deadline:
            now = time.time()
            if now < next_sample:
                time.sleep(min(1.0, next_sample - now))
                continue
            label = "initial" if not samples else "periodic"
            try:
                rawcover = fetch(f"{manager_url}/rawcover?raw=1", timeout=10)
            except Exception as exc:
                log(f"rawcover sample failed label={label}: {exc}")
                next_sample += args.sample_interval_sec
                continue
            latest_rawcover.write_bytes(rawcover)
            pcs = count_nonempty_lines(rawcover)
            elapsed = int(time.time() - start)
            for snapshot_sec in list(pending_snapshots):
                if elapsed < snapshot_sec:
                    continue
                snapshot_path = final_dir / f"rawcover-{snapshot_sec}s.txt"
                snapshot_path.write_bytes(rawcover)
                rawcover_snapshots[str(snapshot_sec)] = str(snapshot_path)
                pending_snapshots.remove(snapshot_sec)
                log(
                    f"rawcover snapshot sec={snapshot_sec} "
                    f"unique_pcs={pcs} path={snapshot_path}"
                )
            interval = max(1, int(time.time() - last_sample))
            delta = pcs - last_pcs
            row = {
                "sample_time_utc": utc_now(),
                "elapsed_sec": elapsed,
                "unique_pcs": pcs,
                "delta_pcs": delta,
                "pcs_per_sec": delta / interval,
                "label": label,
            }
            samples.append(row)
            with coverage_csv.open("a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(
                    [row["sample_time_utc"], elapsed, pcs, delta, f"{row['pcs_per_sec']:.6f}", label]
                )
            with coverage_jsonl.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row, sort_keys=True) + "\n")
            log(f"sample label={label} elapsed_sec={elapsed} unique_pcs={pcs} delta_pcs={delta}")
            last_pcs = pcs
            last_sample = time.time()
            next_sample += args.sample_interval_sec

        if proc.poll() is not None:
            status = "manager_exited"
    finally:
        try:
            rawcover = fetch(f"{manager_url}/rawcover?raw=1", timeout=15)
            final_rawcover.write_bytes(rawcover)
            latest_rawcover.write_bytes(rawcover)
        except Exception:
            pass
        try:
            final_stats.write_bytes(fetch(f"{manager_url}/stats?raw=1", timeout=10))
        except Exception:
            pass
        if proc.poll() is None:
            log(f"stopping syz-manager pid={proc.pid}")
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=10)

    metadata_file = manager_workdir / "kconfuzz-corpus-meta.jsonl"
    meta_total, meta_dependent = count_jsonl(metadata_file)
    meta_action_stats = action_stats_jsonl(metadata_file)
    exec_status = count_statuses(EXECUTOR_LOG)
    manager_text = manager_log.read_text(encoding="utf-8", errors="replace") if manager_log.exists() else ""
    final_pcs = count_nonempty_lines(final_rawcover.read_bytes()) if final_rawcover.exists() else 0
    summary = {
        "status": status,
        "run_id": args.run_id,
        "result_dir": str(result_dir),
        "duration_sec": args.duration_sec,
        "sample_interval_sec": args.sample_interval_sec,
        "sample_count": len(samples),
        "initial_unique_pcs": samples[0]["unique_pcs"] if samples else 0,
        "final_unique_pcs": final_pcs,
        "pc_delta": final_pcs - (samples[0]["unique_pcs"] if samples else 0),
        "manager_config": str(manager_cfg),
        "manager_log": str(manager_log),
        "coverage_csv": str(coverage_csv),
        "coverage_jsonl": str(coverage_jsonl),
        "rawcover_snapshots": rawcover_snapshots,
        "rawcover_snapshot_pending_sec": sorted(pending_snapshots),
        "audit_file": str(audit_file),
        "relation_table": str(args.relation),
        "action_mix": {
            "max": args.max_actions,
            "random": args.random_actions,
            "related": args.related_actions,
            "corpus_persistence": 0,
        },
        "kconfuzz_disabled": {
            "actions": args.disable_actions,
            "choice": args.disable_choice,
            "metadata": args.disable_metadata,
        },
        "debug_kconfuzz": args.debug_kconfuzz,
        "manager_debug": args.manager_debug,
        "manager_log_counts": {
            "relation_loaded": manager_text.count("loaded relation table"),
            "planned_actions": manager_text.count("planned "),
            "runner_serializing": manager_text.count("runner serializing"),
            "choice_boost_build": manager_text.count("choice-boost-build"),
            "requires_config_context": manager_text.count("requires config context"),
            "without_config_reproduced": manager_text.count("without-config reproduced"),
        },
        "executor_log": str(EXECUTOR_LOG),
        "executor_log_backup": str(executor_log_backup) if executor_log_backup else "",
        "executor_status_counts": exec_status,
        "corpus": {
            "db_exists": (manager_workdir / "corpus.db").exists(),
            "metadata_records": meta_total,
            "metadata_config_dependent": meta_dependent,
            "metadata_file": str(metadata_file),
            "action_stats": meta_action_stats,
        },
    }
    write_json(syz_root / "session_summary.json", summary)
    log(f"kconfuzz paper-style finished status={status} result_dir={result_dir}")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if status == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
