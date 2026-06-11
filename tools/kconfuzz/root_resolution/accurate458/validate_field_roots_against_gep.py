#!/usr/bin/env python3
"""Validate TFuzz FIELD roots against LLVM getelementptr indices.

This checks the exact convention used by ConfTainter/TFuzz FIELD roots:
`FIELD netns_ipv4.69 ...` must match a `%struct.netns_ipv4` GEP with index 69,
not merely the 69th source/debug member.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any


WORKDIR = Path("/home/wang/syzkaller_workdir")
ROOT = WORKDIR / "config_strategy_workspace/value_domain_workspace"
DEFAULT_ROOTS = ROOT / "runs/active130_completed_roots/active130_ready_strict_roots.jsonl"
DEFAULT_PLANS = [
    ROOT / "runs/active130_tfuzz_value_use_plan/bitcode_plan.jsonl",
    ROOT / "runs/active130_blocked_completed_plan/bitcode_plan.jsonl",
]
DEFAULT_KERNEL_BC_ROOT = WORKDIR / "linux-6.12.80-clang18-bc-clean"

GEP_RE = re.compile(
    r"^\s*%(?P<ssa>[A-Za-z0-9_.$]+)\s*=\s*getelementptr\s+(?:inbounds\s+)?"
    r"%struct\.(?P<struct>[A-Za-z0-9_.$]+),\s+ptr\s+[^,]+,\s+i(?:32|64)\s+0,\s+(?P<rest>.+)$"
)
IDX_RE = re.compile(r"i(?:32|64)\s+(\d+)")
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

FIELD_ALIASES = {
    "init_net.ip_forward_update_priority": "sysctl_ip_fwd_update_priority",
    "init_net.tcp_no_metrics_save": "sysctl_tcp_nometrics_save",
    "init_net.txrehash": "sysctl_txrehash",
    "init_net.nf_conntrack_acct": "sysctl_acct",
    "init_net.nf_conntrack_checksum": "sysctl_checksum",
    "init_net.echo_ignore_all": "icmpv6_echo_ignore_all",
    "init_net.echo_ignore_anycast": "icmpv6_echo_ignore_anycast",
    "init_net.echo_ignore_multicast": "icmpv6_echo_ignore_multicast",
    "init_net.error_anycast_as_unicast": "icmpv6_error_anycast_as_unicast",
    "init_net.skip_notify_on_dev_down": "skip_notify_on_dev_down",
}
BACKING_PREFIX_TO_FIELD_PREFIX = (
    ("init_net.ipv4.", ""),
    ("init_net.ipv6.", ""),
    ("init_net.sctp.", ""),
    ("init_net.core.", "sysctl_"),
    ("init_net.xfrm.", "sysctl_"),
    ("init_net.ct.", "sysctl_"),
    ("init_net.unx.", ""),
    ("init_ipc_ns.", ""),
    ("init_user_ns.", ""),
    ("init_uts_ns.", ""),
    ("init_pid_ns.", ""),
    ("files_stat.", ""),
)
GENERIC_TOKENS = {
    "all",
    "data",
    "default",
    "enable",
    "enabled",
    "flag",
    "flags",
    "hash",
    "ignore",
    "mode",
    "net",
    "sysctl",
    "value",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--roots", type=Path, default=DEFAULT_ROOTS)
    parser.add_argument("--plan", type=Path, action="append", default=[])
    parser.add_argument("--kernel-bc-root", type=Path, default=DEFAULT_KERNEL_BC_ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary-out", type=Path)
    parser.add_argument("--corrected-roots-output", type=Path)
    parser.add_argument("--llvm-dis", type=Path)
    return parser.parse_args()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            raw = raw.strip()
            if raw:
                rows.append(json.loads(raw))
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def choose_llvm_dis(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    for name in ("llvm-dis-18", "llvm-dis"):
        found = shutil.which(name)
        if found:
            return Path(found)
    raise SystemExit("llvm-dis not found")


@lru_cache(maxsize=256)
def disassemble_cached(bitcode: str, llvm_dis: str) -> str | None:
    try:
        proc = subprocess.run(
            [llvm_dis, bitcode, "-o", "-"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def parse_field_root(root: str) -> tuple[str, list[int]] | None:
    parts = root.split(".")
    if len(parts) < 2:
        return None
    indices: list[int] = []
    for item in parts[1:]:
        if not item.isdigit():
            return None
        indices.append(int(item))
    return parts[0], indices


def normalize_token(token: str) -> str:
    token = token.strip()
    token = re.sub(r"^proc_", "", token)
    return token


def add_token(tokens: list[str], token: str | None, *, strong: bool = False) -> None:
    if token is None:
        return
    token = normalize_token(token)
    if not token or token in tokens:
        return
    lowered = token.lower()
    if lowered in GENERIC_TOKENS:
        return
    if not strong:
        if len(token) < 4:
            return
    if not IDENT_RE.fullmatch(token):
        return
    tokens.append(token)


def expected_tokens(record: dict[str, Any]) -> list[str]:
    tokens: list[str] = []
    evidence = record.get("tfuzz_root_spec_evidence") or {}
    field = evidence.get("field")
    add_token(tokens, field, strong=bool(field))
    for step in evidence.get("debug_steps") or []:
        add_token(tokens, step.get("field"), strong=True)

    backing = re.sub(r"\s+", "", str(record.get("backing_symbol") or ""))
    alias = FIELD_ALIASES.get(backing)
    add_token(tokens, alias, strong=True if alias else False)
    for prefix, field_prefix in BACKING_PREFIX_TO_FIELD_PREFIX:
        if backing.startswith(prefix):
            leaf = backing[len(prefix) :].split(".")[-1]
            add_token(tokens, leaf, strong=True)
            if field_prefix and not leaf.startswith(field_prefix):
                add_token(tokens, field_prefix + leaf, strong=True)
            if prefix == "init_net.ipv4." and not leaf.startswith("sysctl_"):
                add_token(tokens, "sysctl_" + leaf, strong=True)
            break
    if "." in backing:
        add_token(tokens, backing.split(".")[-1])

    param = str(record.get("param") or "")
    if param:
        add_token(tokens, param.split("/")[-1])
    dotted = str(record.get("dotted_name") or "")
    if dotted:
        add_token(tokens, dotted.split(".")[-1])
    return tokens


def plan_bitcodes_by_param(plans: list[Path]) -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = defaultdict(list)
    for plan in plans:
        for row in read_jsonl(plan):
            bitcode = str(row.get("bitcode") or "")
            if not bitcode:
                continue
            for param in row.get("params") or []:
                if bitcode not in mapping[str(param)]:
                    mapping[str(param)].append(bitcode)
    return mapping


def source_bitcode(record: dict[str, Any], kernel_bc_root: Path) -> str | None:
    source = str(record.get("source_file") or "")
    if not source.endswith(".c"):
        return None
    candidate = kernel_bc_root / Path(source).with_suffix(".bc")
    return str(candidate) if candidate.exists() else None


def evidence_bitcodes(record: dict[str, Any]) -> list[str]:
    out: list[str] = []
    evidence = record.get("tfuzz_root_spec_evidence") or {}
    for candidate in evidence.get("candidates") or []:
        bitcode = str(candidate.get("bitcode") or "")
        if bitcode and bitcode not in out:
            out.append(bitcode)
    for step in evidence.get("debug_steps") or []:
        bitcode = str(step.get("bitcode") or "")
        if bitcode and bitcode not in out:
            out.append(bitcode)
    return out


def parse_geps(ir_text: str, bitcode: str) -> list[dict[str, Any]]:
    geps: list[dict[str, Any]] = []
    for lineno, raw in enumerate(ir_text.splitlines(), 1):
        match = GEP_RE.match(raw)
        if match is None:
            continue
        indices = [int(item) for item in IDX_RE.findall(match.group("rest"))]
        if not indices:
            continue
        struct = match.group("struct")
        geps.append(
            {
                "bitcode": bitcode,
                "field_root": ".".join([struct] + [str(index) for index in indices]),
                "indices": indices,
                "ir_line_number": lineno,
                "ir_snippet": raw.strip(),
                "ssa_name": match.group("ssa"),
                "struct_type": struct,
            }
        )
    return geps


def compact_candidates(candidates: list[dict[str, Any]], limit: int = 12) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in candidates:
        key = (str(item["field_root"]), str(item["bitcode"]), str(item["ssa_name"]))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= limit:
            break
    return out


def root_counts(candidates: list[dict[str, Any]]) -> dict[str, int]:
    counter = Counter(str(item["field_root"]) for item in candidates)
    return dict(sorted(counter.items()))


def validate_one(
    record: dict[str, Any],
    bitcodes_by_param: dict[str, list[str]],
    *,
    kernel_bc_root: Path,
    llvm_dis: Path,
) -> dict[str, Any]:
    param = str(record.get("param") or "")
    spec = record.get("conftainter_root_spec") or {}
    root = str(spec.get("var_name") or "")
    parsed = parse_field_root(root)
    if parsed is None:
        return {"param": param, "status": "invalid_field_root", "field_root": root}
    root_struct, root_indices = parsed
    tokens = expected_tokens(record)

    bitcodes: list[str] = []
    for source in [*bitcodes_by_param.get(param, []), *evidence_bitcodes(record)]:
        if source and source not in bitcodes:
            bitcodes.append(source)
    src_bc = source_bitcode(record, kernel_bc_root)
    if src_bc and src_bc not in bitcodes:
        bitcodes.append(src_bc)
    bitcodes = [path for path in bitcodes if Path(path).exists()]
    if not bitcodes:
        return {
            "param": param,
            "status": "no_bitcode",
            "field_root": root,
            "expected_tokens": tokens,
            "root_reason": record.get("tfuzz_root_spec_reason"),
        }

    named_candidates: list[dict[str, Any]] = []
    root_seen: list[dict[str, Any]] = []
    disasm_failures: list[str] = []
    for bitcode in bitcodes:
        ir_text = disassemble_cached(bitcode, str(llvm_dis))
        if ir_text is None:
            disasm_failures.append(bitcode)
            continue
        for gep in parse_geps(ir_text, bitcode):
            if gep["struct_type"] != root_struct:
                continue
            if gep["indices"] == root_indices:
                root_seen.append(gep)
            ssa = str(gep["ssa_name"])
            matched = [token for token in tokens if token and token in ssa]
            if matched:
                row = dict(gep)
                row["matched_tokens"] = matched
                named_candidates.append(row)

    named_roots = root_counts(named_candidates)
    root_seen_compact = compact_candidates(root_seen, 8)
    named_compact = compact_candidates(
        sorted(
            named_candidates,
            key=lambda row: (
                0 if row["field_root"] == root else 1,
                -len(row.get("matched_tokens") or []),
                str(row["field_root"]),
                str(row["bitcode"]),
            ),
        )
    )

    status = ""
    suggested_root = None
    confidence = "low"
    if named_candidates:
        if root in named_roots:
            status = "ok_named_gep"
            suggested_root = root
            confidence = "high"
        else:
            status = "mismatch_named_gep"
            suggested_root = Counter(str(item["field_root"]) for item in named_candidates).most_common(1)[0][0]
            confidence = "high" if len(named_roots) == 1 else "medium"
    elif root_seen:
        status = "no_named_gep_root_seen"
        confidence = "medium"
    else:
        status = "no_named_gep_no_root_seen"
        confidence = "low"

    return {
        "param": param,
        "status": status,
        "confidence": confidence,
        "field_root": root,
        "root_struct": root_struct,
        "root_indices": root_indices,
        "suggested_field_root": suggested_root,
        "suggested_root_counts": named_roots,
        "expected_tokens": tokens,
        "checked_bitcodes": bitcodes,
        "disasm_failures": disasm_failures,
        "named_gep_candidates": named_compact,
        "root_seen_candidates": root_seen_compact,
        "root_reason": record.get("tfuzz_root_spec_reason"),
        "backing_symbol": record.get("backing_symbol"),
        "source_file": record.get("source_file"),
    }


def auto_correction_allowed(validation: dict[str, Any]) -> bool:
    if (
        validation.get("status") != "mismatch_named_gep"
        or validation.get("confidence") != "high"
        or not validation.get("suggested_field_root")
    ):
        return False
    parsed_old = parse_field_root(str(validation.get("field_root") or ""))
    parsed_new = parse_field_root(str(validation.get("suggested_field_root") or ""))
    if parsed_old is None or parsed_new is None:
        return False
    if parsed_old[0] != parsed_new[0] or len(parsed_old[1]) != len(parsed_new[1]):
        return False
    if validation.get("root_reason") != "debug_metadata_field_path":
        return False
    return True


def corrected_records(
    roots: list[dict[str, Any]],
    validation_by_param: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in roots:
        param = str(row.get("param") or "")
        validation = validation_by_param.get(param)
        if validation and auto_correction_allowed(validation):
            row = dict(row)
            root_spec = {"var_type": "FIELD", "var_name": str(validation["suggested_field_root"])}
            row["conftainter_root_spec"] = root_spec
            row["llvm_root_spec"] = dict(root_spec)
            row["tfuzz_root_spec_status"] = "ready_corrected_field_root"
            row["tfuzz_root_spec_reason"] = "validated_llvm_gep_ssa_token_field_root"
            row["tfuzz_root_spec_evidence"] = {
                "confidence": "high",
                "field_root": validation["suggested_field_root"],
                "match_kind": "validated_llvm_gep_ssa_token_field_root",
                "previous_field_root": validation["field_root"],
                "expected_tokens": validation["expected_tokens"],
                "candidates": validation["named_gep_candidates"],
            }
        out.append(row)
    return out


def main() -> int:
    args = parse_args()
    plans = args.plan or DEFAULT_PLANS
    llvm_dis = choose_llvm_dis(args.llvm_dis)
    roots = read_jsonl(args.roots)
    field_roots = [
        row
        for row in roots
        if (row.get("conftainter_root_spec") or {}).get("var_type") == "FIELD"
    ]
    bitcodes_by_param = plan_bitcodes_by_param(plans)

    validations = [
        validate_one(row, bitcodes_by_param, kernel_bc_root=args.kernel_bc_root, llvm_dis=llvm_dis)
        for row in field_roots
    ]
    validation_by_param = {str(row["param"]): row for row in validations}
    write_jsonl(args.output, validations)

    if args.corrected_roots_output:
        write_jsonl(args.corrected_roots_output, corrected_records(roots, validation_by_param))

    mismatches = [row for row in validations if row["status"] == "mismatch_named_gep"]
    auto_correctable = [row for row in mismatches if auto_correction_allowed(row)]
    summary = {
        "roots": str(args.roots),
        "plans": [str(path) for path in plans],
        "kernel_bc_root": str(args.kernel_bc_root),
        "llvm_dis": str(llvm_dis),
        "input_root_count": len(roots),
        "field_root_count": len(field_roots),
        "status_counts": dict(Counter(row["status"] for row in validations)),
        "confidence_counts": dict(Counter(row.get("confidence") for row in validations)),
        "mismatch_count": len(mismatches),
        "high_confidence_mismatch_count": sum(1 for row in mismatches if row.get("confidence") == "high"),
        "auto_correctable_mismatch_count": len(auto_correctable),
        "mismatches": [
            {
                "param": row["param"],
                "field_root": row["field_root"],
                "suggested_field_root": row.get("suggested_field_root"),
                "confidence": row.get("confidence"),
                "root_reason": row.get("root_reason"),
                "expected_tokens": row.get("expected_tokens"),
            }
            for row in mismatches
        ],
        "outputs": {
            "validation_jsonl": str(args.output),
            "corrected_roots": str(args.corrected_roots_output) if args.corrected_roots_output else None,
        },
    }
    summary_path = args.summary_out or args.output.with_suffix(".summary.json")
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(summary_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
