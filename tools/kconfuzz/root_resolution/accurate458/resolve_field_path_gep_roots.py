#!/usr/bin/env python3
"""Resolve sysctl FIELD roots through source/debug field paths and LLVM GEPs.

The key invariant is conservative:

1. Source/debug/pahole evidence may identify the intended C field name/path.
2. The final ConfTainter/TFuzz FIELD root must come from an LLVM GEP index.
3. A root is auto-corrected only when the LLVM GEP candidate has the same
   struct and the same index depth as the current root, and the SSA name
   contains a non-generic leaf field token.

This keeps nested/array/aggregate cases visible in evidence without turning a
parent GEP such as `uts_namespace.0` into a leaf root such as
`uts_namespace.0.5`.
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
DEFAULT_ROOTS = (
    ROOT / "runs/tfuzz_root_specs_validated_gep_current/tfuzz_ready_strict_config_root.jsonl"
)
DEFAULT_PLAN = (
    ROOT / "runs/tfuzz_root_specs_validated_gep_current/target_plan/bitcode_plan.jsonl"
)
DEFAULT_KERNEL_BC_ROOT = WORKDIR / "linux-6.12.80-clang18-bc-clean"
DEFAULT_VMLINUX = WORKDIR / "linux-6.12.80/vmlinux"

GEP_RE = re.compile(
    r"^\s*%(?P<ssa>[A-Za-z0-9_.$]+)\s*=\s*getelementptr\s+(?:inbounds\s+)?"
    r"%struct\.(?P<struct>[A-Za-z0-9_.$]+),\s+ptr\s+[^,]+,\s+i(?:32|64)\s+0,\s+(?P<rest>.+)$"
)
IDX_RE = re.compile(r"i(?:32|64)\s+(\d+)")
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
FIELD_COMPONENT_RE = re.compile(
    r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:\[(?P<index>[^\]]+)\])?$"
)

GENERIC_TOKENS = {
    "all",
    "arp",
    "data",
    "default",
    "enable",
    "enabled",
    "flag",
    "flags",
    "hash",
    "ignore",
    "init",
    "ipv4",
    "ipv6",
    "mode",
    "name",
    "net",
    "range",
    "sysctl",
    "use",
    "value",
}

FIELD_TOKEN_ALIASES = {
    "init_net.ipv4.sysctl_ip_fwd_update_priority": "sysctl_ip_fwd_update_priority",
    "init_net.ipv4.sysctl_tcp_nometrics_save": "sysctl_tcp_nometrics_save",
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

BACKING_ALIASES = {
    "init_net.sctp.addip_noauth_enable": "netns_sctp.addip_noauth",
    "init_net.nf_conntrack_acct": "netns_ct.sysctl_acct",
    "init_net.nf_conntrack_checksum": "netns_ct.sysctl_checksum",
    "init_net.echo_ignore_all": "netns_sysctl_ipv6.icmpv6_echo_ignore_all",
    "init_net.echo_ignore_anycast": "netns_sysctl_ipv6.icmpv6_echo_ignore_anycast",
    "init_net.echo_ignore_multicast": "netns_sysctl_ipv6.icmpv6_echo_ignore_multicast",
    "init_net.error_anycast_as_unicast": "netns_sysctl_ipv6.icmpv6_error_anycast_as_unicast",
    "init_net.skip_notify_on_dev_down": "netns_sysctl_ipv6.skip_notify_on_dev_down",
    "init_net.txrehash": "netns_core.sysctl_txrehash",
    "nf_icmpv6_net.timeout": "nf_icmp_net.timeout",
    "ipv4_devconf.data[IPV4_DEVCONF_FORWARDING-1]": "in_device.cnf.data[IPV4_DEVCONF_FORWARDING-1]",
}

BACKING_PREFIX_STRUCTS = (
    ("init_ipc_ns.", "ipc_namespace."),
    ("init_user_ns.", "user_namespace."),
    ("init_uts_ns.", "uts_namespace."),
    ("init_pid_ns.", "pid_namespace."),
    ("files_stat.", "files_stat_struct."),
    ("init_net.sctp.", "netns_sctp."),
    ("init_net.core.", "netns_core."),
    ("init_net.xfrm.", "netns_xfrm."),
    ("init_net.ipv4.", "netns_ipv4."),
    ("init_net.ipv6.", "netns_ipv6."),
    ("init_net.ct.", "netns_ct."),
    ("init_net.unx.", "netns_unix."),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--roots", type=Path, default=DEFAULT_ROOTS)
    parser.add_argument("--plan", type=Path, action="append", default=[])
    parser.add_argument("--kernel-bc-root", type=Path, default=DEFAULT_KERNEL_BC_ROOT)
    parser.add_argument("--vmlinux", type=Path, default=DEFAULT_VMLINUX)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--llvm-dis", type=Path)
    parser.add_argument("--pahole", type=Path)
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


def choose_tool(explicit: Path | None, *names: str) -> Path | None:
    if explicit is not None:
        return explicit
    for name in names:
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


def normalize_backing(text: str | None) -> str:
    if text is None:
        return ""
    value = re.sub(r"\s+", "", str(text))
    value = re.sub(r"^\(\s*void\s*\*\s*\)", "", value)
    while value.startswith("&"):
        value = value[1:]
    return value


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


def normalize_token(token: Any) -> str:
    text = str(token or "").strip()
    text = re.sub(r"^proc_", "", text)
    return text


def add_token(tokens: list[str], token: Any, *, strong: bool = False) -> None:
    text = normalize_token(token)
    if not text or text == "None":
        return
    if text.lower() in GENERIC_TOKENS:
        return
    if not strong and len(text) < 4:
        return
    if not IDENT_RE.fullmatch(text):
        return
    if text not in tokens:
        tokens.append(text)


def parse_field_component(component: str) -> dict[str, Any] | None:
    match = FIELD_COMPONENT_RE.match(component)
    if match is None:
        return None
    return {"name": match.group("name"), "array_index_expr": match.group("index")}


def parse_field_path(path: str) -> dict[str, Any] | None:
    components = [parse_field_component(part) for part in path.split(".") if part]
    if not components or any(component is None for component in components):
        return None
    typed = [component for component in components if component is not None]
    if len(typed) < 2:
        return None
    return {
        "struct_type": typed[0]["name"],
        "components": typed[1:],
        "field_names": [str(component["name"]) for component in typed[1:]],
        "leaf_field": str(typed[-1]["name"]),
        "raw_path": path,
    }


def normalized_struct_paths(record: dict[str, Any]) -> list[dict[str, Any]]:
    backing = normalize_backing(record.get("backing_symbol"))
    paths: list[str] = []
    alias = BACKING_ALIASES.get(backing)
    if alias:
        paths.append(alias)
    for prefix, replacement in BACKING_PREFIX_STRUCTS:
        if backing.startswith(prefix):
            paths.append(replacement + backing[len(prefix) :])
            break
    if backing.startswith("init_net."):
        paths.append("net." + backing[len("init_net.") :])

    source_file = str(record.get("source_file") or "")
    if source_file == "net/ipv4/sysctl_net_ipv4.c" and backing.startswith("init_net."):
        suffix = backing.removeprefix("init_net.")
        if not suffix.startswith(("ipv4.", "core.", "xfrm.", "sctp.", "ct.")):
            paths.append(f"netns_ipv4.sysctl_{suffix}")

    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\.", backing):
        paths.append(backing)

    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in paths:
        parsed = parse_field_path(path)
        if parsed is None or parsed["raw_path"] in seen:
            continue
        seen.add(parsed["raw_path"])
        out.append(parsed)
    return out


def field_path_evidence(record: dict[str, Any], current_root: str) -> dict[str, Any]:
    evidence = record.get("tfuzz_root_spec_evidence") or {}
    debug_steps = list(evidence.get("debug_steps") or [])
    parsed_current = parse_field_root(current_root)
    current_struct = parsed_current[0] if parsed_current else evidence.get("struct_type")

    debug_path = None
    debug_leaf = None
    debug_ordinals: list[int] = []
    if current_struct and debug_steps:
        parts = [str(current_struct)]
        for step in debug_steps:
            field = step.get("field")
            if not field:
                continue
            if "array_index" in step:
                parts.append(f"{field}[{step['array_index']}]")
            else:
                parts.append(str(field))
            if "field_index" in step:
                debug_ordinals.append(int(step["field_index"]))
            debug_leaf = str(field)
        if len(parts) > 1:
            debug_path = ".".join(parts)

    backing_paths = normalized_struct_paths(record)
    field_names: list[str] = []
    leaf_tokens: list[str] = []
    path_tokens: list[str] = []

    for step in debug_steps:
        field = step.get("field")
        add_token(path_tokens, field, strong=True)
        field_names.append(str(field)) if field else None
    add_token(leaf_tokens, debug_leaf, strong=True)

    for path in backing_paths:
        for name in path["field_names"]:
            add_token(path_tokens, name, strong=True)
        add_token(leaf_tokens, path["leaf_field"], strong=True)
        if path["leaf_field"].startswith("sysctl_"):
            add_token(leaf_tokens, path["leaf_field"].removeprefix("sysctl_"), strong=True)

    backing = normalize_backing(record.get("backing_symbol"))
    alias = FIELD_TOKEN_ALIASES.get(backing)
    add_token(leaf_tokens, alias, strong=True)
    if alias and alias.startswith("sysctl_"):
        add_token(leaf_tokens, alias.removeprefix("sysctl_"), strong=True)

    if backing:
        for bracketed in re.findall(r"\[([A-Za-z_][A-Za-z0-9_]*)", backing):
            add_token(path_tokens, bracketed, strong=True)
        leaf = re.split(r"[.\[]", backing)[-1].rstrip("]")
        add_token(leaf_tokens, leaf, strong=True)
        if not leaf.startswith("sysctl_"):
            add_token(leaf_tokens, "sysctl_" + leaf, strong=True)
        add_token(path_tokens, leaf, strong=True)

    param = str(record.get("param") or "")
    dotted = str(record.get("dotted_name") or "")
    if param:
        add_token(leaf_tokens, param.split("/")[-1], strong=True)
    if dotted:
        add_token(leaf_tokens, dotted.split(".")[-1], strong=True)

    # The GEP search should see both leaf-specific and path tokens, but auto
    # correction only trusts candidates that match a leaf token.
    gep_tokens: list[str] = []
    for token in [*leaf_tokens, *path_tokens]:
        add_token(gep_tokens, token, strong=True)

    return {
        "backing_symbol": backing,
        "debug_field_path": debug_path,
        "debug_leaf_field": debug_leaf,
        "debug_ordinals": debug_ordinals,
        "normalized_struct_paths": backing_paths,
        "field_names": sorted(set(field_names)),
        "leaf_tokens": leaf_tokens,
        "path_tokens": path_tokens,
        "gep_tokens": gep_tokens,
        "source_file": record.get("source_file"),
    }


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


def same_depth_roots(candidates: list[dict[str, Any]], root_indices: list[int]) -> list[dict[str, Any]]:
    return [row for row in candidates if len(row.get("indices") or []) == len(root_indices)]


@lru_cache(maxsize=128)
def pahole_struct_fields(pahole: str, vmlinux: str, struct_type: str) -> dict[str, Any] | None:
    if not Path(vmlinux).exists():
        return None
    try:
        proc = subprocess.run(
            [pahole, "-C", struct_type, vmlinux],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return None
    if proc.returncode != 0:
        return None

    fields: list[dict[str, Any]] = []
    for raw in proc.stdout.splitlines():
        if "/*" not in raw or ";" not in raw:
            continue
        decl = raw.split("/*", 1)[0].strip()
        decl = decl.rstrip(";").strip()
        decl = re.sub(r"\s+__attribute__\(\(.*?\)\)", "", decl).strip()
        match = re.search(
            r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*(?::\s*\d+)?$",
            decl,
        )
        if match is None:
            continue
        name = match.group("name")
        if name in {"struct", "union"}:
            continue
        fields.append({"ordinal": len(fields), "field": name, "decl": decl})
    return {"struct_type": struct_type, "field_count": len(fields), "fields": fields}


def dwarf_matches(
    struct_type: str,
    leaf_tokens: list[str],
    path_tokens: list[str],
    *,
    pahole: Path | None,
    vmlinux: Path | None,
) -> list[dict[str, Any]]:
    if pahole is None or vmlinux is None or not vmlinux.exists():
        return []
    layout = pahole_struct_fields(str(pahole), str(vmlinux), struct_type)
    if not layout:
        return []
    tokens: list[str] = []
    for token in [*leaf_tokens, *path_tokens]:
        if token not in tokens:
            tokens.append(token)
    leaf_out: list[dict[str, Any]] = []
    path_out: list[dict[str, Any]] = []
    for field in layout["fields"]:
        name = str(field["field"])
        matched = [token for token in tokens if token and token in name]
        if not matched:
            continue
        row = dict(field)
        row["matched_tokens"] = matched
        row["leaf_token_match"] = any(token in name for token in leaf_tokens)
        if row["leaf_token_match"]:
            leaf_out.append(row)
        else:
            path_out.append(row)
    return (leaf_out or path_out)[:16]


def classify_resolution(
    *,
    current_root: str,
    root_struct: str,
    root_indices: list[int],
    candidates: list[dict[str, Any]],
    current_root_seen: list[dict[str, Any]],
    root_reason: str | None,
) -> dict[str, Any]:
    leaf_candidates = [row for row in candidates if row.get("leaf_token_match")]
    same_depth_leaf = same_depth_roots(leaf_candidates, root_indices)

    if current_root in root_counts(leaf_candidates):
        return {
            "resolution_kind": "validated_current_root",
            "suggested_field_root": current_root,
            "confidence": "high",
            "auto_correctable": False,
            "auto_correct_reason": "current root already has a leaf-token LLVM GEP",
        }

    if same_depth_leaf:
        counts = root_counts(same_depth_leaf)
        if len(counts) == 1:
            suggested = next(iter(counts))
            auto = root_reason == "debug_metadata_field_path"
            return {
                "resolution_kind": "same_depth_leaf_gep_mismatch",
                "suggested_field_root": suggested,
                "confidence": "high",
                "auto_correctable": bool(auto),
                "auto_correct_reason": (
                    "same struct/depth leaf-token LLVM GEP"
                    if auto
                    else "same-depth GEP exists but original root was not debug_metadata_field_path"
                ),
            }
        return {
            "resolution_kind": "ambiguous_same_depth_leaf_gep",
            "suggested_field_root": None,
            "confidence": "medium",
            "auto_correctable": False,
            "auto_correct_reason": "multiple same-depth leaf-token LLVM GEP roots",
        }

    if leaf_candidates:
        return {
            "resolution_kind": "aggregate_or_nested_leaf_gep",
            "suggested_field_root": Counter(str(row["field_root"]) for row in leaf_candidates).most_common(1)[0][0],
            "confidence": "medium",
            "auto_correctable": False,
            "auto_correct_reason": "LLVM GEP matches leaf token but index depth differs",
        }

    if candidates:
        return {
            "resolution_kind": "aggregate_or_parent_only_gep",
            "suggested_field_root": Counter(str(row["field_root"]) for row in candidates).most_common(1)[0][0],
            "confidence": "low",
            "auto_correctable": False,
            "auto_correct_reason": "LLVM GEP only matched parent/path token, not leaf token",
        }

    if current_root_seen:
        return {
            "resolution_kind": "current_root_seen_without_field_name",
            "suggested_field_root": current_root,
            "confidence": "medium",
            "auto_correctable": False,
            "auto_correct_reason": "current root GEP exists but field name was not visible in SSA",
        }

    return {
        "resolution_kind": "no_named_gep",
        "suggested_field_root": None,
        "confidence": "low",
        "auto_correctable": False,
        "auto_correct_reason": "no LLVM GEP matched the derived field tokens",
    }


def resolve_one(
    record: dict[str, Any],
    bitcodes_by_param: dict[str, list[str]],
    *,
    kernel_bc_root: Path,
    llvm_dis: Path,
    pahole: Path | None,
    vmlinux: Path | None,
) -> dict[str, Any]:
    param = str(record.get("param") or "")
    spec = record.get("conftainter_root_spec") or {}
    current_root = str(spec.get("var_name") or "")
    parsed = parse_field_root(current_root)
    if parsed is None:
        return {
            "param": param,
            "resolution_kind": "invalid_field_root",
            "field_root": current_root,
            "auto_correctable": False,
        }

    root_struct, root_indices = parsed
    path_evidence = field_path_evidence(record, current_root)
    leaf_tokens = list(path_evidence["leaf_tokens"])
    path_tokens = list(path_evidence["path_tokens"])
    gep_tokens = list(path_evidence["gep_tokens"])

    bitcodes: list[str] = []
    for source in [*bitcodes_by_param.get(param, []), *evidence_bitcodes(record)]:
        if source and source not in bitcodes:
            bitcodes.append(source)
    src_bc = source_bitcode(record, kernel_bc_root)
    if src_bc and src_bc not in bitcodes:
        bitcodes.append(src_bc)
    bitcodes = [path for path in bitcodes if Path(path).exists()]

    named_candidates: list[dict[str, Any]] = []
    current_root_seen: list[dict[str, Any]] = []
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
                current_root_seen.append(gep)
            ssa = str(gep["ssa_name"])
            matched_leaf = [token for token in leaf_tokens if token and token in ssa]
            matched_path = [token for token in path_tokens if token and token in ssa]
            matched_all = [token for token in gep_tokens if token and token in ssa]
            if not matched_all:
                continue
            row = dict(gep)
            row["matched_tokens"] = matched_all
            row["matched_leaf_tokens"] = matched_leaf
            row["matched_path_tokens"] = matched_path
            row["leaf_token_match"] = bool(matched_leaf)
            named_candidates.append(row)

    named_candidates.sort(
        key=lambda row: (
            0 if row.get("leaf_token_match") else 1,
            abs(len(row.get("indices") or []) - len(root_indices)),
            str(row["field_root"]),
            str(row["bitcode"]),
        )
    )
    current_root_seen.sort(key=lambda row: (str(row["bitcode"]), int(row["ir_line_number"])))

    resolution = classify_resolution(
        current_root=current_root,
        root_struct=root_struct,
        root_indices=root_indices,
        candidates=named_candidates,
        current_root_seen=current_root_seen,
        root_reason=record.get("tfuzz_root_spec_reason"),
    )
    dwarf = dwarf_matches(
        root_struct,
        leaf_tokens,
        path_tokens,
        pahole=pahole,
        vmlinux=vmlinux,
    )

    return {
        "param": param,
        "field_root": current_root,
        "root_struct": root_struct,
        "root_indices": root_indices,
        "root_reason": record.get("tfuzz_root_spec_reason"),
        "backing_symbol": record.get("backing_symbol"),
        "source_file": record.get("source_file"),
        "field_path_evidence": path_evidence,
        "dwarf_layout_matches": dwarf,
        "checked_bitcodes": bitcodes,
        "disasm_failures": disasm_failures,
        "named_gep_root_counts": root_counts(named_candidates),
        "named_gep_candidates": compact_candidates(named_candidates),
        "current_root_seen_candidates": compact_candidates(current_root_seen, 8),
        **resolution,
    }


def corrected_records(
    roots: list[dict[str, Any]],
    validation_by_param: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in roots:
        param = str(row.get("param") or "")
        validation = validation_by_param.get(param)
        if validation and validation.get("auto_correctable") and validation.get("suggested_field_root"):
            row = dict(row)
            previous_root = (row.get("conftainter_root_spec") or {}).get("var_name")
            root_spec = {"var_type": "FIELD", "var_name": str(validation["suggested_field_root"])}
            row["conftainter_root_spec"] = root_spec
            row["llvm_root_spec"] = dict(root_spec)
            row["tfuzz_root_spec_status"] = "ready_corrected_field_root"
            row["tfuzz_root_spec_reason"] = "validated_field_path_to_llvm_gep_root"
            row["tfuzz_root_spec_evidence"] = {
                "confidence": validation.get("confidence"),
                "field_root": validation["suggested_field_root"],
                "match_kind": "validated_field_path_to_llvm_gep_root",
                "previous_field_root": previous_root,
                "field_path_evidence": validation.get("field_path_evidence"),
                "named_gep_candidates": validation.get("named_gep_candidates"),
            }
        out.append(row)
    return out


def main() -> int:
    args = parse_args()
    plans = args.plan or [DEFAULT_PLAN]
    llvm_dis = choose_tool(args.llvm_dis, "llvm-dis-18", "llvm-dis")
    if llvm_dis is None:
        raise SystemExit("llvm-dis not found")
    pahole = choose_tool(args.pahole, "pahole")
    vmlinux = args.vmlinux if args.vmlinux.exists() else None

    roots = read_jsonl(args.roots)
    field_roots = [
        row
        for row in roots
        if (row.get("conftainter_root_spec") or {}).get("var_type") == "FIELD"
    ]
    bitcodes_by_param = plan_bitcodes_by_param(plans)

    validations = [
        resolve_one(
            row,
            bitcodes_by_param,
            kernel_bc_root=args.kernel_bc_root,
            llvm_dis=llvm_dis,
            pahole=pahole,
            vmlinux=vmlinux,
        )
        for row in field_roots
    ]
    validation_by_param = {str(row["param"]): row for row in validations}

    out_dir = args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    validation_path = out_dir / "field_path_gep_resolution.jsonl"
    corrected_path = out_dir / "tfuzz_ready_strict_config_root.field_path_gep_corrected.jsonl"
    summary_path = out_dir / "summary.json"
    write_jsonl(validation_path, validations)
    write_jsonl(corrected_path, corrected_records(roots, validation_by_param))

    resolution_counts = Counter(str(row.get("resolution_kind")) for row in validations)
    auto_correctable = [row for row in validations if row.get("auto_correctable")]
    summary = {
        "roots": str(args.roots),
        "plans": [str(path) for path in plans],
        "kernel_bc_root": str(args.kernel_bc_root),
        "llvm_dis": str(llvm_dis),
        "pahole": str(pahole) if pahole else None,
        "vmlinux": str(vmlinux) if vmlinux else None,
        "input_root_count": len(roots),
        "field_root_count": len(field_roots),
        "resolution_counts": dict(sorted(resolution_counts.items())),
        "confidence_counts": dict(Counter(str(row.get("confidence")) for row in validations)),
        "auto_correctable_count": len(auto_correctable),
        "auto_correctable": [
            {
                "param": row["param"],
                "field_root": row["field_root"],
                "suggested_field_root": row.get("suggested_field_root"),
                "leaf_tokens": row.get("field_path_evidence", {}).get("leaf_tokens"),
                "root_reason": row.get("root_reason"),
            }
            for row in auto_correctable
        ],
        "outputs": {
            "resolution_jsonl": str(validation_path),
            "corrected_roots": str(corrected_path),
            "summary": str(summary_path),
        },
    }
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(summary_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
