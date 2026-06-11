#!/usr/bin/env python3
"""Build TFuzz-consumable root specs from runtime config-root records.

This is a workdir-local staging tool. It does not modify the original
ConfTainter/TFuzz checkout and does not run TFuzz. Its job is to separate:

  runtime param -> root spec is ready for TFuzz

from:

  runtime param -> source-level root exists, but still needs LLVM FIELD index
  resolution or is an action/handler-only sysctl with no durable storage root.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Any

from infer_field_roots_from_bitcode import infer_candidates


DEFAULT_WORKDIR = Path("/home/wang/syzkaller_workdir")
DEFAULT_ROOTS = (
    DEFAULT_WORKDIR
    / "kconfuzz_relation_repro/runs/runtime_root_mapping_current/config_root.runtime_full.jsonl"
)
DEFAULT_KERNEL_BC_ROOT = DEFAULT_WORKDIR / "linux-6.12.80-clang18-bc-clean"
DEFAULT_KERNEL_SOURCE_ROOT = DEFAULT_KERNEL_BC_ROOT
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.$]*$")
GENERIC_FIELD_VALIDATION_TOKENS = {
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
    "mode",
    "net",
    "sysctl",
    "use",
    "value",
}

DEBUG_STRUCT_RE = re.compile(
    r"^!(?P<id>\d+) = (?:distinct )?!DICompositeType\(tag: DW_TAG_structure_type, name: \"(?P<name>[^\"]+)\".*elements: !(?P<elements>\d+)"
)
DEBUG_ARRAY_RE = re.compile(
    r"^!(?P<id>\d+) = (?:distinct )?!DICompositeType\(tag: DW_TAG_array_type, .*baseType: !(?P<base>\d+)"
)
DEBUG_ELEMENTS_RE = re.compile(r"^!(?P<id>\d+) = !\{(?P<body>.*)\}$")
DEBUG_MEMBER_RE = re.compile(
    r"^!(?P<id>\d+) = !DIDerivedType\(tag: DW_TAG_member, name: \"(?P<name>[^\"]+)\", scope: !(?P<scope>\d+).*?(?:baseType: !(?P<base>\d+))?"
)
DEBUG_DERIVED_BASE_RE = re.compile(r"^!(?P<id>\d+) = !DIDerivedType\(.*baseType: !(?P<base>\d+)")
FIELD_COMPONENT_RE = re.compile(
    r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:\[(?P<index>[^\]]+)\])?$"
)

NEIGH_ENUM_INDICES = {
    "NEIGH_VAR_MCAST_PROBES": 0,
    "NEIGH_VAR_UCAST_PROBES": 1,
    "NEIGH_VAR_APP_PROBES": 2,
    "NEIGH_VAR_MCAST_REPROBES": 3,
    "NEIGH_VAR_RETRANS_TIME": 4,
    "NEIGH_VAR_RETRANS_TIME_MS": 4,
    "NEIGH_VAR_BASE_REACHABLE_TIME": 5,
    "NEIGH_VAR_BASE_REACHABLE_TIME_MS": 5,
    "NEIGH_VAR_DELAY_PROBE_TIME": 6,
    "NEIGH_VAR_INTERVAL_PROBE_TIME_MS": 7,
    "NEIGH_VAR_GC_STALETIME": 8,
    "NEIGH_VAR_QUEUE_LEN_BYTES": 9,
    "NEIGH_VAR_QUEUE_LEN": 9,
    "NEIGH_VAR_PROXY_QLEN": 10,
    "NEIGH_VAR_ANYCAST_DELAY": 11,
    "NEIGH_VAR_PROXY_DELAY": 12,
    "NEIGH_VAR_LOCKTIME": 13,
}
NEIGH_TABLE_FIELD_INDICES = {
    "gc_interval": 15,
    "gc_thresh1": 16,
    "gc_thresh2": 17,
    "gc_thresh3": 18,
}
ENUM_VALUE_MAP = {
    **NEIGH_ENUM_INDICES,
    "IPV4_DEVCONF_FORWARDING": 1,
    "TCP_CONNTRACK_NONE": 0,
    "TCP_CONNTRACK_SYN_SENT": 1,
    "TCP_CONNTRACK_SYN_RECV": 2,
    "TCP_CONNTRACK_ESTABLISHED": 3,
    "TCP_CONNTRACK_FIN_WAIT": 4,
    "TCP_CONNTRACK_CLOSE_WAIT": 5,
    "TCP_CONNTRACK_LAST_ACK": 6,
    "TCP_CONNTRACK_TIME_WAIT": 7,
    "TCP_CONNTRACK_CLOSE": 8,
    "TCP_CONNTRACK_LISTEN": 9,
    "TCP_CONNTRACK_IGNORE": 11,
    "TCP_CONNTRACK_RETRANS": 12,
    "TCP_CONNTRACK_UNACK": 13,
    "TCP_CONNTRACK_MAX_RETRANS": 12,
    "TCP_CONNTRACK_UNACKNOWLEDGED": 13,
    "UDP_CT_UNREPLIED": 0,
    "UDP_CT_REPLIED": 1,
    "CT_DCCP_NONE": 0,
    "CT_DCCP_REQUEST": 1,
    "CT_DCCP_RESPOND": 2,
    "CT_DCCP_PARTOPEN": 3,
    "CT_DCCP_OPEN": 4,
    "CT_DCCP_CLOSEREQ": 5,
    "CT_DCCP_CLOSING": 6,
    "CT_DCCP_TIMEWAIT": 7,
    "SCTP_CONNTRACK_NONE": 0,
    "SCTP_CONNTRACK_CLOSED": 1,
    "SCTP_CONNTRACK_COOKIE_WAIT": 2,
    "SCTP_CONNTRACK_COOKIE_ECHOED": 3,
    "SCTP_CONNTRACK_ESTABLISHED": 4,
    "SCTP_CONNTRACK_SHUTDOWN_SENT": 5,
    "SCTP_CONNTRACK_SHUTDOWN_RECD": 6,
    "SCTP_CONNTRACK_SHUTDOWN_ACK_SENT": 7,
    "SCTP_CONNTRACK_HEARTBEAT_SENT": 8,
    "SCTP_CONNTRACK_HEARTBEAT_ACKED": 9,
    "GRE_CT_UNREPLIED": 0,
    "GRE_CT_REPLIED": 1,
    "UCOUNT_USER_NAMESPACES": 0,
    "UCOUNT_PID_NAMESPACES": 1,
    "UCOUNT_UTS_NAMESPACES": 2,
    "UCOUNT_IPC_NAMESPACES": 3,
    "UCOUNT_NET_NAMESPACES": 4,
    "UCOUNT_MNT_NAMESPACES": 5,
    "UCOUNT_CGROUP_NAMESPACES": 6,
    "UCOUNT_TIME_NAMESPACES": 7,
    "UCOUNT_INOTIFY_INSTANCES": 8,
    "UCOUNT_INOTIFY_WATCHES": 9,
    "UCOUNT_FANOTIFY_GROUPS": 10,
    "UCOUNT_FANOTIFY_MARKS": 11,
    "DQST_LOOKUPS": 0,
    "DQST_DROPS": 1,
    "DQST_READS": 2,
    "DQST_WRITES": 3,
    "DQST_CACHE_HITS": 4,
    "DQST_ALLOC_DQUOTS": 5,
    "DQST_FREE_DQUOTS": 6,
    "DQST_SYNCS": 7,
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
    "ipv4_devconf.data[IPV4_DEVCONF_FORWARDING-1]": "in_device.21.1.0",
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
XFS_PARAM_FIELD_INDICES = {
    "sgid_inherit": 0,
    "symlink_mode": 1,
    "panic_mask": 2,
    "error_level": 3,
    "syncd_timer": 4,
    "stats_clear": 5,
    "inherit_sync": 6,
    "inherit_nodump": 7,
    "inherit_noatim": 8,
    "xfs_buf_timer": 9,
    "xfs_buf_age": 10,
    "inherit_nosym": 11,
    "rotorstep": 12,
    "inherit_nodfrg": 13,
    "fstrm_timer": 14,
    "blockgc_timer": 15,
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
EXPECTED_STRUCT_PREFIXES = {
    "init_net.sctp.": {"netns_sctp"},
    "init_net.core.": {"netns_core"},
    "init_net.xfrm.": {"netns_xfrm", "dst_ops"},
    "init_net.ipv4.": {"netns_ipv4", "fqdir", "ping_group_range"},
    "init_net.ipv6.": {"netns_ipv6", "netns_sysctl_ipv6", "fqdir"},
    "init_net.ct.": {"netns_ct"},
    "init_net.unx.": {"netns_unix"},
    "init_ipc_ns.": {"ipc_namespace"},
    "init_user_ns.": {"user_namespace"},
    "init_uts_ns.": {"uts_namespace"},
    "init_pid_ns.": {"pid_namespace"},
    "files_stat.": {"files_stat_struct"},
    "mptcp_pernet.": {"mptcp_pernet"},
    "nf_conntrack_net.": {"nf_conntrack_net"},
    "nf_tcp_net.": {"nf_tcp_net"},
    "nf_udp_net.": {"nf_udp_net"},
    "nf_dccp_net.": {"nf_dccp_net"},
    "nf_sctp_net.": {"nf_sctp_net"},
    "nf_generic_net.": {"nf_generic_net"},
    "nf_icmp_net.": {"nf_icmp_net"},
    "nf_icmpv6_net.": {"nf_icmpv6_net"},
    "nft_ct_frag6_pernet.": {"nft_ct_frag6_pernet"},
    "neigh_parms.": {"neigh_parms"},
    "neigh_table.": {"neigh_table"},
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--roots", type=Path, default=DEFAULT_ROOTS)
    parser.add_argument("--kernel-bc-root", type=Path, default=DEFAULT_KERNEL_BC_ROOT)
    parser.add_argument("--kernel-source-root", type=Path, default=DEFAULT_KERNEL_SOURCE_ROOT)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--infer-field-roots",
        action="store_true",
        help="Resolve STRUCT roots into TFuzz FIELD roots using source .bc metadata and GEPs.",
    )
    parser.add_argument(
        "--validate-single-symbols",
        action="store_true",
        help="For SINGLE roots, disassemble the source .bc and check whether @symbol is referenced.",
    )
    parser.add_argument(
        "--validate-field-roots-against-gep",
        action="store_true",
        help="For FIELD roots, verify the root index against same-bitcode named LLVM GEPs.",
    )
    parser.add_argument(
        "--auto-correct-field-roots",
        action="store_true",
        help="When FIELD validation finds one high-confidence named GEP root, replace the root with it.",
    )
    parser.add_argument("--llvm-dis", type=Path)
    return parser.parse_args()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if raw:
            rows.append(json.loads(raw))
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def choose_tool(explicit: Path | None, *candidates: str) -> Path | None:
    if explicit is not None:
        return explicit
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return Path(found)
    return None


def source_to_bc(source_file: str | None, kernel_bc_root: Path) -> Path | None:
    if not source_file:
        return None
    source = Path(source_file)
    if source.suffix != ".c":
        return None
    candidate = kernel_bc_root / source.with_suffix(".bc")
    return candidate if candidate.exists() else None


def classify_blocked_field(record: dict[str, Any]) -> str:
    param = str(record.get("param", ""))
    backing = str(record.get("backing_symbol") or "")
    source_file = str(record.get("source_file") or "")

    if not backing or backing == "None":
        if any(param.endswith(suffix) for suffix in ("/flush", "/register", "/status")):
            return "action_or_virtual_param_without_storage"
        return "missing_backing_symbol"
    if "neigh_parms.data[" in backing or param.startswith(("net/ipv4/neigh/", "net/ipv6/neigh/")):
        return "needs_neigh_array_enum_to_field_root"
    if backing.startswith("init_net."):
        return "needs_init_net_field_path_to_field_root"
    if backing.startswith(("nf_", "nft_", "xt_")) or source_file.startswith("net/netfilter/"):
        return "needs_netfilter_struct_field_root"
    if backing.startswith("mptcp_pernet."):
        return "needs_mptcp_struct_field_root"
    if backing.startswith("nft_ct_frag6_pernet."):
        return "needs_nf_frag6_struct_field_root"
    if backing.startswith(("ipv4_devconf.", "ipv6_devconf.")):
        return "needs_devconf_field_root"
    if "." in backing or "[" in backing:
        return "needs_generic_struct_field_root"
    return "unsupported_struct_root_shape"


def single_symbol_seen(bitcode: Path, symbol: str, llvm_dis: Path | None) -> str:
    if llvm_dis is None:
        return "not_checked_missing_llvm_dis"
    try:
        proc = subprocess.run(
            [str(llvm_dis), str(bitcode), "-o", "-"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return "not_checked_disassemble_timeout"
    if proc.returncode != 0:
        return "not_checked_disassemble_failed"
    pattern = re.compile(rf"@{re.escape(symbol)}\b")
    return "symbol_referenced_in_source_bc" if pattern.search(proc.stdout) else "symbol_not_seen_in_source_bc"


def normalize_backing(backing: str) -> str:
    return re.sub(r"\s+", "", backing)


def normalize_token(token: str) -> str:
    token = re.sub(r"^sysctl_", "", token)
    token = re.sub(r"^proc_", "", token)
    return token


def derive_tokens(record: dict[str, Any]) -> list[str]:
    tokens: list[str] = []
    param = str(record.get("param", ""))
    dotted = str(record.get("dotted_name") or "")
    backing = normalize_backing(str(record.get("backing_symbol") or ""))
    sources = [
        param.split("/")[-1],
        dotted.split(".")[-1] if dotted else "",
        backing.split(".")[-1] if backing else "",
        backing.rsplit("_", 1)[-1] if "_" in backing else "",
    ]
    for bracketed in re.findall(r"\[([A-Za-z_][A-Za-z0-9_]*)\]", backing):
        sources.append(bracketed)
        sources.append(bracketed.lower())
    for source in sources:
        source = normalize_token(source)
        if source and len(source) >= 3 and source not in tokens:
            tokens.append(source)
    return tokens


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


def add_validation_token(tokens: list[str], token: Any) -> None:
    if token is None:
        return
    text = str(token).strip()
    if not text or text == "None":
        return
    text = re.sub(r"^proc_", "", text)
    if text.lower() in GENERIC_FIELD_VALIDATION_TOKENS:
        return
    if not IDENT_RE.match(text):
        return
    if text not in tokens:
        tokens.append(text)


def field_validation_tokens(record: dict[str, Any], evidence: dict[str, Any] | None) -> list[str]:
    tokens: list[str] = []
    evidence = evidence or {}
    add_validation_token(tokens, evidence.get("field"))
    for step in evidence.get("debug_steps") or []:
        add_validation_token(tokens, step.get("field"))

    backing = normalize_backing(str(record.get("backing_symbol") or ""))
    alias = FIELD_TOKEN_ALIASES.get(backing)
    add_validation_token(tokens, alias)
    if backing.startswith("init_net.ipv4."):
        leaf = backing.removeprefix("init_net.ipv4.").split(".")[-1]
        add_validation_token(tokens, leaf)
        if not leaf.startswith("sysctl_"):
            add_validation_token(tokens, "sysctl_" + leaf)
    elif backing.startswith("init_net."):
        add_validation_token(tokens, backing.split(".")[-1])
    elif "." in backing:
        add_validation_token(tokens, backing.split(".")[-1])

    param = str(record.get("param") or "")
    if param:
        add_validation_token(tokens, param.split("/")[-1])
    dotted = str(record.get("dotted_name") or "")
    if dotted:
        add_validation_token(tokens, dotted.split(".")[-1])

    return tokens


def compact_gep_candidates(candidates: list[dict[str, Any]], limit: int = 12) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for candidate in candidates:
        key = (str(candidate.get("field_root")), str(candidate.get("ssa_name")))
        if key in seen:
            continue
        seen.add(key)
        output.append(
            {
                "field_root": candidate.get("field_root"),
                "struct_type": candidate.get("struct_type"),
                "indices": candidate.get("indices"),
                "matched_tokens": candidate.get("matched_tokens"),
                "ssa_name": candidate.get("ssa_name"),
                "ir_line_number": candidate.get("ir_line_number"),
                "ir_snippet": candidate.get("ir_snippet"),
            }
        )
        if len(output) >= limit:
            break
    return output


def validate_field_root_against_gep(
    record: dict[str, Any],
    root_spec: dict[str, str],
    evidence: dict[str, Any] | None,
    *,
    bitcode: Path | None,
    llvm_dis: Path | None,
) -> dict[str, Any]:
    root = str(root_spec.get("var_name") or "")
    parsed = parse_field_root(root)
    if parsed is None:
        return {"status": "invalid_field_root", "field_root": root, "confidence": "low"}
    root_struct, _root_indices = parsed
    tokens = field_validation_tokens(record, evidence)
    if bitcode is None:
        return {
            "status": "no_source_bitcode",
            "field_root": root,
            "root_struct": root_struct,
            "expected_tokens": tokens,
            "confidence": "low",
        }
    ir_text = disassemble_ir(bitcode, llvm_dis)
    if ir_text is None:
        return {
            "status": "disassemble_failed",
            "field_root": root,
            "root_struct": root_struct,
            "expected_tokens": tokens,
            "source_bitcode": str(bitcode),
            "confidence": "low",
        }
    candidates, _summary = infer_candidates(ir_text, tokens, str(record.get("param") or ""))
    same_struct = [candidate for candidate in candidates if candidate.get("struct_type") == root_struct]
    named_roots = Counter(str(candidate.get("field_root")) for candidate in same_struct if candidate.get("field_root"))
    if named_roots and root in named_roots:
        return {
            "status": "ok_named_gep",
            "field_root": root,
            "root_struct": root_struct,
            "expected_tokens": tokens,
            "source_bitcode": str(bitcode),
            "suggested_field_root": root,
            "suggested_root_counts": dict(sorted(named_roots.items())),
            "named_gep_candidates": compact_gep_candidates(same_struct),
            "confidence": "high",
        }
    if named_roots:
        suggested_root = named_roots.most_common(1)[0][0]
        return {
            "status": "mismatch_named_gep",
            "field_root": root,
            "root_struct": root_struct,
            "expected_tokens": tokens,
            "source_bitcode": str(bitcode),
            "suggested_field_root": suggested_root,
            "suggested_root_counts": dict(sorted(named_roots.items())),
            "named_gep_candidates": compact_gep_candidates(same_struct),
            "confidence": "high" if len(named_roots) == 1 else "medium",
        }
    return {
        "status": "no_named_gep",
        "field_root": root,
        "root_struct": root_struct,
        "expected_tokens": tokens,
        "source_bitcode": str(bitcode),
        "confidence": "low",
    }


def field_auto_correction_allowed(
    validation: dict[str, Any],
    evidence: dict[str, Any] | None,
) -> bool:
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
    evidence = evidence or {}
    if evidence.get("match_kind") != "debug_metadata_field_path":
        return False
    return True


@lru_cache(maxsize=128)
def disassemble_ir_cached(bitcode: str, llvm_dis: str) -> str | None:
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


def disassemble_ir(bitcode: Path, llvm_dis: Path | None) -> str | None:
    if llvm_dis is None:
        return None
    return disassemble_ir_cached(str(bitcode), str(llvm_dis))


def parse_debug_index(ir_text: str) -> dict[str, Any]:
    structs_by_name: dict[str, dict[str, Any]] = {}
    struct_name_by_id: dict[str, str] = {}
    elements_by_id: dict[str, list[str]] = {}
    members_by_id: dict[str, dict[str, str | None]] = {}
    derived_base_by_id: dict[str, str] = {}

    for raw in ir_text.splitlines():
        line = raw.strip()
        if m := DEBUG_STRUCT_RE.match(line):
            meta_id = m.group("id")
            name = m.group("name")
            struct_name_by_id[meta_id] = name
            structs_by_name[name] = {"id": meta_id, "elements": m.group("elements"), "members": []}
            continue
        if m := DEBUG_ARRAY_RE.match(line):
            derived_base_by_id[m.group("id")] = m.group("base")
            continue
        if m := DEBUG_ELEMENTS_RE.match(line):
            elements_by_id[m.group("id")] = re.findall(r"!(\d+)", m.group("body"))
            continue
        if m := DEBUG_MEMBER_RE.match(line):
            base_match = re.search(r"baseType: !(\d+)", line)
            members_by_id[m.group("id")] = {
                "name": m.group("name"),
                "scope": m.group("scope"),
                "base": base_match.group(1) if base_match else None,
            }
            if base_match:
                derived_base_by_id[m.group("id")] = base_match.group(1)
            continue
        if m := DEBUG_DERIVED_BASE_RE.match(line):
            derived_base_by_id.setdefault(m.group("id"), m.group("base"))

    for struct in structs_by_name.values():
        ordered_members: list[dict[str, str | None]] = []
        for member_id in elements_by_id.get(str(struct["elements"]), []):
            member = members_by_id.get(member_id)
            if member is not None:
                ordered_members.append(member)
        if not ordered_members:
            ordered_members = [
                member
                for member in members_by_id.values()
                if member.get("scope") == struct["id"]
            ]
        struct["members"] = ordered_members
    return {
        "structs_by_name": structs_by_name,
        "struct_name_by_id": struct_name_by_id,
        "derived_base_by_id": derived_base_by_id,
    }


@lru_cache(maxsize=128)
def debug_index_cached(bitcode: str, llvm_dis: str) -> dict[str, Any] | None:
    ir_text = disassemble_ir_cached(bitcode, llvm_dis)
    if ir_text is None:
        return None
    return parse_debug_index(ir_text)


def debug_index(bitcode: Path, llvm_dis: Path | None) -> dict[str, Any] | None:
    if llvm_dis is None:
        return None
    return debug_index_cached(str(bitcode), str(llvm_dis))


def resolve_struct_type(meta: dict[str, Any], type_id: str | None, depth: int = 0) -> str | None:
    if type_id is None or depth > 12:
        return None
    if type_id in meta["struct_name_by_id"]:
        return meta["struct_name_by_id"][type_id]
    base = meta["derived_base_by_id"].get(type_id)
    if base is None:
        return None
    return resolve_struct_type(meta, base, depth + 1)


def parse_index_expr(expr: str) -> int | None:
    expr = re.sub(r"\s+", "", expr)
    if expr.isdigit():
        return int(expr)
    if m := re.match(r"^([A-Za-z_][A-Za-z0-9_]*)([+-])(\d+)$", expr):
        base = ENUM_VALUE_MAP.get(m.group(1))
        if base is None:
            return None
        delta = int(m.group(3))
        return base + delta if m.group(2) == "+" else base - delta
    return ENUM_VALUE_MAP.get(expr)


def parse_field_components(path: str) -> list[dict[str, Any]] | None:
    components: list[dict[str, Any]] = []
    for raw in path.split("."):
        m = FIELD_COMPONENT_RE.match(raw)
        if m is None:
            return None
        index_expr = m.group("index")
        array_index = parse_index_expr(index_expr) if index_expr is not None else None
        if index_expr is not None and array_index is None:
            return None
        components.append({"name": m.group("name"), "array_index": array_index})
    return components


def resolve_debug_field_root(struct_path: str, bitcode: Path, llvm_dis: Path | None) -> dict[str, Any] | None:
    components = parse_field_components(struct_path)
    if not components or len(components) < 2:
        return None
    meta = debug_index(bitcode, llvm_dis)
    if meta is None:
        return None

    root_struct = str(components[0]["name"])
    current_struct = root_struct
    indices: list[int] = []
    debug_steps: list[dict[str, Any]] = []

    for idx, component in enumerate(components[1:], start=1):
        struct = meta["structs_by_name"].get(current_struct)
        if struct is None:
            return None
        members = list(struct.get("members", []))
        member_index = next(
            (
                offset
                for offset, member in enumerate(members)
                if member.get("name") == component["name"]
            ),
            None,
        )
        if member_index is None:
            return None
        member = members[member_index]
        indices.append(member_index)
        debug_steps.append(
            {
                "struct_type": current_struct,
                "field": component["name"],
                "field_index": member_index,
            }
        )
        if component["array_index"] is not None:
            indices.append(int(component["array_index"]))
            debug_steps[-1]["array_index"] = int(component["array_index"])
            continue
        if idx < len(components) - 1:
            current_struct = resolve_struct_type(meta, str(member.get("base")) if member.get("base") else None)
            if current_struct is None:
                return None

    return {
        "field_root": ".".join([root_struct] + [str(index) for index in indices]),
        "match_kind": "debug_metadata_field_path",
        "struct_type": root_struct,
        "indices": indices,
        "debug_steps": debug_steps,
    }


def direct_neigh_field_root(backing: str) -> dict[str, Any] | None:
    if m := re.match(r"^neigh_parms\.data\[(NEIGH_VAR_[A-Za-z0-9_]+)\]$", backing):
        enum_name = m.group(1)
        enum_value = NEIGH_ENUM_INDICES.get(enum_name)
        if enum_value is None:
            return None
        return {
            "field_root": f"neigh_parms.12.{enum_value}",
            "match_kind": "direct_neigh_parms_data_enum",
            "struct_type": "neigh_parms",
            "indices": [12, enum_value],
            "enum_name": enum_name,
        }
    if m := re.match(r"^neigh_table\.(gc_interval|gc_thresh1|gc_thresh2|gc_thresh3)$", backing):
        field = m.group(1)
        return {
            "field_root": f"neigh_table.{NEIGH_TABLE_FIELD_INDICES[field]}",
            "match_kind": "direct_neigh_table_field",
            "struct_type": "neigh_table",
            "indices": [NEIGH_TABLE_FIELD_INDICES[field]],
            "field": field,
        }
    return None


def direct_xfs_field_root(backing: str) -> dict[str, Any] | None:
    if m := re.match(r"^xfs_params\.([A-Za-z_][A-Za-z0-9_]*)\.val$", backing):
        field = m.group(1)
        field_index = XFS_PARAM_FIELD_INDICES.get(field)
        if field_index is None:
            return None
        return {
            "field_root": f"xfs_param.{field_index}.1",
            "match_kind": "direct_xfs_param_val_field",
            "struct_type": "xfs_param",
            "indices": [field_index, 1],
            "field": field,
        }
    return None


def normalized_struct_path(record: dict[str, Any]) -> str | None:
    backing = normalize_backing(str(record.get("backing_symbol") or ""))
    if not backing or backing == "None":
        return None
    alias = BACKING_ALIASES.get(backing)
    if alias:
        return None if alias.count(".") >= 3 and alias.split(".")[0].isdigit() else alias
    for prefix, replacement in BACKING_PREFIX_STRUCTS:
        if backing.startswith(prefix):
            return replacement + backing[len(prefix) :]
    if backing.startswith("init_net."):
        return "net." + backing[len("init_net.") :]
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\.", backing):
        return backing
    return None


def additional_struct_paths(record: dict[str, Any]) -> list[str]:
    backing = normalize_backing(str(record.get("backing_symbol") or ""))
    source_file = str(record.get("source_file") or "")
    paths: list[str] = []
    if source_file == "net/ipv4/sysctl_net_ipv4.c" and backing.startswith("init_net."):
        suffix = backing.removeprefix("init_net.")
        if not suffix.startswith(("ipv4.", "core.", "xfrm.", "sctp.", "ct.")):
            paths.append(f"netns_ipv4.sysctl_{suffix}")
    return paths


def direct_field_root(record: dict[str, Any], bitcode: Path | None, llvm_dis: Path | None) -> dict[str, Any] | None:
    backing = normalize_backing(str(record.get("backing_symbol") or ""))
    if backing in BACKING_ALIASES and BACKING_ALIASES[backing].startswith("in_device."):
        return {
            "field_root": BACKING_ALIASES[backing],
            "match_kind": "direct_ipv4_devconf_forwarding",
            "struct_type": "in_device",
            "indices": [21, 1, 0],
        }
    direct = direct_neigh_field_root(backing)
    if direct is not None:
        return direct
    direct = direct_xfs_field_root(backing)
    if direct is not None:
        return direct
    if bitcode is None:
        return None
    struct_paths: list[str] = []
    primary = normalized_struct_path(record)
    if primary is not None:
        struct_paths.append(primary)
    struct_paths.extend(additional_struct_paths(record))
    seen: set[str] = set()
    for struct_path in struct_paths:
        if struct_path in seen:
            continue
        seen.add(struct_path)
        resolved = resolve_debug_field_root(struct_path, bitcode, llvm_dis)
        if resolved is not None:
            return resolved
    return None


def expected_structs(record: dict[str, Any]) -> set[str]:
    backing = normalize_backing(str(record.get("backing_symbol") or ""))
    expected: set[str] = set()
    for prefix, structs in EXPECTED_STRUCT_PREFIXES.items():
        if backing.startswith(prefix):
            expected.update(structs)
    if backing in {"init_net.nf_conntrack_acct", "init_net.nf_conntrack_checksum"}:
        expected.add("netns_ct")
    if backing.startswith("init_net.") and not expected:
        expected.add("net")
    first = backing.split(".", 1)[0]
    if first and first != "init_net" and IDENT_RE.match(first):
        expected.add(first)
    return expected


def score_gep_candidate(record: dict[str, Any], candidate: dict[str, Any]) -> float:
    score = 1.5 * len(candidate.get("matched_tokens", []))
    score += 0.15 * len(candidate.get("indices", []))
    struct_type = str(candidate.get("struct_type") or "")
    if struct_type in expected_structs(record):
        score += 6.0
    backing = normalize_backing(str(record.get("backing_symbol") or ""))
    if backing.startswith("init_net.sctp.") and struct_type == "sctp_endpoint":
        score -= 8.0
    if backing.startswith("init_net.") and struct_type.startswith("netns_"):
        score += 1.5
    if candidate.get("ssa_name", "").endswith(".i"):
        score += 0.2
    return score


def gep_field_root(record: dict[str, Any], bitcode: Path | None, llvm_dis: Path | None) -> dict[str, Any] | None:
    if bitcode is None:
        return None
    tokens = derive_tokens(record)
    if not tokens:
        return None
    ir_text = disassemble_ir(bitcode, llvm_dis)
    if ir_text is None:
        return None
    candidates, _summary = infer_candidates(ir_text, tokens, str(record.get("param") or ""))
    if not candidates:
        return None
    ranked: list[tuple[float, dict[str, Any]]] = []
    seen: set[str] = set()
    for candidate in candidates:
        root = str(candidate.get("field_root") or "")
        if not root or root in seen:
            continue
        seen.add(root)
        ranked.append((score_gep_candidate(record, candidate), candidate))
    if not ranked:
        return None
    ranked.sort(key=lambda item: (-item[0], item[1]["field_root"]))
    best_score, best = ranked[0]
    expected = expected_structs(record)
    if expected and str(best.get("struct_type") or "") not in expected:
        return None
    return {
        "field_root": best["field_root"],
        "match_kind": "gep_ssa_token_field_root",
        "score": best_score,
        "struct_type": best.get("struct_type"),
        "indices": best.get("indices"),
        "tokens": tokens,
        "candidates": [
            {
                "field_root": candidate["field_root"],
                "score": score,
                "struct_type": candidate.get("struct_type"),
                "indices": candidate.get("indices"),
                "matched_tokens": candidate.get("matched_tokens"),
                "ir_line_number": candidate.get("ir_line_number"),
                "match_kind": "gep_ssa_token_field_root",
            }
            for score, candidate in ranked[:10]
        ],
    }


def infer_field_root(
    record: dict[str, Any],
    bitcode: Path | None,
    llvm_dis: Path | None,
) -> dict[str, Any] | None:
    direct = direct_field_root(record, bitcode, llvm_dis)
    if direct is not None:
        direct = dict(direct)
        direct["confidence"] = "high"
        return direct
    gep = gep_field_root(record, bitcode, llvm_dis)
    if gep is not None:
        gep = dict(gep)
        gep["confidence"] = "medium"
        return gep
    return None


def choose_root_spec(
    record: dict[str, Any],
    *,
    infer_fields: bool,
    bitcode: Path | None,
    llvm_dis: Path | None,
) -> tuple[dict[str, str] | None, str, str, dict[str, Any] | None]:
    existing = record.get("conftainter_root_spec")
    if existing and existing.get("var_type") in {"SINGLE", "FIELD"} and existing.get("var_name"):
        return (
            {"var_type": str(existing["var_type"]), "var_name": str(existing["var_name"])},
            "ready_existing_conftainter_root",
            "existing_conftainter_root_spec",
            None,
        )

    llvm_root = record.get("llvm_root_spec") or {}
    backing_kind = str(record.get("backing_kind") or "")
    var_type = str(llvm_root.get("var_type") or "")
    var_name = str(llvm_root.get("var_name") or "")
    if var_type == "SINGLE" and backing_kind == "global_scalar" and IDENT_RE.match(var_name):
        return (
            {"var_type": "SINGLE", "var_name": var_name},
            "ready_single_from_llvm_root",
            "global_scalar_llvm_root_spec",
            None,
        )

    if var_type == "SINGLE" and backing_kind == "handler_private":
        return None, "blocked_handler_private", "handler_private_not_a_stable_config_storage_root", None
    if var_type == "SINGLE" and backing_kind == "unknown":
        return None, "blocked_unknown_single", "unknown_backing_kind_not_safe_for_tfuzz", None
    if var_type == "STRUCT":
        if infer_fields:
            inferred = infer_field_root(record, bitcode, llvm_dis)
            if inferred is not None:
                return (
                    {"var_type": "FIELD", "var_name": str(inferred["field_root"])},
                    "ready_inferred_field_root",
                    str(inferred.get("match_kind") or "inferred_field_root"),
                    inferred,
                )
        return None, "blocked_needs_field_resolution", classify_blocked_field(record), None

    return None, "blocked_unhandled_root_shape", f"{backing_kind}:{var_type or 'missing_var_type'}", None


def main() -> int:
    args = parse_args()
    llvm_dis = choose_tool(args.llvm_dis, "llvm-dis-18", "llvm-dis")
    rows = read_jsonl(args.roots)
    output_rows: list[dict[str, Any]] = []
    ready_params: list[str] = []
    ready_config_roots: list[dict[str, Any]] = []
    ready_strict_config_roots: list[dict[str, Any]] = []
    blocked_rows: list[dict[str, Any]] = []
    counters = Counter()
    reason_counts = Counter()
    subsystem_counts = Counter()
    field_validation_counts = Counter()
    field_correction_count = 0

    for record in rows:
        param = str(record["param"])
        bitcode = source_to_bc(record.get("source_file"), args.kernel_bc_root)
        root_spec, status, reason, evidence = choose_root_spec(
            record,
            infer_fields=args.infer_field_roots,
            bitcode=bitcode,
            llvm_dis=llvm_dis,
        )
        field_validation: dict[str, Any] | None = None
        if (
            root_spec
            and root_spec["var_type"] == "FIELD"
            and args.validate_field_roots_against_gep
        ):
            field_validation = validate_field_root_against_gep(
                record,
                root_spec,
                evidence,
                bitcode=bitcode,
                llvm_dis=llvm_dis,
            )
            field_validation_counts[str(field_validation.get("status") or "missing_status")] += 1
            if (
                args.auto_correct_field_roots
                and field_auto_correction_allowed(field_validation, evidence)
            ):
                previous_root_spec = dict(root_spec)
                root_spec = {
                    "var_type": "FIELD",
                    "var_name": str(field_validation["suggested_field_root"]),
                }
                status = "ready_corrected_field_root"
                reason = "validated_llvm_gep_ssa_token_field_root"
                evidence = {
                    "confidence": "high",
                    "field_root": root_spec["var_name"],
                    "match_kind": "validated_llvm_gep_ssa_token_field_root",
                    "previous_root_spec": previous_root_spec,
                    "previous_evidence": evidence,
                    "validation": field_validation,
                }
                field_correction_count += 1

        validation_status = "not_applicable"
        if (
            args.validate_single_symbols
            and root_spec
            and root_spec["var_type"] == "SINGLE"
            and bitcode is not None
        ):
            validation_status = single_symbol_seen(bitcode, root_spec["var_name"], llvm_dis)
        elif root_spec and root_spec["var_type"] == "SINGLE":
            validation_status = "not_checked"
        elif root_spec and root_spec["var_type"] == "FIELD":
            if field_validation is not None:
                if status == "ready_corrected_field_root":
                    validation_status = "corrected_" + str(field_validation.get("status") or "field_root")
                else:
                    validation_status = str(field_validation.get("status") or "field_root_validation_unknown")
            else:
                validation_status = "accepted_existing_field_root"

        row = {
            "param": param,
            "status": status,
            "reason": reason,
            "tfuzz_root_spec": root_spec,
            "backing_kind": record.get("backing_kind"),
            "backing_symbol": record.get("backing_symbol"),
            "llvm_root_spec": record.get("llvm_root_spec"),
            "source_file": record.get("source_file"),
            "source_bitcode": str(bitcode) if bitcode else None,
            "root_spec_evidence": evidence,
            "mapping_confidence": record.get("mapping_confidence"),
            "scope_type": record.get("scope_type"),
            "validation_status": validation_status,
            "field_root_validation": field_validation,
        }
        output_rows.append(row)
        counters[status] += 1
        reason_counts[reason] += 1
        subsystem_counts["/".join(param.split("/")[:2])] += 1
        if root_spec is not None:
            ready_params.append(param)
            ready_record = dict(record)
            ready_record["conftainter_root_spec"] = root_spec
            ready_record["tfuzz_root_spec_status"] = status
            ready_record["tfuzz_root_spec_reason"] = reason
            ready_record["tfuzz_root_spec_evidence"] = evidence
            if field_validation is not None:
                ready_record["tfuzz_root_spec_validation"] = field_validation
            ready_config_roots.append(ready_record)

            strict_record = dict(ready_record)
            strict_record["llvm_root_spec"] = dict(root_spec)
            strict_record.pop("conftainter_root_candidates", None)
            strict_record.pop("conftainter_refinement", None)
            ready_strict_config_roots.append(strict_record)
        else:
            blocked_rows.append(row)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    specs_path = args.output_dir / "tfuzz_root_specs.jsonl"
    blocked_path = args.output_dir / "tfuzz_root_specs.blocked.jsonl"
    ready_params_path = args.output_dir / "tfuzz_ready_params.txt"
    ready_config_roots_path = args.output_dir / "tfuzz_ready_config_root.jsonl"
    ready_strict_config_roots_path = args.output_dir / "tfuzz_ready_strict_config_root.jsonl"
    write_jsonl(specs_path, output_rows)
    write_jsonl(blocked_path, blocked_rows)
    write_jsonl(ready_config_roots_path, ready_config_roots)
    write_jsonl(ready_strict_config_roots_path, ready_strict_config_roots)
    ready_params_path.write_text("\n".join(sorted(ready_params)) + "\n", encoding="utf-8")

    summary = {
        "status": "completed",
        "roots": str(args.roots),
        "kernel_bc_root": str(args.kernel_bc_root),
        "param_count": len(output_rows),
        "ready_count": len(ready_params),
        "blocked_count": len(blocked_rows),
        "status_counts": dict(sorted(counters.items())),
        "reason_counts": dict(reason_counts.most_common()),
        "subsystem_counts": dict(sorted(subsystem_counts.items())),
        "validate_single_symbols": bool(args.validate_single_symbols),
        "validate_field_roots_against_gep": bool(args.validate_field_roots_against_gep),
        "auto_correct_field_roots": bool(args.auto_correct_field_roots),
        "field_root_validation_counts": dict(sorted(field_validation_counts.items())),
        "field_root_correction_count": field_correction_count,
        "infer_field_roots": bool(args.infer_field_roots),
        "kernel_source_root": str(args.kernel_source_root),
        "llvm_dis": str(llvm_dis) if llvm_dis else None,
        "outputs": {
            "tfuzz_root_specs": str(specs_path),
            "blocked_specs": str(blocked_path),
            "ready_params": str(ready_params_path),
            "ready_config_roots": str(ready_config_roots_path),
            "ready_strict_config_roots": str(ready_strict_config_roots_path),
        },
    }
    summary_path = args.output_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(summary_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
