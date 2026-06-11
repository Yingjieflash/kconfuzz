#!/usr/bin/env python3
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

import argparse
import json
import os
import re
from pathlib import Path


DEFAULT_ROOTS = (
    "/home/wang/syzkaller_workdir/kconfuzz_relation_repro/runs/"
    "runtime_root_mapping_current/config_root.runtime_full.jsonl"
)
DEFAULT_INVENTORY = (
    "/home/wang/syzkaller_workdir/direct_syzkaller_relation_repro/data/"
    "sysctl_inventory/sysctl_params_runtime_raw.jsonl"
)
DEFAULT_CLASSIFIED = (
    "/home/wang/syzkaller_workdir/linux-6.12.80/docs/"
    "sysctl_inventory/sysctl_params_classified.jsonl"
)
DEFAULT_MUTATOR_TABLE = (
    "tools/kconfuzz/value_domains/accurate458/"
    "parameter_mutator_table.simple.jsonl"
)
DEFAULT_MUTATOR_CONFIDENCE = "high,medium,low"
DEFAULT_ACCURATE_ROOTS = (
    "tools/kconfuzz/root_resolution/accurate458/"
    "accurate_roots.conservative.jsonl"
)

ZERO_BOUNDS = {
    "SYSCTL_ZERO",
    "SYSCTL_INT_ZERO",
    "SYSCTL_LONG_ZERO",
    "&zero",
    "&long_zero",
    "(void *)SYSCTL_ZERO",
}

BOUND_VALUES = {
    "SYSCTL_ONE": 1,
    "SYSCTL_INT_ONE": 1,
    "SYSCTL_LONG_ONE": 1,
    "&one": 1,
    "&long_one": 1,
    "(void *)SYSCTL_ONE": 1,
    "SYSCTL_TWO": 2,
    "SYSCTL_THREE": 3,
    "SYSCTL_FOUR": 4,
}

SEMANTIC_BINARY_RE = re.compile(
    r"(^|[_-])("
    r"enable|enabled|disable|disabled|allow|ignore|autocorking|"
    r"nonlocal_bind|auth|checksum|loose|paranoid|legacy|restrict|"
    r"forwarding|xfrm|redirects|source_route|accept_local"
    r")([_-]|$)"
)

DANGEROUS_RE = re.compile(
    r"(^|/|[_-])("
    r"panic|oops|hardlockup|softlockup|hung_task|watchdog|nmi|"
    r"modules_disabled|kexec_load_disabled|sysrq|unprivileged_bpf_disabled"
    r")([/_-]|$)"
)


def c_quote(value):
    return json.dumps(str(value))


def go_quote(value):
    return json.dumps(str(value))


def load_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def load_jsonl_map(path, key):
    if not path or not os.path.exists(path):
        return {}
    return {row[key]: row for row in load_jsonl(path) if key in row}


def value_text(value):
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    text = str(value).strip()
    if re.fullmatch(r"-?\d+", text):
        return str(int(text))
    return text


def unique_text_values(values):
    ret = []
    seen = set()
    for value in values or []:
        text = value_text(value)
        if text in seen:
            continue
        seen.add(text)
        ret.append(text)
    return ret


def int_or_none(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not re.fullmatch(r"-?\d+", text):
        return None
    return int(text)


def generate_random_legal_values(row):
    random_min = int_or_none(row.get("random_min"))
    random_max = int_or_none(row.get("random_max"))
    if random_min is None or random_max is None or random_min > random_max:
        return []
    candidates = []
    for key in ("current_value_int", "min", "max", "random_min", "random_max"):
        value = int_or_none(row.get(key))
        if value is not None:
            candidates.append(value)
    candidates.append(random_min + (random_max - random_min) // 2)
    for value in row.get("tfuzz_values") or []:
        candidates.append(int_or_none(value))
    for value in row.get("seed_values") or []:
        candidates.append(int_or_none(value))
    for value in (-1, 0, 1, 2, 3, 4, 7, 8, 16, 31, 32, 63, 64, 127, 128, 255, 256, 1024):
        candidates.append(value)
    legal = []
    for value in candidates:
        if value is None:
            continue
        if random_min <= value <= random_max:
            legal.append(value)
    return unique_text_values(legal)


def load_mutator_table(path, confidence_filter):
    stats = {
        "path": os.path.abspath(path) if path else "",
        "rows_total": 0,
        "rows_bad_format": 0,
        "rows_dropped_confidence": 0,
        "rows_loaded": 0,
        "confidence_counts": {},
        "family_counts": {},
        "kind_counts": {},
    }
    if not path or not os.path.exists(path):
        stats["missing"] = True
        return {}, stats
    allowed = {item.strip() for item in confidence_filter.split(",") if item.strip()}
    ret = {}
    for row in load_jsonl(path):
        stats["rows_total"] += 1
        confidence = str(row.get("confidence") or "").strip()
        stats["confidence_counts"][confidence] = stats["confidence_counts"].get(confidence, 0) + 1
        family = str(row.get("family") or "").strip()
        stats["family_counts"][family] = stats["family_counts"].get(family, 0) + 1
        kind = str(row.get("kind") or "").strip()
        stats["kind_counts"][kind] = stats["kind_counts"].get(kind, 0) + 1
        if row.get("value_format") != "decimal_int":
            stats["rows_bad_format"] += 1
            continue
        if allowed and confidence not in allowed:
            stats["rows_dropped_confidence"] += 1
            continue
        param = row.get("param")
        if not param:
            continue
        ret[param] = {
            "confidence": confidence,
            "family": family,
            "kind": kind,
            "prob_tfuzz": int(row.get("prob_tfuzz") or 0),
            "prob_seed": int(row.get("prob_seed") or 0),
            "prob_random_legal": int(row.get("prob_random_legal") or 0),
            "prob_out_of_domain": int(row.get("prob_out_of_domain") or 0),
            "tfuzz_values": unique_text_values(row.get("tfuzz_values")),
            "seed_values": unique_text_values(row.get("seed_values")),
            "random_values": generate_random_legal_values(row),
            "out_of_domain_values": unique_text_values(row.get("out_of_domain_values")),
        }
        stats["rows_loaded"] += 1
    return ret, stats


def load_accurate_root_stats(path, mutators):
    stats = {
        "path": os.path.abspath(path) if path else "",
        "rows_total": 0,
        "var_type_counts": {},
        "accuracy_counts": {},
        "status_counts": {},
        "mutator_params_missing_from_accurate_roots": [],
        "accurate_roots_not_in_mutator_count": 0,
    }
    if not path or not os.path.exists(path):
        stats["missing"] = True
        return stats
    root_params = set()
    for row in load_jsonl(path):
        stats["rows_total"] += 1
        root_params.add(row.get("param"))
        root_spec = row.get("conftainter_root_spec") or row.get("llvm_root_spec") or {}
        var_type = root_spec.get("var_type")
        stats["var_type_counts"][var_type] = stats["var_type_counts"].get(var_type, 0) + 1
        accuracy = row.get("mvp_root_accuracy")
        stats["accuracy_counts"][accuracy] = stats["accuracy_counts"].get(accuracy, 0) + 1
        status = row.get("tfuzz_root_spec_status")
        stats["status_counts"][status] = stats["status_counts"].get(status, 0) + 1
    mutator_params = set(mutators)
    stats["mutator_params_missing_from_accurate_roots"] = sorted(mutator_params - root_params)
    stats["accurate_roots_not_in_mutator_count"] = len(root_params - mutator_params)
    return stats


def param_domain(param):
    if param.startswith("net/ipv4/"):
        return "ipv4"
    if param.startswith("net/ipv6/"):
        return "ipv6"
    if param.startswith("net/sctp/"):
        return "sctp"
    return "generic"


def primary_source(classified):
    if not classified:
        return {}
    if classified.get("primary_source"):
        return classified["primary_source"]
    metadata = classified.get("source_metadata") or []
    return metadata[0] if metadata else {}


def is_zero_bound(value):
    if value is None:
        return False
    text = str(value).strip()
    return text in ZERO_BOUNDS or "zero" in text.lower()


def bound_value(value):
    if value is None:
        return None
    text = str(value).strip()
    if text in BOUND_VALUES:
        return BOUND_VALUES[text]
    match = re.fullmatch(r"-?\d+", text)
    if match:
        return int(text)
    return None


def is_dangerous(param):
    return bool(DANGEROUS_RE.search(param))


def is_semantic_binary(param, source):
    leaf = param.split("/")[-1]
    handler = str(source.get("proc_handler") or "")
    if SEMANTIC_BINARY_RE.search(leaf):
        return True
    return handler in {
        "proc_do_static_key",
        "proc_sctp_do_auth",
        "bpf_stats_handler",
        "sysctl_schedstats",
        "timer_migration_handler",
    }


def value_spec(record, classified):
    domain = record.get("value_domain")
    default = record.get("default_value")
    param = record.get("param", "")
    source = primary_source(classified)
    guess = str(classified.get("value_type_guess") or source.get("value_type_guess") or "").strip()
    handler = str(record.get("proc_handler") or source.get("proc_handler") or "").strip()
    dangerous = is_dangerous(param)

    if domain == "bool01":
        if guess == "bool" or handler == "proc_dobool":
            value_domain = "bool_strict"
            auto_safe = True
        elif is_zero_bound(source.get("extra1")) and bound_value(source.get("extra2")) == 1:
            value_domain = "bool_range01"
            auto_safe = True
        elif is_semantic_binary(param, source):
            value_domain = "binary_semantic"
            auto_safe = True
        else:
            value_domain = "binary_observed"
            auto_safe = False
        if dangerous:
            auto_safe = False
        return ["0", "1"], value_domain, auto_safe, "dangerous_name" if dangerous else value_domain

    if domain == "small_enum":
        max_bound = bound_value(source.get("extra2"))
        if max_bound is None or max_bound < 2:
            try:
                default_int = int(default)
            except (TypeError, ValueError):
                default_int = 2
            max_bound = default_int
        max_value = min(max(max_bound, 2), 8)
        auto_safe = not dangerous
        return (
            [str(i) for i in range(max_value + 1)],
            "small_enum",
            auto_safe,
            "dangerous_name" if dangerous else "small_enum",
        )
    return None, domain or "unsupported", False, "unsupported_value_domain"


def attach_mutator(record, mutator):
    values = unique_text_values(
        record.get("values", [])
        + mutator["tfuzz_values"]
        + mutator["seed_values"]
        + mutator["random_values"]
        + mutator["out_of_domain_values"]
    )
    value_ids = {value: idx for idx, value in enumerate(values)}
    record["values"] = values
    record["mutator"] = {
        "confidence": mutator["confidence"],
        "family": mutator["family"],
        "kind": mutator["kind"],
        "prob_tfuzz": mutator["prob_tfuzz"],
        "prob_seed": mutator["prob_seed"],
        "prob_random_legal": mutator["prob_random_legal"],
        "prob_out_of_domain": mutator["prob_out_of_domain"],
        "tfuzz_ids": [value_ids[value] for value in mutator["tfuzz_values"] if value in value_ids],
        "seed_ids": [value_ids[value] for value in mutator["seed_values"] if value in value_ids],
        "random_ids": [value_ids[value] for value in mutator["random_values"] if value in value_ids],
        "out_of_domain_ids": [
            value_ids[value] for value in mutator["out_of_domain_values"] if value in value_ids
        ],
    }
    return record


def build_registry(
    roots_path,
    inventory_path,
    classified_path,
    mutator_path,
    mutator_confidence,
    accurate_roots_path,
):
    inventory = load_jsonl_map(inventory_path, "full_path")
    classified = load_jsonl_map(classified_path, "full_path")
    mutators, mutator_stats = load_mutator_table(mutator_path, mutator_confidence)
    accurate_root_stats = load_accurate_root_stats(accurate_roots_path, mutators)
    base_records = []
    extra_records = []
    for row in load_jsonl(roots_path):
        param = row.get("param")
        if not param:
            continue
        inv = inventory.get(param, {})
        if not inv.get("readable") or not inv.get("writable_by_mode_guess"):
            continue
        values, value_domain, auto_safe, safety_class = value_spec(row, classified.get(param, {}))
        mutator = mutators.get(param)
        if not values and not mutator:
            continue
        if not values:
            values = []
            value_domain = f"mutator_{mutator['kind']}"
            auto_safe = True
            safety_class = f"mutator_{mutator['confidence']}"
        if mutator and not is_dangerous(param):
            auto_safe = True
            if safety_class == "unsupported_value_domain" or not safety_class:
                safety_class = f"mutator_{mutator['confidence']}"
        if is_dangerous(param):
            auto_safe = False
            safety_class = "dangerous_name"
        record = {
            "param": param,
            "proc_path": "/proc/sys/" + param,
            "values": unique_text_values(values),
            "domain": param_domain(param),
            "value_domain": value_domain,
            "source_value_domain": row.get("value_domain"),
            "auto_safe": auto_safe,
            "safety_class": safety_class,
            "mutator": None,
        }
        if mutator:
            record = attach_mutator(record, mutator)
        if value_spec(row, classified.get(param, {}))[0]:
            base_records.append(record)
        else:
            extra_records.append(record)
    base_records.sort(key=lambda item: item["param"])
    extra_records.sort(key=lambda item: item["param"])
    records = base_records + extra_records
    base_params = {rec["param"] for rec in base_records}
    mutator_stats["registry_existing_params"] = sum(
        1 for param in mutators if param in base_params
    )
    mutator_stats["registry_added_params"] = sum(
        1 for rec in extra_records if rec.get("mutator")
    )
    mutator_stats["registry_attached_params"] = sum(
        1 for rec in records if rec.get("mutator")
    )
    return records, mutator_stats, accurate_root_stats


def write_c_header(path, records):
    lines = [
        "// Code generated by tools/kconfuzz/gen_runtime_config_registry.py; DO NOT EDIT.",
        "",
    ]
    value_arrays = {}
    for rec in records:
        key = tuple(rec["values"])
        value_arrays.setdefault(key, f"kconfuzz_values_{len(value_arrays)}")
    for values, name in value_arrays.items():
        lines.append(f"static const char* const {name}[] = {{{', '.join(c_quote(v) for v in values)}}};")
    lines += [
        "",
        "enum kconfuzz_runtime_config_id {",
    ]
    for idx, _ in enumerate(records):
        lines.append(f"\tKCONFUZZ_CFG_{idx:04d} = {idx},")
    lines += [
        f"\tKCONFUZZ_CFG_COUNT = {len(records)},",
        "};",
        "",
        "static const struct kconfuzz_runtime_config_entry kconfuzz_runtime_configs[] = {",
    ]
    for rec in records:
        array_name = value_arrays[tuple(rec["values"])]
        lines.append(
            f"\t{{{c_quote(rec['param'])}, {c_quote(rec['proc_path'])}, "
            f"{array_name}, {len(rec['values'])}}},"
        )
    lines += [
        "};",
        "",
    ]
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def write_go_registry(path, records):
    def go_ids(ids):
        if not ids:
            return "nil"
        return "[]uint64{" + ", ".join(str(item) for item in ids) + "}"

    def mutator_fields(rec):
        mutator = rec.get("mutator")
        if not mutator:
            return ""
        return (
            f", Mutator: true, MutatorConfidence: {go_quote(mutator['confidence'])}, "
            f"MutatorKind: {go_quote(mutator['kind'])}, MutatorFamily: {go_quote(mutator['family'])}, "
            f"MutatorProbTfuzz: {mutator['prob_tfuzz']}, "
            f"MutatorProbSeed: {mutator['prob_seed']}, "
            f"MutatorProbRandomLegal: {mutator['prob_random_legal']}, "
            f"MutatorProbOutOfDomain: {mutator['prob_out_of_domain']}, "
            f"MutatorTfuzzValueIDs: {go_ids(mutator['tfuzz_ids'])}, "
            f"MutatorSeedValueIDs: {go_ids(mutator['seed_ids'])}, "
            f"MutatorRandomValueIDs: {go_ids(mutator['random_ids'])}, "
            f"MutatorOutOfDomainValueIDs: {go_ids(mutator['out_of_domain_ids'])}"
        )

    lines = [
        "// Code generated by tools/kconfuzz/gen_runtime_config_registry.py; DO NOT EDIT.",
        "",
        "package kconfuzz",
        "",
        "var SupportedParams = map[string]ConfigParam{",
    ]
    for idx, rec in enumerate(records):
        lines.append(
            f"\t{go_quote(rec['param'])}: {{Name: {go_quote(rec['param'])}, "
            f"ID: {idx}, ValueCount: {len(rec['values'])}, "
            f"Domain: {go_quote(rec['domain'])}, ValueDomain: {go_quote(rec['value_domain'])}, "
            f"AutoSafe: {str(rec['auto_safe']).lower()}{mutator_fields(rec)}}},"
        )
    lines += [
        "}",
        "",
    ]
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def write_manifest(
    path,
    records,
    roots_path,
    inventory_path,
    mutator_path,
    mutator_stats,
    accurate_roots_path,
    accurate_root_stats,
):
    summary = {
        "roots": os.path.abspath(roots_path),
        "inventory": os.path.abspath(inventory_path),
        "mutator_table": os.path.abspath(mutator_path) if mutator_path else "",
        "mutator_stats": mutator_stats,
        "accurate_roots": os.path.abspath(accurate_roots_path) if accurate_roots_path else "",
        "accurate_root_stats": accurate_root_stats,
        "generated_count": len(records),
        "auto_safe_count": 0,
        "unsafe_count": 0,
        "mutator_count": 0,
        "value_domain_counts": {},
        "source_value_domain_counts": {},
        "domain_counts": {},
        "safety_class_counts": {},
    }
    for rec in records:
        if rec["auto_safe"]:
            summary["auto_safe_count"] += 1
        else:
            summary["unsafe_count"] += 1
        if rec.get("mutator"):
            summary["mutator_count"] += 1
        summary["value_domain_counts"][rec["value_domain"]] = (
            summary["value_domain_counts"].get(rec["value_domain"], 0) + 1
        )
        summary["source_value_domain_counts"][rec["source_value_domain"]] = (
            summary["source_value_domain_counts"].get(rec["source_value_domain"], 0) + 1
        )
        summary["domain_counts"][rec["domain"]] = summary["domain_counts"].get(rec["domain"], 0) + 1
        summary["safety_class_counts"][rec["safety_class"]] = (
            summary["safety_class_counts"].get(rec["safety_class"], 0) + 1
        )
    Path(path).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--roots", default=DEFAULT_ROOTS)
    parser.add_argument("--inventory", default=DEFAULT_INVENTORY)
    parser.add_argument("--classified", default=DEFAULT_CLASSIFIED)
    parser.add_argument("--mutator-table", default=DEFAULT_MUTATOR_TABLE)
    parser.add_argument("--mutator-confidence", default=DEFAULT_MUTATOR_CONFIDENCE)
    parser.add_argument("--accurate-roots", default=DEFAULT_ACCURATE_ROOTS)
    parser.add_argument("--c-out", default="executor/kconfuzz_runtime_configs.gen.h")
    parser.add_argument("--go-out", default="pkg/kconfuzz/registry_gen.go")
    parser.add_argument("--manifest-out", default="pkg/kconfuzz/registry_gen.summary.json")
    args = parser.parse_args()

    records, mutator_stats, accurate_root_stats = build_registry(
        args.roots,
        args.inventory,
        args.classified,
        args.mutator_table,
        args.mutator_confidence,
        args.accurate_roots,
    )
    write_c_header(args.c_out, records)
    write_go_registry(args.go_out, records)
    write_manifest(
        args.manifest_out,
        records,
        args.roots,
        args.inventory,
        args.mutator_table,
        mutator_stats,
        args.accurate_roots,
        accurate_root_stats,
    )
    print(
        f"generated {len(records)} runtime config entries "
        f"({mutator_stats.get('registry_attached_params', 0)} with mutator domains)"
    )


if __name__ == "__main__":
    main()
