# Linked-Exact 965 Relation Tables

This directory contains the syscall-to-runtime-configuration relation tables
used by the KConfuzz paper-style experiment.

## Files

- `param_syzkaller_call_relation.executor_current.jsonl`: the table consumed by
  `pkg/kconfuzz.LoadRelationTable()` and suitable for
  `SYZ_KCONFUZZ_RELATION_TABLE`.
- `param_syzkaller_call_relation.positive.jsonl.gz`: compressed archive of the
  full positive relation table before executor filtering. The uncompressed
  source has 250,731 JSONL rows and is kept compressed to avoid GitHub's large
  raw-file limits.
- `param_syzkaller_call_relation.executor_current.summary.json`: exact filter
  summary for the executor-current table.
- `executor_effective_relation.summary.json`: compact counts for the effective
  relation edges available to executor actions.

## How It Was Obtained

The relation pipeline starts from Linux 6.12.80 LLVM bitcode built with the
clang18 fuzzing kernel configuration. Runtime configuration parameters are
represented by TFuzz/root-resolution specs and parameter-function influence
records. Syzkaller calls are represented by Linux syscall-description files and
their descriptor entry functions.

For each runtime parameter and syzkaller call, the pipeline computes whether
the parameter's influenced kernel functions intersect the call descriptor's
reachable functions. A row is emitted when the intersection is positive. Rows
keep the evidence needed for auditing, including `param`, `param_domain`,
`syzkaller_call`, `descriptor_domain`, entry functions, intersection functions,
and an example evidence path.

The full positive table is then filtered to match the online executor path:

- the parameter must exist in `pkg/kconfuzz.SupportedParams`;
- the generated registry must mark the parameter as `AutoSafe`;
- generic descriptor-domain edges are dropped;
- `param_domain` must equal `descriptor_domain`.

The resulting executor-current table has 19,223 rows, 417 loaded parameters,
and 125 loaded syzkaller calls. Its edge domains are IPv4 and IPv6 for this
experiment snapshot.

## Use

```bash
export SYZ_KCONFUZZ_RELATION_TABLE="$PWD/tools/kconfuzz/relations/linked_exact_965/param_syzkaller_call_relation.executor_current.jsonl"
```

To inspect the archived full positive table:

```bash
gzip -cd tools/kconfuzz/relations/linked_exact_965/param_syzkaller_call_relation.positive.jsonl.gz | head
```
