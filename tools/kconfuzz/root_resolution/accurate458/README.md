# Accurate458 Root Inputs

This directory is a local copy of the conservative root-resolution artifacts used
by the KConfuzz value-domain table. The source tree under
`/home/wang/syzkaller_workdir/config_strategy_workspace/value_domain_workspace`
is not modified by the syzkaller executor-side experiment.

The active root file is:

```text
accurate_roots.conservative.jsonl
```

It contains 458 conservative roots:

```text
SINGLE global roots: 271
FIELD roots validated against LLVM GEP: 103
FIELD roots corrected from debug/DWARF ordinal to LLVM GEP index: 84
```

The key correction is that FIELD roots use LLVM IR GEP indices, not debug
metadata/DWARF field ordinals. The copied resolver script is:

```text
resolve_field_path_gep_roots.py
```

The current mutator table is expected to be a subset of these 458 roots. Validate
that local invariant with:

```bash
python3 tools/kconfuzz/root_resolution/accurate458/validate_accurate458_inputs.py
```

Expected current result:

```text
accurate_root_count: 458
mutator_row_count: 424
mutator_params_missing_from_accurate_roots: []
registry_mutator_param_count: 422
mutator_params_missing_from_registry: ["vm/compact_memory", "vm/drop_caches"]
```

The two registry misses are write-only sysctls in the runtime inventory, so they
are not executor-action registry entries.
