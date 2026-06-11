# KConfuzz

KConfuzz is a syzkaller-based prototype for configuration-aware kernel fuzzing.
It extends syzkaller so a generated syscall program can carry executor-only
runtime configuration actions, such as temporary sysctl writes, without changing
the syz program syntax or corpus identity.

This repository is a cleaned release copy of the paper-reproduction experiment.
It contains the modified syzkaller source tree, the KConfuzz planner and runtime
configuration registry, smoke-test inputs, and small scripts used to run
paper-style experiments.

## What Changed

- `executor/`: accepts KConfuzz config instructions in the executor input
  buffer, writes supported procfs sysctl values, and restores original values
  after each program execution.
- `prog/`: adds `KConfuzzConfigContext` and executor serialization support for
  config actions.
- `pkg/kconfuzz/`: loads syscall-to-runtime-parameter relation tables, filters
  unsafe/noisy edges, and plans sequence-level or call-level actions.
- `pkg/fuzzer`, `pkg/corpus`, `pkg/manager`, `pkg/rpcserver`: propagate config
  contexts through fuzzing, triage, corpus metadata, queue requests, and runner
  serialization.
- `tools/kconfuzz/`: generates the runtime config registry and stores the value
  domain/root-resolution artifacts used by this experiment.
- `kconfuzz_smoke/`: controlled inputs for validating positive and negative
  executor-side config-action behavior.
- `configs/` and `scripts/`: example manager configs and a paper-style runner.

More implementation notes are in [`KCONFUZZ_EXEC_PLAN.md`](KCONFUZZ_EXEC_PLAN.md).
The original syzkaller README is preserved at
[`docs/syzkaller-upstream-readme.md`](docs/syzkaller-upstream-readme.md).

## Build

Install the normal syzkaller dependencies first: Go, a C/C++ compiler, make, and
the kernel/VM setup required by syzkaller.

```bash
make
```

The build creates binaries under `bin/`, including `bin/syz-manager` and the
target executor under `bin/linux_amd64/`.

## Quick Smoke Run

The smoke inputs are designed to check the executor path with a small relation
table:

```bash
export SYZ_KCONFUZZ_RELATION_TABLE="$PWD/kconfuzz_smoke/relation_positive.jsonl"
export SYZ_KCONFUZZ_DEBUG=1
```

Then run syzkaller in your normal VM setup with a manager config that points
`syzkaller` to this repository and uses a kernel image/rootfs suitable for your
machine. Executor-side action logs are written to:

```text
/tmp/syz-kconfuzz-config-actions.log
```

Expected positive behavior:

```text
planner relation -> exec buffer action -> executor sysctl flip -> program run -> restore
```

Negative smoke inputs are included to confirm that generic relation edges,
missing relation-table configuration, and unrelated programs do not trigger
config writes.

## Paper-Style Experiment

Edit `configs/paper_48h.cfg` before running it. The following fields are
machine-specific and must point to your local paths:

- `workdir`
- `kernel_obj`
- `kernel_src`
- `image`
- `sshkey`
- `syzkaller`
- `vm.kernel`

Run a short local experiment:

```bash
python3 scripts/run_kconfuzz_paper.py \
  --template-cfg configs/paper_48h.cfg \
  --relation /path/to/param_syzkaller_call_relation.executor_current.jsonl \
  --duration-sec 300 \
  --sample-interval-sec 30 \
  --debug-kconfuzz
```

The script writes results under `results/<run-id>/`, including manager logs,
coverage samples, KConfuzz audit logs, and a final JSON summary.

## Main Runtime Knobs

```text
SYZ_KCONFUZZ_RELATION_TABLE=/path/to/relation.jsonl
SYZ_KCONFUZZ_ACTION_STRATEGY=sequence|call|both
SYZ_KCONFUZZ_MAX_ACTIONS=4
SYZ_KCONFUZZ_MAX_ACTIONS_PER_CALL=1
SYZ_KCONFUZZ_RANDOM_ACTIONS=0
SYZ_KCONFUZZ_RELATED_ACTIONS=15
SYZ_KCONFUZZ_AUDIT_FILE=/path/to/kconfuzz-audit.jsonl
SYZ_KCONFUZZ_DEBUG=1
```

Ablation switches:

```text
SYZ_KCONFUZZ_DISABLE_ACTIONS=1
SYZ_KCONFUZZ_DISABLE_CHOICE=1
SYZ_KCONFUZZ_DISABLE_METADATA=1
```

## Relation Table Format

The planner expects newline-delimited JSON records:

```json
{"param":"net/ipv4/tcp_autocorking","param_domain":"ipv4","syzkaller_call":"getsockopt$inet_int","descriptor_domain":"ipv4"}
```

Automatic executor writes are intentionally conservative. The planner keeps
only rows whose parameter exists in the generated registry, is marked
`AutoSafe`, has a non-generic descriptor domain, and has matching
`param_domain` and `descriptor_domain`.

## License

This prototype is based on syzkaller and keeps syzkaller's Apache 2.0 license.
See [`LICENSE`](LICENSE).
