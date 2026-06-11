# KConfuzz Executor-Side Config Actions

This copy of syzkaller is an experiment branch for executor-side runtime
configuration adjustment. The original `../syzkaller` tree is not modified.

## Exec Buffer Extension

The syz program text/corpus is unchanged. Runtime config updates are carried in
the executor input buffer as an executor-only instruction:

```text
execInstrKConfuzzConfig = -5
payload:
  param_id uint64
  value_id uint64
  flags    uint64
```

Go-side entry point:

```go
Prog.SerializeForExecWithKConfuzz([]prog.KConfuzzConfigAction{...})
```

Queue-side entry point:

```go
queue.Request.KConfuzzConfigActions
```

The rpc runner serializes these actions into the exec buffer before sending the
program to `syz-executor`. If the queue request does not carry explicit actions,
the runner can build sequence-level actions from a direct
`runtime parameter -> syzkaller call descriptor` JSONL table:

```text
SYZ_KCONFUZZ_RELATION_TABLE=tools/kconfuzz/relations/linked_exact_965/param_syzkaller_call_relation.executor_current.jsonl
```

The planner lives in `pkg/kconfuzz`. It intentionally keeps only rows where the
parameter is supported by the executor table, marked `AutoSafe`, and
`param_domain == descriptor_domain`, so noisy generic edges and unsafe params
are not used for automatic writes. Planner-generated actions set the
executor-side `flip` flag: the executor reads the current sysctl value and
selects the next legal value, with `value_id` kept as a fallback when the
current value cannot be matched.

Planner knobs:

```text
SYZ_KCONFUZZ_ACTION_STRATEGY=sequence|call|both
SYZ_KCONFUZZ_MAX_ACTIONS=4
SYZ_KCONFUZZ_MAX_ACTIONS_PER_CALL=1
SYZ_KCONFUZZ_AUDIT_FILE=/path/to/kconfuzz-audit.jsonl
```

`sequence` implements paper-style sequence-level adjusting by writing related
params before call 0. `call` writes before each related syscall. `both` starts
with the sequence-level action set and fills remaining action budget with
call-local params. The audit file records how many relation rows are loaded,
which rows are dropped, and how many choice-table pseudo programs are built.

## Executor Behavior

When `syz-executor` sees `execInstrKConfuzzConfig`, it:

1. waits for already scheduled threaded calls to finish as a lightweight barrier,
2. maps `param_id,value_id` to a procfs sysctl path and value,
3. saves the original value on first write,
4. writes the requested value,
5. restores touched values after the program completes.

Logs are appended to:

```text
/tmp/syz-kconfuzz-config-actions.log
```

When executor debug output is enabled, the same records are also printed with a
`kconfuzz:` prefix. This is useful for VM smoke tests because sandbox setup can
make executor-local `/tmp` files disappear with the executor process.

## Runtime Config Registry

The runtime config registry is generated from the 1210-parameter runtime sysctl
inventory plus the runtime-root mapping:

```bash
tools/kconfuzz/gen_runtime_config_registry.py
```

For automatic executor writes, the generated registry keeps readable,
mode-writable `bool01` and `small_enum` candidates, but it separates the
observed value domain from automatic safety. Current safety classes are:

```text
bool_strict:      source type/handler says bool
bool_range01:     source min/max bounds are SYSCTL_ZERO -> SYSCTL_ONE
binary_semantic:  name/handler looks binary, but lacks strict range evidence
binary_observed:  current value is 0/1 only; not auto-safe
small_enum:       bounded small enum, usually 0..2/4
dangerous_name:   panic/watchdog/one-way-like names; not auto-safe
```

The current generated registry has 598 candidate entries, but only 211 are
`AutoSafe=true` and therefore eligible for relation-planned actions. Existing
corpus metadata and explicit request actions are also filtered through the same
registry before execution, so old unsafe actions cannot bypass the tightened
planner.

The old prototype hook that read `/tmp/syz-config-*.conf` during executor setup
has been removed from this copy; config writes are now driven only by executor
input instructions.

## Smoke Validation

Controlled VM smoke inputs and captured outputs are stored in `kconfuzz_smoke/`.
The positive case verified:

```text
planner relation -> exec buffer action -> executor sysctl flip -> program run -> restore
```

The negative cases verified that generic relation edges, missing relation env,
and unrelated syz programs do not trigger config writes.

## Manager-Level Smoke

A real manager smoke is stored outside this syzkaller copy:

```text
/home/wang/syzkaller_workdir/kconfuzz_manager_natural_smoke/
```

The smoke uses a narrow relation:

```json
{"param":"net/ipv6/ip_nonlocal_bind","param_domain":"ipv6","syzkaller_call":"bind$inet6","descriptor_domain":"ipv6"}
```

and a 3-VM manager configuration that enables only `socket$inet6` and
`bind$inet6`. Three VMs are intentional: with one or two VMs, syzkaller's
triage deflake requests can be delayed by the distributor `Avoid` set, so a
short smoke run may falsely look like it produced no corpus.

The first manager run was started with `SYZ_KCONFUZZ_RELATION_TABLE` and
created `workdir/kconfuzz-corpus-meta.jsonl`. A second run was started without
`SYZ_KCONFUZZ_RELATION_TABLE`, with only `SYZ_KCONFUZZ_DEBUG=1`. The restore
log shows:

```text
20 restored corpus metadata records
251 runner serializations from request-actions/context
0 loaded relation table records
0 planner-env/planned records
```

This verifies that `LoadSeeds()` restores the persisted
`KConfuzzConfigContext`, and execution uses the restored action instead of
replanning from the relation table. During the second run syzkaller minimized
and pruned the corpus, so the sidecar shrank to 12 records; this is expected and
also exercises sidecar pruning.

## Ablation Switches

The copied syzkaller tree has environment switches for small ablation
experiments:

```text
SYZ_KCONFUZZ_DISABLE_ACTIONS=1
SYZ_KCONFUZZ_DISABLE_CHOICE=1
SYZ_KCONFUZZ_DISABLE_METADATA=1
```

They are used by:

```text
/home/wang/syzkaller_workdir/kconfuzz_ablation_experiment/
```

The current four groups are:

```text
baseline:    relation off, actions off, metadata off, choice off
choice-only: relation on,  actions off, metadata off, choice on
action-only: relation on,  actions on,  metadata on,  choice off
full:        relation on,  actions on,  metadata on,  choice on
```
