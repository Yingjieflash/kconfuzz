# KConfuzz Executor Smoke

This directory contains the controlled VM smoke inputs used to validate the
executor-side runtime config action path.

## Inputs

- `positive_ipv4.syz`: uses `socket$inet` plus `getsockopt$inet_int`.
- `negative_unrelated.syz`: uses `getpid`.
- `relation_positive.jsonl`: maps `net/ipv4/tcp_autocorking` to
  `getsockopt$inet_int` with `ipv4 -> ipv4`.
- `relation_generic_only.jsonl`: same param/call but `descriptor_domain=generic`,
  which the planner must filter out.

## Result

Original smoke run used a QEMU VM booted from:

- kernel: `/home/wang/syzkaller_workdir/linux-6.12.80-clang18-fuzz/arch/x86/boot/bzImage`
- image: `/home/wang/syzkaller_workdir/vmimg/bookworm.img`
- syzkaller copy: `/home/wang/syzkaller_workdir/kconfuzz_paper_experiment/syzkaller`

Observed positive case:

```text
kconfuzz: planned 1 config actions for 2 calls
kconfuzz: status=applied param=net/ipv4/tcp_autocorking ... requested=0 actual=0 before=1 flags=2
kconfuzz: status=restored param=net/ipv4/tcp_autocorking ... value=1
```

Observed negative cases:

- generic-only relation: loaded with `calls=0 edges=0`, no `status=applied`.
- no `SYZ_KCONFUZZ_RELATION_TABLE`: no kconfuzz planner/action output.
- unrelated syz program with positive relation: loaded relation, no action.

Full captured outputs are under `results/`.
