# Field Path to LLVM GEP Root Resolution

This run implements the conservative root-resolution scheme:

1. Derive the intended C field path from `backing_symbol`, source/debug evidence,
   and available DWARF layout from `pahole`.
2. Search planned/source LLVM bitcode for `getelementptr` instructions whose SSA
   name contains a non-generic leaf field token.
3. Use the LLVM GEP index as the final FIELD root.
4. Auto-correct only when the candidate has the same struct and same index depth
   as the current root. Nested, array, and aggregate-parent GEPs are reported but
   not rewritten.

## Inputs

- Roots: `/home/wang/syzkaller_workdir/config_strategy_workspace/value_domain_workspace/runs/tfuzz_root_specs_validated_gep_current/tfuzz_ready_strict_config_root.jsonl`
- Target plan: `/home/wang/syzkaller_workdir/config_strategy_workspace/value_domain_workspace/runs/tfuzz_root_specs_validated_gep_current/target_plan/bitcode_plan.jsonl`
- Kernel bitcode root: `/home/wang/syzkaller_workdir/linux-6.12.80-clang18-bc-clean`
- DWARF layout source: `/home/wang/syzkaller_workdir/linux-6.12.80/vmlinux`

## Outputs

- Resolution evidence: `field_path_gep_resolution.jsonl`
- Corrected roots: `tfuzz_ready_strict_config_root.field_path_gep_corrected.jsonl`
- Summary: `summary.json`
- Revalidation: `revalidate_corrected_summary.json`

## Full Ready Roots Result

- Input ready roots: 1158
- FIELD roots checked: 887
- Validated current root: 103
- Same-depth leaf GEP mismatch, auto-corrected: 84
- Aggregate/nested leaf GEP, not auto-corrected: 45
- Aggregate/parent-only GEP, not auto-corrected: 16
- Ambiguous same-depth leaf GEP, not auto-corrected: 3
- No named GEP: 636

The 84 auto-corrections exactly match the previous conservative GEP gate set.

## Active130 Intersection

- Active params: 130
- Active FIELD roots resolved here: 81
- Validated current root: 21
- Same-depth leaf GEP mismatch, auto-corrected: 13
- Aggregate/parent-only GEP, not auto-corrected: 1
- No named GEP: 46

The 13 active130 corrections are:

- `net/ipv4/fib_multipath_use_neigh`: `netns_ipv4.154 -> netns_ipv4.156`
- `net/ipv4/icmp_echo_enable_probe`: `netns_ipv4.51 -> netns_ipv4.53`
- `net/ipv4/icmp_echo_ignore_all`: `netns_ipv4.50 -> netns_ipv4.52`
- `net/ipv4/icmp_echo_ignore_broadcasts`: `netns_ipv4.52 -> netns_ipv4.54`
- `net/ipv4/icmp_errors_use_inbound_ifaddr`: `netns_ipv4.54 -> netns_ipv4.56`
- `net/ipv4/icmp_ignore_bogus_error_responses`: `netns_ipv4.53 -> netns_ipv4.55`
- `net/ipv4/ip_autobind_reuse`: `netns_ipv4.69 -> netns_ipv4.71`
- `net/ipv4/nexthop_compat_mode`: `netns_ipv4.72 -> netns_ipv4.74`
- `net/ipv4/tcp_backlog_ack_defer`: `netns_ipv4.88 -> netns_ipv4.90`
- `net/ipv4/tcp_ecn_fallback`: `netns_ipv4.64 -> netns_ipv4.66`
- `net/ipv4/tcp_migrate_req`: `netns_ipv4.86 -> netns_ipv4.88`
- `net/ipv4/tcp_no_ssthresh_metrics_save`: `netns_ipv4.113 -> netns_ipv4.115`
- `net/ipv4/tcp_plb_enabled`: `netns_ipv4.133 -> netns_ipv4.135`

## Revalidation

Revalidating the corrected roots with the previous GEP validator produced:

- `ok_named_gep`: 187
- `mismatch_named_gep`: 59
- `no_named_gep_no_root_seen`: 641
- `auto_correctable_mismatch_count`: 0

The remaining 59 mismatches are depth-mismatched nested/array/aggregate cases,
for example `nf_tcp_net.0.8 -> nf_tcp_net.0` and
`user_namespace.17.0 -> user_namespace.17`; they are intentionally not
rewritten by this resolver.
