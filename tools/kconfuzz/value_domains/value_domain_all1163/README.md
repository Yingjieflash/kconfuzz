# Runtime Param Mutation Domains

This directory contains the compact value-domain table for direct runtime
parameter mutation.

Primary file:

- `runtime_param_mutation_domains.jsonl`: all params from the selected
  `param_functions.jsonl`, including disabled rows with `skip_reason`.
- `runtime_param_mutation_domains.enabled.jsonl`: only rows where
  `mutation_enabled` is true.
- `parameter_mutator_table.simple.jsonl`: compatibility table using the flat
  fields consumed by the runtime config mutator.
- `summary.json`: counts and source paths.

Selection policy:

- Target weights are `{'tfuzz_semantic_values': 40, 'seed_values': 20, 'random_legal_values': 35, 'out_of_domain_probe_values': 5}`.
- If a per-param pool is empty, use `effective_weights_percent`, which
  renormalizes the target weights across available pools for that param.
- `random_legal.mode=explicit_values` means sample uniformly from
  `random_legal.explicit_values`.
- `random_legal.mode=*range` means sample an integer in
  `[sample_min, sample_max]`.
- `out_of_domain_probe_values` are intentionally outside the inferred legal
  domain and should be used with the configured low probability.

Generated rows: 1163
Mutation-enabled rows: 1101
Simple mutator rows: 1101
