# Simple Mutator Table Schema

File: `parameter_mutator_table.simple.jsonl`

This is the mutator-facing table. It is filtered from
`parameter_value_domains.final.jsonl` and keeps only rows that are usable for
online numeric sysctl mutation.

## Row Filter

Included rows satisfy:

```text
eligible_for_online_mutation == true
and at least one usable pool exists
```

Current count:

```text
source records: 458
simple table records: 424
```

Skipped rows include one-way parameters, strings, non-writable parameters, and
rows with no usable value pool.

## Probability Fields

Each row has four direct probability fields:

```text
prob_tfuzz
prob_seed
prob_random_legal
prob_out_of_domain
```

They always sum to `100`.

The base policy is:

```text
60%  tfuzz_values
20%  seed_values
15%  random legal value
5%   out_of_domain_values
```

If a pool is unavailable for a row, its probability becomes `0` and the normal
probability is redistributed to available pools. `out_of_domain` stays at `5%`
when available and at least one normal pool exists.

Example:

```text
all pools available:       60 / 20 / 15 / 5
no tfuzz, has seed/random: 0 / 54 / 41 / 5
tfuzz+seed only:           71 / 24 / 0 / 5
seed only, no invalid:     0 / 100 / 0 / 0
```

## Fields

- `schema_version`: currently `simple-mutator-table-v1`.
- `param`: sysctl path without `/proc/sys/`.
- `proc_sys_path`: full procfs path to write.
- `value_format`: currently `decimal_int`; write values as decimal strings.
- `kind`: domain kind, such as `strict_bool`, `bool_like_int`,
  `bounded_numeric_taint`, `unbounded_numeric`, or `small_enum_int`.
- `family`: coarse family: `bool`, `numeric`, `enum`, or `bitmask`.
- `confidence`: `high`, `medium`, or `low`.
- `handler`: sysctl proc handler.
- `current_value`: current runtime value as text.
- `current_value_int`: parsed current integer, or `null`.
- `min`: known legal lower bound, or `null`.
- `max`: known legal upper bound, or `null`.
- `has_complete_range`: true if both `min` and `max` are known.

## Value Pools

- `tfuzz_values`: values inferred from TFuzz/taint use sites, already clipped to
  known legal constraints.
- `seed_values`: deterministic seed values. This includes TFuzz values, static
  legal seeds, boundary values, and current-value neighbors.
- `out_of_domain_values`: low-rate invalid or out-of-range probes.

## Random Legal Fields

Use these only when `prob_random_legal > 0`.

- `random_min`: inclusive lower bound for random generation.
- `random_max`: inclusive upper bound for random generation.
- `random_mode`: range source:
  - `bounded_range`: complete sysctl min/max.
  - `lower_bounded_type_range`: known lower bound, type-level upper bound.
  - `upper_bounded_type_range`: known upper bound, type-level lower bound.
  - `numeric_type_range`: no sysctl bounds, type-level range only.
- `random_bits`: integer width hint.
- `random_signedness`: `signed`, `unsigned`, or `unknown`.

## Mutator Pseudocode

```text
for row in table:
    pick n in [0, 99]

    if n < prob_tfuzz:
        value = choose(row.tfuzz_values)
    elif n < prob_tfuzz + prob_seed:
        value = choose(row.seed_values)
    elif n < prob_tfuzz + prob_seed + prob_random_legal:
        value = random_int(row.random_min, row.random_max)
    else:
        value = choose(row.out_of_domain_values)

    write row.proc_sys_path with decimal(value)
```

For first experiments, use:

```text
confidence in {"high", "medium"}
```

For broader coverage, include `low` but report it separately.

