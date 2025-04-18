# Review

- This attack focuses on returning an arbitrary pointer from `malloc`.
- Root cause: can modify top chunk size.
- Applicable until: < `glibc 2.29`.

# Idea

Leverage an overflow into the top chunk and change its size to a large value to bridge the gap between the top chunk and the target (can span and wrap around the whole VA space). This allows us to request a new chunk overlapping the target and overwriting it with user controlled data. The technique worked as the top chunk size was not subject to any size integrity checks, nor was malloc checked for arbitrarily large allocation request that would exhaust the whole VA space.

# Further use

- arbitrary read and write
- rce

# Limits

`glibc 2.29` introduced a top chunk size field sanity check, which ensures that the top chunk size does not exceed its arena’s system_mem value.
`glibc 2.30` introduced a maximum allocation size check, which limits the size of the gap the House of Force can bridge.