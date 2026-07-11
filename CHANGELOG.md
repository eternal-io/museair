# CHANGELOG

## Algorithm itself

### Before v1

For version `v0.4-rc4` of the algorithm, its 128-bit version had insufficient output diffusion and actually failed the SMHasher3 test suite.

This was caused by incorrectly extrapolating the quality performance of the 64-bit version to the 128-bit version.
The issue was resolved by applying an additional avalanche step to the 128-bit version.

## This crate

### Before 0.5

For versions `0.4.0` and earlier of this crate, the incremental hasher implementation contained a critical bug.

When the total bytes written exceeded 192 bytes, the incremental output would almost certainly differ from the one-shot output.
Furthermore, inconsistent write chunking could also cause the incremental output to be unstable in itself.

These versions have all been yanked from crates.io.
