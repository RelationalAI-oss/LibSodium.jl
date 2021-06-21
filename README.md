_**This Repo is DEPRECATED. Please prefer https://github.com/Gnimuc/Sodium.jl.**_

# LibSodium.jl
This packages generates Julia bindings for (part of) the `libsodium` library, relying on
`Clang.jl`.

_Warning_: Currently, it generates bindings only for the part of `libsodium` needed for
generating (but _not_ verifying) Ed25519 public-key signatures. Supporting the full
`libsodium` functionality would require the proper translation of `libsodium` macros that
depend transitively on compiler macros like `__INT64_C` which require concatenation (`##`).
These cases don't seem to be handled by `Clang.jl` out of the box.
