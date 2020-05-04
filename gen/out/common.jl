# Automatically generated using Clang.jl


# Skipping MacroDefinition: SODIUM_EXPORT __attribute__ ( ( visibility ( "default" ) ) )
# Skipping MacroDefinition: SODIUM_EXPORT_WEAK SODIUM_EXPORT __attribute__ ( ( weak ) )
# Skipping MacroDefinition: CRYPTO_ALIGN ( x ) __attribute__ ( ( aligned ( x ) ) )
# Skipping MacroDefinition: SODIUM_MIN ( A , B ) ( ( A ) < ( B ) ? ( A ) : ( B ) )
# Skipping MacroDefinition: SODIUM_SIZE_MAX SODIUM_MIN ( UINT64_MAX , SIZE_MAX )

const crypto_hash_sha512_BYTES = UInt32(64)

struct crypto_hash_sha512_state
    state::NTuple{8, UInt64}
    count::NTuple{2, UInt64}
    buf::NTuple{128, UInt8}
end

const crypto_sign_ed25519_BYTES = UInt32(64)
const crypto_sign_ed25519_SEEDBYTES = UInt32(32)
const crypto_sign_ed25519_PUBLICKEYBYTES = UInt32(32)
const crypto_sign_ed25519_SECRETKEYBYTES = UInt32(32) + UInt32(32)

struct crypto_sign_ed25519ph_state
    hs::crypto_hash_sha512_state
end
