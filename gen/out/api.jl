# Julia wrapper for header: core.h
# Automatically generated using Clang.jl


function sodium_init()
    ccall((:sodium_init, libsodium), Cint, ())
end

function sodium_set_misuse_handler(handler)
    ccall((:sodium_set_misuse_handler, libsodium), Cint, (Ptr{Cvoid},), handler)
end

function sodium_misuse()
    ccall((:sodium_misuse, libsodium), Cvoid, ())
end
# Julia wrapper for header: export.h
# Automatically generated using Clang.jl

# Julia wrapper for header: crypto_hash_sha512.h
# Automatically generated using Clang.jl


function crypto_hash_sha512_statebytes()
    ccall((:crypto_hash_sha512_statebytes, libsodium), Csize_t, ())
end

function crypto_hash_sha512_bytes()
    ccall((:crypto_hash_sha512_bytes, libsodium), Csize_t, ())
end

function crypto_hash_sha512(out, in, inlen)
    ccall((:crypto_hash_sha512, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong), out, in, inlen)
end

function crypto_hash_sha512_init(state)
    ccall((:crypto_hash_sha512_init, libsodium), Cint, (Ptr{crypto_hash_sha512_state},), state)
end

function crypto_hash_sha512_update(state, in, inlen)
    ccall((:crypto_hash_sha512_update, libsodium), Cint, (Ptr{crypto_hash_sha512_state}, Ptr{Cuchar}, Culonglong), state, in, inlen)
end

function crypto_hash_sha512_final(state, out)
    ccall((:crypto_hash_sha512_final, libsodium), Cint, (Ptr{crypto_hash_sha512_state}, Ptr{Cuchar}), state, out)
end
# Julia wrapper for header: crypto_sign_ed25519.h
# Automatically generated using Clang.jl


function crypto_sign_ed25519ph_statebytes()
    ccall((:crypto_sign_ed25519ph_statebytes, libsodium), Csize_t, ())
end

function crypto_sign_ed25519_bytes()
    ccall((:crypto_sign_ed25519_bytes, libsodium), Csize_t, ())
end

function crypto_sign_ed25519_seedbytes()
    ccall((:crypto_sign_ed25519_seedbytes, libsodium), Csize_t, ())
end

function crypto_sign_ed25519_publickeybytes()
    ccall((:crypto_sign_ed25519_publickeybytes, libsodium), Csize_t, ())
end

function crypto_sign_ed25519_secretkeybytes()
    ccall((:crypto_sign_ed25519_secretkeybytes, libsodium), Csize_t, ())
end

function crypto_sign_ed25519_messagebytes_max()
    ccall((:crypto_sign_ed25519_messagebytes_max, libsodium), Csize_t, ())
end

function crypto_sign_ed25519(sm, smlen_p, m, mlen, sk)
    ccall((:crypto_sign_ed25519, libsodium), Cint, (Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), sm, smlen_p, m, mlen, sk)
end

function crypto_sign_ed25519_detached(sig, siglen_p, m, mlen, sk)
    ccall((:crypto_sign_ed25519_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), sig, siglen_p, m, mlen, sk)
end

function crypto_sign_ed25519_verify_detached(sig, m, mlen, pk)
    ccall((:crypto_sign_ed25519_verify_detached, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Culonglong, Ptr{Cuchar}), sig, m, mlen, pk)
end

function crypto_sign_ed25519_keypair(pk, sk)
    ccall((:crypto_sign_ed25519_keypair, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), pk, sk)
end

function crypto_sign_ed25519_seed_keypair(pk, sk, seed)
    ccall((:crypto_sign_ed25519_seed_keypair, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}, Ptr{Cuchar}), pk, sk, seed)
end

function crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, ed25519_pk)
    ccall((:crypto_sign_ed25519_pk_to_curve25519, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), curve25519_pk, ed25519_pk)
end

function crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, ed25519_sk)
    ccall((:crypto_sign_ed25519_sk_to_curve25519, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), curve25519_sk, ed25519_sk)
end

function crypto_sign_ed25519_sk_to_seed(seed, sk)
    ccall((:crypto_sign_ed25519_sk_to_seed, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), seed, sk)
end

function crypto_sign_ed25519_sk_to_pk(pk, sk)
    ccall((:crypto_sign_ed25519_sk_to_pk, libsodium), Cint, (Ptr{Cuchar}, Ptr{Cuchar}), pk, sk)
end

function crypto_sign_ed25519ph_init(state)
    ccall((:crypto_sign_ed25519ph_init, libsodium), Cint, (Ptr{crypto_sign_ed25519ph_state},), state)
end

function crypto_sign_ed25519ph_update(state, m, mlen)
    ccall((:crypto_sign_ed25519ph_update, libsodium), Cint, (Ptr{crypto_sign_ed25519ph_state}, Ptr{Cuchar}, Culonglong), state, m, mlen)
end

function crypto_sign_ed25519ph_final_create(state, sig, siglen_p, sk)
    ccall((:crypto_sign_ed25519ph_final_create, libsodium), Cint, (Ptr{crypto_sign_ed25519ph_state}, Ptr{Cuchar}, Ptr{Culonglong}, Ptr{Cuchar}), state, sig, siglen_p, sk)
end

function crypto_sign_ed25519ph_final_verify(state, sig, pk)
    ccall((:crypto_sign_ed25519ph_final_verify, libsodium), Cint, (Ptr{crypto_sign_ed25519ph_state}, Ptr{Cuchar}, Ptr{Cuchar}), state, sig, pk)
end
