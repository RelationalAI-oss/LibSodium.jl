using LibSodium
using Test

@testset "Public-key signatures - Ed25519 - Signing" begin

    sodium_init()

    string_to_sign = "test"

    seed_hex = "3ba564b9eb1a7e4549da027dc6dea3fb8ba0c2970f65cdcca13bd3a8dc8e7de7"
    seed = hex2bytes(seed_hex)

    # Generate public & secret key
    pk = Vector{Cuchar}(undef, crypto_sign_ed25519_PUBLICKEYBYTES)
    sk = Vector{Cuchar}(undef, crypto_sign_ed25519_SECRETKEYBYTES)
    crypto_sign_ed25519_seed_keypair(pk, sk, seed)

    @test bytes2hex(sk) == "3ba564b9eb1a7e4549da027dc6dea3fb8ba0c2970f65cdcca13bd3a8dc8e7de7e539bc6e0faa5df63176178f8809bfcbd4a6ac3178803a89e697ebe309384879"
    @test sizeof(sk) == 64

    signed_message = Vector{Cuchar}(undef, crypto_sign_ed25519_BYTES + sizeof(string_to_sign))
    signed_message_len = Ref{Culonglong}(0)

    signature = Vector{Cuchar}(undef, crypto_sign_ed25519_BYTES)
    signature_len = Ref{Culonglong}(0)

    crypto_sign_ed25519(signed_message, signed_message_len, string_to_sign, sizeof(string_to_sign), sk)
    crypto_sign_ed25519_detached(signature, signature_len, string_to_sign, sizeof(string_to_sign), sk)

    @test bytes2hex(signed_message) == "13247659998dd51b975a273d39f646bbbf1e48b61168605b6c727803cef30c6ef5370e9f4cb8faf2cb773fc82886bffe5d5603165293b62c83edc34a86af0d0774657374"
    @test signed_message_len[] == 68
    @test bytes2hex(signature) == "13247659998dd51b975a273d39f646bbbf1e48b61168605b6c727803cef30c6ef5370e9f4cb8faf2cb773fc82886bffe5d5603165293b62c83edc34a86af0d07"
    @test signature_len[] == 64

end
