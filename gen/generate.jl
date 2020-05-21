module LibSodiumClangWrap
using Clang
using Printf

using libsodium_jll

m = @eval module Anon end
const LIBSODIUM_JLL_DIR = dirname(dirname(pathof(libsodium_jll)))
m.include(joinpath(LIBSODIUM_JLL_DIR, "src", "libsodium_jll.jl"))

const LIBSODIUM_DIR = dirname(dirname(m.libsodium_jll.libsodium_path))
const LIBSODIUM_INCLUDE = joinpath(LIBSODIUM_DIR, "include", "sodium")

const HEADER_FNAMES = ["core.h",
                       "export.h",
                       "crypto_hash_sha512.h",
                       "crypto_sign_ed25519.h"]
const HEADER_PATHS = map(hn -> joinpath(LIBSODIUM_INCLUDE, hn) |> normpath,
                         HEADER_FNAMES)

const IGNORE_DEFINITIONS = ["crypto_sign_ed25519_MESSAGEBYTES_MAX",
                            "crypto_sign_ed25519_open"]
function cursor_wrapped(cursor_name, cursor)
    any(map(def -> startswith(cursor_name, def), IGNORE_DEFINITIONS)) ? false : true
end

const OUTPUT_DIR = abspath(@__DIR__, "out")

wc = init(; headers = HEADER_PATHS,
            output_file = joinpath(OUTPUT_DIR, "api.jl"),
            common_file = joinpath(OUTPUT_DIR, "common.jl"),
            clang_includes = vcat(LIBSODIUM_INCLUDE, CLANG_INCLUDE),
            clang_args = ["-I", joinpath(LIBSODIUM_INCLUDE, "..")],
            header_wrapped = (root, current)->root == current,
            header_library = x->"libsodium",
            cursor_wrapped = cursor_wrapped,
            clang_diagnostics = true,
            )

run(wc)

end
