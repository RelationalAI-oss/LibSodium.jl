module LibSodium

using libsodium_jll

const OUTPUT_DIR = abspath(@__DIR__, "..", "gen", "out")

include(joinpath(OUTPUT_DIR, "ctypes.jl"))
export Ctm, Ctime_t, Cclock_t
include(joinpath(OUTPUT_DIR, "common.jl"))
include(joinpath(OUTPUT_DIR, "api.jl"))

foreach(names(@__MODULE__, all=true)) do s
    if any([startswith(string(s), prefix) for prefix in ["sodium_", "crypto_"]])
        @eval export $s
    end
end

end
