module LibSodium

using libsodium_jll

const OUTPUT_DIR = abspath(@__DIR__, "..", "gen", "out")

include(joinpath(OUTPUT_DIR, "exports.jl"))
include(joinpath(OUTPUT_DIR, "ctypes.jl"))
export Ctm, Ctime_t, Cclock_t
include(joinpath(OUTPUT_DIR, "common.jl"))
include(joinpath(OUTPUT_DIR, "api.jl"))

end
