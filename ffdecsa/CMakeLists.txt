project (ffdecsa)

file (GLOB ffdecsa_srcs "ffdecsa.c")
file (GLOB ffdecsa_hdrs "*.h")

set (lib_name "ffdecsa")

if (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86)|(X86)|(amd64)|(AMD64)")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -msse -msse2 -msse3")
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "(arm)|(ARM)")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfpu=neon")
    set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -mfpu=neon")
endif (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86)|(X86)|(amd64)|(AMD64)")

if (CMAKE_COMPILER_IS_GNUCC)
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -O3 -pipe -ffunction-sections -fdata-sections -funroll-loops -fomit-frame-pointer -fno-schedule-insns")
endif (CMAKE_COMPILER_IS_GNUCC)

add_library (${lib_name} STATIC ${ffdecsa_srcs} ${ffdecsa_hdrs})
