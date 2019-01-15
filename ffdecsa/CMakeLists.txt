project (ffdecsa)

file (GLOB ffdecsa_srcs "ffdecsa.c")
file (GLOB ffdecsa_hdrs "*.h")

set (lib_name "ffdecsa")

add_library (${lib_name} STATIC ${ffdecsa_srcs} ${ffdecsa_hdrs})
