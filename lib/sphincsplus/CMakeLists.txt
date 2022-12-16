project(sphincsplus C ASM)

set(SPHINCSPLUS_SRCS
  src/ref/address.c 
  src/ref/randombytes.c 
  src/ref/merkle.c 
  src/ref/wots.c 
  src/ref/wotsx1.c 
  src/ref/utils.c 
  src/ref/utilsx1.c 
  src/ref/fors.c 
  src/ref/sign.c
)

set(SPHINCSPLUS_FIPS202_SRCS
  src/ref/fips202.c 
  src/ref/hash_shake.c 
  src/ref/thash_shake_robust.c
)

if(MSVC)
  add_compile_options(/nologo /O2 /W4 /wd4146 /wd4244)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -O3 -std=c99 -Wconversion -Wmissing-prototypes)
endif()

add_library(sphincsplus 
  ${SPHINCSPLUS_SRCS}
  ${SPHINCSPLUS_FIPS202_SRCS}
)

target_include_directories(
  sphincsplus
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/ref>
)
