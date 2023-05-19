project(kyber C ASM)

set(KYBER_SRCS
  src/ref/kex.c
  src/ref/kem.c
  src/ref/indcpa.c
  src/ref/polyvec.c
  src/ref/poly.c
  src/ref/ntt.c
  src/ref/cbd.c
  src/ref/reduce.c
  src/ref/verify.c
  src/ref/randombytes.c
)
set(KYBER_FIPS202_SRCS ${KYBER_SRCS} src/ref/symmetric-shake.c)
set(KYBER_NINETIES_SRCS ${KYBER_SRCS} src/ref/symmetric-aes.c)
set(FIPS202_SRCS src/ref/fips202.c)
set(AES256CTR_SRCS src/ref/aes256ctr.c)
set(SHA2_SRCS src/ref/sha256.c src/ref/sha512.c)
set(TEST_KYBER_SRCS src/ref/test_kyber.c src/ref/randombytes.c)
set(TEST_KEX_SRCS src/ref/test_kex.c src/ref/randombytes.c)
set(TEST_VECTORS_SRCS src/ref/test_vectors.c)
set(TEST_SPEED_SRCS src/ref/test_speed.c src/ref/speed_print.c src/ref/cpucycles.c src/ref/randombytes.c)

if(MSVC)
  add_compile_options(/nologo /O2 /W4 /wd4146 /wd4244)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Werror)
  add_compile_options(-Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith)
  add_compile_options(-O3 -fomit-frame-pointer)
endif()

add_library(fips202_ref ${FIPS202_SRCS})
add_library(aes256ctr_ref ${AES256CTR_SRCS})
add_library(sha2_ref ${SHA2_SRCS})

# Kyber 1024
add_library(kyber ${KYBER_FIPS202_SRCS})
# add_library(kyber1024_90s_ref ${KYBER_NINETIES_SRCS})
target_compile_definitions(kyber PUBLIC KYBER_K=4)
# target_compile_definitions(kyber1024_90s_ref PUBLIC KYBER_K=4 KYBER_90S)
target_link_libraries(kyber PUBLIC fips202_ref)
# target_link_libraries(kyber1024_90s_ref INTERFACE aes256ctr_ref sha2_ref)

add_test(NAME kyber COMMAND test_kyber1024_ref)
# add_test(NAME kex1024_ref COMMAND test_kex1024_ref)
# add_test(NAME kyber1024-90s_ref COMMAND test_kyber1024-90s_ref)
# add_test(NAME kex1024-90_ref COMMAND test_kex1024-90s_ref)

if(WIN32)
  add_test(NAME vectors1024_ref COMMAND PowerShell -Command "$<TARGET_FILE:test_vectors1024_ref> | dos2unix > tvecs1024")
  # add_test(NAME vectors1024-90s_ref COMMAND PowerShell -Command "$<TARGET_FILE:test_vectors1024-90s_ref> | dos2unix > tvecs1024-90s")
  add_test(NAME debug COMMAND powershell -Command "gc tvecs512 | select -first 10")
else()
  add_test(NAME vectors1024_ref COMMAND sh -c "\"$<TARGET_FILE:test_vectors1024_ref>\" > tvecs1024")
  # add_test(NAME vectors1024-90s_ref COMMAND sh -c "\"$<TARGET_FILE:test_vectors1024-90s_ref>\" > tvecs1024-90s")
endif()

install(TARGETS kyber fips202_ref aes256ctr_ref sha2_ref
  CONFIGURATIONS ${CMAKE_BUILD_TYPE}
  EXPORT kyberTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
# add_test(NAME hashes COMMAND sha256sum -c ../../SHA256SUMS)
