project(pqclean C ASM)

set(PQCLEAN_COMMON_SRCS
    src/common/aes.c
    src/common/fips202.c
    src/common/nistseedexpander.c
    src/common/randombytes.c
    src/common/sha2.c
    src/common/sp800-185.c
)

set(HQC_128_SRCS
    src/crypto_kem/hqc-128/clean/code.c
    src/crypto_kem/hqc-128/clean/fft.c
    src/crypto_kem/hqc-128/clean/gf.c
    src/crypto_kem/hqc-128/clean/gf2x.c
    src/crypto_kem/hqc-128/clean/hqc.c
    src/crypto_kem/hqc-128/clean/kem.c
    src/crypto_kem/hqc-128/clean/parsing.c
    src/crypto_kem/hqc-128/clean/reed_muller.c
    src/crypto_kem/hqc-128/clean/reed_solomon.c
    src/crypto_kem/hqc-128/clean/shake_ds.c
    src/crypto_kem/hqc-128/clean/shake_prng.c
    src/crypto_kem/hqc-128/clean/vector.c
)

set(HQC_192_SRCS
    src/crypto_kem/hqc-192/clean/code.c
    src/crypto_kem/hqc-192/clean/fft.c
    src/crypto_kem/hqc-192/clean/gf.c
    src/crypto_kem/hqc-192/clean/gf2x.c
    src/crypto_kem/hqc-192/clean/hqc.c
    src/crypto_kem/hqc-192/clean/kem.c
    src/crypto_kem/hqc-192/clean/parsing.c
    src/crypto_kem/hqc-192/clean/reed_muller.c
    src/crypto_kem/hqc-192/clean/reed_solomon.c
    src/crypto_kem/hqc-192/clean/shake_ds.c
    src/crypto_kem/hqc-192/clean/shake_prng.c
    src/crypto_kem/hqc-192/clean/vector.c
)

set(HQC_256_SRCS
    src/crypto_kem/hqc-256/clean/code.c
    src/crypto_kem/hqc-256/clean/fft.c
    src/crypto_kem/hqc-256/clean/gf.c
    src/crypto_kem/hqc-256/clean/gf2x.c
    src/crypto_kem/hqc-256/clean/hqc.c
    src/crypto_kem/hqc-256/clean/kem.c
    src/crypto_kem/hqc-256/clean/parsing.c
    src/crypto_kem/hqc-256/clean/reed_muller.c
    src/crypto_kem/hqc-256/clean/reed_solomon.c
    src/crypto_kem/hqc-256/clean/shake_ds.c
    src/crypto_kem/hqc-256/clean/shake_prng.c
    src/crypto_kem/hqc-256/clean/vector.c
)

set(MLKEM512_SRCS
    src/crypto_kem/ml-kem-512/clean/cbd.c
    src/crypto_kem/ml-kem-512/clean/indcpa.c
    src/crypto_kem/ml-kem-512/clean/kem.c
    src/crypto_kem/ml-kem-512/clean/ntt.c
    src/crypto_kem/ml-kem-512/clean/poly.c
    src/crypto_kem/ml-kem-512/clean/polyvec.c
    src/crypto_kem/ml-kem-512/clean/reduce.c
    src/crypto_kem/ml-kem-512/clean/symmetric-shake.c
    src/crypto_kem/ml-kem-512/clean/verify.c
)

set(MLKEM768_SRCS
    src/crypto_kem/ml-kem-768/clean/cbd.c
    src/crypto_kem/ml-kem-768/clean/indcpa.c
    src/crypto_kem/ml-kem-768/clean/kem.c
    src/crypto_kem/ml-kem-768/clean/ntt.c
    src/crypto_kem/ml-kem-768/clean/poly.c
    src/crypto_kem/ml-kem-768/clean/polyvec.c
    src/crypto_kem/ml-kem-768/clean/reduce.c
    src/crypto_kem/ml-kem-768/clean/symmetric-shake.c
    src/crypto_kem/ml-kem-768/clean/verify.c
)

set(MLKEM1024_SRCS
    src/crypto_kem/ml-kem-1024/clean/cbd.c
    src/crypto_kem/ml-kem-1024/clean/indcpa.c
    src/crypto_kem/ml-kem-1024/clean/kem.c
    src/crypto_kem/ml-kem-1024/clean/ntt.c
    src/crypto_kem/ml-kem-1024/clean/poly.c
    src/crypto_kem/ml-kem-1024/clean/polyvec.c
    src/crypto_kem/ml-kem-1024/clean/reduce.c
    src/crypto_kem/ml-kem-1024/clean/symmetric-shake.c
    src/crypto_kem/ml-kem-1024/clean/verify.c
)

set(MCELIECE348864_SRCS
    src/crypto_kem/mceliece348864/clean/aes256ctr.c
    src/crypto_kem/mceliece348864/clean/benes.c
    src/crypto_kem/mceliece348864/clean/bm.c
    src/crypto_kem/mceliece348864/clean/controlbits.c
    src/crypto_kem/mceliece348864/clean/crypto_int16.c
    src/crypto_kem/mceliece348864/clean/crypto_int32.c
    src/crypto_kem/mceliece348864/clean/crypto_uint16.c
    src/crypto_kem/mceliece348864/clean/crypto_uint32.c
    src/crypto_kem/mceliece348864/clean/crypto_uint64.c
    src/crypto_kem/mceliece348864/clean/decrypt.c
    src/crypto_kem/mceliece348864/clean/encrypt.c
    src/crypto_kem/mceliece348864/clean/gf.c
    src/crypto_kem/mceliece348864/clean/operations.c
    src/crypto_kem/mceliece348864/clean/pk_gen.c
    src/crypto_kem/mceliece348864/clean/root.c
    src/crypto_kem/mceliece348864/clean/sk_gen.c
    src/crypto_kem/mceliece348864/clean/synd.c
    src/crypto_kem/mceliece348864/clean/transpose.c
    src/crypto_kem/mceliece348864/clean/util.c
)

set(MCELIECE348864F_SRCS
    src/crypto_kem/mceliece348864f/clean/aes256ctr.c
    src/crypto_kem/mceliece348864f/clean/benes.c
    src/crypto_kem/mceliece348864f/clean/bm.c
    src/crypto_kem/mceliece348864f/clean/controlbits.c
    src/crypto_kem/mceliece348864f/clean/crypto_int16.c
    src/crypto_kem/mceliece348864f/clean/crypto_int32.c
    src/crypto_kem/mceliece348864f/clean/crypto_uint16.c
    src/crypto_kem/mceliece348864f/clean/crypto_uint32.c
    src/crypto_kem/mceliece348864f/clean/crypto_uint64.c
    src/crypto_kem/mceliece348864f/clean/decrypt.c
    src/crypto_kem/mceliece348864f/clean/encrypt.c
    src/crypto_kem/mceliece348864f/clean/gf.c
    src/crypto_kem/mceliece348864f/clean/operations.c
    src/crypto_kem/mceliece348864f/clean/pk_gen.c
    src/crypto_kem/mceliece348864f/clean/root.c
    src/crypto_kem/mceliece348864f/clean/sk_gen.c
    src/crypto_kem/mceliece348864f/clean/synd.c
    src/crypto_kem/mceliece348864f/clean/transpose.c
    src/crypto_kem/mceliece348864f/clean/util.c
)

set(MCELIECE460896_SRCS
    src/crypto_kem/mceliece460896/clean/aes256ctr.c
    src/crypto_kem/mceliece460896/clean/benes.c
    src/crypto_kem/mceliece460896/clean/bm.c
    src/crypto_kem/mceliece460896/clean/controlbits.c
    src/crypto_kem/mceliece460896/clean/crypto_int16.c
    src/crypto_kem/mceliece460896/clean/crypto_int32.c
    src/crypto_kem/mceliece460896/clean/crypto_uint16.c
    src/crypto_kem/mceliece460896/clean/crypto_uint32.c
    src/crypto_kem/mceliece460896/clean/crypto_uint64.c
    src/crypto_kem/mceliece460896/clean/decrypt.c
    src/crypto_kem/mceliece460896/clean/encrypt.c
    src/crypto_kem/mceliece460896/clean/gf.c
    src/crypto_kem/mceliece460896/clean/operations.c
    src/crypto_kem/mceliece460896/clean/pk_gen.c
    src/crypto_kem/mceliece460896/clean/root.c
    src/crypto_kem/mceliece460896/clean/sk_gen.c
    src/crypto_kem/mceliece460896/clean/synd.c
    src/crypto_kem/mceliece460896/clean/transpose.c
    src/crypto_kem/mceliece460896/clean/util.c
)

set(MCELIECE460896F_SRCS
    src/crypto_kem/mceliece460896f/clean/aes256ctr.c
    src/crypto_kem/mceliece460896f/clean/benes.c
    src/crypto_kem/mceliece460896f/clean/bm.c
    src/crypto_kem/mceliece460896f/clean/controlbits.c
    src/crypto_kem/mceliece460896f/clean/crypto_int16.c
    src/crypto_kem/mceliece460896f/clean/crypto_int32.c
    src/crypto_kem/mceliece460896f/clean/crypto_uint16.c
    src/crypto_kem/mceliece460896f/clean/crypto_uint32.c
    src/crypto_kem/mceliece460896f/clean/crypto_uint64.c
    src/crypto_kem/mceliece460896f/clean/decrypt.c
    src/crypto_kem/mceliece460896f/clean/encrypt.c
    src/crypto_kem/mceliece460896f/clean/gf.c
    src/crypto_kem/mceliece460896f/clean/operations.c
    src/crypto_kem/mceliece460896f/clean/pk_gen.c
    src/crypto_kem/mceliece460896f/clean/root.c
    src/crypto_kem/mceliece460896f/clean/sk_gen.c
    src/crypto_kem/mceliece460896f/clean/synd.c
    src/crypto_kem/mceliece460896f/clean/transpose.c
    src/crypto_kem/mceliece460896f/clean/util.c
)

set(MCELIECE6688128_SRCS
    src/crypto_kem/mceliece6688128/clean/aes256ctr.c
    src/crypto_kem/mceliece6688128/clean/benes.c
    src/crypto_kem/mceliece6688128/clean/bm.c
    src/crypto_kem/mceliece6688128/clean/controlbits.c
    src/crypto_kem/mceliece6688128/clean/crypto_int16.c
    src/crypto_kem/mceliece6688128/clean/crypto_int32.c
    src/crypto_kem/mceliece6688128/clean/crypto_uint16.c
    src/crypto_kem/mceliece6688128/clean/crypto_uint32.c
    src/crypto_kem/mceliece6688128/clean/crypto_uint64.c
    src/crypto_kem/mceliece6688128/clean/decrypt.c
    src/crypto_kem/mceliece6688128/clean/encrypt.c
    src/crypto_kem/mceliece6688128/clean/gf.c
    src/crypto_kem/mceliece6688128/clean/operations.c
    src/crypto_kem/mceliece6688128/clean/pk_gen.c
    src/crypto_kem/mceliece6688128/clean/root.c
    src/crypto_kem/mceliece6688128/clean/sk_gen.c
    src/crypto_kem/mceliece6688128/clean/synd.c
    src/crypto_kem/mceliece6688128/clean/transpose.c
    src/crypto_kem/mceliece6688128/clean/util.c
)

set(MCELIECE6688128F_SRCS
    src/crypto_kem/mceliece6688128f/clean/aes256ctr.c
    src/crypto_kem/mceliece6688128f/clean/benes.c
    src/crypto_kem/mceliece6688128f/clean/bm.c
    src/crypto_kem/mceliece6688128f/clean/controlbits.c
    src/crypto_kem/mceliece6688128f/clean/crypto_int16.c
    src/crypto_kem/mceliece6688128f/clean/crypto_int32.c
    src/crypto_kem/mceliece6688128f/clean/crypto_uint16.c
    src/crypto_kem/mceliece6688128f/clean/crypto_uint32.c
    src/crypto_kem/mceliece6688128f/clean/crypto_uint64.c
    src/crypto_kem/mceliece6688128f/clean/decrypt.c
    src/crypto_kem/mceliece6688128f/clean/encrypt.c
    src/crypto_kem/mceliece6688128f/clean/gf.c
    src/crypto_kem/mceliece6688128f/clean/operations.c
    src/crypto_kem/mceliece6688128f/clean/pk_gen.c
    src/crypto_kem/mceliece6688128f/clean/root.c
    src/crypto_kem/mceliece6688128f/clean/sk_gen.c
    src/crypto_kem/mceliece6688128f/clean/synd.c
    src/crypto_kem/mceliece6688128f/clean/transpose.c
    src/crypto_kem/mceliece6688128f/clean/util.c
)

set(MCELIECE6960119_SRCS
    src/crypto_kem/mceliece6960119/clean/aes256ctr.c
    src/crypto_kem/mceliece6960119/clean/benes.c
    src/crypto_kem/mceliece6960119/clean/bm.c
    src/crypto_kem/mceliece6960119/clean/controlbits.c
    src/crypto_kem/mceliece6960119/clean/crypto_int16.c
    src/crypto_kem/mceliece6960119/clean/crypto_int32.c
    src/crypto_kem/mceliece6960119/clean/crypto_uint16.c
    src/crypto_kem/mceliece6960119/clean/crypto_uint32.c
    src/crypto_kem/mceliece6960119/clean/crypto_uint64.c
    src/crypto_kem/mceliece6960119/clean/decrypt.c
    src/crypto_kem/mceliece6960119/clean/encrypt.c
    src/crypto_kem/mceliece6960119/clean/gf.c
    src/crypto_kem/mceliece6960119/clean/operations.c
    src/crypto_kem/mceliece6960119/clean/pk_gen.c
    src/crypto_kem/mceliece6960119/clean/root.c
    src/crypto_kem/mceliece6960119/clean/sk_gen.c
    src/crypto_kem/mceliece6960119/clean/synd.c
    src/crypto_kem/mceliece6960119/clean/transpose.c
    src/crypto_kem/mceliece6960119/clean/util.c
)

set(MCELIECE6960119F_SRCS
    src/crypto_kem/mceliece6960119f/clean/aes256ctr.c
    src/crypto_kem/mceliece6960119f/clean/benes.c
    src/crypto_kem/mceliece6960119f/clean/bm.c
    src/crypto_kem/mceliece6960119f/clean/controlbits.c
    src/crypto_kem/mceliece6960119f/clean/crypto_int16.c
    src/crypto_kem/mceliece6960119f/clean/crypto_int32.c
    src/crypto_kem/mceliece6960119f/clean/crypto_uint16.c
    src/crypto_kem/mceliece6960119f/clean/crypto_uint32.c
    src/crypto_kem/mceliece6960119f/clean/crypto_uint64.c
    src/crypto_kem/mceliece6960119f/clean/decrypt.c
    src/crypto_kem/mceliece6960119f/clean/encrypt.c
    src/crypto_kem/mceliece6960119f/clean/gf.c
    src/crypto_kem/mceliece6960119f/clean/operations.c
    src/crypto_kem/mceliece6960119f/clean/pk_gen.c
    src/crypto_kem/mceliece6960119f/clean/root.c
    src/crypto_kem/mceliece6960119f/clean/sk_gen.c
    src/crypto_kem/mceliece6960119f/clean/synd.c
    src/crypto_kem/mceliece6960119f/clean/transpose.c
    src/crypto_kem/mceliece6960119f/clean/util.c
)

set(MCELIECE8192128_SRCS
    src/crypto_kem/mceliece8192128/clean/aes256ctr.c
    src/crypto_kem/mceliece8192128/clean/benes.c
    src/crypto_kem/mceliece8192128/clean/bm.c
    src/crypto_kem/mceliece8192128/clean/controlbits.c
    src/crypto_kem/mceliece8192128/clean/crypto_int16.c
    src/crypto_kem/mceliece8192128/clean/crypto_int32.c
    src/crypto_kem/mceliece8192128/clean/crypto_uint16.c
    src/crypto_kem/mceliece8192128/clean/crypto_uint32.c
    src/crypto_kem/mceliece8192128/clean/crypto_uint64.c
    src/crypto_kem/mceliece8192128/clean/decrypt.c
    src/crypto_kem/mceliece8192128/clean/encrypt.c
    src/crypto_kem/mceliece8192128/clean/gf.c
    src/crypto_kem/mceliece8192128/clean/operations.c
    src/crypto_kem/mceliece8192128/clean/pk_gen.c
    src/crypto_kem/mceliece8192128/clean/root.c
    src/crypto_kem/mceliece8192128/clean/sk_gen.c
    src/crypto_kem/mceliece8192128/clean/synd.c
    src/crypto_kem/mceliece8192128/clean/transpose.c
    src/crypto_kem/mceliece8192128/clean/util.c
)

set(MCELIECE8192128F_SRCS
    src/crypto_kem/mceliece8192128f/clean/aes256ctr.c
    src/crypto_kem/mceliece8192128f/clean/benes.c
    src/crypto_kem/mceliece8192128f/clean/bm.c
    src/crypto_kem/mceliece8192128f/clean/controlbits.c
    src/crypto_kem/mceliece8192128f/clean/crypto_int16.c
    src/crypto_kem/mceliece8192128f/clean/crypto_int32.c
    src/crypto_kem/mceliece8192128f/clean/crypto_uint16.c
    src/crypto_kem/mceliece8192128f/clean/crypto_uint32.c
    src/crypto_kem/mceliece8192128f/clean/crypto_uint64.c
    src/crypto_kem/mceliece8192128f/clean/decrypt.c
    src/crypto_kem/mceliece8192128f/clean/encrypt.c
    src/crypto_kem/mceliece8192128f/clean/gf.c
    src/crypto_kem/mceliece8192128f/clean/operations.c
    src/crypto_kem/mceliece8192128f/clean/pk_gen.c
    src/crypto_kem/mceliece8192128f/clean/root.c
    src/crypto_kem/mceliece8192128f/clean/sk_gen.c
    src/crypto_kem/mceliece8192128f/clean/synd.c
    src/crypto_kem/mceliece8192128f/clean/transpose.c
    src/crypto_kem/mceliece8192128f/clean/util.c
)

set(MLDSA44_SRCS
    src/crypto_sign/ml-dsa-44/clean/ntt.c
    src/crypto_sign/ml-dsa-44/clean/packing.c
    src/crypto_sign/ml-dsa-44/clean/poly.c
    src/crypto_sign/ml-dsa-44/clean/polyvec.c
    src/crypto_sign/ml-dsa-44/clean/reduce.c
    src/crypto_sign/ml-dsa-44/clean/rounding.c
    src/crypto_sign/ml-dsa-44/clean/sign.c
    src/crypto_sign/ml-dsa-44/clean/symmetric-shake.c
)

set(MLDSA65_SRCS
    src/crypto_sign/ml-dsa-65/clean/ntt.c
    src/crypto_sign/ml-dsa-65/clean/packing.c
    src/crypto_sign/ml-dsa-65/clean/poly.c
    src/crypto_sign/ml-dsa-65/clean/polyvec.c
    src/crypto_sign/ml-dsa-65/clean/reduce.c
    src/crypto_sign/ml-dsa-65/clean/rounding.c
    src/crypto_sign/ml-dsa-65/clean/sign.c
    src/crypto_sign/ml-dsa-65/clean/symmetric-shake.c
)

set(MLDSA87_SRCS
    src/crypto_sign/ml-dsa-87/clean/ntt.c
    src/crypto_sign/ml-dsa-87/clean/packing.c
    src/crypto_sign/ml-dsa-87/clean/poly.c
    src/crypto_sign/ml-dsa-87/clean/polyvec.c
    src/crypto_sign/ml-dsa-87/clean/reduce.c
    src/crypto_sign/ml-dsa-87/clean/rounding.c
    src/crypto_sign/ml-dsa-87/clean/sign.c
    src/crypto_sign/ml-dsa-87/clean/symmetric-shake.c
)

set(FALCON_512_SRCS
    src/crypto_sign/falcon-512/clean/codec.c
    src/crypto_sign/falcon-512/clean/common.c
    src/crypto_sign/falcon-512/clean/fft.c
    src/crypto_sign/falcon-512/clean/fpr.c
    src/crypto_sign/falcon-512/clean/keygen.c
    src/crypto_sign/falcon-512/clean/pqclean.c
    src/crypto_sign/falcon-512/clean/rng.c
    src/crypto_sign/falcon-512/clean/sign.c
    src/crypto_sign/falcon-512/clean/vrfy.c
)

set(FALCON_1024_SRCS
    src/crypto_sign/falcon-1024/clean/codec.c
    src/crypto_sign/falcon-1024/clean/common.c
    src/crypto_sign/falcon-1024/clean/fft.c
    src/crypto_sign/falcon-1024/clean/fpr.c
    src/crypto_sign/falcon-1024/clean/keygen.c
    src/crypto_sign/falcon-1024/clean/pqclean.c
    src/crypto_sign/falcon-1024/clean/rng.c
    src/crypto_sign/falcon-1024/clean/sign.c
    src/crypto_sign/falcon-1024/clean/vrfy.c
)

set(SPHINCS_SHA2_128F_SRCS
    src/crypto_sign/sphincs-sha2-128f-simple/clean/address.c
    src/crypto_sign/sphincs-sha2-128f-simple/clean/context_sha2.c
    src/crypto_sign/sphincs-sha2-128f-simple/clean/fors.c
    src/crypto_sign/sphincs-sha2-128f-simple/clean/hash_sha2.c
    src/crypto_sign/sphincs-sha2-128f-simple/clean/merkle.c
    src/crypto_sign/sphincs-sha2-128f-simple/clean/sign.c
    src/crypto_sign/sphincs-sha2-128f-simple/clean/thash_sha2_simple.c
    src/crypto_sign/sphincs-sha2-128f-simple/clean/utils.c
    src/crypto_sign/sphincs-sha2-128f-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-sha2-128f-simple/clean/wots.c
    src/crypto_sign/sphincs-sha2-128f-simple/clean/wotsx1.c
)

set(SPHINCS_SHA2_128S_SRCS
    src/crypto_sign/sphincs-sha2-128s-simple/clean/address.c
    src/crypto_sign/sphincs-sha2-128s-simple/clean/context_sha2.c
    src/crypto_sign/sphincs-sha2-128s-simple/clean/fors.c
    src/crypto_sign/sphincs-sha2-128s-simple/clean/hash_sha2.c
    src/crypto_sign/sphincs-sha2-128s-simple/clean/merkle.c
    src/crypto_sign/sphincs-sha2-128s-simple/clean/sign.c
    src/crypto_sign/sphincs-sha2-128s-simple/clean/thash_sha2_simple.c
    src/crypto_sign/sphincs-sha2-128s-simple/clean/utils.c
    src/crypto_sign/sphincs-sha2-128s-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-sha2-128s-simple/clean/wots.c
    src/crypto_sign/sphincs-sha2-128s-simple/clean/wotsx1.c
)

set(SPHINCS_SHA2_192F_SRCS
    src/crypto_sign/sphincs-sha2-192f-simple/clean/address.c
    src/crypto_sign/sphincs-sha2-192f-simple/clean/context_sha2.c
    src/crypto_sign/sphincs-sha2-192f-simple/clean/fors.c
    src/crypto_sign/sphincs-sha2-192f-simple/clean/hash_sha2.c
    src/crypto_sign/sphincs-sha2-192f-simple/clean/merkle.c
    src/crypto_sign/sphincs-sha2-192f-simple/clean/sign.c
    src/crypto_sign/sphincs-sha2-192f-simple/clean/thash_sha2_simple.c
    src/crypto_sign/sphincs-sha2-192f-simple/clean/utils.c
    src/crypto_sign/sphincs-sha2-192f-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-sha2-192f-simple/clean/wots.c
    src/crypto_sign/sphincs-sha2-192f-simple/clean/wotsx1.c
)

set(SPHINCS_SHA2_192S_SRCS
    src/crypto_sign/sphincs-sha2-192s-simple/clean/address.c
    src/crypto_sign/sphincs-sha2-192s-simple/clean/context_sha2.c
    src/crypto_sign/sphincs-sha2-192s-simple/clean/fors.c
    src/crypto_sign/sphincs-sha2-192s-simple/clean/hash_sha2.c
    src/crypto_sign/sphincs-sha2-192s-simple/clean/merkle.c
    src/crypto_sign/sphincs-sha2-192s-simple/clean/sign.c
    src/crypto_sign/sphincs-sha2-192s-simple/clean/thash_sha2_simple.c
    src/crypto_sign/sphincs-sha2-192s-simple/clean/utils.c
    src/crypto_sign/sphincs-sha2-192s-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-sha2-192s-simple/clean/wots.c
    src/crypto_sign/sphincs-sha2-192s-simple/clean/wotsx1.c
)

set(SPHINCS_SHA2_256F_SRCS
    src/crypto_sign/sphincs-sha2-256f-simple/clean/address.c
    src/crypto_sign/sphincs-sha2-256f-simple/clean/context_sha2.c
    src/crypto_sign/sphincs-sha2-256f-simple/clean/fors.c
    src/crypto_sign/sphincs-sha2-256f-simple/clean/hash_sha2.c
    src/crypto_sign/sphincs-sha2-256f-simple/clean/merkle.c
    src/crypto_sign/sphincs-sha2-256f-simple/clean/sign.c
    src/crypto_sign/sphincs-sha2-256f-simple/clean/thash_sha2_simple.c
    src/crypto_sign/sphincs-sha2-256f-simple/clean/utils.c
    src/crypto_sign/sphincs-sha2-256f-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-sha2-256f-simple/clean/wots.c
    src/crypto_sign/sphincs-sha2-256f-simple/clean/wotsx1.c
)

set(SPHINCS_SHA2_256S_SRCS
    src/crypto_sign/sphincs-sha2-256s-simple/clean/address.c
    src/crypto_sign/sphincs-sha2-256s-simple/clean/context_sha2.c
    src/crypto_sign/sphincs-sha2-256s-simple/clean/fors.c
    src/crypto_sign/sphincs-sha2-256s-simple/clean/hash_sha2.c
    src/crypto_sign/sphincs-sha2-256s-simple/clean/merkle.c
    src/crypto_sign/sphincs-sha2-256s-simple/clean/sign.c
    src/crypto_sign/sphincs-sha2-256s-simple/clean/thash_sha2_simple.c
    src/crypto_sign/sphincs-sha2-256s-simple/clean/utils.c
    src/crypto_sign/sphincs-sha2-256s-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-sha2-256s-simple/clean/wots.c
    src/crypto_sign/sphincs-sha2-256s-simple/clean/wotsx1.c
)

set(SPHINCS_SHAKE_128F_SRCS
    src/crypto_sign/sphincs-shake-128f-simple/clean/address.c
    src/crypto_sign/sphincs-shake-128f-simple/clean/context_shake.c
    src/crypto_sign/sphincs-shake-128f-simple/clean/fors.c
    src/crypto_sign/sphincs-shake-128f-simple/clean/hash_shake.c
    src/crypto_sign/sphincs-shake-128f-simple/clean/merkle.c
    src/crypto_sign/sphincs-shake-128f-simple/clean/sign.c
    src/crypto_sign/sphincs-shake-128f-simple/clean/thash_shake_simple.c
    src/crypto_sign/sphincs-shake-128f-simple/clean/utils.c
    src/crypto_sign/sphincs-shake-128f-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-shake-128f-simple/clean/wots.c
    src/crypto_sign/sphincs-shake-128f-simple/clean/wotsx1.c
)

set(SPHINCS_SHAKE_128S_SRCS
    src/crypto_sign/sphincs-shake-128s-simple/clean/address.c
    src/crypto_sign/sphincs-shake-128s-simple/clean/context_shake.c
    src/crypto_sign/sphincs-shake-128s-simple/clean/fors.c
    src/crypto_sign/sphincs-shake-128s-simple/clean/hash_shake.c
    src/crypto_sign/sphincs-shake-128s-simple/clean/merkle.c
    src/crypto_sign/sphincs-shake-128s-simple/clean/sign.c
    src/crypto_sign/sphincs-shake-128s-simple/clean/thash_shake_simple.c
    src/crypto_sign/sphincs-shake-128s-simple/clean/utils.c
    src/crypto_sign/sphincs-shake-128s-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-shake-128s-simple/clean/wots.c
    src/crypto_sign/sphincs-shake-128s-simple/clean/wotsx1.c
)

set(SPHINCS_SHAKE_192F_SRCS
    src/crypto_sign/sphincs-shake-192f-simple/clean/address.c
    src/crypto_sign/sphincs-shake-192f-simple/clean/context_shake.c
    src/crypto_sign/sphincs-shake-192f-simple/clean/fors.c
    src/crypto_sign/sphincs-shake-192f-simple/clean/hash_shake.c
    src/crypto_sign/sphincs-shake-192f-simple/clean/merkle.c
    src/crypto_sign/sphincs-shake-192f-simple/clean/sign.c
    src/crypto_sign/sphincs-shake-192f-simple/clean/thash_shake_simple.c
    src/crypto_sign/sphincs-shake-192f-simple/clean/utils.c
    src/crypto_sign/sphincs-shake-192f-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-shake-192f-simple/clean/wots.c
    src/crypto_sign/sphincs-shake-192f-simple/clean/wotsx1.c
)

set(SPHINCS_SHAKE_192S_SRCS
    src/crypto_sign/sphincs-shake-192s-simple/clean/address.c
    src/crypto_sign/sphincs-shake-192s-simple/clean/context_shake.c
    src/crypto_sign/sphincs-shake-192s-simple/clean/fors.c
    src/crypto_sign/sphincs-shake-192s-simple/clean/hash_shake.c
    src/crypto_sign/sphincs-shake-192s-simple/clean/merkle.c
    src/crypto_sign/sphincs-shake-192s-simple/clean/sign.c
    src/crypto_sign/sphincs-shake-192s-simple/clean/thash_shake_simple.c
    src/crypto_sign/sphincs-shake-192s-simple/clean/utils.c
    src/crypto_sign/sphincs-shake-192s-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-shake-192s-simple/clean/wots.c
    src/crypto_sign/sphincs-shake-192s-simple/clean/wotsx1.c
)

set(SPHINCS_SHAKE_256F_SRCS
    src/crypto_sign/sphincs-shake-256f-simple/clean/address.c
    src/crypto_sign/sphincs-shake-256f-simple/clean/context_shake.c
    src/crypto_sign/sphincs-shake-256f-simple/clean/fors.c
    src/crypto_sign/sphincs-shake-256f-simple/clean/hash_shake.c
    src/crypto_sign/sphincs-shake-256f-simple/clean/merkle.c
    src/crypto_sign/sphincs-shake-256f-simple/clean/sign.c
    src/crypto_sign/sphincs-shake-256f-simple/clean/thash_shake_simple.c
    src/crypto_sign/sphincs-shake-256f-simple/clean/utils.c
    src/crypto_sign/sphincs-shake-256f-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-shake-256f-simple/clean/wots.c
    src/crypto_sign/sphincs-shake-256f-simple/clean/wotsx1.c
)

set(SPHINCS_SHAKE_256S_SRCS
    src/crypto_sign/sphincs-shake-256s-simple/clean/address.c
    src/crypto_sign/sphincs-shake-256s-simple/clean/context_shake.c
    src/crypto_sign/sphincs-shake-256s-simple/clean/fors.c
    src/crypto_sign/sphincs-shake-256s-simple/clean/hash_shake.c
    src/crypto_sign/sphincs-shake-256s-simple/clean/merkle.c
    src/crypto_sign/sphincs-shake-256s-simple/clean/sign.c
    src/crypto_sign/sphincs-shake-256s-simple/clean/thash_shake_simple.c
    src/crypto_sign/sphincs-shake-256s-simple/clean/utils.c
    src/crypto_sign/sphincs-shake-256s-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-shake-256s-simple/clean/wots.c
    src/crypto_sign/sphincs-shake-256s-simple/clean/wotsx1.c
)

add_library(
    pqclean STATIC
    ${HQC_128_SRCS}
    ${HQC_192_SRCS}
    ${HQC_256_SRCS}
    ${MLKEM512_SRCS}
    ${MLKEM768_SRCS}
    ${MLKEM1024_SRCS}
    ${MCELIECE348864_SRCS}
    ${MCELIECE348864F_SRCS}
    ${MCELIECE460896_SRCS}
    ${MCELIECE460896F_SRCS}
    ${MCELIECE6688128_SRCS}
    ${MCELIECE6688128F_SRCS}
    ${MCELIECE6960119_SRCS}
    ${MCELIECE6960119F_SRCS}
    ${MCELIECE8192128_SRCS}
    ${MCELIECE8192128F_SRCS}
    ${MLDSA44_SRCS}
    ${MLDSA65_SRCS}
    ${MLDSA87_SRCS}
    ${FALCON_512_SRCS}
    ${FALCON_1024_SRCS}
    ${SPHINCS_SHA2_128F_SRCS}
    ${SPHINCS_SHA2_128S_SRCS}
    ${SPHINCS_SHA2_192F_SRCS}
    ${SPHINCS_SHA2_192S_SRCS}
    ${SPHINCS_SHA2_256F_SRCS}
    ${SPHINCS_SHA2_256S_SRCS}
    ${SPHINCS_SHAKE_128F_SRCS}
    ${SPHINCS_SHAKE_128S_SRCS}
    ${SPHINCS_SHAKE_192F_SRCS}
    ${SPHINCS_SHAKE_192S_SRCS}
    ${SPHINCS_SHAKE_256F_SRCS}
    ${SPHINCS_SHAKE_256S_SRCS}
    ${PQCLEAN_COMMON_SRCS}
)

target_include_directories(
    pqclean
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/hqc-128/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/hqc-192/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/hqc-256/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/ml-kem-512/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/ml-kem-768/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/ml-kem-1024/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/mceliece348864/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/mceliece348864f/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/mceliece460896/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/mceliece460896f/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/mceliece6688128/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/mceliece6688128f/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/mceliece6960119/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/mceliece6960119f/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/mceliece8192128/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/mceliece8192128f/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/ml-dsa-44/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/ml-dsa-65/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/ml-dsa-87/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/falcon-512/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/falcon-1024/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-sha2-128f-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-sha2-128s-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-sha2-192f-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-sha2-192s-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-sha2-256f-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-sha2-256s-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-shake-128f-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-shake-128s-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-shake-192f-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-shake-192s-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-shake-256f-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-shake-256s-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

install(TARGETS pqclean
  CONFIGURATIONS ${CMAKE_BUILD_TYPE}
  EXPORT pqcleanTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
