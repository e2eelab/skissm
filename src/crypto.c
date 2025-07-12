/*
 * Copyright © 2021 Academia Sinica. All Rights Reserved.
 *
 * This file is part of E2EE Security.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * E2EE Security is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with E2EE Security.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "e2ees/crypto.h"

#include <errno.h>
#include <string.h>

#include "additions/curve_sigs.h"
#include "curve25519-donna.h"

#include "gcm.h"
#include "hkdf.h"
#include "md.h"
#include "platform.h"
#include "sha256.h"
#include "base64.h"

#include "PQClean/src/crypto_kem/hqc-128/clean/api.h"
#include "PQClean/src/crypto_kem/hqc-192/clean/api.h"
#include "PQClean/src/crypto_kem/hqc-256/clean/api.h"
#include "PQClean/src/crypto_kem/ml-kem-512/clean/api.h"
#include "PQClean/src/crypto_kem/ml-kem-768/clean/api.h"
#include "PQClean/src/crypto_kem/ml-kem-1024/clean/api.h"
#include "PQClean/src/crypto_kem/mceliece348864/clean/api.h"
#include "PQClean/src/crypto_kem/mceliece348864f/clean/api.h"
#include "PQClean/src/crypto_kem/mceliece460896/clean/api.h"
#include "PQClean/src/crypto_kem/mceliece460896f/clean/api.h"
#include "PQClean/src/crypto_kem/mceliece6688128/clean/api.h"
#include "PQClean/src/crypto_kem/mceliece6688128f/clean/api.h"
#include "PQClean/src/crypto_kem/mceliece6960119/clean/api.h"
#include "PQClean/src/crypto_kem/mceliece6960119f/clean/api.h"
#include "PQClean/src/crypto_kem/mceliece8192128/clean/api.h"
#include "PQClean/src/crypto_kem/mceliece8192128f/clean/api.h"
#include "PQClean/src/crypto_sign/ml-dsa-44/clean/api.h"
#include "PQClean/src/crypto_sign/ml-dsa-65/clean/api.h"
#include "PQClean/src/crypto_sign/ml-dsa-87/clean/api.h"
#include "PQClean/src/crypto_sign/falcon-512/clean/api.h"
#include "PQClean/src/crypto_sign/falcon-1024/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-sha2-128f-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-sha2-128s-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-sha2-192f-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-sha2-192s-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-sha2-256f-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-sha2-256s-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-shake-128f-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-shake-128s-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-shake-192f-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-shake-192s-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-shake-256f-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-shake-256s-simple/clean/api.h"

#include "e2ees/account.h"
#include "e2ees/cipher.h"
#include "e2ees/mem_util.h"

/** amount of random data required to create a Curve25519 keypair */
#define CURVE25519_RANDOM_LENGTH CURVE25519_KEY_LENGTH

#define AES256_FILE_AD "E2EES ---> file encryption with AES256/GCM/Nopadding algorithm"
#define AES256_FILE_AD_LEN 64
#define AES256_FILE_KDF_INFO "FILE"

#define AES256_DATA_AD "E2EES ---> data encryption with AES256/GCM/Nopadding algorithm"
#define AES256_DATA_AD_LEN 64

/** buffer length for file encryption/decryption */
#define FILE_ENCRYPTION_BUFFER_LENGTH 8192

static const uint8_t CURVE25519_BASEPOINT[32] = {9};


// digital signature

static crypto_ds_param_t curve25519_sign_param = {
    false,
    CURVE25519_KEY_LENGTH,
    CURVE25519_KEY_LENGTH,
    CURVE_SIGNATURE_LENGTH
};

static crypto_ds_param_t mldsa44_param = {
    true,
    PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t mldsa65_param = {
    true,
    PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t mldsa87_param = {
    true,
    PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t falcon512_param = {
    true,
    PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t falcon1024_param = {
    true,
    PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_sha2_128f_param = {
    true,
    PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_sha2_128s_param = {
    true,
    PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_sha2_192f_param = {
    true,
    PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_sha2_192s_param = {
    true,
    PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_sha2_256f_param = {
    true,
    PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_sha2_256s_param = {
    true,
    PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_shake_128f_param = {
    true,
    PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_shake_128s_param = {
    true,
    PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_shake_192f_param = {
    true,
    PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_shake_192s_param = {
    true,
    PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_shake_256f_param = {
    true,
    PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_shake_256s_param = {
    true,
    PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_BYTES
};


// kem

static crypto_kem_param_t curve25519_ECDH_param = {
    false,
    CURVE25519_KEY_LENGTH,
    CURVE25519_KEY_LENGTH,
    0,
    CURVE25519_KEY_LENGTH
};

static crypto_kem_param_t hqc128_param = {
    true,
    PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t hqc192_param = {
    true,
    PQCLEAN_HQC192_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_HQC192_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_HQC192_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_HQC192_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t hqc256_param = {
    true,
    PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mlkem512_param = {
    true,
    PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mlkem768_param = {
    true,
    PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mlkem1024_param = {
    true,
    PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mceliece348864_param = {
    true,
    PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mceliece348864f_param = {
    true,
    PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mceliece460896_param = {
    true,
    PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mceliece460896f_param = {
    true,
    PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mceliece6688128_param = {
    true,
    PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mceliece6688128f_param = {
    true,
    PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mceliece6960119_param = {
    true,
    PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mceliece6960119f_param = {
    true,
    PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mceliece8192128_param = {
    true,
    PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mceliece8192128f_param = {
    true,
    PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_BYTES
};


// symmetric encryption

static crypto_se_param_t aes256_param = {
    AES256_KEY_LENGTH,
    AES256_IV_LENGTH,
    AES256_GCM_TAG_LENGTH
};

// hash
static crypto_hash_param_t sha256_param = {
    SHA256_OUTPUT_LENGTH,
};

// ditigal signature

crypto_ds_param_t get_curve25519_sign_param() {
    return curve25519_sign_param;
}

crypto_ds_param_t get_mldsa44_param() {
    return mldsa44_param;
}

crypto_ds_param_t get_mldsa65_param() {
    return mldsa65_param;
}

crypto_ds_param_t get_mldsa87_param() {
    return mldsa87_param;
}

crypto_ds_param_t get_falcon512_param() {
    return falcon512_param;
}

crypto_ds_param_t get_falcon1024_param() {
    return falcon1024_param;
}

crypto_ds_param_t get_sphincs_sha2_128f_param() {
    return sphincs_sha2_128f_param;
}

crypto_ds_param_t get_sphincs_sha2_128s_param() {
    return sphincs_sha2_128s_param;
}

crypto_ds_param_t get_sphincs_sha2_192f_param() {
    return sphincs_sha2_192f_param;
}

crypto_ds_param_t get_sphincs_sha2_192s_param() {
    return sphincs_sha2_192s_param;
}

crypto_ds_param_t get_sphincs_sha2_256f_param() {
    return sphincs_sha2_256f_param;
}

crypto_ds_param_t get_sphincs_sha2_256s_param() {
    return sphincs_sha2_256s_param;
}

crypto_ds_param_t get_sphincs_shake_128f_param() {
    return sphincs_shake_128f_param;
}

crypto_ds_param_t get_sphincs_shake_128s_param() {
    return sphincs_shake_128s_param;
}

crypto_ds_param_t get_sphincs_shake_192f_param() {
    return sphincs_shake_192f_param;
}

crypto_ds_param_t get_sphincs_shake_192s_param() {
    return sphincs_shake_192s_param;
}

crypto_ds_param_t get_sphincs_shake_256f_param() {
    return sphincs_shake_256f_param;
}

crypto_ds_param_t get_sphincs_shake_256s_param() {
    return sphincs_shake_256s_param;
}

int crypto_mldsa44_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

int crypto_mldsa65_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

int crypto_mldsa87_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

int crypto_falcon512_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

int crypto_falcon1024_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

int crypto_sphincs_sha2_128f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

int crypto_sphincs_sha2_128s_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

int crypto_sphincs_sha2_192f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

int crypto_sphincs_sha2_192s_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

int crypto_sphincs_sha2_256f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

int crypto_sphincs_sha2_256s_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

int crypto_sphincs_shake_128f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

int crypto_sphincs_shake_128s_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

int crypto_sphincs_shake_192f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

int crypto_sphincs_shake_192s_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

int crypto_sphincs_shake_256f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

int crypto_sphincs_shake_256s_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}


// kem

crypto_kem_param_t get_curve25519_ECDH_param() {
    return curve25519_ECDH_param;
}

crypto_kem_param_t get_hqc128_param() {
    return hqc128_param;
}

crypto_kem_param_t get_hqc192_param() {
    return hqc192_param;
}

crypto_kem_param_t get_hqc256_param() {
    return hqc256_param;
}

crypto_kem_param_t get_mlkem512_param() {
    return mlkem512_param;
}

crypto_kem_param_t get_mlkem768_param() {
    return mlkem768_param;
}

crypto_kem_param_t get_mlkem1024_param() {
    return mlkem1024_param;
}

crypto_kem_param_t get_mceliece348864_param() {
    return mceliece348864_param;
}

crypto_kem_param_t get_mceliece348864f_param() {
    return mceliece348864f_param;
}

crypto_kem_param_t get_mceliece460896_param() {
    return mceliece460896_param;
}

crypto_kem_param_t get_mceliece460896f_param() {
    return mceliece460896f_param;
}

crypto_kem_param_t get_mceliece6688128_param() {
    return mceliece6688128_param;
}

crypto_kem_param_t get_mceliece6688128f_param() {
    return mceliece6688128f_param;
}

crypto_kem_param_t get_mceliece6960119_param() {
    return mceliece6960119_param;
}

crypto_kem_param_t get_mceliece6960119f_param() {
    return mceliece6960119f_param;
}

crypto_kem_param_t get_mceliece8192128_param() {
    return mceliece8192128_param;
}

crypto_kem_param_t get_mceliece8192128f_param() {
    return mceliece8192128f_param;
}

crypto_se_param_t get_aes256_param() {
    return aes256_param;
}

crypto_hash_param_t get_sha256_param() {
    return sha256_param;
}

int crypto_hqc128_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

int crypto_hqc192_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC192_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_HQC192_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC192_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_HQC192_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_HQC192_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

int crypto_hqc256_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

int crypto_mlkem512_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

int crypto_mlkem768_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

int crypto_mlkem1024_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

int crypto_mceliece348864_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

int crypto_mceliece348864f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

int crypto_mceliece460896_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

int crypto_mceliece460896f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

int crypto_mceliece6688128_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

int crypto_mceliece6688128f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

int crypto_mceliece6960119_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

int crypto_mceliece6960119f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

int crypto_mceliece8192128_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

int crypto_mceliece8192128f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

int crypto_hqc128_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_HQC128_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

int crypto_hqc192_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC192_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_HQC192_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_HQC192_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

int crypto_hqc256_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_HQC256_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

int crypto_mlkem512_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

int crypto_mlkem768_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

int crypto_mlkem1024_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

int crypto_mceliece348864_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

int crypto_mceliece348864f_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

int crypto_mceliece460896_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

int crypto_mceliece460896f_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

int crypto_mceliece6688128_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

int crypto_mceliece6688128f_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

int crypto_mceliece6960119_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

int crypto_mceliece6960119f_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

int crypto_mceliece8192128_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

int crypto_mceliece8192128f_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

int crypto_hqc128_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_HQC128_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

int crypto_hqc192_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_HQC192_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

int crypto_hqc256_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_HQC256_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

int crypto_mlkem512_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

int crypto_mlkem768_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

int crypto_mlkem1024_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

int crypto_mceliece348864_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

int crypto_mceliece348864f_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

int crypto_mceliece460896_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

int crypto_mceliece460896f_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

int crypto_mceliece6688128_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

int crypto_mceliece6688128f_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

int crypto_mceliece6960119_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

int crypto_mceliece6960119f_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

int crypto_mceliece8192128_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

int crypto_mceliece8192128f_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static void crypto_curve25519_generate_private_key(uint8_t *private_key) {
    uint8_t random[CURVE25519_RANDOM_LENGTH];
    get_e2ees_plugin()->common_handler.gen_rand(random, sizeof(random));

    random[0] &= 248;
    random[31] &= 127;
    random[31] |= 64;

    memcpy(private_key, random, CURVE25519_KEY_LENGTH);
}

int CURVE25519_crypto_sign_keypair(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    int result;

    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * CURVE25519_KEY_LENGTH);
    priv_key->len = CURVE25519_KEY_LENGTH;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * CURVE25519_KEY_LENGTH);
    pub_key->len = CURVE25519_KEY_LENGTH;

    uint8_t msg[10] = {0};
    uint8_t signature[CURVE_SIGNATURE_LENGTH];

    while (true) {
        crypto_curve25519_generate_private_key(priv_key->data);

        curve25519_donna(pub_key->data, priv_key->data, CURVE25519_BASEPOINT);
        crypto_curve25519_sign(priv_key->data, msg, 10, signature);
        result = crypto_curve25519_verify(signature, pub_key->data, msg, 10);
        if (result != 0) {
            // verify failed, regenerate the key pair
            e2ees_notify_log(
                NULL,
                BAD_SIGNATURE,
                "CURVE25519_crypto_sign_keypair() verify failed, regenerate the key pair."
            );
        } else {
            // success
            break;
        }
        // TODO in case of long running
    }

    return result;
}

int CURVE25519_crypto_keypair(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * CURVE25519_KEY_LENGTH);
    priv_key->len = CURVE25519_KEY_LENGTH;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * CURVE25519_KEY_LENGTH);
    pub_key->len = CURVE25519_KEY_LENGTH;

    crypto_curve25519_generate_private_key(priv_key->data);

    return curve25519_donna(pub_key->data, priv_key->data, CURVE25519_BASEPOINT);
}

int CURVE25519_crypto_sign_signature(
    uint8_t *signature_out, size_t *signature_out_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *private_key
) {
    *signature_out_len = CURVE_SIGNATURE_LENGTH;
    uint8_t nonce[*signature_out_len];
    get_e2ees_plugin()->common_handler.gen_rand(nonce, sizeof(nonce));
    return curve25519_sign(signature_out, private_key, msg, msg_len, nonce);
}

int CURVE25519_crypto_sign_verify(
    const uint8_t *signature_in, size_t signature_in_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *public_key
) {
    return curve25519_verify(signature_in, public_key, msg, msg_len);
}

int crypto_curve25519_dh(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return curve25519_donna(shared_secret, our_key->data, ciphertext->data);
}

void crypto_curve25519_sign(
    uint8_t *private_key,
    uint8_t *msg, size_t msg_len,
    uint8_t *signature_out
) {
    uint8_t nonce[CURVE_SIGNATURE_LENGTH];
    get_e2ees_plugin()->common_handler.gen_rand(nonce, sizeof(nonce));
    curve25519_sign(signature_out, private_key, msg, msg_len, nonce);
}

int crypto_curve25519_verify(
    uint8_t *signature_in, uint8_t *public_key,
    uint8_t *msg, size_t msg_len
) {
    return curve25519_verify(signature_in, public_key, msg, msg_len);
}

int crypto_aes_encrypt_gcm(
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    const uint8_t *aes_key, const uint8_t *iv,
    const uint8_t *add, size_t add_len,
    uint8_t *ciphertext_data
) {
    int ret = E2EES_RESULT_SUCC;

    mbedtls_gcm_context ctx;
    unsigned char *tag_buf = ciphertext_data + plaintext_data_len;
    mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;
    int key_len = AES256_KEY_LENGTH * 8;

    mbedtls_gcm_init(&ctx);
    ret = mbedtls_gcm_setkey(&ctx, cipher, aes_key, key_len);
    if (ret == E2EES_RESULT_SUCC) {
        ret = mbedtls_gcm_crypt_and_tag(
            &ctx, MBEDTLS_GCM_ENCRYPT,
            plaintext_data_len, iv,
            AES256_IV_LENGTH, add, add_len, plaintext_data,
            ciphertext_data, AES256_GCM_TAG_LENGTH, tag_buf
        );
    }

    mbedtls_gcm_free(&ctx);

    return ret;
}

int crypto_aes_decrypt_gcm(
    const uint8_t *ciphertext_data, size_t ciphertext_data_len,
    const uint8_t *aes_key, const uint8_t *iv,
    const uint8_t *add, size_t add_len,
    uint8_t *plaintext_data, size_t *plaintext_data_len
) {
    int ret = E2EES_RESULT_SUCC;

    mbedtls_gcm_context ctx;
    unsigned char *input_tag_buf =
        (unsigned char *)(ciphertext_data + ciphertext_data_len - AES256_GCM_TAG_LENGTH);
    unsigned char tag_buf[AES256_GCM_TAG_LENGTH];
    mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;
    int key_len = AES256_KEY_LENGTH * 8;

    mbedtls_gcm_init(&ctx);
    ret = mbedtls_gcm_setkey(&ctx, cipher, aes_key, key_len);
    if (ret == E2EES_RESULT_SUCC) {
        ret = mbedtls_gcm_crypt_and_tag(
            &ctx, MBEDTLS_GCM_DECRYPT,
            ciphertext_data_len - AES256_GCM_TAG_LENGTH, iv,
            AES256_IV_LENGTH, add, add_len, ciphertext_data,
            plaintext_data, AES256_GCM_TAG_LENGTH, tag_buf
        );
    }
    mbedtls_gcm_free(&ctx);

    // verify tag in "constant-time"
    int diff = 0, i;
    for (i = 0; i < AES256_GCM_TAG_LENGTH; i++)
        diff |= input_tag_buf[i] ^ tag_buf[i];
    if (diff == 0) {
        *plaintext_data_len = ciphertext_data_len - AES256_GCM_TAG_LENGTH;
    } else {
        *plaintext_data_len = 0;
        ret = E2EES_RESULT_FAIL;
    }

    return ret;
}

size_t encrypt_aes_data_with_iv(
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    const uint8_t aes_key[AES256_KEY_LENGTH],
    const uint8_t iv[AES256_DATA_IV_LENGTH],
    uint8_t **ciphertext_data
) {
    size_t ciphertext_data_len = aes256_gcm_ciphertext_data_len(plaintext_data_len);
    *ciphertext_data = (uint8_t *)malloc(ciphertext_data_len);

    mbedtls_gcm_context ctx;
    unsigned char *tag_buf = *ciphertext_data + plaintext_data_len;
    int ret;
    mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;

    int key_len = AES256_KEY_LENGTH * 8;
    uint8_t AD[AES256_DATA_AD_LEN] = AES256_DATA_AD;

    mbedtls_gcm_init(&ctx);
    ret = mbedtls_gcm_setkey(&ctx, cipher, aes_key, key_len);
    if (ret == E2EES_RESULT_SUCC) {
        ret = mbedtls_gcm_crypt_and_tag(
            &ctx, MBEDTLS_GCM_ENCRYPT,
            plaintext_data_len, iv,
            AES256_DATA_IV_LENGTH, AD, AES256_DATA_AD_LEN, plaintext_data,
            *ciphertext_data, AES256_GCM_TAG_LENGTH, tag_buf
        );
    }

    mbedtls_gcm_free(&ctx);

    // done
    if (ret == E2EES_RESULT_SUCC) {
        return ciphertext_data_len;
    } else {
        free_mem((void **)ciphertext_data, ciphertext_data_len);
        *ciphertext_data = NULL;
        return 0;
    }
}

size_t encrypt_aes_data(
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    const uint8_t aes_key[AES256_KEY_LENGTH],
    uint8_t **ciphertext_data
) {
    uint8_t iv[AES256_DATA_IV_LENGTH] = {0};
    return encrypt_aes_data_with_iv(plaintext_data, plaintext_data_len, aes_key, iv, ciphertext_data);
}

size_t decrypt_aes_data_with_iv(
    const uint8_t *ciphertext_data, size_t ciphertext_data_len,
    const uint8_t aes_key[AES256_KEY_LENGTH],
    const uint8_t iv[AES256_DATA_IV_LENGTH],
    uint8_t **plaintext_data
) {
    size_t plaintext_data_len = aes256_gcm_plaintext_data_len(ciphertext_data_len);
    *plaintext_data = (uint8_t *)malloc(plaintext_data_len);

    mbedtls_gcm_context ctx;
    unsigned char *input_tag_buf =
            (unsigned char *)(ciphertext_data + ciphertext_data_len - AES256_GCM_TAG_LENGTH);
    unsigned char tag_buf[AES256_GCM_TAG_LENGTH];
    int ret;
    mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;

    int key_len = AES256_KEY_LENGTH * 8;
    uint8_t AD[AES256_DATA_AD_LEN] = AES256_DATA_AD;

    mbedtls_gcm_init(&ctx);
    ret = mbedtls_gcm_setkey(&ctx, cipher, aes_key, key_len);
    if (ret == E2EES_RESULT_SUCC) {
        ret = mbedtls_gcm_crypt_and_tag(
            &ctx, MBEDTLS_GCM_DECRYPT,
            plaintext_data_len, iv,
            AES256_DATA_IV_LENGTH, AD, AES256_DATA_AD_LEN, ciphertext_data,
            *plaintext_data, AES256_GCM_TAG_LENGTH, tag_buf
        );
    }
    mbedtls_gcm_free(&ctx);

    // verify tag in "constant-time"
    int diff = 0, i;
    for (i = 0; i < AES256_GCM_TAG_LENGTH; i++)
        diff |= input_tag_buf[i] ^ tag_buf[i];
    if (diff == 0) {
        return plaintext_data_len;
    } else {
        return 0;
    }
}

size_t decrypt_aes_data(
    const uint8_t *ciphertext_data, size_t ciphertext_data_len,
    const uint8_t aes_key[AES256_KEY_LENGTH],
    uint8_t **plaintext_data
) {
    uint8_t iv[AES256_DATA_IV_LENGTH] = {0};
    return decrypt_aes_data_with_iv(ciphertext_data, ciphertext_data_len, aes_key, iv, plaintext_data);
}

int encrypt_aes_file(
    const char *in_file_path, const char *out_file_path,
    const uint8_t aes_key[AES256_KEY_LENGTH]
) {
    FILE *infile, *outfile;
    infile = fopen(in_file_path, "r");
    if (infile == NULL) {
        e2ees_notify_log(
            NULL,
            BAD_FILE_ENCRYPTION,
            "encrypt_aes_file() in_file_path: %s, with errorno: %d.", in_file_path, errno);
        return -1;
    }

    outfile = fopen(out_file_path, "w");
    if (outfile == NULL) {
        e2ees_notify_log(
            NULL,
            BAD_FILE_ENCRYPTION,
            "encrypt_aes_file() out_file_path: %s, with errorno: %d.", out_file_path, errno);
        // release
        fclose(infile);
        return -1;
    }

    fseek(infile, 0, SEEK_END);
    long size = ftell(infile);
    fseek(infile, 0, SEEK_SET);

    int max_plaintext_size = FILE_ENCRYPTION_BUFFER_LENGTH;
    unsigned char in_buffer[max_plaintext_size];
    unsigned char out_buffer[FILE_ENCRYPTION_BUFFER_LENGTH];

    int key_len = AES256_KEY_LENGTH * 8;
    uint8_t AD[AES256_FILE_AD_LEN] = AES256_FILE_AD;

    int times = size / max_plaintext_size;
    int rest = size % max_plaintext_size;

    mbedtls_gcm_context ctx;
    mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;
    int ret;
    mbedtls_gcm_init(&ctx);
    ret = mbedtls_gcm_setkey(&ctx, cipher, aes_key, key_len);
    if (ret == E2EES_RESULT_SUCC) {
        uint8_t iv[AES256_DATA_IV_LENGTH] = {0};
        ret = mbedtls_gcm_starts(&ctx, MBEDTLS_GCM_ENCRYPT, iv, AES256_DATA_IV_LENGTH, AD, AES256_FILE_AD_LEN);
    }

    if (ret == E2EES_RESULT_SUCC) {
        int i;
        for (i = 0; i < times; i++) {
            fread(in_buffer, sizeof(char), max_plaintext_size, infile);
            if ((ret = mbedtls_gcm_update(&ctx, max_plaintext_size, in_buffer, out_buffer)) != 0)
                break;
            fwrite(out_buffer, sizeof(char), max_plaintext_size, outfile);
        }
    }
    if (ret == E2EES_RESULT_SUCC) {
        if (rest > 0) {
            fread(in_buffer, sizeof(char), rest, infile);
            if ((ret = mbedtls_gcm_update(&ctx, rest, in_buffer, out_buffer)) == 0) {
                fwrite(out_buffer, sizeof(char), rest, outfile);
            }
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        uint8_t tag[AES256_GCM_TAG_LENGTH];
        if ((ret = mbedtls_gcm_finish(&ctx, tag, AES256_GCM_TAG_LENGTH)) == 0) {
            fwrite(tag, sizeof(char), AES256_GCM_TAG_LENGTH, outfile);
        }
    }

    mbedtls_gcm_free(&ctx);

    fclose(outfile);
    fclose(infile);

    return ret;
}

int decrypt_aes_file(
    const char *in_file_path, const char *out_file_path,
    const uint8_t aes_key[AES256_KEY_LENGTH]
) {
    FILE *infile, *outfile;
    infile = fopen(in_file_path, "r+");
    if (infile == NULL) {
        e2ees_notify_log(
            NULL,
            BAD_FILE_DECRYPTION,
            "decrypt_aes_file() in_file_path: %s, with errorno: %d.", in_file_path, errno);
        return -1;
    }

    outfile = fopen(out_file_path, "w");
    if (outfile == NULL) {
        e2ees_notify_log(
            NULL,
            BAD_FILE_DECRYPTION,
            "decrypt_aes_file() out_file_path: %s, with errorno: %d.", out_file_path, errno);
        // release
        fclose(infile);
        return -1;
    }

    int key_len = AES256_KEY_LENGTH * 8;
    uint8_t AD[AES256_FILE_AD_LEN] = AES256_FILE_AD;

    fseek(infile, 0, SEEK_END);
    long size = ftell(infile);
    fseek(infile, 0, SEEK_SET);

    int max_ciphertext_size = FILE_ENCRYPTION_BUFFER_LENGTH;
    unsigned char in_buffer[max_ciphertext_size];
    unsigned char out_buffer[FILE_ENCRYPTION_BUFFER_LENGTH];

    int times = (size - AES256_GCM_TAG_LENGTH) / max_ciphertext_size;
    int rest = (size - AES256_GCM_TAG_LENGTH) % max_ciphertext_size;

    mbedtls_gcm_context ctx;
    mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;
    int ret;
    int i;
    mbedtls_gcm_init(&ctx);
    ret = mbedtls_gcm_setkey(&ctx, cipher, aes_key, key_len);
    if (ret == E2EES_RESULT_SUCC) {
        uint8_t iv[AES256_DATA_IV_LENGTH] = {0};
        ret = mbedtls_gcm_starts(&ctx, MBEDTLS_GCM_DECRYPT, iv, AES256_DATA_IV_LENGTH, AD, AES256_FILE_AD_LEN);
    }

    if (ret == E2EES_RESULT_SUCC) {
        for (i = 0; i < times; i++) {
            fread(in_buffer, sizeof(char), max_ciphertext_size, infile);
            if ((ret = mbedtls_gcm_update(&ctx, max_ciphertext_size, in_buffer, out_buffer)) != 0)
                break;
            fwrite(out_buffer, sizeof(char), max_ciphertext_size, outfile);
        }
    }
    if (ret == E2EES_RESULT_SUCC) {
        if (rest > 0) {
            fread(in_buffer, sizeof(char), rest, infile);
            if ((ret = mbedtls_gcm_update(&ctx, rest, in_buffer, out_buffer)) == 0) {
                fwrite(out_buffer, sizeof(char), rest, outfile);
            }
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        uint8_t tag[AES256_GCM_TAG_LENGTH];
        if ((ret = mbedtls_gcm_finish(&ctx, tag, AES256_GCM_TAG_LENGTH)) == 0) {
            // fwrite(tag, sizeof(char), AES256_GCM_TAG_LENGTH, outfile);
            // verify tag
            uint8_t input_tag[AES256_GCM_TAG_LENGTH];
            fread(input_tag, sizeof(uint8_t), AES256_GCM_TAG_LENGTH, infile);

            // verify tag in "constant-time"
            int diff = 0;
            for (i = 0; i < AES256_GCM_TAG_LENGTH; i++)
                diff |= input_tag[i] ^ tag[i];
            if (diff == 0) {
                ret = E2EES_RESULT_SUCC;
            } else {
                ret = E2EES_RESULT_FAIL;
            }
        }
    }

    mbedtls_gcm_free(&ctx);

    fclose(outfile);
    fclose(infile);

    return ret;
}

int encrypt_file(
    const char *in_file_path, const char *out_file_path,
    const uint8_t *password,
    const size_t password_len
) {
    // prepare aes_key
    size_t salt_len = 0;
    uint8_t salt[salt_len];
    uint8_t aes_key[AES256_KEY_LENGTH];

    crypto_hkdf_sha256(
        password, password_len,
        salt, salt_len,
        (uint8_t *)AES256_FILE_KDF_INFO, sizeof(AES256_FILE_KDF_INFO) - 1,
        aes_key, AES256_KEY_LENGTH
    );

    // perform aes encryption
    return encrypt_aes_file(in_file_path, out_file_path, aes_key);
}

int decrypt_file(
    const char *in_file_path, const char *out_file_path,
    const uint8_t *password,
    const size_t password_len
) {
    // prepare aes_key
    size_t salt_len = 0;
    uint8_t salt[salt_len];
    uint8_t aes_key[AES256_KEY_LENGTH];

    crypto_hkdf_sha256(
        password, password_len,
        salt, salt_len,
        (uint8_t *)AES256_FILE_KDF_INFO, sizeof(AES256_FILE_KDF_INFO) - 1,
        aes_key, AES256_KEY_LENGTH
    );

    // perform aes decryption
    return decrypt_aes_file(in_file_path, out_file_path, aes_key);
}

int crypto_hkdf_sha256(
    const uint8_t *input, size_t input_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len, uint8_t *output,
    size_t output_len
) {
    const mbedtls_md_info_t *sha256_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return mbedtls_hkdf(sha256_info, salt, salt_len, input, input_len, info, info_len, output, output_len);
}

int crypto_hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *input, size_t input_len,
    uint8_t *output
) {
    int ret = E2EES_RESULT_SUCC;
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&ctx);
    ret = mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    ret = mbedtls_md_hmac_starts(&ctx, (const unsigned char *)key, key_len);
    ret = mbedtls_md_hmac_update(&ctx, (const unsigned char *)input, input_len);
    ret = mbedtls_md_hmac_finish(&ctx, output);
    mbedtls_md_free(&ctx);

    return ret;
}

int crypto_sha256(const uint8_t *msg, size_t msg_len, uint8_t *hash_out) {
    int ret = E2EES_RESULT_SUCC;
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);
    ret = mbedtls_sha256_starts_ret(&ctx, 0);
    ret = mbedtls_sha256_update_ret(&ctx, msg, msg_len);
    ret = mbedtls_sha256_finish_ret(&ctx, hash_out);
    mbedtls_sha256_free(&ctx);

    return ret;
}

char *crypto_base64_encode(const uint8_t *msg, size_t msg_len) {
    size_t len = 4 * ((msg_len + 2) / 3) + 1;
    char *output = (char *)malloc(sizeof(char) * len);
    mbedtls_base64_encode((unsigned char *)output, len, &len, (const unsigned char *)msg, msg_len);
    return output;
}

size_t crypto_base64_decode(uint8_t **msg_out, const unsigned char *base64_str) {
    size_t base64_str_len = strlen((const char *)base64_str);
    int pad = base64_str_len > 0 && (base64_str_len % 4 || base64_str[base64_str_len - 1] == '=');
    size_t len = ((base64_str_len + 3) / 4 - pad) * 4;
    unsigned char buffer[len + 1];
    size_t msg_out_len;
    int ret = mbedtls_base64_decode(buffer, len + 1, &msg_out_len, base64_str, base64_str_len);

    if (msg_out_len > (len + 1)) {
        // something wrong with the length
        return 0;
    }
    *msg_out = (uint8_t *)malloc(sizeof(uint8_t) * msg_out_len);
    memcpy(*msg_out, buffer, msg_out_len);

    unset(buffer, len + 1);

    return msg_out_len;
}

int crypto_hash_by_e2ees_pack_id(
    uint32_t e2ees_pack_id_raw,
    const uint8_t *msg, size_t msg_len,
    uint8_t **hash_out, size_t *hash_out_len
) {
    e2ees_pack_id_t e2ees_pack_id = raw_to_e2ees_pack_id(e2ees_pack_id_raw);
    hash_suite_t *hash_suite = get_hash_suite(e2ees_pack_id.hash);
    if (hash_suite == NULL) {
        e2ees_notify_log(
            NULL,
            BAD_E2EES_PACK,
            "crypto_hash_by_e2ees_pack_id() hash_suite not found: %d.", e2ees_pack_id_raw
        );
        return -1;
    }

    uint32_t hash_len = hash_suite->get_crypto_param().hash_len;
    *hash_out_len = hash_len;
    *hash_out = (uint8_t *)malloc(sizeof(uint8_t) * hash_len);
    int result = hash_suite->hash(msg, msg_len, *hash_out);
    if (result < 0) {
        free_mem((void **)&hash_out, hash_len);
    }
    return result;
}

int crypto_ds_key_gen_by_e2ees_pack_id(
    uint32_t e2ees_pack_id_raw,
    ProtobufCBinaryData *pub_key,
    ProtobufCBinaryData *priv_key
) {
    e2ees_pack_id_t e2ees_pack_id = raw_to_e2ees_pack_id(e2ees_pack_id_raw);
    ds_suite_t *digital_signature_suite = get_ds_suite(e2ees_pack_id.ds);
    if (digital_signature_suite == NULL) {
        e2ees_notify_log(
            NULL,
            BAD_E2EES_PACK,
            "crypto_ds_key_gen_by_e2ees_pack_id() digital_signature_suite not found: %d.", e2ees_pack_id_raw
        );
        return -1;
    }

    int result = digital_signature_suite->sign_key_gen(pub_key, priv_key);
    if (result < 0) {
        e2ees_notify_log(
            NULL,
            BAD_KEY_PAIR,
            "crypto_ds_key_gen_by_e2ees_pack_id() gen key failed."
        );
        free_protobuf(pub_key);
        free_protobuf(priv_key);
    }

    return result;
}

int crypto_ds_sign_by_e2ees_pack_id(
    uint32_t e2ees_pack_id_raw,
    uint8_t **signature_out, size_t *signature_out_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *private_key, size_t private_key_len
) {
    e2ees_pack_id_t e2ees_pack_id = raw_to_e2ees_pack_id(e2ees_pack_id_raw);
    ds_suite_t *digital_signature_suite = get_ds_suite(e2ees_pack_id.ds);
    if (digital_signature_suite == NULL) {
        e2ees_notify_log(
            NULL,
            BAD_E2EES_PACK,
            "crypto_ds_sign_by_e2ees_pack_id() digital_signature_suite not found: %d.", e2ees_pack_id_raw
        );
        return -1;
    }
    if (private_key == NULL || private_key_len != digital_signature_suite->get_crypto_param().sign_priv_key_len) {
        e2ees_notify_log(
            NULL,
            BAD_PRIVATE_KEY,
            "crypto_ds_sign_by_e2ees_pack_id() private_key wrong."
        );
        return -1;
    }

    int sig_len = digital_signature_suite->get_crypto_param().sig_len;
    *signature_out = (uint8_t *)malloc(sizeof(uint8_t) * sig_len);
    int result = digital_signature_suite->sign(*signature_out, signature_out_len, msg, msg_len, private_key);
    if (result < 0) {
        e2ees_notify_log(
            NULL,
            BAD_SIGNATURE,
            "crypto_ds_sign_by_e2ees_pack_id() sign failed."
        );
        free_mem((void **)signature_out, sig_len);
    }

    return result;
}

int crypto_ds_verify_by_e2ees_pack_id(
    uint32_t e2ees_pack_id_raw,
    const uint8_t *signature_in, size_t signature_in_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *public_key, size_t public_key_len
) {
    e2ees_pack_id_t e2ees_pack_id = raw_to_e2ees_pack_id(e2ees_pack_id_raw);
    ds_suite_t *digital_signature_suite = get_ds_suite(e2ees_pack_id.ds);
    if (digital_signature_suite == NULL) {
        e2ees_notify_log(
            NULL,
            BAD_E2EES_PACK,
            "crypto_ds_verify_by_e2ees_pack_id() digital_signature_suite not found: %d.", e2ees_pack_id_raw
        );
        return -1;
    }
    if (public_key == NULL || public_key_len != digital_signature_suite->get_crypto_param().sign_pub_key_len) {
        e2ees_notify_log(
            NULL,
            BAD_PUBLIC_KEY,
            "crypto_ds_sign_by_e2ees_pack_id() public_key wrong."
        );
        return -1;
    }

    int result = digital_signature_suite->verify(signature_in, signature_in_len, msg, msg_len, public_key);
    if (result < 0) {
        e2ees_notify_log(
            NULL,
            BAD_SIGNATURE,
            "crypto_ds_verify_by_e2ees_pack_id() verify failed."
        );
    }

    return result;
}
