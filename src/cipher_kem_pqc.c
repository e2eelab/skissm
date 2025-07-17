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
#include <stdbool.h>
#include <string.h>

#include <PQClean/src/crypto_kem/hqc-128/clean/api.h>
#include <PQClean/src/crypto_kem/hqc-192/clean/api.h>
#include <PQClean/src/crypto_kem/hqc-256/clean/api.h>
#include <PQClean/src/crypto_kem/ml-kem-512/clean/api.h>
#include <PQClean/src/crypto_kem/ml-kem-768/clean/api.h>
#include <PQClean/src/crypto_kem/ml-kem-1024/clean/api.h>
#include <PQClean/src/crypto_kem/mceliece348864/clean/api.h>
#include <PQClean/src/crypto_kem/mceliece348864f/clean/api.h>
#include <PQClean/src/crypto_kem/mceliece460896/clean/api.h>
#include <PQClean/src/crypto_kem/mceliece460896f/clean/api.h>
#include <PQClean/src/crypto_kem/mceliece6688128/clean/api.h>
#include <PQClean/src/crypto_kem/mceliece6688128f/clean/api.h>
#include <PQClean/src/crypto_kem/mceliece6960119/clean/api.h>
#include <PQClean/src/crypto_kem/mceliece6960119f/clean/api.h>
#include <PQClean/src/crypto_kem/mceliece8192128/clean/api.h>
#include <PQClean/src/crypto_kem/mceliece8192128f/clean/api.h>

#include "e2ees/cipher.h"
#include "e2ees/mem_util.h"

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

static crypto_kem_param_t get_hqc128_param() {
    return hqc128_param;
}

static crypto_kem_param_t get_hqc192_param() {
    return hqc192_param;
}

static crypto_kem_param_t get_hqc256_param() {
    return hqc256_param;
}

static crypto_kem_param_t get_mlkem512_param() {
    return mlkem512_param;
}

static crypto_kem_param_t get_mlkem768_param() {
    return mlkem768_param;
}

static crypto_kem_param_t get_mlkem1024_param() {
    return mlkem1024_param;
}

static crypto_kem_param_t get_mceliece348864_param() {
    return mceliece348864_param;
}

static crypto_kem_param_t get_mceliece348864f_param() {
    return mceliece348864f_param;
}

static crypto_kem_param_t get_mceliece460896_param() {
    return mceliece460896_param;
}

static crypto_kem_param_t get_mceliece460896f_param() {
    return mceliece460896f_param;
}

static crypto_kem_param_t get_mceliece6688128_param() {
    return mceliece6688128_param;
}

static crypto_kem_param_t get_mceliece6688128f_param() {
    return mceliece6688128f_param;
}

static crypto_kem_param_t get_mceliece6960119_param() {
    return mceliece6960119_param;
}

static crypto_kem_param_t get_mceliece6960119f_param() {
    return mceliece6960119f_param;
}

static crypto_kem_param_t get_mceliece8192128_param() {
    return mceliece8192128_param;
}

static crypto_kem_param_t get_mceliece8192128f_param() {
    return mceliece8192128f_param;
}

static int crypto_hqc128_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_hqc192_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC192_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_HQC192_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC192_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_HQC192_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_HQC192_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_hqc256_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_mlkem512_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_mlkem768_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_mlkem1024_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_mceliece348864_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_mceliece348864f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_mceliece460896_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_mceliece460896f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_mceliece6688128_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_mceliece6688128f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_mceliece6960119_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_mceliece6960119f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_mceliece8192128_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_mceliece8192128f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_hqc128_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_HQC128_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_hqc192_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC192_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_HQC192_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_HQC192_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_hqc256_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_HQC256_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_mlkem512_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_mlkem768_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_mlkem1024_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_mceliece348864_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_mceliece348864f_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_mceliece460896_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_mceliece460896f_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_mceliece6688128_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_mceliece6688128f_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_mceliece6960119_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_mceliece6960119f_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_mceliece8192128_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_mceliece8192128f_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_hqc128_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_HQC128_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_hqc192_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_HQC192_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_hqc256_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_HQC256_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_mlkem512_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_mlkem768_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_mlkem1024_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_mceliece348864_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_mceliece348864f_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_mceliece460896_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_mceliece460896f_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_mceliece6688128_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_mceliece6688128f_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_mceliece6960119_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_mceliece6960119f_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_mceliece8192128_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_mceliece8192128f_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

// default kem suites with pqc

struct kem_suite_t E2EES_HQC128 = {
    get_hqc128_param,
    crypto_hqc128_generate_key_pair,
    crypto_hqc128_encaps,
    crypto_hqc128_decaps
};

struct kem_suite_t E2EES_HQC192 = {
    get_hqc192_param,
    crypto_hqc192_generate_key_pair,
    crypto_hqc192_encaps,
    crypto_hqc192_decaps
};

struct kem_suite_t E2EES_HQC256 = {
    get_hqc256_param,
    crypto_hqc256_generate_key_pair,
    crypto_hqc256_encaps,
    crypto_hqc256_decaps
};

struct kem_suite_t E2EES_MLKEM512 = {
    get_mlkem512_param,
    crypto_mlkem512_generate_key_pair,
    crypto_mlkem512_encaps,
    crypto_mlkem512_decaps
};

struct kem_suite_t E2EES_MLKEM768 = {
    get_mlkem768_param,
    crypto_mlkem768_generate_key_pair,
    crypto_mlkem768_encaps,
    crypto_mlkem768_decaps
};

struct kem_suite_t E2EES_MLKEM1024 = {
    get_mlkem1024_param,
    crypto_mlkem1024_generate_key_pair,
    crypto_mlkem1024_encaps,
    crypto_mlkem1024_decaps
};

struct kem_suite_t E2EES_MCELIECE348864 = {
    get_mceliece348864_param,
    crypto_mceliece348864_generate_key_pair,
    crypto_mceliece348864_encaps,
    crypto_mceliece348864_decaps
};

struct kem_suite_t E2EES_MCELIECE348864F = {
    get_mceliece348864f_param,
    crypto_mceliece348864f_generate_key_pair,
    crypto_mceliece348864f_encaps,
    crypto_mceliece348864f_decaps
};

struct kem_suite_t E2EES_MCELIECE460896 = {
    get_mceliece460896_param,
    crypto_mceliece460896_generate_key_pair,
    crypto_mceliece460896_encaps,
    crypto_mceliece460896_decaps
};

struct kem_suite_t E2EES_MCELIECE460896F = {
    get_mceliece460896f_param,
    crypto_mceliece460896f_generate_key_pair,
    crypto_mceliece460896f_encaps,
    crypto_mceliece460896f_decaps
};

struct kem_suite_t E2EES_MCELIECE6688128 = {
    get_mceliece6688128_param,
    crypto_mceliece6688128_generate_key_pair,
    crypto_mceliece6688128_encaps,
    crypto_mceliece6688128_decaps
};

struct kem_suite_t E2EES_MCELIECE6688128F = {
    get_mceliece6688128f_param,
    crypto_mceliece6688128f_generate_key_pair,
    crypto_mceliece6688128f_encaps,
    crypto_mceliece6688128f_decaps
};

struct kem_suite_t E2EES_MCELIECE6960119 = {
    get_mceliece6960119_param,
    crypto_mceliece6960119_generate_key_pair,
    crypto_mceliece6960119_encaps,
    crypto_mceliece6960119_decaps
};

struct kem_suite_t E2EES_MCELIECE6960119F = {
    get_mceliece6960119f_param,
    crypto_mceliece6960119f_generate_key_pair,
    crypto_mceliece6960119f_encaps,
    crypto_mceliece6960119f_decaps
};

struct kem_suite_t E2EES_MCELIECE8192128 = {
    get_mceliece8192128_param,
    crypto_mceliece8192128_generate_key_pair,
    crypto_mceliece8192128_encaps,
    crypto_mceliece8192128_decaps
};

struct kem_suite_t E2EES_MCELIECE8192128F = {
    get_mceliece8192128f_param,
    crypto_mceliece8192128f_generate_key_pair,
    crypto_mceliece8192128f_encaps,
    crypto_mceliece8192128f_decaps
};
