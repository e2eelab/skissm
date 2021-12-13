/*
 * Copyright © 2020-2021 by Academia Sinica
 *
 * This file is part of SKISSM.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SKISSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SKISSM.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm.h"

/** length of a sha256 hash */
#define SHA256_OUTPUT_LENGTH 32

/** length of a public or private Curve25519 key */
#define CURVE25519_KEY_LENGTH 32

/** length of a Curve25519 signature */
#define CURVE_SIGNATURE_LENGTH 64

/** length of associated data */
#define AD_LENGTH 64

/** length of an aes256 key */
#define AES256_KEY_LENGTH 32

/** length of an aes256 initialisation vector */
#define AES256_IV_LENGTH 16

/** length of an aes256 gcm tag */
#define AES256_GCM_TAG_LENGTH 16

crypto_param get_ecdh_x25519_aes256_gcm_sha256_param();

void crypto_curve25519_generate_private_key(
    ProtobufCBinaryData *priv_key, size_t priv_key_len
);

void crypto_curve25519_generate_public_key(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

void crypto_curve25519_generate_key_pair(
    Skissm__KeyPair *key_pair
);

void crypto_curve25519_dh(
    const Skissm__KeyPair *our_key,
    const ProtobufCBinaryData *their_key,
    uint8_t *shared_secret
);

void crypto_curve25519_sign(uint8_t *private_key,
    uint8_t *msg, size_t msg_len, uint8_t *signature_out
);

size_t crypto_curve25519_verify(
    uint8_t *signature_in, uint8_t *public_key,
    uint8_t *msg, size_t msg_len);

/** HMAC-based Key Derivation Function (HKDF)
 * https://tools.ietf.org/html/rfc5869
 * Derives key material from the input bytes. */
void crypto_hkdf_sha256(
    const uint8_t *input, size_t input_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len,
    uint8_t *output, size_t output_len
);

/** HMAC: Keyed-Hashing for Message Authentication
 * http://tools.ietf.org/html/rfc2104
 * Computes HMAC-SHA-256 of the input for the key. The output buffer must
 * be at least SHA256_OUTPUT_LENGTH (32) bytes long. */
void crypto_hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *input, size_t input_len,
    uint8_t *output
);

void crypto_sha256(
    const uint8_t *msg, size_t msg_len,
    uint8_t *hash_out
);

/**
 * Calculate output length for AES256 GCM mode encryption.
 */
size_t crypto_aes_encrypt_gcm_length(size_t input_length);

/**
 * @brief AES256 encrypt function in GCM mode
 * @see [AES256 GCM mode](https://datatracker.ietf.org/doc/html/rfc5288)
 *
 * @param plaintext
 * @param plaintext_len
 * @param key
 * @param iv
 * @param add
 * @param add_len
 * @param ciphertext
 */
void crypto_aes_encrypt_gcm(
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *key, const uint8_t *iv,
    const uint8_t *add, size_t add_len,
    uint8_t *ciphertext);

/**
 * @brief AES256 decrypt function in GCM mode
 * @see [AES256 GCM mode](https://datatracker.ietf.org/doc/html/rfc5288)
 *
 * @param ciphertext
 * @param ciphertext_len
 * @param key
 * @param iv
 * @param add
 * @param add_len
 * @param output
 * @return size_t
 */
size_t crypto_aes_decrypt_gcm(
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *key, const uint8_t *iv,
    const uint8_t *add, size_t add_len,
    uint8_t *output);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_H_ */
