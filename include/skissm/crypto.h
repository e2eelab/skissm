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

#include "skissm/skissm.h"

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

/** length of an aes256 initialisation vector for file encryption */
#define AES256_DATA_IV_LENGTH 12

crypto_param_t get_ecdh_x25519_aes256_gcm_sha256_param();

crypto_param_t get_kyber1024_sphincsplus_aes256_gcm_sha256_param();

void crypto_curve25519_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

void crypto_curve25519_signature_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

void crypto_kyber1024_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

void crypto_sphincsplus_shake256_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

uint8_t *crypto_curve25519_dh(
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *their_key,
    uint8_t *shared_secret
);

uint8_t *crypto_kyber1024_shared_secret(
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *their_key,
    uint8_t *shared_secret
);

void crypto_curve25519_sign(uint8_t *private_key,
    uint8_t *msg, size_t msg_len, uint8_t *signature_out
);

void crypto_sphincsplus_shake256_sign(
    uint8_t *private_key,
    uint8_t *msg, size_t msg_len,
    uint8_t *signature_out
);

int crypto_curve25519_verify(
    uint8_t *signature_in, uint8_t *public_key,
    uint8_t *msg, size_t msg_len
);

int crypto_sphincsplus_shake256_verify(
    uint8_t *signature_in, uint8_t *public_key,
    uint8_t *msg, size_t msg_len
);

/**
 * @brief HMAC-based Key Derivation Function (HKDF).
 * https://tools.ietf.org/html/rfc5869
 * Derives key material from the input bytes.
 *
 * @param input
 * @param input_len
 * @param salt
 * @param salt_len
 * @param info
 * @param info_len
 * @param output
 * @param output_len
 */
void crypto_hkdf_sha256(
    const uint8_t *input, size_t input_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len,
    uint8_t *output, size_t output_len
);

/**
 * @brief Keyed-Hashing for Message Authentication (HMAC).
 * http://tools.ietf.org/html/rfc2104
 * Computes HMAC-SHA-256 of the input for the key.
 * The output buffer must be at least SHA256_OUTPUT_LENGTH (32) bytes long.
 *
 * @param key
 * @param key_len
 * @param input
 * @param input_len
 * @param output
 */
void crypto_hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *input, size_t input_len,
    uint8_t *output
);

/**
 * @brief Secure Hash Algorithms (SHAs)
 * https://www.rfc-editor.org/rfc/rfc6234
 * Computes HMAC-SHA-256 of the input for the key.
 * The output buffer must be at least SHA256_OUTPUT_LENGTH (32) bytes long.
 *
 * @param msg
 * @param msg_len
 * @param hash_out
 */
void crypto_sha256(
    const uint8_t *msg, size_t msg_len,
    uint8_t *hash_out
);

/**
 * @brief AES256 encrypt function in GCM mode.
 * @see [AES256 GCM mode](https://datatracker.ietf.org/doc/html/rfc5288)
 * @param plaintext_data
 * @param plaintext_data_len
 * @param aes_key
 * @param iv
 * @param add
 * @param add_len
 * @param ciphertext_data
 */
void crypto_aes_encrypt_gcm(
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    const uint8_t *aes_key, const uint8_t *iv,
    const uint8_t *add, size_t add_len,
    uint8_t *ciphertext_data
);

/**
 * @brief AES256 decrypt function in GCM mode.
 * @see [AES256 GCM mode](https://datatracker.ietf.org/doc/html/rfc5288)
 *
 * @param ciphertext_data
 * @param ciphertext_data_len
 * @param aes_key
 * @param iv
 * @param add
 * @param add_len
 * @param plaintext_data
 * @return size_t plaintext data length
 */
size_t crypto_aes_decrypt_gcm(
    const uint8_t *ciphertext_data, size_t ciphertext_data_len,
    const uint8_t *aes_key, const uint8_t *iv,
    const uint8_t *add, size_t add_len,
    uint8_t *plaintext_data
);

/**
 * @brief AES256 encrypt data in GCM mode.
 *
 * @param plaintext_data
 * @param plaintext_data_len
 * @param aes_key
 * @param ciphertext_data
 * @return size_t ciphertext data length
 */
size_t encrypt_aes_data(
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    const uint8_t aes_key[AES256_KEY_LENGTH],
    uint8_t **ciphertext_data
);

/**
 * @brief AES256 decrypt data in GCM mode.
 *
 * @param ciphertext_data
 * @param ciphertext_data_len
 * @param aes_key
 * @param plaintext_data
 * @return size_t plaintext data length
 */
size_t decrypt_aes_data(
    const uint8_t *ciphertext_data, size_t ciphertext_data_len,
    const uint8_t aes_key[AES256_KEY_LENGTH],
    uint8_t **plaintext_data
);

/**
 * @brief AES256 encrypt file in GCM mode.
 *
 * @param in_file_path
 * @param out_file_path
 * @param aes_key
 * @return int 0 for success
 */
int encrypt_aes_file(
    const char *in_file_path, const char *out_file_path,
    const uint8_t aes_key[AES256_KEY_LENGTH]
);

/**
 * @brief AES256 decrypt file in GCM mode.
 *
 * @param in_file_path
 * @param out_file_path
 * @param aes_key
 * @return int 0 for success
 */
int decrypt_aes_file(
    const char *in_file_path, const char *out_file_path,
    const uint8_t aes_key[AES256_KEY_LENGTH]
);

/**
 * @brief AES256 encrypt file in GCM mode with arbitrary password length.
 *
 * @param in_file_path
 * @param out_file_path
 * @param password
 * @param password_len
 * @return int 0 for success
 */
int encrypt_file(
    const char *in_file_path, const char *out_file_path,
    const uint8_t *password,
    const size_t password_len
);

/**
 * @brief AES256 decrypt file in GCM mode with arbitrary password length.
 *
 * @param in_file_path
 * @param out_file_path
 * @param password
 * @param password_len
 * @return int 0 for success
 */
int decrypt_file(
    const char *in_file_path, const char *out_file_path,
    const uint8_t *password,
    const size_t password_len
);

/**
 * @brief Encode to base64 string.
 *
 * @param msg
 * @param msg_len
 * @return char*
 */
char *crypto_base64_encode(const uint8_t *msg, size_t msg_len);

/**
 * @brief Decode from base64 string.
 *
 * @param base64_data
 * @param base64_data_len
 * @return char*
 */
char *crypto_base64_decode(const uint8_t *base64_data, size_t base64_data_len);


#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_H_ */
