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
#ifndef CIPHER_H_
#define CIPHER_H_

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm/skissm.h"

/**
 * The context strings that are used by the HKDF
 * for deriving next root key and chain key.
 */
#define KDF_INFO_ROOT "ROOT"
#define KDF_INFO_RATCHET "RATCHET"

typedef struct digital_signature_suite_t {
    /**
     * @brief Get the parameters of this digital signature suite.
     * @return crypto_digital_signature_param_t
     */
    struct crypto_digital_signature_param_t (*get_crypto_param)(void);

    /**
     * @brief Generate a random key pair that will be used to generate or verify a signature.
     *
     * @param pub_key
     * @param priv_key
     */
    int (*sign_key_gen)(
        ProtobufCBinaryData *,
        ProtobufCBinaryData *
    );

    /**
     * @brief Sign a message.
     *
     * @param signature_out
     * @param signature_out_len
     * @param msg
     * @param msg_len
     * @param private_key
     */
    int (*sign)(
        uint8_t *, size_t *,
        const uint8_t *, size_t,
        const uint8_t *
    );

    /**
     * @brief Verify a signature with a given message.
     *
     * @param signature_in
     * @param signature_in_len
     * @param msg
     * @param msg_len
     * @param public_key
     * @return value < 0 for error
     */
    int (*verify)(
        const uint8_t *, size_t,
        const uint8_t *, size_t,
        const uint8_t *
    );
} digital_signature_suite_t;

typedef struct kem_suite_t {
    /**
     * @brief Get the parameters of this kem suite.
     * @return crypto_kem_param_t
     */
    struct crypto_kem_param_t (*get_crypto_param)(void);

    /**
     * @brief Generate a random key pair that will be used to calculate shared secret keys.
     *
     * @param pub_key
     * @param priv_key
     */
    int (*asym_key_gen)(
        ProtobufCBinaryData *,
        ProtobufCBinaryData *
    );

    /**
    * @brief Calculate shared secret key.
    *
    * @param our_key
    * @param their_key
    * @param shared_secret
    * @return Cipher text (optional) that could be used to calculate shared secret key.
    */
    uint8_t *(*ss_key_gen)(
        const ProtobufCBinaryData *,
        const ProtobufCBinaryData *,
        uint8_t *
    );
} kem_suite_t;

typedef struct symmetric_encryption_suite_t {
    /**
     * @brief Get the parameters of this kem suite.
     * @return crypto_symmetric_encryption_param_t
     */
    struct crypto_symmetric_encryption_param_t (*get_crypto_param)(void);

    /**
     * @brief Encrypt a given plaintext.
     *
     * @param ad The associated data
     * @param key The secret key
     * @param plaintext_data The plaintext to encrypt
     * @param plaintext_data_len The plaintext length
     * @param ciphertext_data The output cipher text
     * @return Success or not
     */
    size_t (*encrypt)(
        const ProtobufCBinaryData *,
        const uint8_t *,
        const uint8_t *, size_t,
        uint8_t **
    );

    /**
     * @brief Decrypt a given ciphertext.
     *
     * @param ad The associated data
     * @param key The secret key
     * @param ciphertext_data The ciphertext to decrypt
     * @param ciphertext_data_len The ciphertext length
     * @param plaintext_data The output plaintext
     * @return The length of plaintext_data or -1 for decryption error
     */
    size_t (*decrypt)(
        const ProtobufCBinaryData *,
        const uint8_t *,
        const uint8_t *, size_t,
        uint8_t **
    );

    /**
     * @brief HMAC-based key derivation function.
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
    void (*hkdf)(
        const uint8_t *, size_t,
        const uint8_t *, size_t,
        const uint8_t *, size_t,
        uint8_t *, size_t
    );

    /**
     * @brief Keyed-Hashing for message authentication.
     *
     * @param key
     * @param key_len
     * @param input
     * @param input_len
     * @param output
     */
    void (*hmac)(
        const uint8_t *, size_t,
        const uint8_t *, size_t,
        uint8_t *
    );

    /**
     * @brief Hash function.
     *
     * @param msg
     * @param msg_len
     * @param hash_out
     */
    void (*hash)(
        const uint8_t *,
        size_t,
        uint8_t *
    );
} symmetric_encryption_suite_t;

typedef struct cipher_suite_t {
    digital_signature_suite_t *digital_signature_suite;
    kem_suite_t *kem_suite;
    symmetric_encryption_suite_t *symmetric_encryption_suite;
} cipher_suite_t;

/**
 * @brief Calculate ciphertext data len for AES GCM.
 *
 * @param plaintext_data_length
 * @return size_t length of ciphertext data
 */
size_t aes256_gcm_ciphertext_data_len(size_t plaintext_data_length);

/**
 * @brief Calculate plaintext data len for AES GCM.
 *
 * @param ciphertext_data_len
 * @return size_t length of plaintext data
 */
size_t aes256_gcm_plaintext_data_len(size_t ciphertext_data_len);

/**
 * @brief Encrypt plaintext with AES GCM.
 *
 * @param ad
 * @param aes_key
 * @param plaintext_data
 * @param plaintext_data_len
 * @param ciphertext_data
 * @return size_t length of ciphertext_data
 */
size_t aes256_gcm_encrypt(const ProtobufCBinaryData *ad, const uint8_t *aes_key,
    const uint8_t *plaintext_data, size_t plaintext_data_len, uint8_t **ciphertext_data
);

/**
 * @brief Decrypt a ciphertext with AES GCM.
 *
 * @param ad
 * @param aes_key
 * @param ciphertext_data
 * @param ciphertext_data_len
 * @param plaintext_data
 * @return size_t length of plaintext_data
 */
size_t aes256_gcm_decrypt(const ProtobufCBinaryData *ad, const uint8_t *aes_key,
    const uint8_t *ciphertext_data, size_t ciphertext_data_len, uint8_t **plaintext_data
);

#ifdef __cplusplus
}
#endif

#endif /* CIPHER_H_ */
