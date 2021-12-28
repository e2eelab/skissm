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

struct cipher;

typedef crypto_param (*get_crypto_param_type)(void);

typedef struct cipher_suite {
  /**
   * @brief Get the parameters of this cipher suite.
   * @return crypto_param
   */
  get_crypto_param_type get_crypto_param;

  /**
   * @brief Generate a random private key.
   *
   * @param priv_key
   * @param priv_key_len
   */
  void (*gen_private_key)(ProtobufCBinaryData *priv_key, size_t priv_key_len);

  /**
   * @brief Generate public key by given private key.
   *
   * @param pub_key
   * @param priv_key
   */
  void (*gen_public_key)(ProtobufCBinaryData *pub_key,
                         ProtobufCBinaryData *priv_key);

  /**
   * @brief Generate a random long-term key pair.
   *
   * @param key_pair
   */
  void (*lt_key_gen)(Skissm__KeyPair *key_pair);

  /**
   * @brief Generate a random medium-term key pair.
   *
   * @param key_pair
   */
  void (*mt_key_gen)(Skissm__KeyPair *key_pair);

  /**
   * @brief Generate a random short-term key pair.
   *
   * @param key_pair
   */
  void (*st_key_gen)(Skissm__KeyPair *key_pair);

  /**
   * @brief Calculate shared secret key.
   *
   * @param our_key
   * @param their_key
   * @param shared_secret
   * @return Cipher text (optional) that could be used to calculate shared secret key.
   */
  uint8_t *(*ss_key_gen)(const ProtobufCBinaryData *our_key, const ProtobufCBinaryData *their_key, uint8_t *shared_secret);

  /**
   * @brief Encrypt a given plain text.
   *
   * @param ad The associated data
   * @param key The secret key
   * @param plaintext The plain text to encrypt
   * @param plaintext_len The plain text length
   * @param ciphertext The output cipher text
   * @return Success or not
   */
  size_t (*encrypt)(const uint8_t *ad, const uint8_t *key,
                    const uint8_t *plaintext, size_t plaintext_len,
                    uint8_t **ciphertext);

  /**
   * @brief Decrypt a given cipher text.
   *
   * @param ad The associated data
   * @param key The secret key
   * @param ciphertext The cipher text to decrypt
   * @param ciphertext_len The plain text length
   * @param plaintext The output plain text
   * @return The length of plaintext or -1 for decryption error
   */
  size_t (*decrypt)(const uint8_t *ad, const uint8_t *key,
                    const uint8_t *ciphertext, size_t ciphertext_len,
                    uint8_t **plaintext);

  /**
   * @brief Sign a message.
   *
   * @param private_key
   * @param msg
   * @param msg_len
   * @param signature_out
   */
  void (*sign)(uint8_t *private_key,
    uint8_t *msg, size_t msg_len, uint8_t *signature_out);

  /**
   * @brief Verify a signature with given message.
   *
   * @param signature_in
   * @param public_key
   * @param msg
   * @param msg_len
   */
  size_t (*verify)(
    uint8_t *signature_in, uint8_t *public_key,
    uint8_t *msg, size_t msg_len);

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
    const uint8_t *input, size_t input_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len,
    uint8_t *output, size_t output_len);

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
    const uint8_t *key, size_t key_len,
    const uint8_t *input, size_t input_len,
    uint8_t *output);

  /**
   * @brief Hash function.
   *
   * @param msg
   * @param msg_len
   * @param hash_out
   */
  void (*hash)(
    const uint8_t *msg, size_t msg_len,
    uint8_t *hash_out);
} cipher_suite;

struct cipher {
  const struct cipher_suite *suite1;
};

extern const struct cipher_suite E2EE_ECDH_X25519_AES256_GCM_SHA256;

#define CIPHER_INIT                                                            \
  { &E2EE_ECDH_X25519_AES256_GCM_SHA256 }

extern const struct cipher CIPHER;

#ifdef __cplusplus
}
#endif

#endif /* CIPHER_H_ */
