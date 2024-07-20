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

/** length of an aes256 key */
#define AES256_KEY_LENGTH 32

/** length of an aes256 initialisation vector */
#define AES256_IV_LENGTH 16

/** length of an aes256 gcm tag */
#define AES256_GCM_TAG_LENGTH 16

/** length of an aes256 initialisation vector for file encryption */
#define AES256_DATA_IV_LENGTH 12

crypto_digital_signature_param_t get_curve25519_sign_param();

crypto_digital_signature_param_t get_dilithium2_param();

crypto_digital_signature_param_t get_dilithium3_param();

crypto_digital_signature_param_t get_dilithium5_param();

crypto_digital_signature_param_t get_falcon512_param();

crypto_digital_signature_param_t get_falcon1024_param();

crypto_digital_signature_param_t get_sphincs_sha2_128f_param();

crypto_digital_signature_param_t get_sphincs_sha2_128s_param();

crypto_digital_signature_param_t get_sphincs_sha2_192f_param();

crypto_digital_signature_param_t get_sphincs_sha2_192s_param();

crypto_digital_signature_param_t get_sphincs_sha2_256f_param();

crypto_digital_signature_param_t get_sphincs_sha2_256s_param();

crypto_digital_signature_param_t get_sphincs_shake_128f_param();

crypto_digital_signature_param_t get_sphincs_shake_128s_param();

crypto_digital_signature_param_t get_sphincs_shake_192f_param();

crypto_digital_signature_param_t get_sphincs_shake_192s_param();

crypto_digital_signature_param_t get_sphincs_shake_256f_param();

crypto_digital_signature_param_t get_sphincs_shake_256s_param();

int crypto_dilithium2_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_dilithium3_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_dilithium5_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_falcon512_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_falcon1024_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_sphincs_sha2_128f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_sphincs_sha2_128s_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_sphincs_sha2_192f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_sphincs_sha2_192s_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_sphincs_sha2_256f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_sphincs_sha2_256s_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_sphincs_shake_128f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_sphincs_shake_128s_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_sphincs_shake_192f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_sphincs_shake_192s_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_sphincs_shake_256f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_sphincs_shake_256s_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

crypto_kem_param_t get_curve25519_ECDH_param();

crypto_kem_param_t get_hqc128_param();

crypto_kem_param_t get_hqc192_param();

crypto_kem_param_t get_hqc256_param();

crypto_kem_param_t get_kyber512_param();

crypto_kem_param_t get_kyber768_param();

crypto_kem_param_t get_kyber1024_param();

crypto_kem_param_t get_mceliece348864_param();

crypto_kem_param_t get_mceliece348864f_param();

crypto_kem_param_t get_mceliece460896_param();

crypto_kem_param_t get_mceliece460896f_param();

crypto_kem_param_t get_mceliece6688128_param();

crypto_kem_param_t get_mceliece6688128f_param();

crypto_kem_param_t get_mceliece6960119_param();

crypto_kem_param_t get_mceliece6960119f_param();

crypto_kem_param_t get_mceliece8192128_param();

crypto_kem_param_t get_mceliece8192128f_param();

crypto_symmetric_encryption_param_t get_aes256_param();

crypto_hash_param_t get_sha256_param();

int crypto_hqc128_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_hqc192_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_hqc256_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_kyber512_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_kyber768_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_kyber1024_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_mceliece348864_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_mceliece348864f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_mceliece460896_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_mceliece460896f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_mceliece6688128_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_mceliece6688128f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_mceliece6960119_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_mceliece6960119f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_mceliece8192128_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_mceliece8192128f_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
);

int crypto_hqc128_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
);

int crypto_hqc192_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
);

int crypto_hqc256_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
);

int crypto_kyber512_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
);

int crypto_kyber768_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
);

int crypto_kyber1024_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
);

int crypto_mceliece348864_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
);

int crypto_mceliece348864f_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
);

int crypto_mceliece460896_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
);

int crypto_mceliece460896f_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
);

int crypto_mceliece6688128_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
);

int crypto_mceliece6688128f_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
);

int crypto_mceliece6960119_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
);

int crypto_mceliece6960119f_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
);

int crypto_mceliece8192128_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
);

int crypto_mceliece8192128f_encaps(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
);

int crypto_hqc128_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
);

int crypto_hqc192_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
);

int crypto_hqc256_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
);

int crypto_kyber512_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
);

int crypto_kyber768_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
);

int crypto_kyber1024_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
);

int crypto_mceliece348864_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
);

int crypto_mceliece348864f_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
);

int crypto_mceliece460896_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
);

int crypto_mceliece460896f_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
);

int crypto_mceliece6688128_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
);

int crypto_mceliece6688128f_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
);

int crypto_mceliece6960119_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
);

int crypto_mceliece6960119f_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
);

int crypto_mceliece8192128_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
);

int crypto_mceliece8192128f_decaps(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
);

int CURVE25519_crypto_sign_keypair(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key);

int CURVE25519_crypto_keypair(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key);

int CURVE25519_crypto_sign_signature(
    uint8_t *signature_out, size_t *signature_out_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *private_key
);

int CURVE25519_crypto_sign_verify(
    const uint8_t *signature_in, size_t signature_in_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *public_key
);

int crypto_curve25519_dh(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
);

void crypto_curve25519_sign(uint8_t *private_key,
    uint8_t *msg, size_t msg_len, uint8_t *signature_out
);

int crypto_curve25519_verify(
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
int crypto_hkdf_sha256(
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
int crypto_hmac_sha256(
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
int crypto_sha256(
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
int crypto_aes_encrypt_gcm(
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
 * @param plaintext_data_len
 * @return size_t plaintext data length
 */
int crypto_aes_decrypt_gcm(
    const uint8_t *ciphertext_data, size_t ciphertext_data_len,
    const uint8_t *aes_key, const uint8_t *iv,
    const uint8_t *add, size_t add_len,
    uint8_t *plaintext_data, size_t *plaintext_data_len
);

/**
 * @brief AES256 encrypt data in GCM mode.
 *
 * @param plaintext_data
 * @param plaintext_data_len
 * @param aes_key
 * @param iv
 * @param ciphertext_data
 * @return
 */
size_t encrypt_aes_data_with_iv(
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    const uint8_t aes_key[AES256_KEY_LENGTH],
    const uint8_t iv[AES256_DATA_IV_LENGTH],
    uint8_t **ciphertext_data
);

/**
 * @brief AES256 encrypt data in GCM mode.
 * The initial vector iv is designated to zeros.
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
 *  @brief AES256 decrypt data in GCM mode.
 *
 * @param ciphertext_data
 * @param ciphertext_data_len
 * @param aes_key
 * @param iv
 * @param plaintext_data
 * @return
 */
size_t decrypt_aes_data_with_iv(
    const uint8_t *ciphertext_data, size_t ciphertext_data_len,
    const uint8_t aes_key[AES256_KEY_LENGTH],
    const uint8_t iv[AES256_DATA_IV_LENGTH],
    uint8_t **plaintext_data
);

/**
 * @brief AES256 decrypt data in GCM mode.
 * The initial vector iv is designated to zeros.
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
 * The initial vector iv is designated to zeros.
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
 * The initial vector iv is designated to zeros.
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
 * @brief AES256 encrypt file in GCM mode.
 * The initial vector iv is designated to zeros.
 * The password is an arbitrary vector with non-zero length.
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
 * @brief AES256 decrypt file in GCM mode.
 * The initial vector iv is designated to zeros.
 * The password is an arbitrary vector with non-zero length.
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
size_t crypto_base64_decode(uint8_t **msg_out, const unsigned char *base64_str);

/**
 * @brief Calculate hash with respect to the specific e2ee pack ID raw number.
 *
 * @param e2ee_pack_id_raw
 * @param msg
 * @param msg_len
 * @param hash_out
 * @param hash_out_len
 * @return value < 0 for error
 */
int crypto_hash_by_e2ee_pack_id(
    uint32_t e2ee_pack_id_raw,
    const uint8_t *msg, size_t msg_len,
    uint8_t **hash_out, size_t *hash_out_len
);

/**
 * @brief Generate a random key pair that will be used to generate or verify a signature
 * with respect to the specific e2ee pack ID raw number.
 *
 * @param e2ee_pack_id_raw
 * @param pub_key
 * @param priv_key
 * @return value < 0 for error
 */
int crypto_ds_key_gen_by_e2ee_pack_id(
    uint32_t e2ee_pack_id_raw,
    ProtobufCBinaryData *pub_key,
    ProtobufCBinaryData *priv_key
);

/**
 * @brief Sign a message
 * with respect to the specific e2ee pack ID raw number.
 *
 * @param e2ee_pack_id_raw
 * @param signature_out
 * @param signature_out_len
 * @param msg
 * @param msg_len
 * @param private_key
 * @param private_key_len
 * @return value < 0 for error
 */
int crypto_ds_sign_by_e2ee_pack_id(
    uint32_t e2ee_pack_id_raw,
    uint8_t **signature_out, size_t *signature_out_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *private_key, size_t private_key_len
);

/**
 * @brief Verify a signature with a given message
 * with respect to the specific e2ee pack ID raw number.
 *
 * @param e2ee_pack_id_raw
 * @param signature_in
 * @param signature_in_len
 * @param msg
 * @param msg_len
 * @param public_key
 * @param public_key_len
 * @return value < 0 for error
 */
int crypto_ds_verify_by_e2ee_pack_id(
    uint32_t e2ee_pack_id_raw,
    const uint8_t *signature_in, size_t signature_in_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *public_key, size_t public_key_len
);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_H_ */
