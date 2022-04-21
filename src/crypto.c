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
#include "skissm/crypto.h"

#include <string.h>

#include "additions/curve_sigs.h"
#include "curve25519-donna.h"

#include "gcm.h"
#include "hkdf.h"
#include "md.h"
#include "platform.h"
#include "sha256.h"
#include "base64.h"

#include "skissm/account.h"
#include "skissm/mem_util.h"

/** amount of random data required to create a Curve25519 keypair */
#define CURVE25519_RANDOM_LENGTH CURVE25519_KEY_LENGTH

static const uint8_t CURVE25519_BASEPOINT[32] = {9};
static const size_t AES_KEY_SCHEDULE_LENGTH = 60;
static const size_t AES_KEY_BITS = 8 * AES256_KEY_LENGTH;
static const size_t AES_BLOCK_LENGTH = 16;
static const size_t SHA256_BLOCK_LENGTH = 64;
static const uint8_t HKDF_DEFAULT_SALT[32] = {};

static crypto_param_t ecdh_x25519_aes256_gcm_sha256_param = {
    CURVE25519_KEY_LENGTH,
    CURVE25519_KEY_LENGTH,
    CURVE_SIGNATURE_LENGTH,
    SHA256_OUTPUT_LENGTH,
    AES256_KEY_LENGTH,
    AES256_IV_LENGTH,
    AES256_GCM_TAG_LENGTH
};

crypto_param_t get_ecdh_x25519_aes256_gcm_sha256_param() {
    return ecdh_x25519_aes256_gcm_sha256_param;
}

void crypto_curve25519_generate_key_pair(ProtobufCBinaryData *pub_key,
                                         ProtobufCBinaryData *priv_key) {
  priv_key->data =
      (uint8_t *)malloc(sizeof(uint8_t) * CURVE25519_KEY_LENGTH);
  priv_key->len = CURVE25519_KEY_LENGTH;

  pub_key->data =
      (uint8_t *)malloc(sizeof(uint8_t) * CURVE25519_KEY_LENGTH);
  pub_key->len = CURVE25519_KEY_LENGTH;

  uint8_t random[CURVE25519_RANDOM_LENGTH];
  get_skissm_plugin()->common_handler.handle_gen_rand(random, sizeof(random));

  memcpy(priv_key->data, random, CURVE25519_KEY_LENGTH);

  curve25519_donna(pub_key->data, priv_key->data,
                   CURVE25519_BASEPOINT);
}

uint8_t *crypto_curve25519_dh(const ProtobufCBinaryData *our_key,
                          const ProtobufCBinaryData *their_key,
                          uint8_t *shared_secret) {
  curve25519_donna(shared_secret, our_key->data, their_key->data);
  return NULL;
}

void crypto_curve25519_sign(uint8_t *private_key, uint8_t *msg, size_t msg_len,
                            uint8_t *signature_out) {
  uint8_t nonce[CURVE_SIGNATURE_LENGTH];
  get_skissm_plugin()->common_handler.handle_gen_rand(nonce, sizeof(nonce));
  curve25519_sign(signature_out, private_key, msg, msg_len, nonce);
}

size_t crypto_curve25519_verify(uint8_t *signature_in, uint8_t *public_key,
                                uint8_t *msg, size_t msg_len) {
  int result;
  result = curve25519_verify(signature_in, public_key, msg, msg_len);
  return (size_t)(result);
}

void crypto_aes_encrypt_gcm(const uint8_t *plaintext_data,
                            size_t plaintext_data_len,
                            const uint8_t *key, const uint8_t *iv,
                            const uint8_t *add, size_t add_len,
                            uint8_t *ciphertext_data) {
  mbedtls_gcm_context ctx;
  unsigned char *tag_buf = ciphertext_data + plaintext_data_len;
  int ret;
  mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;
  int key_len = 256;

  mbedtls_gcm_init(&ctx);
  ret = mbedtls_gcm_setkey(&ctx, cipher, key, key_len);
  ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT,
                                  plaintext_data_len, iv,
                                  AES256_IV_LENGTH, add, add_len, plaintext_data,
                                  ciphertext_data, AES256_GCM_TAG_LENGTH, tag_buf);

  mbedtls_gcm_free(&ctx);
}

size_t crypto_aes_decrypt_gcm(const uint8_t *ciphertext_data,
                              size_t ciphertext_data_len,
                              const uint8_t *key, const uint8_t *iv,
                              const uint8_t *add, size_t add_len,
                              uint8_t *plaintext_data) {
  mbedtls_gcm_context ctx;
  unsigned char *input_tag_buf =
      (unsigned char *)(ciphertext_data + ciphertext_data_len - AES256_GCM_TAG_LENGTH);
  unsigned char tag_buf[AES256_GCM_TAG_LENGTH];
  int ret;
  mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;
  int key_len = 256;

  mbedtls_gcm_init(&ctx);
  ret = mbedtls_gcm_setkey(&ctx, cipher, key, key_len);
  ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_DECRYPT,
                                  ciphertext_data_len - AES256_GCM_TAG_LENGTH, iv,
                                  AES256_IV_LENGTH, add, add_len, ciphertext_data,
                                  plaintext_data, AES256_GCM_TAG_LENGTH, tag_buf);
  mbedtls_gcm_free(&ctx);

  // verify tag in "constant-time"
  int diff = 0, i;
  for (i = 0; i < AES256_GCM_TAG_LENGTH; i++)
    diff |= input_tag_buf[i] ^ tag_buf[i];
  if (diff == 0) {
    return (ciphertext_data_len - AES256_GCM_TAG_LENGTH);
  } else {
    return (size_t)(-1);
  }
}

void crypto_hkdf_sha256(const uint8_t *input, size_t input_len,
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *info, size_t info_len, uint8_t *output,
                        size_t output_len) {
  const mbedtls_md_info_t *sha256_info =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_hkdf(sha256_info, salt, salt_len, input, input_len, info, info_len,
               output, output_len);
}

void crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *input, size_t input_len,
                        uint8_t *output) {
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char *)key, key_len);
  mbedtls_md_hmac_update(&ctx, (const unsigned char *)input, input_len);
  mbedtls_md_hmac_finish(&ctx, output);
  mbedtls_md_free(&ctx);
}

void crypto_sha256(const uint8_t *msg, size_t msg_len, uint8_t *hash_out) {
  int buflen, ret = 0;
  mbedtls_sha256_context ctx;

  mbedtls_sha256_init(&ctx);
  ret = mbedtls_sha256_starts_ret(&ctx, 0);
  ret = mbedtls_sha256_update_ret(&ctx, msg, msg_len);
  ret = mbedtls_sha256_finish_ret(&ctx, hash_out);

  mbedtls_sha256_free(&ctx);
}

char *crypto_base64_encode(const uint8_t *msg, size_t msg_len) {
    size_t len = 4 * ((msg_len + 2) / 3) + 1;
    char* output = (char*)malloc(sizeof(char) * len);
    mbedtls_base64_encode((unsigned char *)output, len, &len, (const unsigned char *)msg, msg_len);
    return output;
}

char *crypto_base64_decode(const uint8_t *base64_data, size_t base64_data_len) {
    int pad = base64_data_len > 0 && (base64_data_len % 4 || base64_data[base64_data_len - 1] == '=');
    size_t len = ((len + 3) / 4 - pad) * 4 + 1;
    char* output = (char*)malloc(sizeof(char) * len);
    mbedtls_base64_decode((unsigned char*)output, len, &len, (const unsigned char *)base64_data, base64_data_len);
    return output;
}
