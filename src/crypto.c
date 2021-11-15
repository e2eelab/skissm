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
#include <string.h>

#include "account.h"
#include "crypto.h"
#include "mem_util.h"

#include "additions/curve_sigs.h"
#include "curve25519/curve25519-donna.h"

#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/platform.h"
#include "mbedtls/sha256.h"

static const uint8_t CURVE25519_BASEPOINT[32] = {9};
static const size_t AES_KEY_SCHEDULE_LENGTH = 60;
static const size_t AES_KEY_BITS = 8 * AES256_KEY_LENGTH;
static const size_t AES_BLOCK_LENGTH = 16;
static const size_t SHA256_BLOCK_LENGTH = 64;
static const uint8_t HKDF_DEFAULT_SALT[32] = {};

void crypto_curve25519_generate_private_key(ProtobufCBinaryData *priv_key,
                                            size_t priv_key_len) {
  priv_key->len = priv_key_len;
  priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * priv_key_len);
  get_ssm_plugin()->handle_rg(priv_key->data, priv_key->len);
}

void crypto_curve25519_generate_public_key(ProtobufCBinaryData *pub_key,
                                           ProtobufCBinaryData *priv_key) {
  pub_key->len = priv_key->len;
  pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * pub_key->len);
  curve25519_donna(pub_key->data, priv_key->data, CURVE25519_BASEPOINT);
}

void crypto_curve25519_generate_key_pair(
    Org__E2eelab__Skissm__Proto__KeyPair *key_pair) {
  key_pair->private_key.data =
      (uint8_t *)malloc(sizeof(uint8_t) * CURVE25519_KEY_LENGTH);
  key_pair->private_key.len = CURVE25519_KEY_LENGTH;

  key_pair->public_key.data =
      (uint8_t *)malloc(sizeof(uint8_t) * CURVE25519_KEY_LENGTH);
  key_pair->public_key.len = CURVE25519_KEY_LENGTH;

  uint8_t random[CURVE25519_RANDOM_LENGTH];
  get_ssm_plugin()->handle_rg(random, sizeof(random));

  memcpy(key_pair->private_key.data, random, CURVE25519_KEY_LENGTH);

  curve25519_donna(key_pair->public_key.data, key_pair->private_key.data,
                   CURVE25519_BASEPOINT);
}

void crypto_curve25519_dh(const Org__E2eelab__Skissm__Proto__KeyPair *our_key,
                          const ProtobufCBinaryData *their_key,
                          uint8_t *shared_secret) {
  curve25519_donna(shared_secret, our_key->private_key.data, their_key->data);
}

void crypto_curve25519_sign(uint8_t *private_key, uint8_t *msg, size_t msg_len,
                            uint8_t *signature_out) {
  uint8_t nonce[CURVE_SIGNATURE_LENGTH];
  get_ssm_plugin()->handle_rg(nonce, sizeof(nonce));
  curve25519_sign(signature_out, private_key, msg, msg_len, nonce);
}

size_t crypto_curve25519_verify(uint8_t *signature_in, uint8_t *public_key,
                                uint8_t *msg, size_t msg_len) {
  int result;
  result = curve25519_verify(signature_in, public_key, msg, msg_len);
  return (size_t)(result);
}

void crypto_aes_encrypt_gcm(const uint8_t *input, size_t input_length,
                            const uint8_t *key, const uint8_t *iv,
                            const uint8_t *add, size_t add_length,
                            uint8_t *ciphertext) {
  mbedtls_gcm_context ctx;
  unsigned char *tag_buf = ciphertext + input_length;
  int ret;
  mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;
  int key_len = 256;

  mbedtls_gcm_init(&ctx);
  ret = mbedtls_gcm_setkey(&ctx, cipher, key, key_len);
  ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, input_length, iv,
                                  AES256_IV_LENGTH, add, add_length, input,
                                  ciphertext, AES256_GCM_TAG_LENGTH, tag_buf);

  mbedtls_gcm_free(&ctx);
}

size_t crypto_aes_decrypt_gcm(const uint8_t *input, size_t input_length,
                              const uint8_t *key, const uint8_t *iv,
                              const uint8_t *add, size_t add_length,
                              uint8_t *output) {
  mbedtls_gcm_context ctx;
  unsigned char *input_tag_buf =
      (unsigned char *)(input + input_length - AES256_GCM_TAG_LENGTH);
  unsigned char tag_buf[AES256_GCM_TAG_LENGTH];
  int ret;
  mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;
  int key_len = 256;

  mbedtls_gcm_init(&ctx);
  ret = mbedtls_gcm_setkey(&ctx, cipher, key, key_len);
  ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_DECRYPT,
                                  input_length - AES256_GCM_TAG_LENGTH, iv,
                                  AES256_IV_LENGTH, add, add_length, input,
                                  output, AES256_GCM_TAG_LENGTH, tag_buf);
  mbedtls_gcm_free(&ctx);

  // verify tag in "constant-time"
  int diff = 0, i;
  for (i = 0; i < AES256_GCM_TAG_LENGTH; i++)
    diff |= input_tag_buf[i] ^ tag_buf[i];
  if (diff == 0) {
    return (input_length - AES256_GCM_TAG_LENGTH);
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
  ret = mbedtls_sha256_starts(&ctx, 0);
  ret = mbedtls_sha256_update(&ctx, msg, msg_len);
  ret = mbedtls_sha256_finish(&ctx, hash_out);

  mbedtls_sha256_free(&ctx);
}
