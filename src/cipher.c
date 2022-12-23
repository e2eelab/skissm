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
#include "skissm/cipher.h"

#include <stdbool.h>
#include <string.h>

#include "skissm/crypto.h"
#include "skissm/mem_util.h"

static inline size_t aes256_gcm_ciphertext_data_len(size_t plaintext_data_length) {
  return plaintext_data_length + AES256_GCM_TAG_LENGTH;
}

static inline size_t aes256_gcm_plaintext_data_len(size_t ciphertext_data_len) {
  return ciphertext_data_len - AES256_GCM_TAG_LENGTH;
}

size_t aes256_gcm_encrypt(const uint8_t *ad, const uint8_t *aes_key,
                          const uint8_t *plaintext_data, size_t plaintext_data_len,
                          uint8_t **ciphertext_data) {
  uint8_t *iv = (uint8_t *)aes_key + AES256_KEY_LENGTH;
  size_t ciphertext_data_len = aes256_gcm_ciphertext_data_len(plaintext_data_len);
  *ciphertext_data = (uint8_t *)malloc(ciphertext_data_len);
  crypto_aes_encrypt_gcm(plaintext_data, plaintext_data_len, aes_key, iv, ad, AD_LENGTH,
                         *ciphertext_data);
  return ciphertext_data_len;
}

size_t aes256_gcm_decrypt(const uint8_t *ad, const uint8_t *aes_key,
                          const uint8_t *ciphertext_data,
                          size_t ciphertext_data_len, uint8_t **plaintext_data) {
  uint8_t *iv = (uint8_t *)aes_key + AES256_KEY_LENGTH;
  size_t plaintext_data_len = aes256_gcm_plaintext_data_len(ciphertext_data_len);
  *plaintext_data = (uint8_t *)malloc(plaintext_data_len);
  size_t decrypted_data_len = crypto_aes_decrypt_gcm(ciphertext_data, ciphertext_data_len, aes_key, iv, ad,
                                AD_LENGTH, *plaintext_data);
  if (decrypted_data_len == 0) {
    free_mem((void **)plaintext_data, plaintext_data_len);
  }
  return decrypted_data_len;
}
