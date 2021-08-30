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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "cipher.h"
#include "test_env.h"

int main(){
    uint8_t plaintext[] = "This is a aes gcm test.";
    size_t plaintext_length = sizeof(plaintext) - 1;
    uint8_t key[32] = "aes_gcm_key_aes_gcm_key_aes_keys";
    uint8_t iv[16] = "aes_gcm_iv_aesiv";
    uint8_t AD[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01";
    uint8_t ciphertext[plaintext_length + 16];

    crypto_aes_encrypt_gcm(plaintext, plaintext_length, key, iv, AD, 64, ciphertext);

    uint8_t decrypted_plaintext[plaintext_length];
    size_t decrypted_plaintext_len
        = crypto_aes_decrypt_gcm(ciphertext, sizeof(ciphertext), key, iv, AD, 64, decrypted_plaintext);

    assert(decrypted_plaintext_len == plaintext_length);
    assert(memcmp(plaintext, decrypted_plaintext, plaintext_length) == 0);

    print_hex("plaintext", plaintext, plaintext_length);
    print_hex("decrypted_plaintext", decrypted_plaintext, decrypted_plaintext_len);

    return 0;
}

