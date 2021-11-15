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

#include "mem_util.h"
#include "crypto.h"

#include "test_util.h"

int main(){
    uint8_t key[32] = "aes_gcm_key_aes_gcm_key_aes_keys";
    uint8_t iv[16] = "aes_gcm_iv_aesiv";
    uint8_t AD[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01";
    uint8_t *plaintext, *ciphertext, *decrypted_plaintext;
    size_t plaintext_len, ciphertext_len, decrypted_plaintext_len;

    size_t tot_test = 2000;
    FILE *fptr;
    int i;
    for (i = 0; i < tot_test; i++){
        char str[20];
        sprintf(str, "./data/%d", i);
        if ((fptr = fopen(str, "r")) == NULL){
            printf("Error! opening file");
            // Program exits if the file pointer returns NULL.
            exit(1);
        } else{
            fseek(fptr, 0, SEEK_END);
            plaintext_len = ftell(fptr);
            fseek(fptr, 0, SEEK_SET);
            plaintext = (uint8_t *) malloc(sizeof(uint8_t) * plaintext_len);
            fread(plaintext, 1, plaintext_len, fptr);
            fclose(fptr);
        }
        ciphertext_len = plaintext_len + AES256_GCM_TAG_LENGTH;
        ciphertext = (uint8_t *) malloc(sizeof(uint8_t) * ciphertext_len);
        crypto_aes_encrypt_gcm(plaintext, plaintext_len, key, iv, AD, 64, ciphertext);

        decrypted_plaintext = (uint8_t *) malloc(sizeof(uint8_t) * plaintext_len);
        decrypted_plaintext_len = crypto_aes_decrypt_gcm(ciphertext, ciphertext_len, key, iv, AD, 64, decrypted_plaintext);

        assert(decrypted_plaintext_len == plaintext_len);
        assert(memcmp(plaintext, decrypted_plaintext, plaintext_len) == 0);

        print_hex("plaintext", plaintext, plaintext_len);
        print_hex("decrypted_plaintext", decrypted_plaintext, decrypted_plaintext_len);

        free_mem((void **)&plaintext, plaintext_len);
        free_mem((void **)&ciphertext, ciphertext_len);
        free_mem((void **)&decrypted_plaintext, decrypted_plaintext_len);
    }

    return 0;
}

