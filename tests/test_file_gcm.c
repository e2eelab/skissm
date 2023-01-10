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
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>

#include "skissm/crypto.h"
#include "skissm/mem_util.h"

static void test_file(){
    uint8_t key[32] = "aes_gcm_key_aes_gcm_key_aes_keys";
    uint8_t iv[16] = "aes_gcm_iv_aesiv";
    uint8_t AD[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01";
    ProtobufCBinaryData *ad = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
    ad->len = 64;
    ad->data = (uint8_t *)malloc(sizeof(uint8_t) * 64);
    memcpy(ad->data, AD, 64);

    uint8_t *plaintext, *decrypted_plaintext;
    size_t plaintext_len, decrypted_plaintext_len;

    size_t tot_test = 2000;
    FILE *fptr;
    int i;
    for (i = 0; i < tot_test; i++){
        char in_str[20], out_str[20];
        sprintf(in_str, "./data/%d", i);
        if ((fptr = fopen(in_str, "r")) == NULL){
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

        // sprintf(out_str, "./data/%d", i);
        encrypt_aes_file(in_str, out_str, ad, key);

        char decrypted_file[20];
        // sprintf(decrypted_file, "./data/%d", i);
        decrypt_aes_file(out_str, decrypted_file, ad, key);
        if ((fptr = fopen(decrypted_file, "r")) == NULL){
            printf("Error! opening file");
            // Program exits if the file pointer returns NULL.
            exit(1);
        } else{
            fseek(fptr, 0, SEEK_END);
            decrypted_plaintext_len = ftell(fptr);
            fseek(fptr, 0, SEEK_SET);
            decrypted_plaintext = (uint8_t *) malloc(sizeof(uint8_t) * decrypted_plaintext_len);
            fread(decrypted_plaintext, 1, decrypted_plaintext_len, fptr);
            fclose(fptr);
        }

        assert(decrypted_plaintext_len == plaintext_len);
        assert(memcmp(plaintext, decrypted_plaintext, plaintext_len) == 0);

        // release
        free_mem((void **)&plaintext, plaintext_len);
        free_mem((void **)&decrypted_plaintext, decrypted_plaintext_len);
    }
}

int main() {
    return 0;
}
