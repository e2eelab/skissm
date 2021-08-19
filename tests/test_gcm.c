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

