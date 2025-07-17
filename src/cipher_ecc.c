/*
 * Copyright © 2021 Academia Sinica. All Rights Reserved.
 *
 * This file is part of E2EE Security.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * E2EE Security is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with E2EE Security.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "e2ees/cipher_ecc.h"

#include <stdbool.h>
#include <string.h>

#include <additions/curve_sigs.h>
#include <curve25519-donna.h>

#include "e2ees/cipher.h"
#include "e2ees/mem_util.h"

static const uint8_t CURVE25519_BASEPOINT[32] = {9};

static crypto_ds_param_t curve25519_sign_param = {
    false,
    CURVE25519_KEY_LENGTH,
    CURVE25519_KEY_LENGTH,
    CURVE_SIGNATURE_LENGTH
};

static crypto_ds_param_t get_curve25519_sign_param() {
    return curve25519_sign_param;
}

static void crypto_curve25519_sign(
    uint8_t *private_key,
    uint8_t *msg, size_t msg_len,
    uint8_t *signature_out
) {
    uint8_t nonce[CURVE_SIGNATURE_LENGTH];
    get_e2ees_plugin()->common_handler.gen_rand(nonce, sizeof(nonce));
    curve25519_sign(signature_out, private_key, msg, msg_len, nonce);
}

static int crypto_curve25519_verify(
    uint8_t *signature_in, uint8_t *public_key,
    uint8_t *msg, size_t msg_len
) {
    return curve25519_verify(signature_in, public_key, msg, msg_len);
}

static void crypto_curve25519_generate_private_key(uint8_t *private_key) {
    uint8_t random[CURVE25519_RANDOM_LENGTH];
    get_e2ees_plugin()->common_handler.gen_rand(random, sizeof(random));

    random[0] &= 248;
    random[31] &= 127;
    random[31] |= 64;

    memcpy(private_key, random, CURVE25519_KEY_LENGTH);
}

static int CURVE25519_crypto_sign_keypair(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    int result;

    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * CURVE25519_KEY_LENGTH);
    priv_key->len = CURVE25519_KEY_LENGTH;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * CURVE25519_KEY_LENGTH);
    pub_key->len = CURVE25519_KEY_LENGTH;

    uint8_t msg[10] = {0};
    uint8_t signature[CURVE_SIGNATURE_LENGTH];

    while (true) {
        crypto_curve25519_generate_private_key(priv_key->data);

        curve25519_donna(pub_key->data, priv_key->data, CURVE25519_BASEPOINT);
        crypto_curve25519_sign(priv_key->data, msg, 10, signature);
        result = crypto_curve25519_verify(signature, pub_key->data, msg, 10);
        if (result != 0) {
            // verify failed, regenerate the key pair
            e2ees_notify_log(
                NULL,
                BAD_SIGNATURE,
                "CURVE25519_crypto_sign_keypair() verify failed, regenerate the key pair."
            );
        } else {
            // success
            break;
        }
        // TODO in case of long running
    }

    return result;
}

static int CURVE25519_crypto_sign_signature(
    uint8_t *signature_out, size_t *signature_out_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *private_key
) {
    *signature_out_len = CURVE_SIGNATURE_LENGTH;
    uint8_t nonce[*signature_out_len];
    get_e2ees_plugin()->common_handler.gen_rand(nonce, sizeof(nonce));
    return curve25519_sign(signature_out, private_key, msg, msg_len, nonce);
}

static int CURVE25519_crypto_sign_verify(
    const uint8_t *signature_in, size_t signature_in_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *public_key
) {
    return curve25519_verify(signature_in, public_key, msg, msg_len);
}

static crypto_kem_param_t curve25519_ECDH_param = {
    false,
    CURVE25519_KEY_LENGTH,
    CURVE25519_KEY_LENGTH,
    0,
    CURVE25519_KEY_LENGTH
};

static crypto_kem_param_t get_curve25519_ECDH_param() {
    return curve25519_ECDH_param;
}

static int CURVE25519_crypto_keypair(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * CURVE25519_KEY_LENGTH);
    priv_key->len = CURVE25519_KEY_LENGTH;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * CURVE25519_KEY_LENGTH);
    pub_key->len = CURVE25519_KEY_LENGTH;

    crypto_curve25519_generate_private_key(priv_key->data);

    return curve25519_donna(pub_key->data, priv_key->data, CURVE25519_BASEPOINT);
}

static int crypto_curve25519_dh(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return curve25519_donna(shared_secret, our_key->data, ciphertext->data);
}

// default digital signature suite with ecc
struct ds_suite_t E2EES_CURVE25519_SIGN = {
    get_curve25519_sign_param,
    CURVE25519_crypto_sign_keypair,
    CURVE25519_crypto_sign_signature,
    CURVE25519_crypto_sign_verify
};

// default kem suite with ecc
struct kem_suite_t E2EES_CURVE25519_ECDH = {
    get_curve25519_ECDH_param,
    CURVE25519_crypto_keypair,
    NULL,
    crypto_curve25519_dh
};