/**
 * @file
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
#ifndef RATCHET_H_
#define RATCHET_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm/skissm.h"
#include "skissm/cipher.h"

/** Initialise the session using a shared secret and the public part of the
 * remote's first ratchet key */
int initialise_as_bob(
    Skissm__Ratchet **ratchet_out,
    const cipher_suite_t *cipher_suite,
    const uint8_t *shared_secret, size_t shared_secret_len,
    const Skissm__KeyPair *our_ratchet_key, ProtobufCBinaryData *their_ratchet_key
);

/** Initialise the session using a shared secret and the public/private key
 * pair for the first ratchet key */
int initialise_as_alice(
    Skissm__Ratchet **ratchet_out,
    const cipher_suite_t *cipher_suite,
    const uint8_t *shared_secret,
    size_t shared_secret_len,
    const Skissm__KeyPair *our_ratchet_key,
    ProtobufCBinaryData *their_ratchet_key,
    ProtobufCBinaryData *their_encaps_ciphertext
);

/**
 * @brief Encrypt plaintext_data to Skissm__One2oneMsgPayload payload
 * and keep updated ratchet states.
 *
 * @param payload_out
 * @param cipher_suite
 * @param ratchet
 * @param ad
 * @param plaintext_data
 * @param plaintext_data_len
 */
int encrypt_ratchet(
    Skissm__One2oneMsgPayload **payload_out,
    const cipher_suite_t *cipher_suite,
    Skissm__Ratchet *ratchet,
    ProtobufCBinaryData ad,
    const uint8_t *plaintext_data, size_t plaintext_data_len
);

/**
 * @brief Decrypt Skissm__One2oneMsgPayload payload to plaintext_data
 * and keep updated ratchet states.
 *
 * @param decrypted_data_out
 * @param decrypted_data_len_out
 * @param cipher_suite
 * @param ratchet
 * @param ad
 * @param payload
 * @return length of plaintext_data
 * @return 0 for error
 */
int decrypt_ratchet(
    uint8_t **decrypted_data_out, size_t *decrypted_data_len_out,
    const cipher_suite_t *cipher_suite,
    Skissm__Ratchet *ratchet, ProtobufCBinaryData ad, Skissm__One2oneMsgPayload *payload
);

#ifdef __cplusplus
}
#endif

#endif /* RATCHET_H_ */
