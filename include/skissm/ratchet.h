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
#ifndef RATCHET_H_
#define RATCHET_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm/skissm.h"
#include "skissm/cipher.h"
#include "skissm/crypto.h"

/** length of a shared key */
#define SHARED_KEY_LENGTH SHA256_OUTPUT_LENGTH

/** length of a message key */
#define MESSAGE_KEY_LENGTH (AES256_KEY_LENGTH + AES256_IV_LENGTH)

typedef struct cipher cipher;

typedef uint8_t shared_key[SHARED_KEY_LENGTH];
typedef uint8_t derived_key[MESSAGE_KEY_LENGTH];

void initialise_ratchet(Skissm__E2eeRatchet **ratchet);

/** Initialise the session using a shared secret and the public part of the
 * remote's first ratchet key */
void initialise_as_bob(
    Skissm__E2eeRatchet *ratchet, const uint8_t *shared_secret, size_t shared_secret_length,
    const Skissm__KeyPair *our_ratchet_key
);

/** Initialise the session using a shared secret and the public/private key
 * pair for the first ratchet key */
void initialise_as_alice(
    Skissm__E2eeRatchet *ratchet, const uint8_t *shared_secret, size_t shared_secret_length,
    const Skissm__KeyPair *our_ratchet_key, ProtobufCBinaryData *their_ratchet_key
);

void encrypt_ratchet(
    Skissm__E2eeRatchet *ratchet,
    ProtobufCBinaryData ad,
    const uint8_t *plaintext, size_t plaintext_length,
    Skissm__E2eeMsgPayload **e2ee_msg_payload
);

size_t decrypt_ratchet(
    Skissm__E2eeRatchet *ratchet, ProtobufCBinaryData ad, Skissm__E2eeMsgPayload *e2ee_msg_payload,
    uint8_t **plaintext
);

#ifdef __cplusplus
}
#endif

#endif /* RATCHET_H_ */
