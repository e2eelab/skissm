#ifndef RATCHET_H_
#define RATCHET_H_

#include <stdint.h>
#include <stddef.h>

#include "skissm.h"
#include "cipher.h"
#include "crypto.h"

typedef struct cipher cipher;

static const size_t MAX_RECEIVER_CHAINS = 5;
static const size_t MAX_SKIPPED_MESSAGE_KEYS = 40;

static const size_t SHARED_KEY_LENGTH = SHA256_OUTPUT_LENGTH;
static const size_t MESSAGE_KEY_LENGTH = AES256_KEY_LENGTH + AES256_IV_LENGTH;

typedef uint8_t shared_key[SHARED_KEY_LENGTH];
typedef uint8_t derived_key[MESSAGE_KEY_LENGTH];

void initialise_ratchet(Org__E2eelab__Skissm__Proto__E2eeRatchet **ratchet);

/** Initialise the session using a shared secret and the public part of the
 * remote's first ratchet key */
void initialise_as_bob(
    Org__E2eelab__Skissm__Proto__E2eeRatchet *ratchet, const uint8_t *shared_secret, size_t shared_secret_length,
    const Org__E2eelab__Skissm__Proto__KeyPair *our_ratchet_key
);

/** Initialise the session using a shared secret and the public/private key
 * pair for the first ratchet key */
void initialise_as_alice(
    Org__E2eelab__Skissm__Proto__E2eeRatchet *ratchet, const uint8_t *shared_secret, size_t shared_secret_length,
    const Org__E2eelab__Skissm__Proto__KeyPair *our_ratchet_key, ProtobufCBinaryData *their_ratchet_key
);

void encrypt_ratchet(
    Org__E2eelab__Skissm__Proto__E2eeRatchet *ratchet,
    ProtobufCBinaryData ad,
    const uint8_t *plaintext, size_t plaintext_length,
    Org__E2eelab__Skissm__Proto__E2eeMsgPayload **e2ee_msg_payload
);

size_t decrypt_ratchet(
    Org__E2eelab__Skissm__Proto__E2eeRatchet *ratchet, ProtobufCBinaryData ad, Org__E2eelab__Skissm__Proto__E2eeMsgPayload *e2ee_msg_payload,
    uint8_t **plaintext
);

#endif /* RATCHET_H_ */
