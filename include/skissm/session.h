#ifndef SESSION_H_
#define SESSION_H_

#include <stdbool.h>

#include "skissm.h"

/**
 * @brief Handler for message encryption
 *
 */
typedef struct encryption_handler {
    /**
     * @param msg
     * @param msg_len
     */
    void (*on_encrypted)(uint8_t **, size_t);
} encryption_handler;

void initialise_session(
    Org__E2eelab__Skissm__Proto__E2eeSession *session,
    Org__E2eelab__Skissm__Proto__E2eeAddress *from,
    Org__E2eelab__Skissm__Proto__E2eeAddress *to
);

void pack_e2ee_plaintext(
    uint8_t *plaintext, size_t plaintext_len,
    Org__E2eelab__Skissm__Proto__E2eePlaintextType plaintext_type,
    uint8_t **context, size_t *context_len
);

size_t new_outbound_session(
    Org__E2eelab__Skissm__Proto__E2eeSession *session,
    const Org__E2eelab__Skissm__Proto__E2eeAccount *local_account,
    Org__E2eelab__Skissm__Proto__E2eePreKeyBundle *their_pre_key_bundle
);

size_t new_inbound_session(
    Org__E2eelab__Skissm__Proto__E2eeSession *session,
    Org__E2eelab__Skissm__Proto__E2eeAccount *local_account,
    Org__E2eelab__Skissm__Proto__E2eeMessage *inbound_prekey_message
);

/**
 * @brief Encrypt a given context by engaging corresponding outbound session.
 *
 * @param from From address
 * @param to To Address
 * @param context context to be encrypted
 * @param context_len context length
 * @return size_t 
 */
size_t encrypt_session(
    Org__E2eelab__Skissm__Proto__E2eeAddress *from,
    Org__E2eelab__Skissm__Proto__E2eeAddress *to,
    const uint8_t *context, size_t context_len
);

/**
 * @brief Decrypt a received msg_payload by engaging corresponding inbound session.
 *
 * @param receive_msg_payload
 * @return size_t Succcess or not
 */
size_t decrypt_session(Org__E2eelab__Skissm__Proto__E2eeMessage *receive_msg_payload);

void describe(Org__E2eelab__Skissm__Proto__E2eeSession *session, char *describe_buffer, size_t buflen);

#endif /* SESSION_H_ */
