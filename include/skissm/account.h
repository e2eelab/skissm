#ifndef ACCOUNT_H_
#define ACCOUNT_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "skissm.h"

void account_begin();

void account_end();

/**
 * @brief Create a new account object
 * This will generate an identity key pair, a signed pre-key pair,
 * a signature, and 100 one-time pre-key pairs.
 * @return Org__E2eelab__Skissm__Proto__E2eeAccount*
 */
Org__E2eelab__Skissm__Proto__E2eeAccount *create_account();

/**
 * @brief Get the local account object
 *
 * @param address the peer address that is related to an account
 * @return The local account object
 */
Org__E2eelab__Skissm__Proto__E2eeAccount *
get_local_account(Org__E2eelab__Skissm__Proto__E2eeAddress *address);

/**  */

/**
 * @brief Lookup a one-time pre-key with a given public key
 *
 * @param account The account for looking up the one-time pre-key
 * @param one_time_pre_key_id The one-time pre-key id to be matched
 * @return The matched one-time pre-key.
 */
const Org__E2eelab__Skissm__Proto__OneTimePreKeyPair *
lookup_one_time_pre_key(Org__E2eelab__Skissm__Proto__E2eeAccount *account,
                        uint32_t one_time_pre_key_id);

/**
 * @brief Generate a signed pre-key and a signature
 *
 * @param account The account to be updated with new generated signed pre-key
 * @return Success or not
 */
size_t
generate_signed_pre_key(Org__E2eelab__Skissm__Proto__E2eeAccount *account);

/** Generates a number of new one time keys. */

/**
 * @brief Generates a number of new one-time pre-keys
 *
 * @param number_of_keys The given number
 * @param account The account to be appended with new generated one-time
 * pre-keys
 * @return Org__E2eelab__Skissm__Proto__OneTimePreKeyPair**
 */
Org__E2eelab__Skissm__Proto__OneTimePreKeyPair **
generate_opks(size_t number_of_keys,
              Org__E2eelab__Skissm__Proto__E2eeAccount *account);

/**
 * @brief Mark one of the one-time pre-key pairs as used given by ID
 *
 * @param account The account to be processed
 * @param id The id of one-time pre-key that will be marked as used.
 * @return Success or not
 */
size_t mark_opk_as_used(Org__E2eelab__Skissm__Proto__E2eeAccount *account,
                        uint32_t id);

/**
 * @brief Create a register request payload object
 * Copy all of the public keys stored in the account that will be published
 * to the messaging server.
 * @param account The account to be processed
 * @return The payload data
 */
Org__E2eelab__Skissm__Proto__RegisterUserRequestPayload *
create_register_request_payload(
    Org__E2eelab__Skissm__Proto__E2eeAccount *account);

/**
 * @brief Remove the used one-time pre-keys
 *
 * @param account The account to be processed
 */
void free_one_time_pre_key(Org__E2eelab__Skissm__Proto__E2eeAccount *account);

#endif /* ACCOUNT_H_ */
