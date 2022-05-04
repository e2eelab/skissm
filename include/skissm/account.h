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
#ifndef ACCOUNT_H_
#define ACCOUNT_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm/skissm.h"

void account_begin();

void account_end();

/**
 * @brief Create a new account object
 * This will generate an identity key pair, a signed pre-key pair,
 * a signature, and 100 one-time pre-key pairs.
 * @param account_id a unique account id start form 1
 * @param e2ee_pack_id an id (0, 1) of e2ee package
 * @return Skissm__Account*
 */
Skissm__Account *create_account(uint64_t account_id, const char *e2ee_pack_id);

/**
 * @brief Get the current account that is loaded
 * by default or switched by address.
 *
 * @return Skissm__Account* An account used currently.
 */
Skissm__Account *get_account();

/**
 * @brief Set current account.
 * @param account
 */
void set_account(Skissm__Account *account);

/**
 * @brief Switch to a account with given address. The account will be NULL if it can't be found from database.
 *
 * @param address the peer address that is related to an account
 * @return Skissm__Account* The account object
 */
Skissm__Account *
switch_account(Skissm__E2eeAddress *address);

/**
 * @brief Lookup an one-time pre-key with a given public key
 *
 * @param account The account for looking up the one-time pre-key
 * @param one_time_pre_key_id The one-time pre-key id to be matched
 * @return const Skissm__OneTimePreKey* The matched one-time pre-key.
 */
const Skissm__OneTimePreKey *
lookup_one_time_pre_key(Skissm__Account *account,
                        uint32_t one_time_pre_key_id);

/**
 * @brief Generate a new signed pre-key pair and a new signature.
 *
 * @param account The account to be updated with new generated signed pre-key
 * @return Success or not
 */
size_t
generate_signed_pre_key(Skissm__Account *account);

/**
 * @brief Generates a number of new one-time pre-keys
 *
 * @param number_of_keys The given number
 * @param account The account to be appended with new generated one-time
 * pre-keys
 * @return Skissm__OneTimePreKey**
 */
Skissm__OneTimePreKey **
generate_opks(size_t number_of_keys,
              Skissm__Account *account);

/**
 * @brief Mark one of the one-time pre-key pairs as used given by ID
 *
 * @param account The account to be processed
 * @param id The id of one-time pre-key that will be marked as used.
 * @return Success or not
 */
size_t mark_opk_as_used(Skissm__Account *account,
                        uint32_t id);

/**
 * @brief Remove the used one-time pre-keys
 *
 * @param account The account to be processed
 */
void free_one_time_pre_key(Skissm__Account *account);

#ifdef __cplusplus
}
#endif

#endif /* ACCOUNT_H_ */
