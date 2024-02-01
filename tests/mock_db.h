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
#ifndef MOCK_DB_H_
#define MOCK_DB_H_

#include <sqlite3.h>
#include <stdbool.h>

#include "skissm/skissm.h"

void mock_db_begin();
void mock_db_end();
size_t load_address_ids(sqlite_int64 **address_ids);
char *load_version(uint64_t address_id);
protobuf_c_boolean load_saved(uint64_t address_id);
bool load_address(uint64_t address_id, Skissm__E2eeAddress **address);
bool load_group_address(uint64_t address_id, Skissm__E2eeAddress **address);
void load_password(uint64_t address_id, char *password);
uint32_t load_e2ee_pack_id(uint64_t address_id);
void load_identity_key_pair(uint64_t address_id, Skissm__IdentityKey **identity_key_pair);
void load_signed_pre_key_pair(uint64_t address_id, Skissm__SignedPreKey **signed_pre_key);
int load_n_one_time_pre_keys(uint64_t address_id);
uint32_t load_one_time_pre_keys(uint64_t address_id, Skissm__OneTimePreKey ***one_time_pre_keys);
uint32_t load_next_one_time_pre_key_id(uint64_t address_id);
bool load_address_id(Skissm__E2eeAddress *address, sqlite_int64 *address_id);
sqlite_int64 insert_address(Skissm__E2eeAddress *address);
sqlite_int64 insert_key_pair(Skissm__KeyPair *key_pair);
sqlite_int64 insert_identity_key(Skissm__IdentityKey *identity_key);
sqlite_int64 insert_signed_pre_key(Skissm__SignedPreKey *signed_pre_key);
sqlite_int64 insert_one_time_pre_key(Skissm__OneTimePreKey *one_time_pre_key);
sqlite_int64 insert_account(
    const char *version, protobuf_c_boolean saved, const char *auth, sqlite_int64 address_id,
    const char *password, uint32_t e2ee_pack_id, sqlite_int64 identity_key_pair_id,
    sqlite_int64 signed_pre_key_id, sqlite_int64 next_one_time_pre_key_id
);
void insert_account_identity_key_id(uint64_t address_id, sqlite_int64 identity_key_id);
void insert_account_signed_pre_key_id(uint64_t address_id, sqlite_int64 signed_pre_key_id);
void insert_account_one_time_pre_key_id(uint64_t address_id, sqlite_int64 one_time_pre_key_id);
bool update_signed_pre_key(Skissm__E2eeAddress *address, Skissm__SignedPreKey *signed_pre_key);
void load_signed_pre_key(Skissm__E2eeAddress *address, uint32_t spk_id, Skissm__SignedPreKey **signed_pre_key_pair);
bool remove_expired_signed_pre_key(Skissm__E2eeAddress *address);
bool remove_one_time_pre_key(Skissm__E2eeAddress *address, uint32_t one_time_pre_key_id);
bool update_one_time_pre_key(Skissm__E2eeAddress *address, uint32_t one_time_pre_key_id);
bool add_one_time_pre_key(Skissm__E2eeAddress *address, Skissm__OneTimePreKey *one_time_pre_key);
void store_account(Skissm__Account *account);
void load_account_by_address_id(uint64_t address_id, Skissm__Account **account);
void load_auth(Skissm__E2eeAddress *address, char **auth); // new added
void load_account_by_address(Skissm__E2eeAddress *address, Skissm__Account **account);
size_t load_accounts(Skissm__Account ***accounts);
void load_inbound_session(char *session_id, Skissm__E2eeAddress *our_address, Skissm__Session **session);
void load_outbound_session(Skissm__E2eeAddress *our_address, Skissm__E2eeAddress *their_address, Skissm__Session **session);
int load_n_outbound_sessions(Skissm__E2eeAddress *our_address, const char *their_user_id);
size_t load_outbound_sessions(Skissm__E2eeAddress *our_address, const char *their_user_id, const char *their_domain, Skissm__Session ***outbound_sessions);
void store_session(Skissm__Session *session);
void unload_session(Skissm__E2eeAddress *our_address, Skissm__E2eeAddress *their_address);
void unload_old_session(Skissm__E2eeAddress *our_address, Skissm__E2eeAddress *their_address);
void load_group_session_by_address(Skissm__E2eeAddress *sender_address, Skissm__E2eeAddress *owner_address, Skissm__E2eeAddress *group_address, Skissm__GroupSession **group_session);
void load_group_session_by_id(Skissm__E2eeAddress *sender_address, Skissm__E2eeAddress *owner_address, char *session_id, Skissm__GroupSession **group_session);
int load_n_group_sessions(Skissm__E2eeAddress *owner_address, Skissm__E2eeAddress *group_address);
size_t load_group_sessions(Skissm__E2eeAddress *owner_address, Skissm__E2eeAddress *group_address, Skissm__GroupSession ***group_sessions);
int load_n_group_addresses(Skissm__E2eeAddress *sender_address, Skissm__E2eeAddress *owner_address);
size_t load_group_addresses(Skissm__E2eeAddress *sender_address, Skissm__E2eeAddress *owner_address, Skissm__E2eeAddress ***group_addresses);
void store_group_session(Skissm__GroupSession *group_session);
void unload_group_session_by_address(Skissm__E2eeAddress *session_owner, Skissm__E2eeAddress *group_address);
void unload_group_session_by_id(Skissm__E2eeAddress *session_owner, char *session_id);
void store_pending_plaintext_data(
    Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *to_address, char *pending_plaintext_id,
    uint8_t *group_pre_key_plaintext, size_t group_pre_key_plaintext_len
);
size_t load_pending_plaintext_data(
    Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *to_address, char ***pending_plaintext_id_list,
    uint8_t ***e2ee_plaintext_data_list, size_t **e2ee_plaintext_data_len_list
);
void unload_pending_plaintext_data(Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *to_address, char *pending_plaintext_id);
void store_pending_request_data(Skissm__E2eeAddress *user_address, char *request_id, uint8_t request_type, uint8_t *request_data, size_t request_data_len);
size_t load_pending_request_data(Skissm__E2eeAddress *user_address, char ***request_id_list, uint8_t **request_type, uint8_t ***request_data_list, size_t **request_data_len_list);
void unload_pending_request_data(Skissm__E2eeAddress *user_address, char *request_id);

#endif /* MOCK_DB_H_ */
