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
#ifndef TEST_DB_H_
#define TEST_DB_H_

#include <sqlite3.h>

#include "skissm/skissm.h"

void test_db_begin();
void test_db_end();
void load_id(ProtobufCBinaryData **account_id);
size_t load_ids(sqlite_int64 **account_ids);
uint32_t load_version(uint64_t account_id);
protobuf_c_boolean load_saved(uint64_t account_id);
void load_address(uint64_t account_id, Skissm__E2eeAddress **address);
void load_password(uint64_t account_id, char *password);
uint32_t load_e2ee_pack_id(uint64_t account_id);
void load_identity_key_pair(uint64_t account_id, Skissm__IdentityKey **identity_key_pair);
void load_signed_pre_key_pair(
    uint64_t account_id,
    Skissm__SignedPreKey **signed_pre_key);
int load_n_one_time_pre_keys(uint64_t account_id);
uint32_t load_one_time_pre_keys(
    uint64_t account_id,
    Skissm__OneTimePreKey ***one_time_pre_keys);
uint32_t load_next_signed_pre_key_id(uint64_t account_id);
uint32_t load_next_one_time_pre_key_id(uint64_t account_id);
void load_id_by_address(Skissm__E2eeAddress *address, sqlite_int64 *account_id);
sqlite_int64 insert_address(Skissm__E2eeAddress *address);
sqlite_int64 insert_key_pair(Skissm__KeyPair *key_pair);
sqlite_int64 insert_identity_key(Skissm__IdentityKey *identity_key);
sqlite_int64 insert_signed_pre_key(Skissm__SignedPreKey *signed_pre_key);
sqlite_int64 insert_one_time_pre_key(Skissm__OneTimePreKey *one_time_pre_key);
sqlite_int64 insert_account(uint64_t account_id, int version, protobuf_c_boolean saved,
                            sqlite_int64 address_id, const char *password, int cipher_suite_id,
                            sqlite_int64 identity_key_pair_id, sqlite_int64 signed_pre_key_id,
                            sqlite_int64 next_one_time_pre_key_id);
void insert_account_identity_key_id(uint64_t account_id, sqlite_int64 identity_key_id);
void insert_account_signed_pre_key_id(uint64_t account_id,
                                      sqlite_int64 signed_pre_key_id);
void insert_account_one_time_pre_key_id(uint64_t account_id,
                                        sqlite_int64 one_time_pre_key_id);
void update_identity_key(uint64_t account_id, Skissm__IdentityKey *identity_key_pair);
void update_signed_pre_key(uint64_t account_id, Skissm__SignedPreKey *signed_pre_key);
void load_signed_pre_key(uint64_t account_id, uint32_t spk_id, Skissm__SignedPreKey **signed_pre_key_pair);
void remove_expired_signed_pre_key(uint64_t account_id);
void update_address(uint64_t account_id, Skissm__E2eeAddress *address);
void remove_one_time_pre_key(uint64_t account_id, uint32_t one_time_pre_key_id);
void update_one_time_pre_key(uint64_t account_id, uint32_t one_time_pre_key_id);
void add_one_time_pre_key(uint64_t account_id, Skissm__OneTimePreKey *one_time_pre_key);
void load_inbound_session(char *session_id,
                          Skissm__E2eeAddress *owner,
                          Skissm__Session **session);
void load_outbound_session(Skissm__E2eeAddress *owner,
                           Skissm__E2eeAddress *to,
                           Skissm__Session **session);
void store_session(Skissm__Session *session);
void unload_session(
    Skissm__E2eeAddress *owner,
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to
);
void load_outbound_group_session(
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address,
    Skissm__GroupSession **group_session);
void load_inbound_group_session(
    Skissm__E2eeAddress *receiver_address,
    Skissm__E2eeAddress *group_address,
    Skissm__GroupSession **group_session);
void store_group_session(
    Skissm__GroupSession *group_session);
void unload_group_session(
    Skissm__GroupSession *group_session);
void unload_inbound_group_session(
    Skissm__E2eeAddress *receiver_address,
    char *session_id
);
void store_group_pre_key(Skissm__E2eeAddress *member_address,
                         uint8_t *group_pre_key_plaintext,
                         size_t group_pre_key_plaintext_len
);
uint32_t load_group_pre_keys(Skissm__E2eeAddress *member_address,
    uint8_t ***e2ee_plaintext_data_list,
    size_t **e2ee_plaintext_data_len_list);

void unload_group_pre_key(Skissm__E2eeAddress *member_address);

#endif /* TEST_DB_H_ */
