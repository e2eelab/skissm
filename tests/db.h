

#ifndef TEST_DB_H_
#define TEST_DB_H_

#include "skissm.h"
#include <sqlite3.h>

void init_db();
void close_db();
void load_id(ProtobufCBinaryData **account_id_pp);
uint32_t load_version(ProtobufCBinaryData *account_id);
protobuf_c_boolean load_saved(ProtobufCBinaryData *account_id);

void load_address(ProtobufCBinaryData *account_id,
                  Org__E2eelab__Lib__Protobuf__E2eeAddress **address_pp);
void load_identity_key_pair(
    ProtobufCBinaryData *account_id,
    Org__E2eelab__Lib__Protobuf__KeyPair **identity_key_pair_pp);
void load_signed_pre_key_pair(
    ProtobufCBinaryData *account_id,
    Org__E2eelab__Lib__Protobuf__SignedPreKeyPair **signed_pre_key_pair_pp);
int load_n_one_time_pre_keys(ProtobufCBinaryData *account_id);
uint32_t load_one_time_pre_keys(
    ProtobufCBinaryData *account_id,
    Org__E2eelab__Lib__Protobuf__OneTimePreKeyPair ***one_time_pre_keys_ppp);
uint32_t load_next_signed_pre_key_id(ProtobufCBinaryData *account_id);
uint32_t load_next_one_time_pre_key_id(ProtobufCBinaryData *account_id);
void load_id_by_address(Org__E2eelab__Lib__Protobuf__E2eeAddress *address_p,
                        ProtobufCBinaryData **account_id_pp);
sqlite_int64
insert_address(Org__E2eelab__Lib__Protobuf__E2eeAddress *address_p);
sqlite_int64 insert_key_pair(Org__E2eelab__Lib__Protobuf__KeyPair *key_pair_p);
sqlite_int64 insert_signed_pre_key(
    Org__E2eelab__Lib__Protobuf__SignedPreKeyPair *signed_pre_key_p);
sqlite_int64 insert_one_time_pre_key(
    Org__E2eelab__Lib__Protobuf__OneTimePreKeyPair *one_time_pre_key_p);
sqlite_int64 insert_account(ProtobufCBinaryData *account_id, int version,
                            protobuf_c_boolean saved, sqlite_int64 address_id,
                            sqlite_int64 identity_key_pair_id,
                            sqlite_int64 signed_pre_key_id,
                            sqlite_int64 next_signed_pre_key_id,
                            sqlite_int64 next_one_time_pre_key_id);
void insert_account_signed_pre_key_id(sqlite_int64 account_id,
                                      sqlite_int64 signed_pre_key_id);
void insert_account_one_time_pre_key_id(sqlite_int64 account_id,
                                        sqlite_int64 one_time_pre_key_id);
void update_identity_key(
    Org__E2eelab__Lib__Protobuf__E2eeAccount *account,
    Org__E2eelab__Lib__Protobuf__KeyPair *identity_key_pair);
void update_signed_pre_key(
    Org__E2eelab__Lib__Protobuf__E2eeAccount *account,
    Org__E2eelab__Lib__Protobuf__SignedPreKeyPair *signed_pre_key);
void update_address(Org__E2eelab__Lib__Protobuf__E2eeAccount *account,
                    Org__E2eelab__Lib__Protobuf__E2eeAddress *address);
void remove_one_time_pre_key(Org__E2eelab__Lib__Protobuf__E2eeAccount *account,
                             uint32_t one_time_pre_key_id);
void add_one_time_pre_key(
    Org__E2eelab__Lib__Protobuf__E2eeAccount *account,
    Org__E2eelab__Lib__Protobuf__OneTimePreKeyPair *one_time_pre_key);
void load_inbound_session(ProtobufCBinaryData session_id,
                          Org__E2eelab__Lib__Protobuf__E2eeAddress *owner,
                          Org__E2eelab__Lib__Protobuf__E2eeSession **session);
void store_session(Org__E2eelab__Lib__Protobuf__E2eeSession *session);
void load_outbound_session(Org__E2eelab__Lib__Protobuf__E2eeAddress *owner,
                           Org__E2eelab__Lib__Protobuf__E2eeAddress *to,
                           Org__E2eelab__Lib__Protobuf__E2eeSession **session);
void load_outbound_group_session(
    Org__E2eelab__Lib__Protobuf__E2eeAddress *user_address,
    Org__E2eelab__Lib__Protobuf__E2eeAddress *group_address,
    Org__E2eelab__Lib__Protobuf__E2eeGroupSession **group_session);
void load_inbound_group_session(
    ProtobufCBinaryData group_session_id,
    Org__E2eelab__Lib__Protobuf__E2eeAddress *user_address,
    Org__E2eelab__Lib__Protobuf__E2eeGroupSession **group_session);
void store_group_session(
    Org__E2eelab__Lib__Protobuf__E2eeGroupSession *group_session);
void unload_group_session(
    Org__E2eelab__Lib__Protobuf__E2eeGroupSession *group_session);

#endif /* TEST_DB_H_ */
