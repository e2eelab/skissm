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
#ifndef TEST_UTIL_H_
#define TEST_UTIL_H_

#include "skissm/skissm.h"

#define E2EELAB_DOMAIN          "e2eelab.org"
#define TEST_E2EE_PACK_ID_ECC       "0"
#define TEST_E2EE_PACK_ID_PQC       "1"

#define gen_e2ee_pack_id_ecc() \
    gen_e2ee_pack_id_raw( \
        0, \
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_CURVE25519, \
        E2EE_PACK_ALG_KEM_CURVE25519, \
        E2EE_PACK_ALG_SYMMETRIC_KEY_AES256, \
        E2EE_PACK_ALG_HASH_SHA2_256 \
    )

#define gen_e2ee_pack_id_pqc() \
    gen_e2ee_pack_id_raw( \
        0, \
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_DILITHIUM5, \
        E2EE_PACK_ALG_KEM_KYBER1024, \
        E2EE_PACK_ALG_SYMMETRIC_KEY_AES256, \
        E2EE_PACK_ALG_HASH_SHA2_256 \
    )

// debug msg to console
void print_hex(char *title, uint8_t *msg, size_t msg_len);
void print_msg(char *title, uint8_t *msg, size_t len);
void print_log(char *log_msg, int log_code);
void print_result(char *title, bool success);

bool is_null(void *pointer_1, void *pointer_2);
bool is_not_null(void *pointer_1, void *pointer_2);

// is_equal
bool is_equal_data(ProtobufCBinaryData *data1, ProtobufCBinaryData *data2);
bool is_equal_str(char *str1, char *str2);
bool is_equal_keypair(Skissm__KeyPair *keypair1, Skissm__KeyPair *keypair2);
bool is_equal_spk(Skissm__SignedPreKey *spk1, Skissm__SignedPreKey *spk2);
bool is_equal_opk(Skissm__OneTimePreKey *opk1, Skissm__OneTimePreKey *opk2);
bool is_equal_account(Skissm__Account *account1, Skissm__Account *account2);
bool is_equal_message_key(Skissm__MsgKey *msg_key_1, Skissm__MsgKey *msg_key_2);
bool is_equal_chain(Skissm__ChainKey *chain_key_1, Skissm__ChainKey *chain_key_2);
bool is_equal_sender_chain(Skissm__SenderChainNode *sender_chain_1, Skissm__SenderChainNode *sender_chain_2);
bool is_equal_receiver_chain(Skissm__ReceiverChainNode *receiver_chain_node_1, Skissm__ReceiverChainNode *receiver_chain_node_2);
bool is_equal_skipped_message_key(Skissm__SkippedMsgKeyNode *skipped_msg_key_node_1, Skissm__SkippedMsgKeyNode *skipped_msg_key_node_2);
bool is_equal_ratchet(Skissm__Ratchet *ratchet_1, Skissm__Ratchet *ratchet_2);
bool is_equal_session(Skissm__Session *session_1, Skissm__Session *session_2);
bool is_equal_sessions(Skissm__Session **sessions_1, Skissm__Session **sessions_2, size_t session_num);
bool is_equal_group_session(Skissm__GroupSession *group_session_1, Skissm__GroupSession *group_session_2);

// mock
void mock_data(ProtobufCBinaryData *to, const char *from);
void mock_string(char **to, const char *from);
char *mock_domain_str();
void mock_address(Skissm__E2eeAddress **address_pp, const char *user_id, const char *domain, const char *device_id);
void mock_random_group_address(Skissm__E2eeAddress **address);
void mock_random_user_address(Skissm__E2eeAddress **address);
void mock_keypair(Skissm__KeyPair **keypair, const char *public_key, const char *private_key);
void mock_identity_keypair(Skissm__IdentityKey **identity_keypair, const char *public_key, const char *private_key);
void mock_signed_pre_keypair(Skissm__SignedPreKey **signed_pre_keypair, uint32_t spk_id, const char *public_key, const char *private_key, const char *signature);
void mock_one_time_pre_keypair(Skissm__OneTimePreKey **one_time_pre_keypair, uint32_t opk_id, protobuf_c_boolean used, const char *public_key, const char *private_key);

// hash
void pre_key_bundle_hash(
    uint8_t **out,
    size_t *out_len,
    Skissm__E2eeAddress *address,
    Skissm__IdentityKeyPublic *ik,
    Skissm__SignedPreKeyPublic *spk,
    Skissm__OneTimePreKeyPublic *opk
);

void proto_msg_hash(
    uint8_t **out,
    size_t *out_len,
    Skissm__ProtoMsgTag *tag,
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to,
    Skissm__ProtoMsg__PayloadCase payload_case,
    void *payload
);

// free
void free_account(Skissm__Account *account);
void free_keypair(Skissm__KeyPair *keypair);
void free_signed_pre_keypair(Skissm__SignedPreKey *signed_pre_keypair);
void free_one_time_pre_key_pair(Skissm__OneTimePreKey *one_time_pre_keypair);
void free_address(Skissm__E2eeAddress *address);

#endif /* TEST_UTIL_H_ */
