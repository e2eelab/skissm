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

// debug msg to console
void print_msg(char *title, uint8_t *msg, size_t len);
void print_error(char *error_msg, int error_code);
void print_hex(char *title, uint8_t *msg, size_t msg_len);
void print_result(char *title, bool success);

// is_equal
bool is_equal_data(ProtobufCBinaryData *data1, ProtobufCBinaryData *data2);
bool is_equal_str(char *str1, char *str2);
bool is_equal_address(Skissm__E2eeAddress *address1, Skissm__E2eeAddress *address2);
bool is_equal_keypair(Skissm__KeyPair *keypair1, Skissm__KeyPair *keypair2);
bool is_equal_spk(Skissm__SignedPreKeyPair *spk1, Skissm__SignedPreKeyPair *spk2);
bool is_equal_opk(Skissm__OneTimePreKeyPair *opk1, Skissm__OneTimePreKeyPair *opk2);
bool is_equal_account(Skissm__E2eeAccount *account1, Skissm__E2eeAccount *account2);
bool is_equal_session(Skissm__E2eeSession *session_1, Skissm__E2eeSession *session_2);
bool is_equal_group_session(Skissm__E2eeGroupSession *group_session_1, Skissm__E2eeGroupSession *group_session_2);

// mock
void mock_data(ProtobufCBinaryData *to, const char *from);
void mock_string(char **to, const char *from);
void mock_address(Skissm__E2eeAddress **address_pp, const char *user_id, const char *domain, const char *device_id);
void mock_keypair(Skissm__KeyPair **keypair, const char *public_key, const char *private_key);
void mock_signed_pre_keypair(Skissm__SignedPreKeyPair **signed_pre_keypair, uint32_t spk_id, const char *public_key, const char *private_key, const char *signature);
void mock_onetime_pre_keypiar(Skissm__OneTimePreKeyPair **onetime_pre_keypiar, uint32_t opk_id, protobuf_c_boolean used, const char *public_key, const char *private_key);

// free
void free_account(Skissm__E2eeAccount *account);
void free_keypair(Skissm__KeyPair *keypair);
void free_signed_pre_keypair(Skissm__SignedPreKeyPair *signed_pre_keypair);
void free_one_time_pre_key_pair(Skissm__OneTimePreKeyPair *onetime_pre_keypiar);
void free_address(Skissm__E2eeAddress *address);

#endif /* TEST_UTIL_H_ */