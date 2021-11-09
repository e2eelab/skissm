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
#ifndef MEM_UTIL_H_
#define MEM_UTIL_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "skissm.h"

/** Check if two buffers are equal in constant time. */
bool is_equal(
    const uint8_t *buffer_a,
    const uint8_t *buffer_b,
    size_t length
);

bool compare_protobuf(ProtobufCBinaryData *src_1, ProtobufCBinaryData *src_2);

bool compare_address(Org__E2eelab__Skissm__Proto__E2eeAddress *address_1, Org__E2eelab__Skissm__Proto__E2eeAddress *address_2);

bool compare_member_addresses(
    Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses_1, size_t member_num_1,
    Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses_2, size_t member_num_2
);

bool safe_strcmp(char *str1, char *str2);

void copy_protobuf_from_protobuf(ProtobufCBinaryData *dest, const ProtobufCBinaryData *src);
void copy_protobuf_from_array(ProtobufCBinaryData *dest, const uint8_t *src, size_t len);
void overwrite_protobuf_from_array(ProtobufCBinaryData *dest, const uint8_t *src);

void copy_address_from_address(Org__E2eelab__Skissm__Proto__E2eeAddress **dest, const Org__E2eelab__Skissm__Proto__E2eeAddress *src);

void copy_key_pair_from_key_pair(
    Org__E2eelab__Skissm__Proto__KeyPair **dest,
    Org__E2eelab__Skissm__Proto__KeyPair *src
);

void copy_spk_from_spk(
    Org__E2eelab__Skissm__Proto__SignedPreKeyPair **dest,
    Org__E2eelab__Skissm__Proto__SignedPreKeyPair *src
);

void copy_opks_from_opks(
    Org__E2eelab__Skissm__Proto__OneTimePreKeyPair ***dest,
    Org__E2eelab__Skissm__Proto__OneTimePreKeyPair **src,
    size_t opk_num
);

void copy_account_from_account(
    Org__E2eelab__Skissm__Proto__E2eeAccount **dest,
    Org__E2eelab__Skissm__Proto__E2eeAccount *src
);

void copy_member_addresses_from_member_addresses(
    Org__E2eelab__Skissm__Proto__E2eeAddress ***dest,
    const Org__E2eelab__Skissm__Proto__E2eeAddress **src,
    size_t member_num
);

void free_member_addresses(Org__E2eelab__Skissm__Proto__E2eeAddress ***dest, size_t member_num);

void free_protobuf(ProtobufCBinaryData *output);

void free_mem(void **buffer, size_t buffer_len);

/**
 * Clear the memory held in the buffer.
 * This is more resilient to being optimised away than memset or bzero.
 */
void unset(void volatile *buffer, size_t buffer_len);

#endif /* MEM_UTIL_H_ */
