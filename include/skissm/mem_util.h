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

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm/skissm.h"

/** Check if two buffers are equal in constant time. */
bool is_equal(
    const uint8_t *buffer_a,
    const uint8_t *buffer_b,
    size_t length
);

/**
 * @brief Generate a UUID string
 *
 * @return char*
 */
char *generate_uuid_str();

/**
 * @brief Compare two ProtobufCBinaryData objects.
 *
 * @param src_1
 * @param src_2
 * @return true
 * @return false
 */
bool compare_protobuf(ProtobufCBinaryData *src_1, ProtobufCBinaryData *src_2);

/**
 * @brief Compare two Skissm__E2eeAddress objects.
 *
 * @param address_1
 * @param address_2
 * @return true
 * @return false
 */
bool compare_address(Skissm__E2eeAddress *address_1, Skissm__E2eeAddress *address_2);

/**
 * @brief Compaare two Skissm__E2eeAddress arrays.
 *
 * @param member_addresses_1
 * @param member_num_1
 * @param member_addresses_2
 * @param member_num_2
 * @return true
 * @return false
 */
bool compare_member_addresses(
    Skissm__E2eeAddress **member_addresses_1, size_t member_num_1,
    Skissm__E2eeAddress **member_addresses_2, size_t member_num_2
);

/**
 * @brief Compare two char string that can be NULL.
 *
 * @param str1
 * @param str2
 * @return true
 * @return false
 */
bool safe_strcmp(char *str1, char *str2);

/**
 * @brief Copy ProtobufCBinaryData from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_protobuf_from_protobuf(ProtobufCBinaryData *dest, const ProtobufCBinaryData *src);

/**
 * @brief Copy data from byte array to ProtobufCBinaryData.
 *
 * @param dest
 * @param src
 * @param len
 */
void copy_protobuf_from_array(ProtobufCBinaryData *dest, const uint8_t *src, size_t len);

/**
 * @brief Overwrite data from byte array to ProtobufCBinaryData.
 *
 * @param dest
 * @param src
 */
void overwrite_protobuf_from_array(ProtobufCBinaryData *dest, const uint8_t *src);

/**
 * @brief Copy Skissm__E2eeAddress from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_address_from_address(Skissm__E2eeAddress **dest, const Skissm__E2eeAddress *src);

/**
 * @brief Copy Skissm__KeyPair from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_key_pair_from_key_pair(
    Skissm__KeyPair **dest,
    Skissm__KeyPair *src
);

/**
 * @brief Copy Skissm__SignedPreKey from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_spk_from_spk(
    Skissm__SignedPreKey **dest,
    Skissm__SignedPreKey *src
);

/**
 * @brief Copy Skissm__OneTimePreKey from src to dest.
 *
 * @param dest
 * @param src
 * @param opk_num
 */
void copy_opks_from_opks(
    Skissm__OneTimePreKey ***dest,
    Skissm__OneTimePreKey **src,
    size_t opk_num
);

/**
 * @brief Copy Skissm__Account from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_account_from_account(
    Skissm__Account **dest,
    Skissm__Account *src
);

/**
 * @brief Copy Skissm__E2eeAddress array from src to dest.
 *
 * @param dest
 * @param src
 * @param member_num
 */
void copy_member_addresses_from_member_addresses(
    Skissm__E2eeAddress ***dest,
    const Skissm__E2eeAddress **src,
    size_t member_num
);

/**
 * @brief Release memory of Skissm__E2eeAddress array.
 *
 * @param dest
 * @param member_num
 */
void free_member_addresses(Skissm__E2eeAddress ***dest, size_t member_num);

/**
 * @brief Release memory of ProtobufCBinaryData.
 *
 * @param output
 */
void free_protobuf(ProtobufCBinaryData *output);

/**
 * @brief Release a memory block.
 *
 * @param buffer
 * @param buffer_len
 */
void free_mem(void **buffer, size_t buffer_len);

/**
 * Clear the memory held in the buffer.
 * This is more resilient to being optimised away than memset or bzero.
 */
void unset(void volatile *buffer, size_t buffer_len);

#ifdef __cplusplus
}
#endif

#endif /* MEM_UTIL_H_ */
