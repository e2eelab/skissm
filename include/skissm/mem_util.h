/**
 * @file
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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm/skissm.h"

#define free_string(arg) \
    if (arg != NULL) { \
        free(arg); \
        arg = NULL; \
    }

#define free_proto(arg) \
    if (arg != NULL) { \
        skissm__##arg##__free_unpacked(arg, NULL); \
        arg = NULL; \
    }

/** Check if two buffers are equal in constant time. */
bool is_equal(const uint8_t *buffer_a, const uint8_t *buffer_b, size_t len);

/**
 * @brief Generate a UUID string.
 *
 * @return char*
 */
char *generate_uuid_str();

/**
 * @brief Generate hex string from given uint8 array.
 *
 * @param buffer
 * @param buffer_len
 * @param hex_str output hex str
 * @return the length of output hex str
 */
size_t to_hex_str(const uint8_t *buffer, size_t buffer_len, char **hex_str);

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
 * @brief Compare two char string that can be NULL.
 *
 * @param str_1
 * @param str_2
 * @return true
 * @return false
 */
bool safe_strcmp(const char *str_1, const char *str_2);

/**
 * @brief Compare two user's ids.
 *
 * @param address
 * @param user_id
 * @param domain
 * @return true
 * @return false
 */
bool compare_user_id(Skissm__E2eeAddress *address, const char *user_id, const char *domain);

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
 * @brief Compaare two Skissm__GroupMember arrays.
 *
 * @param group_members_1
 * @param group_member_num_1
 * @param group_members_2
 * @param group_member_num_2
 * @return true
 * @return false
 */
bool compare_group_member(
    Skissm__GroupMember **group_members_1,
    size_t group_member_num_1,
    Skissm__GroupMember **group_members_2,
    size_t group_member_num_2
);

/**
 * @brief Initialize the ProtobufCBinaryData.
 *
 * @param dest
 */
void init_protobuf(ProtobufCBinaryData *dest);

/**
 * @brief Malloc the ProtobufCBinaryData with given len.
 *
 * @param dest
 * @param len
 */
void malloc_protobuf(ProtobufCBinaryData *dest, size_t len);

uint8_t *get_identity_public_key_ds_uint8_from_account(Skissm__Account *src);

ProtobufCBinaryData *get_identity_public_key_ds_bytes_from_account(Skissm__Account *src);

/**
 * @brief Copy ProtobufCBinaryData from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_protobuf_from_protobuf(ProtobufCBinaryData *dest, const ProtobufCBinaryData *src);

/**
 * @brief Copy ProtobufCBinaryData from bool.
 *
 * @param dest
 * @param src
 */
void copy_protobuf_from_bool(ProtobufCBinaryData *dest, bool src);

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
 * @brief Copy ProtobufCBinaryData list from src to dest.
 *
 * @param dest
 * @param src
 * @param protobuf_num
 */
void copy_protobuf_list_from_protobuf_list(
    ProtobufCBinaryData *dest, const ProtobufCBinaryData *src, size_t protobuf_num
);

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
void copy_key_pair_from_key_pair(Skissm__KeyPair **dest, Skissm__KeyPair *src);

/**
 * @brief Copy Skissm__IdentityKey from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_ik_from_ik(Skissm__IdentityKey **dest, Skissm__IdentityKey *src);

/**
 * @brief Copy Skissm__SignedPreKey from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_spk_from_spk(Skissm__SignedPreKey **dest, Skissm__SignedPreKey *src);

/**
 * @brief Copy Skissm__OneTimePreKey from src to dest.
 *
 * @param dest
 * @param src
 * @param opk_num
 */
void copy_opks_from_opks(Skissm__OneTimePreKey ***dest, Skissm__OneTimePreKey **src, size_t opk_num);

/**
 * @brief Copy Skissm__Subject from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_subject_from_subject(Skissm__Subject **dest, Skissm__Subject *src);

/**
 * @brief Copy Skissm__Cert from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_cert_from_cert(Skissm__Cert **dest, Skissm__Cert *src);

/**
 * @brief Copy Skissm__Certificate from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_certificate_from_certificate(Skissm__Certificate **dest, Skissm__Certificate *src);

/**
 * @brief Copy Skissm__Account from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_account_from_account(Skissm__Account **dest, Skissm__Account *src);

/**
 * @brief Copy Skissm__ChainKey from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_chain_key_from_chain_key(Skissm__ChainKey **dest, Skissm__ChainKey *src);

/**
 * @brief Copy Skissm__MsgKey from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_msg_key_from_msg_key(Skissm__MsgKey **dest, Skissm__MsgKey *src);

/**
 * @brief Copy Skissm__SenderChainNode from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_sender_chain_from_sender_chain(Skissm__SenderChainNode **dest, Skissm__SenderChainNode *src);

/**
 * @brief Copy Skissm__ReceiverChainNode from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_receiver_chain_from_receiver_chain(Skissm__ReceiverChainNode **dest, Skissm__ReceiverChainNode *src);

/**
 * @brief Copy Skissm__SkippedMsgKeyNode from src to dest.
 *
 * @param dest
 * @param src
 * @param skipped_msg_keys_num
 */
void copy_skipped_msg_keys_from_skipped_msg_keys(
    Skissm__SkippedMsgKeyNode ***dest,
    Skissm__SkippedMsgKeyNode **src,
    size_t skipped_msg_keys_num
);

/**
 * @brief Copy Skissm__Ratchet from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_ratchet_from_ratchet(Skissm__Ratchet **dest, Skissm__Ratchet *src);

/**
 * @brief Copy Skissm__Session from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_session_from_session(Skissm__Session **dest, Skissm__Session *src);

/**
 * @brief Copy Skissm__IdentityKeyPublic from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_ik_public_from_ik_public(Skissm__IdentityKeyPublic **dest, Skissm__IdentityKeyPublic *src);

/**
 * @brief Copy Skissm__SignedPreKeyPublic from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_spk_public_from_spk_public(Skissm__SignedPreKeyPublic **dest, Skissm__SignedPreKeyPublic *src);

/**
 * @brief Copy Skissm__OneTimePreKeyPublic from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_opk_public_from_opk_public(Skissm__OneTimePreKeyPublic **dest, Skissm__OneTimePreKeyPublic *src);

/**
 * @brief Copy Skissm__GroupMemberInfo from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_group_member_id(Skissm__GroupMemberInfo **dest, Skissm__GroupMemberInfo *src);

/**
 * @brief Copy Skissm__GroupMemberInfo array from src to dest.
 *
 * @param dest
 * @param src
 * @param to_member_addresses_total_num
 */
void copy_group_member_ids(Skissm__GroupMemberInfo ***dest, Skissm__GroupMemberInfo **src, size_t to_member_addresses_total_num);

/**
 * @brief Copy Skissm__GroupMember from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_group_member(Skissm__GroupMember **dest, Skissm__GroupMember *src);

/**
 * @brief Copy Skissm__GroupMember array from src to dest.
 *
 * @param dest
 * @param src
 * @param group_members_num
 */
void copy_group_members(Skissm__GroupMember ***dest, Skissm__GroupMember **src, size_t group_members_num);

/**
 * @brief Copy Skissm__GroupInfo from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_group_info(Skissm__GroupInfo **dest, Skissm__GroupInfo *src);

/**
 * @brief Copy Skissm__CreateGroupMsg from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_create_group_msg(Skissm__CreateGroupMsg **dest, Skissm__CreateGroupMsg *src);

/**
 * @brief Copy Skissm__AddGroupMembersMsg from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_add_group_members_msg(Skissm__AddGroupMembersMsg **dest, Skissm__AddGroupMembersMsg *src);

/**
 * @brief Copy Skissm__AddGroupMemberDeviceMsg from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_add_group_member_device_msg(Skissm__AddGroupMemberDeviceMsg **dest, Skissm__AddGroupMemberDeviceMsg *src);

/**
 * @brief Copy Skissm__RemoveGroupMembersMsg from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_remove_group_members_msg(Skissm__RemoveGroupMembersMsg **dest, Skissm__RemoveGroupMembersMsg *src);

/**
 * @brief Copy Skissm__LeaveGroupMsg from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_leave_group_msg(Skissm__LeaveGroupMsg **dest, Skissm__LeaveGroupMsg *src);

/**
 * @brief Add new Skissm__GroupMember array to dest.
 *
 * @param dest
 * @param old_group_info
 * @param adding_members
 * @param adding_members_num
 */
void add_group_members_to_group_info(
    Skissm__GroupInfo **dest,
    Skissm__GroupInfo *old_group_info,
    Skissm__GroupMember **adding_members,
    size_t adding_members_num
);

/**
 * @brief Remove some Skissm__GroupMember from old_group_info.
 *
 * @param dest
 * @param old_group_info
 * @param removing_members
 * @param removing_members_num
 */
void remove_group_members_from_group_info(
    Skissm__GroupInfo **dest,
    Skissm__GroupInfo *old_group_info,
    Skissm__GroupMember **removing_members,
    size_t removing_members_num
);

/**
 * @brief Copy member info to group member.
 * @param member_info
 * @return
 */
Skissm__GroupMember *member_info_to_group_member(Skissm__GroupMemberInfo *member_info);

/**
 *  * @brief Collect unique user ID from member_info_list then convert and collect it into member_list
 * @param dest
 * @param member_info_list
 * @param member_info_list_num
 * @param member_list
 * @param member_list_num
 * @return
 */
size_t member_info_to_group_members(
    Skissm__GroupMember ***dest,
    Skissm__GroupMemberInfo **member_info_list,
    size_t member_info_list_num,
    Skissm__GroupMember **member_list,
    size_t member_list_num
);

/**
 * @brief Release memory of Skissm__E2eeAddress array.
 *
 * @param dest
 * @param e2ee_addresses_num
 */
void free_e2ee_addresses(Skissm__E2eeAddress ***dest, size_t e2ee_addresses_num);

/**
 * @brief Release memory of Skissm__InviteResponse array.
 *
 * @param dest
 * @param invite_response_num
 */
void free_invite_response_list(Skissm__InviteResponse ***dest, size_t invite_response_num);

/**
 * @brief Release memory of Skissm__GroupMember array.
 *
 * @param dest
 * @param group_members_num
 */
void free_group_members(Skissm__GroupMember ***dest, size_t group_members_num);

/**
 * @brief Release memory of ProtobufCBinaryData.
 *
 * @param output
 */
void free_protobuf(ProtobufCBinaryData *output);

/**
 * @brief Release memory of ProtobufCBinaryData list.
 *
 * @param output
 * @param protobuf_num
 */
void free_protobuf_list(ProtobufCBinaryData **output, size_t protobuf_num);

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
