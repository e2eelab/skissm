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
#include "skissm/mem_util.h"

#include <string.h>

#include "skissm/crypto.h"

bool is_equal(const uint8_t *buffer_a, const uint8_t *buffer_b, size_t len) {
    uint8_t volatile result = 0;
    while (len--) {
        result |= (*(buffer_a++)) ^ (*(buffer_b++));
    }

    return result == 0;
}

char *generate_uuid_str() {
    uint8_t uuid[UUID_LEN];
    get_skissm_plugin()->common_handler.gen_uuid(uuid);
    // to base64
    return crypto_base64_encode(uuid, UUID_LEN);
}

size_t to_hex_str(const uint8_t *buffer, size_t buffer_len, char **hex_str) {
    size_t hex_str_len = buffer_len * 2 + 1;
    *hex_str = (char *)malloc(hex_str_len * sizeof(char));
    char *p = &(*hex_str[0]);
    int i, n;
    size_t output_len = 0;
    for (i = 0; (i < buffer_len) && (output_len <= hex_str_len); i++) {
        n = sprintf(p, "%02X", buffer[i]);
        p += n;
        output_len += n;
    }
    *p = '\0';

    return hex_str_len;
}

///-----------------compare-----------------///

bool compare_protobuf(ProtobufCBinaryData *src_1, ProtobufCBinaryData *src_2) {
    if (src_1 == NULL && src_2 == NULL)
        return true;
    if (src_1 != NULL && src_2 != NULL) {
        if (src_1->len == src_2->len) {
            if (memcmp(src_1->data, src_2->data, src_1->len) == 0) {
                return true;
            }
        }
    }
    return false;
}

bool safe_strcmp(const char *str_1, const char *str_2) {
    if (str_1 == NULL && str_2 == NULL)
        return true;
    if (str_1 != NULL && str_2 != NULL) {
        return strcmp(str_1, str_2) == 0;
    }
    return false;
}

bool compare_user_id(Skissm__E2eeAddress *address, const char *user_id, const char *domain) {
    if (address == NULL && user_id == NULL && domain == NULL)
        return true;
    if ((user_id == NULL && domain != NULL) || (user_id != NULL && domain == NULL))
        return false;
    if ((address == NULL && user_id != NULL) || (address != NULL && user_id == NULL))
        return false;

    return safe_strcmp(address->domain, domain) && (address->peer_case == SKISSM__E2EE_ADDRESS__PEER_USER) && (safe_strcmp(address->user->user_id, user_id));
}

bool compare_address(Skissm__E2eeAddress *address_1, Skissm__E2eeAddress *address_2) {
    if (address_1 == NULL && address_2 == NULL)
        return true;
    if ((address_1 == NULL && address_2 != NULL) || (address_1 != NULL && address_2 == NULL))
        return false;

    return safe_strcmp(address_1->domain, address_2->domain) && (address_1->peer_case == address_2->peer_case) &&
           (((address_1->peer_case == SKISSM__E2EE_ADDRESS__PEER_USER) &&
             (safe_strcmp(address_1->user->user_id, address_2->user->user_id) && safe_strcmp(address_1->user->device_id, address_2->user->device_id))) ||
            ((address_1->peer_case == SKISSM__E2EE_ADDRESS__PEER_GROUP) && (safe_strcmp(address_1->group->group_id, address_2->group->group_id))));
}

bool compare_group_member(Skissm__GroupMember **group_members_1, size_t group_member_num_1, Skissm__GroupMember **group_members_2, size_t group_member_num_2) {
    if (group_members_1 == NULL && group_members_2 == NULL)
        return true;
    if ((group_members_1 == NULL && group_members_2 != NULL) || (group_members_1 != NULL && group_members_2 == NULL))
        return false;
    if (group_member_num_1 != group_member_num_2)
        return false;

    size_t i;
    for (i = 0; i < group_member_num_1; i++) {
        if ((group_members_1[i]->role != group_members_2[i]->role) || !safe_strcmp(group_members_1[i]->user_id, group_members_2[i]->user_id) ||
            !safe_strcmp(group_members_1[i]->domain, group_members_2[i]->domain))
            return false;
    }
    return true;
}

///-----------------copy protobuf-----------------///

void copy_protobuf_from_protobuf(ProtobufCBinaryData *dest, const ProtobufCBinaryData *src) {
    dest->len = src->len;
    dest->data = (uint8_t *)malloc(sizeof(uint8_t) * src->len);
    memcpy(dest->data, src->data, src->len);
}

void copy_protobuf_from_array(ProtobufCBinaryData *dest, const uint8_t *src, size_t len) {
    dest->len = len;
    dest->data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    memcpy(dest->data, src, len);
}

void overwrite_protobuf_from_array(ProtobufCBinaryData *dest, const uint8_t *src) { memcpy(dest->data, src, dest->len); }

///-----------------copy address-----------------///

void copy_address_from_address(Skissm__E2eeAddress **dest, const Skissm__E2eeAddress *src) {
    *dest = (Skissm__E2eeAddress *)malloc(sizeof(Skissm__E2eeAddress));
    skissm__e2ee_address__init(*dest);
    if (src != NULL) {
        if (src->domain != NULL)
            (*dest)->domain = strdup(src->domain);
        if (src->peer_case == SKISSM__E2EE_ADDRESS__PEER_USER) {
            (*dest)->user = (Skissm__PeerUser *)malloc(sizeof(Skissm__PeerUser));
            skissm__peer_user__init((*dest)->user);
            (*dest)->peer_case = SKISSM__E2EE_ADDRESS__PEER_USER;
            if (src->user->user_id != NULL)
                (*dest)->user->user_id = strdup(src->user->user_id);
            if (src->user->device_id != NULL)
                (*dest)->user->device_id = strdup(src->user->device_id);
        } else if (src->peer_case == SKISSM__E2EE_ADDRESS__PEER_GROUP) {
            (*dest)->group = (Skissm__PeerGroup *)malloc(sizeof(Skissm__PeerGroup));
            skissm__peer_group__init((*dest)->group);
            (*dest)->peer_case = SKISSM__E2EE_ADDRESS__PEER_GROUP;
            if (src->group->group_id != NULL)
                (*dest)->group->group_id = strdup(src->group->group_id);
        }
    }
}

///-----------------copy key pair, ik, spk, opk-----------------///

void copy_key_pair_from_key_pair(Skissm__KeyPair **dest, Skissm__KeyPair *src) {
    *dest = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(*dest);
    copy_protobuf_from_protobuf(&((*dest)->private_key), &(src->private_key));
    copy_protobuf_from_protobuf(&((*dest)->public_key), &(src->public_key));
}

void copy_ik_from_ik(Skissm__IdentityKey **dest, Skissm__IdentityKey *src) {
    *dest = (Skissm__IdentityKey *)malloc(sizeof(Skissm__IdentityKey));
    skissm__identity_key__init(*dest);
    copy_key_pair_from_key_pair(&((*dest)->asym_key_pair), src->asym_key_pair);
    copy_key_pair_from_key_pair(&((*dest)->sign_key_pair), src->sign_key_pair);
}

void copy_spk_from_spk(Skissm__SignedPreKey **dest, Skissm__SignedPreKey *src) {
    *dest = (Skissm__SignedPreKey *)malloc(sizeof(Skissm__SignedPreKey));
    skissm__signed_pre_key__init(*dest);
    (*dest)->spk_id = src->spk_id;
    copy_key_pair_from_key_pair(&((*dest)->key_pair), src->key_pair);
    copy_protobuf_from_protobuf(&((*dest)->signature), &(src->signature));
    (*dest)->ttl = src->ttl;
}

void copy_opks_from_opks(Skissm__OneTimePreKey ***dest, Skissm__OneTimePreKey **src, size_t opk_num) {
    *dest = (Skissm__OneTimePreKey **)malloc(sizeof(Skissm__OneTimePreKey *) * opk_num);
    size_t i;
    for (i = 0; i < opk_num; i++) {
        (*dest)[i] = (Skissm__OneTimePreKey *)malloc(sizeof(Skissm__OneTimePreKey));
        skissm__one_time_pre_key__init((*dest)[i]);
        (*dest)[i]->opk_id = src[i]->opk_id;
        (*dest)[i]->used = src[i]->used;
        copy_key_pair_from_key_pair(&((*dest)[i]->key_pair), src[i]->key_pair);
    }
}

///-----------------copy account-----------------///

void copy_account_from_account(Skissm__Account **dest, Skissm__Account *src) {
    *dest = (Skissm__Account *)malloc(sizeof(Skissm__Account));
    skissm__account__init(*dest);
    (*dest)->version = strdup(src->version);
    (*dest)->account_id = src->account_id;
    (*dest)->saved = src->saved;
    if (src->address) {
        copy_address_from_address(&((*dest)->address), src->address);
    }
    (*dest)->password = strdup(src->password);
    (*dest)->e2ee_pack_id = strdup(src->e2ee_pack_id);
    if (src->identity_key) {
        copy_ik_from_ik(&((*dest)->identity_key), src->identity_key);
    }
    if (src->signed_pre_key) {
        copy_spk_from_spk(&((*dest)->signed_pre_key), src->signed_pre_key);
    }
    if (src->one_time_pre_keys) {
        copy_opks_from_opks(&((*dest)->one_time_pre_keys), src->one_time_pre_keys, src->n_one_time_pre_keys);
    }
    (*dest)->n_one_time_pre_keys = src->n_one_time_pre_keys;
    (*dest)->next_one_time_pre_key_id = src->next_one_time_pre_key_id;
}

///-----------------copy chain key, message key, ratchet, session-----------------///

void copy_chain_key_from_chain_key(Skissm__ChainKey **dest, Skissm__ChainKey *src) {
    *dest = (Skissm__ChainKey *)malloc(sizeof(Skissm__ChainKey));
    skissm__chain_key__init(*dest);
    (*dest)->index = src->index;
    copy_protobuf_from_protobuf(&((*dest)->shared_key), &(src->shared_key));
}

void copy_msg_key_from_msg_key(Skissm__MsgKey **dest, Skissm__MsgKey *src) {
    *dest = (Skissm__MsgKey *)malloc(sizeof(Skissm__MsgKey));
    skissm__msg_key__init(*dest);
    (*dest)->index = src->index;
    copy_protobuf_from_protobuf(&((*dest)->derived_key), &(src->derived_key));
}

void copy_sender_chain_from_sender_chain(Skissm__SenderChainNode **dest, Skissm__SenderChainNode *src) {
    *dest = (Skissm__SenderChainNode *)malloc(sizeof(Skissm__SenderChainNode));
    skissm__sender_chain_node__init(*dest);
    copy_protobuf_from_protobuf(&((*dest)->ratchet_key), &(src->ratchet_key));
    copy_chain_key_from_chain_key(&((*dest)->chain_key), src->chain_key);
}

void copy_receiver_chains_from_receiver_chains(Skissm__ReceiverChainNode ***dest, Skissm__ReceiverChainNode **src, size_t receiver_chains_num) {
    *dest = (Skissm__ReceiverChainNode **)malloc(sizeof(Skissm__ReceiverChainNode *) * receiver_chains_num);
    size_t i;
    for (i = 0; i < receiver_chains_num; i++) {
        (*dest)[i] = (Skissm__ReceiverChainNode *)malloc(sizeof(Skissm__ReceiverChainNode));
        skissm__receiver_chain_node__init((*dest)[i]);
        copy_protobuf_from_protobuf(&((*dest)[i]->ratchet_key_public), &(src[i]->ratchet_key_public));
        copy_chain_key_from_chain_key(&((*dest)[i]->chain_key), src[i]->chain_key);
    }
}

void copy_skipped_msg_keys_from_skipped_msg_keys(Skissm__SkippedMsgKeyNode ***dest, Skissm__SkippedMsgKeyNode **src, size_t skipped_msg_keys_num) {
    *dest = (Skissm__SkippedMsgKeyNode **)malloc(sizeof(Skissm__SkippedMsgKeyNode *) * skipped_msg_keys_num);
    size_t i;
    for (i = 0; i < skipped_msg_keys_num; i++) {
        (*dest)[i] = (Skissm__SkippedMsgKeyNode *)malloc(sizeof(Skissm__SkippedMsgKeyNode));
        skissm__skipped_msg_key_node__init((*dest)[i]);
        copy_protobuf_from_protobuf(&((*dest)[i]->ratchet_key_public), &(src[i]->ratchet_key_public));
        copy_msg_key_from_msg_key(&((*dest)[i]->msg_key), src[i]->msg_key);
    }
}

void copy_ratchet_from_ratchet(Skissm__Ratchet **dest, Skissm__Ratchet *src) {
    *dest = (Skissm__Ratchet *)malloc(sizeof(Skissm__Ratchet));
    skissm__ratchet__init(*dest);
    copy_protobuf_from_protobuf(&((*dest)->root_key), &(src->root_key));
    copy_sender_chain_from_sender_chain(&((*dest)->sender_chain), src->sender_chain);
    (*dest)->n_receiver_chains = src->n_receiver_chains;
    copy_receiver_chains_from_receiver_chains(&((*dest)->receiver_chains), src->receiver_chains, src->n_receiver_chains);
    (*dest)->n_skipped_msg_keys = src->n_skipped_msg_keys;
    copy_skipped_msg_keys_from_skipped_msg_keys(&((*dest)->skipped_msg_keys), src->skipped_msg_keys, src->n_skipped_msg_keys);
}

void copy_session_from_session(Skissm__Session **dest, Skissm__Session *src) {
    *dest = (Skissm__Session *)malloc(sizeof(Skissm__Session));
    skissm__session__init(*dest);
    (*dest)->version = strdup(src->version);
    (*dest)->e2ee_pack_id = strdup(src->e2ee_pack_id);
    (*dest)->session_id = strdup(src->session_id);
    copy_address_from_address(&((*dest)->session_owner), src->session_owner);
    copy_address_from_address(&((*dest)->from), src->from);
    copy_address_from_address(&((*dest)->to), src->to);
    copy_ratchet_from_ratchet(&((*dest)->ratchet), src->ratchet);
    copy_protobuf_from_protobuf(&((*dest)->alice_identity_key), &(src->alice_identity_key));
    copy_protobuf_from_protobuf(&((*dest)->alice_ephemeral_key), &(src->alice_ephemeral_key));
    copy_protobuf_from_protobuf(&((*dest)->bob_signed_pre_key), &(src->bob_signed_pre_key));
    (*dest)->bob_signed_pre_key_id = src->bob_signed_pre_key_id;
    copy_protobuf_from_protobuf(&((*dest)->bob_one_time_pre_key), &(src->bob_one_time_pre_key));
    (*dest)->bob_one_time_pre_key_id = src->bob_one_time_pre_key_id;
    (*dest)->f2f = src->f2f;
    (*dest)->responded = src->responded;
    copy_protobuf_from_protobuf(&((*dest)->associated_data), &(src->associated_data));
}

///-----------------copy public key-----------------///

void copy_ik_public_from_ik_public(Skissm__IdentityKeyPublic **dest, Skissm__IdentityKeyPublic *src) {
    *dest = (Skissm__IdentityKeyPublic *)malloc(sizeof(Skissm__IdentityKeyPublic));
    skissm__identity_key_public__init(*dest);
    copy_protobuf_from_protobuf(&((*dest)->asym_public_key), &(src->asym_public_key));
    copy_protobuf_from_protobuf(&((*dest)->sign_public_key), &(src->sign_public_key));
}

void copy_spk_public_from_spk_public(Skissm__SignedPreKeyPublic **dest, Skissm__SignedPreKeyPublic *src) {
    *dest = (Skissm__SignedPreKeyPublic *)malloc(sizeof(Skissm__SignedPreKeyPublic));
    skissm__signed_pre_key_public__init(*dest);
    (*dest)->spk_id = src->spk_id;
    copy_protobuf_from_protobuf(&((*dest)->public_key), &(src->public_key));
    copy_protobuf_from_protobuf(&((*dest)->signature), &(src->signature));
}

void copy_opk_public_from_opk_public(Skissm__OneTimePreKeyPublic **dest, Skissm__OneTimePreKeyPublic *src) {
    *dest = (Skissm__OneTimePreKeyPublic *)malloc(sizeof(Skissm__OneTimePreKeyPublic));
    skissm__one_time_pre_key_public__init(*dest);
    (*dest)->opk_id = src->opk_id;
    copy_protobuf_from_protobuf(&((*dest)->public_key), &(src->public_key));
}

///-----------------copy group member id-----------------///

void copy_group_member_id(Skissm__GroupMemberID **dest, Skissm__GroupMemberID *src) {
    *dest = (Skissm__GroupMemberID *)malloc(sizeof(Skissm__GroupMemberID));
    skissm__group_member_id__init(*dest);

    copy_address_from_address(&((*dest)->group_member_address), src->group_member_address);
    copy_protobuf_from_protobuf(&((*dest)->public_key), &(src->public_key));
}

void copy_group_member_ids(Skissm__GroupMemberID ***dest, Skissm__GroupMemberID **src, size_t to_member_addresses_total_num) {
    *dest = (Skissm__GroupMemberID **)malloc(sizeof(Skissm__GroupMemberID *) * to_member_addresses_total_num);
    size_t i;
    for (i = 0; i < to_member_addresses_total_num; i++) {
        copy_group_member_id(&((*dest)[i]), src[i]);
    }
}

///-----------------group member, group info-----------------///

void copy_group_member(Skissm__GroupMember **dest, Skissm__GroupMember *src) {
    *dest = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(*dest);
    if (src != NULL) {
        if (src->user_id != NULL)
            (*dest)->user_id = strdup(src->user_id);
        if (src->domain != NULL)
            (*dest)->domain = strdup(src->domain);
        (*dest)->role = src->role;
    }
}

void copy_group_members(Skissm__GroupMember ***dest, Skissm__GroupMember **src, size_t group_members_num) {
    *dest = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * group_members_num);
    size_t i;
    for (i = 0; i < group_members_num; i++) {
        copy_group_member(&((*dest)[i]), src[i]);
    }
}

void copy_group_info(Skissm__GroupInfo **dest, Skissm__GroupInfo *src) {
    *dest = (Skissm__GroupInfo *)malloc(sizeof(Skissm__GroupInfo));
    skissm__group_info__init(*dest);
    if (src != NULL) {
        if (src->group_name != NULL)
            (*dest)->group_name = strdup(src->group_name);
        if (src->group_address != NULL)
            copy_address_from_address(&((*dest)->group_address), src->group_address);
        (*dest)->n_group_members = src->n_group_members;
        if (src->group_members != NULL)
            copy_group_members(&((*dest)->group_members), src->group_members, src->n_group_members);
    }
}
/*struct  _Skissm__RemoveGroupMembersMsg
{
  ProtobufCMessage base;
  char *e2ee_pack_id;
  Skissm__E2eeAddress *sender_address;
  Skissm__GroupInfo *group_info;
  size_t n_member_ids;
  Skissm__GroupMemberID **member_ids;
  size_t n_removing_members;
  Skissm__GroupMember **removing_members;
};*/

/*struct  _Skissm__CreateGroupMsg
{
  ProtobufCMessage base;
  char *e2ee_pack_id;
  Skissm__E2eeAddress *sender_address;
  Skissm__GroupInfo *group_info;
  size_t n_member_ids;
  Skissm__GroupMemberID **member_ids;
};*/

/*struct  _Skissm__AddGroupMembersMsg
{
  ProtobufCMessage base;
  char *e2ee_pack_id;
  Skissm__E2eeAddress *sender_address;
  Skissm__GroupInfo *group_info;
  size_t n_adding_member_ids;
  Skissm__GroupMemberID **adding_member_ids;
  size_t n_adding_members;
  Skissm__GroupMember **adding_members;
};*/
///---------------------copy  msg---------------------///

void copy_create_msg(Skissm__CreateGroupMsg **dest, Skissm__CreateGroupMsg *src) {
    *dest = (Skissm__CreateGroupMsg *)malloc(sizeof(Skissm__CreateGroupMsg));
    skissm__create_group_msg__init(*dest);
    if (src != NULL) {
        if (src->e2ee_pack_id != NULL)
            (*dest)->e2ee_pack_id = strdup(src->e2ee_pack_id);
        if (src->sender_address != NULL)
            copy_address_from_address(&((*dest)->sender_address), src->sender_address);
        if (src->group_info != NULL)
            copy_group_info(&((*dest)->group_info), src->group_info);
        (*dest)->n_member_ids = src->n_member_ids;
        if (src->member_ids != NULL)
            copy_group_member_ids(&((*dest)->member_ids), src->member_ids, src->n_member_ids);
    }
}
void copy_remove_msg(Skissm__RemoveGroupMembersMsg **dest, Skissm__RemoveGroupMembersMsg *src) {
    *dest = (Skissm__RemoveGroupMembersMsg *)malloc(sizeof(Skissm__RemoveGroupMembersMsg));
    skissm__remove_group_members_msg__init(*dest);
    if (src != NULL) {
        if (src->e2ee_pack_id != NULL)
            (*dest)->e2ee_pack_id = strdup(src->e2ee_pack_id);
        if (src->sender_address != NULL)
            copy_address_from_address(&((*dest)->sender_address), src->sender_address);
        if (src->group_info != NULL)
            copy_group_info(&((*dest)->group_info), src->group_info);
        (*dest)->n_member_ids = src->n_member_ids;
        if (src->member_ids != NULL)
            copy_group_member_ids(&((*dest)->member_ids), src->member_ids, src->n_member_ids);
        (*dest)->n_removing_members = src->n_removing_members;
        if (src->removing_members != NULL)
            copy_group_members(&((*dest)->removing_members), src->removing_members, src->n_removing_members);
    }
}

void copy_add_msg(Skissm__AddGroupMembersMsg **dest, Skissm__AddGroupMembersMsg *src) {
    *dest = (Skissm__AddGroupMembersMsg *)malloc(sizeof(Skissm__AddGroupMembersMsg));
    skissm__add_group_members_msg__init(*dest);
    if (src != NULL) {
        if (src->e2ee_pack_id != NULL)
            (*dest)->e2ee_pack_id = strdup(src->e2ee_pack_id);
        if (src->sender_address != NULL)
            copy_address_from_address(&((*dest)->sender_address), src->sender_address);
        if (src->group_info != NULL)
            copy_group_info(&((*dest)->group_info), src->group_info);
        (*dest)->n_adding_member_ids = src->n_adding_member_ids;
        if (src->adding_member_ids != NULL)
            copy_group_member_ids(&((*dest)->adding_member_ids), src->adding_member_ids, src->n_adding_member_ids);
        (*dest)->n_adding_members = src->n_adding_members;
        if (src->adding_members != NULL)
            copy_group_members(&((*dest)->adding_members), src->adding_members, src->n_adding_members);
    }
}
///-----------------add or remove group members-----------------///

void add_group_members_to_group_info(Skissm__GroupInfo **dest, Skissm__GroupInfo *old_group_info, Skissm__GroupMember **adding_members, size_t adding_members_num) {
    size_t old_group_members_num = old_group_info->n_group_members;
    size_t new_group_members_num = old_group_members_num + adding_members_num;
    *dest = (Skissm__GroupInfo *)malloc(sizeof(Skissm__GroupInfo));
    skissm__group_info__init(*dest);
    if (old_group_info->group_name != NULL)
        (*dest)->group_name = strdup(old_group_info->group_name);
    if (old_group_info->group_address != NULL)
        copy_address_from_address(&((*dest)->group_address), old_group_info->group_address);
    (*dest)->n_group_members = new_group_members_num;
    (*dest)->group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * new_group_members_num);
    size_t i;
    for (i = 0; i < old_group_members_num; i++) {
        copy_group_member(&(((*dest)->group_members)[i]), (old_group_info->group_members)[i]);
    }
    for (i = old_group_members_num; i < new_group_members_num; i++) {
        copy_group_member(&(((*dest)->group_members)[i]), adding_members[i - old_group_members_num]);
    }
}

void remove_group_members_from_group_info(Skissm__GroupInfo **dest, Skissm__GroupInfo *old_group_info, Skissm__GroupMember **removing_members, size_t removing_members_num) {
    size_t old_group_members_num = old_group_info->n_group_members;
    size_t new_group_members_num = old_group_members_num - removing_members_num;
    *dest = (Skissm__GroupInfo *)malloc(sizeof(Skissm__GroupInfo));
    skissm__group_info__init(*dest);
    if (old_group_info->group_name != NULL)
        (*dest)->group_name = strdup(old_group_info->group_name);
    if (old_group_info->group_address != NULL)
        copy_address_from_address(&((*dest)->group_address), old_group_info->group_address);
    (*dest)->n_group_members = new_group_members_num;
    (*dest)->group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * new_group_members_num);
    size_t i, cur_pos = 0;
    for (i = 0; i < old_group_members_num; i++) {
        if ((cur_pos == removing_members_num) || ((old_group_info->group_members)[i]->role != removing_members[cur_pos]->role) ||
            !safe_strcmp((old_group_info->group_members)[i]->user_id, removing_members[cur_pos]->user_id) ||
            !safe_strcmp((old_group_info->group_members)[i]->domain, removing_members[cur_pos]->domain)) {
            copy_group_member(&(((*dest)->group_members)[i - cur_pos]), (old_group_info->group_members)[i]);
        } else {
            cur_pos++;
        }
    }
}

///-----------------release-----------------///

void free_group_members(Skissm__GroupMember ***dest, size_t group_members_num) {
    size_t i;
    for (i = 0; i < group_members_num; i++) {
        skissm__group_member__free_unpacked((*dest)[i], NULL);
        (*dest)[i] = NULL;
    }
    free(*dest);
    *dest = NULL;
}

void free_protobuf(ProtobufCBinaryData *output) {
    if (output->data) {
        unset(output->data, output->len);
        free(output->data);
    }
    output->len = 0;
    output->data = NULL;
}

void free_mem(void **buffer, size_t buffer_len) {
    unset(*buffer, buffer_len);
    free(*buffer);
    *buffer = NULL;
}

void unset(void volatile *buffer, size_t buffer_len) {
    char volatile *pos = (char volatile *)(buffer);
    char volatile *end = pos + buffer_len;
    while (pos != end) {
        *(pos++) = 0;
    }
}
