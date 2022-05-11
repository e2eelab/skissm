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

bool is_equal(const uint8_t *buffer_a, const uint8_t *buffer_b, size_t length) {
    uint8_t volatile result = 0;
    while (length--) {
        result |= (*(buffer_a++)) ^ (*(buffer_b++));
    }

    return result == 0;
}

char *generate_uuid_str() {
    uint8_t uuid[UUID_LEN];
    get_skissm_plugin()->common_handler.handle_gen_uuid(uuid);
    // to base64
    return crypto_base64_encode(uuid, UUID_LEN);
}

bool compare_protobuf(ProtobufCBinaryData *src_1, ProtobufCBinaryData *src_2) {
    if (src_1->len == src_2->len) {
        if (memcmp(src_1->data, src_2->data, src_1->len) == 0) {
            return true;
        }
    }
    return false;
}

bool safe_strcmp(const char *str1, const char *str2) {
    if (str1 == NULL && str2 == NULL)
        return true;
    if (str1 != NULL && str2 != NULL) {
        return strcmp(str1, str2) == 0;
    }
    return false;
}

bool compare_address(Skissm__E2eeAddress *address_1, Skissm__E2eeAddress *address_2) {
    if (address_1 == NULL && address_2 == NULL)
        return true;
    if ((address_1 == NULL && address_2 != NULL)
        || (address_1 != NULL && address_2 == NULL))
        return false;

    return safe_strcmp(address_1->domain, address_2->domain)
        && (address_1->peer_case == address_2->peer_case)
        && (((address_1->peer_case == SKISSM__E2EE_ADDRESS__PEER_USER)
                && (safe_strcmp(address_1->user->user_id, address_2->user->user_id) && safe_strcmp(address_1->user->device_id, address_2->user->device_id)))
            || ((address_1->peer_case == SKISSM__E2EE_ADDRESS__PEER_GROUP)
                && (safe_strcmp(address_1->group->group_id, address_2->group->group_id))));
}

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

void copy_account_from_account(Skissm__Account **dest, Skissm__Account *src) {
    *dest = (Skissm__Account *)malloc(sizeof(Skissm__Account));
    skissm__account__init(*dest);
    (*dest)->version = src->version;
    (*dest)->account_id = src->account_id;
    (*dest)->saved = src->saved;
    if (src->address) {
        copy_address_from_address(&((*dest)->address), src->address);
    }
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

void copy_ik_public_from_ik_public(Skissm__IdentityKeyPublic **dest, Skissm__IdentityKeyPublic *src){
    *dest = (Skissm__IdentityKeyPublic *)malloc(sizeof(Skissm__IdentityKeyPublic));
    skissm__identity_key_public__init(*dest);
    copy_protobuf_from_protobuf(&((*dest)->asym_public_key), &(src->asym_public_key));
    copy_protobuf_from_protobuf(&((*dest)->sign_public_key), &(src->sign_public_key));
}

void copy_spk_public_from_spk_public(Skissm__SignedPreKeyPublic **dest, Skissm__SignedPreKeyPublic *src){
    *dest = (Skissm__SignedPreKeyPublic *)malloc(sizeof(Skissm__SignedPreKeyPublic));
    skissm__signed_pre_key_public__init(*dest);
    (*dest)->spk_id = src->spk_id;
    copy_protobuf_from_protobuf(&((*dest)->public_key), &(src->public_key));
    copy_protobuf_from_protobuf(&((*dest)->signature), &(src->signature));
}

void copy_opk_public_from_opk_public(Skissm__OneTimePreKeyPublic **dest, Skissm__OneTimePreKeyPublic *src){
    *dest = (Skissm__OneTimePreKeyPublic *)malloc(sizeof(Skissm__OneTimePreKeyPublic));
    skissm__one_time_pre_key_public__init(*dest);
    (*dest)->opk_id = src->opk_id;
    copy_protobuf_from_protobuf(&((*dest)->public_key), &(src->public_key));
}

void copy_group_member(Skissm__GroupMember **dest, Skissm__GroupMember *src) {
    *dest = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(*dest);
    if (src != NULL) {
        if (src->user_id != NULL)
            (*dest)->user_id = strdup(src->user_id);
        (*dest)->role =  src->role;
    }
}

void copy_group_members(Skissm__GroupMember ***dest, Skissm__GroupMember **src, size_t group_members_num) {
    *dest = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * group_members_num);
    size_t i;
    for (i = 0; i < group_members_num; i++) {
        copy_group_member(&((*dest)[i]), src[i]);
    }
}

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
