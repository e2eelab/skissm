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
#include <string.h>

#include "mem_util.h"

bool is_equal(const uint8_t *buffer_a, const uint8_t *buffer_b, size_t length) {
    uint8_t volatile result = 0;
    while (length--) {
        result |= (*(buffer_a++)) ^ (*(buffer_b++));
    }
    return result == 0;
}

bool compare_protobuf(ProtobufCBinaryData *src_1, ProtobufCBinaryData *src_2) {
    if (src_1->len == src_2->len) {
        if (memcmp(src_1->data, src_2->data, src_1->len) == 0) {
            return true;
        }
    }
    return false;
}

bool safe_strcmp(char *str1, char *str2) {
    if (str1 == NULL && str2 == NULL)
        return true;
    if (str1 != NULL && str2 != NULL) {
        return strcmp(str1, str2) == 0;
    }
    return false;
}

bool compare_address(Org__E2eelab__Skissm__Proto__E2eeAddress *address_1, Org__E2eelab__Skissm__Proto__E2eeAddress *address_2) {
    if ((address_1->user_id.len == address_2->user_id.len) && (address_1->domain.len == address_2->domain.len) && (address_1->device_id.len == address_2->device_id.len) &&
        (address_1->group_id.len == address_2->group_id.len)) {
        if ((memcmp(address_1->user_id.data, address_2->user_id.data, address_1->user_id.len) == 0) && (memcmp(address_1->domain.data, address_2->domain.data, address_1->domain.len) == 0) &&
            (memcmp(address_1->device_id.data, address_2->device_id.data, address_1->device_id.len) == 0) &&
            (memcmp(address_1->group_id.data, address_2->group_id.data, address_1->group_id.len) == 0)) {
            return true;
        }
        return false;
    }

    return false;
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

void copy_address_from_address(Org__E2eelab__Skissm__Proto__E2eeAddress **dest, const Org__E2eelab__Skissm__Proto__E2eeAddress *src) {
    *dest = (Org__E2eelab__Skissm__Proto__E2eeAddress *)malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAddress));
    org__e2eelab__skissm__proto__e2ee_address__init(*dest);
    if (src->user_id.data) {
        (*dest)->user_id.len = src->user_id.len;
        (*dest)->user_id.data = (uint8_t *)malloc(sizeof(uint8_t) * src->user_id.len);
        memcpy((*dest)->user_id.data, src->user_id.data, src->user_id.len);
    }
    if (src->domain.data) {
        (*dest)->domain.len = src->domain.len;
        (*dest)->domain.data = (uint8_t *)malloc(sizeof(uint8_t) * src->domain.len);
        memcpy((*dest)->domain.data, src->domain.data, src->domain.len);
    }
    if (src->device_id.data) {
        (*dest)->device_id.len = src->device_id.len;
        (*dest)->device_id.data = (uint8_t *)malloc(sizeof(uint8_t) * src->device_id.len);
        memcpy((*dest)->device_id.data, src->device_id.data, src->device_id.len);
    }
    if (src->group_id.data) {
        (*dest)->group_id.len = src->group_id.len;
        (*dest)->group_id.data = (uint8_t *)malloc(sizeof(uint8_t) * src->group_id.len);
        memcpy((*dest)->group_id.data, src->group_id.data, src->group_id.len);
    }
}

void copy_key_pair_from_key_pair(Org__E2eelab__Skissm__Proto__KeyPair **dest, Org__E2eelab__Skissm__Proto__KeyPair *src) {
    *dest = (Org__E2eelab__Skissm__Proto__KeyPair *)malloc(sizeof(Org__E2eelab__Skissm__Proto__KeyPair));
    org__e2eelab__skissm__proto__key_pair__init(*dest);
    copy_protobuf_from_protobuf(&((*dest)->private_key), &(src->private_key));
    copy_protobuf_from_protobuf(&((*dest)->public_key), &(src->public_key));
}

void copy_spk_from_spk(Org__E2eelab__Skissm__Proto__SignedPreKeyPair **dest, Org__E2eelab__Skissm__Proto__SignedPreKeyPair *src) {
    *dest = (Org__E2eelab__Skissm__Proto__SignedPreKeyPair *)malloc(sizeof(Org__E2eelab__Skissm__Proto__SignedPreKeyPair));
    org__e2eelab__skissm__proto__signed_pre_key_pair__init(*dest);
    (*dest)->spk_id = src->spk_id;
    copy_key_pair_from_key_pair(&((*dest)->key_pair), src->key_pair);
    copy_protobuf_from_protobuf(&((*dest)->signature), &(src->signature));
    (*dest)->ttl = src->ttl;
}

void copy_opks_from_opks(Org__E2eelab__Skissm__Proto__OneTimePreKeyPair ***dest, Org__E2eelab__Skissm__Proto__OneTimePreKeyPair **src, size_t opk_num) {
    *dest = (Org__E2eelab__Skissm__Proto__OneTimePreKeyPair **)malloc(sizeof(Org__E2eelab__Skissm__Proto__OneTimePreKeyPair *) * opk_num);
    size_t i;
    for (i = 0; i < opk_num; i++) {
        (*dest)[i] = (Org__E2eelab__Skissm__Proto__OneTimePreKeyPair *)malloc(sizeof(Org__E2eelab__Skissm__Proto__OneTimePreKeyPair));
        org__e2eelab__skissm__proto__one_time_pre_key_pair__init((*dest)[i]);
        (*dest)[i]->opk_id = src[i]->opk_id;
        (*dest)[i]->used = src[i]->used;
        copy_key_pair_from_key_pair(&((*dest)[i]->key_pair), src[i]->key_pair);
    }
}

void copy_account_from_account(Org__E2eelab__Skissm__Proto__E2eeAccount **dest, Org__E2eelab__Skissm__Proto__E2eeAccount *src) {
    *dest = (Org__E2eelab__Skissm__Proto__E2eeAccount *)malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAccount));
    org__e2eelab__skissm__proto__e2ee_account__init(*dest);
    (*dest)->version = src->version;
    if (src->account_id.data) {
        copy_protobuf_from_protobuf(&((*dest)->account_id), &(src->account_id));
    }
    (*dest)->saved = src->saved;
    if (src->address) {
        copy_address_from_address(&((*dest)->address), src->address);
    }
    if (src->identity_key_pair) {
        copy_key_pair_from_key_pair(&((*dest)->identity_key_pair), src->identity_key_pair);
    }
    if (src->signed_pre_key_pair) {
        copy_spk_from_spk(&((*dest)->signed_pre_key_pair), src->signed_pre_key_pair);
    }
    if (src->one_time_pre_keys) {
        copy_opks_from_opks(&((*dest)->one_time_pre_keys), src->one_time_pre_keys, src->n_one_time_pre_keys);
    }
    (*dest)->n_one_time_pre_keys = src->n_one_time_pre_keys;
    (*dest)->next_signed_pre_key_id = src->next_signed_pre_key_id;
    (*dest)->next_one_time_pre_key_id = src->next_one_time_pre_key_id;
}

void copy_member_addresses_from_member_addresses(Org__E2eelab__Skissm__Proto__E2eeAddress ***dest, const Org__E2eelab__Skissm__Proto__E2eeAddress **src, size_t member_num) {
    *dest = (Org__E2eelab__Skissm__Proto__E2eeAddress **)malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAddress *) * member_num);
    size_t i;
    for (i = 0; i < member_num; i++) {
        copy_address_from_address(&((*dest)[i]), src[i]);
    }
}

void free_member_addresses(Org__E2eelab__Skissm__Proto__E2eeAddress ***dest, size_t member_num) {
    size_t i;
    for (i = 0; i < member_num; i++) {
        org__e2eelab__skissm__proto__e2ee_address__free_unpacked((*dest)[i], NULL);
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
