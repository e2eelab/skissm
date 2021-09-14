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

#include "account.h"
#include "skissm.h"
#include "cipher.h"
#include "account_manager.h"
#include "crypto.h"
#include "mem_util.h"

static const struct cipher CIPHER = CIPHER_INIT;
static Org__E2eelab__Skissm__Proto__E2eeAccount *local_account = NULL;

void account_begin(){
    Org__E2eelab__Skissm__Proto__E2eeAccount **accounts = NULL;
    size_t account_num = ssm_plugin.load_accounts(&accounts);

    if (account_num == 0){
        if (accounts != NULL){
            ssm_notify_error(BAD_LOAD_ACCOUNTS, "account_begin()");
        }
        return;
    }
    Org__E2eelab__Skissm__Proto__E2eeAccount *cur_account = NULL;
    int64_t now;
    size_t i;
    for (i = 0; i < account_num; i++){
        cur_account = accounts[i];
        /* Check if the signed pre-key expired */
        now = ssm_plugin.handle_get_ts();
        if (now > cur_account->signed_pre_key_pair->ttl){
            generate_signed_pre_key(cur_account);
            publish_spk(cur_account);
        }

        /* Check and remove signed pre-keys (keep last two) */
        ssm_plugin.remove_expired_signed_pre_key(&(cur_account->account_id));

        /* Check if there are too many "used" one-time pre-keys */
        free_one_time_pre_key(cur_account);

        /* Release */
        org__e2eelab__skissm__proto__e2ee_account__free_unpacked(cur_account, NULL);
        cur_account = NULL;
    }
    free(accounts);
}

void account_end(){
    if (local_account != NULL){
        org__e2eelab__skissm__proto__e2ee_account__free_unpacked(local_account, NULL);
        local_account = NULL;
    }
}

Org__E2eelab__Skissm__Proto__E2eeAccount *create_account(){
    Org__E2eelab__Skissm__Proto__E2eeAccount *account = (Org__E2eelab__Skissm__Proto__E2eeAccount *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAccount));
    org__e2eelab__skissm__proto__e2ee_account__init(account);

    // Set the version
    account->version = PROTOCOL_VERSION;

    // Set some initial ids
    account->next_signed_pre_key_id = 1;
    account->next_one_time_pre_key_id = 1;

    // Generate an account ID
    account->account_id.data = (uint8_t *) malloc(sizeof(uint8_t) * UUID_LEN);
    account->account_id.len = UUID_LEN;
    ssm_plugin.handle_generate_uuid(account->account_id.data);

    // Generate the identity key pair
    account->identity_key_pair = (Org__E2eelab__Skissm__Proto__KeyPair *) malloc(sizeof(Org__E2eelab__Skissm__Proto__KeyPair));
    org__e2eelab__skissm__proto__key_pair__init(account->identity_key_pair);
    CIPHER.suit1->gen_key_pair(account->identity_key_pair);

    // Generate a signed pre-key pair
    generate_signed_pre_key(account);

    // Generate 100 one-time pre-key pairs
    generate_opks(100, account);

    return account;
}

Org__E2eelab__Skissm__Proto__E2eeAccount *get_local_account(Org__E2eelab__Skissm__Proto__E2eeAddress *address){
    if (local_account != NULL){
        if ((local_account->address) && compare_address(local_account->address, address)){
            return local_account;
        }
        org__e2eelab__skissm__proto__e2ee_account__free_unpacked(local_account, NULL);
        local_account = NULL;
    }
    ssm_plugin.load_account_by_address(address, &local_account);
    return local_account;
}

size_t generate_signed_pre_key(Org__E2eelab__Skissm__Proto__E2eeAccount *account){
    // Check whether the old signed pre-key exists or not
    if (account->signed_pre_key_pair){
        org__e2eelab__skissm__proto__signed_pre_key_pair__free_unpacked(account->signed_pre_key_pair, NULL);
        account->signed_pre_key_pair = NULL;
    }

    // Initialize
    account->signed_pre_key_pair = (Org__E2eelab__Skissm__Proto__SignedPreKeyPair *) malloc(sizeof(Org__E2eelab__Skissm__Proto__SignedPreKeyPair));
    org__e2eelab__skissm__proto__signed_pre_key_pair__init(account->signed_pre_key_pair);

    // Generate signed pre-key
    account->signed_pre_key_pair->key_pair = (Org__E2eelab__Skissm__Proto__KeyPair *) malloc(sizeof(Org__E2eelab__Skissm__Proto__KeyPair));
    org__e2eelab__skissm__proto__key_pair__init(account->signed_pre_key_pair->key_pair);
    CIPHER.suit1->gen_key_pair(account->signed_pre_key_pair->key_pair);
    account->signed_pre_key_pair->spk_id = (account->next_signed_pre_key_id)++;

    // Generate signature
    account->signed_pre_key_pair->signature.data = (uint8_t *) malloc(CURVE_SIGNATURE_LENGTH);
    account->signed_pre_key_pair->signature.len = CURVE_SIGNATURE_LENGTH;
    CIPHER.suit1->sign(
        account->identity_key_pair->private_key.data,
        account->signed_pre_key_pair->key_pair->public_key.data,
        CURVE25519_KEY_LENGTH,
        account->signed_pre_key_pair->signature.data);

    int64_t now = ssm_plugin.handle_get_ts();
    account->signed_pre_key_pair->ttl = now + SIGNED_PRE_KEY_EXPIRATION;

    return 0;
}

const Org__E2eelab__Skissm__Proto__OneTimePreKeyPair *lookup_one_time_pre_key(
    Org__E2eelab__Skissm__Proto__E2eeAccount *account,
    uint32_t one_time_pre_key_id
) {
    Org__E2eelab__Skissm__Proto__OneTimePreKeyPair **cur = account->one_time_pre_keys;
    size_t i;
    for (i = 0; i < account->n_one_time_pre_keys; i++){
        if (cur[i]->opk_id == one_time_pre_key_id){
            return cur[i];
        }
    }
    return NULL;
}

Org__E2eelab__Skissm__Proto__OneTimePreKeyPair **generate_opks(size_t number_of_keys, Org__E2eelab__Skissm__Proto__E2eeAccount *account){
    // Generate a number of one-time pre-key pairs

    Org__E2eelab__Skissm__Proto__OneTimePreKeyPair **inserted_one_time_pre_key_list_node;

    if (account->one_time_pre_keys == NULL){
        inserted_one_time_pre_key_list_node = (Org__E2eelab__Skissm__Proto__OneTimePreKeyPair **) malloc(sizeof(Org__E2eelab__Skissm__Proto__OneTimePreKeyPair *) * number_of_keys);
        account->one_time_pre_keys = inserted_one_time_pre_key_list_node;
        account->n_one_time_pre_keys = number_of_keys;
    } else{
        size_t n = account->n_one_time_pre_keys;
        account->n_one_time_pre_keys = n + number_of_keys;
        Org__E2eelab__Skissm__Proto__OneTimePreKeyPair **temp_one_time_pre_keys;
        temp_one_time_pre_keys = (Org__E2eelab__Skissm__Proto__OneTimePreKeyPair **) malloc(sizeof(Org__E2eelab__Skissm__Proto__OneTimePreKeyPair *) * account->n_one_time_pre_keys);
        size_t i;
        for (i = 0; i < n; i++){
            temp_one_time_pre_keys[i] = (Org__E2eelab__Skissm__Proto__OneTimePreKeyPair *) malloc(sizeof(Org__E2eelab__Skissm__Proto__OneTimePreKeyPair));
            org__e2eelab__skissm__proto__one_time_pre_key_pair__init(temp_one_time_pre_keys[i]);
            temp_one_time_pre_keys[i]->opk_id = account->one_time_pre_keys[i]->opk_id;
            temp_one_time_pre_keys[i]->used = account->one_time_pre_keys[i]->used;
            temp_one_time_pre_keys[i]->key_pair = (Org__E2eelab__Skissm__Proto__KeyPair *) malloc(sizeof(Org__E2eelab__Skissm__Proto__KeyPair));
            org__e2eelab__skissm__proto__key_pair__init(temp_one_time_pre_keys[i]->key_pair);
            copy_protobuf_from_protobuf(&(temp_one_time_pre_keys[i]->key_pair->private_key), &(account->one_time_pre_keys[i]->key_pair->private_key));
            copy_protobuf_from_protobuf(&(temp_one_time_pre_keys[i]->key_pair->public_key), &(account->one_time_pre_keys[i]->key_pair->public_key));
            org__e2eelab__skissm__proto__one_time_pre_key_pair__free_unpacked(account->one_time_pre_keys[i], NULL);
            account->one_time_pre_keys[i] = NULL;
        }
        free(account->one_time_pre_keys);
        account->one_time_pre_keys = temp_one_time_pre_keys;
        inserted_one_time_pre_key_list_node = &((account->one_time_pre_keys)[n]);
    }

    unsigned i;
    for (i = 0; i < number_of_keys; i++) {
        Org__E2eelab__Skissm__Proto__OneTimePreKeyPair *node;
        node = (Org__E2eelab__Skissm__Proto__OneTimePreKeyPair *) malloc(sizeof(Org__E2eelab__Skissm__Proto__OneTimePreKeyPair));
        org__e2eelab__skissm__proto__one_time_pre_key_pair__init(node);
        node->opk_id = (account->next_one_time_pre_key_id)++;
        node->used = false;
        node->key_pair = (Org__E2eelab__Skissm__Proto__KeyPair *) malloc(sizeof(Org__E2eelab__Skissm__Proto__KeyPair));
        org__e2eelab__skissm__proto__key_pair__init(node->key_pair);
        CIPHER.suit1->gen_key_pair(node->key_pair);
        inserted_one_time_pre_key_list_node[i] = node;
    }

    return inserted_one_time_pre_key_list_node;
}

size_t mark_opk_as_used(Org__E2eelab__Skissm__Proto__E2eeAccount *account, uint32_t id){
    Org__E2eelab__Skissm__Proto__OneTimePreKeyPair **cur = account->one_time_pre_keys;
    unsigned int i;
    for (i = 0; i < account->n_one_time_pre_keys; i++){
        if (cur[i]->opk_id == id){
            cur[i]->used = true;
            return cur[i]->opk_id;
        }
    }

    ssm_notify_error(ERROR_REMOVE_OPK, "mark_opk_as_used()");
    return (size_t)(-1);
}

Org__E2eelab__Skissm__Proto__RegisterUserRequestPayload *create_register_request_payload(
    Org__E2eelab__Skissm__Proto__E2eeAccount *account
) {
    Org__E2eelab__Skissm__Proto__RegisterUserRequestPayload *payload = (Org__E2eelab__Skissm__Proto__RegisterUserRequestPayload *) malloc(sizeof(Org__E2eelab__Skissm__Proto__RegisterUserRequestPayload));
    org__e2eelab__skissm__proto__register_user_request_payload__init(payload);

    unsigned int i;

    copy_protobuf_from_protobuf(&(payload->identity_key_public), &(account->identity_key_pair->public_key));

    payload->signed_pre_key_public = (Org__E2eelab__Skissm__Proto__SignedPreKeyPublic *) malloc(sizeof(Org__E2eelab__Skissm__Proto__SignedPreKeyPublic));
    org__e2eelab__skissm__proto__signed_pre_key_public__init(payload->signed_pre_key_public);
    payload->signed_pre_key_public->spk_id = account->signed_pre_key_pair->spk_id;
    copy_protobuf_from_protobuf(&(payload->signed_pre_key_public->public_key), &(account->signed_pre_key_pair->key_pair->public_key));

    copy_protobuf_from_protobuf(&(payload->signed_pre_key_public->signature), &(account->signed_pre_key_pair->signature));

    payload->n_one_time_pre_keys = account->n_one_time_pre_keys;
    payload->one_time_pre_keys = (Org__E2eelab__Skissm__Proto__OneTimePreKeyPublic **) malloc(sizeof(Org__E2eelab__Skissm__Proto__OneTimePreKeyPublic *) * payload->n_one_time_pre_keys);
    for (i = 0; i < payload->n_one_time_pre_keys; i++){
        payload->one_time_pre_keys[i] = (Org__E2eelab__Skissm__Proto__OneTimePreKeyPublic *) malloc(sizeof(Org__E2eelab__Skissm__Proto__OneTimePreKeyPublic));
        org__e2eelab__skissm__proto__one_time_pre_key_public__init(payload->one_time_pre_keys[i]);
        payload->one_time_pre_keys[i]->opk_id = account->one_time_pre_keys[i]->opk_id;
        copy_protobuf_from_protobuf(&(payload->one_time_pre_keys[i]->public_key), &(account->one_time_pre_keys[i]->key_pair->public_key));
    }

    return payload;
}

static void copy_one_time_pre_keys(
    Org__E2eelab__Skissm__Proto__OneTimePreKeyPair **dest,
    Org__E2eelab__Skissm__Proto__OneTimePreKeyPair **src,
    size_t num
) {
    size_t i;
    for (i = 0; i < num; i++){
        dest[i] = (Org__E2eelab__Skissm__Proto__OneTimePreKeyPair *) malloc(sizeof(Org__E2eelab__Skissm__Proto__OneTimePreKeyPair));
        org__e2eelab__skissm__proto__one_time_pre_key_pair__init(dest[i]);
        dest[i]->opk_id = src[i]->opk_id;
        dest[i]->used = src[i]->used;
        dest[i]->key_pair = (Org__E2eelab__Skissm__Proto__KeyPair *) malloc(sizeof(Org__E2eelab__Skissm__Proto__KeyPair));
        org__e2eelab__skissm__proto__key_pair__init(dest[i]->key_pair);
        copy_protobuf_from_protobuf(&(dest[i]->key_pair->private_key), &(src[i]->key_pair->private_key));
        copy_protobuf_from_protobuf(&(dest[i]->key_pair->public_key), &(src[i]->key_pair->public_key));
    }
}

/* TODO: free_one_time_pre_key */
void free_one_time_pre_key(Org__E2eelab__Skissm__Proto__E2eeAccount *account){
    size_t used_num = 0;
    size_t new_num;
    unsigned int i;
    if (account->one_time_pre_keys){
        for (i = 0; i < account->n_one_time_pre_keys; i++){
            if (account->one_time_pre_keys[i]){
                if (account->one_time_pre_keys[i]->used == true){
                    used_num++;
                } else{
                    break;
                }
            }
        }
        if (used_num >= 60){
            new_num = account->n_one_time_pre_keys - used_num;
            Org__E2eelab__Skissm__Proto__OneTimePreKeyPair **new_one_time_pre_keys;
            if (new_num > 0){
                new_one_time_pre_keys = (Org__E2eelab__Skissm__Proto__OneTimePreKeyPair **) malloc(sizeof(Org__E2eelab__Skissm__Proto__OneTimePreKeyPair *) * new_num);
                Org__E2eelab__Skissm__Proto__OneTimePreKeyPair **temp = &(account->one_time_pre_keys[used_num]);
                copy_one_time_pre_keys(new_one_time_pre_keys, temp, new_num);
            }
            for (i = 0; i < account->n_one_time_pre_keys; i++){
                ssm_plugin.remove_one_time_pre_key(&(account->account_id), account->one_time_pre_keys[i]->opk_id);
                org__e2eelab__skissm__proto__one_time_pre_key_pair__free_unpacked(account->one_time_pre_keys[i], NULL);
                account->one_time_pre_keys[i] = NULL;
            }
            free_mem((void **)&(account->one_time_pre_keys), sizeof(Org__E2eelab__Skissm__Proto__OneTimePreKeyPair **) * account->n_one_time_pre_keys);
            if (new_num > 0){
                account->one_time_pre_keys = new_one_time_pre_keys;
            }
        }
    }
}
