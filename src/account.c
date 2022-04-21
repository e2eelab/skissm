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
#include "skissm/account.h"

#include <string.h>

#include "skissm/account_manager.h"
#include "skissm/cipher.h"
#include "skissm/e2ee_client_internal.h"
#include "skissm/mem_util.h"

static Skissm__Account *local_account = NULL;

void account_begin() {
    Skissm__Account **accounts = NULL;
    size_t account_num = get_skissm_plugin()->db_handler.load_accounts(&accounts);

    if (account_num == 0) {
        if (accounts != NULL) {
            ssm_notify_error(BAD_LOAD_ACCOUNTS, "account_begin()");
        }
        return;
    }
    Skissm__Account *cur_account = NULL;
    int64_t now;
    size_t i;
    for (i = 0; i < account_num; i++) {
        cur_account = accounts[i];
        /* Check if the signed pre-key expired */
        now = get_skissm_plugin()->common_handler.handle_get_ts();
        if (now > cur_account->signed_pre_key->ttl) {
            generate_signed_pre_key(cur_account);
            publish_spk_internal(cur_account);
        }

        /* Check and remove signed pre-keys (keep last two) */
        get_skissm_plugin()->db_handler.remove_expired_signed_pre_key(cur_account->account_id);

        /* Check if there are too many "used" one-time pre-keys */
        free_one_time_pre_key(cur_account);

        /* Release */
        skissm__account__free_unpacked(cur_account, NULL);
        cur_account = NULL;
    }
    free(accounts);
}

void account_end() {
    if (local_account != NULL) {
        skissm__account__free_unpacked(local_account, NULL);
        local_account = NULL;
    }
}

Skissm__Account *create_account(uint64_t account_id, uint32_t e2ee_pack_id) {
    Skissm__Account *account = (Skissm__Account *)malloc(sizeof(Skissm__Account));
    skissm__account__init(account);

    // Set the version
    account->version = PROTOCOL_VERSION;

    // Set some initial ids
    account->next_one_time_pre_key_id = 1;

    // Generate an account ID
    account->account_id = account_id;

    // Generate the identity key pair
    account->identity_key = (Skissm__IdentityKey *)malloc(sizeof(Skissm__IdentityKey));
    skissm__identity_key__init(account->identity_key);
    account->identity_key->asym_key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(account->identity_key->asym_key_pair);

    const cipher_suite_t *cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;

    cipher_suite->asym_key_gen(&(account->identity_key->asym_key_pair->public_key), &(account->identity_key->asym_key_pair->private_key));
    account->identity_key->sign_key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(account->identity_key->sign_key_pair);
    cipher_suite->sign_key_gen(&(account->identity_key->sign_key_pair->public_key), &(account->identity_key->sign_key_pair->private_key));

    // Generate a signed pre-key pair
    generate_signed_pre_key(account);

    // Generate 100 one-time pre-key pairs
    generate_opks(100, account);

    return account;
}

Skissm__Account *get_local_account(Skissm__E2eeAddress *address) {
    if (local_account != NULL) {
        if ((local_account->address) && compare_address(local_account->address, address)) {
            return local_account;
        }
        skissm__account__free_unpacked(local_account, NULL);
        local_account = NULL;
    }
    get_skissm_plugin()->db_handler.load_account_by_address(address, &local_account);
    return local_account;
}

size_t generate_signed_pre_key(Skissm__Account *account) {
    uint32_t next_signed_pre_key_id = 1;
    // Check whether the old signed pre-key exists or not
    if (account->signed_pre_key) {
        next_signed_pre_key_id = account->signed_pre_key->spk_id + 1;
        skissm__signed_pre_key__free_unpacked(account->signed_pre_key, NULL);
        account->signed_pre_key = NULL;
    }

    // Initialize
    account->signed_pre_key = (Skissm__SignedPreKey *)malloc(sizeof(Skissm__SignedPreKey));
    skissm__signed_pre_key__init(account->signed_pre_key);

    const cipher_suite_t *cipher_suite = get_e2ee_pack(account->e2ee_pack_id)->cipher_suite;

    // Generate signed pre-key
    account->signed_pre_key->key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(account->signed_pre_key->key_pair);
    cipher_suite->asym_key_gen(&(account->signed_pre_key->key_pair->public_key), &(account->signed_pre_key->key_pair->private_key));
    account->signed_pre_key->spk_id = next_signed_pre_key_id;

    // Generate signature
    int key_len = cipher_suite->get_crypto_param().asym_key_len;
    int sig_len = cipher_suite->get_crypto_param().sig_len;
    account->signed_pre_key->signature.data = (uint8_t *)malloc(sig_len);
    account->signed_pre_key->signature.len = sig_len;
    cipher_suite->sign(account->identity_key->sign_key_pair->private_key.data, account->signed_pre_key->key_pair->public_key.data, key_len, account->signed_pre_key->signature.data);

    int64_t now = get_skissm_plugin()->common_handler.handle_get_ts();
    account->signed_pre_key->ttl = now + SIGNED_PRE_KEY_EXPIRATION;

    return 0;
}

const Skissm__OneTimePreKey *lookup_one_time_pre_key(Skissm__Account *account, uint32_t one_time_pre_key_id) {
    Skissm__OneTimePreKey **cur = account->one_time_pre_keys;
    size_t i;
    for (i = 0; i < account->n_one_time_pre_keys; i++) {
        if (cur[i]->opk_id == one_time_pre_key_id) {
            return cur[i];
        }
    }
    return NULL;
}

Skissm__OneTimePreKey **generate_opks(size_t number_of_keys, Skissm__Account *account) {
    // Generate a number of one-time pre-key pairs

    Skissm__OneTimePreKey **inserted_one_time_pre_key_list_node;

    if (account->one_time_pre_keys == NULL) {
        inserted_one_time_pre_key_list_node = (Skissm__OneTimePreKey **)malloc(sizeof(Skissm__OneTimePreKey *) * number_of_keys);
        account->one_time_pre_keys = inserted_one_time_pre_key_list_node;
        account->n_one_time_pre_keys = number_of_keys;
    } else {
        size_t n = account->n_one_time_pre_keys;
        account->n_one_time_pre_keys = n + number_of_keys;
        Skissm__OneTimePreKey **temp_one_time_pre_keys;
        temp_one_time_pre_keys = (Skissm__OneTimePreKey **)malloc(sizeof(Skissm__OneTimePreKey *) * account->n_one_time_pre_keys);
        size_t i;
        for (i = 0; i < n; i++) {
            temp_one_time_pre_keys[i] = (Skissm__OneTimePreKey *)malloc(sizeof(Skissm__OneTimePreKey));
            skissm__one_time_pre_key__init(temp_one_time_pre_keys[i]);
            temp_one_time_pre_keys[i]->opk_id = account->one_time_pre_keys[i]->opk_id;
            temp_one_time_pre_keys[i]->used = account->one_time_pre_keys[i]->used;
            temp_one_time_pre_keys[i]->key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
            skissm__key_pair__init(temp_one_time_pre_keys[i]->key_pair);
            copy_protobuf_from_protobuf(&(temp_one_time_pre_keys[i]->key_pair->private_key), &(account->one_time_pre_keys[i]->key_pair->private_key));
            copy_protobuf_from_protobuf(&(temp_one_time_pre_keys[i]->key_pair->public_key), &(account->one_time_pre_keys[i]->key_pair->public_key));
            skissm__one_time_pre_key__free_unpacked(account->one_time_pre_keys[i], NULL);
            account->one_time_pre_keys[i] = NULL;
        }
        free(account->one_time_pre_keys);
        account->one_time_pre_keys = temp_one_time_pre_keys;
        inserted_one_time_pre_key_list_node = &((account->one_time_pre_keys)[n]);
    }

    const cipher_suite_t *cipher_suite = get_e2ee_pack(account->e2ee_pack_id)->cipher_suite;
    unsigned i;
    for (i = 0; i < number_of_keys; i++) {
        Skissm__OneTimePreKey *node;
        node = (Skissm__OneTimePreKey *)malloc(sizeof(Skissm__OneTimePreKey));
        skissm__one_time_pre_key__init(node);
        node->opk_id = (account->next_one_time_pre_key_id)++;
        node->used = false;
        node->key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
        skissm__key_pair__init(node->key_pair);
        cipher_suite->asym_key_gen(&(node->key_pair->public_key), &(node->key_pair->private_key));
        inserted_one_time_pre_key_list_node[i] = node;
    }

    return inserted_one_time_pre_key_list_node;
}

size_t mark_opk_as_used(Skissm__Account *account, uint32_t id) {
    Skissm__OneTimePreKey **cur = account->one_time_pre_keys;
    unsigned int i;
    for (i = 0; i < account->n_one_time_pre_keys; i++) {
        if (cur[i]->opk_id == id) {
            cur[i]->used = true;
            return cur[i]->opk_id;
        }
    }

    ssm_notify_error(ERROR_REMOVE_OPK, "mark_opk_as_used()");
    return (size_t)(-1);
}

static void copy_one_time_pre_keys(Skissm__OneTimePreKey **dest, Skissm__OneTimePreKey **src, size_t num) {
    size_t i;
    for (i = 0; i < num; i++) {
        dest[i] = (Skissm__OneTimePreKey *)malloc(sizeof(Skissm__OneTimePreKey));
        skissm__one_time_pre_key__init(dest[i]);
        dest[i]->opk_id = src[i]->opk_id;
        dest[i]->used = src[i]->used;
        dest[i]->key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
        skissm__key_pair__init(dest[i]->key_pair);
        copy_protobuf_from_protobuf(&(dest[i]->key_pair->private_key), &(src[i]->key_pair->private_key));
        copy_protobuf_from_protobuf(&(dest[i]->key_pair->public_key), &(src[i]->key_pair->public_key));
    }
}

/* TODO: Need to be checked */
void free_one_time_pre_key(Skissm__Account *account) {
    size_t used_num = 0;
    size_t new_num;
    unsigned int i;
    if (account->one_time_pre_keys) {
        for (i = 0; i < account->n_one_time_pre_keys; i++) {
            if (account->one_time_pre_keys[i]) {
                if (account->one_time_pre_keys[i]->used == true) {
                    used_num++;
                } else {
                    break;
                }
            }
        }
        if (used_num >= 60) {
            new_num = account->n_one_time_pre_keys - used_num;
            Skissm__OneTimePreKey **new_one_time_pre_keys;
            if (new_num > 0) {
                new_one_time_pre_keys = (Skissm__OneTimePreKey **)malloc(sizeof(Skissm__OneTimePreKey *) * new_num);
                Skissm__OneTimePreKey **temp = &(account->one_time_pre_keys[used_num]);
                copy_one_time_pre_keys(new_one_time_pre_keys, temp, new_num);
            }
            for (i = 0; i < account->n_one_time_pre_keys; i++) {
                get_skissm_plugin()->db_handler.remove_one_time_pre_key(account->account_id, account->one_time_pre_keys[i]->opk_id);
                skissm__one_time_pre_key__free_unpacked(account->one_time_pre_keys[i], NULL);
                account->one_time_pre_keys[i] = NULL;
            }
            free_mem((void **)&(account->one_time_pre_keys), sizeof(Skissm__OneTimePreKey **) * account->n_one_time_pre_keys);
            if (new_num > 0) {
                account->one_time_pre_keys = new_one_time_pre_keys;
            }
        }
    }
}
