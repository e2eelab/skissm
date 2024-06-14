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

#include "skissm/account_cash.h"
#include "skissm/account_manager.h"
#include "skissm/cipher.h"
#include "skissm/e2ee_client_internal.h"
#include "skissm/mem_util.h"

void account_begin() {
    // load accounts that may be null
    Skissm__Account **accounts = NULL;
    size_t account_num = get_skissm_plugin()->db_handler.load_accounts(&accounts);

    Skissm__Account *cur_account = NULL;
    int64_t now;
    size_t i;
    for (i = 0; i < account_num; i++) {
        cur_account = accounts[i];

        // check if the signed pre-key expired
        now = get_skissm_plugin()->common_handler.gen_ts();
        if (now > cur_account->signed_pre_key->ttl) {
            generate_signed_pre_key(cur_account);
            Skissm__PublishSpkResponse *response = publish_spk_internal(cur_account);
            // release
            if (response != NULL)
                skissm__publish_spk_response__free_unpacked(response, NULL);
        }

        // check and remove signed pre-keys (keep last two)
        get_skissm_plugin()->db_handler.remove_expired_signed_pre_key(cur_account->address);

        // check if there are too many "used" one-time pre-keys
        free_one_time_pre_key(cur_account);

        // resend the pending data if necessary
        resume_connection_internal(cur_account);

        // store into cash
        store_account_into_cash(cur_account);

        // release
        skissm__account__free_unpacked(cur_account, NULL);
    }

    // release
    if (accounts != NULL)
        free(accounts);
}

void account_end() {
    free_account_casher_list();
}

Skissm__Account *create_account(uint32_t e2ee_pack_id) {
    Skissm__Account *account = (Skissm__Account *)malloc(sizeof(Skissm__Account));
    skissm__account__init(account);

    // set the version, e2ee_pack_id
    account->version = strdup(E2EE_PROTOCOL_VERSION);
    account->e2ee_pack_id = e2ee_pack_id;

    // set some initial ids
    account->next_one_time_pre_key_id = 1;

    // generate the identity key pair
    const cipher_suite_t *cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;

    account->identity_key = (Skissm__IdentityKey *)malloc(sizeof(Skissm__IdentityKey));
    skissm__identity_key__init(account->identity_key);

    account->identity_key->asym_key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(account->identity_key->asym_key_pair);
    cipher_suite->kem_suite->asym_key_gen(&account->identity_key->asym_key_pair->public_key, &account->identity_key->asym_key_pair->private_key);

    account->identity_key->sign_key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(account->identity_key->sign_key_pair);
    cipher_suite->digital_signature_suite->sign_key_gen(&account->identity_key->sign_key_pair->public_key, &account->identity_key->sign_key_pair->private_key);

    // generate a signed pre-key pair
    generate_signed_pre_key(account);

    // generate 100 one-time pre-key pairs
    generate_opks(100, account);

    return account;
}

size_t generate_signed_pre_key(Skissm__Account *account) {
    uint32_t next_signed_pre_key_id = 1;
    // check whether the old signed pre-key exists or not
    if (account->signed_pre_key) {
        next_signed_pre_key_id = account->signed_pre_key->spk_id + 1;
        skissm__signed_pre_key__free_unpacked(account->signed_pre_key, NULL);
        account->signed_pre_key = NULL;
    }

    // initialize
    account->signed_pre_key = (Skissm__SignedPreKey *)malloc(sizeof(Skissm__SignedPreKey));
    Skissm__SignedPreKey *signed_pre_key = account->signed_pre_key;
    skissm__signed_pre_key__init(signed_pre_key);

    const cipher_suite_t *cipher_suite = get_e2ee_pack(account->e2ee_pack_id)->cipher_suite;

    // generate a signed pre-key pair
    signed_pre_key->key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
    Skissm__KeyPair *key_pair = signed_pre_key->key_pair;
    skissm__key_pair__init(key_pair);
    cipher_suite->kem_suite->asym_key_gen(&key_pair->public_key, &key_pair->private_key);
    signed_pre_key->spk_id = next_signed_pre_key_id;

    // generate a signature
    int pub_key_len = cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
    int sig_len = cipher_suite->digital_signature_suite->get_crypto_param().sig_len;
    size_t signature_out_len;
    malloc_protobuf(&(signed_pre_key->signature), sig_len);
    cipher_suite->digital_signature_suite->sign(
        signed_pre_key->signature.data, &signature_out_len,
        key_pair->public_key.data, pub_key_len,
        account->identity_key->sign_key_pair->private_key.data
    );

    int64_t now = get_skissm_plugin()->common_handler.gen_ts();
    signed_pre_key->ttl = now + SIGNED_PRE_KEY_EXPIRATION_MS;

    return 0;
}

const Skissm__OneTimePreKey *lookup_one_time_pre_key(Skissm__Account *account, uint32_t one_time_pre_key_id) {
    Skissm__OneTimePreKey **cur = account->one_time_pre_key_list;
    if (cur == NULL) {
        // there is no one-tme pre-keys in the account
        ssm_notify_log(account->address, BAD_ONE_TIME_PRE_KEY, "lookup_one_time_pre_key() opk not found");
        return NULL;
    }

    size_t i;
    for (i = 0; i < account->n_one_time_pre_key_list; i++) {
        if (cur[i] != NULL) {
            if (cur[i]->opk_id == one_time_pre_key_id) {
                return cur[i];
            }
        } else {
            ssm_notify_log(account->address, BAD_ONE_TIME_PRE_KEY, "lookup_one_time_pre_key() the number of opks does not match");
            break;
        }
    }
    return NULL;
}

Skissm__OneTimePreKey **generate_opks(size_t number_of_keys, Skissm__Account *account) {
    // generate a number of one-time pre-key pairs

    Skissm__OneTimePreKey **inserted_one_time_pre_key_list_node = NULL;

    bool succ = true;

    if (account->one_time_pre_key_list == NULL) {
        // there is no one-tme pre-keys in the account
        inserted_one_time_pre_key_list_node = (Skissm__OneTimePreKey **)malloc(sizeof(Skissm__OneTimePreKey *) * number_of_keys);
        account->one_time_pre_key_list = inserted_one_time_pre_key_list_node;
        account->n_one_time_pre_key_list = number_of_keys;
    } else {
        // there are several one-time pre-keys in the account
        size_t old_opk_num = account->n_one_time_pre_key_list;
        size_t new_opk_num = old_opk_num + number_of_keys;
        Skissm__OneTimePreKey **temp_one_time_pre_key_list = (Skissm__OneTimePreKey **)malloc(sizeof(Skissm__OneTimePreKey *) * new_opk_num);
        Skissm__OneTimePreKey *cur_one_time_pre_key = NULL;
        Skissm__KeyPair *temp_key_pair = NULL;

        size_t i;
        for (i = 0; i < old_opk_num; i++) {
            temp_one_time_pre_key_list[i] = (Skissm__OneTimePreKey *)malloc(sizeof(Skissm__OneTimePreKey));
            skissm__one_time_pre_key__init(temp_one_time_pre_key_list[i]);

            cur_one_time_pre_key = account->one_time_pre_key_list[i];
            if (cur_one_time_pre_key == NULL) {
                ssm_notify_log(account->address, BAD_ONE_TIME_PRE_KEY, "generate_opks() the number of opks does not match");
                succ = false;
                break;
            }
            temp_one_time_pre_key_list[i]->opk_id = cur_one_time_pre_key->opk_id;
            temp_one_time_pre_key_list[i]->used = cur_one_time_pre_key->used;
            temp_one_time_pre_key_list[i]->key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
            temp_key_pair = temp_one_time_pre_key_list[i]->key_pair;
            skissm__key_pair__init(temp_key_pair);
            copy_protobuf_from_protobuf(&(temp_key_pair->private_key), &(cur_one_time_pre_key->key_pair->private_key));
            copy_protobuf_from_protobuf(&(temp_key_pair->public_key), &(cur_one_time_pre_key->key_pair->public_key));

            // release the old data
            skissm__one_time_pre_key__free_unpacked(cur_one_time_pre_key, NULL);
            cur_one_time_pre_key = NULL;
        }

        if (succ) {
            // release the old memory
            free_mem((void **)&(account->one_time_pre_key_list), sizeof(Skissm__OneTimePreKey *) * old_opk_num);
            // insert the new data
            account->one_time_pre_key_list = temp_one_time_pre_key_list;
            account->n_one_time_pre_key_list = new_opk_num;
            inserted_one_time_pre_key_list_node = &((account->one_time_pre_key_list)[old_opk_num]);
        } else {
            // release
            for (i = 0; i < new_opk_num; i++) {
                skissm__one_time_pre_key__free_unpacked(temp_one_time_pre_key_list[i], NULL);
                temp_one_time_pre_key_list[i] = NULL;
            }
            free_mem((void **)&temp_one_time_pre_key_list, sizeof(Skissm__OneTimePreKey *) * new_opk_num);
        }
    }

    if (succ == false) {
        // there is some error in the account
        return NULL;
    }

    const cipher_suite_t *cipher_suite = get_e2ee_pack(account->e2ee_pack_id)->cipher_suite;
    size_t i;
    for (i = 0; i < number_of_keys; i++) {
        Skissm__OneTimePreKey *node = (Skissm__OneTimePreKey *)malloc(sizeof(Skissm__OneTimePreKey));
        skissm__one_time_pre_key__init(node);
        node->opk_id = (account->next_one_time_pre_key_id)++;
        node->used = false;
        node->key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
        skissm__key_pair__init(node->key_pair);
        cipher_suite->kem_suite->asym_key_gen(&node->key_pair->public_key, &node->key_pair->private_key);
        inserted_one_time_pre_key_list_node[i] = node;
    }

    return inserted_one_time_pre_key_list_node;
}

int mark_opk_as_used(Skissm__Account *account, uint32_t id) {
    Skissm__OneTimePreKey **cur = account->one_time_pre_key_list;
    if (cur == NULL) {
        // there is no one-tme pre-keys in the account
        ssm_notify_log(account->address, BAD_ONE_TIME_PRE_KEY, "mark_opk_as_used() opk not found");
        return -1;
    }

    size_t i;
    for (i = 0; i < account->n_one_time_pre_key_list; i++) {
        if (cur[i] != NULL) {
            if (cur[i]->opk_id == id) {
                cur[i]->used = true;
                return cur[i]->opk_id;
            }
        } else {
            ssm_notify_log(account->address, BAD_ONE_TIME_PRE_KEY, "mark_opk_as_used() the number of opks does not match");
            break;
        }
    }

    ssm_notify_log(account->address, BAD_REMOVE_OPK, "mark_opk_as_used() opk id not found");
    return -1;
}

static void copy_one_time_pre_key_list(Skissm__OneTimePreKey **dest, Skissm__OneTimePreKey **src, size_t num) {
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

void free_one_time_pre_key(Skissm__Account *account) {
    size_t used_num = 0;
    size_t new_num;
    size_t i;
    if (account->one_time_pre_key_list) {
        for (i = 0; i < account->n_one_time_pre_key_list; i++) {
            if (account->one_time_pre_key_list[i]) {
                if (account->one_time_pre_key_list[i]->used == true) {
                    used_num++;
                } else {
                    // we use the one-time pre-keys from ahead
                    break;
                }
            }
        }
        // we release the "used" one-time pre-keys if there are many
        if (used_num >= 60) {
            new_num = account->n_one_time_pre_key_list - used_num;
            Skissm__OneTimePreKey **new_one_time_pre_key_list = NULL;
            if (new_num > 0) {
                new_one_time_pre_key_list = (Skissm__OneTimePreKey **)malloc(sizeof(Skissm__OneTimePreKey *) * new_num);
                Skissm__OneTimePreKey **temp = &(account->one_time_pre_key_list[used_num]);
                copy_one_time_pre_key_list(new_one_time_pre_key_list, temp, new_num);
            }
            for (i = 0; i < account->n_one_time_pre_key_list; i++) {
                get_skissm_plugin()->db_handler.remove_one_time_pre_key(account->address, account->one_time_pre_key_list[i]->opk_id);
                skissm__one_time_pre_key__free_unpacked(account->one_time_pre_key_list[i], NULL);
                account->one_time_pre_key_list[i] = NULL;
            }
            free_mem((void **)&(account->one_time_pre_key_list), sizeof(Skissm__OneTimePreKey *) * account->n_one_time_pre_key_list);
            if (new_num > 0) {
                account->one_time_pre_key_list = new_one_time_pre_key_list;
            }
            account->n_one_time_pre_key_list = new_num;
        }
    }
}
