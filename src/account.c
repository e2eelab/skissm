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

#include "skissm/account_cache.h"
#include "skissm/account_manager.h"
#include "skissm/cipher.h"
#include "skissm/e2ee_client_internal.h"
#include "skissm/mem_util.h"
#include "skissm/safe_check.h"

void account_begin() {
    int ret = 0;

    // load accounts that may be null
    Skissm__Account **accounts = NULL;
    size_t account_num = get_skissm_plugin()->db_handler.load_accounts(&accounts);

    Skissm__Account *cur_account = NULL;
    int64_t now;
    size_t i;
    for (i = 0; i < account_num; i++) {
        cur_account = accounts[i];

        if (safe_registered_account(cur_account)) {
            // check if the signed pre-key expired
            now = get_skissm_plugin()->common_handler.gen_ts();
            if (now > cur_account->signed_pre_key->ttl) {
                uint32_t e2ee_pack_id = cur_account->e2ee_pack_id;
                uint32_t cur_spk_id = cur_account->signed_pre_key->spk_id;
                Skissm__SignedPreKey *signed_pre_key = NULL;
                uint8_t *identity_private_key = cur_account->identity_key->sign_key_pair->private_key.data;
                // generate a new pair of signed pre-key
                ret = generate_signed_pre_key(&signed_pre_key, e2ee_pack_id, cur_spk_id, identity_private_key);

                if (ret == 0) {
                    // release the old signed pre-key
                    skissm__signed_pre_key__free_unpacked(cur_account->signed_pre_key, NULL);
                    cur_account->signed_pre_key = signed_pre_key;

                    Skissm__PublishSpkResponse *response = publish_spk_internal(cur_account);
                    // release
                    if (response != NULL)
                        skissm__publish_spk_response__free_unpacked(response, NULL);
                }
            }

            // check and remove signed pre-keys (keep last two)
            get_skissm_plugin()->db_handler.remove_expired_signed_pre_key(cur_account->address);

            // check if there are too many "used" one-time pre-keys
            free_one_time_pre_key(cur_account);

            // resend the pending data if necessary
            resume_connection_internal(cur_account);
        }

        // check and remove signed pre-keys (keep last two)
        get_skissm_plugin()->db_handler.remove_expired_signed_pre_key(cur_account->address);

        // check if there are too many "used" one-time pre-keys
        free_one_time_pre_key(cur_account);

        // resend the pending data if necessary
        resume_connection_internal(cur_account);

        // store into cache
        store_account_into_cache(cur_account);

        // release
        if (cur_account != NULL) {
            skissm__account__free_unpacked(cur_account, NULL);
            cur_account = NULL;
        }
    }

    // release
    if (accounts != NULL) {
        free_mem((void **)&accounts, sizeof(Skissm__Account *) * account_num);
    }
}

void account_end() {
    free_account_cacheer_list();
}

int create_account(Skissm__Account **account_out, uint32_t e2ee_pack_id) {
    int ret = 0;

    Skissm__Account *account = NULL;
    Skissm__IdentityKey *identity_key = NULL;
    Skissm__SignedPreKey *signed_pre_key = NULL;
    uint32_t cur_spk_id = 0;
    Skissm__OneTimePreKey **one_time_pre_key_list = NULL;
    size_t number_of_keys = 100;
    uint32_t cur_opk_id = 1;

    // get the cipher suite
    const cipher_suite_t *cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;
    if (!safe_cipher_suite(cipher_suite)) {
        ret = -1;
    }

    if (ret == 0) {
        // generate the identity key pair
        ret = generate_identity_key(&identity_key, e2ee_pack_id);
    }

    if (ret == 0) {
        // generate a signed pre-key pair
        ret = generate_signed_pre_key(&signed_pre_key, e2ee_pack_id, cur_spk_id, identity_key->sign_key_pair->private_key.data);
    }

    if (ret == 0) {
        // generate 100 one-time pre-key pairs
        ret = generate_opks(&one_time_pre_key_list, number_of_keys, e2ee_pack_id, cur_opk_id);
    }

    if (ret == 0) {
        account = (Skissm__Account *)malloc(sizeof(Skissm__Account));
        skissm__account__init(account);

        // set the version, e2ee_pack_id
        account->version = strdup(E2EE_PROTOCOL_VERSION);
        account->e2ee_pack_id = e2ee_pack_id;

        account->identity_key = identity_key;
        account->signed_pre_key = signed_pre_key;
        insert_opks(account, one_time_pre_key_list, number_of_keys);

        *account_out = account;
    } else {
        if (identity_key != NULL) {
            skissm__identity_key__free_unpacked(identity_key, NULL);
            identity_key = NULL;
        }
        if (signed_pre_key != NULL) {
            skissm__signed_pre_key__free_unpacked(signed_pre_key, NULL);
            signed_pre_key = NULL;
        }
        if (one_time_pre_key_list != NULL) {
            size_t i;
            for (i = 0; i < number_of_keys; i++) {
                if (one_time_pre_key_list[i] != NULL) {
                    skissm__one_time_pre_key__free_unpacked(one_time_pre_key_list[i], NULL);
                    one_time_pre_key_list[i] = NULL;
                }
            }
            free_mem((void **)&one_time_pre_key_list, sizeof(Skissm__OneTimePreKey *) * number_of_keys);
        }
    }

    return ret;
}

int generate_identity_key(
    Skissm__IdentityKey **identity_key_out,
    uint32_t e2ee_pack_id
) {
    int ret = 0;

    uint32_t asym_pub_key_len;
    uint32_t asym_priv_key_len;
    uint32_t sign_pub_key_len;
    uint32_t sign_priv_key_len;
    Skissm__IdentityKey *identity_key = NULL;
    Skissm__KeyPair *asym_key_pair = NULL;
    Skissm__KeyPair *sign_key_pair = NULL;

    // get the cipher suite
    const cipher_suite_t *cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;
    if (safe_cipher_suite(cipher_suite)) {
        asym_pub_key_len = cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
        asym_priv_key_len = cipher_suite->kem_suite->get_crypto_param().asym_priv_key_len;
        sign_pub_key_len = cipher_suite->digital_signature_suite->get_crypto_param().sign_pub_key_len;
        sign_priv_key_len = cipher_suite->digital_signature_suite->get_crypto_param().sign_priv_key_len;
    } else {
        ret = -1;
    }

    if (ret == 0) {
        asym_key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
        skissm__key_pair__init(asym_key_pair);
        ret = cipher_suite->kem_suite->asym_key_gen(&(asym_key_pair->public_key), &(asym_key_pair->private_key));

        if (!accurate_key_pair(asym_key_pair, asym_pub_key_len, asym_priv_key_len)) {
            ret = -1;
        }
    }

    if (ret == 0) {
        sign_key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
        skissm__key_pair__init(sign_key_pair);
        ret = cipher_suite->digital_signature_suite->sign_key_gen(&(sign_key_pair->public_key), &(sign_key_pair->private_key));

        if (!accurate_key_pair(sign_key_pair, sign_pub_key_len, sign_priv_key_len)) {
            ret = -1;
        }
    }

    if (ret == 0) {
        identity_key = (Skissm__IdentityKey *)malloc(sizeof(Skissm__IdentityKey));
        skissm__identity_key__init(identity_key);

        identity_key->asym_key_pair = asym_key_pair;
        identity_key->sign_key_pair = sign_key_pair;

        *identity_key_out = identity_key;
    } else {
        if (asym_key_pair != NULL) {
            skissm__key_pair__free_unpacked(asym_key_pair, NULL);
            asym_key_pair = NULL;
        }
        if (sign_key_pair != NULL) {
            skissm__key_pair__free_unpacked(sign_key_pair, NULL);
            sign_key_pair = NULL;
        }
    }

    return ret;
}

int generate_signed_pre_key(
    Skissm__SignedPreKey **signed_pre_key_out,
    uint32_t e2ee_pack_id, uint32_t cur_spk_id,
    const uint8_t *identity_private_key
) {
    int ret = 0;

    uint32_t asym_pub_key_len;
    uint32_t asym_priv_key_len;
    uint32_t sig_len;
    Skissm__SignedPreKey *signed_pre_key = NULL;
    Skissm__KeyPair *key_pair = NULL;
    uint8_t *signature_data = NULL;
    size_t signature_data_len;

    // get the cipher suite
    const cipher_suite_t *cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;
    if (safe_cipher_suite(cipher_suite)) {
        asym_pub_key_len = cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
        asym_priv_key_len = cipher_suite->kem_suite->get_crypto_param().asym_priv_key_len;
        sig_len = cipher_suite->digital_signature_suite->get_crypto_param().sig_len;
    } else {
        ret = -1;
    }

    if (ret == 0) {
        // generate a signed pre-key pair
        key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
        skissm__key_pair__init(key_pair);
        ret = cipher_suite->kem_suite->asym_key_gen(&(key_pair->public_key), &(key_pair->private_key));

        if (!accurate_key_pair(key_pair, asym_pub_key_len, asym_priv_key_len)) {
            ret = -1;
        }
    }

    if (ret == 0) {
        signature_data = (uint8_t *)malloc(sizeof(uint8_t) * sig_len);
        // generate a signature
        ret = cipher_suite->digital_signature_suite->sign(
            signature_data, &signature_data_len,
            key_pair->public_key.data, asym_pub_key_len,
            identity_private_key
        );

        if (sig_len != signature_data_len) {
            ret = -1;
        }
    }

    if (ret == 0) {
        signed_pre_key = (Skissm__SignedPreKey *)malloc(sizeof(Skissm__SignedPreKey));
        skissm__signed_pre_key__init(signed_pre_key);

        signed_pre_key->key_pair = key_pair;
        copy_protobuf_from_array(&(signed_pre_key->signature), signature_data, signature_data_len);

        signed_pre_key->spk_id = cur_spk_id + 1;

        int64_t now = get_skissm_plugin()->common_handler.gen_ts();
        signed_pre_key->ttl = now + SIGNED_PRE_KEY_EXPIRATION_MS;

        *signed_pre_key_out = signed_pre_key;
    } else {
        if (key_pair != NULL) {
            skissm__key_pair__free_unpacked(key_pair, NULL);
            key_pair = NULL;
        }
        if (signature_data != NULL) {
            free_mem((void **)&signature_data, sizeof(uint8_t) * sig_len);
        }
    }

    return ret;
}

// size_t generate_signed_pre_key(Skissm__Account *account) {
//     uint32_t next_signed_pre_key_id = 1;
//     // check whether the old signed pre-key exists or not
//     if (account->signed_pre_key) {
//         next_signed_pre_key_id = account->signed_pre_key->spk_id + 1;
//         skissm__signed_pre_key__free_unpacked(account->signed_pre_key, NULL);
//         account->signed_pre_key = NULL;
//     }

//     // initialize
//     account->signed_pre_key = (Skissm__SignedPreKey *)malloc(sizeof(Skissm__SignedPreKey));
//     Skissm__SignedPreKey *signed_pre_key = account->signed_pre_key;
//     skissm__signed_pre_key__init(signed_pre_key);

//     const cipher_suite_t *cipher_suite = get_e2ee_pack(account->e2ee_pack_id)->cipher_suite;

//     // generate a signed pre-key pair
//     signed_pre_key->key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
//     Skissm__KeyPair *key_pair = signed_pre_key->key_pair;
//     skissm__key_pair__init(key_pair);
//     cipher_suite->kem_suite->asym_key_gen(&key_pair->public_key, &key_pair->private_key);
//     signed_pre_key->spk_id = next_signed_pre_key_id;

//     // generate a signature
//     int pub_key_len = cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
//     int sig_len = cipher_suite->digital_signature_suite->get_crypto_param().sig_len;
//     size_t signature_out_len;
//     malloc_protobuf(&(signed_pre_key->signature), sig_len);
//     cipher_suite->digital_signature_suite->sign(
//         signed_pre_key->signature.data, &signature_out_len,
//         key_pair->public_key.data, pub_key_len,
//         account->identity_key->sign_key_pair->private_key.data
//     );

//     int64_t now = get_skissm_plugin()->common_handler.gen_ts();
//     signed_pre_key->ttl = now + SIGNED_PRE_KEY_EXPIRATION_MS;

//     return 0;
// }

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

int generate_opks(
    Skissm__OneTimePreKey ***one_time_pre_key_out, size_t number_of_keys,
    uint32_t e2ee_pack_id, uint32_t cur_opk_id
) {
    int ret = 0;

    uint32_t asym_pub_key_len;
    uint32_t asym_priv_key_len;
    Skissm__OneTimePreKey **one_time_pre_key_list = NULL;
    Skissm__KeyPair *key_pair = NULL;
    size_t i;

    const cipher_suite_t *cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;
    if (safe_cipher_suite(cipher_suite)) {
        asym_pub_key_len = cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
        asym_priv_key_len = cipher_suite->kem_suite->get_crypto_param().asym_priv_key_len;
    } else {
        ret = -1;
    }

    if (ret == 0) {
        one_time_pre_key_list = (Skissm__OneTimePreKey **)malloc(sizeof(Skissm__OneTimePreKey *) * number_of_keys);
        for (i = 0; i < number_of_keys; i++) {
            key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
            skissm__key_pair__init(key_pair);
            ret = cipher_suite->kem_suite->asym_key_gen(&(key_pair->public_key), &(key_pair->private_key));

            if (!accurate_key_pair(key_pair, asym_pub_key_len, asym_priv_key_len)) {
                ret = -1;
            }

            if (ret == 0) {
                one_time_pre_key_list[i] = (Skissm__OneTimePreKey *)malloc(sizeof(Skissm__OneTimePreKey));
                skissm__one_time_pre_key__init(one_time_pre_key_list[i]);
                copy_key_pair_from_key_pair(&(one_time_pre_key_list[i]->key_pair), key_pair);
                one_time_pre_key_list[i]->opk_id = cur_opk_id + i;
                one_time_pre_key_list[i]->used = false;

                // release
                skissm__key_pair__free_unpacked(key_pair, NULL);
                key_pair = NULL;
            } else {
                // release
                skissm__key_pair__free_unpacked(key_pair, NULL);
                key_pair = NULL;
                break;
            }
        }

        if (ret == 0) {
            *one_time_pre_key_out = one_time_pre_key_list;
        } else {
            if (one_time_pre_key_list != NULL) {
                for (i = 0; i < number_of_keys; i++) {
                    if (one_time_pre_key_list[i] != NULL) {
                        skissm__one_time_pre_key__free_unpacked(one_time_pre_key_list[i], NULL);
                        one_time_pre_key_list[i] = NULL;
                    }
                }
                free_mem((void **)&one_time_pre_key_list, sizeof(Skissm__OneTimePreKey *) * number_of_keys);
            }
        }
    }

    return ret;
}

int insert_opks(Skissm__Account *account, Skissm__OneTimePreKey **src, size_t src_num) {
    int ret = 0;

    size_t i, j;
    size_t old_opk_num;
    size_t new_opk_num;
    Skissm__OneTimePreKey **temp_one_time_pre_key_list = NULL;
    Skissm__OneTimePreKey **cur_one_time_pre_key_list = NULL;
    Skissm__OneTimePreKey *cur_one_time_pre_key = NULL;
    Skissm__KeyPair *cur_key_pair = NULL;

    if (safe_one_time_pre_key_list(account->one_time_pre_key_list, account->n_one_time_pre_key_list)) {
        old_opk_num = account->n_one_time_pre_key_list;
        new_opk_num = old_opk_num + src_num;
    } else {
        ret = -1;
    }

    if (ret == 0) {
        if (old_opk_num == 0) {
            // there is no one-tme pre-keys in the account
            account->one_time_pre_key_list = src;
            account->n_one_time_pre_key_list = src_num;
            account->next_one_time_pre_key_id = src[src_num - 1]->opk_id + 1;
        } else {
            // there are several one-time pre-keys in the account
            temp_one_time_pre_key_list = (Skissm__OneTimePreKey **)malloc(sizeof(Skissm__OneTimePreKey *) * new_opk_num);

            cur_one_time_pre_key_list = account->one_time_pre_key_list;
            for (i = 0; i < old_opk_num; i++) {
                temp_one_time_pre_key_list[i] = (Skissm__OneTimePreKey *)malloc(sizeof(Skissm__OneTimePreKey));
                skissm__one_time_pre_key__init(temp_one_time_pre_key_list[i]);

                cur_one_time_pre_key = cur_one_time_pre_key_list[i];
                temp_one_time_pre_key_list[i]->opk_id = cur_one_time_pre_key->opk_id;
                temp_one_time_pre_key_list[i]->used = cur_one_time_pre_key->used;
                temp_one_time_pre_key_list[i]->key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
                cur_key_pair = temp_one_time_pre_key_list[i]->key_pair;
                skissm__key_pair__init(cur_key_pair);
                copy_protobuf_from_protobuf(&(cur_key_pair->private_key), &(cur_one_time_pre_key->key_pair->private_key));
                copy_protobuf_from_protobuf(&(cur_key_pair->public_key), &(cur_one_time_pre_key->key_pair->public_key));

                // release the old data
                skissm__one_time_pre_key__free_unpacked(cur_one_time_pre_key, NULL);
                cur_one_time_pre_key = NULL;
            }
            free_mem((void **)&(cur_one_time_pre_key_list), sizeof(Skissm__OneTimePreKey *) * old_opk_num);

            for (i = 0; i < new_opk_num; i++) {
                j = old_opk_num + i;
                temp_one_time_pre_key_list[j] = (Skissm__OneTimePreKey *)malloc(sizeof(Skissm__OneTimePreKey));
                skissm__one_time_pre_key__init(temp_one_time_pre_key_list[j]);

                cur_one_time_pre_key = src[i];
                temp_one_time_pre_key_list[j]->opk_id = cur_one_time_pre_key->opk_id;
                temp_one_time_pre_key_list[j]->used = cur_one_time_pre_key->used;
                temp_one_time_pre_key_list[j]->key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
                cur_key_pair = temp_one_time_pre_key_list[j]->key_pair;
                skissm__key_pair__init(cur_key_pair);
                copy_protobuf_from_protobuf(&(cur_key_pair->private_key), &(cur_one_time_pre_key->key_pair->private_key));
                copy_protobuf_from_protobuf(&(cur_key_pair->public_key), &(cur_one_time_pre_key->key_pair->public_key));
            }

            account->one_time_pre_key_list = temp_one_time_pre_key_list;
            account->n_one_time_pre_key_list = new_opk_num;
            account->next_one_time_pre_key_id = src[src_num - 1]->opk_id + 1;
        }
    }

    return ret;
}

// Skissm__OneTimePreKey **generate_opks(size_t number_of_keys, Skissm__Account *account) {
//     // generate a number of one-time pre-key pairs

//     Skissm__OneTimePreKey **inserted_one_time_pre_key_list_node = NULL;

//     bool succ = true;

//     if (account->one_time_pre_key_list == NULL) {
//         // there is no one-tme pre-keys in the account
//         inserted_one_time_pre_key_list_node = (Skissm__OneTimePreKey **)malloc(sizeof(Skissm__OneTimePreKey *) * number_of_keys);
//         account->one_time_pre_key_list = inserted_one_time_pre_key_list_node;
//         account->n_one_time_pre_key_list = number_of_keys;
//     } else {
//         // there are several one-time pre-keys in the account
//         size_t old_opk_num = account->n_one_time_pre_key_list;
//         size_t new_opk_num = old_opk_num + number_of_keys;
//         Skissm__OneTimePreKey **temp_one_time_pre_key_list = (Skissm__OneTimePreKey **)malloc(sizeof(Skissm__OneTimePreKey *) * new_opk_num);
//         Skissm__OneTimePreKey *cur_one_time_pre_key = NULL;
//         Skissm__KeyPair *temp_key_pair = NULL;

//         size_t i;
//         for (i = 0; i < old_opk_num; i++) {
//             temp_one_time_pre_key_list[i] = (Skissm__OneTimePreKey *)malloc(sizeof(Skissm__OneTimePreKey));
//             skissm__one_time_pre_key__init(temp_one_time_pre_key_list[i]);

//             cur_one_time_pre_key = account->one_time_pre_key_list[i];
//             if (cur_one_time_pre_key == NULL) {
//                 ssm_notify_log(account->address, BAD_ONE_TIME_PRE_KEY, "generate_opks() the number of opks does not match");
//                 succ = false;
//                 break;
//             }
//             temp_one_time_pre_key_list[i]->opk_id = cur_one_time_pre_key->opk_id;
//             temp_one_time_pre_key_list[i]->used = cur_one_time_pre_key->used;
//             temp_one_time_pre_key_list[i]->key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
//             temp_key_pair = temp_one_time_pre_key_list[i]->key_pair;
//             skissm__key_pair__init(temp_key_pair);
//             copy_protobuf_from_protobuf(&(temp_key_pair->private_key), &(cur_one_time_pre_key->key_pair->private_key));
//             copy_protobuf_from_protobuf(&(temp_key_pair->public_key), &(cur_one_time_pre_key->key_pair->public_key));

//             // release the old data
//             skissm__one_time_pre_key__free_unpacked(cur_one_time_pre_key, NULL);
//             cur_one_time_pre_key = NULL;
//         }

//         if (succ) {
//             // release the old memory
//             free_mem((void **)&(account->one_time_pre_key_list), sizeof(Skissm__OneTimePreKey *) * old_opk_num);
//             // insert the new data
//             account->one_time_pre_key_list = temp_one_time_pre_key_list;
//             account->n_one_time_pre_key_list = new_opk_num;
//             inserted_one_time_pre_key_list_node = &((account->one_time_pre_key_list)[old_opk_num]);
//         } else {
//             // release
//             for (i = 0; i < new_opk_num; i++) {
//                 skissm__one_time_pre_key__free_unpacked(temp_one_time_pre_key_list[i], NULL);
//                 temp_one_time_pre_key_list[i] = NULL;
//             }
//             free_mem((void **)&temp_one_time_pre_key_list, sizeof(Skissm__OneTimePreKey *) * new_opk_num);
//         }
//     }

//     if (succ == false) {
//         // there is some error in the account
//         return NULL;
//     }

//     const cipher_suite_t *cipher_suite = get_e2ee_pack(account->e2ee_pack_id)->cipher_suite;
//     size_t i;
//     for (i = 0; i < number_of_keys; i++) {
//         Skissm__OneTimePreKey *node = (Skissm__OneTimePreKey *)malloc(sizeof(Skissm__OneTimePreKey));
//         skissm__one_time_pre_key__init(node);
//         node->opk_id = (account->next_one_time_pre_key_id)++;
//         node->used = false;
//         node->key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
//         skissm__key_pair__init(node->key_pair);
//         cipher_suite->kem_suite->asym_key_gen(&node->key_pair->public_key, &node->key_pair->private_key);
//         inserted_one_time_pre_key_list_node[i] = node;
//     }

//     return inserted_one_time_pre_key_list_node;
// }

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
