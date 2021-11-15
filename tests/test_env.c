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
#include "test_env.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <sqlite3.h>
#include <string.h>

#include "cipher.h"
#include "crypto.h"
#include "e2ee_protocol.h"
#include "e2ee_protocol_simulator.h"
#include "mem_util.h"

#include "test_util.h"
#include "test_db.h"

// utility functions
void create_domain(ProtobufCBinaryData *domain) {
    domain->len = sizeof(E2EELAB_DOMAIN);
    domain->data = (uint8_t *)malloc(sizeof(uint8_t) * domain->len);
    memcpy(domain->data, E2EELAB_DOMAIN, domain->len);
}

void random_id(ProtobufCBinaryData *id, size_t len) {
    id->len = len;
    id->data = (uint8_t *)malloc(len * sizeof(uint8_t));
    get_ssm_plugin()->handle_rg(id->data, len);
}

char *random_chars(size_t len) {
    static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,<.>~!@#$+-*";
    char *str = NULL;
    if (len) {
        str = malloc(sizeof(char) * (len + 1));
        if (str) {
            for (int n = 0; n < len; n++) {
                int key = rand() % (int)(sizeof(charset) - 1);
                str[n] = charset[key];
            }
            str[len] = '\0';
        }
    }
    return str;
}

// common handlers
static int64_t handle_get_ts() {
    time_t now = time(0);
    return now;
}

static void handle_rg(uint8_t *rand_out, size_t rand_out_len) {
    srand((unsigned int)time(NULL));
    for (int i = 0; i < rand_out_len; i++) {
        rand_out[i] = random() % UCHAR_MAX;
    }
}

static void handle_generate_uuid(uint8_t uuid[UUID_LEN]) { handle_rg(uuid, UUID_LEN); }

static int handle_send(uint8_t *msg, size_t msg_len) {
    mock_protocol_receive(msg, msg_len);
    return 0;
}

// account related handlers
void load_account(ProtobufCBinaryData *account_id, Org__E2eelab__Skissm__Proto__E2eeAccount **account) {
    if (account_id == NULL) {
        load_id(&account_id);
        load_account(account_id, account);
        free(account_id);
        return;
    }

    *account = (Org__E2eelab__Skissm__Proto__E2eeAccount *)malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAccount));
    org__e2eelab__skissm__proto__e2ee_account__init((*account));

    (*account)->version = load_version(account_id);
    (*account)->saved = load_saved(account_id);
    load_address(account_id, &((*account)->address));

    load_signed_pre_key_pair(account_id, &((*account)->signed_pre_key_pair));
    load_identity_key_pair(account_id, &((*account)->identity_key_pair));
    (*account)->n_one_time_pre_keys = load_one_time_pre_keys(account_id, &((*account)->one_time_pre_keys));
    (*account)->next_signed_pre_key_id = load_next_signed_pre_key_id(account_id);
    (*account)->next_one_time_pre_key_id = load_next_one_time_pre_key_id(account_id);
}

size_t load_accounts(Org__E2eelab__Skissm__Proto__E2eeAccount ***accounts) {
    // load all account_ids
    ProtobufCBinaryData **account_ids;
    size_t num = load_ids(&account_ids);

    // load all account by account_ids
    if (num == 0) {
        *accounts = NULL;
    } else {
        *accounts = (Org__E2eelab__Skissm__Proto__E2eeAccount **)malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAccount *) * num);
        for (int i = 0; i < num; i++) {
            load_account(account_ids[i], &(*accounts)[i]);
            // release account_ids element
            free(account_ids[i]);
        }

        // release account_ids array
        free(account_ids);
    }

    // done
    return num;
}

void load_account_by_address(Org__E2eelab__Skissm__Proto__E2eeAddress *address, Org__E2eelab__Skissm__Proto__E2eeAccount **account) {
    ProtobufCBinaryData *account_id;
    load_id_by_address(address, &account_id);
    load_account(account_id, account);
}

void store_account(Org__E2eelab__Skissm__Proto__E2eeAccount *account) {
    // insert address
    sqlite_int64 address_id = insert_address(account->address);

    // insert identity_key_pair
    sqlite_int64 identity_key_pair_id = insert_key_pair(account->identity_key_pair);

    // insert signed_pre_key_pair
    sqlite_int64 signed_pre_key_id = insert_signed_pre_key(account->signed_pre_key_pair);

    // insert one_time_pre_keys
    sqlite_int64 one_time_pre_key_ids[account->n_one_time_pre_keys];
    for (int i = 0; i < account->n_one_time_pre_keys; i++) {
        one_time_pre_key_ids[i] = insert_one_time_pre_key(account->one_time_pre_keys[i]);
    }

    // insert account
    sqlite_int64 account_id = insert_account(&(account->account_id), account->version, account->saved, address_id, identity_key_pair_id, signed_pre_key_id, account->next_signed_pre_key_id,
                                             account->next_one_time_pre_key_id);

    // insert ACCOUNT_SIGNED_PRE_KEY_PAIR
    insert_account_signed_pre_key_id(account_id, signed_pre_key_id);

    // insert ACCOUNT_ONE_TIME_PRE_KEY_PAIR
    for (int i = 0; i < account->n_one_time_pre_keys; i++) {
        insert_account_one_time_pre_key_id(account_id, one_time_pre_key_ids[i]);
    }
}

// callback handlers
static void on_one2one_msg_received(Org__E2eelab__Skissm__Proto__E2eeAddress *from_address, Org__E2eelab__Skissm__Proto__E2eeAddress *to_address, uint8_t *plaintext, size_t plaintext_len) {
    print_msg("on_one2one_msg_received: plaintext", plaintext, plaintext_len);
}

static void on_group_msg_received(Org__E2eelab__Skissm__Proto__E2eeAddress *from_address, Org__E2eelab__Skissm__Proto__E2eeAddress *group_address, uint8_t *plaintext, size_t plaintext_len) {
    print_msg("on_group_msg_received: plaintext", plaintext, plaintext_len);
}

struct skissm_plugin ssm_plugin = {
    // common
    handle_get_ts,
    handle_rg,
    handle_generate_uuid,
    handle_send,
    // account
    store_account,
    load_account,
    load_accounts,
    load_account_by_address,
    update_identity_key,
    update_signed_pre_key,
    load_old_signed_pre_key,
    remove_expired_signed_pre_key,
    update_address,
    add_one_time_pre_key,
    remove_one_time_pre_key,
    update_one_time_pre_key,
    // session
    load_inbound_session,
    store_session,
    load_outbound_session,
    unload_session,
    load_outbound_group_session,
    load_inbound_group_session,
    store_group_session,
    unload_group_session,
    unload_inbound_group_session,
};

// test case interface

void setup() {
    set_ssm_plugin(&ssm_plugin);
    test_db_begin();
    ssm_begin();
    protocol_simulator_begin();
}

void tear_down() {
    test_db_end();
    ssm_end();
    protocol_simulator_end();
}