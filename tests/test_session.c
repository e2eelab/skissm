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
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "skissm/account.h"
#include "skissm/account_manager.h"
#include "skissm/e2ee_client.h"
#include "skissm/mem_util.h"
#include "skissm/ratchet.h"
#include "skissm/session.h"
#include "skissm/session_manager.h"
#include "skissm/skissm.h"

#include "test_plugin.h"
#include "test_util.h"

#define account_data_max 2

static const cipher_suite_t *test_cipher_suite;

static Skissm__Account *account_data[account_data_max];

static uint8_t account_data_insert_pos;

typedef struct store_plaintext {
    uint8_t *plaintext;
    size_t plaintext_len;
} store_plaintext;

store_plaintext plaintext_store = {NULL, 0};

static void on_error(ErrorCode error_code, const char *error_msg) {
    print_error((char *)error_msg, error_code);
}

static void on_user_registered(Skissm__Account *account){
    copy_account_from_account(&(account_data[account_data_insert_pos]), account);
    account_data_insert_pos++;
}

static void on_inbound_session_invited(Skissm__E2eeAddress *from) {
    printf("on_inbound_session_invited\n");
}

static void on_inbound_session_ready(Skissm__Session *inbound_session){
    printf("on_inbound_session_ready\n");
}

static void on_outbound_session_ready(Skissm__Session *outbound_session){
    printf("on_outbound_session_ready\n");
}

static void on_one2one_msg_received(
    Skissm__E2eeAddress *from_address,
    Skissm__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    print_msg("on_one2one_msg_received: plaintext", plaintext, plaintext_len);
    if (plaintext_store.plaintext != NULL){
        free_mem((void **)&(plaintext_store.plaintext), plaintext_store.plaintext_len);
    }
    plaintext_store.plaintext = (uint8_t *) malloc(sizeof(uint8_t) * plaintext_len);
    memcpy(plaintext_store.plaintext, plaintext, plaintext_len);
    plaintext_store.plaintext_len = plaintext_len;
}

static skissm_event_handler_t test_event_handler = {
    on_error,
    on_user_registered,
    on_inbound_session_invited,
    on_inbound_session_ready,
    on_outbound_session_ready,
    on_one2one_msg_received,
    NULL,
    NULL,
    NULL,
    NULL
};

static void test_begin(){
    account_data[0] = NULL;
    account_data[1] = NULL;
    account_data_insert_pos = 0;

    get_skissm_plugin()->event_handler = test_event_handler;
}

static void test_end(){
    skissm__account__free_unpacked(account_data[0], NULL);
    account_data[0] = NULL;
    skissm__account__free_unpacked(account_data[1], NULL);
    account_data[1] = NULL;
    account_data_insert_pos = 0;
}

static void test_encryption(
    Skissm__Session *outbound_session,
    uint8_t *plaintext, size_t plaintext_len
) {
    if (plaintext_store.plaintext != NULL){
        free_mem((void **)&(plaintext_store.plaintext), plaintext_store.plaintext_len);
    }

    // send encrypted msg
    send_one2one_msg(outbound_session->from, outbound_session->to, plaintext, plaintext_len);
    if (plaintext_store.plaintext == NULL){
        printf("Test failed!!!\n");
        assert(false);
        return;
    }
    assert(plaintext_len == plaintext_store.plaintext_len);
    assert(memcmp(plaintext, plaintext_store.plaintext, plaintext_len) == 0);
}

static void create_test_account(uint64_t account_id, const char *user_name) {
    const char *e2ee_pack_id = TEST_E2EE_PACK_ID;
    const char *device_id = generate_uuid_str();
    const char *authenticator = "email";
    const char *auth_code = "123456";
    Skissm__RegisterUserResponse *response =
        register_user(account_id,
            e2ee_pack_id,
            user_name,
            device_id,
            authenticator,
            auth_code);
    assert(safe_strcmp(device_id, response->address->user->device_id));
    printf("Test user registered: \"%s@%s\"\n", response->address->user->user_id, response->address->domain);
}

static void test_basic_session(){
    // test start
    tear_up();
    test_begin();

    create_test_account(1, "alice");
    create_test_account(2, "bob");

    Skissm__Session *outbound_session;

    // Alice invites Bob to create a session
    Skissm__InviteResponse *response = invite(account_data[0]->address, account_data[1]->address);
    assert(response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK); // waiting Accept

    // Load the outbound session
    get_skissm_plugin()->db_handler.load_outbound_session(account_data[0]->address, account_data[1]->address, &outbound_session);
    assert(outbound_session != NULL);
    assert(outbound_session->responded == true);

    // Alice sends an encrypted message to Bob, and Bob decrypts the message
    uint8_t plaintext[] = "Hello, World";
    size_t plaintext_len = sizeof(plaintext) - 1;
    test_encryption(outbound_session, plaintext, plaintext_len);

    // test stop
    skissm__session__free_unpacked(outbound_session, NULL);
    test_end();
    tear_down();
}

static void test_interaction(){
    // test start
    tear_up();
    test_begin();

    create_test_account(1, "alice");
    create_test_account(2, "bob");

    Skissm__Session *outbound_session_a, *outbound_session_b;

    // Alice invites Bob to create a session
    Skissm__InviteResponse *response = invite(account_data[0]->address, account_data[1]->address);
    assert(response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK); // waiting Accept

    // Alice loads the outbound session
    get_skissm_plugin()->db_handler.load_outbound_session(account_data[0]->address, account_data[1]->address, &outbound_session_a);
    assert(outbound_session_a != NULL);
    assert(outbound_session_a->responded == true);

    // Alice sends an encrypted message to Bob, and Bob decrypts the message
    uint8_t plaintext[] = "Hi! Bob! This is Alice.";
    size_t plaintext_len = sizeof(plaintext) - 1;
    test_encryption(outbound_session_a, plaintext, plaintext_len);

    // Bob invites Alice to create a session
    Skissm__InviteResponse *response1 = invite(account_data[1]->address, account_data[0]->address);
    assert(response1 != NULL && response1->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK); // waiting Accept

    // Bob loads the outbound session
    get_skissm_plugin()->db_handler.load_outbound_session(account_data[1]->address, account_data[0]->address, &outbound_session_b);
    assert(outbound_session_b != NULL);
    assert(outbound_session_b->responded == true);

    // Bob sends an encrypted message to Alice, and Alice decrypts the message
    uint8_t plaintext_2[] = "Hello! This is Bob.";
    size_t plaintext_len_2 = sizeof(plaintext_2) - 1;
    test_encryption(outbound_session_b, plaintext_2, plaintext_len_2);

    // test stop
    skissm__session__free_unpacked(outbound_session_a, NULL);
    skissm__session__free_unpacked(outbound_session_b, NULL);
    test_end();
    tear_down();
}

static void test_continual_messages(){
    // test start
    tear_up();
    test_begin();

    create_test_account(1, "alice");
    create_test_account(2, "bob");

    Skissm__Session *outbound_session;

    // Alice invites Bob to create a session
    Skissm__InviteResponse *response = invite(account_data[0]->address, account_data[1]->address);
    assert(response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK); // waiting Accep

    // Load the outbound session
    get_skissm_plugin()->db_handler.load_outbound_session(account_data[0]->address, account_data[1]->address, &outbound_session);
    assert(outbound_session != NULL);
    assert(outbound_session->responded == true);

    // Alice sends an encrypted message to Bob, and Bob decrypts the message
    int i;
    for (i = 0; i < 1000; i++){
        uint8_t plaintext[64];
        size_t plaintext_len = snprintf((char *)plaintext, 64, "[%4d]This message will be sent a lot of times.", i);
        test_encryption(outbound_session, plaintext, plaintext_len);
    }

    // test stop
    skissm__session__free_unpacked(outbound_session, NULL);
    test_end();
    tear_down();
}

int main() {
    test_cipher_suite = get_e2ee_pack(TEST_E2EE_PACK_ID)->cipher_suite;

    test_basic_session();
    test_interaction();
    test_continual_messages();

    return 0;
}
