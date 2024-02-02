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
#include <pthread.h>

#include "skissm/account.h"
#include "skissm/account_manager.h"
#include "skissm/e2ee_client.h"
#include "skissm/mem_util.h"
#include "skissm/ratchet.h"
#include "skissm/session.h"
#include "skissm/session_manager.h"
#include "skissm/skissm.h"

#include "mock_server_sending.h"
#include "test_plugin.h"
#include "test_util.h"

#define account_data_max 10

static Skissm__Account *account_data[account_data_max];

static uint8_t account_data_insert_pos;

static uint8_t test_plaintext[] = "Session test!!!";
static size_t test_plaintext_len;

static void on_log(Skissm__E2eeAddress *user_address, LogCode log_code, const char *log_msg) {
    // print_log((char *)log_msg, log_code);
}

static void on_user_registered(Skissm__Account *account){
    copy_account_from_account(&(account_data[account_data_insert_pos]), account);
    account_data_insert_pos++;
}

static void on_inbound_session_invited(Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *from) {
    // printf("on_inbound_session_invited\n");
}

static void on_inbound_session_ready(Skissm__E2eeAddress *user_address, Skissm__Session *inbound_session){
    // if (inbound_session->f2f == true) {
    //     printf("the face-to-face inbound session is ready\n");
    // } else {
    //     printf("on_inbound_session_ready\n");
    // }
}

static void on_outbound_session_ready(Skissm__E2eeAddress *user_address, Skissm__Session *outbound_session){
    // if (outbound_session->f2f == true) {
    //     printf("the face-to-face outbound session is ready\n");
    // } else {
    //     printf("on_outbound_session_ready\n");
    // }
}

static void on_one2one_msg_received(
    Skissm__E2eeAddress *user_address, 
    Skissm__E2eeAddress *from_address,
    Skissm__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    assert(memcmp(plaintext, test_plaintext, plaintext_len) == 0);
    // print_msg("on_one2one_msg_received: plaintext", plaintext, plaintext_len);
}

static void on_other_device_msg_received(
    Skissm__E2eeAddress *user_address, 
    Skissm__E2eeAddress *from_address,
    Skissm__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    assert(memcmp(plaintext, test_plaintext, plaintext_len) == 0);
    // print_msg("on_other_device_msg_received: plaintext", plaintext, plaintext_len);
}

static skissm_event_handler_t test_event_handler = {
    on_log,
    on_user_registered,
    on_inbound_session_invited,
    on_inbound_session_ready,
    on_outbound_session_ready,
    on_one2one_msg_received,
    on_other_device_msg_received,
    NULL,
    NULL,
    NULL,
    NULL
};

static void test_begin(){
    test_plaintext_len = sizeof(test_plaintext) - 1;

    int i;
    for (i = 0; i < account_data_max; i++) {
        account_data[i] = NULL;
    }
    account_data_insert_pos = 0;

    get_skissm_plugin()->event_handler = test_event_handler;

    start_mock_server_sending();
}

static void test_end(){
    stop_mock_server_sending();

    int i;
    for (i = 0; i < account_data_max; i++) {
        if (account_data[i] != NULL) {
            skissm__account__free_unpacked(account_data[i], NULL);
            account_data[i] = NULL;
        }
    }
    account_data_insert_pos = 0;
}

static void mock_alice_account(const char *user_name) {
    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_CURVE25519,
        E2EE_PACK_ALG_KEM_CURVE25519,
        E2EE_PACK_ALG_SYMMETRIC_ENCRYPTION_AES256_SHA256
    );
    char *device_id = generate_uuid_str();
    const char *authenticator = "alice@domain.com.tw";
    const char *auth_code = "123456";
    Skissm__RegisterUserResponse *response =
        register_user(
            e2ee_pack_id,
            user_name,
            user_name,
            device_id,
            authenticator,
            auth_code
        );
    assert(safe_strcmp(device_id, response->address->user->device_id));
    printf("Test user registered: \"%s@%s\"\n", response->address->user->user_id, response->address->domain);

    // release
    free(device_id);
    skissm__register_user_response__free_unpacked(response, NULL);
}

static void mock_bob_account(const char *user_name) {
    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_CURVE25519,
        E2EE_PACK_ALG_KEM_CURVE25519,
        E2EE_PACK_ALG_SYMMETRIC_ENCRYPTION_AES256_SHA256
    );
    char *device_id = generate_uuid_str();
    const char *authenticator = "bob@domain.com.tw";
    const char *auth_code = "654321";
    Skissm__RegisterUserResponse *response =
        register_user(
            e2ee_pack_id,
            user_name,
            user_name,
            device_id,
            authenticator,
            auth_code
        );
    assert(safe_strcmp(device_id, response->address->user->device_id));
    printf("Test user registered: \"%s@%s\"\n", response->address->user->user_id, response->address->domain);

    // release
    free(device_id);
    skissm__register_user_response__free_unpacked(response, NULL);
}

static void mock_alice_pqc_account(const char *user_name) {
    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_256F,
        E2EE_PACK_ALG_KEM_KYBER1024,
        E2EE_PACK_ALG_SYMMETRIC_ENCRYPTION_AES256_SHA256
    );
    char *device_id = generate_uuid_str();
    const char *authenticator = "alice@domain.com.tw";
    const char *auth_code = "123456";
    Skissm__RegisterUserResponse *response =
        register_user(
            e2ee_pack_id,
            user_name,
            user_name,
            device_id,
            authenticator,
            auth_code
        );
    assert(safe_strcmp(device_id, response->address->user->device_id));
    printf("Test user registered: \"%s@%s\"\n", response->address->user->user_id, response->address->domain);

    // release
    free(device_id);
    skissm__register_user_response__free_unpacked(response, NULL);
}

static void mock_bob_pqc_account(const char *user_name) {
    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_256F,
        E2EE_PACK_ALG_KEM_KYBER1024,
        E2EE_PACK_ALG_SYMMETRIC_ENCRYPTION_AES256_SHA256
    );
    char *device_id = generate_uuid_str();
    const char *authenticator = "bob@domain.com.tw";
    const char *auth_code = "654321";
    Skissm__RegisterUserResponse *response =
        register_user(
            e2ee_pack_id,
            user_name,
            user_name,
            device_id,
            authenticator,
            auth_code
        );
    assert(safe_strcmp(device_id, response->address->user->device_id));
    printf("Test user registered: \"%s@%s\"\n", response->address->user->user_id, response->address->domain);

    // release
    free(device_id);
    skissm__register_user_response__free_unpacked(response, NULL);
}

static void test_encryption(
    Skissm__E2eeAddress *from_address, const char *to_user_id, const char *to_domain,
    uint8_t *plaintext, size_t plaintext_len
) {
    // send encrypted msg
    Skissm__SendOne2oneMsgResponse *response = NULL;
    response = send_one2one_msg(from_address, to_user_id, to_domain,
        SKISSM__NOTIF_LEVEL__NOTIF_LEVEL_NORMAL,
        plaintext, plaintext_len
    );

    // release
    if (response != NULL)
        skissm__send_one2one_msg_response__free_unpacked(response, NULL);
}

static void test_basic_session(){
    // test start
    printf("test_basic_session begin!!!\n");
    tear_up();
    test_begin();

    mock_alice_account("alice");
    mock_bob_account("bob");

    Skissm__E2eeAddress *alice_address = account_data[0]->address;
    Skissm__E2eeAddress *bob_address = account_data[1]->address;
    char *bob_user_id = bob_address->user->user_id;
    char *bob_domain = bob_address->domain;

    // Alice invites Bob to create a session
    Skissm__InviteResponse *response = invite(alice_address, bob_user_id, bob_domain);
    assert(response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK); // waiting Accept

    sleep(1);
    // load the outbound session
    Skissm__Session *outbound_session = NULL;
    get_skissm_plugin()->db_handler.load_outbound_session(alice_address, bob_address, &outbound_session);
    assert(outbound_session != NULL);
    assert(outbound_session->responded == true);

    // Alice sends an encrypted message to Bob, and Bob decrypts the message
    test_encryption(alice_address, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);

    // test stop
    skissm__invite_response__free_unpacked(response, NULL);
    skissm__session__free_unpacked(outbound_session, NULL);
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_interaction(){
    // test start
    printf("test_interaction begin!!!\n");
    tear_up();
    test_begin();

    mock_alice_account("alice");
    mock_bob_account("bob");

    Skissm__E2eeAddress *alice_address = account_data[0]->address;
    Skissm__E2eeAddress *bob_address = account_data[1]->address;
    char *alice_user_id = alice_address->user->user_id;
    char *alice_domain = alice_address->domain;
    char *bob_user_id = bob_address->user->user_id;
    char *bob_domain = bob_address->domain;

    Skissm__Session *outbound_session_a, *outbound_session_b;

    // Alice invites Bob to create a session
    Skissm__InviteResponse *response = invite(alice_address, bob_user_id, bob_domain);
    assert(response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK); // waiting Accept

    sleep(1);
    // Alice loads the outbound session
    get_skissm_plugin()->db_handler.load_outbound_session(alice_address, bob_address, &outbound_session_a);
    assert(outbound_session_a != NULL);
    assert(outbound_session_a->responded == true);

    // Alice sends an encrypted message to Bob, and Bob decrypts the message
    test_encryption(alice_address, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);

    // Bob sends an encrypted message to Alice, and Alice decrypts the message
    test_encryption(bob_address, alice_user_id, alice_domain, test_plaintext, test_plaintext_len);

    // test stop
    skissm__invite_response__free_unpacked(response, NULL);
    skissm__session__free_unpacked(outbound_session_a, NULL);
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_continual_messages(){
    // test start
    printf("test_continual_messages begin!!!\n");
    tear_up();
    test_begin();

    mock_alice_account("alice");
    mock_bob_account("bob");

    Skissm__E2eeAddress *alice_address = account_data[0]->address;
    Skissm__E2eeAddress *bob_address = account_data[1]->address;
    char *bob_user_id = bob_address->user->user_id;
    char *bob_domain = bob_address->domain;

    // Alice invites Bob to create a session
    Skissm__InviteResponse *response = invite(alice_address, bob_user_id, bob_domain);
    assert(response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK); // waiting Accept

    sleep(1);

    // Alice sends an encrypted message to Bob, and Bob decrypts the message
    int i;
    for (i = 0; i < 3000; i++){
        // uint8_t plaintext[64];
        // size_t plaintext_len = snprintf((char *)plaintext, 64, "[%4d]This message will be sent a lot of times.", i);
        test_encryption(alice_address, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);
    }

    // test stop
    skissm__invite_response__free_unpacked(response, NULL);
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_multiple_devices(){
    // test start
    printf("test_multiple_devices begin!!!\n");
    tear_up();
    test_begin();

    mock_alice_account("Alice");
    mock_alice_account("Alice");
    mock_alice_account("Alice");

    // Alice's user_id should be the same
    assert(strcmp(account_data[0]->address->user->user_id, account_data[1]->address->user->user_id) == 0);
    assert(strcmp(account_data[0]->address->user->user_id, account_data[2]->address->user->user_id) == 0);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_one_to_many(){
    // test start
    printf("test_one_to_many begin!!!\n");
    tear_up();
    test_begin();

    mock_alice_account("Alice");
    mock_bob_account("Bob");
    mock_bob_account("Bob");
    mock_bob_account("Bob");

    sleep(3);

    // Bob's user_id should be the same
    assert(strcmp(account_data[1]->address->user->user_id, account_data[2]->address->user->user_id) == 0);
    assert(strcmp(account_data[1]->address->user->user_id, account_data[3]->address->user->user_id) == 0);

    Skissm__E2eeAddress *alice_address = account_data[0]->address;
    char *bob_user_id = account_data[1]->address->user->user_id;
    char *bob_domain = account_data[1]->address->domain;

    // Alice invites Bob to create a session
    Skissm__InviteResponse *response = invite(alice_address, bob_user_id, bob_domain);
    assert(response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK); // waiting Accept

    sleep(3);
    // load the outbound sessions
    Skissm__Session **outbound_sessions = NULL;
    size_t outbound_sessions_num = get_skissm_plugin()->db_handler.load_outbound_sessions(alice_address, bob_user_id, bob_domain, &outbound_sessions);
    assert(outbound_sessions_num == 3);

    // load the inbound sessions
    Skissm__Session **inbound_sessions = (Skissm__Session **)malloc(sizeof(Skissm__Session *) * 3);
    get_skissm_plugin()->db_handler.load_inbound_session(outbound_sessions[0]->session_id, outbound_sessions[0]->their_address, &(inbound_sessions[0]));
    get_skissm_plugin()->db_handler.load_inbound_session(outbound_sessions[1]->session_id, outbound_sessions[1]->their_address, &(inbound_sessions[1]));
    get_skissm_plugin()->db_handler.load_inbound_session(outbound_sessions[2]->session_id, outbound_sessions[2]->their_address, &(inbound_sessions[2]));

    // check if the outbound sessions and inbound sessions match
    Skissm__Session *outbound_session, *inbound_session;
    outbound_session = outbound_sessions[0];
    inbound_session = inbound_sessions[0];
    assert(compare_protobuf(&(outbound_session->ratchet->receiver_chain->chain_key->shared_key), &(inbound_session->ratchet->sender_chain->chain_key->shared_key)));
    outbound_session = outbound_sessions[1];
    inbound_session = inbound_sessions[1];
    assert(compare_protobuf(&(outbound_session->ratchet->receiver_chain->chain_key->shared_key), &(inbound_session->ratchet->sender_chain->chain_key->shared_key)));
    outbound_session = outbound_sessions[2];
    inbound_session = inbound_sessions[2];
    assert(compare_protobuf(&(outbound_session->ratchet->receiver_chain->chain_key->shared_key), &(inbound_session->ratchet->sender_chain->chain_key->shared_key)));

    // Alice sends an encrypted message to Bob, and Bob decrypts the message
    test_encryption(alice_address, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);

    // test stop
    skissm__invite_response__free_unpacked(response, NULL);
    size_t i;
    for (i = 0; i < outbound_sessions_num; i++) {
        skissm__session__free_unpacked(outbound_sessions[i], NULL);
        outbound_sessions[i] = NULL;
        skissm__session__free_unpacked(inbound_sessions[i], NULL);
        inbound_sessions[i] = NULL;
    }
    free(outbound_sessions);
    free(inbound_sessions);
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_many_to_one() {
    // test start
    printf("test_many_to_one begin!!!\n");
    tear_up();
    test_begin();

    mock_alice_account("Alice");
    mock_alice_account("Alice");
    mock_alice_account("Alice");
    mock_bob_account("Bob");

    Skissm__E2eeAddress *device_1 = account_data[0]->address;
    Skissm__E2eeAddress *device_2 = account_data[1]->address;
    Skissm__E2eeAddress *device_3 = account_data[2]->address;

    Skissm__E2eeAddress *bob_address = account_data[3]->address;
    char *bob_user_id = bob_address->user->user_id;
    char *bob_domain = bob_address->domain;

    Skissm__Session **outbound_sessions = (Skissm__Session **)malloc(sizeof(Skissm__Session *) * 3);

    // Alice invites Bob to create a session
    Skissm__InviteResponse *response = invite(device_1, bob_user_id, bob_domain);

    sleep(1);
    // Alice sends an encrypted message to Bob, and Bob decrypts the message
    test_encryption(device_1, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);

    // test stop
    skissm__invite_response__free_unpacked(response, NULL);
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_many_to_many() {
    // test start
    printf("test_many_to_many begin!!!\n");
    tear_up();
    test_begin();

    mock_alice_account("Alice");
    mock_alice_account("Alice");
    mock_alice_account("Alice");
    mock_bob_account("Bob");
    mock_bob_account("Bob");
    mock_bob_account("Bob");

    Skissm__E2eeAddress *alice_address_1 = account_data[0]->address;
    Skissm__E2eeAddress *alice_address_2 = account_data[1]->address;
    Skissm__E2eeAddress *alice_address_3 = account_data[2]->address;
    char *alice_user_id = alice_address_1->user->user_id;
    char *alice_domain = alice_address_1->domain;
    Skissm__E2eeAddress *bob_address_1 = account_data[3]->address;
    Skissm__E2eeAddress *bob_address_2 = account_data[4]->address;
    Skissm__E2eeAddress *bob_address_3 = account_data[5]->address;
    char *bob_user_id = bob_address_1->user->user_id;
    char *bob_domain = bob_address_1->domain;

    // Alice invites Bob to create a session
    Skissm__InviteResponse *response = invite(alice_address_1, bob_user_id, bob_domain);

    sleep(3);
    // Alice sends an encrypted message to Bob, and Bob decrypts the message
    test_encryption(alice_address_1, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);

    sleep(1);
    // Bob sends an encrypted message to Alice, and Alice decrypts the message
    test_encryption(bob_address_1, alice_user_id, alice_domain, test_plaintext, test_plaintext_len);

    // test stop
    skissm__invite_response__free_unpacked(response, NULL);
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_basic_pqc_session(){
    // test start
    printf("test_basic_pqc_session begin!!!\n");
    tear_up();
    test_begin();

    mock_alice_pqc_account("alice");
    mock_bob_pqc_account("bob");

    Skissm__E2eeAddress *alice_address = account_data[0]->address;
    Skissm__E2eeAddress *bob_address = account_data[1]->address;
    char *bob_user_id = bob_address->user->user_id;
    char *bob_domain = bob_address->domain;

    // Alice invites Bob to create a session
    Skissm__InviteResponse *response = invite(alice_address, bob_user_id, bob_domain);
    assert(response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK); // waiting Accept

    sleep(1);
    // Alice sends an encrypted message to Bob, and Bob decrypts the message
    test_encryption(alice_address, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);

    // test stop
    skissm__invite_response__free_unpacked(response, NULL);
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_pqc_many_to_many() {
    // test start
    printf("test_pqc_many_to_many begin!!!\n");
    tear_up();
    test_begin();

    mock_alice_pqc_account("Alice");
    mock_alice_pqc_account("Alice");
    mock_alice_pqc_account("Alice");
    mock_bob_pqc_account("Bob");
    mock_bob_pqc_account("Bob");
    mock_bob_pqc_account("Bob");

    sleep(2);

    Skissm__E2eeAddress *alice_address_1 = account_data[0]->address;
    Skissm__E2eeAddress *alice_address_2 = account_data[1]->address;
    Skissm__E2eeAddress *alice_address_3 = account_data[2]->address;
    char *alice_user_id = alice_address_1->user->user_id;
    char *alice_domain = alice_address_1->domain;
    Skissm__E2eeAddress *bob_address_1 = account_data[3]->address;
    Skissm__E2eeAddress *bob_address_2 = account_data[4]->address;
    Skissm__E2eeAddress *bob_address_3 = account_data[5]->address;
    char *bob_user_id = bob_address_1->user->user_id;
    char *bob_domain = bob_address_1->domain;

    sleep(2);
    // Alice invites Bob to create a session
    Skissm__InviteResponse *response = invite(alice_address_1, bob_user_id, bob_domain);

    sleep(1);
    // Alice sends an encrypted message to Bob, and Bob decrypts the message
    test_encryption(alice_address_1, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);

    sleep(1);
    // Bob sends an encrypted message to Alice, and Alice decrypts the message
    test_encryption(bob_address_1, alice_user_id, alice_domain, test_plaintext, test_plaintext_len);

    // test stop
    skissm__invite_response__free_unpacked(response, NULL);
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_change_devices() {
    // test start
    printf("test_change_devices begin!!!\n");
    tear_up();
    test_begin();

    mock_alice_pqc_account("Alice");
    mock_alice_pqc_account("Alice");
    mock_bob_pqc_account("Bob");
    mock_bob_pqc_account("Bob");

    sleep(2);

    Skissm__E2eeAddress *alice_address_1 = account_data[0]->address;
    Skissm__E2eeAddress *alice_address_2 = account_data[1]->address;
    char *alice_user_id = alice_address_1->user->user_id;
    char *alice_domain = alice_address_1->domain;
    Skissm__E2eeAddress *bob_address_1 = account_data[2]->address;
    Skissm__E2eeAddress *bob_address_2 = account_data[3]->address;
    char *bob_user_id = bob_address_1->user->user_id;
    char *bob_domain = bob_address_1->domain;

    sleep(2);
    // Alice invites Bob to create a session
    Skissm__InviteResponse *response = invite(alice_address_1, bob_user_id, bob_domain);

    sleep(2);

    // Alice adds a new device
    mock_alice_pqc_account("Alice");

    sleep(1);
    // Alice sends a message to Bob
    test_encryption(alice_address_1, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);

    sleep(1);

    // Bob sends a message to Alice
    test_encryption(bob_address_1, alice_user_id, alice_domain, test_plaintext, test_plaintext_len);

    // test stop
    skissm__invite_response__free_unpacked(response, NULL);
    test_end();
    tear_down();
    printf("====================================\n");
}

int main() {
    // test_basic_session();
    test_interaction();
    test_continual_messages();
    // test_multiple_devices();
    // test_one_to_many();
    // test_many_to_one();
    // test_many_to_many();
    // test_basic_pqc_session();
    test_pqc_many_to_many();
    test_change_devices();

    return 0;
}
