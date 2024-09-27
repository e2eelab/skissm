/**
 * @file
 * @copyright © 2020-2021 by Academia Sinica
 * @brief session test
 *
 * @page test_session session documentation
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
 * 
 * @section test_basic_session
 * Alice and Bob establish their session. Alice sends a message to Bob. Bob should decrypt the message successfully.
 * 
 * @section test_interaction
 * Alice and Bob establish their session. Alice sends a message to Bob. Next, Bob sends a message to Alice.
 * 
 * @section test_continual_messages
 * Alice sends 3000 messages to Bob.
 * 
 * @section test_multiple_devices
 * 
 * 
 * @section test_one_to_many
 * Alice has one device, and Bob has three devices. Alice sends a message to Bob.
 * 
 * @section test_many_to_one
 * Alice has three devices, and Bob has one device. Alice sends a message to Bob.
 * 
 * @section test_many_to_many
 * Both Alice and Bob have three devices. Alice sends a message to Bob.
 * 
 * @section test_change_devices
 * Both Alice and Bob have two devices. Alice adds a new device. Then Alice sends a message to Bob. Next, Bob sends a message to Alice.
 * 
 * 
 * 
 * @defgroup session_int session integration test
 * @ingroup Integration
 * This includes integration tests about session.
 * 
 * @defgroup session_test_basic_session basic session test
 * @ingroup session_int
 * @{
 * @section sec31001 Test Case ID
 * v1.0is01
 * @section sec31002 Test Case Title
 * test_basic_session
 * @section sec31003 Test Description
 * Alice and Bob establish their session. Alice sends a message to Bob. Bob should decrypt the message successfully.
 * @section sec31004 Test Objectives
 * To assure that the invitee can decrypt the inviter's message once the session is completed.
 * @section sec31005 Preconditions
 * @section sec31006 Test Steps
 * Step 1: Alice invites Bob to create a session.\n
 * Step 2: Alice sends a message to Bob.\n
 * Step 3: Bob decrypts the message.
 * @section sec31007 Expected Results
 * The output of the decrypted message.
 * @}
 * 
 * @defgroup session_test_interaction interaction test
 * @ingroup session_int
 * @{
 * @section sec31101 Test Case ID
 * v1.0is02
 * @section sec31102 Test Case Title
 * test_interaction
 * @section sec31103 Test Description
 * Alice and Bob establish their session. Alice sends a message to Bob. Next, Bob sends a message to Alice.
 * @section sec31104 Test Objectives
 * To assure that both of the inviter and the invitee can decrypt the other's message.
 * @section sec31105 Preconditions
 * @section sec31106 Test Steps
 * Step 1: Alice invites Bob to create a session.\n
 * Step 2: Alice sends a message to Bob.\n
 * Step 3: Bob decrypts the message.\n
 * Step 4: Bob sends a message to Alice.\n
 * Step 5: Alice decrypts the message.
 * @section sec31107 Expected Results
 * The output of the decrypted messages.
 * @}
 * 
 * @defgroup session_test_continual_messages continual messages test
 * @ingroup session_int
 * @{
 * @section sec31201 Test Case ID
 * v1.0is03
 * @section sec31202 Test Case Title
 * test_continual_messages
 * @section sec31203 Test Description
 * Alice sends 3000 messages to Bob.
 * @section sec31204 Test Objectives
 * To assure that a large number of messages can be decrypted.
 * @section sec31205 Preconditions
 * @section sec31206 Test Steps
 * Step 1: Alice invites Bob to create a session.\n
 * Step 2: Alice sends 3000 messages to Bob.\n
 * Step 3: Bob decrypts all of these messages.
 * @section sec31207 Expected Results
 * The output of the decrypted messages.
 * @}
 * 
 * @defgroup session_test_one_to_many multiple devices test: one to many
 * @ingroup session_int
 * @{
 * @section sec31401 Test Case ID
 * v1.0is04
 * @section sec31402 Test Case Title
 * test_one_to_many
 * @section sec31403 Test Description
 * Alice has one device, and Bob has three devices. Alice sends a message to Bob.
 * @section sec31404 Test Objectives
 * To assure that the session mechanism is applicable to multiple devices.
 * @section sec31405 Preconditions
 * @section sec31406 Test Steps
 * Step 1: Alice invites Bob to create a session.\n
 * Step 2: Alice sends a message to Bob.\n
 * Step 3: Bob decrypts the message, using all of his devices.
 * @section sec31407 Expected Results
 * The output of the decrypted messages.
 * @}
 * 
 * @defgroup session_test_many_to_one multiple devices test: many to one
 * @ingroup session_int
 * @{
 * @section sec31501 Test Case ID
 * v1.0is05
 * @section sec31502 Test Case Title
 * test_many_to_one
 * @section sec31503 Test Description
 * Alice has three devices, and Bob has one device. Alice sends a message to Bob.
 * @section sec31504 Test Objectives
 * To assure that the session mechanism is applicable to multiple devices.
 * @section sec31505 Preconditions
 * @section sec31506 Test Steps
 * Step 1: Alice invites Bob to create a session.\n
 * Step 2: Alice sends a message to Bob with one of her devices.\n
 * Step 3: Bob decrypts the message.
 * @section sec31507 Expected Results
 * The output of the decrypted messages.
 * @}
 * 
 * @defgroup session_test_many_to_many multiple devices test: many to many
 * @ingroup session_int
 * @{
 * @section sec31601 Test Case ID
 * v1.0is06
 * @section sec31602 Test Case Title
 * test_many_to_many
 * @section sec31603 Test Description
 * Both Alice and Bob have three devices. Alice sends a message to Bob.
 * @section sec31604 Test Objectives
 * To assure that the session mechanism is applicable to multiple devices.
 * @section sec31605 Preconditions
 * @section sec31606 Test Steps
 * Step 1: Alice invites Bob to create a session.\n
 * Step 2: Alice sends a message to Bob with one of her devices.\n
 * Step 3: Bob decrypts the message, using all of his devices.
 * @section sec31607 Expected Results
 * The output of the decrypted messages.
 * @}
 * 
 * @defgroup session_test_change_devices change devices test
 * @ingroup session_int
 * @{
 * @section sec31701 Test Case ID
 * v1.0is07
 * @section sec31702 Test Case Title
 * test_change_devices
 * @section sec31703 Test Description
 * Both Alice and Bob have two devices. Alice adds a new device. Then Alice sends a message to Bob. Next, Bob sends a message to Alice.
 * @section sec31704 Test Objectives
 * To assure that the session can be used once one of the both sides adds a new device.
 * @section sec31705 Preconditions
 * @section sec31706 Test Steps
 * Step 1: Alice invites Bob to create a session.\n
 * Step 2: Alice adds a new device.\n
 * Step 3: Alice uses the old device to send a message to Bob, and then Bob decrypts the message.\n
 * Step 4: Bob sends a message to Alice, and then Alice decrypts the message.
 * @section sec31707 Expected Results
 * The output of the decrypted messages.
 * @}
 * 
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
    uint32_t e2ee_pack_id = gen_e2ee_pack_id_pqc();
    char *device_id = generate_uuid_str();
    const char *authenticator = "alice@domain.com.tw";
    const char *auth_code = "123456";
    Skissm__RegisterUserResponse *response = NULL;
    int ret = register_user(
        &response, e2ee_pack_id, user_name, user_name, device_id, authenticator, auth_code
    );
    assert(ret == 0);
    printf("Test user registered: \"%s@%s\"\n", response->address->user->user_id, response->address->domain);

    // release
    free(device_id);
    skissm__register_user_response__free_unpacked(response, NULL);
}

static void mock_bob_account(const char *user_name) {
    uint32_t e2ee_pack_id = gen_e2ee_pack_id_pqc();
    char *device_id = generate_uuid_str();
    const char *authenticator = "bob@domain.com.tw";
    const char *auth_code = "654321";
    Skissm__RegisterUserResponse *response = NULL;
    int ret = register_user(
        &response, e2ee_pack_id, user_name, user_name, device_id, authenticator, auth_code
    );
    assert(ret == 0);
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

static void test_basic_session() {
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

    sleep(1);
    // Alice sends an encrypted message to Bob, and Bob decrypts the message
    test_encryption(alice_address, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);

    // test stop
    skissm__invite_response__free_unpacked(response, NULL);
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_interaction() {
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

    // Alice invites Bob to create a session
    Skissm__InviteResponse *response = invite(alice_address, bob_user_id, bob_domain);

    sleep(1);
    // Alice sends an encrypted message to Bob, and Bob decrypts the message
    test_encryption(alice_address, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);

    // Bob sends an encrypted message to Alice, and Alice decrypts the message
    test_encryption(bob_address, alice_user_id, alice_domain, test_plaintext, test_plaintext_len);

    // test stop
    skissm__invite_response__free_unpacked(response, NULL);
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_continual_messages() {
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

    sleep(1);
    // Alice sends an encrypted message to Bob, and Bob decrypts the message
    int i;
    for (i = 0; i < 3000; i++){
        test_encryption(alice_address, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);
    }

    // test stop
    skissm__invite_response__free_unpacked(response, NULL);
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_one_to_many() {
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

    sleep(3);
    // Alice sends an encrypted message to Bob, and Bob decrypts the message
    test_encryption(alice_address, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);

    // test stop
    skissm__invite_response__free_unpacked(response, NULL);
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

    mock_alice_account("Alice");
    mock_alice_account("Alice");
    mock_bob_account("Bob");
    mock_bob_account("Bob");

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
    mock_alice_account("Alice");

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
    test_basic_session();
    test_interaction();
    test_continual_messages();
    test_one_to_many();
    test_many_to_one();
    test_many_to_many();
    test_change_devices();

    return 0;
}
