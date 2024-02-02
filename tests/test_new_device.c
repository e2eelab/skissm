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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "skissm/e2ee_client.h"
#include "skissm/mem_util.h"

#include "mock_server_sending.h"
#include "test_util.h"
#include "test_plugin.h"

#define account_data_max 10
#define group_max 10

static Skissm__Account *account_data[account_data_max];

static uint8_t account_data_insert_pos;

static uint8_t test_plaintext[] = "New devices test!!!";

static void on_log(Skissm__E2eeAddress *user_address, LogCode log_code, const char *log_msg) {
    print_log((char *)log_msg, log_code);
}

static void on_user_registered(Skissm__Account *account){
    copy_account_from_account(&(account_data[account_data_insert_pos]), account);
    account_data_insert_pos++;
}

static void on_inbound_session_invited(Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *from) {
    printf("on_inbound_session_invited\n");
}

static void on_inbound_session_ready(Skissm__E2eeAddress *user_address, Skissm__Session *inbound_session){
    if (inbound_session->f2f == true) {
        printf("the face-to-face inbound session is ready\n");
    } else {
        printf("on_inbound_session_ready\n");
    }
}

static void on_outbound_session_ready(Skissm__E2eeAddress *user_address, Skissm__Session *outbound_session){
    if (outbound_session->f2f == true) {
        printf("the face-to-face outbound session is ready\n");
    } else {
        printf("on_outbound_session_ready\n");
    }
}

static void on_one2one_msg_received(
    Skissm__E2eeAddress *user_address, 
    Skissm__E2eeAddress *from_address,
    Skissm__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    assert(memcmp(plaintext, test_plaintext, plaintext_len) == 0);
    printf("%s received the message!\n", to_address->user->user_name);
}

static void on_other_device_msg_received(
    Skissm__E2eeAddress *user_address, 
    Skissm__E2eeAddress *from_address,
    Skissm__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    assert(memcmp(plaintext, test_plaintext, plaintext_len) == 0);
    printf("%s received the message from other devices!\n", to_address->user->user_name);
}

static void on_group_msg_received(Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *group_address, uint8_t *plaintext, size_t plaintext_len) {
    assert(memcmp(plaintext, test_plaintext, plaintext_len) == 0);
    printf("%s received the message from a group member!\n", user_address->user->user_name);
}

static void on_group_created(
    Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *group_address, const char *group_name,
    Skissm__GroupMember **group_members, size_t group_members_num
) {
    print_msg("on_group_created: group_name", (uint8_t *)group_name, strlen(group_name));
}

static void on_group_members_added(
    Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *group_address, const char *group_name,
    Skissm__GroupMember **group_members, size_t group_members_num,
    Skissm__GroupMember **added_group_members, size_t added_group_members_num
) {
    print_msg("on_group_members_added: group_name", (uint8_t *)group_name, strlen(group_name));
    size_t i;
    for (i = 0; i < added_group_members_num; i++) {
        print_msg("    member_id", (uint8_t *)(added_group_members[i]->user_id), strlen(added_group_members[i]->user_id));
    }
}

static void on_group_members_removed(
    Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *group_address, const char *group_name,
    Skissm__GroupMember **group_members, size_t group_members_num,
    Skissm__GroupMember **removed_group_members, size_t removed_group_members_num
) {
    print_msg("on_group_members_removed: group_name", (uint8_t *)group_name, strlen(group_name));
    size_t i;
    for (i = 0; i < removed_group_members_num; i++) {
        print_msg("    member_id", (uint8_t *)(removed_group_members[i]->user_id), strlen(removed_group_members[i]->user_id));
    }
}

static skissm_event_handler_t test_event_handler = {
    on_log,
    on_user_registered,
    on_inbound_session_invited,
    on_inbound_session_ready,
    on_outbound_session_ready,
    on_one2one_msg_received,
    on_other_device_msg_received,
    on_group_msg_received,
    on_group_created,
    on_group_members_added,
    on_group_members_removed
};

static void test_begin(){
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
    const char *device_id = generate_uuid_str();
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
}

static void mock_bob_account(const char *user_name) {
    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_CURVE25519,
        E2EE_PACK_ALG_KEM_CURVE25519,
        E2EE_PACK_ALG_SYMMETRIC_ENCRYPTION_AES256_SHA256
    );
    const char *device_id = generate_uuid_str();
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
}

static void mock_claire_account(const char *user_name) {
    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_CURVE25519,
        E2EE_PACK_ALG_KEM_CURVE25519,
        E2EE_PACK_ALG_SYMMETRIC_ENCRYPTION_AES256_SHA256
    );
    const char *device_id = generate_uuid_str();
    const char *authenticator = "claire@domain.com.tw";
    const char *auth_code = "987654";
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

static void mock_user_pqc_account(const char *user_name, const char *authenticator, const char *auth_code) {
    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_256F,
        E2EE_PACK_ALG_KEM_KYBER1024,
        E2EE_PACK_ALG_SYMMETRIC_ENCRYPTION_AES256_SHA256
    );
    char *device_id = generate_uuid_str();
    Skissm__RegisterUserResponse *response = register_user(
        e2ee_pack_id, user_name, user_name, device_id, authenticator, auth_code
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
    response = send_one2one_msg(
        from_address, to_user_id, to_domain,
        SKISSM__NOTIF_LEVEL__NOTIF_LEVEL_NORMAL,
        plaintext, plaintext_len);

    // release
    skissm__send_one2one_msg_response__free_unpacked(response, NULL);
}

static void test_group_encryption(
    Skissm__E2eeAddress *sender_address, Skissm__E2eeAddress *group_address,
    uint8_t *plaintext_data, size_t plaintext_data_len
) {
    Skissm__SendGroupMsgResponse *response = send_group_msg(
        sender_address, group_address,
        SKISSM__NOTIF_LEVEL__NOTIF_LEVEL_NORMAL,
        plaintext_data, plaintext_data_len);
    
    // release
    skissm__send_group_msg_response__free_unpacked(response, NULL);
}

static void test_two_members_session() {
    // test start
    printf("test_two_members_session begin!!!\n");

    size_t test_plaintext_len = sizeof(test_plaintext) - 1;

    tear_up();
    test_begin();

    mock_alice_account("alice");
    mock_bob_account("bob");

    Skissm__E2eeAddress *alice_address = account_data[0]->address;
    char *alice_user_id = alice_address->user->user_id;
    char *alice_domain = alice_address->domain;
    Skissm__E2eeAddress *bob_address = account_data[1]->address;
    char *bob_user_id = bob_address->user->user_id;
    char *bob_domain = bob_address->domain;

    // Alice invites Bob to create a session
    Skissm__InviteResponse *response_1 = invite(alice_address, bob_user_id, bob_domain);

    sleep(1);

    // Alice add a new device
    mock_alice_account("alice");

    Skissm__E2eeAddress *device_2 = account_data[2]->address;

    sleep(1);
    // Alice sends an encrypted message to Bob
    test_encryption(device_2, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);

    // release
    skissm__invite_response__free_unpacked(response_1, NULL);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_two_members_four_devices() {
    // test start
    printf("test_two_members_four_devices begin!!!\n");

    size_t test_plaintext_len = sizeof(test_plaintext) - 1;

    tear_up();
    test_begin();

    mock_alice_pqc_account("alice");
    mock_bob_pqc_account("bob");

    Skissm__E2eeAddress *alice_device_1 = account_data[0]->address;
    char *alice_user_id = alice_device_1->user->user_id;
    char *alice_domain = alice_device_1->domain;
    Skissm__E2eeAddress *bob_device_1 = account_data[1]->address;
    char *bob_user_id = bob_device_1->user->user_id;
    char *bob_domain = bob_device_1->domain;

    // Alice invites Bob to create a session
    Skissm__InviteResponse *response_1 = invite(alice_device_1, bob_user_id, bob_domain);

    sleep(3);

    // Alice sends a message to Bob
    test_encryption(alice_device_1, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);

    // Bob sends a message to Alice
    test_encryption(bob_device_1, alice_user_id, alice_domain, test_plaintext, test_plaintext_len);

    sleep(2);

    // Alice adds a new device
    mock_alice_pqc_account("alice");

    Skissm__E2eeAddress *alice_device_2 = account_data[2]->address;

    sleep(1);

    // Alice uses the first device to send a message
    test_encryption(alice_device_1, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);
    // Alice uses the second device to send a message
    test_encryption(alice_device_2, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);
    // Bob sends a message
    test_encryption(bob_device_1, alice_user_id, alice_domain, test_plaintext, test_plaintext_len);

    sleep(2);

    // Bob adds a new device
    mock_bob_pqc_account("bob");

    Skissm__E2eeAddress *bob_device_2 = account_data[3]->address;

    sleep(1);

    // Bob uses the first device to send a message
    test_encryption(bob_device_1, alice_user_id, alice_domain, test_plaintext, test_plaintext_len);
    // Bob uses the second device to send a message
    test_encryption(bob_device_2, alice_user_id, alice_domain, test_plaintext, test_plaintext_len);
    // Alice uses the first device to send a message
    test_encryption(alice_device_1, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);
    // Alice uses the second device to send a message
    test_encryption(alice_device_2, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);

    // release
    skissm__invite_response__free_unpacked(response_1, NULL);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_three_members_group_session() {
    // test start
    printf("test_three_members_group_session begin!!!\n");

    size_t test_plaintext_len = sizeof(test_plaintext) - 1;

    tear_up();
    test_begin();

    // prepare account
    mock_alice_account("alice");
    mock_bob_account("bob");
    mock_claire_account("claire");

    Skissm__E2eeAddress *alice_address = account_data[0]->address;
    char *alice_user_id = alice_address->user->user_id;
    char *alice_domain = alice_address->domain;
    Skissm__E2eeAddress *bob_address = account_data[1]->address;
    char *bob_user_id = bob_address->user->user_id;
    char *bob_domain = bob_address->domain;
    Skissm__E2eeAddress *claire_address = account_data[2]->address;
    char *claire_user_id = claire_address->user->user_id;
    char *claire_domain = claire_address->domain;

    // Alice, Bob and Claire invite each others
    Skissm__InviteResponse *response_1 = invite(alice_address, bob_user_id, bob_domain);
    Skissm__InviteResponse *response_2 = invite(alice_address, claire_user_id, claire_domain);
    Skissm__InviteResponse *response_3 = invite(bob_address, claire_user_id, claire_domain);

    sleep(3);
    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 3);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(alice_user_id);
    group_members[0]->domain = strdup(alice_domain);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(bob_user_id);
    group_members[1]->domain = strdup(bob_domain);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the third group member is Claire
    group_members[2] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[2]);
    group_members[2]->user_id = strdup(claire_user_id);
    group_members[2]->domain = strdup(claire_domain);
    group_members[2]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(alice_address, "Group name", group_members, 3);

    sleep(2);

    // Alice adds a new device
    mock_alice_account("alice");

    Skissm__E2eeAddress *alice_address_2 = account_data[3]->address;

    sleep(1);
    // Alice sends a message to the group via the second device
    printf("Alice sent a message.\n");
    test_group_encryption(alice_address_2, create_group_response->group_address, test_plaintext, test_plaintext_len);

    // Claire sends a message to the group
    printf("Claire sent a message.\n");
    test_group_encryption(claire_address, create_group_response->group_address, test_plaintext, test_plaintext_len);

    // release
    skissm__invite_response__free_unpacked(response_1, NULL);
    skissm__invite_response__free_unpacked(response_2, NULL);
    skissm__invite_response__free_unpacked(response_3, NULL);
    skissm__group_member__free_unpacked(group_members[0], NULL);
    skissm__group_member__free_unpacked(group_members[1], NULL);
    skissm__group_member__free_unpacked(group_members[2], NULL);
    free(group_members);
    skissm__create_group_response__free_unpacked(create_group_response, NULL);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_multiple_devices() {
    // test start
    printf("test_several_members_and_groups begin!!!\n");

    size_t test_plaintext_len = sizeof(test_plaintext) - 1;

    tear_up();
    test_begin();

    // prepare account
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");

    Skissm__E2eeAddress *alice_address_1 = account_data[0]->address;
    char *alice_user_id = alice_address_1->user->user_id;
    char *alice_domain = alice_address_1->domain;
    Skissm__E2eeAddress *alice_address_2 = account_data[1]->address;

    Skissm__E2eeAddress *bob_address = account_data[2]->address;
    char *bob_user_id = bob_address->user->user_id;
    char *bob_domain = bob_address->domain;

    Skissm__InviteResponse *response_1 = invite(alice_address_1, bob_user_id, bob_domain);

    sleep(3);

    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");

    sleep(3);

    test_encryption(bob_address, alice_user_id, alice_domain, test_plaintext, test_plaintext_len);

    // release
    skissm__invite_response__free_unpacked(response_1, NULL);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_several_members_and_groups() {
    // test start
    printf("test_several_members_and_groups begin!!!\n");

    size_t test_plaintext_len = sizeof(test_plaintext) - 1;

    tear_up();
    test_begin();

    // prepare account
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");
    mock_user_pqc_account("Claire", "claire@domain.com.tw", "345678");
    mock_user_pqc_account("Claire", "claire@domain.com.tw", "345678");
    mock_user_pqc_account("David", "david@domain.com.tw", "456789");
    mock_user_pqc_account("Emily", "emily@domain.com.tw", "567890");
    mock_user_pqc_account("Emily", "emily@domain.com.tw", "567890");
    mock_user_pqc_account("Frank", "frank@domain.com.tw", "678901");

    sleep(5);

    Skissm__E2eeAddress *alice_address_1 = account_data[0]->address;
    char *alice_user_id = alice_address_1->user->user_id;
    char *alice_domain = alice_address_1->domain;
    Skissm__E2eeAddress *alice_address_2 = account_data[1]->address;

    Skissm__E2eeAddress *bob_address = account_data[2]->address;
    char *bob_user_id = bob_address->user->user_id;
    char *bob_domain = bob_address->domain;

    Skissm__E2eeAddress *claire_address_1 = account_data[3]->address;
    char *claire_user_id = claire_address_1->user->user_id;
    char *claire_domain = claire_address_1->domain;
    Skissm__E2eeAddress *claire_address_2 = account_data[4]->address;

    Skissm__E2eeAddress *david_address = account_data[5]->address;
    char *david_user_id = david_address->user->user_id;
    char *david_domain = david_address->domain;

    Skissm__E2eeAddress *emily_address_1 = account_data[6]->address;
    char *emily_user_id = emily_address_1->user->user_id;
    char *emily_domain = emily_address_1->domain;
    Skissm__E2eeAddress *emily_address_2 = account_data[7]->address;

    Skissm__E2eeAddress *frank_address = account_data[8]->address;
    char *frank_user_id = frank_address->user->user_id;
    char *frank_domain = frank_address->domain;

    // some invitation
    Skissm__InviteResponse *response_1 = invite(alice_address_1, bob_user_id, bob_domain);
    Skissm__InviteResponse *response_2 = invite(alice_address_2, claire_user_id, claire_domain);

    Skissm__InviteResponse *response_3 = invite(david_address, emily_user_id, emily_domain);

    Skissm__InviteResponse *response_4 = invite(frank_address, alice_user_id, alice_domain);
    Skissm__InviteResponse *response_5 = invite(emily_address_2, frank_user_id, frank_domain);

    sleep(3);

    // Alice, Bob and Claire create a group
    Skissm__GroupMember **group_members_1 = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 3);
    group_members_1[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members_1[0]);
    group_members_1[0]->user_id = strdup(alice_user_id);
    group_members_1[0]->domain = strdup(alice_domain);
    group_members_1[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    group_members_1[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members_1[1]);
    group_members_1[1]->user_id = strdup(bob_user_id);
    group_members_1[1]->domain = strdup(bob_domain);
    group_members_1[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    group_members_1[2] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members_1[2]);
    group_members_1[2]->user_id = strdup(claire_user_id);
    group_members_1[2]->domain = strdup(claire_domain);
    group_members_1[2]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    Skissm__CreateGroupResponse *create_group_response_1 = create_group(alice_address_1, "The first group", group_members_1, 3);

    sleep(2);

    // Alice, Emily and Frank create a group
    Skissm__GroupMember **group_members_2 = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 3);
    group_members_2[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members_2[0]);
    group_members_2[0]->user_id = strdup(frank_user_id);
    group_members_2[0]->domain = strdup(frank_domain);
    group_members_2[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    group_members_2[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members_2[1]);
    group_members_2[1]->user_id = strdup(emily_user_id);
    group_members_2[1]->domain = strdup(emily_domain);
    group_members_2[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    group_members_2[2] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members_2[2]);
    group_members_2[2]->user_id = strdup(alice_user_id);
    group_members_2[2]->domain = strdup(alice_domain);
    group_members_2[2]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    Skissm__CreateGroupResponse *create_group_response_2 = create_group(frank_address, "The second group", group_members_2, 3);

    sleep(2);

    // Alice adds a new device
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");

    // Emily adds a new device
    mock_user_pqc_account("Emily", "emily@domain.com.tw", "567890");

    sleep(3);

    // Bob sends a message to Alice
    printf("Bob sent a message to Alice.\n");
    test_encryption(bob_address, alice_user_id, alice_domain, test_plaintext, test_plaintext_len);

    // Alice sends a message to the first group
    printf("Alice sent a message to the first group.\n");
    test_group_encryption(alice_address_1, create_group_response_1->group_address, test_plaintext, test_plaintext_len);

    // Frank sends a message to the second group
    printf("Frank sent a message to the second group.\n");
    test_group_encryption(frank_address, create_group_response_2->group_address, test_plaintext, test_plaintext_len);

    // Emily sends a message to David
    printf("Emily sent a message to David.\n");
    test_encryption(emily_address_2, david_user_id, david_domain, test_plaintext, test_plaintext_len);

    // release
    skissm__invite_response__free_unpacked(response_1, NULL);
    skissm__invite_response__free_unpacked(response_2, NULL);
    skissm__invite_response__free_unpacked(response_3, NULL);
    skissm__invite_response__free_unpacked(response_4, NULL);
    skissm__invite_response__free_unpacked(response_5, NULL);
    skissm__group_member__free_unpacked(group_members_1[0], NULL);
    skissm__group_member__free_unpacked(group_members_1[1], NULL);
    skissm__group_member__free_unpacked(group_members_1[2], NULL);
    free(group_members_1);
    skissm__group_member__free_unpacked(group_members_2[0], NULL);
    skissm__group_member__free_unpacked(group_members_2[1], NULL);
    skissm__group_member__free_unpacked(group_members_2[2], NULL);
    free(group_members_2);
    skissm__create_group_response__free_unpacked(create_group_response_1, NULL);
    skissm__create_group_response__free_unpacked(create_group_response_2, NULL);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

int main() {
    // test_two_members_session();
    // test_two_members_four_devices();
    // test_three_members_group_session();
    // test_multiple_devices();
    test_several_members_and_groups();
    return 0;
}
