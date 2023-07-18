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

static Skissm__Account *account_data[account_data_max];

static uint8_t account_data_insert_pos;

typedef struct store_group {
    Skissm__E2eeAddress *group_address;
    char *group_name;
} store_group;

store_group group = {NULL, NULL};

typedef struct f2f_password_data {
    Skissm__E2eeAddress *sender;
    Skissm__E2eeAddress *receiver;
    uint8_t *f2f_password;
    size_t f2f_password_len;
    struct f2f_password_data *next;
} f2f_password_data;

static f2f_password_data *f2f_pw_data = NULL;

static uint8_t *f2f_password = NULL;
static size_t f2f_password_len = 0;

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

static void f2f_password_created(
    Skissm__E2eeAddress *sender,
    Skissm__E2eeAddress *receiver,
    uint8_t *password,
    size_t password_len
) {
    if (f2f_pw_data != NULL) {
        f2f_password_data *cur_data = f2f_pw_data;
        while (cur_data->next != NULL) {
            cur_data = cur_data->next;
        }
        cur_data->next = (f2f_password_data *)malloc(sizeof(f2f_password_data));
        copy_address_from_address(&(cur_data->next->sender), sender);
        copy_address_from_address(&(cur_data->next->receiver), receiver);
        cur_data->next->f2f_password_len = password_len;
        cur_data->next->f2f_password = (uint8_t *)malloc(sizeof(uint8_t) * password_len);
        memcpy(cur_data->next->f2f_password, password, password_len);
        cur_data = cur_data->next;
        cur_data->next = (f2f_password_data *)malloc(sizeof(f2f_password_data));
        copy_address_from_address(&(cur_data->next->sender), receiver);
        copy_address_from_address(&(cur_data->next->receiver), sender);
        cur_data->next->f2f_password_len = password_len;
        cur_data->next->f2f_password = (uint8_t *)malloc(sizeof(uint8_t) * password_len);
        memcpy(cur_data->next->f2f_password, password, password_len);
        cur_data->next->next = NULL;
    } else {
        f2f_pw_data = (f2f_password_data *)malloc(sizeof(f2f_password_data));
        copy_address_from_address(&(f2f_pw_data->sender), sender);
        copy_address_from_address(&(f2f_pw_data->receiver), receiver);
        f2f_pw_data->f2f_password_len = password_len;
        f2f_pw_data->f2f_password = (uint8_t *)malloc(sizeof(uint8_t) * password_len);
        memcpy(f2f_pw_data->f2f_password, password, password_len);
        f2f_pw_data->next = (f2f_password_data *)malloc(sizeof(f2f_password_data));
        copy_address_from_address(&(f2f_pw_data->next->sender), receiver);
        copy_address_from_address(&(f2f_pw_data->next->receiver), sender);
        f2f_pw_data->next->f2f_password_len = password_len;
        f2f_pw_data->next->f2f_password = (uint8_t *)malloc(sizeof(uint8_t) * password_len);
        memcpy(f2f_pw_data->next->f2f_password, password, password_len);
        f2f_pw_data->next->next = NULL;
    }
}

static void on_f2f_password_acquired(
    Skissm__E2eeAddress *user_address, 
    Skissm__E2eeAddress *sender,
    Skissm__E2eeAddress *receiver,
    uint8_t **password,
    size_t *password_len
) {
    f2f_password_data *cur_data = f2f_pw_data;
    while (cur_data != NULL) {
        if (!compare_address(cur_data->sender, sender) || !compare_address(cur_data->receiver, receiver)) {
            cur_data = cur_data->next;
        } else {
            break;
        }
    }

    if (cur_data == NULL)
        return;

    *password_len = cur_data->f2f_password_len;
    *password = (uint8_t *)malloc(sizeof(uint8_t) * cur_data->f2f_password_len);
    memcpy(*password, cur_data->f2f_password, *password_len);
}

static void on_one2one_msg_received(
    Skissm__E2eeAddress *user_address, 
    Skissm__E2eeAddress *from_address,
    Skissm__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    print_msg("on_one2one_msg_received: plaintext", plaintext, plaintext_len);
}

static void on_other_device_msg_received(
    Skissm__E2eeAddress *user_address, 
    Skissm__E2eeAddress *from_address,
    Skissm__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    print_msg("on_other_device_msg_received: plaintext", plaintext, plaintext_len);
}

static void on_f2f_session_ready(Skissm__E2eeAddress *user_address, Skissm__Session *session) {
    if (session->from->user->device_id != NULL) {
        printf("New outbound face-to-face session created.\n");
        printf("Owner(User ID): %s\n", session->session_owner->user->user_id);
        printf("Owner(Device ID): %s\n", session->session_owner->user->device_id);
        printf("From: %s\n", session->from->user->user_id);
        printf("to: %s\n", session->to->user->user_id);
    } else {
        printf("New inbound face-to-face session created.\n");
        printf("Owner(User ID): %s\n", session->session_owner->user->user_id);
        printf("Owner(Device ID): %s\n", session->session_owner->user->device_id);
        printf("From: %s\n", session->from->user->user_id);
        printf("to: %s\n", session->to->user->user_id);
    }
}

static void on_group_msg_received(Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *group_address, uint8_t *plaintext, size_t plaintext_len) {
    print_msg("on_group_msg_received: plaintext", plaintext, plaintext_len);
}

static void on_group_created(Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *group_address, const char *group_name) {
    print_msg("on_group_created: group_name", (uint8_t *)group_name, strlen(group_name));

    copy_address_from_address(&(group.group_address), group_address);
    group.group_name = strdup(group_name);
}

static void on_group_members_added(Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *group_address, const char *group_name, Skissm__GroupMember **added_group_members, size_t added_group_members_num) {
    print_msg("on_group_members_added: group_name", (uint8_t *)group_name, strlen(group_name));
    size_t i;
    for (i = 0; i < added_group_members_num; i++) {
        print_msg("    member_id", (uint8_t *)(added_group_members[i]->user_id), strlen(added_group_members[i]->user_id));
    }
}

static void on_group_members_removed(Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *group_address, const char *group_name, Skissm__GroupMember **removed_group_members, size_t removed_group_members_num) {
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
    on_f2f_password_acquired,
    on_one2one_msg_received,
    on_other_device_msg_received,
    on_f2f_session_ready,
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

    f2f_pw_data = NULL;

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

    if (group.group_address != NULL) {
        skissm__e2ee_address__free_unpacked(group.group_address, NULL);
    }
    if (group.group_name != NULL) {
        free(group.group_name);
    }

    if (f2f_pw_data != NULL) {
        f2f_password_data *cur_data = f2f_pw_data;
        f2f_password_data *temp_data;
        while (cur_data != NULL) {
            temp_data = cur_data;
            cur_data = cur_data->next;
            skissm__e2ee_address__free_unpacked(temp_data->sender, NULL);
            skissm__e2ee_address__free_unpacked(temp_data->receiver, NULL);
            free(temp_data->f2f_password);
            temp_data->f2f_password_len = 0;
            temp_data->next = NULL;
        }
    }
}

static void mock_alice_account(uint64_t account_id, const char *user_name) {
    const char *e2ee_pack_id = TEST_E2EE_PACK_ID_ECC;
    const char *device_id = generate_uuid_str();
    const char *authenticator = "alice@domain.com.tw";
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

static void mock_bob_account(uint64_t account_id, const char *user_name) {
    const char *e2ee_pack_id = TEST_E2EE_PACK_ID_ECC;
    const char *device_id = generate_uuid_str();
    const char *authenticator = "bob@domain.com.tw";
    const char *auth_code = "654321";
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

static void mock_claire_account(uint64_t account_id, const char *user_name) {
    const char *e2ee_pack_id = TEST_E2EE_PACK_ID_ECC;
    const char *device_id = generate_uuid_str();
    const char *authenticator = "claire@domain.com.tw";
    const char *auth_code = "987654";
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

static void test_encryption(
    Skissm__E2eeAddress *from_address, const char *to_user_id, const char *to_domain,
    uint8_t *plaintext, size_t plaintext_len
) {
    // send encrypted msg
    Skissm__SendOne2oneMsgResponse *response = NULL;
    response = send_one2one_msg(from_address, to_user_id, to_domain, plaintext, plaintext_len);

    // release
    skissm__send_one2one_msg_response__free_unpacked(response, NULL);
}

static void test_group_encryption(
    Skissm__E2eeAddress *sender_address, Skissm__E2eeAddress *group_address,
    uint8_t *plaintext_data, size_t plaintext_data_len
) {
    Skissm__SendGroupMsgResponse *response = send_group_msg(sender_address, group_address, plaintext_data, plaintext_data_len);
    
    // release
    skissm__send_group_msg_response__free_unpacked(response, NULL);
}

static void test_two_members_session(){
    // test start
    printf("test_two_members_session begin!!!\n");
    tear_up();
    test_begin();

    mock_alice_account(1, "alice");
    mock_bob_account(2, "bob");

    Skissm__E2eeAddress *alice_address = account_data[0]->address;
    char *alice_user_id = alice_address->user->user_id;
    char *alice_domain = alice_address->domain;
    Skissm__E2eeAddress *bob_address = account_data[1]->address;
    char *bob_user_id = bob_address->user->user_id;
    char *bob_domain = bob_address->domain;

    // Alice invites Bob to create a session
    Skissm__InviteResponse *response_1 = invite(alice_address, bob_user_id, bob_domain);
    // Bob invites Alice to create a session
    Skissm__InviteResponse *response_2 = invite(bob_address, alice_user_id, alice_domain);

    sleep(3);

    // Alice add a new device
    mock_alice_account(3, "alice");

    Skissm__E2eeAddress *device_2 = account_data[2]->address;

    // face-to-face session creation between Alice's two devices
    uint8_t password_1[] = "password 1";
    size_t password_1_len = sizeof(password_1) - 1;
    f2f_password_created(device_2, alice_address, password_1, password_1_len);

    f2f_invite(device_2, alice_address, 0, password_1, password_1_len);

    sleep(1);
    // Alice sends an encrypted message to Bob
    uint8_t plaintext[] = "This message will be sent to Bob and Alice's first device.";
    size_t plaintext_len = sizeof(plaintext) - 1;
    test_encryption(device_2, bob_user_id, bob_domain, plaintext, plaintext_len);

    // release
    skissm__invite_response__free_unpacked(response_1, NULL);
    skissm__invite_response__free_unpacked(response_2, NULL);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_three_members_group_session() {
    // test start
    printf("test_continual begin!!!\n");
    tear_up();
    test_begin();

    // Prepare account
    mock_alice_account(1, "alice");
    mock_bob_account(2, "bob");
    mock_claire_account(3, "claire");

    Skissm__E2eeAddress *alice_address = account_data[0]->address;
    char *alice_user_id = alice_address->user->user_id;
    char *alice_domain = alice_address->domain;
    Skissm__E2eeAddress *bob_address = account_data[1]->address;
    char *bob_user_id = bob_address->user->user_id;
    char *bob_domain = bob_address->domain;
    Skissm__E2eeAddress *claire_address = account_data[2]->address;
    char *claire_user_id = claire_address->user->user_id;
    char *claire_domain = claire_address->domain;

    // Alice invites Bob and Claire to join the group
    Skissm__InviteResponse *response_1 = invite(alice_address, bob_user_id, bob_domain);
    Skissm__InviteResponse *response_2 = invite(alice_address, claire_user_id, claire_domain);
    // Bob invites Alice and Claire to join the group
    Skissm__InviteResponse *response_3 = invite(bob_address, alice_user_id, alice_domain);
    Skissm__InviteResponse *response_4 = invite(bob_address, claire_user_id, claire_domain);
    // Claire invites Alice and Bob to join the group
    Skissm__InviteResponse *response_5 = invite(claire_address, alice_user_id, alice_domain);
    Skissm__InviteResponse *response_6 = invite(claire_address, bob_user_id, bob_domain);

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

    // Alice add a new device
    mock_alice_account(4, "alice");

    Skissm__E2eeAddress *alice_address_2 = account_data[3]->address;

    // face-to-face session creation between Alice's two devices
    uint8_t password_1[] = "password 1";
    size_t password_1_len = sizeof(password_1) - 1;
    f2f_password_created(alice_address_2, alice_address, password_1, password_1_len);

    f2f_invite(alice_address_2, alice_address, 0, password_1, password_1_len);

    sleep(1);
    // Alice sends a message to the group via the second device
    uint8_t plaintext_1[] = "This message is from Alice's second device.";
    size_t plaintext_1_len = sizeof(plaintext_1) - 1;
    test_group_encryption(alice_address_2, group.group_address, plaintext_1, plaintext_1_len);

    // Claire sends a message to the group
    uint8_t plaintext_3[] = "This message is from Claire.";
    size_t plaintext_3_len = sizeof(plaintext_3) - 1;
    test_group_encryption(claire_address, group.group_address, plaintext_3, plaintext_3_len);

    // release
    skissm__invite_response__free_unpacked(response_1, NULL);
    skissm__invite_response__free_unpacked(response_2, NULL);
    skissm__invite_response__free_unpacked(response_3, NULL);
    skissm__invite_response__free_unpacked(response_4, NULL);
    skissm__invite_response__free_unpacked(response_5, NULL);
    skissm__invite_response__free_unpacked(response_6, NULL);
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

int main() {
    test_two_members_session();
    test_three_members_group_session();
    return 0;
}
