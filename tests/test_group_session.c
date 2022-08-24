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

#include "skissm/account.h"
#include "skissm/account_manager.h"
#include "skissm/e2ee_client.h"
#include "skissm/group_session.h"
#include "skissm/group_session_manager.h"
#include "skissm/mem_util.h"

#include "test_util.h"
#include "test_plugin.h"

#define account_data_max 10

static const cipher_suite_t *test_cipher_suite;

static Skissm__Account *account_data[account_data_max];

static uint8_t account_data_insert_pos;

typedef struct store_plaintext {
    uint8_t *plaintext;
    size_t plaintext_len;
} store_plaintext;

typedef struct store_group {
    Skissm__E2eeAddress *group_address;
    char *group_name;
} store_group;

store_plaintext plaintext_store = {NULL, 0};

store_group group = {NULL, NULL};

static uint8_t *f2f_password = NULL;
static size_t f2f_password_len = 0;

static void on_error(ErrorCode error_code, const char *error_msg) { print_error((char *)error_msg, error_code); }

static void on_user_registered(Skissm__Account *account) {
    print_msg("on_user_registered: user_id", (uint8_t *)account->address->user->user_id, strlen(account->address->user->user_id));

    copy_account_from_account(&(account_data[account_data_insert_pos]), account);
    account_data_insert_pos++;
}

static void on_inbound_session_invited(Skissm__E2eeAddress *from){
    printf("on_inbound_session_invited\n");
}

static void on_inbound_session_ready(Skissm__Session *inbound_session){
    printf("on_inbound_session_ready\n");
}

static void on_outbound_session_ready(Skissm__Session *outbound_session){
    printf("on_outbound_session_ready\n");
}

static void on_f2f_password_created(uint8_t *password, size_t password_len) {
    if (f2f_password != NULL)
        free(f2f_password);
    f2f_password_len = password_len;
    f2f_password = (uint8_t *)malloc(sizeof(uint8_t) * f2f_password_len);
    memcpy(f2f_password, password, password_len);
}

static void on_f2f_password_acquired(uint8_t **password, size_t *password_len) {
    *password_len = f2f_password_len;
    *password = (uint8_t *)malloc(sizeof(uint8_t) * f2f_password_len);
    memcpy(*password, f2f_password, f2f_password_len);
}

static void on_one2one_msg_received(Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *to_address, uint8_t *plaintext, size_t plaintext_len) {
    print_msg("on_one2one_msg_received: plaintext", plaintext, plaintext_len);
}

static void on_other_device_msg_received(Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *to_address, uint8_t *plaintext, size_t plaintext_len) {
    print_msg("on_other_device_msg_received: plaintext", plaintext, plaintext_len);
}

static void on_f2f_session_ready(Skissm__Session *session) {
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

static void on_group_msg_received(Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *group_address, uint8_t *plaintext, size_t plaintext_len) {
    print_msg("on_group_msg_received: plaintext", plaintext, plaintext_len);

    if (plaintext_store.plaintext != NULL) {
        free_mem((void **)&(plaintext_store.plaintext), plaintext_store.plaintext_len);
    }
    plaintext_store.plaintext = (uint8_t *)malloc(sizeof(uint8_t) * plaintext_len);
    memcpy(plaintext_store.plaintext, plaintext, plaintext_len);
    plaintext_store.plaintext_len = plaintext_len;
}

static void on_group_created(Skissm__E2eeAddress *group_address, const char *group_name) {
    print_msg("on_group_created: group_name", (uint8_t *)group_name, strlen(group_name));

    copy_address_from_address(&(group.group_address), group_address);
    group.group_name = strdup(group_name);
}

static void on_group_members_added(Skissm__E2eeAddress *group_address, const char *group_name, Skissm__GroupMember **added_group_members, size_t added_group_members_num) {
    print_msg("on_group_members_added: group_name", (uint8_t *)group_name, strlen(group_name));
    size_t i;
    for (i = 0; i < added_group_members_num; i++) {
        print_msg("    member_id", (uint8_t *)(added_group_members[i]->user_id), strlen(added_group_members[i]->user_id));
    }
}

static void on_group_members_removed(Skissm__E2eeAddress *group_address, const char *group_name, Skissm__GroupMember **removed_group_members, size_t removed_group_members_num) {
    print_msg("on_group_members_removed: group_name", (uint8_t *)group_name, strlen(group_name));
    size_t i;
    for (i = 0; i < removed_group_members_num; i++) {
        print_msg("    member_id", (uint8_t *)(removed_group_members[i]->user_id), strlen(removed_group_members[i]->user_id));
    }
}

static skissm_event_handler_t test_event_handler = {
    on_error,
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

static void test_begin() {
    account_data[0] = NULL;
    account_data[1] = NULL;
    account_data[2] = NULL;
    account_data_insert_pos = 0;

    group.group_address = NULL;
    group.group_name = NULL;

    plaintext_store.plaintext = NULL;
    plaintext_store.plaintext_len = 0;

    get_skissm_plugin()->event_handler = test_event_handler;
}

static void test_end() {
    skissm__account__free_unpacked(account_data[0], NULL);
    account_data[0] = NULL;
    skissm__account__free_unpacked(account_data[1], NULL);
    account_data[1] = NULL;
    skissm__account__free_unpacked(account_data[2], NULL);
    account_data[2] = NULL;
    account_data_insert_pos = 0;

    skissm__e2ee_address__free_unpacked(group.group_address, NULL);
    if (group.group_name != NULL) {
        free(group.group_name);
    }

    if (plaintext_store.plaintext != NULL) {
        free(plaintext_store.plaintext);
    }
    plaintext_store.plaintext_len = 0;
}

static void mock_alice_account(uint64_t account_id, const char *user_name) {
    const char *e2ee_pack_id = TEST_E2EE_PACK_ID;
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
    const char *e2ee_pack_id = TEST_E2EE_PACK_ID;
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
    const char *e2ee_pack_id = TEST_E2EE_PACK_ID;
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

static void test_encryption(Skissm__E2eeAddress *sender_address, Skissm__E2eeAddress *group_address, uint8_t *plaintext_data, size_t plaintext_data_len) {
    if (plaintext_store.plaintext != NULL){
        free_mem((void **)&(plaintext_store.plaintext), plaintext_store.plaintext_len);
    }
    
    Skissm__SendGroupMsgResponse *response = send_group_msg(sender_address,
        group_address, plaintext_data, plaintext_data_len);
    
    assert(response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK);
    assert(plaintext_data_len == plaintext_store.plaintext_len);
    assert(memcmp(plaintext_data, plaintext_store.plaintext, plaintext_data_len) == 0);
    
    // release
    skissm__send_group_msg_response__free_unpacked(response, NULL);
}

static void test_create_group() {
    // test start
    tear_up();
    test_begin();

    // Prepare account
    mock_alice_account(1, "alice");
    mock_bob_account(2, "bob");

    // Alice invites Bob to create a group
    switch_account(account_data[0]->address);
    invite(account_data[0]->address, account_data[1]->address->user->user_id, account_data[1]->address->domain);

    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 2);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(account_data[0]->address->user->user_id);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(account_data[1]->address->user->user_id);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(account_data[0]->address, "Group name", group_members, 2);

    assert(create_group_response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK);
    Skissm__E2eeAddress *group_address = create_group_response->group_address;

    // Alice sends a message to the group
    uint8_t plaintext_data[] = "This is the group session test.";
    size_t plaintext_data_len = sizeof(plaintext_data) - 1;
    test_encryption(account_data[0]->address, group_address, plaintext_data, plaintext_data_len);

    // release
    skissm__group_member__free_unpacked(group_members[0], NULL);
    skissm__group_member__free_unpacked(group_members[1], NULL);
    free(group_members);
    skissm__create_group_response__free_unpacked(create_group_response, NULL);

    // test stop
    test_end();
    tear_down();
}

static void test_add_group_members() {
    // test start
    tear_up();
    test_begin();

    // Prepare account
    mock_alice_account(1, "alice");
    mock_bob_account(2, "bob");
    mock_claire_account(3, "claire");

    // Alice invites Bob to create a group
    invite(account_data[0]->address, account_data[1]->address->user->user_id, account_data[1]->address->domain);

    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 2);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(account_data[0]->address->user->user_id);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(account_data[1]->address->user->user_id);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(account_data[0]->address, "Group name", group_members, 2);

    // Alice invites Claire to join the group
    invite(account_data[0]->address, account_data[2]->address->user->user_id, account_data[2]->address->domain);
    // the new group member is Claire
    Skissm__GroupMember **new_group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *));
    new_group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(new_group_members[0]);
    new_group_members[0]->user_id = strdup(account_data[2]->address->user->user_id);
    new_group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    size_t new_group_member_num = 1;
    // add the new group member to the group
    Skissm__AddGroupMembersResponse *add_group_members_response = add_group_members(account_data[0]->address, group.group_address, new_group_members, new_group_member_num);
    assert(add_group_members_response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK);

    // Alice sends a message to the group
    uint8_t plaintext_data[] = "This message will be sent to Bob and Claire.";
    size_t plaintext_data_len = sizeof(plaintext_data) - 1;
    test_encryption(account_data[0]->address, group.group_address, plaintext_data, plaintext_data_len);

    // release
    skissm__group_member__free_unpacked(group_members[0], NULL);
    skissm__group_member__free_unpacked(group_members[1], NULL);
    free(group_members);
    skissm__create_group_response__free_unpacked(create_group_response, NULL);
    skissm__group_member__free_unpacked(new_group_members[0], NULL);
    free(new_group_members);
    skissm__add_group_members_response__free_unpacked(add_group_members_response, NULL);

    // test stop
    test_end();
    tear_down();
}

static void test_remove_group_members() {
    // test start
    tear_up();
    test_begin();

    // Prepare account
    mock_alice_account(1, "alice");
    mock_bob_account(2, "bob");
    mock_claire_account(3, "claire");

    // Alice invites Bob and Claire to join the group
    invite(account_data[0]->address, account_data[1]->address->user->user_id, account_data[1]->address->domain);
    invite(account_data[0]->address, account_data[2]->address->user->user_id, account_data[2]->address->domain);

    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 3);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(account_data[0]->address->user->user_id);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(account_data[1]->address->user->user_id);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the second group member is Claire
    group_members[2] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[2]);
    group_members[2]->user_id = strdup(account_data[2]->address->user->user_id);
    group_members[2]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(account_data[0]->address, "Group name", group_members, 3);

    // the removing group member is Claire
    Skissm__GroupMember **removing_group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *));
    removing_group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(removing_group_members[0]);
    removing_group_members[0]->user_id = strdup(account_data[2]->address->user->user_id);
    removing_group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    size_t removing_group_member_num = 1;

    // Alice removes Claire out of the group
    Skissm__RemoveGroupMembersResponse *remove_group_members_response = remove_group_members(account_data[0]->address, group.group_address, removing_group_members, removing_group_member_num);
    assert(remove_group_members_response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK);

    // Alice sends a message to the group
    uint8_t plaintext[] = "This message will be sent to Bob only.";
    size_t plaintext_len = sizeof(plaintext) - 1;
    test_encryption(account_data[0]->address, group.group_address, plaintext, plaintext_len);

    // release
    skissm__group_member__free_unpacked(group_members[0], NULL);
    skissm__group_member__free_unpacked(group_members[1], NULL);
    skissm__group_member__free_unpacked(group_members[2], NULL);
    free(group_members);
    skissm__create_group_response__free_unpacked(create_group_response, NULL);
    skissm__group_member__free_unpacked(removing_group_members[0], NULL);
    free(removing_group_members);
    skissm__remove_group_members_response__free_unpacked(remove_group_members_response, NULL);

    // test stop
    test_end();
    tear_down();
}

static void test_create_add_remove() {
    // test start
    tear_up();
    test_begin();

    // Prepare account
    mock_alice_account(1, "alice");
    mock_bob_account(2, "bob");
    mock_claire_account(3, "claire");

    // Alice invites Bob to create a group
    invite(account_data[0]->address, account_data[1]->address->user->user_id, account_data[1]->address->domain);

    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 2);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(account_data[0]->address->user->user_id);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(account_data[1]->address->user->user_id);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(account_data[0]->address, "Group name", group_members, 2);

    // Alice sends a message to the group
    uint8_t plaintext[] = "This is the group session test.";
    size_t plaintext_len = sizeof(plaintext) - 1;
    test_encryption(account_data[0]->address, group.group_address, plaintext, plaintext_len);

    // Alice invites Claire to join the group
    invite(account_data[0]->address, account_data[2]->address->user->user_id, account_data[2]->address->domain);
    // the new group member is Claire
    Skissm__GroupMember **new_group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *));
    new_group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(new_group_members[0]);
    new_group_members[0]->user_id = strdup(account_data[2]->address->user->user_id);
    new_group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    size_t new_group_member_num = 1;
    // add the new group member to the group
    Skissm__AddGroupMembersResponse *add_group_members_response = add_group_members(account_data[0]->address, group.group_address, new_group_members, new_group_member_num);

    // Alice sends a message to the group
    uint8_t plaintext_2[] = "This message will be sent to Bob and Claire.";
    size_t plaintext_len_2 = sizeof(plaintext_2) - 1;
    test_encryption(account_data[0]->address, group.group_address, plaintext_2, plaintext_len_2);

    // Alice removes Claire out of the group
    Skissm__RemoveGroupMembersResponse *remove_group_members_response = remove_group_members(account_data[0]->address, group.group_address, new_group_members, new_group_member_num);

    // Alice sends a message to the group
    uint8_t plaintext_3[] = "This message will be sent to Bob only.";
    size_t plaintext_len_3 = sizeof(plaintext_3) - 1;
    test_encryption(account_data[0]->address, group.group_address, plaintext_3, plaintext_len_3);

    // release
    skissm__group_member__free_unpacked(group_members[0], NULL);
    skissm__group_member__free_unpacked(group_members[1], NULL);
    free(group_members);
    skissm__create_group_response__free_unpacked(create_group_response, NULL);
    skissm__group_member__free_unpacked(new_group_members[0], NULL);
    free(new_group_members);
    skissm__add_group_members_response__free_unpacked(add_group_members_response, NULL);
    skissm__remove_group_members_response__free_unpacked(remove_group_members_response, NULL);

    // test stop
    test_end();
    tear_down();
}

static void test_interaction() {
    // test start
    tear_up();
    test_begin();

    // Prepare account
    mock_alice_account(1, "alice");
    mock_bob_account(2, "bob");
    mock_claire_account(3, "claire");

    // Alice invites Bob and Claire to join the group
    invite(account_data[0]->address, account_data[1]->address->user->user_id, account_data[1]->address->domain);
    invite(account_data[0]->address, account_data[2]->address->user->user_id, account_data[2]->address->domain);
    // Bob invites Alice and Claire to join the group
    invite(account_data[1]->address, account_data[0]->address->user->user_id, account_data[0]->address->domain);
    invite(account_data[1]->address, account_data[2]->address->user->user_id, account_data[2]->address->domain);
    // Claire invites Alice and Bob to join the group
    invite(account_data[2]->address, account_data[0]->address->user->user_id, account_data[0]->address->domain);
    invite(account_data[2]->address, account_data[1]->address->user->user_id, account_data[1]->address->domain);

    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 3);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(account_data[0]->address->user->user_id);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(account_data[1]->address->user->user_id);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the second group member is Claire
    group_members[2] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[2]);
    group_members[2]->user_id = strdup(account_data[2]->address->user->user_id);
    group_members[2]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(account_data[0]->address, "Group name", group_members, 3);

    // Alice sends a message to the group
    uint8_t plaintext_data_a[] = "This message will be sent to Bob and Claire.";
    size_t plaintext_data_a_len = sizeof(plaintext_data_a) - 1;
    test_encryption(account_data[0]->address, group.group_address, plaintext_data_a, plaintext_data_a_len);

    // Bob sends a message to the group
    uint8_t plaintext_data_b[] = "This message will be sent to Alice and Claire.";
    size_t plaintext_data_b_len = sizeof(plaintext_data_b) - 1;
    test_encryption(account_data[1]->address, group.group_address, plaintext_data_b, plaintext_data_b_len);

    // Claire sends a message to the group
    uint8_t plaintext_data_c[] = "This message will be sent to Alice and Bob.";
    size_t plaintext_data_c_len = sizeof(plaintext_data_c) - 1;
    test_encryption(account_data[2]->address, group.group_address, plaintext_data_c, plaintext_data_c_len);

    // release
    skissm__group_member__free_unpacked(group_members[0], NULL);
    skissm__group_member__free_unpacked(group_members[1], NULL);
    skissm__group_member__free_unpacked(group_members[2], NULL);
    free(group_members);
    skissm__create_group_response__free_unpacked(create_group_response, NULL);

    // test stop
    test_end();
    tear_down();
}

static void test_continual() {
    // test start
    tear_up();
    test_begin();

    // Prepare account
    mock_alice_account(1, "alice");
    mock_bob_account(2, "bob");
    mock_claire_account(3, "claire");

    // Alice invites Bob and Claire to join the group
    invite(account_data[0]->address, account_data[1]->address->user->user_id, account_data[1]->address->domain);
    invite(account_data[0]->address, account_data[2]->address->user->user_id, account_data[2]->address->domain);
    // Bob invites Alice and Claire to join the group
    invite(account_data[1]->address, account_data[0]->address->user->user_id, account_data[0]->address->domain);
    invite(account_data[1]->address, account_data[2]->address->user->user_id, account_data[2]->address->domain);
    // Claire invites Alice and Bob to join the group
    invite(account_data[2]->address, account_data[0]->address->user->user_id, account_data[0]->address->domain);
    invite(account_data[2]->address, account_data[1]->address->user->user_id, account_data[1]->address->domain);

    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 3);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(account_data[0]->address->user->user_id);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(account_data[1]->address->user->user_id);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the second group member is Claire
    group_members[2] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[2]);
    group_members[2]->user_id = strdup(account_data[2]->address->user->user_id);
    group_members[2]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(account_data[0]->address, "Group name", group_members, 3);

    int i;
    // Alice sends a message to the group
    uint8_t plaintext_data_a[] = "This message will be sent to Bob and Claire by 1000 times.";
    size_t plaintext_data_a_len = sizeof(plaintext_data_a) - 1;
    for (i = 0; i < 1000; i++) {
        test_encryption(account_data[0]->address, group.group_address, plaintext_data_a, plaintext_data_a_len);
    }

    // Bob sends a message to the group
    uint8_t plaintext_data_b[] = "This message will be sent to Alice and Claire by 1000 times.";
    size_t plaintext_data_b_len = sizeof(plaintext_data_b) - 1;
    for (i = 0; i < 1000; i++) {
        test_encryption(account_data[1]->address, group.group_address, plaintext_data_b, plaintext_data_b_len);
    }

    // Claire sends a message to the group
    uint8_t plaintext_data_c[] = "This message will be sent to Alice and Bob by 1000 times.";
    size_t plaintext_data_c_len = sizeof(plaintext_data_c) - 1;
    for (i = 0; i < 1000; i++) {
        test_encryption(account_data[2]->address, group.group_address, plaintext_data_c, plaintext_data_c_len);
    }

    // release
    skissm__group_member__free_unpacked(group_members[0], NULL);
    skissm__group_member__free_unpacked(group_members[1], NULL);
    skissm__group_member__free_unpacked(group_members[2], NULL);
    free(group_members);
    skissm__create_group_response__free_unpacked(create_group_response, NULL);

    // test stop
    test_end();
    tear_down();
}

void test_multiple_devices() {
    // test start
    tear_up();
    test_begin();

    // Prepare account
    mock_alice_account(1, "Alice");
    mock_alice_account(2, "Alice");
    mock_bob_account(3, "Bob");
    mock_bob_account(4, "Bob");
    mock_claire_account(5, "Claire");
    mock_claire_account(6, "Claire");

    Skissm__E2eeAddress *alice_address_1 = account_data[0]->address;
    Skissm__E2eeAddress *alice_address_2 = account_data[1]->address;
    char *alice_user_id = alice_address_1->user->user_id;
    char *alice_domain = alice_address_1->domain;
    Skissm__E2eeAddress *bob_address_1 = account_data[2]->address;
    Skissm__E2eeAddress *bob_address_2 = account_data[3]->address;
    char *bob_user_id = bob_address_1->user->user_id;
    char *bob_domain = bob_address_1->domain;
    Skissm__E2eeAddress *claire_address_1 = account_data[4]->address;
    Skissm__E2eeAddress *claire_address_2 = account_data[5]->address;
    char *claire_user_id = claire_address_1->user->user_id;
    char *claire_domain = claire_address_1->domain;

    // face-to-face session between each member's devices
    uint8_t password_alice[] = "password alice";
    size_t password_alice_len = sizeof(password_alice) - 1;
    on_f2f_password_created(password_alice, password_alice_len);
    f2f_invite(alice_address_1, alice_address_2, 0, password_alice, password_alice_len);

    uint8_t password_bob[] = "password bob";
    size_t password_bob_len = sizeof(password_bob) - 1;
    on_f2f_password_created(password_bob, password_bob_len);
    f2f_invite(bob_address_1, bob_address_2, 0, password_bob, password_bob_len);

    uint8_t password_claire[] = "password claire";
    size_t password_claire_len = sizeof(password_claire) - 1;
    on_f2f_password_created(password_claire, password_claire_len);
    f2f_invite(claire_address_1, claire_address_2, 0, password_claire, password_claire_len);

    // create group

    // release

    // test stop
    test_end();
    tear_down();
}

int main() {
    test_cipher_suite = get_e2ee_pack(TEST_E2EE_PACK_ID)->cipher_suite;

    test_create_group();
    test_add_group_members();
    test_remove_group_members();
    test_create_add_remove();
    test_interaction();
    test_continual();
    // test_multiple_devices();

    return 0;
}
