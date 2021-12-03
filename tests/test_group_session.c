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

#include "account.h"
#include "account_manager.h"
#include "e2ee_protocol.h"
#include "e2ee_protocol_handler.h"
#include "group_session.h"
#include "group_session_manager.h"
#include "mem_util.h"

#include "test_util.h"
#include "test_env.h"

extern register_user_response_handler register_user_response_handler_store;

#define account_data_max 3

static Skissm__E2eeAccount *account_data[account_data_max];

static uint8_t account_data_insert_pos;

typedef struct store_plaintext {
    uint8_t *plaintext;
    size_t plaintext_len;
} store_plaintext;

typedef struct store_group {
    Skissm__E2eeAddress *group_address;
    ProtobufCBinaryData *group_name;
} store_group;

store_plaintext plaintext_store = {NULL, 0};

store_group group = {NULL, NULL};

static void test_begin() {
    account_data[0] = NULL;
    account_data[1] = NULL;
    account_data[2] = NULL;
    account_data_insert_pos = 0;
}

static void test_end() {
    skissm__e2ee_account__free_unpacked(account_data[0], NULL);
    account_data[0] = NULL;
    skissm__e2ee_account__free_unpacked(account_data[1], NULL);
    account_data[1] = NULL;
    skissm__e2ee_account__free_unpacked(account_data[2], NULL);
    account_data[2] = NULL;
    account_data_insert_pos = 0;
}

static void on_error(ErrorCode error_code, char *error_msg) { print_error(error_msg, error_code); }

static void on_user_registered(Skissm__E2eeAccount *account) {
    copy_account_from_account(&(account_data[account_data_insert_pos]), account);
    account_data_insert_pos++;
}

static void on_one2one_msg_received(Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *to_address, uint8_t *plaintext, size_t plaintext_len) {
    print_msg("on_one2one_msg_received: plaintext", plaintext, plaintext_len);
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

static void on_group_created(Skissm__E2eeAddress *group_address, ProtobufCBinaryData *group_name) {
    copy_address_from_address(&(group.group_address), group_address);
    
    group.group_name = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
    copy_protobuf_from_protobuf(group.group_name, group_name);
}

static void on_group_members_added(Skissm__E2eeAddress *group_address, ProtobufCBinaryData *group_name, Skissm__E2eeAddress **member_addresses) {}

static void on_group_members_removed(Skissm__E2eeAddress *group_address, ProtobufCBinaryData *group_name, Skissm__E2eeAddress **member_addresses) {}

static skissm_event_handler test_event_handler = {on_error, on_user_registered, on_one2one_msg_received, on_group_msg_received, on_group_created, on_group_members_added, on_group_members_removed};

static void test_encryption(Skissm__E2eeAddress *sender_address, uint8_t *plaintext, size_t plaintext_len) {
    encrypt_group_session(sender_address, group.group_address, plaintext, plaintext_len);
    assert(plaintext_len == plaintext_store.plaintext_len);
    assert(memcmp(plaintext, plaintext_store.plaintext, plaintext_len) == 0);
}

static void test_create_group() {
    // test start
    setup();
    test_begin();

    set_skissm_event_handler(&test_event_handler);

    // Prepare account
    register_account();
    register_account();

    // Alice invites Bob to create a group
    Skissm__E2eeAddress **member_addresses = (Skissm__E2eeAddress **)malloc(sizeof(Skissm__E2eeAddress *) * 2);
    copy_address_from_address(&(member_addresses[0]), account_data[0]->address);
    copy_address_from_address(&(member_addresses[1]), account_data[1]->address);

    ProtobufCBinaryData *group_name = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
    group_name->len = strlen("Group name");
    group_name->data = (uint8_t *)malloc(sizeof(uint8_t) * group_name->len);
    memcpy(group_name->data, "Group name", group_name->len);
    create_group(account_data[0]->address, group_name, member_addresses, 2);

    // Alice sends a message to the group
    uint8_t plaintext[] = "This is the group session test.";
    size_t plaintext_len = sizeof(plaintext) - 1;
    test_encryption(account_data[0]->address, plaintext, plaintext_len);

    // release
    skissm__e2ee_address__free_unpacked(member_addresses[0], NULL);
    skissm__e2ee_address__free_unpacked(member_addresses[1], NULL);
    free(member_addresses);
    free_protobuf(group_name);

    // test stop
    test_end();
    tear_down();
}

static void test_add_group_members() {
    // test start
    setup();
    test_begin();

    set_skissm_event_handler(&test_event_handler);

    // Prepare account
    register_account();
    register_account();
    register_account();

    // Alice invites Bob to create a group
    Skissm__E2eeAddress **member_addresses = (Skissm__E2eeAddress **)malloc(sizeof(Skissm__E2eeAddress *) * 2);
    copy_address_from_address(&(member_addresses[0]), account_data[0]->address);
    copy_address_from_address(&(member_addresses[1]), account_data[1]->address);

    ProtobufCBinaryData *group_name = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
    group_name->len = strlen("Group name");
    group_name->data = (uint8_t *)malloc(sizeof(uint8_t) * group_name->len);
    memcpy(group_name->data, "Group name", group_name->len);
    create_group(account_data[0]->address, group_name, member_addresses, 2);

    // Alice invites Claire to join the group
    Skissm__E2eeAddress **new_member_addresses = (Skissm__E2eeAddress **)malloc(sizeof(Skissm__E2eeAddress *));
    copy_address_from_address(&(new_member_addresses[0]), account_data[2]->address);
    size_t new_member_num = 1;
    size_t result = add_group_members(account_data[0]->address, group.group_address, new_member_addresses, new_member_num);
    assert(result == 0);

    // Alice sends a message to the group
    uint8_t plaintext[] = "This message will be sent to Bob and Claire.";
    size_t plaintext_len = sizeof(plaintext) - 1;
    test_encryption(account_data[0]->address, plaintext, plaintext_len);

    // release
    skissm__e2ee_address__free_unpacked(member_addresses[0], NULL);
    skissm__e2ee_address__free_unpacked(member_addresses[1], NULL);
    free(member_addresses);
    free_protobuf(group_name);
    skissm__e2ee_address__free_unpacked(new_member_addresses[0], NULL);
    free(new_member_addresses);

    // test stop
    test_end();
    tear_down();
}

static void test_remove_group_members() {
    // test start
    setup();
    test_begin();

    set_skissm_event_handler(&test_event_handler);

    // Prepare account
    register_account();
    register_account();
    register_account();

    // Alice invites Bob to create a group
    Skissm__E2eeAddress **member_addresses = (Skissm__E2eeAddress **)malloc(sizeof(Skissm__E2eeAddress *) * 3);
    copy_address_from_address(&(member_addresses[0]), account_data[0]->address);
    copy_address_from_address(&(member_addresses[1]), account_data[1]->address);
    copy_address_from_address(&(member_addresses[2]), account_data[2]->address);

    ProtobufCBinaryData *group_name = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
    group_name->len = strlen("Group name");
    group_name->data = (uint8_t *)malloc(sizeof(uint8_t) * group_name->len);
    memcpy(group_name->data, "Group name", group_name->len);
    create_group(account_data[0]->address, group_name, member_addresses, 3);

    Skissm__E2eeAddress **removing_member_addresses = (Skissm__E2eeAddress **)malloc(sizeof(Skissm__E2eeAddress *));
    copy_address_from_address(&(removing_member_addresses[0]), account_data[2]->address);
    size_t removing_member_num = 1;

    // Alice removes Claire out of the group
    remove_group_members(account_data[0]->address, group.group_address, removing_member_addresses, removing_member_num);

    // Alice sends a message to the group
    uint8_t plaintext[] = "This message will be sent to Bob only.";
    size_t plaintext_len = sizeof(plaintext) - 1;
    test_encryption(account_data[0]->address, plaintext, plaintext_len);

    // release
    skissm__e2ee_address__free_unpacked(member_addresses[0], NULL);
    skissm__e2ee_address__free_unpacked(member_addresses[1], NULL);
    skissm__e2ee_address__free_unpacked(member_addresses[2], NULL);
    free(member_addresses);
    free_protobuf(group_name);
    skissm__e2ee_address__free_unpacked(removing_member_addresses[0], NULL);
    free(removing_member_addresses);

    // test stop
    test_end();
    tear_down();
}

static void test_create_add_remove() {
    // test start
    setup();
    test_begin();

    set_skissm_event_handler(&test_event_handler);

    // Prepare account
    register_account();
    register_account();
    register_account();

    // Alice invites Bob to create a group
    Skissm__E2eeAddress **member_addresses = (Skissm__E2eeAddress **)malloc(sizeof(Skissm__E2eeAddress *) * 2);
    copy_address_from_address(&(member_addresses[0]), account_data[0]->address);
    copy_address_from_address(&(member_addresses[1]), account_data[1]->address);

    ProtobufCBinaryData *group_name = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
    group_name->len = strlen("Group name");
    group_name->data = (uint8_t *)malloc(sizeof(uint8_t) * group_name->len);
    memcpy(group_name->data, "Group name", group_name->len);
    create_group(account_data[0]->address, group_name, member_addresses, 2);

    // Alice sends a message to the group
    uint8_t plaintext[] = "This is the group session test.";
    size_t plaintext_len = sizeof(plaintext) - 1;
    test_encryption(account_data[0]->address, plaintext, plaintext_len);

    // Alice invites Claire to join the group
    Skissm__E2eeAddress **new_member_addresses = (Skissm__E2eeAddress **)malloc(sizeof(Skissm__E2eeAddress *));
    copy_address_from_address(&(new_member_addresses[0]), account_data[2]->address);
    size_t new_member_num = 1;
    size_t result = add_group_members(account_data[0]->address, group.group_address, new_member_addresses, new_member_num);
    assert(result == 0);

    // Alice sends a message to the group
    uint8_t plaintext_2[] = "This message will be sent to Bob and Claire.";
    size_t plaintext_len_2 = sizeof(plaintext_2) - 1;
    test_encryption(account_data[0]->address, plaintext_2, plaintext_len_2);

    // Alice removes Claire out of the group
    remove_group_members(account_data[0]->address, group.group_address, new_member_addresses, new_member_num);

    // Alice sends a message to the group
    uint8_t plaintext_3[] = "This message will be sent to Bob only.";
    size_t plaintext_len_3 = sizeof(plaintext_3) - 1;
    test_encryption(account_data[0]->address, plaintext_3, plaintext_len_3);

    // release
    skissm__e2ee_address__free_unpacked(member_addresses[0], NULL);
    skissm__e2ee_address__free_unpacked(member_addresses[1], NULL);
    free(member_addresses);
    free_protobuf(group_name);
    skissm__e2ee_address__free_unpacked(new_member_addresses[0], NULL);
    free(new_member_addresses);

    // test stop
    test_end();
    tear_down();
}

int main() {
    test_create_group();
    test_add_group_members();
    test_remove_group_members();
    test_create_add_remove();

    return 0;
}
