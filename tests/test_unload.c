/*
 * Copyright © 2021 Academia Sinica. All Rights Reserved.
 *
 * This file is part of E2EE Security.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * E2EE Security is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with E2EE Security.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "e2ees/account.h"
#include "e2ees/crypto.h"
#include "e2ees/e2ees_client.h"
#include "e2ees/group_session.h"
#include "e2ees/mem_util.h"
#include "e2ees/session.h"
#include "e2ees/e2ees.h"

#include "test_plugin.h"
#include "mock_db.h"
#include "test_util.h"

void test_unload_group_session_by_id(){
    tear_up();

    // create two addresses
    E2ees__E2eeAddress *Alice, *Bob;
    mock_address(&Alice, "alice", E2EELAB_DOMAIN, "alice's device");
    mock_address(&Bob, "bob", E2EELAB_DOMAIN, "bob's device");

    // the first group member is Alice
    E2ees__GroupMember **group_member_list = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *) * 2);
    group_member_list[0] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember));
    e2ees__group_member__init(group_member_list[0]);
    group_member_list[0]->user_id = strdup(Alice->user->user_id);
    group_member_list[0]->domain = strdup(Alice->domain);
    group_member_list[0]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_member_list[1] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember));
    e2ees__group_member__init(group_member_list[1]);
    group_member_list[1]->user_id = strdup(Bob->user->user_id);
    group_member_list[1]->domain = strdup(Bob->domain);
    group_member_list[1]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MEMBER;

    // mock group address
    E2ees__E2eeAddress *group_address = (E2ees__E2eeAddress *)malloc(sizeof(E2ees__E2eeAddress));
    e2ees__e2ee_address__init(group_address);
    group_address->group = (E2ees__PeerGroup *)malloc(sizeof(E2ees__PeerGroup));
    e2ees__peer_group__init(group_address->group);
    group_address->peer_case = E2EES__E2EE_ADDRESS__PEER_GROUP;
    group_address->domain = mock_domain_str();
    group_address->group->group_id = generate_uuid_str();

    // create inbound group session
    E2ees__GroupSession *group_session = (E2ees__GroupSession *)malloc(sizeof(E2ees__GroupSession));
    e2ees__group_session__init(group_session);

    group_session->version = strdup(E2EES_PROTOCOL_VERSION);

    copy_address_from_address(&(group_session->sender), Alice);
    copy_address_from_address(&(group_session->session_owner), Alice);
    group_session->session_id = generate_uuid_str();

    group_session->group_info =
    (E2ees__GroupInfo *)malloc(sizeof(E2ees__GroupInfo));
    E2ees__GroupInfo *group_info = group_session->group_info;
    e2ees__group_info__init(group_info);
    group_info->group_name = strdup("test_group");
    copy_address_from_address(&(group_info->group_address), group_address);
    group_info->n_group_member_list = 2;
    copy_group_members(&(group_info->group_member_list), group_member_list, group_info->n_group_member_list);

    group_session->sequence = 0;

    group_session->chain_key.len = 32;
    group_session->chain_key.data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    get_e2ees_plugin()->common_handler.gen_rand(group_session->chain_key.data, 32);

    group_session->associated_data.len = 64;
    group_session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * 64);
    memcpy(group_session->associated_data.data, group_session->chain_key.data, 32);
    memcpy((group_session->associated_data.data) + 32, group_session->chain_key.data, CURVE25519_KEY_LENGTH);

    // insert to the db
    store_group_session(group_session);

    // unload the group session
    unload_group_session_by_id(Alice, group_session->session_id);

    // try to load the unloaded group session
    E2ees__GroupSession *group_session_copy = NULL;
    load_group_session_by_id(Alice, Alice, group_session->session_id, &group_session_copy);

    // assert group_session_copy is NULL
    print_result("test_unload_group_session_by_id", (group_session_copy == NULL));

    // free
    e2ees__e2ee_address__free_unpacked(Alice, NULL);
    e2ees__e2ee_address__free_unpacked(Bob, NULL);
    e2ees__group_member__free_unpacked(group_member_list[0], NULL);
    e2ees__group_member__free_unpacked(group_member_list[1], NULL);
    free(group_member_list);
    e2ees__e2ee_address__free_unpacked(group_address, NULL);
    e2ees__group_session__free_unpacked(group_session, NULL);
    e2ees__group_session__free_unpacked(group_session_copy, NULL);

    tear_down();
}

int main(){
    test_unload_group_session_by_id();
    return 0;
}
