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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "skissm/account.h"
#include "skissm/crypto.h"
#include "skissm/e2ee_client.h"
#include "skissm/group_session.h"
#include "skissm/mem_util.h"
#include "skissm/session.h"
#include "skissm/skissm.h"

#include "test_plugin.h"
#include "mock_db.h"
#include "test_util.h"

void test_unload_inbound_group_session(){
    tear_up();

    // create two addresses
    Skissm__E2eeAddress *Alice, *Bob;
    mock_address(&Alice, "alice", E2EELAB_DOMAIN, "alice's device");
    mock_address(&Bob, "bob", E2EELAB_DOMAIN, "bob's device");

    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 2);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(Alice->user->user_id);
    group_members[0]->domain = strdup(Alice->domain);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(Bob->user->user_id);
    group_members[1]->domain = strdup(Bob->domain);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;

    // mock group address
    Skissm__E2eeAddress *group_address = (Skissm__E2eeAddress *) malloc(sizeof(Skissm__E2eeAddress));
    skissm__e2ee_address__init(group_address);
    group_address->group = (Skissm__PeerGroup *) malloc(sizeof(Skissm__PeerGroup));
    skissm__peer_group__init(group_address->group);
    group_address->peer_case = SKISSM__E2EE_ADDRESS__PEER_GROUP;
    group_address->domain = mock_domain_str();
    group_address->group->group_id = generate_uuid_str();

    // create inbound group session
    Skissm__GroupSession *group_session = (Skissm__GroupSession *) malloc(sizeof(Skissm__GroupSession));
    skissm__group_session__init(group_session);

    group_session->version = strdup(E2EE_PROTOCOL_VERSION);

    copy_address_from_address(&(group_session->session_owner), Alice);
    group_session->session_id = generate_uuid_str();

    group_session->group_info =
    (Skissm__GroupInfo *) malloc(sizeof(Skissm__GroupInfo));
    Skissm__GroupInfo *group_info = group_session->group_info;
    skissm__group_info__init(group_info);
    group_info->group_name = strdup("test_group");
    copy_address_from_address(&(group_info->group_address), group_address);
    group_info->n_group_members = 2;
    copy_group_members(&(group_info->group_members), group_members, group_info->n_group_members);

    group_session->sequence = 0;

    group_session->chain_key.len = 32;
    group_session->chain_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    get_skissm_plugin()->common_handler.gen_rand(group_session->chain_key.data, 32);

    crypto_curve25519_generate_key_pair(&(group_session->signature_public_key), &(group_session->signature_private_key));

    group_session->associated_data.len = AD_LENGTH;
    group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * AD_LENGTH);
    memcpy(group_session->associated_data.data, group_session->chain_key.data, 32);
    memcpy((group_session->associated_data.data) + 32, group_session->signature_public_key.data, CURVE25519_KEY_LENGTH);

    // insert to the db
    store_group_session(group_session);

    // unload the group session
    unload_inbound_group_session(Alice, group_session->session_id);

    // try to load the unloaded group session
    Skissm__GroupSession *group_session_copy = NULL;
    load_inbound_group_session(Alice, group_session->session_id, &group_session_copy);

    // assert group_session_copy is NULL
    print_result("test_unload_inbound_group_session", (group_session_copy == NULL));

    // free
    skissm__e2ee_address__free_unpacked(Alice, NULL);
    skissm__e2ee_address__free_unpacked(Bob, NULL);
    skissm__group_member__free_unpacked(group_members[0], NULL);
    skissm__group_member__free_unpacked(group_members[1], NULL);
    free(group_members);
    skissm__e2ee_address__free_unpacked(group_address, NULL);
    skissm__group_session__free_unpacked(group_session, NULL);
    skissm__group_session__free_unpacked(group_session_copy, NULL);

    tear_down();
}

int main(){
    test_unload_inbound_group_session();
    return 0;
}
