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
#include "skissm/ratchet.h"
#include "skissm/session.h"
#include "skissm/skissm.h"

#include "test_plugin.h"
#include "mock_db.h"
#include "test_plugin.h"
#include "test_util.h"

static const cipher_suite_t *test_cipher_suite;

void test_load_outbound_session()
{
    tear_up();;

    // create session and two addresses
    Skissm__Session *session = (Skissm__Session *) malloc(sizeof(Skissm__Session));
    Skissm__E2eeAddress *from, *to;
    mock_address(&from, "alice", "alice's domain", "alice's device");
    mock_address(&to, "bob", "bob's domain", "bob's device");
    initialise_session(session, TEST_E2EE_PACK_ID_ECC, from, to);
    copy_address_from_address(&(session->our_address), from);

    // create mock public keys
    session->alice_ephemeral_key.len = 32;
    session->alice_ephemeral_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->alice_ephemeral_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);

    session->associated_data.len = 64;
    session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * 64);
    memcpy(session->associated_data.data, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", 64);

    session->session_id = generate_uuid_str();

    // insert to the db
    store_session(session);

    // load_outbound_session
    Skissm__Session *session_copy;
    load_outbound_session(from, to, &session_copy);

    // assert session equals to session_copy
    print_result("test_load_outbound_session", is_equal_session(session, session_copy));

    // free
    skissm__e2ee_address__free_unpacked(from, NULL);
    skissm__e2ee_address__free_unpacked(to, NULL);
    skissm__session__free_unpacked(session, NULL);
    skissm__session__free_unpacked(session_copy, NULL);

    tear_down();
}

void test_load_outbound_sessions()
{
    tear_up();;

    // create sessions
    Skissm__Session *session_1, *session_2, *session_3;
    session_1 = (Skissm__Session *) malloc(sizeof(Skissm__Session));
    session_2 = (Skissm__Session *) malloc(sizeof(Skissm__Session));
    session_3 = (Skissm__Session *) malloc(sizeof(Skissm__Session));

    // create addresses
    Skissm__E2eeAddress *from, *to_1, *to_2, *to_3;
    mock_address(&from, "alice", "alice's domain", "alice's device");
    mock_address(&to_1, "bob", "bob's domain", "bob's device 1");
    mock_address(&to_2, "bob", "bob's domain", "bob's device 2");
    mock_address(&to_3, "bob", "bob's domain", "bob's device 3");

    // initialise sessions
    initialise_session(session_1, TEST_E2EE_PACK_ID_ECC, from, to_1);
    copy_address_from_address(&(session_1->our_address), from);
    initialise_session(session_2, TEST_E2EE_PACK_ID_ECC, from, to_2);
    copy_address_from_address(&(session_2->our_address), from);
    initialise_session(session_3, TEST_E2EE_PACK_ID_ECC, from, to_3);
    copy_address_from_address(&(session_3->our_address), from);

    // create mock public keys for session_1
    session_1->alice_ephemeral_key.len = 32;
    session_1->alice_ephemeral_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session_1->alice_ephemeral_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);

    session_1->associated_data.len = 64;
    session_1->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * 64);
    memcpy(session_1->associated_data.data, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", 64);

    session_1->session_id = generate_uuid_str();

    // insert to the db
    store_session(session_1);

    // create mock public keys for session_2
    session_2->alice_ephemeral_key.len = 32;
    session_2->alice_ephemeral_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session_2->alice_ephemeral_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);

    session_2->associated_data.len = 64;
    session_2->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * 64);
    memcpy(session_2->associated_data.data, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", 64);

    session_2->session_id = generate_uuid_str();

    // insert to the db
    store_session(session_2);

    // create mock public keys for session_3
    session_3->alice_ephemeral_key.len = 32;
    session_3->alice_ephemeral_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session_3->alice_ephemeral_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);

    session_3->associated_data.len = 64;
    session_3->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * 64);
    memcpy(session_3->associated_data.data, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", 64);

    session_3->session_id = generate_uuid_str();

    // insert to the db
    store_session(session_3);

    Skissm__Session **sessions = (Skissm__Session **) malloc(sizeof(Skissm__Session *) * 3);
    sessions[0] = session_1;
    sessions[1] = session_2;
    sessions[2] = session_3;

    // load_outbound_session
    Skissm__Session **sessions_copy;
    load_outbound_sessions(from, to_1->user->user_id, &sessions_copy);

    // assert session equals to session_copy
    print_result("test_load_outbound_sessions", is_equal_sessions(sessions, sessions_copy, 3));

    // free
    skissm__e2ee_address__free_unpacked(from, NULL);
    skissm__e2ee_address__free_unpacked(to_1, NULL);
    skissm__e2ee_address__free_unpacked(to_2, NULL);
    skissm__e2ee_address__free_unpacked(to_3, NULL);
    skissm__session__free_unpacked(session_1, NULL);
    skissm__session__free_unpacked(session_2, NULL);
    skissm__session__free_unpacked(session_3, NULL);

    tear_down();
}

void test_load_inbound_session()
{
    tear_up();

    // create session and two addresses
    Skissm__Session *session = (Skissm__Session *) malloc(sizeof(Skissm__Session));
    skissm__session__init(session);

    Skissm__E2eeAddress *from, *to;
    mock_address(&from, "alice", "alice's domain", "alice's device");
    mock_address(&to, "bob", "bob's domain", "bob's device");
    initialise_session(session, TEST_E2EE_PACK_ID_ECC, from, to);
    copy_address_from_address(&(session->our_address), to);

    // create mock public keys
    session->alice_ephemeral_key.len = 32;
    session->alice_ephemeral_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->alice_ephemeral_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);

    session->associated_data.len = 64;
    session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * 64);
    memcpy(session->associated_data.data, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", 64);

    session->session_id = generate_uuid_str();

    // insert to the db
    store_session(session);

    // load_inbound_session
    Skissm__Session *session_copy;
    load_inbound_session(session->session_id, to, &session_copy);

    // assert session equals to session_copy
    print_result("test_load_inbound_session", is_equal_session(session, session_copy));

    // free
    skissm__e2ee_address__free_unpacked(from, NULL);
    skissm__e2ee_address__free_unpacked(to, NULL);
    skissm__session__free_unpacked(session, NULL);
    skissm__session__free_unpacked(session_copy, NULL);

    tear_down();
}

void test_load_group_session_by_address()
{
    tear_up();

    // create two addresses
    Skissm__E2eeAddress *Alice, *Bob;
    mock_address(&Alice, "alice", "alice's domain", "alice's device");
    mock_address(&Bob, "bob", "bob's domain", "bob's device");

    // create group_members
    Skissm__GroupMember **group_members = (Skissm__GroupMember **) malloc(sizeof(Skissm__GroupMember *) * 2);
    group_members[0] = (Skissm__GroupMember *) malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup("alice");
    group_members[0]->domain = strdup("alice's domain");
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    group_members[1] = (Skissm__GroupMember *) malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup("bob");
    group_members[1]->domain = strdup("bob's domain");
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;

    // mock group address
    Skissm__E2eeAddress *group_address = (Skissm__E2eeAddress *) malloc(sizeof(Skissm__E2eeAddress));
    skissm__e2ee_address__init(group_address);
    group_address->group = (Skissm__PeerGroup *) malloc(sizeof(Skissm__PeerGroup));
    skissm__peer_group__init(group_address->group);
    group_address->peer_case = SKISSM__E2EE_ADDRESS__PEER_GROUP;
    group_address->domain = mock_domain_str();
    group_address->group->group_id = generate_uuid_str();

    // create outbound group session
    Skissm__GroupSession *group_session = (Skissm__GroupSession *) malloc(sizeof(Skissm__GroupSession));
    skissm__group_session__init(group_session);

    group_session->version = strdup(E2EE_PROTOCOL_VERSION);

    copy_address_from_address(&(group_session->sender), Alice);
    copy_address_from_address(&(group_session->session_owner), Alice);
    group_session->session_id = generate_uuid_str();

    group_session->group_info =
    (Skissm__GroupInfo *) malloc(sizeof(Skissm__GroupInfo));
    Skissm__GroupInfo *group_info = group_session->group_info;
    skissm__group_info__init(group_info);
    group_info->group_name = strdup("test_group");
    copy_address_from_address(&(group_info->group_address), group_address);
    group_info->n_group_members = 2;
    copy_group_members(&(group_info->group_members), group_members, 2);

    group_session->sequence = 0;

    group_session->chain_key.len = 32;
    group_session->chain_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(group_session->chain_key.data, "01234567890123456789012345678901", 32);

    group_session->group_seed.len = 32;
    group_session->group_seed.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(group_session->group_seed.data, "01234567890123456789012345678901", 32);

    group_session->associated_data.len = AD_LENGTH;
    group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * AD_LENGTH);
    memcpy(group_session->associated_data.data, group_session->chain_key.data, 32);
    memcpy((group_session->associated_data.data) + 32, group_session->group_seed.data, CURVE25519_KEY_LENGTH);

    // insert to the db
    store_group_session(group_session);

    // load_outbound_group_session
    Skissm__GroupSession *group_session_copy;
    load_group_session_by_address(Alice, Alice, group_address, &group_session_copy);

    // assert session equals to session_copy
    print_result("test_load_group_session_by_address", is_equal_group_session(group_session, group_session_copy));

    // free
    skissm__e2ee_address__free_unpacked(Alice, NULL);
    skissm__e2ee_address__free_unpacked(Bob, NULL);
    skissm__e2ee_address__free_unpacked(group_address, NULL);
    skissm__group_session__free_unpacked(group_session, NULL);
    skissm__group_session__free_unpacked(group_session_copy, NULL);

    tear_down();
}

void test_load_group_session_by_id()
{
    tear_up();

    // create two addresses
    Skissm__E2eeAddress *Alice, *Bob;
    mock_address(&Alice, "alice", E2EELAB_DOMAIN, "alice's device");
    mock_address(&Bob, "bob", E2EELAB_DOMAIN, "bob's device");

    // create group_members
    Skissm__GroupMember **group_members = (Skissm__GroupMember **) malloc(sizeof(Skissm__GroupMember *) * 2);
    group_members[0] = (Skissm__GroupMember *) malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup("alice");
    group_members[0]->domain = strdup("alice's domain");
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    group_members[1] = (Skissm__GroupMember *) malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup("bob");
    group_members[1]->domain = strdup("bob's domain");
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

    copy_address_from_address(&(group_session->sender), Bob);
    copy_address_from_address(&(group_session->session_owner), Alice);
    group_session->session_id = generate_uuid_str();

    group_session->group_info =
    (Skissm__GroupInfo *) malloc(sizeof(Skissm__GroupInfo));
    Skissm__GroupInfo *group_info = group_session->group_info;
    skissm__group_info__init(group_info);
    group_info->group_name = strdup("test_group");
    copy_address_from_address(&(group_info->group_address), group_address);
    group_info->n_group_members = 2;
    copy_group_members(&(group_info->group_members), group_members, 2);

    group_session->sequence = 0;

    group_session->chain_key.len = 32;
    group_session->chain_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(group_session->chain_key.data, "01234567890123456789012345678901", 32);

    group_session->associated_data.len = AD_LENGTH;
    group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * AD_LENGTH);
    memcpy(group_session->associated_data.data, group_session->chain_key.data, CURVE25519_KEY_LENGTH);
    memcpy((group_session->associated_data.data) + CURVE25519_KEY_LENGTH, group_session->chain_key.data, CURVE25519_KEY_LENGTH);

    // insert to the db
    store_group_session(group_session);

    // load_inbound_group_session for owner: Alice
    Skissm__GroupSession *group_session_copy = NULL;
    load_group_session_by_id(Bob, Alice, group_session->session_id, &group_session_copy);

    // assert session equals to session_copy
    print_result("test_load_group_session_by_id", is_equal_group_session(group_session, group_session_copy));

    // free
    skissm__e2ee_address__free_unpacked(Alice, NULL);
    skissm__e2ee_address__free_unpacked(Bob, NULL);
    skissm__e2ee_address__free_unpacked(group_address, NULL);
    skissm__group_session__free_unpacked(group_session, NULL);
    skissm__group_session__free_unpacked(group_session_copy, NULL);

    tear_down();
}

void test_load_group_addresses() {
    tear_up();

    // create two addresses
    Skissm__E2eeAddress *Alice, *Bob;
    mock_address(&Alice, "alice", E2EELAB_DOMAIN, "alice's device");
    mock_address(&Bob, "bob", E2EELAB_DOMAIN, "bob's device");

    // create group_members
    Skissm__GroupMember **group_members = (Skissm__GroupMember **) malloc(sizeof(Skissm__GroupMember *) * 2);
    group_members[0] = (Skissm__GroupMember *) malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup("alice");
    group_members[0]->domain = strdup("alice's domain");
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    group_members[1] = (Skissm__GroupMember *) malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup("bob");
    group_members[1]->domain = strdup("bob's domain");
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;

    // mock two group addresses
    Skissm__E2eeAddress *group_address = (Skissm__E2eeAddress *) malloc(sizeof(Skissm__E2eeAddress));
    skissm__e2ee_address__init(group_address);
    group_address->group = (Skissm__PeerGroup *) malloc(sizeof(Skissm__PeerGroup));
    skissm__peer_group__init(group_address->group);
    group_address->peer_case = SKISSM__E2EE_ADDRESS__PEER_GROUP;
    group_address->domain = mock_domain_str();
    group_address->group->group_id = generate_uuid_str();

    Skissm__E2eeAddress *group_address_2 = (Skissm__E2eeAddress *) malloc(sizeof(Skissm__E2eeAddress));
    skissm__e2ee_address__init(group_address_2);
    group_address_2->group = (Skissm__PeerGroup *) malloc(sizeof(Skissm__PeerGroup));
    skissm__peer_group__init(group_address_2->group);
    group_address_2->peer_case = SKISSM__E2EE_ADDRESS__PEER_GROUP;
    group_address_2->domain = mock_domain_str();
    group_address_2->group->group_id = generate_uuid_str();

    // create an outbound group session
    Skissm__GroupSession *group_session = (Skissm__GroupSession *) malloc(sizeof(Skissm__GroupSession));
    skissm__group_session__init(group_session);

    group_session->version = strdup(E2EE_PROTOCOL_VERSION);

    copy_address_from_address(&(group_session->sender), Alice);
    copy_address_from_address(&(group_session->session_owner), Alice);
    group_session->session_id = generate_uuid_str();

    group_session->group_info =
    (Skissm__GroupInfo *) malloc(sizeof(Skissm__GroupInfo));
    Skissm__GroupInfo *group_info = group_session->group_info;
    skissm__group_info__init(group_info);
    group_info->group_name = strdup("test_group");
    copy_address_from_address(&(group_info->group_address), group_address);
    group_info->n_group_members = 2;
    copy_group_members(&(group_info->group_members), group_members, 2);

    // insert to the db
    store_group_session(group_session);

    // create a second outbound group session
    Skissm__GroupSession *group_session_2 = (Skissm__GroupSession *) malloc(sizeof(Skissm__GroupSession));
    skissm__group_session__init(group_session_2);

    group_session_2->version = strdup(E2EE_PROTOCOL_VERSION);

    copy_address_from_address(&(group_session_2->sender), Alice);
    copy_address_from_address(&(group_session_2->session_owner), Alice);
    group_session_2->session_id = generate_uuid_str();

    group_session_2->group_info =
    (Skissm__GroupInfo *) malloc(sizeof(Skissm__GroupInfo));
    group_info = group_session_2->group_info;
    skissm__group_info__init(group_info);
    group_info->group_name = strdup("test_group");
    copy_address_from_address(&(group_info->group_address), group_address_2);
    group_info->n_group_members = 2;
    copy_group_members(&(group_info->group_members), group_members, 2);

    // insert to the db
    store_group_session(group_session_2);

    // load the group address
    Skissm__E2eeAddress **group_addresses;
    size_t n_group_addresses = load_group_addresses(Alice, Alice, &group_addresses);

    // assert the group addresses
    bool success = false;
    if (compare_address(group_addresses[0], group_address)) {
        if (compare_address(group_addresses[1], group_address_2)) {
            success = true;
        }
    }
    print_result("test_load_group_addresses", success);

    // free
    skissm__e2ee_address__free_unpacked(Alice, NULL);
    skissm__e2ee_address__free_unpacked(Bob, NULL);
    skissm__e2ee_address__free_unpacked(group_address, NULL);
    skissm__e2ee_address__free_unpacked(group_address_2, NULL);
    skissm__group_session__free_unpacked(group_session, NULL);
    skissm__group_session__free_unpacked(group_session_2, NULL);
    size_t i;
    for (i = 0; i < n_group_addresses; i++) {
        skissm__e2ee_address__free_unpacked(group_addresses[i], NULL);
    }
    free(group_addresses);

    tear_down();
}

void test_store_session()
{
    tear_up();

    // create session and two addresses
    Skissm__Session *session = (Skissm__Session *) malloc(sizeof(Skissm__Session));
    Skissm__E2eeAddress *from, *to;
    mock_address(&from, "alice", "alice's domain", "alice's device");
    mock_address(&to, "bob", "bob's domain", "bob's device");
    initialise_session(session, TEST_E2EE_PACK_ID_ECC, from, to);
    copy_address_from_address(&(session->our_address), from);

    // create mock public keys
    session->alice_ephemeral_key.len = 32;
    session->alice_ephemeral_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->alice_ephemeral_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);

    session->associated_data.len = 64;
    session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * 64);
    memcpy(session->associated_data.data, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", 64);

    session->session_id = generate_uuid_str();

    // initialise ratchet
    initialise_ratchet(&(session->ratchet));
    uint8_t secret[128] = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx";
    ProtobufCBinaryData their_ratchet_key;
    their_ratchet_key.len = 32;
    their_ratchet_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(their_ratchet_key.data, "11111111111111111111111111111111", 32);
    Skissm__KeyPair *our_ratchet_key = (Skissm__KeyPair *) malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(our_ratchet_key);
    our_ratchet_key->private_key.len = 32;
    our_ratchet_key->private_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(our_ratchet_key->private_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);
    our_ratchet_key->public_key.len = 32;
    our_ratchet_key->public_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(our_ratchet_key->public_key.data, "012345abcdefghijklmnopqrstuvwxyz", 32);

    initialise_as_alice(test_cipher_suite, session->ratchet, secret, 128, our_ratchet_key, &their_ratchet_key, NULL);

    // insert to the db
    store_session(session);

    session->ratchet->sender_chain->chain_key->index += 1;
    store_session(session);

    // load_outbound_session
    Skissm__Session *session_copy;
    load_outbound_session(from, to, &session_copy);

    // assert session equals to session_copy
    bool is_equal_index;
    is_equal_index = (session->ratchet->sender_chain->chain_key->index == session_copy->ratchet->sender_chain->chain_key->index);
    print_result("test_store_session", is_equal_index);

    // free
    skissm__e2ee_address__free_unpacked(from, NULL);
    skissm__e2ee_address__free_unpacked(to, NULL);
    skissm__session__free_unpacked(session, NULL);
    skissm__session__free_unpacked(session_copy, NULL);

    tear_down();
}

void test_equal_ratchet_outbound()
{
    tear_up();

    // create session and two addresses
    Skissm__Session *session = (Skissm__Session *) malloc(sizeof(Skissm__Session));
    Skissm__E2eeAddress *from, *to;
    mock_address(&from, "alice", "alice's domain", "alice's device");
    mock_address(&to, "bob", "bob's domain", "bob's device");
    initialise_session(session, TEST_E2EE_PACK_ID_ECC, from, to);
    copy_address_from_address(&(session->our_address), from);

    // create mock public keys
    session->alice_ephemeral_key.len = 32;
    session->alice_ephemeral_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->alice_ephemeral_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);

    session->associated_data.len = 64;
    session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * 64);
    memcpy(session->associated_data.data, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", 64);

    session->session_id = generate_uuid_str();

    // initialise ratchet
    initialise_ratchet(&(session->ratchet));
    uint8_t secret[128] = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx";
    ProtobufCBinaryData their_ratchet_key;
    their_ratchet_key.len = 32;
    their_ratchet_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(their_ratchet_key.data, "11111111111111111111111111111111", 32);
    Skissm__KeyPair *our_ratchet_key = (Skissm__KeyPair *) malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(our_ratchet_key);
    our_ratchet_key->private_key.len = 32;
    our_ratchet_key->private_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(our_ratchet_key->private_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);
    our_ratchet_key->public_key.len = 32;
    our_ratchet_key->public_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(our_ratchet_key->public_key.data, "012345abcdefghijklmnopqrstuvwxyz", 32);

    initialise_as_alice(test_cipher_suite, session->ratchet, secret, 128, our_ratchet_key, &their_ratchet_key, NULL);

    // insert to the db
    store_session(session);

    // load_outbound_session
    Skissm__Session *session_copy;
    load_outbound_session(from, to, &session_copy);

    // assert session equals to session_copy
    print_result("test_equal_ratchet_outbound", is_equal_ratchet(session->ratchet, session_copy->ratchet));

    // free
    skissm__e2ee_address__free_unpacked(from, NULL);
    skissm__e2ee_address__free_unpacked(to, NULL);
    skissm__session__free_unpacked(session, NULL);
    skissm__session__free_unpacked(session_copy, NULL);

    tear_down();
}

void test_equal_ratchet_inbound()
{
    tear_up();

    // create session and two addresses
    Skissm__Session *session = (Skissm__Session *) malloc(sizeof(Skissm__Session));
    Skissm__E2eeAddress *from, *to;
    mock_address(&from, "alice", "alice's domain", "alice's device");
    mock_address(&to, "bob", "bob's domain", "bob's device");
    initialise_session(session, TEST_E2EE_PACK_ID_ECC, from, to);
    copy_address_from_address(&(session->our_address), to);

    // create mock public keys
    session->alice_ephemeral_key.len = 32;
    session->alice_ephemeral_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->alice_ephemeral_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);

    session->associated_data.len = 64;
    session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * 64);
    memcpy(session->associated_data.data, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", 64);

    session->session_id = generate_uuid_str();

    // initialise ratchet
    initialise_ratchet(&(session->ratchet));
    ProtobufCBinaryData their_ratchet_key;
    their_ratchet_key.len = 32;
    their_ratchet_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(their_ratchet_key.data, "11111111111111111111111111111111", 32);
    uint8_t secret[128] = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx";
    Skissm__KeyPair *our_ratchet_key = (Skissm__KeyPair *) malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(our_ratchet_key);
    our_ratchet_key->private_key.len = 32;
    our_ratchet_key->private_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(our_ratchet_key->private_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);
    our_ratchet_key->public_key.len = 32;
    our_ratchet_key->public_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(our_ratchet_key->public_key.data, "012345abcdefghijklmnopqrstuvwxyz", 32);

    initialise_as_bob(test_cipher_suite, session->ratchet, secret, 128, our_ratchet_key, &their_ratchet_key);

    // insert to the db
    store_session(session);

    // create mock receiver chain
    Skissm__ReceiverChainNode *chain = (Skissm__ReceiverChainNode *) malloc(sizeof(Skissm__ReceiverChainNode));
    skissm__receiver_chain_node__init(chain);
    chain->chain_key = (Skissm__ChainKey *) malloc(sizeof(Skissm__ChainKey));
    skissm__chain_key__init(chain->chain_key);
    chain->chain_key->index = 0;
    chain->chain_key->shared_key.len = 32;
    chain->chain_key->shared_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(chain->chain_key->shared_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);
    chain->their_ratchet_public_key.len = 32;
    chain->their_ratchet_public_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(chain->their_ratchet_public_key.data, "012345abcdefghijklmnopqrstuvwxyz", 32);
    chain->our_ratchet_private_key.len = 32;
    chain->our_ratchet_private_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(chain->our_ratchet_private_key.data, "abcdefghijkl012345mnopqrstuvwxyz", 32);
    session->ratchet->receiver_chain = chain;

    // store session again
    store_session(session);

    // load_inbound_session
    Skissm__Session *session_copy;
    load_inbound_session(session->session_id, to, &session_copy);

    // assert session equals to session_copy
    print_result("test_equal_ratchet_inbound", is_equal_ratchet(session->ratchet, session_copy->ratchet));

    // free
    skissm__e2ee_address__free_unpacked(from, NULL);
    skissm__e2ee_address__free_unpacked(to, NULL);
    skissm__session__free_unpacked(session, NULL);
    skissm__session__free_unpacked(session_copy, NULL);

    tear_down();
}

int main(){
    test_cipher_suite = get_e2ee_pack(TEST_E2EE_PACK_ID_ECC)->cipher_suite;

    test_load_outbound_session();
    test_load_outbound_sessions();
    test_load_inbound_session();
    test_load_group_session_by_address();
    test_load_group_session_by_id();
    test_load_group_addresses();
    test_store_session();
    test_equal_ratchet_outbound();
    test_equal_ratchet_inbound();
    return 0;
}
