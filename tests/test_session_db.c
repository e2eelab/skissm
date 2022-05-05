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
#include "test_db.h"
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
    initialise_session(session, TEST_E2EE_PACK_ID, from, to);
    copy_address_from_address(&(session->session_owner), from);

    // create mock public keys
    session->alice_identity_key.len = 32;
    session->alice_identity_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->alice_identity_key.data, "11111111111111111111111111111111", 32);
    session->alice_ephemeral_key.len = 32;
    session->alice_ephemeral_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->alice_ephemeral_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);
    session->bob_signed_pre_key.len = 32;
    session->bob_signed_pre_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->bob_signed_pre_key.data, "22222222222222222222222222222222", 32);
    session->bob_one_time_pre_key.len = 32;
    session->bob_one_time_pre_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->bob_one_time_pre_key.data, "012345abcdefghijklmnopqrstuvwxyz", 32);

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

void test_load_inbound_session()
{
    tear_up();

    // create session and two addresses
    Skissm__Session *session = (Skissm__Session *) malloc(sizeof(Skissm__Session));
    skissm__session__init(session);

    Skissm__E2eeAddress *from, *to;
    mock_address(&from, "alice", "alice's domain", "alice's device");
    mock_address(&to, "bob", "bob's domain", "bob's device");
    initialise_session(session, TEST_E2EE_PACK_ID, from, to);
    copy_address_from_address(&(session->session_owner), to);

    // create mock public keys
    session->alice_identity_key.len = 32;
    session->alice_identity_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->alice_identity_key.data, "11111111111111111111111111111111", 32);
    session->alice_ephemeral_key.len = 32;
    session->alice_ephemeral_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->alice_ephemeral_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);
    session->bob_signed_pre_key.len = 32;
    session->bob_signed_pre_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->bob_signed_pre_key.data, "22222222222222222222222222222222", 32);
    session->bob_one_time_pre_key.len = 32;
    session->bob_one_time_pre_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->bob_one_time_pre_key.data, "012345abcdefghijklmnopqrstuvwxyz", 32);

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

void test_load_outbound_group_session()
{
    tear_up();

    // create two addresses
    Skissm__E2eeAddress *Alice, *Bob;
    mock_address(&Alice, "alice", "alice's domain", "alice's device");
    mock_address(&Bob, "bob", "bob's domain", "bob's device");

    // create member_addresses
    Skissm__E2eeAddress **member_addresses = (Skissm__E2eeAddress **) malloc(sizeof(Skissm__E2eeAddress *) * 2);
    copy_address_from_address(&(member_addresses[0]), Alice);
    copy_address_from_address(&(member_addresses[1]), Bob);

    // mock group address
    Skissm__E2eeAddress *group_address = (Skissm__E2eeAddress *) malloc(sizeof(Skissm__E2eeAddress));
    skissm__e2ee_address__init(group_address);
    group_address->group = (Skissm__PeerGroup *) malloc(sizeof(Skissm__PeerGroup));
    skissm__peer_group__init(group_address->group);
    group_address->peer_case = SKISSM__E2EE_ADDRESS__PEER_GROUP;
    group_address->domain = create_domain_str();
    group_address->group->group_id = generate_uuid_str();

    // create outbound group session
    Skissm__GroupSession *group_session = (Skissm__GroupSession *) malloc(sizeof(Skissm__GroupSession));
    skissm__group_session__init(group_session);

    group_session->version = PROTOCOL_VERSION;

    copy_address_from_address(&(group_session->session_owner), Alice);

    copy_address_from_address(&(group_session->group_address), group_address);

    group_session->session_id = generate_uuid_str();

    group_session->n_member_addresses = 2;

    copy_member_addresses_from_member_addresses(&(group_session->member_addresses), (const Skissm__E2eeAddress **)member_addresses, 2);

    group_session->sequence = 0;

    group_session->chain_key.len = 32;
    group_session->chain_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(group_session->chain_key.data, "01234567890123456789012345678901", 32);

    crypto_curve25519_generate_key_pair(&(group_session->signature_public_key), &(group_session->signature_private_key));

    group_session->associated_data.len = AD_LENGTH;
    group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * AD_LENGTH);
    memcpy(group_session->associated_data.data, group_session->chain_key.data, 32);
    memcpy((group_session->associated_data.data) + 32, group_session->signature_public_key.data, CURVE25519_KEY_LENGTH);

    // insert to the db
    store_group_session(group_session);

    // load_outbound_group_session
    Skissm__GroupSession *group_session_copy;
    load_outbound_group_session(Alice, group_address, &group_session_copy);

    // assert session equals to session_copy
    print_result("test_load_outbound_group_session", is_equal_group_session(group_session, group_session_copy));

    // free
    skissm__e2ee_address__free_unpacked(Alice, NULL);
    skissm__e2ee_address__free_unpacked(Bob, NULL);
    free(member_addresses);
    skissm__e2ee_address__free_unpacked(group_address, NULL);
    skissm__group_session__free_unpacked(group_session, NULL);
    skissm__group_session__free_unpacked(group_session_copy, NULL);

    tear_down();
}

void test_load_inbound_group_session()
{
    tear_up();

    // create two addresses
    Skissm__E2eeAddress *Alice, *Bob;
    mock_address(&Alice, "alice", E2EELAB_DOMAIN, "alice's device");
    mock_address(&Bob, "bob", E2EELAB_DOMAIN, "bob's device");

    // create member_addresses
    Skissm__E2eeAddress **member_addresses = (Skissm__E2eeAddress **) malloc(sizeof(Skissm__E2eeAddress *) * 2);
    copy_address_from_address(&(member_addresses[0]), Alice);
    copy_address_from_address(&(member_addresses[1]), Bob);

    // mock group address
    Skissm__E2eeAddress *group_address = (Skissm__E2eeAddress *) malloc(sizeof(Skissm__E2eeAddress));
    skissm__e2ee_address__init(group_address);
    group_address->group = (Skissm__PeerGroup *) malloc(sizeof(Skissm__PeerGroup));
    skissm__peer_group__init(group_address->group);
    group_address->peer_case = SKISSM__E2EE_ADDRESS__PEER_GROUP;
    group_address->domain = create_domain_str();
    group_address->group->group_id = generate_uuid_str();

    // create inbound group session
    Skissm__GroupSession *group_session = (Skissm__GroupSession *) malloc(sizeof(Skissm__GroupSession));
    skissm__group_session__init(group_session);

    group_session->version = PROTOCOL_VERSION;

    copy_address_from_address(&(group_session->session_owner), Alice);

    copy_address_from_address(&(group_session->group_address), group_address);

    group_session->session_id = generate_uuid_str();

    group_session->n_member_addresses = 2;

    copy_member_addresses_from_member_addresses(&(group_session->member_addresses), (const Skissm__E2eeAddress **)member_addresses, 2);

    group_session->sequence = 0;

    group_session->chain_key.len = 32;
    group_session->chain_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(group_session->chain_key.data, "01234567890123456789012345678901", 32);

    // inbound group session has no signature_private_key
    crypto_curve25519_generate_key_pair(&(group_session->signature_public_key), &(group_session->signature_private_key));
    free_mem((void **)&(group_session->signature_private_key.data), group_session->signature_private_key.len);
    group_session->signature_private_key.data = NULL;
    group_session->signature_private_key.len = 0;

    group_session->associated_data.len = AD_LENGTH;
    group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * AD_LENGTH);
    memcpy(group_session->associated_data.data, group_session->signature_public_key.data, CURVE25519_KEY_LENGTH);
    memcpy((group_session->associated_data.data) + CURVE25519_KEY_LENGTH, group_session->signature_public_key.data, CURVE25519_KEY_LENGTH);

    // insert to the db
    store_group_session(group_session);

    // load_inbound_group_session for owner: Alice
    Skissm__GroupSession *group_session_copy = NULL;
    load_inbound_group_session(Alice, group_session->group_address, &group_session_copy);

    // assert session equals to session_copy
    print_result("test_load_inbound_group_session", is_equal_group_session(group_session, group_session_copy));

    // free
    skissm__e2ee_address__free_unpacked(Alice, NULL);
    skissm__e2ee_address__free_unpacked(Bob, NULL);
    free(member_addresses);
    skissm__e2ee_address__free_unpacked(group_address, NULL);
    skissm__group_session__free_unpacked(group_session, NULL);
    skissm__group_session__free_unpacked(group_session_copy, NULL);

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
    initialise_session(session, TEST_E2EE_PACK_ID, from, to);
    copy_address_from_address(&(session->session_owner), from);

    // create mock public keys
    session->alice_identity_key.len = 32;
    session->alice_identity_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->alice_identity_key.data, "11111111111111111111111111111111", 32);
    session->alice_ephemeral_key.len = 32;
    session->alice_ephemeral_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->alice_ephemeral_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);
    session->bob_signed_pre_key.len = 32;
    session->bob_signed_pre_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->bob_signed_pre_key.data, "22222222222222222222222222222222", 32);
    session->bob_one_time_pre_key.len = 32;
    session->bob_one_time_pre_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->bob_one_time_pre_key.data, "012345abcdefghijklmnopqrstuvwxyz", 32);

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

    initialise_as_alice(test_cipher_suite, session->ratchet, secret, 128, our_ratchet_key, &their_ratchet_key);

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
    initialise_session(session, TEST_E2EE_PACK_ID, from, to);
    copy_address_from_address(&(session->session_owner), from);

    // create mock public keys
    session->alice_identity_key.len = 32;
    session->alice_identity_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->alice_identity_key.data, "11111111111111111111111111111111", 32);
    session->alice_ephemeral_key.len = 32;
    session->alice_ephemeral_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->alice_ephemeral_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);
    session->bob_signed_pre_key.len = 32;
    session->bob_signed_pre_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->bob_signed_pre_key.data, "22222222222222222222222222222222", 32);
    session->bob_one_time_pre_key.len = 32;
    session->bob_one_time_pre_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->bob_one_time_pre_key.data, "012345abcdefghijklmnopqrstuvwxyz", 32);

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

    initialise_as_alice(test_cipher_suite, session->ratchet, secret, 128, our_ratchet_key, &their_ratchet_key);

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
    initialise_session(session, TEST_E2EE_PACK_ID, from, to);
    copy_address_from_address(&(session->session_owner), to);

    // create mock public keys
    session->alice_identity_key.len = 32;
    session->alice_identity_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->alice_identity_key.data, "11111111111111111111111111111111", 32);
    session->alice_ephemeral_key.len = 32;
    session->alice_ephemeral_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->alice_ephemeral_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);
    session->bob_signed_pre_key.len = 32;
    session->bob_signed_pre_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->bob_signed_pre_key.data, "22222222222222222222222222222222", 32);
    session->bob_one_time_pre_key.len = 32;
    session->bob_one_time_pre_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->bob_one_time_pre_key.data, "012345abcdefghijklmnopqrstuvwxyz", 32);

    session->associated_data.len = 64;
    session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * 64);
    memcpy(session->associated_data.data, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", 64);

    session->session_id = generate_uuid_str();

    // initialise ratchet
    initialise_ratchet(&(session->ratchet));
    uint8_t secret[128] = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx";
    Skissm__KeyPair *our_ratchet_key = (Skissm__KeyPair *) malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(our_ratchet_key);
    our_ratchet_key->private_key.len = 32;
    our_ratchet_key->private_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(our_ratchet_key->private_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);
    our_ratchet_key->public_key.len = 32;
    our_ratchet_key->public_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(our_ratchet_key->public_key.data, "012345abcdefghijklmnopqrstuvwxyz", 32);

    initialise_as_bob(test_cipher_suite, session->ratchet, secret, 128, our_ratchet_key);

    // insert to the db
    store_session(session);

    // create mock receiver chain
    session->ratchet->receiver_chains = (Skissm__ReceiverChainNode **) malloc(sizeof(Skissm__ReceiverChainNode *));
    Skissm__ReceiverChainNode *chain = (Skissm__ReceiverChainNode *) malloc(sizeof(Skissm__ReceiverChainNode));
    skissm__receiver_chain_node__init(chain);
    chain->chain_key = (Skissm__ChainKey *) malloc(sizeof(Skissm__ChainKey));
    skissm__chain_key__init(chain->chain_key);
    chain->chain_key->index = 0;
    chain->chain_key->shared_key.len = 32;
    chain->chain_key->shared_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(chain->chain_key->shared_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);
    chain->ratchet_key_public.len = 32;
    chain->ratchet_key_public.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(chain->ratchet_key_public.data, "012345abcdefghijklmnopqrstuvwxyz", 32);
    session->ratchet->receiver_chains[0] = chain;
    session->ratchet->n_receiver_chains = 1;

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
    test_cipher_suite = get_e2ee_pack(TEST_E2EE_PACK_ID)->cipher_suite;

    test_load_outbound_session();
    test_load_inbound_session();
    test_load_outbound_group_session();
    test_load_inbound_group_session();
    test_store_session();
    test_equal_ratchet_outbound();
    test_equal_ratchet_inbound();
    return 0;
}
