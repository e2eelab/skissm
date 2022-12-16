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

#include "skissm/cipher.h"
#include "skissm/group_session.h"
#include "skissm/mem_util.h"
#include "skissm/session_manager.h"

#include "test_util.h"
#include "test_plugin.h"

static const cipher_suite_t *test_cipher_suite;

static void test_one_group_pre_key() {
    // test start
    tear_up();

    const char *e2ee_pack_id = TEST_E2EE_PACK_ID;
    test_cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;

    // mock address
    Skissm__E2eeAddress *user_address, *member_address;
    mock_address(&user_address, "alice", "alice's domain", "alice's device");
    mock_address(&member_address, "bob", "bob's domain", "bob's device");

    int key_len = test_cipher_suite->get_crypto_param().sign_key_len;

    size_t group_members_num = 2;
    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * group_members_num);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(user_address->user->user_id);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(member_address->user->user_id);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;

    // mock group address
    Skissm__E2eeAddress *group_address = (Skissm__E2eeAddress *) malloc(sizeof(Skissm__E2eeAddress));
    skissm__e2ee_address__init(group_address);
    group_address->group = (Skissm__PeerGroup *) malloc(sizeof(Skissm__PeerGroup));
    skissm__peer_group__init(group_address->group);
    group_address->peer_case = SKISSM__E2EE_ADDRESS__PEER_GROUP;
    group_address->domain = mock_domain_str();
    group_address->group->group_id = generate_uuid_str();

    // create an outbound group session
    Skissm__GroupSession *outbound_group_session = (Skissm__GroupSession *) malloc(sizeof(Skissm__GroupSession));
    skissm__group_session__init(outbound_group_session);

    outbound_group_session->version = strdup(E2EE_PROTOCOL_VERSION);
    outbound_group_session->e2ee_pack_id = strdup(e2ee_pack_id);

    copy_address_from_address(&(outbound_group_session->session_owner), user_address);
    copy_address_from_address(&(outbound_group_session->group_address), group_address);

    outbound_group_session->session_id = generate_uuid_str();
    outbound_group_session->n_group_members = group_members_num;
    copy_group_members(&(outbound_group_session->group_members), group_members, group_members_num);

    outbound_group_session->sequence = 0;

    outbound_group_session->chain_key.len = test_cipher_suite->get_crypto_param().hash_len;
    outbound_group_session->chain_key.data = (uint8_t *) malloc(sizeof(uint8_t) * outbound_group_session->chain_key.len);
    get_skissm_plugin()->common_handler.gen_rand(outbound_group_session->chain_key.data, outbound_group_session->chain_key.len);

    test_cipher_suite->sign_key_gen(&(outbound_group_session->signature_public_key), &(outbound_group_session->signature_private_key));

    int ad_len = 2 * key_len;
    outbound_group_session->associated_data.len = ad_len;
    outbound_group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * ad_len);
    memcpy(outbound_group_session->associated_data.data, outbound_group_session->signature_public_key.data, key_len);
    memcpy((outbound_group_session->associated_data.data) + key_len, outbound_group_session->signature_public_key.data, key_len);

    get_skissm_plugin()->db_handler.store_group_session(outbound_group_session);

    uint8_t *group_pre_key_plaintext = NULL;
    size_t group_pre_key_plaintext_len = pack_group_pre_key_plaintext(outbound_group_session, &group_pre_key_plaintext, NULL);

    // store group pre-key
    get_skissm_plugin()->db_handler.store_pending_plaintext_data(
        user_address,
        member_address,
        false,
        group_pre_key_plaintext,
        group_pre_key_plaintext_len
    );

    // load group pre-key
    uint32_t n_group_pre_keys;
    uint8_t **group_pre_key_plaintext_data_list;
    size_t *group_pre_key_plaintext_data_len_list;
    n_group_pre_keys = get_skissm_plugin()->db_handler.load_pending_plaintext_data(
        user_address,
        member_address,
        false,
        &group_pre_key_plaintext_data_list,
        &group_pre_key_plaintext_data_len_list
    );
    assert(group_pre_key_plaintext_len == group_pre_key_plaintext_data_len_list[0]);
    assert(memcmp(group_pre_key_plaintext, group_pre_key_plaintext_data_list[0], group_pre_key_plaintext_data_len_list[0]) == 0);

    // unload group pre-key
    get_skissm_plugin()->db_handler.unload_pending_plaintext_data(user_address, member_address, false);
    uint8_t **group_pre_key_plaintext_data_list_null;
    size_t *group_pre_key_plaintext_data_len_list_null;
    get_skissm_plugin()->db_handler.load_pending_plaintext_data(
        user_address,
        member_address,
        false,
        &group_pre_key_plaintext_data_list_null,
        &group_pre_key_plaintext_data_len_list_null
    );
    assert(group_pre_key_plaintext_data_list_null == NULL);
    assert(group_pre_key_plaintext_data_len_list_null == NULL);

    // release
    skissm__e2ee_address__free_unpacked(user_address, NULL);
    skissm__e2ee_address__free_unpacked(member_address, NULL);
    skissm__e2ee_address__free_unpacked(group_address, NULL);
    skissm__group_session__free_unpacked(outbound_group_session, NULL);

    // test stop
    tear_down();
}

static void test_multiple_group_pre_keys() {}

static void test_pending_request_data() {
    // test start
    tear_up();

    const char *e2ee_pack_id = TEST_E2EE_PACK_ID;

    // mock address
    Skissm__E2eeAddress *alice_address, *bob_address;
    mock_address(&alice_address, "alice", "alice's domain", "alice's device");
    mock_address(&bob_address, "bob", "bob's domain", "bob's device");

    Skissm__AcceptRequest *accept_request = produce_accept_request(e2ee_pack_id, alice_address, bob_address, NULL);

    // pack
    size_t request_data_len = skissm__accept_request__get_packed_size(accept_request);
    uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
    skissm__accept_request__pack(accept_request, request_data);

    // store
    get_skissm_plugin()->db_handler.store_pending_request_data(alice_address, ACCEPT_REQUEST, request_data, request_data_len);

    // load
    int *request_type;
    uint8_t **request_data_list;
    size_t *request_data_len_list;
    size_t pending_request_data_num =
        get_skissm_plugin()->db_handler.load_pending_request_data(
            alice_address, &request_type, &request_data_list, &request_data_len_list
        );

    // assert
    assert(pending_request_data_num == 1);
    assert(request_type[0] == ACCEPT_REQUEST);
    assert(request_data_len_list[0] == request_data_len);
    assert(memcmp(request_data_list[0], request_data, request_data_len) == 0);

    // release
    skissm__accept_request__free_unpacked(accept_request, NULL);
    free_mem((void **)&request_data, request_data_len);
    free_mem((void **)&request_type, pending_request_data_num);
    free_mem((void **)&(request_data_list[0]), request_data_len_list[0]);
    free_mem((void **)&request_data_list, pending_request_data_num);
    free_mem((void **)&request_data_len_list, pending_request_data_num);

    // test stop
    tear_down();
}

int main(){
    test_one_group_pre_key();
    test_multiple_group_pre_keys();
    test_pending_request_data();

    return 0;
}
