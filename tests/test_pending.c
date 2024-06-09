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
#include "skissm/e2ee_client.h"
#include "skissm/e2ee_client_internal.h"
#include "skissm/group_session.h"
#include "skissm/mem_util.h"
#include "skissm/session_manager.h"

#include "test_util.h"
#include "test_plugin.h"

static void on_log(Skissm__E2eeAddress *user_address, LogCode log_code, const char *log_msg) {
    print_log((char *)log_msg, log_code);
}

static skissm_event_handler_t test_event_handler = {
    on_log,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

static const cipher_suite_t *test_cipher_suite;

static void test_one_group_pre_key() {
    // test start
    tear_up();
    get_skissm_plugin()->event_handler = test_event_handler;

    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_CURVE25519,
        E2EE_PACK_ALG_KEM_CURVE25519,
        E2EE_PACK_ALG_SYMMETRIC_KEY_AES256GCM,
        E2EE_PACK_ALG_HASH_SHA2_256
    );
    test_cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;

    // mock address
    Skissm__E2eeAddress *user_address, *member_address;
    mock_address(&user_address, "alice", "alice's domain", "alice's device");
    mock_address(&member_address, "bob", "bob's domain", "bob's device");

    int key_len = test_cipher_suite->digital_signature_suite->get_crypto_param().sign_pub_key_len;

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
    outbound_group_session->e2ee_pack_id = e2ee_pack_id;
    copy_address_from_address(&(outbound_group_session->sender), user_address);
    copy_address_from_address(&(outbound_group_session->session_owner), user_address);
    outbound_group_session->session_id = generate_uuid_str();

    outbound_group_session->group_info =
    (Skissm__GroupInfo *) malloc(sizeof(Skissm__GroupInfo));
    Skissm__GroupInfo *group_info = outbound_group_session->group_info;
    skissm__group_info__init(group_info);
    group_info->group_name = strdup("test_group");
    copy_address_from_address(&(group_info->group_address), group_address);
    group_info->n_group_member_list = group_members_num;
    copy_group_members(&(group_info->group_member_list), group_members, group_members_num);

    outbound_group_session->sequence = 0;

    outbound_group_session->chain_key.len = test_cipher_suite->hash_suite->get_crypto_param().hash_len;
    outbound_group_session->chain_key.data = (uint8_t *) malloc(sizeof(uint8_t) * outbound_group_session->chain_key.len);
    get_skissm_plugin()->common_handler.gen_rand(outbound_group_session->chain_key.data, outbound_group_session->chain_key.len);

    outbound_group_session->group_seed.len = test_cipher_suite->hash_suite->get_crypto_param().hash_len;
    outbound_group_session->group_seed.data = (uint8_t *) malloc(sizeof(uint8_t) * outbound_group_session->group_seed.len);
    get_skissm_plugin()->common_handler.gen_rand(outbound_group_session->group_seed.data, outbound_group_session->group_seed.len);

    int ad_len = 2 * key_len;
    outbound_group_session->associated_data.len = ad_len;
    outbound_group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * ad_len);
    memcpy(outbound_group_session->associated_data.data, outbound_group_session->chain_key.data, key_len);
    memcpy((outbound_group_session->associated_data.data) + key_len, outbound_group_session->chain_key.data, key_len);

    get_skissm_plugin()->db_handler.store_group_session(outbound_group_session);

    uint8_t *group_pre_key_plaintext = NULL;
    size_t group_pre_key_plaintext_len = pack_group_pre_key_plaintext(outbound_group_session, &group_pre_key_plaintext, NULL);

    // store group pre-key
    char *pending_plaintext_id = generate_uuid_str();
    get_skissm_plugin()->db_handler.store_pending_plaintext_data(
        user_address,
        member_address,
        pending_plaintext_id,
        group_pre_key_plaintext,
        group_pre_key_plaintext_len,
        SKISSM__NOTIF_LEVEL__NOTIF_LEVEL_SESSION
    );

    // load group pre-key
    uint32_t n_group_pre_keys;
    char **pending_plaintext_id_list;
    uint8_t **group_pre_key_plaintext_data_list;
    size_t *group_pre_key_plaintext_data_len_list;
    Skissm__NotifLevel *notif_level;
    n_group_pre_keys = get_skissm_plugin()->db_handler.load_pending_plaintext_data(
        user_address,
        member_address,
        &pending_plaintext_id_list,
        &group_pre_key_plaintext_data_list,
        &group_pre_key_plaintext_data_len_list,
        &notif_level
    );
    assert(group_pre_key_plaintext_len == group_pre_key_plaintext_data_len_list[0]);
    assert(memcmp(group_pre_key_plaintext, group_pre_key_plaintext_data_list[0], group_pre_key_plaintext_data_len_list[0]) == 0);

    // unload group pre-key
    get_skissm_plugin()->db_handler.unload_pending_plaintext_data(user_address, member_address, pending_plaintext_id_list[0]);
    char **pending_plaintext_id_list_null;
    uint8_t **group_pre_key_plaintext_data_list_null;
    size_t *group_pre_key_plaintext_data_len_list_null;
    Skissm__NotifLevel *notif_level_null;
    get_skissm_plugin()->db_handler.load_pending_plaintext_data(
        user_address,
        member_address,
        &pending_plaintext_id_list_null,
        &group_pre_key_plaintext_data_list_null,
        &group_pre_key_plaintext_data_len_list_null,
        &notif_level_null
    );
    assert(pending_plaintext_id_list_null == NULL);
    assert(group_pre_key_plaintext_data_list_null == NULL);
    assert(group_pre_key_plaintext_data_len_list_null == NULL);

    // release
    skissm__e2ee_address__free_unpacked(user_address, NULL);
    skissm__e2ee_address__free_unpacked(member_address, NULL);
    skissm__e2ee_address__free_unpacked(group_address, NULL);
    skissm__group_session__free_unpacked(outbound_group_session, NULL);
    free(pending_plaintext_id);
    free_mem((void **)&(group_pre_key_plaintext_data_list[0]), group_pre_key_plaintext_data_len_list[0]);
    free(pending_plaintext_id_list[0]);
    free_mem((void **)&pending_plaintext_id_list, sizeof(char *) * n_group_pre_keys);
    free_mem((void **)&group_pre_key_plaintext_data_list, sizeof(uint8_t *) * n_group_pre_keys);
    free_mem((void **)&group_pre_key_plaintext_data_len_list, sizeof(size_t) * n_group_pre_keys);
    free_mem((void **)&notif_level, sizeof(Skissm__NotifLevel) * n_group_pre_keys);

    // test stop
    tear_down();
}

static void test_multiple_group_pre_keys() {
    // test start
    tear_up();

    // mock address
    Skissm__E2eeAddress *user_address, *member_address;
    mock_address(&user_address, "alice", "alice's domain", "alice's device");
    mock_address(&member_address, "bob", "bob's domain", "bob's device");

    // mock plaintext
    uint8_t plaintext_1[] = "abcdefghijklmnopqrstuvwxyz";
    size_t plaintext_1_len = sizeof(plaintext_1) - 1;
    uint8_t plaintext_2[] = "12345678901234567890";
    size_t plaintext_2_len = sizeof(plaintext_2) - 1;
    uint8_t plaintext_3[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    size_t plaintext_3_len = sizeof(plaintext_3) - 1;

    // store group pre-key
    char *pending_plaintext_1_id = generate_uuid_str();
    char *pending_plaintext_2_id = generate_uuid_str();
    char *pending_plaintext_3_id = generate_uuid_str();
    get_skissm_plugin()->db_handler.store_pending_plaintext_data(
        user_address,
        member_address,
        pending_plaintext_1_id,
        plaintext_1,
        plaintext_1_len,
        SKISSM__NOTIF_LEVEL__NOTIF_LEVEL_SESSION
    );
    get_skissm_plugin()->db_handler.store_pending_plaintext_data(
        user_address,
        member_address,
        pending_plaintext_2_id,
        plaintext_2,
        plaintext_2_len,
        SKISSM__NOTIF_LEVEL__NOTIF_LEVEL_SESSION
    );
    get_skissm_plugin()->db_handler.store_pending_plaintext_data(
        user_address,
        member_address,
        pending_plaintext_3_id,
        plaintext_3,
        plaintext_3_len,
        SKISSM__NOTIF_LEVEL__NOTIF_LEVEL_SESSION
    );

    // load pending plaintext
    uint32_t n_pending_plaintext;
    char **pending_plaintext_id_list;
    uint8_t **pending_plaintext_data_list;
    size_t *pending_plaintext_data_len_list;
    Skissm__NotifLevel *notif_level;
    n_pending_plaintext = get_skissm_plugin()->db_handler.load_pending_plaintext_data(
        user_address,
        member_address,
        &pending_plaintext_id_list,
        &pending_plaintext_data_list,
        &pending_plaintext_data_len_list,
        &notif_level
    );
    assert(n_pending_plaintext == 3);

    // unload group pre-key
    get_skissm_plugin()->db_handler.unload_pending_plaintext_data(user_address, member_address, pending_plaintext_2_id);

    // load pending plaintext again
    uint32_t n_pending_plaintext_left;
    char **pending_plaintext_id_left_list;
    uint8_t **pending_plaintext_data_left_list;
    size_t *pending_plaintext_data_len_left_list;
    Skissm__NotifLevel *notif_level_left;
    n_pending_plaintext_left = get_skissm_plugin()->db_handler.load_pending_plaintext_data(
        user_address,
        member_address,
        &pending_plaintext_id_left_list,
        &pending_plaintext_data_left_list,
        &pending_plaintext_data_len_left_list,
        &notif_level_left
    );
    assert(n_pending_plaintext_left == 2);

    // release
    skissm__e2ee_address__free_unpacked(user_address, NULL);
    skissm__e2ee_address__free_unpacked(member_address, NULL);
    free(pending_plaintext_1_id);
    free(pending_plaintext_2_id);
    free(pending_plaintext_3_id);
    free_mem((void **)&pending_plaintext_id_list, sizeof(char *) * n_pending_plaintext);
    free_mem((void **)&pending_plaintext_data_list, sizeof(uint8_t *) * n_pending_plaintext);
    free_mem((void **)&pending_plaintext_data_len_list, sizeof(size_t) * n_pending_plaintext);
    free_mem((void **)&notif_level, sizeof(Skissm__NotifLevel) * n_pending_plaintext);
    free_mem((void **)&pending_plaintext_id_left_list, sizeof(char *) * n_pending_plaintext_left);
    free_mem((void **)&pending_plaintext_data_left_list, sizeof(uint8_t *) * n_pending_plaintext_left);
    free_mem((void **)&pending_plaintext_data_len_left_list, sizeof(size_t) * n_pending_plaintext_left);
    free_mem((void **)&notif_level_left, sizeof(Skissm__NotifLevel) * n_pending_plaintext_left);

    // test stop
    tear_down();
}

static void test_pending_request_data() {
    // test start
    tear_up();

    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_CURVE25519,
        E2EE_PACK_ALG_KEM_CURVE25519,
        E2EE_PACK_ALG_SYMMETRIC_KEY_AES256GCM,
        E2EE_PACK_ALG_HASH_SHA2_256
    );

    // mock address
    Skissm__E2eeAddress *alice_address, *bob_address;
    mock_address(&alice_address, "alice", "alice's domain", "alice's device");
    mock_address(&bob_address, "bob", "bob's domain", "bob's device");

    ProtobufCBinaryData *our_ratchet_key = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
    our_ratchet_key->len = 32;
    our_ratchet_key->data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(our_ratchet_key->data, "abcdefghijklmnopqrstuvwxyz012345", 32);

    Skissm__AcceptRequest *accept_request = NULL;
    produce_accept_request(&accept_request, e2ee_pack_id, alice_address, bob_address, NULL, our_ratchet_key);

    // pack request to request_data
    size_t request_data_len = skissm__accept_request__get_packed_size(accept_request);
    uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
    skissm__accept_request__pack(accept_request, request_data);

    store_pending_request_internal(alice_address, SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_ACCEPT, request_data, request_data_len, NULL, 0);

    // load
    char **pending_request_id_list;
    uint8_t *request_type_list;
    uint8_t **request_data_list;
    size_t *request_data_len_list;
    size_t pending_request_data_num =
        get_skissm_plugin()->db_handler.load_pending_request_data(
            alice_address, &pending_request_id_list, &request_type_list, &request_data_list, &request_data_len_list
        );

    Skissm__PendingRequest *pending_request = skissm__pending_request__unpack(NULL, request_data_len_list[0], request_data_list[0]);

    // assert
    assert(pending_request_data_num == 1);
    assert(request_type_list[0] == SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_ACCEPT);
    assert(pending_request->request_data.len == request_data_len);
    assert(memcmp((void *)(pending_request->request_data.data), (void *)(request_data), request_data_len) == 0);

    // release
    skissm__e2ee_address__free_unpacked(alice_address, NULL);
    skissm__e2ee_address__free_unpacked(bob_address, NULL);
    free_protobuf(our_ratchet_key);
    free_mem((void **)&our_ratchet_key, sizeof(ProtobufCBinaryData));
    skissm__accept_request__free_unpacked(accept_request, NULL);
    skissm__pending_request__free_unpacked(pending_request, NULL);
    free_mem((void **)&request_data, request_data_len);
    free_mem((void **)&pending_request_id_list, sizeof(char *) * pending_request_data_num);
    free_mem((void **)&request_type_list, sizeof(uint8_t) * pending_request_data_num);
    free_mem((void **)&(request_data_list[0]), request_data_len_list[0]);
    free_mem((void **)&request_data_list, sizeof(uint8_t *) * pending_request_data_num);
    free_mem((void **)&request_data_len_list, sizeof(size_t) * pending_request_data_num);

    // test stop
    tear_down();
}

static void test_sending_before_accept() {
    // test start
    tear_up();

    // register
    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_256F,
        E2EE_PACK_ALG_KEM_KYBER1024,
        E2EE_PACK_ALG_SYMMETRIC_KEY_AES256GCM,
        E2EE_PACK_ALG_HASH_SHA2_256
    );
    char *alice_device_id = generate_uuid_str();
    const char *alice_authenticator = "alice@domain.com.tw";
    const char *alice_auth_code = "123456";
    Skissm__RegisterUserResponse *alice_response = NULL;
    register_user(
        &alice_response, e2ee_pack_id, "Alice", "alice", alice_device_id, alice_authenticator, alice_auth_code
    );
    char *bob_device_id = generate_uuid_str();
    const char *bob_authenticator = "bob@domain.com.tw";
    const char *bob_auth_code = "654321";
    Skissm__RegisterUserResponse *bob_response = NULL;
    register_user(
        &bob_response, e2ee_pack_id, "Bob", "bob", bob_device_id, bob_authenticator, bob_auth_code
    );

    Skissm__E2eeAddress *alice_address = alice_response->address, *bob_address = bob_response->address;

    // send the message first
    uint8_t plaintext[] = "This message will be sent to Bob before he accepts Alice's invitation.";
    size_t plaintext_len = sizeof(plaintext) - 1;

    int i;
    for (i = 0; i < 20; i++) {
        send_one2one_msg(
            alice_address,
            bob_address->user->user_id, bob_address->domain,
            SKISSM__NOTIF_LEVEL__NOTIF_LEVEL_NORMAL,
            plaintext, plaintext_len);
    }

    // invite
    Skissm__InviteResponse *response = invite(alice_address, bob_address->user->user_id, bob_address->domain);

    // release
    free(alice_device_id);
    free(bob_device_id);
    skissm__register_user_response__free_unpacked(alice_response, NULL);
    skissm__register_user_response__free_unpacked(bob_response, NULL);
    skissm__invite_response__free_unpacked(response, NULL);

    // test stop
    tear_down();
}

int main(){
    test_one_group_pre_key();
    test_multiple_group_pre_keys();
    test_pending_request_data();

    return 0;
}
