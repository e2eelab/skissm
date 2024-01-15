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
#include <inttypes.h>

#include "skissm/account.h"
#include "skissm/cipher.h"
#include "skissm/crypto.h"
#include "skissm/mem_util.h"
#include "skissm/skissm.h"
#include "skissm/e2ee_client.h"
#include "skissm/e2ee_client_internal.h"

#include "test_plugin.h"
#include "test_util.h"

static void on_log(Skissm__E2eeAddress *user_address, LogCode log_code, const char *log_msg) {
    print_log((char *)log_msg, log_code);
}

static void on_user_registered(Skissm__Account *account){
    print_msg("on_user_registered: user_id", (uint8_t *)account->address->user->user_id, strlen(account->address->user->user_id));
}

static skissm_event_handler_t test_event_handler = {
    on_log,
    on_user_registered,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

static void verify_one_time_pre_keys(Skissm__Account *account, unsigned int n_one_time_pre_key_list) {
    unsigned int i;

    assert(account->n_one_time_pre_key_list == n_one_time_pre_key_list);

    for (i = 0; i < account->n_one_time_pre_key_list; i++){
        assert(account->one_time_pre_key_list[i]->opk_id == (i + 1));
        assert(account->one_time_pre_key_list[i]->key_pair->private_key.data != NULL);
        assert(account->one_time_pre_key_list[i]->key_pair->private_key.len == CURVE25519_KEY_LENGTH);
        assert(account->one_time_pre_key_list[i]->key_pair->public_key.data != NULL);
        assert(account->one_time_pre_key_list[i]->key_pair->public_key.len == CURVE25519_KEY_LENGTH);
    }
}

static void create_account_test() {
    uint32_t e2ee_pack_id = gen_e2ee_pack_id(
        0,
        E2EE_PACK_ID_DIGITAL_SIGNATURE_CURVE25519,
        E2EE_PACK_ID_KEM_CURVE25519,
        E2EE_PACK_ID_SYMMETRIC_ENCRYPTION_AES256_SHA256
    );

    // Register test
    Skissm__Account *account = create_account(e2ee_pack_id);

    assert(account->identity_key->asym_key_pair->private_key.len == CURVE25519_KEY_LENGTH);
    assert(account->identity_key->asym_key_pair->public_key.len == CURVE25519_KEY_LENGTH);
    assert(account->identity_key->sign_key_pair->private_key.len == CURVE25519_KEY_LENGTH);
    assert(account->identity_key->sign_key_pair->public_key.len == CURVE25519_KEY_LENGTH);
    assert(account->signed_pre_key->spk_id == 1);
    assert(account->signed_pre_key->key_pair->private_key.len == CURVE25519_KEY_LENGTH);
    assert(account->signed_pre_key->key_pair->public_key.len == CURVE25519_KEY_LENGTH);
    assert(account->signed_pre_key->signature.len == CURVE_SIGNATURE_LENGTH);
    verify_one_time_pre_keys(account, 100);

    // Generate a new signed pre-key pair and a new signature
    generate_signed_pre_key(account);

    assert(account->signed_pre_key->spk_id == 2);
    assert(account->signed_pre_key->key_pair->private_key.len == CURVE25519_KEY_LENGTH);
    assert(account->signed_pre_key->key_pair->public_key.len == CURVE25519_KEY_LENGTH);
    assert(account->signed_pre_key->signature.len == CURVE_SIGNATURE_LENGTH);

    // Post some new one-time pre-keys test
    // Generate 80 one-time pre-key pairs
    Skissm__OneTimePreKey **output = generate_opks(80, account);

    verify_one_time_pre_keys(account, 180);

    // store account
    mock_random_user_address(&(account->address));
    get_skissm_plugin()->db_handler.store_account(account);
    printf("stored account\n");

    // load account
    Skissm__Account *loaded_account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(account->address, &loaded_account);
    assert(is_equal_account(account, loaded_account));

    // release
    skissm__account__free_unpacked(account, NULL);
    skissm__account__free_unpacked(loaded_account, NULL);
}

static void load_accounts_test(uint64_t num) {
    printf("====== load_accounts_test ======\n");
    size_t i;
    Skissm__Account **accounts = NULL;
    size_t accounts_num = get_skissm_plugin()->db_handler.load_accounts(&accounts);
    assert(accounts_num == num);
    printf("loaded accounts num: %zu\n", accounts_num);

    // pack/unpack test
    uint8_t **accounts_data;
    size_t *accounts_data_len;
    accounts_data_len = (size_t *)malloc(accounts_num * sizeof(size_t));
    accounts_data = (uint8_t **)malloc(accounts_num * sizeof(uint8_t *));
    memset(accounts_data_len, 0, accounts_num);
    for (i = 0; i < accounts_num; i++) {
        accounts_data_len[i] = skissm__account__get_packed_size(accounts[i]);
        accounts_data[i] = (uint8_t *)malloc(accounts_data_len[i] * sizeof(uint8_t));
        skissm__account__pack(accounts[i], accounts_data[i]);
        assert(accounts_data[i] != NULL);
        assert(accounts_data_len[i] > 0);
    }

    for (i = 0; i < accounts_num; i++) {
        Skissm__Account *unpacked_account  = skissm__account__unpack(NULL, accounts_data_len[i], accounts_data[i]);
        free_mem((void **)(&accounts_data[i]), accounts_data_len[i]);
        assert(is_equal_account(accounts[i], unpacked_account));
        printf("pack/unpack verified\n");
    }
    free_mem((void **)(&accounts_data_len), accounts_num * sizeof(size_t));
    free_mem((void **)(&accounts_data), accounts_num * sizeof(uint8_t *));
}

static void test_create_accounts(uint64_t num) {
    uint64_t i;
    for (i = 1; i <= num; i++) {
        create_account_test();
    }

    load_accounts_test(num);
}

static void test_register_user() {
    printf("====== test_register_user ======\n");
    uint32_t e2ee_pack_id = gen_e2ee_pack_id(
        0,
        E2EE_PACK_ID_DIGITAL_SIGNATURE_CURVE25519,
        E2EE_PACK_ID_KEM_CURVE25519,
        E2EE_PACK_ID_SYMMETRIC_ENCRYPTION_AES256_SHA256
    );
    const char *user_name = "alice";
    const char *user_id = "alice";
    const char *device_id = generate_uuid_str();
    const char *authenticator = "email";
    const char *auth_code = "123456";
    Skissm__RegisterUserResponse *response =
        register_user(
            e2ee_pack_id,
            user_name,
            user_id,
            device_id,
            authenticator,
            auth_code
        );
    assert(safe_strcmp(device_id, response->address->user->device_id));
    printf("Test user registered: \"%s@%s\"\n", response->address->user->user_id, response->address->domain);

    // release
    skissm__register_user_response__free_unpacked(response, NULL);
}

static void test_publish_spk() {
    printf("====== test_publish_spk ======\n");
    uint32_t e2ee_pack_id = gen_e2ee_pack_id(
        0,
        E2EE_PACK_ID_DIGITAL_SIGNATURE_CURVE25519,
        E2EE_PACK_ID_KEM_CURVE25519,
        E2EE_PACK_ID_SYMMETRIC_ENCRYPTION_AES256_SHA256
    );
    const char *user_name = "alice";
    const char *user_id = "alice";
    const char *device_id = generate_uuid_str();
    const char *authenticator = "email";
    const char *auth_code = "123456";
    Skissm__RegisterUserResponse *response =
        register_user(
            e2ee_pack_id,
            user_name,
            user_id,
            device_id,
            authenticator,
            auth_code
        );

    // load account
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(response->address, &account);
    uint32_t old_spk_id = account->signed_pre_key->spk_id;

    // update the signed pre-key
    generate_signed_pre_key(account);
    uint32_t new_spk_id = account->signed_pre_key->spk_id;
    Skissm__PublishSpkResponse *publish_spk_response = publish_spk_internal(account);

    assert(new_spk_id == old_spk_id + 1);

    // release
    skissm__register_user_response__free_unpacked(response, NULL);
    skissm__account__free_unpacked(account, NULL);
    skissm__publish_spk_response__free_unpacked(publish_spk_response, NULL);
}

Skissm__ProtoMsg *mock_supply_opks_msg(Skissm__E2eeAddress *user_address, uint32_t supply_opks_num) {
    Skissm__ProtoMsg *proto_msg = (Skissm__ProtoMsg *)malloc(sizeof(Skissm__ProtoMsg));
    skissm__proto_msg__init(proto_msg);

    copy_address_from_address(&(proto_msg->to), user_address);
    proto_msg->payload_case = SKISSM__PROTO_MSG__PAYLOAD_SUPPLY_OPKS_MSG;
    proto_msg->supply_opks_msg = (Skissm__SupplyOpksMsg *)malloc(sizeof(Skissm__SupplyOpksMsg));
    skissm__supply_opks_msg__init(proto_msg->supply_opks_msg);
    proto_msg->supply_opks_msg->opks_num = supply_opks_num;
    copy_address_from_address(&(proto_msg->supply_opks_msg->user_address), user_address);

    return proto_msg;
}

static void test_supply_opks() {
    printf("====== test_supply_opks ======\n");
    uint32_t e2ee_pack_id = gen_e2ee_pack_id(
        0,
        E2EE_PACK_ID_DIGITAL_SIGNATURE_CURVE25519,
        E2EE_PACK_ID_KEM_CURVE25519,
        E2EE_PACK_ID_SYMMETRIC_ENCRYPTION_AES256_SHA256
    );
    const char *user_name = "alice";
    const char *user_id = "alice";
    const char *device_id = generate_uuid_str();
    const char *authenticator = "email";
    const char *auth_code = "123456";
    Skissm__RegisterUserResponse *response =
        register_user(
            e2ee_pack_id,
            user_name,
            user_id,
            device_id,
            authenticator,
            auth_code
        );

    // load account
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(response->address, &account);

    // the server asks the client to supply some one-time pre-keys
    uint32_t supply_opks_num = 50;
    Skissm__E2eeAddress *user_address = account->address;
    Skissm__ProtoMsg *proto_msg = mock_supply_opks_msg(user_address, supply_opks_num);
    size_t proto_msg_data_len = skissm__proto_msg__get_packed_size(proto_msg);
    uint8_t proto_msg_data[proto_msg_data_len];
    skissm__proto_msg__pack(proto_msg, proto_msg_data);
    Skissm__ConsumeProtoMsgResponse *consume_proto_msg_response = process_proto_msg(proto_msg_data, proto_msg_data_len);

    // assert
    Skissm__Account *account_new = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(response->address, &account_new);
    assert(account_new->n_one_time_pre_key_list == (100 + supply_opks_num));

    // release
    skissm__register_user_response__free_unpacked(response, NULL);
    skissm__account__free_unpacked(account, NULL);
    skissm__account__free_unpacked(account_new, NULL);
    skissm__proto_msg__free_unpacked(proto_msg, NULL);
}

static void test_free_opks() {
    printf("====== test_free_opks ======\n");
    uint32_t e2ee_pack_id = gen_e2ee_pack_id(
        0,
        E2EE_PACK_ID_DIGITAL_SIGNATURE_CURVE25519,
        E2EE_PACK_ID_KEM_CURVE25519,
        E2EE_PACK_ID_SYMMETRIC_ENCRYPTION_AES256_SHA256
    );
    const char *user_name = "alice";
    const char *user_id = "alice";
    const char *device_id = generate_uuid_str();
    const char *authenticator = "email";
    const char *auth_code = "123456";
    Skissm__RegisterUserResponse *response =
        register_user(
            e2ee_pack_id, user_name, user_id, device_id, authenticator, auth_code
        );

    // load account
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(response->address, &account);

    size_t used_opks = 80;
    size_t i;
    for (i = 0; i < used_opks; i++) {
        account->one_time_pre_key_list[i]->used = true;
    }
    free_one_time_pre_key(account);
    // store
    get_skissm_plugin()->db_handler.store_account(account);

    // load account
    Skissm__Account *account_new = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(response->address, &account_new);
    assert(account_new->n_one_time_pre_key_list == (100 - used_opks));
    assert(account_new->one_time_pre_key_list[100 - used_opks] == NULL);

    // release
    skissm__register_user_response__free_unpacked(response, NULL);
    skissm__account__free_unpacked(account, NULL);
    skissm__account__free_unpacked(account_new, NULL);
}

int main(){
    // test start
    tear_up();
    get_skissm_plugin()->event_handler = test_event_handler;

    test_create_accounts(8);
    test_register_user();
    test_publish_spk();
    test_supply_opks();
    test_free_opks();

    // test stop
    tear_down();
    return 0;
}
