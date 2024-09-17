/**
 * @file
 * @copyright © 2020-2021 by Academia Sinica
 * @brief account test
 *
 * @page test_account account documentation
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
 * 
 * @section test_create_accounts
 * Test if we can create accounts.
 * 
 * @section test_register_user
 * This can check if a client can register or not.
 * 
 * @section test_publish_spk
 * If the signed pre-key is expired, the client should generate a new signed pre-key and publish it to the server.
 * 
 * @section test_supply_opks
 * The client will be notified to generate a number of one-time pre-keys if the server finds that the one-time pre-keys are used up.
 * 
 * 
 * 
 * @defgroup Unit Unit test
 * This includes unit tests.
 * 
 * @defgroup Integration Integration test
 * This includes integration tests.
 * 
 * 
 * @defgroup account_unit account unit test
 * @ingroup Unit
 * This includes unit tests about account.
 * 
 * @defgroup account_begin account begin test
 * @ingroup account_unit
 * @{
 * @section sec10001 Test Description
 * 
 * @section sec10002 Test Objectives
 * To verify the functionality of the function account_begin.
 * @section sec10003 Test Case ID
 * @section sec10004 Test Case Title: account_begin
 * @section sec10005 Preconditions
 * @section sec10006 Test Steps
 * @section sec10007 Expected Results
 * @}
 * 
 * @defgroup account_end account end test
 * @ingroup account_unit
 * @{
 * @section sec10101 Test Description
 * 
 * @section sec10102 Test Objectives
 * To verify the functionality of the function account_end.
 * @section sec10103 Test Case ID
 * @section sec10104 Test Case Title: account_end
 * @section sec10105 Preconditions
 * @section sec10106 Test Steps
 * @section sec10107 Expected Results
 * @}
 * 
 * @defgroup generate_identity_key generate identity key test
 * @ingroup account_unit
 * @{
 * @section sec10201 Test Description
 * 
 * @section sec10202 Test Objectives
 * To verify the functionality of the function generate_identity_key.
 * @section sec10203 Test Case ID
 * @section sec10204 Test Case Title: generate_identity_key
 * @section sec10205 Preconditions
 * @section sec10206 Test Steps
 * @section sec10207 Expected Results
 * @}
 * 
 * @defgroup generate_signed_pre_key generate signed pre-key test
 * @ingroup account_unit
 * @{
 * @section sec10301 Test Description
 * 
 * @section sec10302 Test Objectives
 * To verify the functionality of the function generate_signed_pre_key.
 * @section sec10303 Test Case ID
 * @section sec10304 Test Case Title: generate_signed_pre_key
 * @section sec10305 Preconditions
 * @section sec10306 Test Steps
 * @section sec10307 Expected Results
 * @}
 * 
 * @defgroup generate_opks generate one-time pre-key test
 * @ingroup account_unit
 * @{
 * @section sec10401 Test Description
 * 
 * @section sec10402 Test Objectives
 * To verify the functionality of the function generate_opks.
 * @section sec10403 Test Case ID
 * @section sec10404 Test Case Title: generate_opks
 * @section sec10405 Preconditions
 * @section sec10406 Test Steps
 * @section sec10407 Expected Results
 * @}
 * 
 * @defgroup create_account create account test
 * @ingroup account_unit
 * @{
 * @section sec10501 Test Description
 * 
 * @section sec0502 Test Objectives
 * To verify the functionality of the function create_account.
 * @section sec10503 Test Case ID
 * @section sec10504 Test Case Title: create_account
 * @section sec10505 Preconditions
 * @section sec10506 Test Steps
 * @section sec10507 Expected Results
 * @}
 * 
 * 
 * @defgroup account_int account integration test
 * @ingroup Integration
 * This includes integration tests about account.
 * 
 * @defgroup account_test_create_accounts create account test
 * @ingroup account_int
 * @{
 * @section sec11001 Test Description
 * This test case generates a certain number, given by the input, of accounts.
 * These accounts will be stored into db and will be loaded to check integrity.
 * @section sec11002 Test Objectives
 * To assure that this device can create several accounts.
 * @section sec11003 Test Case ID
 * @section sec11004 Test Case Title: test_create_accounts
 * @section sec11005 Preconditions
 * The input parameter num should be inserted.
 * @section sec11006 Test Steps
 * Step 1: Input the parameter num, the number of accounts to be created.\n
 * Step 2: Create the accounts.
 * @section sec11007 Expected Results
 * No output.
 * @}
 * 
 * @defgroup account_test_register_user register user test
 * @ingroup account_int
 * @{
 * @section sec11101 Test Description
 * To call the function register_user with given inputs.
 * @section sec11102 Test Objectives
 * To verify the functionality of the function register_user.
 * @section sec11103 Test Case ID
 * @section sec11104 Test Case Title: test_register_user
 * @section sec11105 Preconditions
 * @section sec11106 Test Steps
 * Step 1: Generate the address, including the user name, user id, device id, etc.\n
 * Step 2: Register.
 * @section sec11107 Expected Results
 * No output.
 * @}
 * 
 * @defgroup account_test_publish_spk publish spk test
 * @ingroup account_int
 * @{
 * @section sec11201 Test Description
 * A registered account will generate a new pair of signed pre-key pair and publish the public part of the key pair and the signature to the server.
 * @section sec11202 Test Objectives
 * To verify the functionality of the function publish_spk_internal.
 * @section sec11203 Test Case ID
 * @section sec11204 Test Case Title: test_publish_spk
 * @section sec11205 Preconditions
 * @section sec11206 Test Steps
 * Step 1: Register.\n
 * Step 2: Generate a new pair of signed pre-key.\n
 * Step 3: Pulish the public part of signed pre-key pair to the server.
 * @section sec11207 Expected Results
 * No output.
 * @}
 * 
 * @defgroup account_test_supply_opks supply opks test
 * @ingroup account_int
 * @{
 * @section sec11301 Test Description
 * The server notifies the client to generate a number of one-time pre-keys.
 * @section sec11302 Test Objectives
 * To assure that the procedure of supplying one-time pre-keys is correct.
 * @section sec11303 Test Case ID
 * @section sec11304 Test Case Title: test_supply_opks
 * @section sec11305 Preconditions
 * @section sec11306 Test Steps
 * Step 1: Register.\n
 * Step 2: Server notifies this device to generate some one-time pre-key pairs.\n
 * Step 3: Generate the one-time pre-key pairs and publish them to the server.
 * @section sec11307 Expected Results
 * No output.
 * @}
 * 
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

static void create_account_test() {
    uint32_t e2ee_pack_id = gen_e2ee_pack_id_pqc();

    int ret = 0;

    // register test
    Skissm__Account *account = NULL;
    ret = create_account(&account, e2ee_pack_id);
    assert(ret == 0);

    // generate a new signed pre-key pair and a new signature
    Skissm__SignedPreKey *signed_pre_key = NULL;
    ret = generate_signed_pre_key(&signed_pre_key, e2ee_pack_id, 1, account->signed_pre_key->key_pair->private_key.data);
    assert(ret == 0);

    skissm__signed_pre_key__free_unpacked(account->signed_pre_key, NULL);
    account->signed_pre_key = signed_pre_key;

    // post some new one-time pre-keys test
    // generate 80 one-time pre-key pairs
    Skissm__OneTimePreKey **output = NULL;
    ret = generate_opks(&output, 80, e2ee_pack_id, 101);
    assert(ret == 0);
    ret = insert_opks(account, output, 80);
    assert(ret == 0);

    // store account
    mock_random_user_address(&(account->address));
    get_skissm_plugin()->db_handler.store_account(account);
    printf("stored account\n");

    // load account
    Skissm__Account *loaded_account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(account->address, &loaded_account);
    assert(is_equal_account(account, loaded_account));

    // release
    free_proto(account);
    if (loaded_account != NULL) {
        skissm__account__free_unpacked(loaded_account, NULL);
        loaded_account = NULL;
    }
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
        Skissm__Account *unpacked_account = skissm__account__unpack(NULL, accounts_data_len[i], accounts_data[i]);
        free_mem((void **)(&accounts_data[i]), accounts_data_len[i]);
        assert(is_equal_account(accounts[i], unpacked_account));
        printf("pack/unpack verified\n");
    }
    free_mem((void **)(&accounts_data_len), accounts_num * sizeof(size_t));
    free_mem((void **)(&accounts_data), accounts_num * sizeof(uint8_t *));
}

static void test_create_accounts(uint64_t num) {
    // test start
    printf("====== test_create_accounts ======\n");
    tear_up();
    get_skissm_plugin()->event_handler = test_event_handler;

    uint64_t i;
    for (i = 1; i <= num; i++) {
        create_account_test();
    }

    load_accounts_test(num);

    // test stop
    tear_down();
    printf("====================================\n");
}

static void test_register_user() {
    // test start
    printf("====== test_register_user ======\n");
    tear_up();
    get_skissm_plugin()->event_handler = test_event_handler;

    uint32_t e2ee_pack_id = gen_e2ee_pack_id_pqc();
    const char *user_name = "alice";
    const char *user_id = "alice";
    const char *device_id = generate_uuid_str();
    const char *authenticator = "email";
    const char *auth_code = "123456";
    int ret = 0;
    Skissm__RegisterUserResponse *response = NULL;
    ret = register_user(
        &response, e2ee_pack_id, user_name, user_id, device_id, authenticator, auth_code
    );
    assert(ret == 0);
    printf("Test user registered: \"%s@%s\"\n", response->address->user->user_id, response->address->domain);

    // release
    skissm__register_user_response__free_unpacked(response, NULL);

    // test stop
    tear_down();
    printf("====================================\n");
}

static void test_publish_spk() {
    // test start
    printf("====== test_publish_spk ======\n");
    tear_up();
    get_skissm_plugin()->event_handler = test_event_handler;

    uint32_t e2ee_pack_id = gen_e2ee_pack_id_pqc();
    const char *user_name = "alice";
    const char *user_id = "alice";
    const char *device_id = generate_uuid_str();
    const char *authenticator = "email";
    const char *auth_code = "123456";
    int ret = 0;
    Skissm__RegisterUserResponse *register_user_response = NULL;
    ret = register_user(
        &register_user_response, e2ee_pack_id, user_name, user_id, device_id, authenticator, auth_code
    );

    // load account
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(register_user_response->address, &account);
    uint32_t old_spk_id = account->signed_pre_key->spk_id;

    // update the signed pre-key
    Skissm__SignedPreKey *signed_pre_key = NULL;
    generate_signed_pre_key(&signed_pre_key, e2ee_pack_id, 1, account->signed_pre_key->key_pair->private_key.data);

    skissm__signed_pre_key__free_unpacked(account->signed_pre_key, NULL);
    account->signed_pre_key = signed_pre_key;

    uint32_t new_spk_id = account->signed_pre_key->spk_id;
    Skissm__PublishSpkResponse *publish_spk_response = NULL;
    publish_spk_internal(&publish_spk_response, account);

    assert(new_spk_id == old_spk_id + 1);

    // release
    free_proto(register_user_response);
    free_proto(account);
    free_proto(publish_spk_response);

    // test stop
    tear_down();
    printf("====================================\n");
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
    // test start
    printf("====== test_supply_opks ======\n");
    tear_up();
    get_skissm_plugin()->event_handler = test_event_handler;

    uint32_t e2ee_pack_id = gen_e2ee_pack_id_pqc();
    const char *user_name = "alice";
    const char *user_id = "alice";
    const char *device_id = generate_uuid_str();
    const char *authenticator = "email";
    const char *auth_code = "123456";
    int ret = 0;
    Skissm__RegisterUserResponse *register_user_response = NULL;
    ret = register_user(
        &register_user_response, e2ee_pack_id, user_name, user_id, device_id, authenticator, auth_code
    );

    // load account
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(register_user_response->address, &account);

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
    get_skissm_plugin()->db_handler.load_account_by_address(register_user_response->address, &account_new);
    assert(account_new->n_one_time_pre_key_list == (100 + supply_opks_num));

    // release
    free_proto(register_user_response);
    free_proto(account);
    if (account_new != NULL) {
        skissm__account__free_unpacked(account_new, NULL);
        account_new = NULL;
    }
    free_proto(proto_msg);

    // test stop
    tear_down();
    printf("====================================\n");
}

static void test_free_opks() {
    // test start
    printf("====== test_free_opks ======\n");
    tear_up();
    get_skissm_plugin()->event_handler = test_event_handler;

    uint32_t e2ee_pack_id = gen_e2ee_pack_id_pqc();
    const char *user_name = "alice";
    const char *user_id = "alice";
    const char *device_id = generate_uuid_str();
    const char *authenticator = "email";
    const char *auth_code = "123456";
    int ret = 0;
    Skissm__RegisterUserResponse *register_user_response = NULL;
    ret = register_user(
        &register_user_response, e2ee_pack_id, user_name, user_id, device_id, authenticator, auth_code
    );

    // load account
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(register_user_response->address, &account);

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
    get_skissm_plugin()->db_handler.load_account_by_address(register_user_response->address, &account_new);
    assert(account_new->n_one_time_pre_key_list == (100 - used_opks));
    assert(account_new->one_time_pre_key_list[100 - used_opks] == NULL);

    // release
    free_proto(register_user_response);
    free_proto(account);
    if (account_new != NULL) {
        skissm__account__free_unpacked(account_new, NULL);
        account_new = NULL;
    }

    // test stop
    tear_down();
    printf("====================================\n");
}

int main() {
    test_create_accounts(8);
    test_register_user();
    test_publish_spk();
    test_supply_opks();
    test_free_opks();

    return 0;
}
