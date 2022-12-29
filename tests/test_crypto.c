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
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "curve25519-donna.h"

#include "skissm/account.h"
#include "skissm/account_manager.h"
#include "skissm/mem_util.h"
#include "skissm/session_manager.h"

#include "test_plugin.h"
#include "test_util.h"

static void on_user_registered(Skissm__Account *account){
}

static skissm_event_handler_t test_event_handler = {
    NULL,
    on_user_registered,
    NULL,
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

static void test_verify_signature() {
    tear_up();

    // set the cipher suite(ECC in this test)
    const cipher_suite_t *cipher_suite = get_e2ee_pack(TEST_E2EE_PACK_ID_ECC)->cipher_suite;

    // generate key pairs
    Skissm__KeyPair *identity_key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(identity_key_pair);
    cipher_suite->sign_key_gen(&(identity_key_pair->public_key), &(identity_key_pair->private_key));

    Skissm__KeyPair *signed_pre_key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(signed_pre_key_pair);
    cipher_suite->asym_key_gen(&(signed_pre_key_pair->public_key), &(signed_pre_key_pair->private_key));

    // generate the signature
    int pub_key_len = cipher_suite->get_crypto_param().asym_pub_key_len;
    int sig_len = cipher_suite->get_crypto_param().sig_len;
    uint8_t *signature = (uint8_t *)malloc(sig_len);
    cipher_suite->sign(
        identity_key_pair->private_key.data,
        signed_pre_key_pair->public_key.data,
        pub_key_len,
        signature
    );

    // verify the signature
    int result;
    result = cipher_suite->verify(
        signature,
        identity_key_pair->public_key.data,
        signed_pre_key_pair->public_key.data,
        pub_key_len
    );

    assert(result == 0);

    // release
    skissm__key_pair__free_unpacked(identity_key_pair, NULL);
    skissm__key_pair__free_unpacked(signed_pre_key_pair, NULL);
    free_mem((void **)&signature, sig_len);

    tear_down();
}

static void test_verify_specific_signature() {
    tear_up();

    const uint8_t CURVE25519_BASEPOINT[32] = {9};

    // set the cipher suite(ECC in this test)
    const cipher_suite_t *cipher_suite = get_e2ee_pack(TEST_E2EE_PACK_ID_ECC)->cipher_suite;
    int pub_key_len = cipher_suite->get_crypto_param().asym_pub_key_len;
    int priv_key_len = cipher_suite->get_crypto_param().asym_priv_key_len;
    int sign_pub_key_len = cipher_suite->get_crypto_param().sign_pub_key_len;
    int sign_priv_key_len = cipher_suite->get_crypto_param().sign_priv_key_len;
    int sig_len = cipher_suite->get_crypto_param().sig_len;
    uint8_t *pos = NULL;

    // check the identity key pair
    Skissm__KeyPair *identity_key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(identity_key_pair);

    identity_key_pair->private_key.data = (uint8_t *)malloc(sizeof(uint8_t) * sign_priv_key_len);
    identity_key_pair->private_key.len = sign_priv_key_len;
    pos = identity_key_pair->private_key.data;
    pos[0] = 0xdb; pos[1] = 0xac; pos[2] = 0xcf; pos[3] = 0x97; pos[4] = 0x89; pos[5] = 0xf3; pos[6] = 0x51; pos[7] = 0x05;
    pos[8] = 0x79; pos[9] = 0x71; pos[10] = 0x2c; pos[11] = 0x0e; pos[12] = 0x0d; pos[13] = 0x60; pos[14] = 0x6b; pos[15] = 0x59;
    pos[16] = 0xd5; pos[17] = 0x59; pos[18] = 0xe1; pos[19] = 0x6c; pos[20] = 0xc1; pos[21] = 0xb9; pos[22] = 0x55; pos[23] = 0x63;
    pos[24] = 0x42; pos[25] = 0x44; pos[26] = 0x71; pos[27] = 0x55; pos[28] = 0x0b; pos[29] = 0xba; pos[30] = 0x97; pos[31] = 0xe6;

    uint8_t *identity_public_key = (uint8_t *)malloc(sizeof(uint8_t) * sign_pub_key_len);
    curve25519_donna(identity_public_key, identity_key_pair->private_key.data, CURVE25519_BASEPOINT);
    print_hex("identity_public_key:", identity_public_key, sign_pub_key_len);

    identity_key_pair->public_key.data = (uint8_t *)malloc(sizeof(uint8_t) * sign_pub_key_len);
    identity_key_pair->public_key.len = sign_pub_key_len;
    pos = identity_key_pair->public_key.data;
    pos[0] = 0xf3; pos[1] = 0x83; pos[2] = 0xb2; pos[3] = 0xe5; pos[4] = 0xd0; pos[5] = 0x7a; pos[6] = 0xec; pos[7] = 0x03;
    pos[8] = 0xc6; pos[9] = 0xc0; pos[10] = 0xe3; pos[11] = 0x93; pos[12] = 0x71; pos[13] = 0xf6; pos[14] = 0xab; pos[15] = 0x84;
    pos[16] = 0x23; pos[17] = 0x73; pos[18] = 0x39; pos[19] = 0x1d; pos[20] = 0xc2; pos[21] = 0x68; pos[22] = 0xbc; pos[23] = 0x49;
    pos[24] = 0xa8; pos[25] = 0x0c; pos[26] = 0xae; pos[27] = 0x65; pos[28] = 0x92; pos[29] = 0x8a; pos[30] = 0x24; pos[31] = 0x6b;

    assert(memcmp(identity_public_key, identity_key_pair->public_key.data, sign_pub_key_len) == 0);

    // check the signed pre-key pair
    Skissm__KeyPair *signed_pre_key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(signed_pre_key_pair);

    signed_pre_key_pair->private_key.data = (uint8_t *)malloc(sizeof(uint8_t) * priv_key_len);
    signed_pre_key_pair->private_key.len = priv_key_len;
    pos = signed_pre_key_pair->private_key.data;
    pos[0] = 0x68; pos[1] = 0x67; pos[2] = 0xfe; pos[3] = 0x71; pos[4] = 0x5b; pos[5] = 0x50; pos[6] = 0x76; pos[7] = 0x55;
    pos[8] = 0xc2; pos[9] = 0x22; pos[10] = 0x63; pos[11] = 0x4f; pos[12] = 0x02; pos[13] = 0xce; pos[14] = 0xa8; pos[15] = 0xd8;
    pos[16] = 0xa7; pos[17] = 0x0a; pos[18] = 0x45; pos[19] = 0x6a; pos[20] = 0x43; pos[21] = 0x1a; pos[22] = 0x4d; pos[23] = 0x85;
    pos[24] = 0x5f; pos[25] = 0x3e; pos[26] = 0xdb; pos[27] = 0x6a; pos[28] = 0xf8; pos[29] = 0x73; pos[30] = 0xd1; pos[31] = 0x61;

    uint8_t *spk_public_key = (uint8_t *)malloc(sizeof(uint8_t) * pub_key_len);
    curve25519_donna(spk_public_key, signed_pre_key_pair->private_key.data, CURVE25519_BASEPOINT);
    print_hex("spk_public_key:", spk_public_key, pub_key_len);

    signed_pre_key_pair->public_key.data = (uint8_t *)malloc(sizeof(uint8_t) * pub_key_len);
    signed_pre_key_pair->public_key.len = pub_key_len;
    pos = signed_pre_key_pair->public_key.data;
    pos[0] = 0x80; pos[1] = 0xdb; pos[2] = 0xa0; pos[3] = 0xe3; pos[4] = 0xd4; pos[5] = 0x55; pos[6] = 0x5e; pos[7] = 0x03;
    pos[8] = 0xb7; pos[9] = 0xaa; pos[10] = 0xee; pos[11] = 0x12; pos[12] = 0x70; pos[13] = 0xe2; pos[14] = 0x7c; pos[15] = 0x0c;
    pos[16] = 0x74; pos[17] = 0xa2; pos[18] = 0xce; pos[19] = 0xae; pos[20] = 0x46; pos[21] = 0x09; pos[22] = 0x12; pos[23] = 0x2b;
    pos[24] = 0x02; pos[25] = 0x99; pos[26] = 0x9a; pos[27] = 0xa1; pos[28] = 0x1d; pos[29] = 0xa1; pos[30] = 0x91; pos[31] = 0x19;

    assert(memcmp(spk_public_key, signed_pre_key_pair->public_key.data, pub_key_len) == 0);

    uint8_t msg[10] = {0};

    int i;
    for (i = 0; i < 10; i++) {
        // generate the signature
        uint8_t *signature = (uint8_t *)malloc(sig_len);
        cipher_suite->sign(
            identity_key_pair->private_key.data,
            msg,
            10,
            signature
        );
        print_hex("signature:", signature, sig_len);

        // verify the signature
        int result;
        result = cipher_suite->verify(
            signature,
            identity_key_pair->public_key.data,
            msg,
            10
        );

        printf("result = %d\n", result);

        // assert(result == 0);
        free_mem((void **)&signature, sig_len);
    }

    // uint8_t *signature_check = (uint8_t *)malloc(sig_len);
    // pos = signature_check;
    // pos[0] = 0xaf; pos[1] = 0xcb; pos[2] = 0xcf; pos[3] = 0xdd; pos[4] = 0x1c; pos[5] = 0x86; pos[6] = 0x7a; pos[7] = 0xf6;
    // pos[8] = 0xf6; pos[9] = 0x27; pos[10] = 0x36; pos[11] = 0xd4; pos[12] = 0xcb; pos[13] = 0x8a; pos[14] = 0x26; pos[15] = 0x40;
    // pos[16] = 0xa1; pos[17] = 0xcc; pos[18] = 0x64; pos[19] = 0xb1; pos[20] = 0x87; pos[21] = 0x60; pos[22] = 0x66; pos[23] = 0xd8;
    // pos[24] = 0x0e; pos[25] = 0x98; pos[26] = 0x80; pos[27] = 0x5a; pos[28] = 0xe4; pos[29] = 0xa1; pos[30] = 0x76; pos[31] = 0x9b;
    // pos[32] = 0x49; pos[33] = 0xc1; pos[34] = 0xf6; pos[35] = 0x88; pos[36] = 0x1c; pos[37] = 0x5d; pos[38] = 0x69; pos[39] = 0xcc;
    // pos[40] = 0xeb; pos[41] = 0x3a; pos[42] = 0x3f; pos[43] = 0x6b; pos[44] = 0x82; pos[45] = 0xd1; pos[46] = 0xf1; pos[47] = 0xca;
    // pos[48] = 0x0d; pos[49] = 0xc0; pos[50] = 0xa9; pos[51] = 0x7d; pos[52] = 0x52; pos[53] = 0xc4; pos[54] = 0xd4; pos[55] = 0x1e;
    // pos[56] = 0x0e; pos[57] = 0x11; pos[58] = 0x44; pos[59] = 0x7d; pos[60] = 0xe5; pos[61] = 0x06; pos[62] = 0x61; pos[63] = 0x84;

    // assert(memcmp(signature, signature_check, sig_len) == 0);

    // release
    skissm__key_pair__free_unpacked(identity_key_pair, NULL);
    free_mem((void **)&identity_public_key, sizeof(uint8_t) * sign_pub_key_len);
    skissm__key_pair__free_unpacked(signed_pre_key_pair, NULL);
    free_mem((void **)&spk_public_key, sizeof(uint8_t) * pub_key_len);
    // free_mem((void **)&signature_check, sig_len);

    tear_down();
}

static void test_verify_signature_multiple_times() {
    tear_up();

    // set the cipher suite(ECC in this test)
    const cipher_suite_t *cipher_suite = get_e2ee_pack(TEST_E2EE_PACK_ID_ECC)->cipher_suite;

    // generate key pairs
    Skissm__KeyPair *identity_key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(identity_key_pair);
    cipher_suite->sign_key_gen(&(identity_key_pair->public_key), &(identity_key_pair->private_key));

    Skissm__KeyPair *signed_pre_key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(signed_pre_key_pair);
    cipher_suite->asym_key_gen(&(signed_pre_key_pair->public_key), &(signed_pre_key_pair->private_key));

    int pub_key_len = cipher_suite->get_crypto_param().asym_pub_key_len;
    int sig_len = cipher_suite->get_crypto_param().sig_len;

    // generate the signature and verify it multiple times
    int result;
    int i;
    for (i = 0; i < 10; i++) {
        uint8_t *signature = (uint8_t *)malloc(sig_len);
        cipher_suite->sign(
            identity_key_pair->private_key.data,
            signed_pre_key_pair->public_key.data,
            pub_key_len,
            signature
        );
        print_hex("signature: ", signature, sig_len);

        result = cipher_suite->verify(
            signature,
            identity_key_pair->public_key.data,
            signed_pre_key_pair->public_key.data,
            pub_key_len
        );

        printf("result = %d\n", result);

        // assert(result == 0);
        free_mem((void **)&signature, sig_len);
    }

    // release
    skissm__key_pair__free_unpacked(identity_key_pair, NULL);
    skissm__key_pair__free_unpacked(signed_pre_key_pair, NULL);

    tear_down();
}

static void test_verify_multiple_signature() {
    tear_up();

    int times = 20;
    int i;

    // set the cipher suite(ECC in this test)
    const cipher_suite_t *cipher_suite = get_e2ee_pack(TEST_E2EE_PACK_ID_ECC)->cipher_suite;
    int pub_key_len = cipher_suite->get_crypto_param().asym_pub_key_len;
    int sig_len = cipher_suite->get_crypto_param().sig_len;

    // malloc the key pairs
    Skissm__KeyPair **identity_key_pairs = (Skissm__KeyPair **)malloc(sizeof(Skissm__KeyPair *) * times);
    Skissm__KeyPair **signed_pre_key_pairs = (Skissm__KeyPair **)malloc(sizeof(Skissm__KeyPair *) * times);
    uint8_t **signature_list = (uint8_t **)malloc(sizeof(uint8_t *) * times);

    // generate key pairs and signature
    for (i = 0; i < times; i++){
        identity_key_pairs[i] = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
        skissm__key_pair__init(identity_key_pairs[i]);
        cipher_suite->sign_key_gen(&(identity_key_pairs[i]->public_key), &(identity_key_pairs[i]->private_key));

        signed_pre_key_pairs[i] = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
        skissm__key_pair__init(signed_pre_key_pairs[i]);
        cipher_suite->asym_key_gen(&(signed_pre_key_pairs[i]->public_key), &(signed_pre_key_pairs[i]->private_key));

        signature_list[i] = (uint8_t *)malloc(sizeof(uint8_t) * sig_len);
        cipher_suite->sign(
            identity_key_pairs[i]->private_key.data,
            signed_pre_key_pairs[i]->public_key.data,
            pub_key_len,
            signature_list[i]
        );
    }

    // verify the signature multiple times
    int result;
    for (i = 0; i < times; i++) {
        result = cipher_suite->verify(
            signature_list[i],
            identity_key_pairs[i]->public_key.data,
            signed_pre_key_pairs[i]->public_key.data,
            pub_key_len
        );

        printf("result = %d\n", result);

        // assert(result == 0);
    }

    // release
    for (i = 0; i < times; i++) {
        skissm__key_pair__free_unpacked(identity_key_pairs[i], NULL);
        skissm__key_pair__free_unpacked(signed_pre_key_pairs[i], NULL);
        free_mem((void **)&(signature_list[i]), sizeof(uint8_t) * sig_len);
    }
    free_mem((void **)&identity_key_pairs, sizeof(Skissm__KeyPair *) * times);
    free_mem((void **)&signed_pre_key_pairs, sizeof(Skissm__KeyPair *) * times);
    free_mem((void **)&signature_list, sizeof(uint8_t *) * times);

    tear_down();
}

static void test_verify_multiple_signature_version2() {
    tear_up();

    int times = 10;
    int i;

    // set the cipher suite(ECC in this test)
    const cipher_suite_t *cipher_suite = get_e2ee_pack(TEST_E2EE_PACK_ID_ECC)->cipher_suite;
    int pub_key_len = cipher_suite->get_crypto_param().asym_pub_key_len;
    int sig_len = cipher_suite->get_crypto_param().sig_len;

    // malloc the key pairs
    Skissm__KeyPair **identity_key_pairs = (Skissm__KeyPair **)malloc(sizeof(Skissm__KeyPair *) * times);
    Skissm__KeyPair **signed_pre_key_pairs = (Skissm__KeyPair **)malloc(sizeof(Skissm__KeyPair *) * times);
    uint8_t **signature_list = (uint8_t **)malloc(sizeof(uint8_t *) * times);

    int result;
    // generate key pairs and signature and verify
    for (i = 0; i < times; i++){
        identity_key_pairs[i] = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
        skissm__key_pair__init(identity_key_pairs[i]);
        cipher_suite->sign_key_gen(&(identity_key_pairs[i]->public_key), &(identity_key_pairs[i]->private_key));

        signed_pre_key_pairs[i] = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
        skissm__key_pair__init(signed_pre_key_pairs[i]);
        cipher_suite->asym_key_gen(&(signed_pre_key_pairs[i]->public_key), &(signed_pre_key_pairs[i]->private_key));

        signature_list[i] = (uint8_t *)malloc(sizeof(uint8_t) * sig_len);
        cipher_suite->sign(
            identity_key_pairs[i]->private_key.data,
            signed_pre_key_pairs[i]->public_key.data,
            pub_key_len,
            signature_list[i]
        );

        print_hex("identity_key_pair(private): ", identity_key_pairs[i]->private_key.data, identity_key_pairs[i]->private_key.len);
        print_hex("identity_key_pair(public): ", identity_key_pairs[i]->public_key.data, identity_key_pairs[i]->public_key.len);
        print_hex("signed_pre_key_pair(private): ", signed_pre_key_pairs[i]->private_key.data, signed_pre_key_pairs[i]->private_key.len);
        print_hex("signed_pre_key_pair(public): ", signed_pre_key_pairs[i]->public_key.data, signed_pre_key_pairs[i]->public_key.len);
        print_hex("signature: ", signature_list[i], sig_len);

        result = cipher_suite->verify(
            signature_list[i],
            identity_key_pairs[i]->public_key.data,
            signed_pre_key_pairs[i]->public_key.data,
            pub_key_len
        );

        assert(result == 0);
    }

    // release
    for (i = 0; i < times; i++) {
        skissm__key_pair__free_unpacked(identity_key_pairs[i], NULL);
        skissm__key_pair__free_unpacked(signed_pre_key_pairs[i], NULL);
        free_mem((void **)&(signature_list[i]), sizeof(uint8_t) * sig_len);
    }
    free_mem((void **)&identity_key_pairs, sizeof(Skissm__KeyPair *) * times);
    free_mem((void **)&signed_pre_key_pairs, sizeof(Skissm__KeyPair *) * times);
    free_mem((void **)&signature_list, sizeof(uint8_t *) * times);

    tear_down();
}

static void test_verify_pre_key_bundle() {
    tear_up();
    get_skissm_plugin()->event_handler = test_event_handler;

    uint64_t account_id = 1;
    const char *user_name = "Alice";
    const char *e2ee_pack_id = TEST_E2EE_PACK_ID_ECC;
    char *device_id = generate_uuid_str();
    const char *authenticator = "alice@domain.com.tw";
    const char *auth_code = "123456";

    Skissm__Account *account = create_account(account_id, e2ee_pack_id);

    // send account message to server
    Skissm__RegisterUserRequest *request = produce_register_request(account);
    request->user_name = strdup(user_name);
    request->device_id = strdup(device_id);
    request->authenticator = strdup(authenticator);
    request->auth_code = strdup(auth_code);
    request->e2ee_pack_id = strdup(e2ee_pack_id);

    Skissm__RegisterUserResponse *response = get_skissm_plugin()->proto_handler.register_user(request);
    consume_register_response(account, response);

    char *user_id = account->address->user->user_id;
    char *domain = account->address->domain;

    Skissm__GetPreKeyBundleRequest *get_pre_key_bundle_request = produce_get_pre_key_bundle_request(user_id, domain, device_id);
    Skissm__GetPreKeyBundleResponse *get_pre_key_bundle_response = get_skissm_plugin()->proto_handler.get_pre_key_bundle(get_pre_key_bundle_request);

    const cipher_suite_t *cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;
    int key_len = cipher_suite->get_crypto_param().asym_pub_key_len;
    Skissm__PreKeyBundle *their_pre_key_bundle = get_pre_key_bundle_response->pre_key_bundles[0];
    assert(memcmp(their_pre_key_bundle->identity_key_public->sign_public_key.data, account->identity_key->sign_key_pair->public_key.data, key_len) == 0);
    assert(memcmp(their_pre_key_bundle->signed_pre_key_public->public_key.data, account->signed_pre_key->key_pair->public_key.data, key_len) == 0);
    assert(memcmp(their_pre_key_bundle->signed_pre_key_public->signature.data, account->signed_pre_key->signature.data, 2 * key_len) == 0);

    int result;
    result = cipher_suite->verify(
        their_pre_key_bundle->signed_pre_key_public->signature.data,
        their_pre_key_bundle->identity_key_public->sign_public_key.data,
        their_pre_key_bundle->signed_pre_key_public->public_key.data,
        key_len
    );

    assert(result == 0);

    // release
    free(device_id);
    skissm__account__free_unpacked(account, NULL);
    skissm__register_user_request__free_unpacked(request, NULL);
    skissm__register_user_response__free_unpacked(response, NULL);
    skissm__get_pre_key_bundle_request__free_unpacked(get_pre_key_bundle_request, NULL);
    skissm__get_pre_key_bundle_response__free_unpacked(get_pre_key_bundle_response, NULL);

    tear_down();
}

int main() {
    // test_verify_signature();
    // test_verify_specific_signature();
    // test_verify_signature_multiple_times();
    test_verify_multiple_signature();
    // test_verify_multiple_signature_version2();
    // test_verify_pre_key_bundle();

    return 0;
}
