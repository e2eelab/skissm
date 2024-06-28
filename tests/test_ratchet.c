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
#include <string.h>

#include "skissm/cipher.h"
#include "skissm/mem_util.h"
#include "skissm/ratchet.h"

#include "test_util.h"
#include "test_plugin.h"

static const cipher_suite_t *test_cipher_suite;

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

static void test_ecc_alice_to_bob() {
    // test start
    printf("test_ecc_alice_to_bob begin!!!\n");
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

    Skissm__KeyPair alice_ratchet_key;
    test_cipher_suite->kem_suite->asym_key_gen(&alice_ratchet_key.public_key, &alice_ratchet_key.private_key);

    Skissm__KeyPair bob_spk;
    test_cipher_suite->kem_suite->asym_key_gen(&bob_spk.public_key, &bob_spk.private_key);

    int ad_len = 2 * test_cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
    uint8_t associated_data[ad_len];
    memset(associated_data, 0, ad_len);
    ProtobufCBinaryData ad;
    ad.len = ad_len;
    ad.data = (uint8_t *) malloc(ad_len * sizeof(uint8_t));
    int i;
    for (i = 0; i < ad_len; i++) {
        ad.data[i] = associated_data[i];
    }

    char *session_id = generate_uuid_str();

    uint8_t shared_secret[] = "shared_secret:nwjeldUbnjwcwkdt5q";

    Skissm__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    initialise_ratchet(&alice_ratchet);
    initialise_ratchet(&bob_ratchet);

    initialise_as_alice(
        test_cipher_suite,
        alice_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &alice_ratchet_key,
        &(bob_spk.public_key),
        NULL
    );
    initialise_as_bob(
        test_cipher_suite,
        bob_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &bob_spk,
        &(alice_ratchet_key.public_key)
    );
    int key_len = test_cipher_suite->kem_suite->get_crypto_param().asym_priv_key_len;

    uint8_t plaintext[] = "Message";
    size_t plaintext_length = sizeof(plaintext) - 1;

    size_t decrypt_length;

    /* Alice sends Bob a message */
    Skissm__One2oneMsgPayload *message = NULL;

    encrypt_ratchet(test_cipher_suite, alice_ratchet, ad, plaintext, plaintext_length, &message);

    uint8_t *output = NULL;
    decrypt_length = decrypt_ratchet(test_cipher_suite, bob_ratchet, ad, message, &output);
    assert(decrypt_length == plaintext_length);
    bool result = is_equal(plaintext, output, plaintext_length);
    assert(result);

    if (result) {
        print_result("Decryption success!!!", true);
    } else {
        print_result("Decryption failed!!!", false);
    }

    skissm__one2one_msg_payload__free_unpacked(message, NULL);
    free_mem((void **)&output, decrypt_length);
    skissm__ratchet__free_unpacked(alice_ratchet, NULL);
    skissm__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    printf("====================================\n");
}

static void test_ecc_bob_to_alice() {
    // test start
    printf("test_ecc_bob_to_alice begin!!!\n");
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

    Skissm__KeyPair alice_ratchet_key;
    test_cipher_suite->kem_suite->asym_key_gen(&alice_ratchet_key.public_key, &alice_ratchet_key.private_key);

    Skissm__KeyPair bob_spk;
    test_cipher_suite->kem_suite->asym_key_gen(&bob_spk.public_key, &bob_spk.private_key);

    int ad_len = 2 * test_cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
    uint8_t associated_data[ad_len];
    memset(associated_data, 0, ad_len);
    ProtobufCBinaryData ad;
    ad.len = ad_len;
    ad.data = (uint8_t *) malloc(ad_len * sizeof(uint8_t));
    int i;
    for (i = 0; i < ad_len; i++) {
        ad.data[i] = associated_data[i];
    }

    char *session_id = generate_uuid_str();

    uint8_t shared_secret[] = "shared_secret:nwjeldUbnjwcwkdt5q";

    Skissm__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    initialise_ratchet(&alice_ratchet);
    initialise_ratchet(&bob_ratchet);

    initialise_as_alice(
        test_cipher_suite,
        alice_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &alice_ratchet_key,
        &(bob_spk.public_key),
        NULL
    );
    initialise_as_bob(
        test_cipher_suite,
        bob_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &bob_spk,
        &(alice_ratchet_key.public_key)
    );
    int key_len = test_cipher_suite->kem_suite->get_crypto_param().asym_priv_key_len;

    uint8_t plaintext[] = "Message";
    size_t plaintext_length = sizeof(plaintext) - 1;

    size_t decrypt_length;

    /* Bob sends Alice a message */
    Skissm__One2oneMsgPayload *message = NULL;

    encrypt_ratchet(test_cipher_suite, bob_ratchet, ad, plaintext, plaintext_length, &message);

    uint8_t *output = NULL;
    decrypt_length = decrypt_ratchet(test_cipher_suite, alice_ratchet, ad, message, &output);
    assert(decrypt_length == plaintext_length);
    bool result = is_equal(plaintext, output, plaintext_length);
    assert(result);

    if (result) {
        print_result("Decryption success!!!", true);
    } else {
        print_result("Decryption failed!!!", false);
    }

    skissm__one2one_msg_payload__free_unpacked(message, NULL);
    free_mem((void **)&output, decrypt_length);
    skissm__ratchet__free_unpacked(alice_ratchet, NULL);
    skissm__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    printf("====================================\n");
}

static void test_ecc_interaction_alice_first() {
    // test start
    printf("test_ecc_interaction_alice_first begin!!!\n");
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

    Skissm__KeyPair alice_ratchet_key;
    test_cipher_suite->kem_suite->asym_key_gen(&alice_ratchet_key.public_key, &alice_ratchet_key.private_key);

    Skissm__KeyPair bob_spk;
    test_cipher_suite->kem_suite->asym_key_gen(&bob_spk.public_key, &bob_spk.private_key);

    int ad_len = 2 * test_cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
    uint8_t associated_data[ad_len];
    memset(associated_data, 0, ad_len);
    ProtobufCBinaryData ad;
    ad.len = ad_len;
    ad.data = (uint8_t *) malloc(ad_len * sizeof(uint8_t));
    int i;
    for (i = 0; i < ad_len; i++) {
        ad.data[i] = associated_data[i];
    }

    char *session_id = generate_uuid_str();

    uint8_t shared_secret[] = "shared_secret:nwjeldUbnjwcwkdt5q";

    Skissm__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    initialise_ratchet(&alice_ratchet);
    initialise_ratchet(&bob_ratchet);

    initialise_as_alice(
        test_cipher_suite,
        alice_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &alice_ratchet_key,
        &(bob_spk.public_key),
        NULL
    );
    initialise_as_bob(
        test_cipher_suite,
        bob_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &bob_spk,
        &(alice_ratchet_key.public_key)
    );
    int key_len = test_cipher_suite->kem_suite->get_crypto_param().asym_priv_key_len;

    bool result;

    /* Alice sends Bob a message */
    uint8_t plaintext_1[] = "Alice's Message";
    size_t plaintext_1_length = sizeof(plaintext_1) - 1;

    Skissm__One2oneMsgPayload *message_1 = NULL;

    encrypt_ratchet(test_cipher_suite, alice_ratchet, ad, plaintext_1, plaintext_1_length, &message_1);

    uint8_t *output_1 = NULL;
    size_t decrypt_length_1 = decrypt_ratchet(test_cipher_suite, bob_ratchet, ad, message_1, &output_1);
    assert(decrypt_length_1 == plaintext_1_length);
    result = is_equal(plaintext_1, output_1, plaintext_1_length);
    assert(result);

    if (result) {
        print_result("Decryption success!!!", true);
    } else {
        print_result("Decryption failed!!!", false);
    }

    /* Bob sends Alice a message */
    uint8_t plaintext_2[] = "Bob's Message";
    size_t plaintext_2_length = sizeof(plaintext_2) - 1;

    Skissm__One2oneMsgPayload *message_2 = NULL;

    encrypt_ratchet(test_cipher_suite, bob_ratchet, ad, plaintext_2, plaintext_2_length, &message_2);

    uint8_t *output_2 = NULL;
    size_t decrypt_length_2 = decrypt_ratchet(test_cipher_suite, alice_ratchet, ad, message_2, &output_2);
    assert(decrypt_length_2 == plaintext_2_length);
    result = is_equal(plaintext_2, output_2, plaintext_2_length);
    assert(result);

    if (result) {
        print_result("Decryption success!!!", true);
    } else {
        print_result("Decryption failed!!!", false);
    }

    skissm__one2one_msg_payload__free_unpacked(message_1, NULL);
    skissm__one2one_msg_payload__free_unpacked(message_2, NULL);
    free_mem((void **)&output_1, decrypt_length_1);
    free_mem((void **)&output_2, decrypt_length_2);
    skissm__ratchet__free_unpacked(alice_ratchet, NULL);
    skissm__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    printf("====================================\n");
}

static void test_ecc_interaction_bob_first() {
    // test start
    printf("test_ecc_interaction_bob_first begin!!!\n");
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

    Skissm__KeyPair alice_ratchet_key;
    test_cipher_suite->kem_suite->asym_key_gen(&alice_ratchet_key.public_key, &alice_ratchet_key.private_key);

    Skissm__KeyPair bob_spk;
    test_cipher_suite->kem_suite->asym_key_gen(&bob_spk.public_key, &bob_spk.private_key);

    int ad_len = 2 * test_cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
    uint8_t associated_data[ad_len];
    memset(associated_data, 0, ad_len);
    ProtobufCBinaryData ad;
    ad.len = ad_len;
    ad.data = (uint8_t *) malloc(ad_len * sizeof(uint8_t));
    int i;
    for (i = 0; i < ad_len; i++) {
        ad.data[i] = associated_data[i];
    }

    char *session_id = generate_uuid_str();

    uint8_t shared_secret[] = "shared_secret:nwjeldUbnjwcwkdt5q";

    Skissm__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    initialise_ratchet(&alice_ratchet);
    initialise_ratchet(&bob_ratchet);

    initialise_as_alice(
        test_cipher_suite,
        alice_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &alice_ratchet_key,
        &(bob_spk.public_key),
        NULL
    );
    initialise_as_bob(
        test_cipher_suite,
        bob_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &bob_spk,
        &(alice_ratchet_key.public_key)
    );
    int key_len = test_cipher_suite->kem_suite->get_crypto_param().asym_priv_key_len;

    bool result;

    /* Bob sends Alice a message */
    uint8_t plaintext_1[] = "Bob's Message";
    size_t plaintext_1_length = sizeof(plaintext_1) - 1;

    Skissm__One2oneMsgPayload *message_1 = NULL;

    encrypt_ratchet(test_cipher_suite, bob_ratchet, ad, plaintext_1, plaintext_1_length, &message_1);

    uint8_t *output_1 = NULL;
    size_t decrypt_length_1 = decrypt_ratchet(test_cipher_suite, alice_ratchet, ad, message_1, &output_1);
    assert(decrypt_length_1 == plaintext_1_length);
    result = is_equal(plaintext_1, output_1, plaintext_1_length);
    assert(result);

    if (result) {
        print_result("Decryption success!!!", true);
    } else {
        print_result("Decryption failed!!!", false);
    }

    /* Alice sends Bob a message */
    uint8_t plaintext_2[] = "Alice's Message";
    size_t plaintext_2_length = sizeof(plaintext_2) - 1;

    Skissm__One2oneMsgPayload *message_2 = NULL;

    encrypt_ratchet(test_cipher_suite, alice_ratchet, ad, plaintext_2, plaintext_2_length, &message_2);

    uint8_t *output_2 = NULL;
    size_t decrypt_length_2 = decrypt_ratchet(test_cipher_suite, bob_ratchet, ad, message_2, &output_2);
    assert(decrypt_length_2 == plaintext_2_length);
    result = is_equal(plaintext_2, output_2, plaintext_2_length);
    assert(result);

    if (result) {
        print_result("Decryption success!!!", true);
    } else {
        print_result("Decryption failed!!!", false);
    }

    skissm__one2one_msg_payload__free_unpacked(message_1, NULL);
    skissm__one2one_msg_payload__free_unpacked(message_2, NULL);
    free_mem((void **)&output_1, decrypt_length_1);
    free_mem((void **)&output_2, decrypt_length_2);
    skissm__ratchet__free_unpacked(alice_ratchet, NULL);
    skissm__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    printf("====================================\n");
}

static void test_ecc_out_of_order() {
    // test start
    printf("test_ecc_out_of_order begin!!!\n");
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

    Skissm__KeyPair alice_ratchet_key;
    test_cipher_suite->kem_suite->asym_key_gen(&alice_ratchet_key.public_key, &alice_ratchet_key.private_key);

    Skissm__KeyPair bob_spk;
    test_cipher_suite->kem_suite->asym_key_gen(&bob_spk.public_key, &bob_spk.private_key);

    int ad_len = 2 * test_cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
    uint8_t associated_data[ad_len];
    memset(associated_data, 0, ad_len);
    ProtobufCBinaryData ad;
    ad.len = ad_len;
    ad.data = (uint8_t *) malloc(ad_len * sizeof(uint8_t));
    int i;
    for (i = 0; i < ad_len; i++) {
        ad.data[i] = associated_data[i];
    }

    char *session_id = generate_uuid_str();

    uint8_t shared_secret[] = "shared_secret:nwjeldUbnjwcwkdt5q";

    Skissm__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    initialise_ratchet(&alice_ratchet);
    initialise_ratchet(&bob_ratchet);

    initialise_as_alice(
        test_cipher_suite,
        alice_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &alice_ratchet_key,
        &(bob_spk.public_key),
        NULL
    );
    initialise_as_bob(
        test_cipher_suite,
        bob_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &bob_spk,
        &(alice_ratchet_key.public_key)
    );
    int key_len = test_cipher_suite->kem_suite->get_crypto_param().asym_priv_key_len;

    bool result;

    /* Alice sends Bob two messages */
    uint8_t plaintext_1[] = "Alice's first Message";
    size_t plaintext_1_length = sizeof(plaintext_1) - 1;

    Skissm__One2oneMsgPayload *message_1 = NULL;

    encrypt_ratchet(test_cipher_suite, alice_ratchet, ad, plaintext_1, plaintext_1_length, &message_1);

    uint8_t plaintext_2[] = "Alice's second Message";
    size_t plaintext_2_length = sizeof(plaintext_2) - 1;

    Skissm__One2oneMsgPayload *message_2 = NULL;

    encrypt_ratchet(test_cipher_suite, alice_ratchet, ad, plaintext_2, plaintext_2_length, &message_2);

    // decrypt the second message first
    uint8_t *output_2 = NULL;
    size_t decrypt_length_2 = decrypt_ratchet(test_cipher_suite, bob_ratchet, ad, message_2, &output_2);
    assert(decrypt_length_2 == plaintext_2_length);
    result = is_equal(plaintext_2, output_2, plaintext_2_length);
    assert(result);

    if (result) {
        print_result("Decryption success!!!", true);
    } else {
        print_result("Decryption failed!!!", false);
    }

    uint8_t *output_1 = NULL;
    size_t decrypt_length_1 = decrypt_ratchet(test_cipher_suite, bob_ratchet, ad, message_1, &output_1);
    assert(decrypt_length_1 == plaintext_1_length);
    result = is_equal(plaintext_1, output_1, plaintext_1_length);
    assert(result);

    if (result) {
        print_result("Decryption success!!!", true);
    } else {
        print_result("Decryption failed!!!", false);
    }

    skissm__one2one_msg_payload__free_unpacked(message_1, NULL);
    skissm__one2one_msg_payload__free_unpacked(message_2, NULL);
    free_mem((void **)&output_1, decrypt_length_1);
    free_mem((void **)&output_2, decrypt_length_2);
    skissm__ratchet__free_unpacked(alice_ratchet, NULL);
    skissm__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    printf("====================================\n");
}

static void test_ecc_continual_message() {
    // test start
    printf("test_ecc_continual_message begin!!!\n");
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

    Skissm__KeyPair alice_ratchet_key;
    test_cipher_suite->kem_suite->asym_key_gen(&alice_ratchet_key.public_key, &alice_ratchet_key.private_key);

    Skissm__KeyPair bob_spk;
    test_cipher_suite->kem_suite->asym_key_gen(&bob_spk.public_key, &bob_spk.private_key);

    int ad_len = 2 * test_cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
    uint8_t associated_data[ad_len];
    memset(associated_data, 0, ad_len);
    ProtobufCBinaryData ad;
    ad.len = ad_len;
    ad.data = (uint8_t *) malloc(ad_len * sizeof(uint8_t));
    int i;
    for (i = 0; i < ad_len; i++) {
        ad.data[i] = associated_data[i];
    }

    char *session_id = generate_uuid_str();

    uint8_t shared_secret[] = "shared_secret:nwjeldUbnjwcwkdt5q";

    Skissm__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    initialise_ratchet(&alice_ratchet);
    initialise_ratchet(&bob_ratchet);

    initialise_as_alice(
        test_cipher_suite,
        alice_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &alice_ratchet_key,
        &(bob_spk.public_key),
        NULL
    );
    initialise_as_bob(
        test_cipher_suite,
        bob_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &bob_spk,
        &(alice_ratchet_key.public_key)
    );
    int key_len = test_cipher_suite->kem_suite->get_crypto_param().asym_priv_key_len;

    // Alice sends Bob messages many times
    int message_num = 1000;

    uint8_t **plaintext = (uint8_t **) malloc(sizeof(uint8_t *) * message_num);
    size_t *plaintext_len = (size_t *) malloc(sizeof(size_t) * message_num);
    Skissm__One2oneMsgPayload **message = (Skissm__One2oneMsgPayload **)malloc(sizeof(Skissm__One2oneMsgPayload *) * message_num);

    for (i = 0; i < message_num; i++) {
        plaintext[i] = (uint8_t *) malloc(sizeof(uint8_t) * 64);
        plaintext_len[i] = snprintf((char *)plaintext[i], 64, "[%4d]This message will be sent a lot of times.", i);
        encrypt_ratchet(test_cipher_suite, alice_ratchet, ad, plaintext[i], plaintext_len[i], &message[i]);
    }

    uint8_t **output = (uint8_t **) malloc(sizeof(uint8_t *) * message_num);
    size_t *output_len = (size_t *) malloc(sizeof(size_t) * message_num);

    bool result;
    for (i = 0; i < message_num; i++) {
        output_len[i] = decrypt_ratchet(test_cipher_suite, bob_ratchet, ad, message[i], &output[i]);

        assert(output_len[i] == plaintext_len[i]);
        result = is_equal(plaintext[i], output[i], plaintext_len[i]);
        assert(result);
    }

    for (i = 0; i < message_num; i++) {
        free_mem((void **)&plaintext[i], sizeof(uint8_t) * 64);
        free_mem((void **)&output[i], output_len[i]);
        skissm__one2one_msg_payload__free_unpacked(message[i], NULL);
    }
    free_mem((void **)&plaintext, sizeof(uint8_t *) * message_num);
    free_mem((void **)&plaintext_len, sizeof(size_t) * message_num);
    free_mem((void **)&output, sizeof(uint8_t *) * message_num);
    free_mem((void **)&output_len, sizeof(size_t) * message_num);
    skissm__ratchet__free_unpacked(alice_ratchet, NULL);
    skissm__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    printf("====================================\n");
}

static void test_pqc_alice_to_bob() {
    // test start
    printf("test_pqc_alice_to_bob begin!!!\n");
    tear_up();

    get_skissm_plugin()->event_handler = test_event_handler;

    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_256F,
        E2EE_PACK_ALG_KEM_KYBER1024,
        E2EE_PACK_ALG_SYMMETRIC_KEY_AES256GCM,
        E2EE_PACK_ALG_HASH_SHA2_256
    );
    test_cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;

    Skissm__KeyPair alice_ratchet_key;
    test_cipher_suite->kem_suite->asym_key_gen(&alice_ratchet_key.public_key, &alice_ratchet_key.private_key);

    Skissm__KeyPair bob_spk;
    test_cipher_suite->kem_suite->asym_key_gen(&bob_spk.public_key, &bob_spk.private_key);

    int ad_len = 2 * test_cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
    uint8_t associated_data[ad_len];
    memset(associated_data, 0, ad_len);
    ProtobufCBinaryData ad;
    ad.len = ad_len;
    ad.data = (uint8_t *) malloc(ad_len * sizeof(uint8_t));
    int i;
    for (i = 0; i < ad_len; i++) {
        ad.data[i] = associated_data[i];
    }

    char *session_id = generate_uuid_str();

    uint8_t shared_secret[] = "shared_secret:nwjeldUbnjwcwkdt5q";

    Skissm__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    initialise_ratchet(&alice_ratchet);
    initialise_ratchet(&bob_ratchet);

    initialise_as_bob(
        test_cipher_suite,
        bob_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &bob_spk,
        &(alice_ratchet_key.public_key)
    );
    initialise_as_alice(
        test_cipher_suite,
        alice_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &alice_ratchet_key,
        &(bob_spk.public_key),
        &(bob_ratchet->sender_chain->our_ratchet_public_key)
    );
    int key_len = test_cipher_suite->kem_suite->get_crypto_param().asym_priv_key_len;

    uint8_t plaintext[] = "Message";
    size_t plaintext_length = sizeof(plaintext) - 1;

    size_t decrypt_length;

    // Alice sends Bob a message
    Skissm__One2oneMsgPayload *message = NULL;

    encrypt_ratchet(test_cipher_suite, alice_ratchet, ad, plaintext, plaintext_length, &message);

    uint8_t *output = NULL;
    decrypt_length = decrypt_ratchet(test_cipher_suite, bob_ratchet, ad, message, &output);
    assert(decrypt_length == plaintext_length);
    bool result = is_equal(plaintext, output, plaintext_length);
    assert(result);

    if (result) {
        print_result("Decryption success!!!", true);
    } else {
        print_result("Decryption failed!!!", false);
    }

    skissm__one2one_msg_payload__free_unpacked(message, NULL);
    free_mem((void **)&output, decrypt_length);
    skissm__ratchet__free_unpacked(alice_ratchet, NULL);
    skissm__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    printf("====================================\n");
}

static void test_pqc_bob_to_alice() {
    // test start
    printf("test_pqc_bob_to_alice begin!!!\n");
    tear_up();

    get_skissm_plugin()->event_handler = test_event_handler;

    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_256F,
        E2EE_PACK_ALG_KEM_KYBER1024,
        E2EE_PACK_ALG_SYMMETRIC_KEY_AES256GCM,
        E2EE_PACK_ALG_HASH_SHA2_256
    );
    test_cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;

    Skissm__KeyPair alice_ratchet_key;
    test_cipher_suite->kem_suite->asym_key_gen(&alice_ratchet_key.public_key, &alice_ratchet_key.private_key);

    Skissm__KeyPair bob_spk;
    test_cipher_suite->kem_suite->asym_key_gen(&bob_spk.public_key, &bob_spk.private_key);

    int ad_len = 2 * test_cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
    uint8_t associated_data[ad_len];
    memset(associated_data, 0, ad_len);
    ProtobufCBinaryData ad;
    ad.len = ad_len;
    ad.data = (uint8_t *) malloc(ad_len * sizeof(uint8_t));
    int i;
    for (i = 0; i < ad_len; i++) {
        ad.data[i] = associated_data[i];
    }

    char *session_id = generate_uuid_str();

    uint8_t shared_secret[] = "shared_secret:nwjeldUbnjwcwkdt5q";

    Skissm__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    initialise_ratchet(&alice_ratchet);
    initialise_ratchet(&bob_ratchet);

    initialise_as_bob(
        test_cipher_suite,
        bob_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &bob_spk,
        &(alice_ratchet_key.public_key)
    );
    initialise_as_alice(
        test_cipher_suite,
        alice_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &alice_ratchet_key,
        &(bob_spk.public_key),
        &(bob_ratchet->sender_chain->our_ratchet_public_key)
    );
    int key_len = test_cipher_suite->kem_suite->get_crypto_param().asym_priv_key_len;

    uint8_t plaintext[] = "Message";
    size_t plaintext_length = sizeof(plaintext) - 1;

    size_t decrypt_length;

    /* Bob sends Alice a message */
    Skissm__One2oneMsgPayload *message = NULL;

    encrypt_ratchet(test_cipher_suite, bob_ratchet, ad, plaintext, plaintext_length, &message);

    uint8_t *output = NULL;
    decrypt_length = decrypt_ratchet(test_cipher_suite, alice_ratchet, ad, message, &output);
    assert(decrypt_length == plaintext_length);
    bool result = is_equal(plaintext, output, plaintext_length);
    assert(result);

    if (result) {
        print_result("Decryption success!!!", true);
    } else {
        print_result("Decryption failed!!!", false);
    }

    skissm__one2one_msg_payload__free_unpacked(message, NULL);
    free_mem((void **)&output, decrypt_length);
    skissm__ratchet__free_unpacked(alice_ratchet, NULL);
    skissm__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    printf("====================================\n");
}

static void test_pqc_interaction_alice_first() {
    // test start
    printf("test_pqc_interaction_alice_first begin!!!\n");
    tear_up();

    get_skissm_plugin()->event_handler = test_event_handler;

    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_256F,
        E2EE_PACK_ALG_KEM_KYBER1024,
        E2EE_PACK_ALG_SYMMETRIC_KEY_AES256GCM,
        E2EE_PACK_ALG_HASH_SHA2_256
    );
    test_cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;

    Skissm__KeyPair alice_ratchet_key;
    test_cipher_suite->kem_suite->asym_key_gen(&alice_ratchet_key.public_key, &alice_ratchet_key.private_key);

    Skissm__KeyPair bob_spk;
    test_cipher_suite->kem_suite->asym_key_gen(&bob_spk.public_key, &bob_spk.private_key);

    int ad_len = 2 * test_cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
    uint8_t associated_data[ad_len];
    memset(associated_data, 0, ad_len);
    ProtobufCBinaryData ad;
    ad.len = ad_len;
    ad.data = (uint8_t *) malloc(ad_len * sizeof(uint8_t));
    int i;
    for (i = 0; i < ad_len; i++) {
        ad.data[i] = associated_data[i];
    }

    char *session_id = generate_uuid_str();

    uint8_t shared_secret[] = "shared_secret:nwjeldUbnjwcwkdt5q";

    Skissm__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    initialise_ratchet(&alice_ratchet);
    initialise_ratchet(&bob_ratchet);

    initialise_as_bob(
        test_cipher_suite,
        bob_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &bob_spk,
        &(alice_ratchet_key.public_key)
    );
    initialise_as_alice(
        test_cipher_suite,
        alice_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &alice_ratchet_key,
        &(bob_spk.public_key),
        &(bob_ratchet->sender_chain->our_ratchet_public_key)
    );
    int key_len = test_cipher_suite->kem_suite->get_crypto_param().asym_priv_key_len;

    bool result;

    /* Alice sends Bob a message */
    uint8_t plaintext_1[] = "Alice's Message";
    size_t plaintext_1_length = sizeof(plaintext_1) - 1;

    Skissm__One2oneMsgPayload *message_1 = NULL;

    encrypt_ratchet(test_cipher_suite, alice_ratchet, ad, plaintext_1, plaintext_1_length, &message_1);

    uint8_t *output_1 = NULL;
    size_t decrypt_length_1 = decrypt_ratchet(test_cipher_suite, bob_ratchet, ad, message_1, &output_1);
    assert(decrypt_length_1 == plaintext_1_length);
    result = is_equal(plaintext_1, output_1, plaintext_1_length);
    assert(result);

    if (result) {
        print_result("Decryption success!!!", true);
    } else {
        print_result("Decryption failed!!!", false);
    }

    /* Bob sends Alice a message */
    uint8_t plaintext_2[] = "Bob's Message";
    size_t plaintext_2_length = sizeof(plaintext_2) - 1;

    Skissm__One2oneMsgPayload *message_2 = NULL;

    encrypt_ratchet(test_cipher_suite, bob_ratchet, ad, plaintext_2, plaintext_2_length, &message_2);

    uint8_t *output_2 = NULL;
    size_t decrypt_length_2 = decrypt_ratchet(test_cipher_suite, alice_ratchet, ad, message_2, &output_2);
    assert(decrypt_length_2 == plaintext_2_length);
    result = is_equal(plaintext_2, output_2, plaintext_2_length);
    assert(result);

    if (result) {
        print_result("Decryption success!!!", true);
    } else {
        print_result("Decryption failed!!!", false);
    }

    skissm__one2one_msg_payload__free_unpacked(message_1, NULL);
    skissm__one2one_msg_payload__free_unpacked(message_2, NULL);
    free_mem((void **)&output_1, decrypt_length_1);
    free_mem((void **)&output_2, decrypt_length_2);
    skissm__ratchet__free_unpacked(alice_ratchet, NULL);
    skissm__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    printf("====================================\n");
}

static void test_pqc_interaction_bob_first() {
    // test start
    printf("test_pqc_interaction_bob_first begin!!!\n");
    tear_up();

    get_skissm_plugin()->event_handler = test_event_handler;

    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_256F,
        E2EE_PACK_ALG_KEM_KYBER1024,
        E2EE_PACK_ALG_SYMMETRIC_KEY_AES256GCM,
        E2EE_PACK_ALG_HASH_SHA2_256
    );
    test_cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;

    Skissm__KeyPair alice_ratchet_key;
    test_cipher_suite->kem_suite->asym_key_gen(&alice_ratchet_key.public_key, &alice_ratchet_key.private_key);

    Skissm__KeyPair bob_spk;
    test_cipher_suite->kem_suite->asym_key_gen(&bob_spk.public_key, &bob_spk.private_key);

    int ad_len = 2 * test_cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
    uint8_t associated_data[ad_len];
    memset(associated_data, 0, ad_len);
    ProtobufCBinaryData ad;
    ad.len = ad_len;
    ad.data = (uint8_t *) malloc(ad_len * sizeof(uint8_t));
    int i;
    for (i = 0; i < ad_len; i++) {
        ad.data[i] = associated_data[i];
    }

    char *session_id = generate_uuid_str();

    uint8_t shared_secret[] = "shared_secret:nwjeldUbnjwcwkdt5q";

    Skissm__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    initialise_ratchet(&alice_ratchet);
    initialise_ratchet(&bob_ratchet);

    initialise_as_bob(
        test_cipher_suite,
        bob_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &bob_spk,
        &(alice_ratchet_key.public_key)
    );
    initialise_as_alice(
        test_cipher_suite,
        alice_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &alice_ratchet_key,
        &(bob_spk.public_key),
        &(bob_ratchet->sender_chain->our_ratchet_public_key)
    );
    int key_len = test_cipher_suite->kem_suite->get_crypto_param().asym_priv_key_len;

    bool result;

    /* Bob sends Alice a message */
    uint8_t plaintext_1[] = "Bob's Message";
    size_t plaintext_1_length = sizeof(plaintext_1) - 1;

    Skissm__One2oneMsgPayload *message_1 = NULL;

    encrypt_ratchet(test_cipher_suite, bob_ratchet, ad, plaintext_1, plaintext_1_length, &message_1);

    uint8_t *output_1 = NULL;
    size_t decrypt_length_1 = decrypt_ratchet(test_cipher_suite, alice_ratchet, ad, message_1, &output_1);
    assert(decrypt_length_1 == plaintext_1_length);
    result = is_equal(plaintext_1, output_1, plaintext_1_length);
    assert(result);

    if (result) {
        print_result("Decryption success!!!", true);
    } else {
        print_result("Decryption failed!!!", false);
    }

    /* Alice sends Bob a message */
    uint8_t plaintext_2[] = "Alice's Message";
    size_t plaintext_2_length = sizeof(plaintext_2) - 1;

    Skissm__One2oneMsgPayload *message_2 = NULL;

    encrypt_ratchet(test_cipher_suite, alice_ratchet, ad, plaintext_2, plaintext_2_length, &message_2);

    uint8_t *output_2 = NULL;
    size_t decrypt_length_2 = decrypt_ratchet(test_cipher_suite, bob_ratchet, ad, message_2, &output_2);
    assert(decrypt_length_2 == plaintext_2_length);
    result = is_equal(plaintext_2, output_2, plaintext_2_length);
    assert(result);

    if (result) {
        print_result("Decryption success!!!", true);
    } else {
        print_result("Decryption failed!!!", false);
    }

    skissm__one2one_msg_payload__free_unpacked(message_1, NULL);
    skissm__one2one_msg_payload__free_unpacked(message_2, NULL);
    free_mem((void **)&output_1, decrypt_length_1);
    free_mem((void **)&output_2, decrypt_length_2);
    skissm__ratchet__free_unpacked(alice_ratchet, NULL);
    skissm__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    printf("====================================\n");
}

static void test_pqc_out_of_order() {
    // test start
    printf("test_pqc_out_of_order begin!!!\n");
    tear_up();

    get_skissm_plugin()->event_handler = test_event_handler;

    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_256F,
        E2EE_PACK_ALG_KEM_KYBER1024,
        E2EE_PACK_ALG_SYMMETRIC_KEY_AES256GCM,
        E2EE_PACK_ALG_HASH_SHA2_256
    );
    test_cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;

    Skissm__KeyPair alice_ratchet_key;
    test_cipher_suite->kem_suite->asym_key_gen(&alice_ratchet_key.public_key, &alice_ratchet_key.private_key);

    Skissm__KeyPair bob_spk;
    test_cipher_suite->kem_suite->asym_key_gen(&bob_spk.public_key, &bob_spk.private_key);

    int ad_len = 2 * test_cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
    uint8_t associated_data[ad_len];
    memset(associated_data, 0, ad_len);
    ProtobufCBinaryData ad;
    ad.len = ad_len;
    ad.data = (uint8_t *) malloc(ad_len * sizeof(uint8_t));
    int i;
    for (i = 0; i < ad_len; i++) {
        ad.data[i] = associated_data[i];
    }

    char *session_id = generate_uuid_str();

    uint8_t shared_secret[] = "shared_secret:nwjeldUbnjwcwkdt5q";

    Skissm__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    initialise_ratchet(&alice_ratchet);
    initialise_ratchet(&bob_ratchet);

    initialise_as_bob(
        test_cipher_suite,
        bob_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &bob_spk,
        &(alice_ratchet_key.public_key)
    );
    initialise_as_alice(
        test_cipher_suite,
        alice_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &alice_ratchet_key,
        &(bob_spk.public_key),
        &(bob_ratchet->sender_chain->our_ratchet_public_key)
    );
    int key_len = test_cipher_suite->kem_suite->get_crypto_param().asym_priv_key_len;

    bool result;

    /* Alice sends Bob two messages */
    uint8_t plaintext_1[] = "Alice's first Message";
    size_t plaintext_1_length = sizeof(plaintext_1) - 1;

    Skissm__One2oneMsgPayload *message_1 = NULL;

    encrypt_ratchet(test_cipher_suite, alice_ratchet, ad, plaintext_1, plaintext_1_length, &message_1);

    uint8_t plaintext_2[] = "Alice's second Message";
    size_t plaintext_2_length = sizeof(plaintext_2) - 1;

    Skissm__One2oneMsgPayload *message_2 = NULL;

    encrypt_ratchet(test_cipher_suite, alice_ratchet, ad, plaintext_2, plaintext_2_length, &message_2);

    // decrypt the second message first
    uint8_t *output_2 = NULL;
    size_t decrypt_length_2 = decrypt_ratchet(test_cipher_suite, bob_ratchet, ad, message_2, &output_2);
    assert(decrypt_length_2 == plaintext_2_length);
    result = is_equal(plaintext_2, output_2, plaintext_2_length);
    assert(result);

    if (result) {
        print_result("Decryption success!!!", true);
    } else {
        print_result("Decryption failed!!!", false);
    }

    uint8_t *output_1 = NULL;
    size_t decrypt_length_1 = decrypt_ratchet(test_cipher_suite, bob_ratchet, ad, message_1, &output_1);
    assert(decrypt_length_1 == plaintext_1_length);
    result = is_equal(plaintext_1, output_1, plaintext_1_length);
    assert(result);

    if (result) {
        print_result("Decryption success!!!", true);
    } else {
        print_result("Decryption failed!!!", false);
    }

    skissm__one2one_msg_payload__free_unpacked(message_1, NULL);
    skissm__one2one_msg_payload__free_unpacked(message_2, NULL);
    free_mem((void **)&output_1, decrypt_length_1);
    free_mem((void **)&output_2, decrypt_length_2);
    skissm__ratchet__free_unpacked(alice_ratchet, NULL);
    skissm__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    printf("====================================\n");
}

static void test_pqc_continual_message() {
    // test start
    printf("test_pqc_continual_message begin!!!\n");
    tear_up();

    get_skissm_plugin()->event_handler = test_event_handler;

    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_256F,
        E2EE_PACK_ALG_KEM_KYBER1024,
        E2EE_PACK_ALG_SYMMETRIC_KEY_AES256GCM,
        E2EE_PACK_ALG_HASH_SHA2_256
    );
    test_cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;

    Skissm__KeyPair alice_ratchet_key;
    test_cipher_suite->kem_suite->asym_key_gen(&alice_ratchet_key.public_key, &alice_ratchet_key.private_key);

    Skissm__KeyPair bob_spk;
    test_cipher_suite->kem_suite->asym_key_gen(&bob_spk.public_key, &bob_spk.private_key);

    int ad_len = 2 * test_cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
    uint8_t associated_data[ad_len];
    memset(associated_data, 0, ad_len);
    ProtobufCBinaryData ad;
    ad.len = ad_len;
    ad.data = (uint8_t *) malloc(ad_len * sizeof(uint8_t));
    int i;
    for (i = 0; i < ad_len; i++) {
        ad.data[i] = associated_data[i];
    }

    char *session_id = generate_uuid_str();

    uint8_t shared_secret[] = "shared_secret:nwjeldUbnjwcwkdt5q";

    Skissm__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    initialise_ratchet(&alice_ratchet);
    initialise_ratchet(&bob_ratchet);

    initialise_as_bob(
        test_cipher_suite,
        bob_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &bob_spk,
        &(alice_ratchet_key.public_key)
    );
    initialise_as_alice(
        test_cipher_suite,
        alice_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &alice_ratchet_key,
        &(bob_spk.public_key),
        &(bob_ratchet->sender_chain->our_ratchet_public_key)
    );
    int key_len = test_cipher_suite->kem_suite->get_crypto_param().asym_priv_key_len;

    // Alice sends Bob messages many times
    int message_num = 1000;

    uint8_t **plaintext = (uint8_t **) malloc(sizeof(uint8_t *) * message_num);
    size_t *plaintext_len = (size_t *) malloc(sizeof(size_t) * message_num);
    Skissm__One2oneMsgPayload **message = (Skissm__One2oneMsgPayload **)malloc(sizeof(Skissm__One2oneMsgPayload *) * message_num);

    for (i = 0; i < message_num; i++) {
        plaintext[i] = (uint8_t *) malloc(sizeof(uint8_t) * 64);
        plaintext_len[i] = snprintf((char *)plaintext[i], 64, "[%4d]This message will be sent a lot of times.", i);
        encrypt_ratchet(test_cipher_suite, alice_ratchet, ad, plaintext[i], plaintext_len[i], &message[i]);
    }

    uint8_t **output = (uint8_t **) malloc(sizeof(uint8_t *) * message_num);
    size_t *output_len = (size_t *) malloc(sizeof(size_t) * message_num);

    bool result;
    for (i = 0; i < message_num; i++) {
        output_len[i] = decrypt_ratchet(test_cipher_suite, bob_ratchet, ad, message[i], &output[i]);

        assert(output_len[i] == plaintext_len[i]);
        result = is_equal(plaintext[i], output[i], plaintext_len[i]);
        assert(result);
    }

    for (i = 0; i < message_num; i++) {
        free_mem((void **)&plaintext[i], sizeof(uint8_t) * 64);
        free_mem((void **)&output[i], output_len[i]);
        skissm__one2one_msg_payload__free_unpacked(message[i], NULL);
    }
    free_mem((void **)&plaintext, sizeof(uint8_t *) * message_num);
    free_mem((void **)&plaintext_len, sizeof(size_t) * message_num);
    free_mem((void **)&output, sizeof(uint8_t *) * message_num);
    free_mem((void **)&output_len, sizeof(size_t) * message_num);
    skissm__ratchet__free_unpacked(alice_ratchet, NULL);
    skissm__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    printf("====================================\n");
}

static void test_pqc_interaction_v2() {
    // test start
    printf("test_pqc_interaction_v2 begin!!!\n");
    tear_up();

    get_skissm_plugin()->event_handler = test_event_handler;

    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_256F,
        E2EE_PACK_ALG_KEM_KYBER1024,
        E2EE_PACK_ALG_SYMMETRIC_KEY_AES256GCM,
        E2EE_PACK_ALG_HASH_SHA2_256
    );
    test_cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;

    Skissm__KeyPair alice_ratchet_key;
    test_cipher_suite->kem_suite->asym_key_gen(&alice_ratchet_key.public_key, &alice_ratchet_key.private_key);

    Skissm__KeyPair bob_spk;
    test_cipher_suite->kem_suite->asym_key_gen(&bob_spk.public_key, &bob_spk.private_key);

    int ad_len = 2 * test_cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
    uint8_t associated_data[ad_len];
    memset(associated_data, 0, ad_len);
    ProtobufCBinaryData ad;
    ad.len = ad_len;
    ad.data = (uint8_t *) malloc(ad_len * sizeof(uint8_t));
    int i;
    for (i = 0; i < ad_len; i++) {
        ad.data[i] = associated_data[i];
    }

    char *session_id = generate_uuid_str();

    uint8_t shared_secret[] = "shared_secret:nwjeldUbnjwcwkdt5q";

    Skissm__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    initialise_ratchet(&alice_ratchet);
    initialise_ratchet(&bob_ratchet);

    initialise_as_bob(
        test_cipher_suite,
        bob_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &bob_spk,
        &(alice_ratchet_key.public_key)
    );
    initialise_as_alice(
        test_cipher_suite,
        alice_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &alice_ratchet_key,
        &(bob_spk.public_key),
        &(bob_ratchet->sender_chain->our_ratchet_public_key)
    );
    int key_len = test_cipher_suite->kem_suite->get_crypto_param().asym_priv_key_len;

    int round = 10;

    uint8_t *plaintext = (uint8_t *) malloc(sizeof(uint8_t) * 64);
    size_t plaintext_len;
    Skissm__One2oneMsgPayload *message = NULL;
    uint8_t *output = NULL;
    size_t output_len;
    bool result;

    for (i = 0; i < round; i++) {
        // the first time, from Alice to Bob
        plaintext_len = snprintf((char *)plaintext, 64, "[%4d]This message is from Alice to Bob.", i * 4);
        encrypt_ratchet(test_cipher_suite, alice_ratchet, ad, plaintext, plaintext_len, &message);

        output_len = decrypt_ratchet(test_cipher_suite, bob_ratchet, ad, message, &output);
        assert(output_len == plaintext_len);
        result = is_equal(plaintext, output, plaintext_len);
        assert(result);

        skissm__one2one_msg_payload__free_unpacked(message, NULL);
        message = NULL;
        free_mem((void **)&output, sizeof(uint8_t) * output_len);

        // the second time, from Alice to Bob
        plaintext_len = snprintf((char *)plaintext, 64, "[%4d]This message is from Alice to Bob.", i * 4 + 1);
        encrypt_ratchet(test_cipher_suite, alice_ratchet, ad, plaintext, plaintext_len, &message);

        output_len = decrypt_ratchet(test_cipher_suite, bob_ratchet, ad, message, &output);
        assert(output_len == plaintext_len);
        result = is_equal(plaintext, output, plaintext_len);
        assert(result);

        skissm__one2one_msg_payload__free_unpacked(message, NULL);
        message = NULL;
        free_mem((void **)&output, sizeof(uint8_t) * output_len);

        // the third time, from Bob to Alice
        plaintext_len = snprintf((char *)plaintext, 64, "[%4d]This message is from Bob to Alice.", i * 4 + 2);
        encrypt_ratchet(test_cipher_suite, bob_ratchet, ad, plaintext, plaintext_len, &message);

        output_len = decrypt_ratchet(test_cipher_suite, alice_ratchet, ad, message, &output);
        assert(output_len == plaintext_len);
        result = is_equal(plaintext, output, plaintext_len);
        assert(result);

        skissm__one2one_msg_payload__free_unpacked(message, NULL);
        message = NULL;
        free_mem((void **)&output, sizeof(uint8_t) * output_len);

        // the third time, from Bob to Alice
        plaintext_len = snprintf((char *)plaintext, 64, "[%4d]This message is from Bob to Alice.", i * 4 + 3);
        encrypt_ratchet(test_cipher_suite, bob_ratchet, ad, plaintext, plaintext_len, &message);

        output_len = decrypt_ratchet(test_cipher_suite, alice_ratchet, ad, message, &output);
        assert(output_len == plaintext_len);
        result = is_equal(plaintext, output, plaintext_len);
        assert(result);

        skissm__one2one_msg_payload__free_unpacked(message, NULL);
        message = NULL;
        free_mem((void **)&output, sizeof(uint8_t) * output_len);
    }

    free_mem((void **)&plaintext, sizeof(uint8_t) * 64);
    skissm__ratchet__free_unpacked(alice_ratchet, NULL);
    skissm__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    printf("====================================\n");
}

static void test_pqc_out_of_order_v2() {
    // test start
    printf("test_pqc_out_of_order_v2 begin!!!\n");
    tear_up();

    get_skissm_plugin()->event_handler = test_event_handler;

    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_256F,
        E2EE_PACK_ALG_KEM_KYBER1024,
        E2EE_PACK_ALG_SYMMETRIC_KEY_AES256GCM,
        E2EE_PACK_ALG_HASH_SHA2_256
    );
    test_cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;

    Skissm__KeyPair alice_ratchet_key;
    test_cipher_suite->kem_suite->asym_key_gen(&alice_ratchet_key.public_key, &alice_ratchet_key.private_key);

    Skissm__KeyPair bob_spk;
    test_cipher_suite->kem_suite->asym_key_gen(&bob_spk.public_key, &bob_spk.private_key);

    int ad_len = 2 * test_cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
    uint8_t associated_data[ad_len];
    memset(associated_data, 0, ad_len);
    ProtobufCBinaryData ad;
    ad.len = ad_len;
    ad.data = (uint8_t *) malloc(ad_len * sizeof(uint8_t));
    int i;
    for (i = 0; i < ad_len; i++) {
        ad.data[i] = associated_data[i];
    }

    char *session_id = generate_uuid_str();

    uint8_t shared_secret[] = "shared_secret:nwjeldUbnjwcwkdt5q";

    Skissm__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    initialise_ratchet(&alice_ratchet);
    initialise_ratchet(&bob_ratchet);

    initialise_as_bob(
        test_cipher_suite,
        bob_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &bob_spk,
        &(alice_ratchet_key.public_key)
    );
    initialise_as_alice(
        test_cipher_suite,
        alice_ratchet,
        shared_secret,
        strlen((const char *)shared_secret),
        &alice_ratchet_key,
        &(bob_spk.public_key),
        &(bob_ratchet->sender_chain->our_ratchet_public_key)
    );
    int key_len = test_cipher_suite->kem_suite->get_crypto_param().asym_priv_key_len;

    int msg_num = 10;
    uint8_t **plaintext = (uint8_t **) malloc(sizeof(uint8_t *) * msg_num);
    size_t *plaintext_len = (size_t *) malloc(sizeof(size_t) * msg_num);
    Skissm__One2oneMsgPayload **message = (Skissm__One2oneMsgPayload **)malloc(sizeof(Skissm__One2oneMsgPayload *) * msg_num);
    uint8_t **output = (uint8_t **) malloc(sizeof(uint8_t *) * msg_num);
    size_t *output_len = (size_t *) malloc(sizeof(size_t) * msg_num);
    bool result;

    for (i = 0; i < msg_num; i++) {
        plaintext[i] = (uint8_t *) malloc(sizeof(uint8_t) * 64);
        plaintext_len[i] = snprintf((char *)plaintext[i], 64, "[%4d]This message may be from Alice or Bob.", i);
    }

    encrypt_ratchet(test_cipher_suite, alice_ratchet, ad, plaintext[0], plaintext_len[0], &message[0]);
    output_len[0] = decrypt_ratchet(test_cipher_suite, bob_ratchet, ad, message[0], &output[0]);
    assert(output_len[0] == plaintext_len[0]);
    result = is_equal(plaintext[0], output[0], plaintext_len[0]);
    assert(result);

    encrypt_ratchet(test_cipher_suite, alice_ratchet, ad, plaintext[1], plaintext_len[1], &message[1]);
    encrypt_ratchet(test_cipher_suite, bob_ratchet, ad, plaintext[2], plaintext_len[2], &message[2]);
    encrypt_ratchet(test_cipher_suite, bob_ratchet, ad, plaintext[3], plaintext_len[3], &message[3]);
    encrypt_ratchet(test_cipher_suite, bob_ratchet, ad, plaintext[4], plaintext_len[4], &message[4]);

    output_len[4] = decrypt_ratchet(test_cipher_suite, alice_ratchet, ad, message[4], &output[4]);
    assert(output_len[4] == plaintext_len[4]);
    result = is_equal(plaintext[4], output[4], plaintext_len[4]);
    assert(result);
    output_len[2] = decrypt_ratchet(test_cipher_suite, alice_ratchet, ad, message[2], &output[2]);
    assert(output_len[2] == plaintext_len[2]);
    result = is_equal(plaintext[2], output[2], plaintext_len[2]);
    assert(result);

    encrypt_ratchet(test_cipher_suite, alice_ratchet, ad, plaintext[5], plaintext_len[5], &message[5]);
    encrypt_ratchet(test_cipher_suite, alice_ratchet, ad, plaintext[6], plaintext_len[6], &message[6]);
    encrypt_ratchet(test_cipher_suite, alice_ratchet, ad, plaintext[7], plaintext_len[7], &message[7]);

    output_len[6] = decrypt_ratchet(test_cipher_suite, bob_ratchet, ad, message[6], &output[6]);
    assert(output_len[6] == plaintext_len[6]);
    result = is_equal(plaintext[6], output[6], plaintext_len[6]);
    assert(result);
    output_len[1] = decrypt_ratchet(test_cipher_suite, bob_ratchet, ad, message[1], &output[1]);
    assert(output_len[1] == plaintext_len[1]);
    result = is_equal(plaintext[1], output[1], plaintext_len[1]);
    assert(result);

    encrypt_ratchet(test_cipher_suite, bob_ratchet, ad, plaintext[8], plaintext_len[8], &message[8]);
    encrypt_ratchet(test_cipher_suite, bob_ratchet, ad, plaintext[9], plaintext_len[9], &message[9]);
    output_len[9] = decrypt_ratchet(test_cipher_suite, alice_ratchet, ad, message[9], &output[9]);
    assert(output_len[9] == plaintext_len[9]);
    result = is_equal(plaintext[9], output[9], plaintext_len[9]);
    assert(result);
    output_len[3] = decrypt_ratchet(test_cipher_suite, alice_ratchet, ad, message[3], &output[3]);
    assert(output_len[3] == plaintext_len[3]);
    result = is_equal(plaintext[3], output[3], plaintext_len[3]);
    assert(result);

    output_len[5] = decrypt_ratchet(test_cipher_suite, bob_ratchet, ad, message[5], &output[5]);
    assert(output_len[5] == plaintext_len[5]);
    result = is_equal(plaintext[5], output[5], plaintext_len[5]);
    assert(result);
    output_len[7] = decrypt_ratchet(test_cipher_suite, bob_ratchet, ad, message[7], &output[7]);
    assert(output_len[7] == plaintext_len[7]);
    result = is_equal(plaintext[7], output[7], plaintext_len[7]);
    assert(result);

    output_len[8] = decrypt_ratchet(test_cipher_suite, alice_ratchet, ad, message[8], &output[8]);
    assert(output_len[8] == plaintext_len[8]);
    result = is_equal(plaintext[8], output[8], plaintext_len[8]);
    assert(result);

    for (i = 0; i < msg_num; i++) {
        free_mem((void **)&plaintext[i], sizeof(uint8_t) * 64);
        free_mem((void **)&output[i], output_len[i]);
        skissm__one2one_msg_payload__free_unpacked(message[i], NULL);
    }
    free_mem((void **)&plaintext, sizeof(uint8_t *) * msg_num);
    free_mem((void **)&plaintext_len, sizeof(size_t) * msg_num);
    free_mem((void **)&output, sizeof(uint8_t *) * msg_num);
    free_mem((void **)&output_len, sizeof(size_t) * msg_num);
    skissm__ratchet__free_unpacked(alice_ratchet, NULL);
    skissm__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    printf("====================================\n");
}

int main() {
    test_ecc_alice_to_bob();
    test_ecc_bob_to_alice();
    test_ecc_interaction_alice_first();
    test_ecc_interaction_bob_first();
    test_ecc_out_of_order();
    test_ecc_continual_message();
    test_pqc_alice_to_bob();
    test_pqc_bob_to_alice();
    test_pqc_interaction_alice_first();
    test_pqc_interaction_bob_first();
    test_pqc_out_of_order();
    test_pqc_continual_message();
    test_pqc_interaction_v2();
    test_pqc_out_of_order_v2();

    return 0;
}
