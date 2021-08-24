#include <assert.h>
#include <string.h>

#include "cipher.h"
#include "mem_util.h"
#include "ratchet.h"

#include "test_env.h"

static const struct cipher CIPHER = CIPHER_INIT;

static void test_alice_to_bob(
  Org__E2eelab__Skissm__Proto__KeyPair alice_ratchet_key,
  Org__E2eelab__Skissm__Proto__KeyPair bob_spk,
  ProtobufCBinaryData session_id,
  ProtobufCBinaryData ad,
  uint8_t *shared_secret
) {
    Org__E2eelab__Skissm__Proto__E2eeRatchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    initialise_ratchet(&alice_ratchet);
    initialise_ratchet(&bob_ratchet);

    initialise_as_alice(alice_ratchet, shared_secret,
                        strlen((const char *)shared_secret), &alice_ratchet_key,
                        &(bob_spk.public_key));
    initialise_as_bob(bob_ratchet, shared_secret, strlen((const char *)shared_secret),
                      &bob_spk);
    assert(
        memcmp(
            bob_spk.public_key.data,
            bob_ratchet->sender_chain->ratchet_key_pair->public_key.data,
            CURVE25519_KEY_LENGTH) == 0);
    assert(
        memcmp(
            bob_spk.private_key.data,
            bob_ratchet->sender_chain->ratchet_key_pair->private_key.data,
            CURVE25519_KEY_LENGTH) == 0);

    uint8_t plaintext[] = "Message";
    size_t plaintext_length = sizeof(plaintext) - 1;

    size_t decrypt_length;

    /* Alice sends Bob a message */
    Org__E2eelab__Skissm__Proto__E2eeMsgPayload *message;

    encrypt_ratchet(alice_ratchet, ad, plaintext, plaintext_length, &message);

    uint8_t *output;
    decrypt_length = decrypt_ratchet(bob_ratchet, ad, message, &output);

    printf("%s\n", output);
    bool result;
    assert(result = is_equal(plaintext, output, plaintext_length));

    if (result) {
      printf("Decryption success!!!\n");
    } else {
      printf("Decryption failed!!!\n");
    }

    Org__E2eelab__Skissm__Proto__e2ee_msg_payload__free_unpacked(message, NULL);
    free_mem((void **)&output, decrypt_length);
    Org__E2eelab__Skissm__Proto__E2eeRatchet__free_unpacked(alice_ratchet, NULL);
    Org__E2eelab__Skissm__Proto__E2eeRatchet__free_unpacked(bob_ratchet, NULL);
}

static void test_bob_to_alice(
  Org__E2eelab__Skissm__Proto__KeyPair alice_ratchet_key,
  Org__E2eelab__Skissm__Proto__KeyPair bob_spk,
  ProtobufCBinaryData session_id,
  ProtobufCBinaryData ad, uint8_t *shared_secret
) {
    Org__E2eelab__Skissm__Proto__E2eeRatchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    initialise_ratchet(&alice_ratchet);
    initialise_ratchet(&bob_ratchet);

    initialise_as_alice(alice_ratchet, shared_secret,
                        strlen((const char *)shared_secret), &alice_ratchet_key,
                        &(bob_spk.public_key));
    initialise_as_bob(bob_ratchet, shared_secret, strlen((const char *)shared_secret),
                      &bob_spk);
    assert(
        memcmp(
            bob_spk.public_key.data,
            bob_ratchet->sender_chain->ratchet_key_pair->public_key.data,
            CURVE25519_KEY_LENGTH) == 0);

    uint8_t plaintext[] = "Message";
    size_t plaintext_length = sizeof(plaintext) - 1;

    size_t decrypt_length;

    /* Bob sends Alice a message */
    Org__E2eelab__Skissm__Proto__E2eeMsgPayload *message;
    encrypt_ratchet(bob_ratchet, ad, plaintext, plaintext_length, &message);

    uint8_t *output;
    decrypt_length = decrypt_ratchet(alice_ratchet, ad, message, &output);

    bool result;
    assert(result = is_equal(plaintext, output, plaintext_length));
    if (result) {
      printf("Decryption success!!!\n");
    } else {
      printf("Decryption failed!!!\n");
    }

    Org__E2eelab__Skissm__Proto__e2ee_msg_payload__free_unpacked(message, NULL);
    free_mem((void **)&output, decrypt_length);
    Org__E2eelab__Skissm__Proto__E2eeRatchet__free_unpacked(alice_ratchet, NULL);
    Org__E2eelab__Skissm__Proto__E2eeRatchet__free_unpacked(bob_ratchet, NULL);
}

static void test_out_of_order(
  Org__E2eelab__Skissm__Proto__KeyPair alice_ratchet_key,
  Org__E2eelab__Skissm__Proto__KeyPair bob_spk,
  ProtobufCBinaryData session_id,
  ProtobufCBinaryData ad, uint8_t *shared_secret
) {
    Org__E2eelab__Skissm__Proto__E2eeRatchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    initialise_ratchet(&alice_ratchet);
    initialise_ratchet(&bob_ratchet);

    initialise_as_alice(alice_ratchet, shared_secret,
                        strlen((const char *)shared_secret), &alice_ratchet_key,
                        &(bob_spk.public_key));
    initialise_as_bob(bob_ratchet, shared_secret, strlen((const char *)shared_secret),
                      &bob_spk);

    uint8_t plaintext_1[] = "First Message";
    size_t plaintext_1_length = sizeof(plaintext_1) - 1;

    uint8_t plaintext_2[] = "Second Messsage. A bit longer than the first.";
    size_t plaintext_2_length = sizeof(plaintext_2) - 1;

    size_t message_1_length, message_2_length;
    size_t output_1_length, output_2_length;

    Org__E2eelab__Skissm__Proto__E2eeMsgPayload *message_1;
    encrypt_ratchet(alice_ratchet, ad, plaintext_1, plaintext_1_length, &message_1);

    Org__E2eelab__Skissm__Proto__E2eeMsgPayload *message_2;
    encrypt_ratchet(alice_ratchet, ad, plaintext_2, plaintext_2_length, &message_2);

    uint8_t *output_1;
    output_1_length = decrypt_ratchet(bob_ratchet, ad, message_2, &output_1);

    bool result;
    assert(result = is_equal(plaintext_2, output_1, plaintext_2_length));
    if (result) {
      printf("The first decryption success!!!\n");
    } else {
      printf("The first decryption failed!!!\n");
    }

    uint8_t *output_2;
    output_2_length = decrypt_ratchet(bob_ratchet, ad, message_1, &output_2);
    assert(result = is_equal(plaintext_1, output_2, plaintext_1_length));
    if (result) {
      printf("The second decryption success!!!\n");
    } else {
      printf("The second decryption failed!!!\n");
    }

    Org__E2eelab__Skissm__Proto__e2ee_msg_payload__free_unpacked(message_1, NULL);
    Org__E2eelab__Skissm__Proto__e2ee_msg_payload__free_unpacked(message_2, NULL);
    free_mem((void **)&output_1, output_1_length);
    free_mem((void **)&output_2, output_2_length);
    Org__E2eelab__Skissm__Proto__E2eeRatchet__free_unpacked(alice_ratchet, NULL);
    Org__E2eelab__Skissm__Proto__E2eeRatchet__free_unpacked(bob_ratchet, NULL);
}

static void test_interaction(
  Org__E2eelab__Skissm__Proto__KeyPair alice_ratchet_key,
  Org__E2eelab__Skissm__Proto__KeyPair bob_spk,
  ProtobufCBinaryData session_id,
  ProtobufCBinaryData ad, uint8_t *shared_secret
) {
    Org__E2eelab__Skissm__Proto__E2eeRatchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    initialise_ratchet(&alice_ratchet);
    initialise_ratchet(&bob_ratchet);

    initialise_as_alice(alice_ratchet, shared_secret,
                        strlen((const char *)shared_secret), &alice_ratchet_key,
                        &(bob_spk.public_key));
    initialise_as_bob(bob_ratchet, shared_secret, strlen((const char *)shared_secret),
                      &bob_spk);

    uint8_t plaintext_alice[] = "This is a message from Alice.";
    size_t plaintext_length_alice = sizeof(plaintext_alice) - 1;

    size_t message_length_alice;
    size_t decrypt_length_alice;

    /* Alice sends Bob a message */
    Org__E2eelab__Skissm__Proto__E2eeMsgPayload *message_alice;
    encrypt_ratchet(alice_ratchet, ad, plaintext_alice, plaintext_length_alice, &message_alice);

    /* Bob received the message from Alice */
    uint8_t *output_alice;
    decrypt_length_alice = decrypt_ratchet(bob_ratchet, ad, message_alice, &output_alice);

    bool result;
    assert(result = is_equal(plaintext_alice, output_alice, plaintext_length_alice));

    assert(bob_ratchet->sender_chain == NULL);

    /* Bob prepares to reply to Alice */
    uint8_t plaintext_bob[] = "This is a message from Bob.";
    size_t plaintext_length_bob = sizeof(plaintext_bob) - 1;

    size_t message_length_bob;
    size_t decrypt_length_bob;

    /* Bob sends Alice a message */
    Org__E2eelab__Skissm__Proto__E2eeMsgPayload *message_bob;
    encrypt_ratchet(bob_ratchet, ad, plaintext_bob, plaintext_length_bob, &message_bob);

    assert(memcmp(bob_ratchet->sender_chain->ratchet_key_pair->public_key.data,
                  bob_spk.public_key.data, CURVE25519_KEY_LENGTH) != 0);

    /* Alice decrypts the message from Bob */
    uint8_t *output_bob;
    decrypt_length_bob = decrypt_ratchet(alice_ratchet, ad, message_bob, &output_bob);

    assert(result = is_equal(plaintext_bob, output_bob, plaintext_length_bob));

    Org__E2eelab__Skissm__Proto__e2ee_msg_payload__free_unpacked(message_alice, NULL);
    Org__E2eelab__Skissm__Proto__e2ee_msg_payload__free_unpacked(message_bob, NULL);
    free_mem((void **)&output_alice, decrypt_length_alice);
    free_mem((void **)&output_bob, decrypt_length_bob);
    Org__E2eelab__Skissm__Proto__E2eeRatchet__free_unpacked(alice_ratchet, NULL);
    Org__E2eelab__Skissm__Proto__E2eeRatchet__free_unpacked(bob_ratchet, NULL);
}

static void test_two_ratchets(
  Org__E2eelab__Skissm__Proto__KeyPair alice_ratchet_key,
  Org__E2eelab__Skissm__Proto__KeyPair bob_ratchet_key,
  Org__E2eelab__Skissm__Proto__KeyPair bob_spk,
  Org__E2eelab__Skissm__Proto__KeyPair alice_spk,
  ProtobufCBinaryData session_id,
  ProtobufCBinaryData ad, uint8_t *shared_secret
) {
    /* This ratchet is used only for Alice to Bob. */
    Org__E2eelab__Skissm__Proto__E2eeRatchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    initialise_ratchet(&alice_ratchet);
    initialise_ratchet(&bob_ratchet);

    initialise_as_alice(alice_ratchet, shared_secret,
                        strlen((const char *)shared_secret), &alice_ratchet_key,
                        &(bob_spk.public_key));
    initialise_as_bob(bob_ratchet, shared_secret, strlen((const char *)shared_secret),
                      &bob_spk);

    /* This ratchet is used only for Bob to Alice. */
    Org__E2eelab__Skissm__Proto__E2eeRatchet *alice_ratchet_2 = NULL, *bob_ratchet_2 = NULL;
    initialise_ratchet(&alice_ratchet_2);
    initialise_ratchet(&bob_ratchet_2);

    initialise_as_alice(bob_ratchet_2, shared_secret,
                        strlen((const char *)shared_secret), &bob_ratchet_key,
                        &(alice_spk.public_key));
    initialise_as_bob(alice_ratchet_2, shared_secret, strlen((const char *)shared_secret),
                      &alice_spk);

    /* Alice prepares a message */
    uint8_t plaintext_alice[] = "Hello, Bob!";
    size_t plaintext_length_alice = sizeof(plaintext_alice) - 1;

    size_t message_length_alice;
    size_t decrypt_length_alice;

    /* Alice sends Bob a message */
    Org__E2eelab__Skissm__Proto__E2eeMsgPayload *message_alice;
    encrypt_ratchet(alice_ratchet, ad, plaintext_alice, plaintext_length_alice, &message_alice);

    /* Bob received the message from Alice */
    uint8_t *output_alice;
    decrypt_length_alice = decrypt_ratchet(bob_ratchet, ad, message_alice, &output_alice);

    bool result;
    assert(result = is_equal(plaintext_alice, output_alice, plaintext_length_alice));

    assert(bob_ratchet->sender_chain == NULL);

    /* Bob prepares to reply to Alice */
    uint8_t plaintext_bob[] = "Hey, Alice!";
    size_t plaintext_length_bob = sizeof(plaintext_bob) - 1;

    size_t message_length_bob;
    size_t decrypt_length_bob;

    /* Bob sends Alice a message */
    Org__E2eelab__Skissm__Proto__E2eeMsgPayload *message_bob;
    encrypt_ratchet(bob_ratchet_2, ad, plaintext_bob, plaintext_length_bob, &message_bob);

    /* Alice decrypts the message from Bob */
    uint8_t *output_bob;
    decrypt_length_bob = decrypt_ratchet(alice_ratchet_2, ad, message_bob, &output_bob);

    assert(result = is_equal(plaintext_bob, output_bob, plaintext_length_bob));

    assert(alice_ratchet_2->sender_chain == NULL);

    Org__E2eelab__Skissm__Proto__e2ee_msg_payload__free_unpacked(message_alice, NULL);
    Org__E2eelab__Skissm__Proto__e2ee_msg_payload__free_unpacked(message_bob, NULL);
    free_mem((void **)&output_alice, decrypt_length_alice);
    free_mem((void **)&output_bob, decrypt_length_bob);
    Org__E2eelab__Skissm__Proto__E2eeRatchet__free_unpacked(alice_ratchet, NULL);
    Org__E2eelab__Skissm__Proto__E2eeRatchet__free_unpacked(bob_ratchet, NULL);
    Org__E2eelab__Skissm__Proto__E2eeRatchet__free_unpacked(alice_ratchet_2, NULL);
    Org__E2eelab__Skissm__Proto__E2eeRatchet__free_unpacked(bob_ratchet_2, NULL);
}

int main() {
    // test start
    setup();

    Org__E2eelab__Skissm__Proto__KeyPair alice_ratchet_key, bob_ratchet_key;
    CIPHER.suit1->gen_key_pair(&alice_ratchet_key);
    CIPHER.suit1->gen_key_pair(&bob_ratchet_key);

    Org__E2eelab__Skissm__Proto__KeyPair bob_spk, alice_spk;
    CIPHER.suit1->gen_key_pair(&bob_spk);
    CIPHER.suit1->gen_key_pair(&alice_spk);

    uint8_t associated_data[AD_LENGTH] = {0};
    ProtobufCBinaryData ad;
    ad.len = AD_LENGTH;
    ad.data = (uint8_t *) malloc(AD_LENGTH * sizeof(uint8_t));
    int i;
    for (i = 0; i < 64; i++) {
      ad.data[i] = associated_data[i];
    }

    ProtobufCBinaryData session_id;
    random_session_id(&session_id);

    uint8_t shared_secret[] = "shared_secret:nwjeldUbnjwcwkdt5q";

    // test_alice_to_bob(alice_ratchet_key, bob_spk, session_id, ad, shared_secret);

    // test_bob_to_alice(alice_ratchet_key, bob_spk, session_id, ad, shared_secret);

    // test_out_of_order(alice_ratchet_key, bob_spk, session_id, ad, shared_secret);

    // test_interaction(alice_ratchet_key, bob_spk, session_id, ad, shared_secret);

    test_two_ratchets(alice_ratchet_key, bob_ratchet_key, bob_spk, alice_spk, session_id, ad, shared_secret);

    // test stop.
    tear_down();
    return 0;
}
