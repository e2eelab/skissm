#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "account.h"
#include "e2ee_protocol.h"
#include "ratchet.h"
#include "session.h"
#include "skissm.h"
#include "mem_util.h"

#include "test_env.h"

extern register_user_response_handler register_user_response_handler_store;

static void test_basic_session(){
    // test start
    setup();

    Org__E2eelab__Lib__Protobuf__E2eeAccount *a_account = create_account();
    register_user_response_handler_store.account = a_account;
    send_register_user_request(a_account, &register_user_response_handler_store);

    Org__E2eelab__Lib__Protobuf__E2eeAccount *b_account = create_account();
    register_user_response_handler_store.account = b_account;
    send_register_user_request(b_account, &register_user_response_handler_store);

    // Alice sends an encrypted message to Bob, and Bob decrypts the message
    uint8_t plaintext[] = "Hello, World";
    size_t plaintext_len = sizeof(plaintext) - 1;
    uint8_t *context = NULL;
    size_t context_len;
    pack_e2ee_plaintext(
        plaintext, plaintext_len,
        ORG__E2EELAB__LIB__PROTOBUF__E2EE_PLAINTEXT_TYPE__COMMON_MSG,
        &context, &context_len
    );
    encrypt_session(a_account->address, b_account->address, context, context_len);

    org__e2eelab__lib__protobuf__e2ee_account__free_unpacked(a_account, NULL);
    org__e2eelab__lib__protobuf__e2ee_account__free_unpacked(b_account, NULL);

    // test stop
    tear_down();
}

static void test_interaction(){
    // test start
    setup();

    Org__E2eelab__Lib__Protobuf__E2eeAccount *a_account = create_account();
    register_user_response_handler_store.account = a_account;
    send_register_user_request(a_account, &register_user_response_handler_store);

    Org__E2eelab__Lib__Protobuf__E2eeAccount *b_account = create_account();
    register_user_response_handler_store.account = b_account;
    send_register_user_request(b_account, &register_user_response_handler_store);

    // Alice sends an encrypted message to Bob, and Bob decrypts the message
    uint8_t plaintext[] = "Hi! Bob! This is Alice.";
    size_t plaintext_len = sizeof(plaintext) - 1;
    uint8_t *context = NULL;
    size_t context_len;
    pack_e2ee_plaintext(
        plaintext, plaintext_len,
        ORG__E2EELAB__LIB__PROTOBUF__E2EE_PLAINTEXT_TYPE__COMMON_MSG,
        &context, &context_len
    );
    encrypt_session(a_account->address, b_account->address, context, context_len);

    // Bob sends an encrypted message to Alice, and Alice decrypts the message
    uint8_t plaintext_2[] = "Hello! This is Bob.";
    size_t plaintext_len_2 = sizeof(plaintext_2) - 1;
    uint8_t *context_2 = NULL;
    size_t context_len_2;
    pack_e2ee_plaintext(
        plaintext_2, plaintext_len_2,
        ORG__E2EELAB__LIB__PROTOBUF__E2EE_PLAINTEXT_TYPE__COMMON_MSG,
        &context_2, &context_len_2
    );
    encrypt_session(b_account->address, a_account->address, context_2, context_len_2);

    org__e2eelab__lib__protobuf__e2ee_account__free_unpacked(a_account, NULL);
    org__e2eelab__lib__protobuf__e2ee_account__free_unpacked(b_account, NULL);

    // test stop
    tear_down();
}

static void test_continual_messages(){
    // test start
    setup();

    Org__E2eelab__Lib__Protobuf__E2eeAccount *a_account = create_account();
    register_user_response_handler_store.account = a_account;
    send_register_user_request(a_account, &register_user_response_handler_store);

    Org__E2eelab__Lib__Protobuf__E2eeAccount *b_account = create_account();
    register_user_response_handler_store.account = b_account;
    send_register_user_request(b_account, &register_user_response_handler_store);

    // Alice sends an encrypted message to Bob, and Bob decrypts the message
    uint8_t plaintext[] = "This message will be sent a lot of times.";
    size_t plaintext_len = sizeof(plaintext) - 1;
    uint8_t *context = NULL;
    size_t context_len;
    pack_e2ee_plaintext(
        plaintext, plaintext_len,
        ORG__E2EELAB__LIB__PROTOBUF__E2EE_PLAINTEXT_TYPE__COMMON_MSG,
        &context, &context_len
    );
    int i;
    for (i = 0; i < 2; i++){
        encrypt_session(a_account->address, b_account->address, context, context_len);
    }

    org__e2eelab__lib__protobuf__e2ee_account__free_unpacked(a_account, NULL);
    org__e2eelab__lib__protobuf__e2ee_account__free_unpacked(b_account, NULL);

    // test stop
    tear_down();
}

int main() {
    test_basic_session();
    test_interaction();
    test_continual_messages();

    return 0;
}
