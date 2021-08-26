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

typedef struct store_plaintext {
  uint8_t *plaintext;
  size_t plaintext_len;
} store_plaintext;

store_plaintext plaintext_store = {NULL, 0};

static void on_error(ErrorCode error_code, char *error_msg) {
    printf("💀 ErrorCode: %d, ErrorMsg: %s\n", error_code, error_msg);
}

static void on_one2one_msg_received(
    Org__E2eelab__Skissm__Proto__E2eeAddress *from_address,
    Org__E2eelab__Skissm__Proto__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    printf("😊 on_one2one_msg_received: plaintext[len=%zu]: %s\n", plaintext_len, plaintext);
    if (plaintext_store.plaintext != NULL){
        free_mem((void **)&(plaintext_store.plaintext), plaintext_store.plaintext_len);
    }
    plaintext_store.plaintext = (uint8_t *) malloc(sizeof(uint8_t) * plaintext_len);
    memcpy(plaintext_store.plaintext, plaintext, plaintext_len);
    plaintext_store.plaintext_len = plaintext_len;
}

static skissm_event_handler test_event_handler = {
    on_error,
    on_one2one_msg_received,
    NULL,
    NULL,
    NULL,
    NULL
};

static void test_encryption(
    Org__E2eelab__Skissm__Proto__E2eeAddress *from_address,
    Org__E2eelab__Skissm__Proto__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    uint8_t *context = NULL;
    size_t context_len;
    pack_e2ee_plaintext(
        plaintext, plaintext_len,
        ORG__E2EELAB__SKISSM__PROTO__E2EE_PLAINTEXT_TYPE__COMMON_MSG,
        &context, &context_len
    );
    encrypt_session(from_address, to_address, context, context_len);
    assert(plaintext_len == plaintext_store.plaintext_len);
    assert(memcmp(plaintext, plaintext_store.plaintext, plaintext_len) == 0);
}

static void test_basic_session(){
    // test start
    setup();

    set_skissm_event_handler(&test_event_handler);

    Org__E2eelab__Skissm__Proto__E2eeAccount *a_account = create_account();
    register_user_response_handler_store.account = a_account;
    send_register_user_request(a_account, &register_user_response_handler_store);

    Org__E2eelab__Skissm__Proto__E2eeAccount *b_account = create_account();
    register_user_response_handler_store.account = b_account;
    send_register_user_request(b_account, &register_user_response_handler_store);

    // Alice sends an encrypted message to Bob, and Bob decrypts the message
    uint8_t plaintext[] = "Hello, World";
    size_t plaintext_len = sizeof(plaintext) - 1;
    test_encryption(a_account->address, b_account->address, plaintext, plaintext_len);

    org__e2eelab__skissm__proto__e2ee_account__free_unpacked(a_account, NULL);
    org__e2eelab__skissm__proto__e2ee_account__free_unpacked(b_account, NULL);

    // test stop
    tear_down();
}

static void test_interaction(){
    // test start
    setup();

    set_skissm_event_handler(&test_event_handler);

    Org__E2eelab__Skissm__Proto__E2eeAccount *a_account = create_account();
    register_user_response_handler_store.account = a_account;
    send_register_user_request(a_account, &register_user_response_handler_store);

    Org__E2eelab__Skissm__Proto__E2eeAccount *b_account = create_account();
    register_user_response_handler_store.account = b_account;
    send_register_user_request(b_account, &register_user_response_handler_store);

    // Alice sends an encrypted message to Bob, and Bob decrypts the message
    uint8_t plaintext[] = "Hi! Bob! This is Alice.";
    size_t plaintext_len = sizeof(plaintext) - 1;
    test_encryption(a_account->address, b_account->address, plaintext, plaintext_len);

    // Bob sends an encrypted message to Alice, and Alice decrypts the message
    uint8_t plaintext_2[] = "Hello! This is Bob.";
    size_t plaintext_len_2 = sizeof(plaintext_2) - 1;
    test_encryption(b_account->address, a_account->address, plaintext_2, plaintext_len_2);

    org__e2eelab__skissm__proto__e2ee_account__free_unpacked(a_account, NULL);
    org__e2eelab__skissm__proto__e2ee_account__free_unpacked(b_account, NULL);

    // test stop
    tear_down();
}

static void test_continual_messages(){
    // test start
    setup();

    set_skissm_event_handler(&test_event_handler);

    Org__E2eelab__Skissm__Proto__E2eeAccount *a_account = create_account();
    register_user_response_handler_store.account = a_account;
    send_register_user_request(a_account, &register_user_response_handler_store);

    Org__E2eelab__Skissm__Proto__E2eeAccount *b_account = create_account();
    register_user_response_handler_store.account = b_account;
    send_register_user_request(b_account, &register_user_response_handler_store);

    // Alice sends an encrypted message to Bob, and Bob decrypts the message
    uint8_t plaintext[] = "This message will be sent a lot of times.";
    size_t plaintext_len = sizeof(plaintext) - 1;
    int i;
    for (i = 0; i < 1000; i++){
        test_encryption(a_account->address, b_account->address, plaintext, plaintext_len);
    }

    org__e2eelab__skissm__proto__e2ee_account__free_unpacked(a_account, NULL);
    org__e2eelab__skissm__proto__e2ee_account__free_unpacked(b_account, NULL);

    // test stop
    tear_down();
}

int main() {
    test_basic_session();
    test_interaction();
    test_continual_messages();

    return 0;
}
