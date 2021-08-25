#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "skissm.h"
#include "e2ee_protocol.h"
#include "account.h"
#include "crypto.h"
#include "mem_util.h"
#include "session.h"
#include "group_session.h"

#include "test_env.h"

// -----------------
#include "test_db.h"
#include "test_env.h"
#include "test_util.h"

static const char DOMAIN[] = "e2eelab.org";

void test_find_session()
{
    setup();

    // create session and two addresses
    Org__E2eelab__Skissm__Proto__E2eeSession *session = (Org__E2eelab__Skissm__Proto__E2eeSession *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeSession));
    Org__E2eelab__Skissm__Proto__E2eeAddress *from, *to;
    mock_address(&from, "alice", "alice's domain", "alice's device");
    mock_address(&to, "bob", "bob's domain", "bob's device");
    initialise_session(session, from, to);
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

    session->session_id.len = 32;
    session->session_id.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->session_id.data, "01234567890123456789012345678901", 32);

    // insert to the db
    store_session(session);

    // load_outbound_session
    Org__E2eelab__Skissm__Proto__E2eeSession *session_copy;
    load_outbound_session(from, to, &session_copy);

    // assert session equals to session_copy
    print_result("test_find_session", is_equal_session(session, session_copy));

    // free
    org__e2eelab__skissm__proto__e2ee_address__free_unpacked(from, NULL);
    org__e2eelab__skissm__proto__e2ee_address__free_unpacked(to, NULL);
    org__e2eelab__skissm__proto__e2ee_session__free_unpacked(session, NULL);
    org__e2eelab__skissm__proto__e2ee_session__free_unpacked(session_copy, NULL);

    tear_down();
}

void test_load_session()
{
    setup();

    // create session and two addresses
    Org__E2eelab__Skissm__Proto__E2eeSession *session = (Org__E2eelab__Skissm__Proto__E2eeSession *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeSession));
    org__e2eelab__skissm__proto__e2ee_session__init(session);
    
    Org__E2eelab__Skissm__Proto__E2eeAddress *from, *to;
    mock_address(&from, "alice", "alice's domain", "alice's device");
    mock_address(&to, "bob", "bob's domain", "bob's device");
    initialise_session(session, from, to);
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

    session->session_id.len = 32;
    session->session_id.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(session->session_id.data, "01234567890123456789012345678901", 32);

    // insert to the db
    store_session(session);

    // load_inbound_session
    Org__E2eelab__Skissm__Proto__E2eeSession *session_copy;
    load_inbound_session(session->session_id, to, &session_copy);

    // assert session equals to session_copy
    print_result("test_load_session", is_equal_session(session, session_copy));

    // free
    org__e2eelab__skissm__proto__e2ee_address__free_unpacked(from, NULL);
    org__e2eelab__skissm__proto__e2ee_address__free_unpacked(to, NULL);
    org__e2eelab__skissm__proto__e2ee_session__free_unpacked(session, NULL);
    org__e2eelab__skissm__proto__e2ee_session__free_unpacked(session_copy, NULL);

    tear_down();
}

void test_load_outbound_group_session()
{
    setup();

    // create two addresses
    Org__E2eelab__Skissm__Proto__E2eeAddress *Alice, *Bob;
    mock_address(&Alice, "alice", "alice's domain", "alice's device");
    mock_address(&Bob, "bob", "bob's domain", "bob's device");

    // create member_addresses
    Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses = (Org__E2eelab__Skissm__Proto__E2eeAddress **) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAddress *) * 2);
    copy_address_from_address(&(member_addresses[0]), Alice);
    copy_address_from_address(&(member_addresses[1]), Bob);

    // mock group address
    Org__E2eelab__Skissm__Proto__E2eeAddress *group_address = (Org__E2eelab__Skissm__Proto__E2eeAddress *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAddress));
    org__e2eelab__skissm__proto__e2ee_address__init(group_address);
    group_address->domain.len = sizeof(DOMAIN);
    group_address->domain.data = (uint8_t *) malloc(sizeof(uint8_t) * sizeof(DOMAIN));
    memcpy(group_address->domain.data, DOMAIN, sizeof(DOMAIN));
    group_address->group_id.len = 32;
    group_address->group_id.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    ssm_handler.handle_rg(group_address->group_id.data, 32);

    // create outbound group session
    Org__E2eelab__Skissm__Proto__E2eeGroupSession *group_session = (Org__E2eelab__Skissm__Proto__E2eeGroupSession *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeGroupSession));
    org__e2eelab__skissm__proto__e2ee_group_session__init(group_session);

    group_session->version = PROTOCOL_VERSION;

    copy_address_from_address(&(group_session->session_owner), Alice);

    copy_address_from_address(&(group_session->group_address), group_address);

    group_session->session_id.len = 32;
    group_session->session_id.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(group_session->session_id.data, "01234567890123456789012345678901", 32);

    group_session->n_member_addresses = 2;

    copy_member_addresses_from_member_addresses(&(group_session->member_addresses), (const Org__E2eelab__Skissm__Proto__E2eeAddress **)member_addresses, 2);

    group_session->sequence = 0;

    group_session->chain_key.len = 32;
    group_session->chain_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(group_session->chain_key.data, "01234567890123456789012345678901", 32);

    group_session->signature_private_key.len = 32;
    group_session->signature_private_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(group_session->signature_private_key.data, "01234567890123456789012345678901", 32);

    crypto_curve25519_generate_public_key(&(group_session->signature_public_key), &(group_session->signature_private_key));

    group_session->associated_data.len = AD_LENGTH;
    group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * AD_LENGTH);
    memcpy(group_session->associated_data.data, group_session->chain_key.data, 32);
    memcpy((group_session->associated_data.data) + 32, group_session->signature_public_key.data, CURVE25519_KEY_LENGTH);

    // insert to the db
    store_group_session(group_session);

    // load_outbound_group_session
    Org__E2eelab__Skissm__Proto__E2eeGroupSession *group_session_copy;
    load_outbound_group_session(Alice, group_address, &group_session_copy);

    // assert session equals to session_copy
    print_result("test_load_outbound_group_session", is_equal_group_session(group_session, group_session_copy));

    // free
    org__e2eelab__skissm__proto__e2ee_address__free_unpacked(Alice, NULL);
    org__e2eelab__skissm__proto__e2ee_address__free_unpacked(Bob, NULL);
    free(member_addresses);
    org__e2eelab__skissm__proto__e2ee_address__free_unpacked(group_address, NULL);
    org__e2eelab__skissm__proto__e2ee_group_session__free_unpacked(group_session, NULL);
    org__e2eelab__skissm__proto__e2ee_group_session__free_unpacked(group_session_copy, NULL);

    tear_down();
}

void test_load_inbound_group_session()
{
    setup();

    // create two addresses
    Org__E2eelab__Skissm__Proto__E2eeAddress *Alice, *Bob;
    mock_address(&Alice, "alice", DOMAIN, "alice's device");
    mock_address(&Bob, "bob", DOMAIN, "bob's device");

    // create member_addresses
    Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses = (Org__E2eelab__Skissm__Proto__E2eeAddress **) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAddress *) * 2);
    copy_address_from_address(&(member_addresses[0]), Alice);
    copy_address_from_address(&(member_addresses[1]), Bob);

    // mock group address
    Org__E2eelab__Skissm__Proto__E2eeAddress *group_address = (Org__E2eelab__Skissm__Proto__E2eeAddress *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAddress));
    org__e2eelab__skissm__proto__e2ee_address__init(group_address);
    group_address->domain.len = sizeof(DOMAIN);
    group_address->domain.data = (uint8_t *) malloc(sizeof(uint8_t) * sizeof(DOMAIN));
    memcpy(group_address->domain.data, DOMAIN, sizeof(DOMAIN));
    group_address->group_id.len = 32;
    group_address->group_id.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    ssm_handler.handle_rg(group_address->group_id.data, 32);

    // create inbound group session
    Org__E2eelab__Skissm__Proto__E2eeGroupSession *group_session = (Org__E2eelab__Skissm__Proto__E2eeGroupSession *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeGroupSession));
    org__e2eelab__skissm__proto__e2ee_group_session__init(group_session);

    group_session->version = PROTOCOL_VERSION;

    copy_address_from_address(&(group_session->session_owner), Alice);

    copy_address_from_address(&(group_session->group_address), group_address);

    group_session->session_id.len = 32;
    group_session->session_id.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(group_session->session_id.data, "01234567890123456789012345678901", 32);

    group_session->n_member_addresses = 2;

    copy_member_addresses_from_member_addresses(&(group_session->member_addresses), (const Org__E2eelab__Skissm__Proto__E2eeAddress **)member_addresses, 2);

    group_session->sequence = 0;

    group_session->chain_key.len = 32;
    group_session->chain_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(group_session->chain_key.data, "01234567890123456789012345678901", 32);

    group_session->signature_private_key.len = 32;
    group_session->signature_private_key.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    memcpy(group_session->signature_private_key.data, "01234567890123456789012345678901", 32);

    crypto_curve25519_generate_public_key(&(group_session->signature_public_key), &(group_session->signature_private_key));

    group_session->associated_data.len = AD_LENGTH;
    group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * AD_LENGTH);
    memcpy(group_session->associated_data.data, group_session->chain_key.data, 32);
    memcpy((group_session->associated_data.data) + 32, group_session->signature_public_key.data, CURVE25519_KEY_LENGTH);

    // insert to the db
    store_group_session(group_session);

    // load_inbound_group_session for owner: Alice
    Org__E2eelab__Skissm__Proto__E2eeGroupSession *group_session_copy = NULL;
    load_inbound_group_session(group_session->session_id, Alice, &group_session_copy);

    // assert session equals to session_copy
    print_result("test_load_inbound_group_session", is_equal_group_session(group_session, group_session_copy));

    // free
    org__e2eelab__skissm__proto__e2ee_address__free_unpacked(Alice, NULL);
    org__e2eelab__skissm__proto__e2ee_address__free_unpacked(Bob, NULL);
    free(member_addresses);
    org__e2eelab__skissm__proto__e2ee_address__free_unpacked(group_address, NULL);
    org__e2eelab__skissm__proto__e2ee_group_session__free_unpacked(group_session, NULL);
    org__e2eelab__skissm__proto__e2ee_group_session__free_unpacked(group_session_copy, NULL);

    tear_down();
}

int main(){
    test_find_session();
    test_load_session();
    test_load_outbound_group_session();
    test_load_inbound_group_session();
    return 0;
}
