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

void test_unload_inbound_group_session(){
    setup();

    // create two addresses
    Org__E2eelab__Skissm__Proto__E2eeAddress *Alice, *Bob;
    mock_address(&Alice, "alice", E2EELAB_DOMAIN, "alice's device");
    mock_address(&Bob, "bob", E2EELAB_DOMAIN, "bob's device");

    // create member_addresses
    Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses = (Org__E2eelab__Skissm__Proto__E2eeAddress **) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAddress *) * 2);
    copy_address_from_address(&(member_addresses[0]), Alice);
    copy_address_from_address(&(member_addresses[1]), Bob);

    // mock group address
    Org__E2eelab__Skissm__Proto__E2eeAddress *group_address = (Org__E2eelab__Skissm__Proto__E2eeAddress *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAddress));
    org__e2eelab__skissm__proto__e2ee_address__init(group_address);
    create_domain(&(group_address->domain));
    random_id(&(group_address->group_id), 32);

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

    // unload the group session
    unload_inbound_group_session(Alice, &(group_session->session_id));

    // try to load the unloaded group session
    Org__E2eelab__Skissm__Proto__E2eeGroupSession *group_session_copy = NULL;
    load_inbound_group_session(group_session->session_id, Alice, &group_session_copy);

    // assert group_session_copy is NULL
    print_result("test_unload_inbound_group_session", (group_session_copy == NULL));

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
    test_unload_inbound_group_session();
    return 0;
}
