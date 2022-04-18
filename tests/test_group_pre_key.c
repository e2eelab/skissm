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
#include "skissm/group_session.h"
#include "skissm/mem_util.h"

#include "test_util.h"
#include "test_env.h"

/** length of a shared key */
#define GROUP_SHARED_KEY_LENGTH     CIPHER.suite1->get_crypto_param().hash_len

int main(){
    // test start
    setup();

    // mock address
    Skissm__E2eeAddress *user_address, *member_address;
    mock_address(&user_address, "alice", "alice's domain", "alice's device");
    mock_address(&member_address, "bob", "bob's domain", "bob's device");

    Skissm__E2eeAddress **member_addresses = (Skissm__E2eeAddress **)malloc(sizeof(Skissm__E2eeAddress *) * 2);
    copy_address_from_address(&(member_addresses[0]), user_address);
    copy_address_from_address(&(member_addresses[1]), member_address);

    int key_len = CIPHER.suite1->get_crypto_param().sign_key_len;
    size_t member_num = 2;

    // mock group address
    Skissm__E2eeAddress *group_address = (Skissm__E2eeAddress *) malloc(sizeof(Skissm__E2eeAddress));
    skissm__e2ee_address__init(group_address);
    group_address->domain = create_domain_str();
    group_address->group_id = generate_uuid_str();

    // create an outbound group session
    Skissm__E2eeGroupSession *outbound_group_session = (Skissm__E2eeGroupSession *) malloc(sizeof(Skissm__E2eeGroupSession));
    skissm__e2ee_group_session__init(outbound_group_session);

    outbound_group_session->version = PROTOCOL_VERSION;

    copy_address_from_address(&(outbound_group_session->session_owner), user_address);
    copy_address_from_address(&(outbound_group_session->group_address), group_address);

    outbound_group_session->session_id = generate_uuid_str();
    outbound_group_session->n_member_addresses = member_num;

    copy_member_addresses_from_member_addresses(&(outbound_group_session->member_addresses), (const Skissm__E2eeAddress **)member_addresses, member_num);

    outbound_group_session->sequence = 0;

    outbound_group_session->chain_key.len = GROUP_SHARED_KEY_LENGTH;
    outbound_group_session->chain_key.data = (uint8_t *) malloc(sizeof(uint8_t) * outbound_group_session->chain_key.len);
    get_skissm_plugin()->common_handler.handle_rg(outbound_group_session->chain_key.data, outbound_group_session->chain_key.len);

    CIPHER.suite1->sign_key_gen(&(outbound_group_session->signature_public_key), &(outbound_group_session->signature_private_key));

    int ad_len = 2 * key_len;
    outbound_group_session->associated_data.len = ad_len;
    outbound_group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * ad_len);
    memcpy(outbound_group_session->associated_data.data, outbound_group_session->signature_public_key.data, key_len);
    memcpy((outbound_group_session->associated_data.data) + key_len, outbound_group_session->signature_public_key.data, key_len);

    get_skissm_plugin()->db_handler.store_group_session(outbound_group_session);

    uint8_t *group_pre_key_plaintext = NULL;
    size_t group_pre_key_plaintext_len = pack_group_pre_key_plaintext(outbound_group_session, &group_pre_key_plaintext, NULL);

    // store group pre-key
    get_skissm_plugin()->db_handler.store_group_pre_key(outbound_group_session->member_addresses[1], group_pre_key_plaintext, group_pre_key_plaintext_len);

    // load group pre-key
    Skissm__E2eePlaintext **e2ee_plaintext;
    uint32_t n_e2ee_plaintext;
    n_e2ee_plaintext = get_skissm_plugin()->db_handler.load_group_pre_keys(member_address, &e2ee_plaintext);
    Skissm__E2eePlaintext *e2ee_plaintext_org = skissm__e2ee_plaintext__unpack(NULL, group_pre_key_plaintext_len, group_pre_key_plaintext);
    assert(e2ee_plaintext_org->payload.len == e2ee_plaintext[0]->payload.len);
    assert(memcmp(e2ee_plaintext_org->payload.data, e2ee_plaintext[0]->payload.data, e2ee_plaintext[0]->payload.len) == 0);

    // unload group pre-key
    get_skissm_plugin()->db_handler.unload_group_pre_key(member_address);
    Skissm__E2eePlaintext **e2ee_plaintext_null = NULL;
    get_skissm_plugin()->db_handler.load_group_pre_keys(member_address, &e2ee_plaintext_null);
    assert(e2ee_plaintext_null == NULL);

    // release
    skissm__e2ee_address__free_unpacked(user_address, NULL);
    skissm__e2ee_address__free_unpacked(member_address, NULL);
    skissm__e2ee_address__free_unpacked(group_address, NULL);
    skissm__e2ee_address__free_unpacked(member_addresses[0], NULL);
    skissm__e2ee_address__free_unpacked(member_addresses[1], NULL);
    free(member_addresses);
    skissm__e2ee_group_session__free_unpacked(outbound_group_session, NULL);

    // test stop
    tear_down();

    return 0;
}
