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
#include "cipher.h"
#include "crypto.h"
#include "mem_util.h"

#include "test_env.h"

static void verify_one_time_pre_keys(Org__E2eelab__Skissm__Proto__E2eeAccount *account, unsigned int n_one_time_pre_keys) {
    unsigned int i;

    assert(account->n_one_time_pre_keys == n_one_time_pre_keys);

    for (i = 0; i < account->n_one_time_pre_keys; i++){
        assert(account->one_time_pre_keys[i]->opk_id == (i + 1));
        assert(account->one_time_pre_keys[i]->key_pair->private_key.data != NULL);
        assert(account->one_time_pre_keys[i]->key_pair->private_key.len == CURVE25519_KEY_LENGTH);
        assert(account->one_time_pre_keys[i]->key_pair->public_key.data != NULL);
        assert(account->one_time_pre_keys[i]->key_pair->public_key.len == CURVE25519_KEY_LENGTH);
    }
}

int main(){
    // test start
    setup();

    // Register test
    Org__E2eelab__Skissm__Proto__E2eeAccount *account = create_account();

    assert(account->identity_key_pair->private_key.len == CURVE25519_KEY_LENGTH);
    assert(account->identity_key_pair->public_key.len == CURVE25519_KEY_LENGTH);
    assert(account->signed_pre_key_pair->spk_id == 1);
    assert(account->signed_pre_key_pair->key_pair->private_key.len == CURVE25519_KEY_LENGTH);
    assert(account->signed_pre_key_pair->key_pair->public_key.len == CURVE25519_KEY_LENGTH);
    assert(account->signed_pre_key_pair->signature.len == CURVE_SIGNATURE_LENGTH);
    verify_one_time_pre_keys(account, 100);

    // Generate a new signed pre-key pair and a new signature
    generate_signed_pre_key(account);

    assert(account->signed_pre_key_pair->spk_id == 2);
    assert(account->signed_pre_key_pair->key_pair->private_key.len == CURVE25519_KEY_LENGTH);
    assert(account->signed_pre_key_pair->key_pair->public_key.len == CURVE25519_KEY_LENGTH);
    assert(account->signed_pre_key_pair->signature.len == CURVE_SIGNATURE_LENGTH);

    // Post some new one-time pre-keys test
    // Generate 80 one-time pre-key pairs
    Org__E2eelab__Skissm__Proto__OneTimePreKeyPair **output = generate_opks(80, account);

    verify_one_time_pre_keys(account, 180);

    // release
    org__e2eelab__skissm__proto__e2ee_account__free_unpacked(account, NULL);

    // test stop.
    tear_down();
    return 0;
}
