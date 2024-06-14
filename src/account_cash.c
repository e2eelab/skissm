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

#include "skissm/account_cash.h"

#include <string.h>

#include "skissm/mem_util.h"

account_casher *account_casher_list = NULL;

void store_account_into_cash(Skissm__Account *account) {
    if (account_casher_list == NULL) {
        account_casher_list = (account_casher *)malloc(sizeof(account_casher));
        account_casher_list->version = strdup(account->version);
        account_casher_list->e2ee_pack_id = account->e2ee_pack_id;
        copy_address_from_address(&(account_casher_list->address), account->address);
        copy_ik_from_ik(&(account_casher_list->identity_key), account->identity_key);
        copy_spk_from_spk(&(account_casher_list->signed_pre_key), account->signed_pre_key);
        account_casher_list->next = NULL;
    } else {
        account_casher *cur = account_casher_list;
        while (cur->next != NULL) {
            cur = cur->next;
        }
        cur->next = (account_casher *)malloc(sizeof(account_casher));
        cur->next->version = strdup(account->version);
        cur->next->e2ee_pack_id = account->e2ee_pack_id;
        copy_address_from_address(&(cur->next->address), account->address);
        copy_ik_from_ik(&(cur->next->identity_key), account->identity_key);
        copy_spk_from_spk(&(cur->next->signed_pre_key), account->signed_pre_key);
        cur->next->next = NULL;
    }
}

void load_version_from_cash(char **version_out, Skissm__E2eeAddress *address) {
    account_casher *cur = account_casher_list;
    while (cur != NULL) {
        if (compare_address(cur->address, address)) {
            *version_out = strdup(cur->version);
            return;
        }
        cur = cur->next;
    }
    *version_out = NULL;
}

void load_e2ee_pack_id_from_cash(uint32_t *e2ee_pack_id_out, Skissm__E2eeAddress *address) {
    account_casher *cur = account_casher_list;
    while (cur != NULL) {
        if (compare_address(cur->address, address)) {
            *e2ee_pack_id_out = cur->e2ee_pack_id;
            return;
        }
        cur = cur->next;
    }
    *e2ee_pack_id_out = 0;
}

void load_identity_key_from_cash(Skissm__IdentityKey **identity_key_out, Skissm__E2eeAddress *address) {
    account_casher *cur = account_casher_list;
    while (cur != NULL) {
        if (compare_address(cur->address, address)) {
            copy_ik_from_ik(identity_key_out, cur->identity_key);
            return;
        }
        cur = cur->next;
    }
    *identity_key_out = NULL;
}

void load_signed_pre_key_from_cash(Skissm__SignedPreKey **signed_pre_key_out, Skissm__E2eeAddress *address) {
    account_casher *cur = account_casher_list;
    while (cur != NULL) {
        if (compare_address(cur->address, address)) {
            copy_spk_from_spk(signed_pre_key_out, cur->signed_pre_key);
            return;
        }
        cur = cur->next;
    }
    *signed_pre_key_out = NULL;
}

void free_account_casher(account_casher *casher) {
    if (casher->version != NULL) {
        free(casher->version);
        casher->version = NULL;
    }
    casher->e2ee_pack_id = 0;
    if (casher->address != NULL) {
        skissm__e2ee_address__free_unpacked(casher->address, NULL);
        casher->address = NULL;
    }
    if (casher->identity_key != NULL) {
        skissm__identity_key__free_unpacked(casher->identity_key, NULL);
        casher->identity_key = NULL;
    }
    if (casher->signed_pre_key != NULL) {
        skissm__signed_pre_key__free_unpacked(casher->signed_pre_key, NULL);
        casher->signed_pre_key = NULL;
    }
    casher = NULL;
}

void free_account_casher_list() {
    account_casher *cur = account_casher_list;
    account_casher *temp;
    while (cur != NULL) {
        temp = cur;
        cur = cur->next;
        free_account_casher(temp);
    }
}
