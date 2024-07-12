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
#ifndef ACCOUNT_CACHE_H_
#define ACCOUNT_CACHE_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm/skissm.h"

typedef struct account_cacheer {
    char *version;
    uint32_t e2ee_pack_id;
    Skissm__E2eeAddress *address;
    Skissm__IdentityKey *identity_key;
    Skissm__SignedPreKey *signed_pre_key;
    ProtobufCBinaryData server_public_key;
    struct account_cacheer *next;
} account_cacheer;

void store_account_into_cache(Skissm__Account *account);

void load_version_from_cache(char **version_out, Skissm__E2eeAddress *address);

void load_e2ee_pack_id_from_cache(uint32_t *e2ee_pack_id_out, Skissm__E2eeAddress *address);

void load_identity_key_from_cache(Skissm__IdentityKey **identity_key_out, Skissm__E2eeAddress *address);

void load_signed_pre_key_from_cache(Skissm__SignedPreKey **signed_pre_key_out, Skissm__E2eeAddress *address);

void load_server_public_key_from_cache(ProtobufCBinaryData *server_public_key, Skissm__E2eeAddress *address);

void free_account_cacheer_list();

#ifdef __cplusplus
}
#endif

#endif /* ACCOUNT_CACHE_H_ */
