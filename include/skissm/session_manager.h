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
#ifndef SESSION_MANAGER_H_
#define SESSION_MANAGER_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm.h"

Skissm__GetPreKeyBundleRequestPayload *produce_get_pre_key_bundle_request_payload(Skissm__E2eeAddress *e2ee_address);

void consume_get_pre_key_bundle_response_payload(
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to,
    uint8_t *context,
    size_t context_len,
    Skissm__GetPreKeyBundleResponsePayload *get_pre_key_bundle_response_payload);

#ifdef __cplusplus
}
#endif

#endif /* SESSION_MANAGER_H_ */
