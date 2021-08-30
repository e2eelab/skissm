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
#ifndef TEST_ENV_H_
#define TEST_ENV_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "skissm.h"

extern const char *db_name;

void setup();
void tear_down();

void random_session_id(ProtobufCBinaryData *session_id);
void print_hex(char *title, uint8_t *msg, size_t msg_len);
void print_result(char *title, bool success);

void load_account(ProtobufCBinaryData *id, Org__E2eelab__Skissm__Proto__E2eeAccount **account);
void load_account_by_address(Org__E2eelab__Skissm__Proto__E2eeAddress *address_p, Org__E2eelab__Skissm__Proto__E2eeAccount **account_pp);
void store_account(Org__E2eelab__Skissm__Proto__E2eeAccount *account);
#endif /* TEST_ENV_H_ */
