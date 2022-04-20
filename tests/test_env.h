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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "skissm/skissm.h"

#define E2EELAB_DOMAIN          "e2eelab.org"
#define TEST_E2EE_PACK_ID       0

extern const char *db_name;

void tear_up();
void tear_down();

char *create_domain_str();
void create_domain(ProtobufCBinaryData *domain);

void load_account(uint64_t account_id, Skissm__Account **account);
void load_account_by_address(Skissm__E2eeAddress *address, Skissm__Account **account);
void store_account(Skissm__Account *account);
#endif /* TEST_ENV_H_ */
