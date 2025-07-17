/*
 * Copyright © 2021 Academia Sinica. All Rights Reserved.
 *
 * This file is part of E2EE Security.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * E2EE Security is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with E2EE Security.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "e2ees/cipher.h"
#include "e2ees/crypto.h"
#include "e2ees/mem_util.h"

static crypto_hf_param_t sha256_param = {
    SHA256_OUTPUT_LENGTH,
};

static crypto_hf_param_t get_sha256_param() {
    return sha256_param;
}

// default hash function suite

const struct hf_suite_t E2EES_SHA256 = {
    get_sha256_param,
    crypto_hkdf_sha256,
    crypto_hmac_sha256,
    crypto_sha256
};