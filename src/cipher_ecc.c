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
#include "e2ees/cipher.h"

#include <stdbool.h>
#include <string.h>

#include "e2ees/crypto.h"

// digital signature

struct ds_suite_t E2EES_CURVE25519_SIGN = {
    get_curve25519_sign_param,
    CURVE25519_crypto_sign_keypair,
    CURVE25519_crypto_sign_signature,
    CURVE25519_crypto_sign_verify
};

// kem

struct kem_suite_t E2EES_CURVE25519_ECDH = {
    get_curve25519_ECDH_param,
    CURVE25519_crypto_keypair,
    NULL,
    crypto_curve25519_dh
};
