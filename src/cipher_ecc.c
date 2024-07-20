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
#include "skissm/cipher.h"

#include <stdbool.h>
#include <string.h>

#include "skissm/crypto.h"

// digital signature

struct digital_signature_suite_t E2EE_CURVE25519_SIGN = {
    get_curve25519_sign_param,
    CURVE25519_crypto_sign_keypair,
    CURVE25519_crypto_sign_signature,
    CURVE25519_crypto_sign_verify
};

// kem

struct kem_suite_t E2EE_CURVE25519_ECDH = {
    get_curve25519_ECDH_param,
    CURVE25519_crypto_keypair,
    NULL,
    crypto_curve25519_dh
};
