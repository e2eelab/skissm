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

const struct cipher_suite E2EE_PQC_AES256_GCM_SHA256 = {
    NULL, // not determined yet(get param)
    NULL, // not determined yet(gen kem key)
    NULL, // not determined yet(gen sign key)
    NULL, // not determined yet(dh)
    aes256_gcm_encrypt,
    aes256_gcm_decrypt,
    NULL, // not determined yet(sign)
    NULL, // not determined yet(verify)
    crypto_hkdf_sha256,
    crypto_hmac_sha256,
    crypto_sha256
};
