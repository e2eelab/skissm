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

const struct cipher_suite_t E2EE_CIPHER_KYBER_SPHINCSPLUS_SHA256_256S_AES256_GCM_SHA256 = {
    get_kyber1024_sphincsplus_aes256_gcm_sha256_param,
    crypto_kyber1024_generate_key_pair,
    crypto_sphincsplus_shake256_generate_key_pair,
    crypto_kyber1024_shared_secret,
    aes256_gcm_encrypt,
    aes256_gcm_decrypt,
    crypto_sphincsplus_shake256_sign,
    crypto_sphincsplus_shake256_verify,
    crypto_hkdf_sha256,
    crypto_hmac_sha256,
    crypto_sha256
};
