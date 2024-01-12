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

#include "PQClean/src/crypto_kem/hqc-128/clean/api.h"
#include "PQClean/src/crypto_kem/hqc-192/clean/api.h"
#include "PQClean/src/crypto_kem/hqc-256/clean/api.h"
#include "PQClean/src/crypto_kem/kyber512/clean/api.h"
#include "PQClean/src/crypto_kem/kyber768/clean/api.h"
#include "PQClean/src/crypto_kem/kyber1024/clean/api.h"
#include "PQClean/src/crypto_kem/mceliece348864/clean/api.h"
#include "PQClean/src/crypto_kem/mceliece348864f/clean/api.h"
#include "PQClean/src/crypto_kem/mceliece460896/clean/api.h"
#include "PQClean/src/crypto_kem/mceliece460896f/clean/api.h"
#include "PQClean/src/crypto_kem/mceliece6688128/clean/api.h"
#include "PQClean/src/crypto_kem/mceliece6688128f/clean/api.h"
#include "PQClean/src/crypto_kem/mceliece6960119/clean/api.h"
#include "PQClean/src/crypto_kem/mceliece6960119f/clean/api.h"
#include "PQClean/src/crypto_kem/mceliece8192128/clean/api.h"
#include "PQClean/src/crypto_kem/mceliece8192128f/clean/api.h"
#include "PQClean/src/crypto_sign/dilithium2/clean/api.h"
#include "PQClean/src/crypto_sign/dilithium3/clean/api.h"
#include "PQClean/src/crypto_sign/dilithium5/clean/api.h"
#include "PQClean/src/crypto_sign/falcon-512/clean/api.h"
#include "PQClean/src/crypto_sign/falcon-1024/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-sha2-128f-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-sha2-128s-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-sha2-192f-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-sha2-192s-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-sha2-256f-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-sha2-256s-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-shake-128f-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-shake-128s-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-shake-192f-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-shake-192s-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-shake-256f-simple/clean/api.h"
#include "PQClean/src/crypto_sign/sphincs-shake-256s-simple/clean/api.h"


// digital signature

struct digital_signature_suite_t E2EE_DILITHIUM2 = {
    get_dilithium2_param,
    crypto_dilithium2_generate_key_pair,
    PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature,
    PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify
};

struct digital_signature_suite_t E2EE_DILITHIUM3 = {
    get_dilithium3_param,
    crypto_dilithium3_generate_key_pair,
    PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_signature,
    PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_verify
};

struct digital_signature_suite_t E2EE_DILITHIUM5 = {
    get_dilithium5_param,
    crypto_dilithium5_generate_key_pair,
    PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_signature,
    PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_verify
};

struct digital_signature_suite_t E2EE_FALCON512 = {
    get_falcon512_param,
    crypto_falcon512_generate_key_pair,
    PQCLEAN_FALCON512_CLEAN_crypto_sign_signature,
    PQCLEAN_FALCON512_CLEAN_crypto_sign_verify
};

struct digital_signature_suite_t E2EE_FALCON1024 = {
    get_falcon1024_param,
    crypto_falcon1024_generate_key_pair,
    PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature,
    PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify
};

struct digital_signature_suite_t E2EE_SPHINCS_SHA2_128F = {
    get_sphincs_sha2_128f_param,
    crypto_sphincs_sha2_128f_generate_key_pair,
    PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify
};

struct digital_signature_suite_t E2EE_SPHINCS_SHA2_128S = {
    get_sphincs_sha2_128s_param,
    crypto_sphincs_sha2_128s_generate_key_pair,
    PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_verify
};

struct digital_signature_suite_t E2EE_SPHINCS_SHA2_192F = {
    get_sphincs_sha2_192f_param,
    crypto_sphincs_sha2_192f_generate_key_pair,
    PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_verify
};

struct digital_signature_suite_t E2EE_SPHINCS_SHA2_192S = {
    get_sphincs_sha2_192s_param,
    crypto_sphincs_sha2_192s_generate_key_pair,
    PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_verify
};

struct digital_signature_suite_t E2EE_SPHINCS_SHA2_256F = {
    get_sphincs_sha2_256f_param,
    crypto_sphincs_sha2_256f_generate_key_pair,
    PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_verify
};

struct digital_signature_suite_t E2EE_SPHINCS_SHA2_256S = {
    get_sphincs_sha2_256s_param,
    crypto_sphincs_sha2_256s_generate_key_pair,
    PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_verify
};

struct digital_signature_suite_t E2EE_SPHINCS_SHAKE_128F = {
    get_sphincs_shake_128f_param,
    crypto_sphincs_shake_128f_generate_key_pair,
    PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_verify
};

struct digital_signature_suite_t E2EE_SPHINCS_SHAKE_128S = {
    get_sphincs_shake_128s_param,
    crypto_sphincs_shake_128s_generate_key_pair,
    PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_verify
};

struct digital_signature_suite_t E2EE_SPHINCS_SHAKE_192F = {
    get_sphincs_shake_192f_param,
    crypto_sphincs_shake_192f_generate_key_pair,
    PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_verify
};

struct digital_signature_suite_t E2EE_SPHINCS_SHAKE_192S = {
    get_sphincs_shake_192s_param,
    crypto_sphincs_shake_192s_generate_key_pair,
    PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_verify
};

struct digital_signature_suite_t E2EE_SPHINCS_SHAKE_256F = {
    get_sphincs_shake_256f_param,
    crypto_sphincs_shake_256f_generate_key_pair,
    PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_verify
};

struct digital_signature_suite_t E2EE_SPHINCS_SHAKE_256S = {
    get_sphincs_shake_256s_param,
    crypto_sphincs_shake_256s_generate_key_pair,
    PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_verify
};


// kem

struct kem_suite_t E2EE_HQC128 = {
    get_hqc128_param,
    crypto_hqc128_generate_key_pair,
    crypto_hqc128_shared_secret
};

struct kem_suite_t E2EE_HQC192 = {
    get_hqc192_param,
    crypto_hqc192_generate_key_pair,
    crypto_hqc192_shared_secret
};

struct kem_suite_t E2EE_HQC256 = {
    get_hqc256_param,
    crypto_hqc256_generate_key_pair,
    crypto_hqc256_shared_secret
};

struct kem_suite_t E2EE_KYBER512 = {
    get_kyber512_param,
    crypto_kyber512_generate_key_pair,
    crypto_kyber512_shared_secret
};

struct kem_suite_t E2EE_KYBER768 = {
    get_kyber768_param,
    crypto_kyber768_generate_key_pair,
    crypto_kyber768_shared_secret
};

struct kem_suite_t E2EE_KYBER1024 = {
    get_kyber1024_param,
    crypto_kyber1024_generate_key_pair,
    crypto_kyber1024_shared_secret
};

struct kem_suite_t E2EE_MCELIECE348864 = {
    get_mceliece348864_param,
    crypto_mceliece348864_generate_key_pair,
    crypto_mceliece348864_shared_secret
};

struct kem_suite_t E2EE_MCELIECE348864F = {
    get_mceliece348864f_param,
    crypto_mceliece348864f_generate_key_pair,
    crypto_mceliece348864f_shared_secret
};

struct kem_suite_t E2EE_MCELIECE460896 = {
    get_mceliece460896_param,
    crypto_mceliece460896_generate_key_pair,
    crypto_mceliece460896_shared_secret
};

struct kem_suite_t E2EE_MCELIECE460896F = {
    get_mceliece460896f_param,
    crypto_mceliece460896f_generate_key_pair,
    crypto_mceliece460896f_shared_secret
};

struct kem_suite_t E2EE_MCELIECE6688128 = {
    get_mceliece6688128_param,
    crypto_mceliece6688128_generate_key_pair,
    crypto_mceliece6688128_shared_secret
};

struct kem_suite_t E2EE_MCELIECE6688128F = {
    get_mceliece6688128f_param,
    crypto_mceliece6688128f_generate_key_pair,
    crypto_mceliece6688128f_shared_secret
};

struct kem_suite_t E2EE_MCELIECE6960119 = {
    get_mceliece6960119_param,
    crypto_mceliece6960119_generate_key_pair,
    crypto_mceliece6960119_shared_secret
};

struct kem_suite_t E2EE_MCELIECE6960119F = {
    get_mceliece6960119f_param,
    crypto_mceliece6960119f_generate_key_pair,
    crypto_mceliece6960119f_shared_secret
};

struct kem_suite_t E2EE_MCELIECE8192128 = {
    get_mceliece8192128_param,
    crypto_mceliece8192128_generate_key_pair,
    crypto_mceliece8192128_shared_secret
};

struct kem_suite_t E2EE_MCELIECE8192128F = {
    get_mceliece8192128f_param,
    crypto_mceliece8192128f_generate_key_pair,
    crypto_mceliece8192128f_shared_secret
};
