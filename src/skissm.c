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
#include "skissm/skissm.h"

#include <stdarg.h>
#include <stdio.h>

#include "skissm/account.h"
#include "skissm/mem_util.h"

extern struct digital_signature_suite_t E2EE_CURVE25519_SIGN;
extern struct digital_signature_suite_t E2EE_DILITHIUM2;
extern struct digital_signature_suite_t E2EE_DILITHIUM3;
extern struct digital_signature_suite_t E2EE_DILITHIUM5;
extern struct digital_signature_suite_t E2EE_FALCON512;
extern struct digital_signature_suite_t E2EE_FALCON1024;
extern struct digital_signature_suite_t E2EE_SPHINCS_SHA2_128F;
extern struct digital_signature_suite_t E2EE_SPHINCS_SHA2_128S;
extern struct digital_signature_suite_t E2EE_SPHINCS_SHA2_192F;
extern struct digital_signature_suite_t E2EE_SPHINCS_SHA2_192S;
extern struct digital_signature_suite_t E2EE_SPHINCS_SHA2_256F;
extern struct digital_signature_suite_t E2EE_SPHINCS_SHA2_256S;
extern struct digital_signature_suite_t E2EE_SPHINCS_SHAKE_128F;
extern struct digital_signature_suite_t E2EE_SPHINCS_SHAKE_128S;
extern struct digital_signature_suite_t E2EE_SPHINCS_SHAKE_192F;
extern struct digital_signature_suite_t E2EE_SPHINCS_SHAKE_192S;
extern struct digital_signature_suite_t E2EE_SPHINCS_SHAKE_256F;
extern struct digital_signature_suite_t E2EE_SPHINCS_SHAKE_256S;
extern struct kem_suite_t E2EE_CURVE25519_ECDH;
extern struct kem_suite_t E2EE_HQC128;
extern struct kem_suite_t E2EE_HQC192;
extern struct kem_suite_t E2EE_HQC256;
extern struct kem_suite_t E2EE_KYBER512;
extern struct kem_suite_t E2EE_KYBER768;
extern struct kem_suite_t E2EE_KYBER1024;
extern struct kem_suite_t E2EE_MCELIECE348864;
extern struct kem_suite_t E2EE_MCELIECE348864F;
extern struct kem_suite_t E2EE_MCELIECE460896;
extern struct kem_suite_t E2EE_MCELIECE460896F;
extern struct kem_suite_t E2EE_MCELIECE6688128;
extern struct kem_suite_t E2EE_MCELIECE6688128F;
extern struct kem_suite_t E2EE_MCELIECE6960119;
extern struct kem_suite_t E2EE_MCELIECE6960119F;
extern struct kem_suite_t E2EE_MCELIECE8192128;
extern struct kem_suite_t E2EE_MCELIECE8192128F;
extern struct symmetric_encryption_suite_t E2EE_AES256_SHA256;

cipher_suite_t E2EE_CIPHER_SUITE = {NULL, NULL, NULL};

e2ee_pack_t E2EE_PACK = {NULL, NULL};

extern struct session_suite_t E2EE_SESSION_ECC;
extern struct session_suite_t E2EE_SESSION_PQC;

static skissm_plugin_t *skissm_plugin;

void skissm_begin(skissm_plugin_t *ssm_plugin) {
    skissm_plugin = ssm_plugin;
    account_begin();
}

void skissm_end() {
    skissm_plugin = NULL;
    account_end();
}

skissm_plugin_t *get_skissm_plugin() { return skissm_plugin; }

void ssm_notify_log(Skissm__E2eeAddress *user_address, LogCode log_code, const char *msg_fmt, ...) {
    if (skissm_plugin != NULL) {
        char msg[256] = {0};
        va_list arg;
        va_start(arg, msg_fmt);
        vsnprintf(msg, 256, msg_fmt, arg);
        va_end(arg);
        skissm_plugin->event_handler.on_log(user_address, log_code, msg);
    }
}

void ssm_notify_user_registered(Skissm__Account *account) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_user_registered(account);
}

void ssm_notify_inbound_session_invited(Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *from) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_inbound_session_invited(user_address, from);
}

void ssm_notify_inbound_session_ready(Skissm__E2eeAddress *user_address, Skissm__Session *inbound_session) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_inbound_session_ready(user_address, inbound_session);
}

void ssm_notify_outbound_session_ready(Skissm__E2eeAddress *user_address, Skissm__Session *outbound_session) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_outbound_session_ready(user_address, outbound_session);
}

void ssm_notify_one2one_msg(
    Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_one2one_msg_received(user_address, from_address, to_address, plaintext, plaintext_len);
}

void ssm_notify_other_device_msg(
    Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_other_device_msg_received(user_address, from_address, to_address, plaintext, plaintext_len);
}

void ssm_notify_group_msg(
    Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *group_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_group_msg_received(user_address, from_address, group_address, plaintext, plaintext_len);
}

void ssm_notify_group_created(Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *group_address, const char *group_name) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_group_created(user_address, group_address, group_name);
}

void ssm_notify_group_members_added(
    Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *group_address, const char *group_name,
    Skissm__GroupMember **adding_group_members, size_t adding_group_members_num
) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_group_members_added(user_address, group_address, group_name, adding_group_members, adding_group_members_num);
}

void ssm_notify_group_members_removed(
    Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *group_address, const char *group_name,
    Skissm__GroupMember **removing_group_members, size_t removing_group_members_num
) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_group_members_removed(user_address, group_address, group_name, removing_group_members, removing_group_members_num);
}

digital_signature_suite_t *get_digital_signature_suite(unsigned id) {
    if (id == E2EE_PACK_ID_DIGITAL_SIGNATURE_CURVE25519) {
        return &E2EE_CURVE25519_SIGN;
    } else if (id == E2EE_PACK_ID_DIGITAL_SIGNATURE_DILITHIUM2) {
        return &E2EE_DILITHIUM2;
    } else if (id == E2EE_PACK_ID_DIGITAL_SIGNATURE_DILITHIUM3) {
        return &E2EE_DILITHIUM3;
    } else if (id == E2EE_PACK_ID_DIGITAL_SIGNATURE_DILITHIUM5) {
        return &E2EE_DILITHIUM5;
    } else if (id == E2EE_PACK_ID_DIGITAL_SIGNATURE_FALCON512) {
        return &E2EE_FALCON512;
    } else if (id == E2EE_PACK_ID_DIGITAL_SIGNATURE_FALCON1024) {
        return &E2EE_FALCON1024;
    } else if (id == E2EE_PACK_ID_DIGITAL_SIGNATURE_SPHINCS_SHA2_128F) {
        return &E2EE_SPHINCS_SHA2_128F;
    } else if (id == E2EE_PACK_ID_DIGITAL_SIGNATURE_SPHINCS_SHA2_128S) {
        return &E2EE_SPHINCS_SHA2_128S;
    } else if (id == E2EE_PACK_ID_DIGITAL_SIGNATURE_SPHINCS_SHA2_192F) {
        return &E2EE_SPHINCS_SHA2_192F;
    } else if (id == E2EE_PACK_ID_DIGITAL_SIGNATURE_SPHINCS_SHA2_192S) {
        return &E2EE_SPHINCS_SHA2_192S;
    } else if (id == E2EE_PACK_ID_DIGITAL_SIGNATURE_SPHINCS_SHA2_256F) {
        return &E2EE_SPHINCS_SHA2_256F;
    } else if (id == E2EE_PACK_ID_DIGITAL_SIGNATURE_SPHINCS_SHA2_256S) {
        return &E2EE_SPHINCS_SHA2_256S;
    } else if (id == E2EE_PACK_ID_DIGITAL_SIGNATURE_SPHINCS_SHAKE_128F) {
        return &E2EE_SPHINCS_SHAKE_128F;
    } else if (id == E2EE_PACK_ID_DIGITAL_SIGNATURE_SPHINCS_SHAKE_128S) {
        return &E2EE_SPHINCS_SHAKE_128S;
    } else if (id == E2EE_PACK_ID_DIGITAL_SIGNATURE_SPHINCS_SHAKE_192F) {
        return &E2EE_SPHINCS_SHAKE_192F;
    } else if (id == E2EE_PACK_ID_DIGITAL_SIGNATURE_SPHINCS_SHAKE_192S) {
        return &E2EE_SPHINCS_SHAKE_192S;
    } else if (id == E2EE_PACK_ID_DIGITAL_SIGNATURE_SPHINCS_SHAKE_256F) {
        return &E2EE_SPHINCS_SHAKE_256F;
    } else if (id == E2EE_PACK_ID_DIGITAL_SIGNATURE_SPHINCS_SHAKE_256S) {
        return &E2EE_SPHINCS_SHAKE_256S;
    } else {
        return NULL;
    }
}

kem_suite_t *get_kem_suite(unsigned id) {
    if (id == E2EE_PACK_ID_KEM_CURVE25519) {
        return &E2EE_CURVE25519_ECDH;
    } else if (id == E2EE_PACK_ID_KEM_HQC128) {
        return &E2EE_HQC128;
    } else if (id == E2EE_PACK_ID_KEM_HQC192) {
        return &E2EE_HQC192;
    } else if (id == E2EE_PACK_ID_KEM_HQC256) {
        return &E2EE_HQC256;
    } else if (id == E2EE_PACK_ID_KEM_KYBER512) {
        return &E2EE_KYBER512;
    } else if (id == E2EE_PACK_ID_KEM_KYBER768) {
        return &E2EE_KYBER768;
    } else if (id == E2EE_PACK_ID_KEM_KYBER1024) {
        return &E2EE_KYBER1024;
    } else if (id == E2EE_PACK_ID_KEM_MCELIECE348864) {
        return &E2EE_MCELIECE348864;
    } else if (id == E2EE_PACK_ID_KEM_MCELIECE348864F) {
        return &E2EE_MCELIECE348864F;
    } else if (id == E2EE_PACK_ID_KEM_MCELIECE460896) {
        return &E2EE_MCELIECE460896;
    } else if (id == E2EE_PACK_ID_KEM_MCELIECE460896) {
        return &E2EE_MCELIECE460896F;
    } else if (id == E2EE_PACK_ID_KEM_MCELIECE6688128) {
        return &E2EE_MCELIECE6688128;
    } else if (id == E2EE_PACK_ID_KEM_MCELIECE6688128F) {
        return &E2EE_MCELIECE6688128F;
    } else if (id == E2EE_PACK_ID_KEM_MCELIECE6960119) {
        return &E2EE_MCELIECE6960119;
    } else if (id == E2EE_PACK_ID_KEM_MCELIECE6960119F) {
        return &E2EE_MCELIECE6960119F;
    } else if (id == E2EE_PACK_ID_KEM_MCELIECE8192128) {
        return &E2EE_MCELIECE8192128;
    } else if (id == E2EE_PACK_ID_KEM_MCELIECE8192128F) {
        return &E2EE_MCELIECE8192128F;
    } else {
        return NULL;
    }
}

symmetric_encryption_suite_t *get_symmetric_encryption_suite(unsigned id) {
    if (id == E2EE_PACK_ID_SYMMETRIC_ENCRYPTION_AES256_SHA256) {
        return &E2EE_AES256_SHA256;
    } else {
        return NULL;
    }
}

cipher_suite_t *get_cipher_suite(e2ee_pack_number *e2ee_pack_number_id) {
    E2EE_CIPHER_SUITE.digital_signature_suite = get_digital_signature_suite(e2ee_pack_number_id->digital_signature);
    E2EE_CIPHER_SUITE.kem_suite = get_kem_suite(e2ee_pack_number_id->kem);
    E2EE_CIPHER_SUITE.symmetric_encryption_suite = get_symmetric_encryption_suite(e2ee_pack_number_id->symmetric_encryption);

    return &E2EE_CIPHER_SUITE;
}

e2ee_pack_t *get_e2ee_pack(uint32_t e2ee_pack_id) {
    e2ee_pack_number *e2ee_pack_number_id = uint32_to_e2ee_pack_number(e2ee_pack_id);

    E2EE_PACK.cipher_suite = get_cipher_suite(e2ee_pack_number_id);
    if (e2ee_pack_number_id->kem != E2EE_PACK_ID_KEM_CURVE25519) {
        E2EE_PACK.session_suite = &E2EE_SESSION_PQC;
    } else {
        E2EE_PACK.session_suite = &E2EE_SESSION_ECC;
    }

    // release
    free_mem((void **)&e2ee_pack_number_id, sizeof(e2ee_pack_number));

    return &E2EE_PACK;
}
