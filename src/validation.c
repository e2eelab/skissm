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
#include "e2ees/validation.h"

///-----------------accuracy-----------------///
bool accurate_key_pair(E2ees__KeyPair *key_pair, uint32_t pub_key_len, uint32_t priv_key_len) {
    if (key_pair != NULL) {
        if (key_pair->public_key.len != pub_key_len) {
            return false;
        }
        if (key_pair->private_key.len != priv_key_len) {
            return false;
        }
    } else {
        return false;
    }
    return true;
}

///-----------------safe check-----------------///

bool is_valid_cipher_suite(const cipher_suite_t *cipher_suite) {
    if (cipher_suite != NULL) {
        if (cipher_suite->ds_suite != NULL) {
            if (cipher_suite->ds_suite->get_crypto_param == NULL)
                return false;
            if (cipher_suite->ds_suite->sign == NULL)
                return false;
            if (cipher_suite->ds_suite->sign_key_gen == NULL)
                return false;
            if (cipher_suite->ds_suite->verify == NULL)
                return false;
        } else {
            return false;
        }
        if (cipher_suite->kem_suite != NULL) {
            if (cipher_suite->kem_suite->asym_key_gen == NULL)
                return false;
            if (cipher_suite->kem_suite->get_crypto_param == NULL)
                return false;
            if (cipher_suite->kem_suite->encaps == NULL)
                return false;
            if (cipher_suite->kem_suite->decaps == NULL)
                return false;
        } else {
            return false;
        }
        if (cipher_suite->se_suite != NULL) {
            if (cipher_suite->se_suite->decrypt == NULL)
                return false;
            if (cipher_suite->se_suite->encrypt == NULL)
                return false;
            if (cipher_suite->se_suite->get_crypto_param == NULL)
                return false;
        } else {
            return false;
        }
        if (cipher_suite->hf_suite != NULL) {
            if (cipher_suite->hf_suite->hash == NULL)
                return false;
            if (cipher_suite->hf_suite->hkdf == NULL)
                return false;
            if (cipher_suite->hf_suite->hmac == NULL)
                return false;
        } else {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_e2ees_pack_id(uint32_t e2ees_pack_id) {
    cipher_suite_t *cipher_suite = get_e2ees_pack(e2ees_pack_id)->cipher_suite;

    return is_valid_cipher_suite(cipher_suite);
}

bool is_valid_protobuf(const ProtobufCBinaryData *src) {
    if (src != NULL) {
        if (src->len == 0 || src->data == NULL) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_protobuf_list(ProtobufCBinaryData *src, size_t len) {
    if (len > 0 && src == NULL)
        return false;
    if (len == 0 && src != NULL)
        return false;
    size_t i;
    for (i = 0; i < len; i++) {
        if (!is_valid_protobuf(&(src[i]))) {
            return false;
        }
    }

    return true;
}

bool is_valid_string(const char *src) {
    if (src != NULL) {
        if (src[0] == '\0') {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_string_list(char **src, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        if (!is_valid_string(src[i])) {
            return false;
        }
    }

    return true;
}

bool is_valid_address(E2ees__E2eeAddress *src) {
    if (src != NULL) {
        if (!is_valid_string(src->domain)) {
            return false;
        }
        if (src->peer_case == E2EES__E2EE_ADDRESS__PEER__NOT_SET) {
            return false;
        } else if (src->peer_case == E2EES__E2EE_ADDRESS__PEER_USER) {
            if (src->user != NULL) {
                // user_name is optional
                // if (!is_valid_string(src->user->user_name)) {
                //    return false;
                // }
                if (!is_valid_string(src->user->user_id)) {
                    return false;
                }
                if (!is_valid_string(src->user->device_id)) {
                    return false;
                }
            } else {
                return false;
            }
        } else if (src->peer_case == E2EES__E2EE_ADDRESS__PEER_GROUP) {
            if (src->group != NULL) {
                // group_name is optional
                // if (!is_valid_string(src->group->group_name)) {
                //     return false;
                // }
                if (!is_valid_string(src->group->group_id)) {
                    return false;
                }
            } else {
                return false;
            }
        } else {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_address_list(E2ees__E2eeAddress **src, size_t len) {
    if (len > 0 && src == NULL)
        return false;
    if (len == 0 && src != NULL)
        return false;
    size_t i;
    for (i = 0; i < len; i++) {
        if (!is_valid_address(src[i])) {
            return false;
        }
    }

    return true;
}

bool is_valid_key_pair(const E2ees__KeyPair *src) {
    if (src != NULL) {
        if (!is_valid_protobuf(&(src->private_key))) {
            return false;
        }
        if (!is_valid_protobuf(&(src->public_key))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_identity_key(E2ees__IdentityKey *src) {
    if (src != NULL) {
        if (!is_valid_key_pair(src->asym_key_pair)) {
            return false;
        }
        if (!is_valid_key_pair(src->sign_key_pair)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_signed_pre_key(E2ees__SignedPreKey *src) {
    if (src != NULL) {
        if (!is_valid_key_pair(src->key_pair)) {
            return false;
        }
        if (!is_valid_protobuf(&(src->signature))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_one_time_pre_key(E2ees__OneTimePreKey *src) {
    if (src != NULL) {
        if (!is_valid_key_pair(src->key_pair)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_one_time_pre_key_list(E2ees__OneTimePreKey **src, size_t len) {
    if (len > 0 && src == NULL)
        return false;
    if (len == 0 && src != NULL)
        return false;
    size_t i;
    for (i = 0; i < len; i++) {
        if (!is_valid_one_time_pre_key(src[i])) {
            return false;
        }
    }

    return true;
}

bool is_valid_unregistered_account(E2ees__Account *src) {
    if (src->version == NULL) {
        return false;
    }
    if (!is_valid_e2ees_pack_id(src->e2ees_pack_id)) {
        return false;
    }
    if (!is_valid_identity_key(src->identity_key)) {
        return false;
    }
    if (!is_valid_signed_pre_key(src->signed_pre_key)) {
        return false;
    }
    if (!is_valid_one_time_pre_key_list(src->one_time_pre_key_list, src->n_one_time_pre_key_list)) {
        return false;
    }
    // the address, password and auth should not be available in an unregistered account
    if (is_valid_address(src->address)) {
        return false;
    }
    if (is_valid_string(src->password)) {
        return false;
    }
    if (is_valid_string(src->auth)) {
        return false;
    }

    return true;
}

bool is_valid_registered_account(E2ees__Account *src) {
    if (src->version == NULL) {
        return false;
    }
    if (!is_valid_e2ees_pack_id(src->e2ees_pack_id)) {
        return false;
    }
    if (!is_valid_address(src->address)) {
        return false;
    }
    if (!is_valid_identity_key(src->identity_key)) {
        return false;
    }
    if (!is_valid_signed_pre_key(src->signed_pre_key)) {
        return false;
    }
    if (!is_valid_one_time_pre_key_list(src->one_time_pre_key_list, src->n_one_time_pre_key_list)) {
        return false;
    }
    if (!is_valid_string(src->password)) {
        return false;
    }
    if (!is_valid_string(src->auth)) {
        return false;
    }

    return true;
}

bool is_valid_msg_key(const E2ees__MsgKey *msg_key) {
    if (msg_key != NULL) {
        return is_valid_protobuf(&(msg_key->derived_key));
    } else {
        return false;
    }
}

bool is_valid_chain_key(const E2ees__ChainKey *chain_key) {
    if (chain_key != NULL) {
        return is_valid_protobuf(&(chain_key->shared_key));
    } else {
        return false;
    }
}

bool is_valid_sender_chain(E2ees__SenderChainNode *sender_chain) {
    if (sender_chain != NULL) {
        if (!is_valid_protobuf(&(sender_chain->our_ratchet_public_key))) {
            return false;
        }
        if (!is_valid_protobuf(&(sender_chain->their_ratchet_public_key))) {
            return false;
        }
        return is_valid_chain_key(sender_chain->chain_key);
    } else {
        return false;
    }
}

bool is_valid_receiver_chain(E2ees__ReceiverChainNode *receiver_chain) {
    if (receiver_chain != NULL) {
        if (!is_valid_protobuf(&(receiver_chain->our_ratchet_private_key))) {
            return false;
        }
        if (!is_valid_protobuf(&(receiver_chain->their_ratchet_public_key))) {
            return false;
        }
        return is_valid_chain_key(receiver_chain->chain_key);
    } else {
        return false;
    }
}

bool is_valid_skipped_msg_key_node(E2ees__SkippedMsgKeyNode *skipped_msg_key_node) {
    if (skipped_msg_key_node != NULL) {
        if (!is_valid_protobuf(&(skipped_msg_key_node->ratchet_key_public))) {
            return false;
        }
        return is_valid_msg_key(skipped_msg_key_node->msg_key);
    } else {
        return false;
    }
}

bool is_valid_skipped_msg_key_list(
    E2ees__SkippedMsgKeyNode **skipped_msg_key_list,
    size_t skipped_msg_key_list_len
) {
    if (skipped_msg_key_list_len == 0 && skipped_msg_key_list != NULL) {
        return false;
    }
    if (skipped_msg_key_list_len > 0 && skipped_msg_key_list == NULL) {
        return false;
    }
    size_t i;
    for (i = 0; i < skipped_msg_key_list_len; i++) {
        if (!is_valid_skipped_msg_key_node(skipped_msg_key_list[i])) {
            return false;
        }
    }

    return true;
}

bool is_valid_ratchet(const E2ees__Ratchet *ratchet) {
    if (ratchet != NULL) {
        if (!is_valid_protobuf(&(ratchet->root_key))) {
            return false;
        }
        if (!is_valid_sender_chain(ratchet->sender_chain)) {
            return false;
        }
        if (ratchet->root_sequence > 0) {
            if (!is_valid_receiver_chain(ratchet->receiver_chain)) {
                return false;
            }
        } else {
            // if the root sequence is equal to zero
            if (ratchet->receiver_chain != NULL) {
                if (!is_valid_protobuf(&(ratchet->receiver_chain->our_ratchet_private_key))) {
                    return false;
                }
            } else {
                return false;
            }
        }
        if (!is_valid_skipped_msg_key_list(ratchet->skipped_msg_key_list, ratchet->n_skipped_msg_key_list)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_uncompleted_session(E2ees__Session *src) {
    if (src != NULL) {
        if (!is_valid_string(src->version)) {
            return false;
        }
        if (!is_valid_e2ees_pack_id(src->e2ees_pack_id)) {
            return false;
        }
        if (!is_valid_string(src->session_id)) {
            return false;
        }
        if (!is_valid_address(src->our_address)) {
            return false;
        }
        if (!is_valid_address(src->their_address)) {
            return false;
        }
        if (is_valid_protobuf(&(src->temp_shared_secret))) {
            if (src->temp_shared_secret.data == NULL) {
                return false;
            }
        } else {
            return false;
        }
        if (is_valid_protobuf(&(src->fingerprint))) {
            if (src->fingerprint.data == NULL) {
                return false;
            }
        } else {
            return false;
        }
        if (!is_valid_key_pair(src->alice_base_key)) {
            return false;
        }
        if (!is_valid_protobuf_list(src->pre_shared_input_list, src->n_pre_shared_input_list)) {
            return false;
        }
        if (src->ratchet != NULL) {
            if (src->ratchet->sender_chain != NULL) {
                if (!is_valid_protobuf(&(src->ratchet->sender_chain->their_ratchet_public_key))) {
                    return false;
                }
            } else {
                return false;
            }
        } else {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_completed_session(E2ees__Session *src) {
    if (src != NULL) {
        if (!is_valid_string(src->version)) {
            return false;
        }
        if (!is_valid_e2ees_pack_id(src->e2ees_pack_id)) {
            return false;
        }
        if (!is_valid_string(src->session_id)) {
            return false;
        }
        if (!is_valid_address(src->our_address)) {
            return false;
        }
        if (!is_valid_address(src->their_address)) {
            return false;
        }
        if (!is_valid_ratchet(src->ratchet)) {
            return false;
        }
        if (!is_valid_protobuf(&(src->associated_data))) {
            return false;
        }
        if (!is_valid_protobuf(&(src->temp_shared_secret))) {
            return false;
        }
        if (!is_valid_protobuf(&(src->fingerprint))) {
            return false;
        }
        if (!is_valid_key_pair(src->alice_base_key)) {
            return false;
        }
        if (!is_valid_protobuf_list(src->pre_shared_input_list, src->n_pre_shared_input_list)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_identity_key_public(E2ees__IdentityKeyPublic *src) {
    if (src != NULL) {
        if (!is_valid_protobuf(&(src->asym_public_key))) {
            return false;
        }
        if (!is_valid_protobuf(&(src->sign_public_key))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_signed_pre_key_public(E2ees__SignedPreKeyPublic *src) {
    if (src != NULL) {
        if (!is_valid_protobuf(&(src->public_key))) {
            return false;
        }
        if (!is_valid_protobuf(&(src->signature))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_one_time_pre_key_public(E2ees__OneTimePreKeyPublic *src) {
    if (src != NULL) {
        if (!is_valid_protobuf(&(src->public_key))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_pre_key_bundle(E2ees__PreKeyBundle *src) {
    if (src != NULL) {
        if (!is_valid_address(src->user_address)) {
            return false;
        }
        if (!is_valid_identity_key_public(src->identity_key_public)) {
            return false;
        }
        if (!is_valid_signed_pre_key_public(src->signed_pre_key_public)) {
            return false;
        }
        // one_time_pre_key_public can be empty if it is out of stock
        // if (!is_valid_one_time_pre_key_public(src->one_time_pre_key_public)) {
        //    return false;
        // }
    } else {
        return false;
    }

    return true;
}

bool is_valid_pre_key_bundle_list(E2ees__PreKeyBundle **src, size_t len) {
    if (len > 0 && src == NULL)
        return false;
    if (len == 0 && src != NULL)
        return false;
    size_t i;
    for (i = 0; i < len; i++) {
        if (!is_valid_pre_key_bundle(src[i])) {
            return false;
        }
    }

    return true;
}

bool is_valid_one2one_msg_payload(const E2ees__One2oneMsgPayload *payload) {
    if (payload != NULL) {
        if (!is_valid_protobuf(&(payload->ratchet_key))) {
            // there is some wrong with the ratchet key data in the payload
            return false;
        }
        if (!is_valid_protobuf(&(payload->ciphertext))) {
            // there is some wrong with the ciphertext data in the payload
            return false;
        }
    } else {
        // the payload is NULL
        return false;
    }

    return true;
}

bool is_valid_group_member(E2ees__GroupMember *src) {
    if (src != NULL) {
        if (!is_valid_string(src->user_id)) {
            return false;
        }
        if (!is_valid_string(src->domain)) {
            return false;
        }
        if ((src->role != E2EES__GROUP_ROLE__GROUP_ROLE_MEMBER) &&
            (src->role != E2EES__GROUP_ROLE__GROUP_ROLE_MANAGER) &&
            (src->role != E2EES__GROUP_ROLE__GROUP_ROLE_PENDING_MEMBER) &&
            (src->role != E2EES__GROUP_ROLE__GROUP_ROLE_PENDING_MANAGER)
        ) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_group_member_list(E2ees__GroupMember **src, size_t len) {
    if (len > 0 && src == NULL)
        return false;
    if (len == 0 && src != NULL)
        return false;
    size_t i;
    for (i = 0; i < len; i++) {
        if (!is_valid_group_member(src[i])) {
            return false;
        }
    }

    return true;
}

bool is_valid_group_info(const E2ees__GroupInfo *src) {
    if (src != NULL) {
        if (!is_valid_string(src->group_name)) {
            return false;
        }
        if (!is_valid_address(src->group_address)) {
            return false;
        }
        if (!is_valid_group_member_list(src->group_member_list, src->n_group_member_list)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_group_info_list(const E2ees__GroupInfo **src, size_t len) {
    if (len > 0 && src == NULL)
        return false;
    if (len == 0 && src != NULL)
        return false;
    size_t i;
    for (i = 0; i < len; i++) {
        if (!is_valid_group_info(src[i])) {
            return false;
        }
    }

    return true;
}

bool is_valid_group_member_info(const E2ees__GroupMemberInfo *src) {
    if (src != NULL) {
        if (!is_valid_address(src->member_address)) {
            return false;
        }
        if (!is_valid_protobuf(&(src->sign_public_key))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_group_member_info_list(const E2ees__GroupMemberInfo **src, size_t len) {
    if (len > 0 && src == NULL)
        return false;
    if (len == 0 && src != NULL)
        return false;
    size_t i;
    for (i = 0; i < len; i++) {
        if (!is_valid_group_member_info(src[i])) {
            return false;
        }
    }

    return true;
}

bool is_valid_group_session_by_member_id(E2ees__GroupSession *src) {
    if (src != NULL) {
        if (!is_valid_e2ees_pack_id(src->e2ees_pack_id)) {
            return false;
        }
        if (!is_valid_address(src->sender)) {
            return false;
        }
        if (!is_valid_address(src->session_owner)) {
            return false;
        }
        if (!is_valid_group_info(src->group_info)) {
            return false;
        }
        if (!is_valid_protobuf(&(src->associated_data))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_group_session_by_pre_key_bundle(E2ees__GroupSession *src) {
    if (src != NULL) {
        if (!is_valid_string(src->version)) {
            return false;
        }
        if (!is_valid_e2ees_pack_id(src->e2ees_pack_id)) {
            return false;
        }
        if (!is_valid_string(src->session_id)) {
            return false;
        }
        if (!is_valid_address(src->sender)) {
            return false;
        }
        if (!is_valid_address(src->session_owner)) {
            return false;
        }
        if (!is_valid_group_info(src->group_info)) {
            return false;
        }
        if (!is_valid_protobuf(&(src->group_seed))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_group_session(E2ees__GroupSession *src) {
    if (src != NULL) {
        if (!is_valid_string(src->version)) {
            return false;
        }
        if (!is_valid_e2ees_pack_id(src->e2ees_pack_id)) {
            return false;
        }
        if (!is_valid_string(src->session_id)) {
            return false;
        }
        if (!is_valid_address(src->sender)) {
            return false;
        }
        if (!is_valid_address(src->session_owner)) {
            return false;
        }
        if (!is_valid_group_info(src->group_info)) {
            return false;
        }
        if (!is_valid_protobuf(&(src->chain_key))) {
            return false;
        }
        if (!is_valid_protobuf(&(src->associated_data))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_group_session_no_chain_key(E2ees__GroupSession *src) {
    if (src != NULL) {
        if (!is_valid_string(src->version)) {
            return false;
        }
        if (!is_valid_e2ees_pack_id(src->e2ees_pack_id)) {
            return false;
        }
        if (!is_valid_string(src->session_id)) {
            return false;
        }
        if (!is_valid_address(src->sender)) {
            return false;
        }
        if (!is_valid_address(src->session_owner)) {
            return false;
        }
        if (!is_valid_group_info(src->group_info)) {
            return false;
        }
        if (!is_valid_protobuf(&(src->associated_data))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_group_update_key_bundle(E2ees__GroupUpdateKeyBundle *src) {
    if (src != NULL) {
        if (!is_valid_string(src->version)) {
            return false;
        }
        if (!is_valid_e2ees_pack_id(src->e2ees_pack_id)) {
            return false;
        }
        if (!is_valid_address(src->sender)) {
            return false;
        }
        if (!is_valid_string(src->session_id)) {
            return false;
        }
        if (!is_valid_group_info(src->group_info)) {
            return false;
        }
        if (!is_valid_protobuf(&(src->chain_key))) {
            return false;
        }
        if (!is_valid_protobuf(&(src->sign_public_key))) {
            return false;
        }
        if (!is_valid_group_member_info_list(
                (const E2ees__GroupMemberInfo **)src->adding_member_info_list,
                src->n_adding_member_info_list)
        ) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_group_pre_key_bundle(E2ees__GroupPreKeyBundle *src) {
    if (src != NULL) {
        if (!is_valid_string(src->version)) {
            return false;
        }
        if (!is_valid_e2ees_pack_id(src->e2ees_pack_id)) {
            return false;
        }
        if (!is_valid_address(src->sender)) {
            return false;
        }
        if (!is_valid_string(src->session_id)) {
            return false;
        }
        if (!is_valid_group_info(src->group_info)) {
            return false;
        }
        if (!is_valid_protobuf(&(src->group_seed))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_group_msg_payload(const E2ees__GroupMsgPayload *payload) {
    if (payload != NULL) {
        if (!is_valid_protobuf(&(payload->ciphertext))) {
            // there is some wrong with the ciphertext data in the payload
            return false;
        }
        if (!is_valid_protobuf(&(payload->signature))) {
            // there is some wrong with the signature data in the payload
            return false;
        }
    } else {
        // the payload is NULL
        return false;
    }

    return true;
}

bool is_valid_register_user_response(E2ees__RegisterUserResponse *src) {
    if (src != NULL) {
        if (src->code != E2EES__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
        if (!is_valid_address(src->address)) {
            return false;
        }
        if (!is_valid_string(src->username)) {
            return false;
        }
        if (!is_valid_string(src->password)) {
            return false;
        }
        if (!is_valid_string(src->auth)) {
            return false;
        }
        if (!is_valid_address_list(src->other_device_address_list, src->n_other_device_address_list)) {
            return false;
        }
        if (!is_valid_address_list(src->other_user_address_list, src->n_other_user_address_list)) {
            return false;
        }
        if (!is_valid_group_info_list((const E2ees__GroupInfo **)src->group_info_list, src->n_group_info_list)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_publish_spk_response(E2ees__PublishSpkResponse *src) {
    if (src != NULL) {
        if (src->code != E2EES__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_supply_opks_response(E2ees__SupplyOpksResponse *src) {
    if (src != NULL) {
        if (src->code != E2EES__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_get_pre_key_bundle_response(E2ees__GetPreKeyBundleResponse *src) {
    if (src != NULL) {
        if (src->code != E2EES__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
        if (!is_valid_string(src->user_id)) {
            return false;
        }
        if (!is_valid_pre_key_bundle_list(src->pre_key_bundles, src->n_pre_key_bundles)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_invite_response(E2ees__InviteResponse *src) {
    if (src != NULL) {
        if (src->code != E2EES__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
        if (!is_valid_string(src->session_id)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_accept_response(E2ees__AcceptResponse *src) {
    if (src != NULL) {
        if (src->code != E2EES__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_create_group_response(E2ees__CreateGroupResponse *src) {
    if (src != NULL) {
        if (src->code != E2EES__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
        if (!is_valid_address(src->group_address)) {
            return false;
        }
        if (!is_valid_group_member_info_list(
                (const E2ees__GroupMemberInfo **)src->member_info_list,
                src->n_member_info_list)
        ) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_add_group_members_response(E2ees__AddGroupMembersResponse *src) {
    if (src != NULL) {
        if (src->code != E2EES__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
        if (!is_valid_group_member_list(src->added_group_member_list, src->n_added_group_member_list)) {
            return false;
        }
        if (!is_valid_group_member_list(src->group_member_list, src->n_group_member_list)) {
            return false;
        }
        if (!is_valid_group_member_info_list(
                (const E2ees__GroupMemberInfo **)src->adding_member_info_list,
                src->n_adding_member_info_list)
        ) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_add_group_member_device_response(E2ees__AddGroupMemberDeviceResponse *src) {
    if (src != NULL) {
        if (src->code != E2EES__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
        if (!is_valid_group_member_list(src->group_member_list, src->n_group_member_list)) {
            return false;
        }
        if (!is_valid_group_member_info(src->adding_member_device_info)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_remove_group_members_response(E2ees__RemoveGroupMembersResponse *src) {
    if (src != NULL) {
        if (src->code != E2EES__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
        if (!is_valid_group_member_list(src->removed_group_member_list, src->n_removed_group_member_list)) {
            return false;
        }
        if (!is_valid_group_member_list(src->group_member_list, src->n_group_member_list)) {
            return false;
        }
        if (!is_valid_group_member_info_list(
                (const E2ees__GroupMemberInfo **)src->member_info_list,
                src->n_member_info_list)
        ) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_leave_group_response(E2ees__LeaveGroupResponse *src) {
    if (src != NULL) {
        if (src->code != E2EES__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
        if (!is_valid_address(src->leave_group_member_address)) {
            return false;
        }
        if (!is_valid_address(src->group_address)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_send_group_msg_response(E2ees__SendGroupMsgResponse *src) {
    if (src != NULL) {
        if (src->code != E2EES__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_supply_opks_msg(E2ees__SupplyOpksMsg *src) {
    if (src != NULL) {
        if (!is_valid_address(src->user_address)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_add_user_device_msg(E2ees__AddUserDeviceMsg *src) {
    if (src != NULL) {
        if (!is_valid_address(src->user_address)) {
            return false;
        }
        if (!is_valid_address_list(src->old_address_list, src->n_old_address_list)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_remove_user_device_msg(E2ees__RemoveUserDeviceMsg *src) {
    if (src != NULL) {
        if (!is_valid_address(src->user_address)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_invite_msg(E2ees__InviteMsg *src) {
    if (src != NULL) {
        if (!is_valid_string(src->version)) {
            return false;
        }
        if (!is_valid_e2ees_pack_id(src->e2ees_pack_id)) {
            return false;
        }
        if (!is_valid_string(src->session_id)) {
            return false;
        }
        if (!is_valid_address(src->from)) {
            return false;
        }
        if (!is_valid_address(src->to)) {
            return false;
        }
        if (!is_valid_protobuf(&(src->alice_identity_key))) {
            return false;
        }
        if (!is_valid_protobuf(&(src->alice_base_key))) {
            return false;
        }
        if (!is_valid_protobuf_list(src->pre_shared_input_list, src->n_pre_shared_input_list)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_accept_msg(E2ees__AcceptMsg *src) {
    if (src != NULL) {
        if (!is_valid_address(src->from)) {
            return false;
        }
        if (!is_valid_address(src->to)) {
            return false;
        }
        if (!is_valid_e2ees_pack_id(src->e2ees_pack_id)) {
            return false;
        }
        if (!is_valid_protobuf(&(src->encaps_ciphertext))) {
            return false;
        }
        if (!is_valid_protobuf(&(src->ratchet_key))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_e2ee_msg(E2ees__E2eeMsg *src) {
    if (src != NULL) {
        if (!is_valid_string(src->version)) {
            return false;
        }
        if (!is_valid_address(src->from)) {
            return false;
        }
        if (!is_valid_address(src->to)) {
            return false;
        }
        if (!is_valid_string(src->session_id)) {
            return false;
        }
        if (src->payload_case == E2EES__E2EE_MSG__PAYLOAD_ONE2ONE_MSG) {
            if (!is_valid_one2one_msg_payload(src->one2one_msg)) {
                return false;
            }
        } else if (src->payload_case == E2EES__E2EE_MSG__PAYLOAD_GROUP_MSG) {
            if (!is_valid_group_msg_payload(src->group_msg)) {
                return false;
            }
        } else {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_create_group_msg(E2ees__CreateGroupMsg *src) {
    if (src != NULL) {
        if (!is_valid_e2ees_pack_id(src->e2ees_pack_id)) {
            return false;
        }
        if (!is_valid_address(src->sender_address)) {
            return false;
        }
        if (!is_valid_group_info(src->group_info)) {
            return false;
        }
        if (!is_valid_group_member_info_list(
                (const E2ees__GroupMemberInfo **)src->member_info_list,
                src->n_member_info_list)
        ) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_add_group_members_msg(E2ees__AddGroupMembersMsg *src) {
    if (src != NULL) {
        if (!is_valid_e2ees_pack_id(src->e2ees_pack_id)) {
            return false;
        }
        if (!is_valid_address(src->sender_address)) {
            return false;
        }
        if (!is_valid_group_info(src->group_info)) {
            return false;
        }
        if (!is_valid_group_member_list(src->adding_member_list, src->n_adding_member_list)) {
            return false;
        }
        if (!is_valid_group_member_info_list(
                (const E2ees__GroupMemberInfo **)src->adding_member_info_list,
                src->n_adding_member_info_list)
        ) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_add_group_member_device_msg(E2ees__AddGroupMemberDeviceMsg *src) {
    if (src != NULL) {
        if (!is_valid_e2ees_pack_id(src->e2ees_pack_id)) {
            return false;
        }
        if (!is_valid_address(src->sender_address)) {
            return false;
        }
        if (!is_valid_group_info(src->group_info)) {
            return false;
        }
        if (!is_valid_group_member_info(src->adding_member_device)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_remove_group_members_msg(E2ees__RemoveGroupMembersMsg *src) {
    if (src != NULL) {
        if (!is_valid_e2ees_pack_id(src->e2ees_pack_id)) {
            return false;
        }
        if (!is_valid_address(src->sender_address)) {
            return false;
        }
        if (!is_valid_group_info(src->group_info)) {
            return false;
        }
        if (!is_valid_group_member_list(src->removing_member_list, src->n_removing_member_list)) {
            return false;
        }
        if (!is_valid_group_member_info_list(
                (const E2ees__GroupMemberInfo **)src->member_info_list,
                src->n_member_info_list)
        ) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_leave_group_msg(E2ees__LeaveGroupMsg *src) {
    if (src != NULL) {
        if (!is_valid_address(src->user_address)) {
            return false;
        }
        if (!is_valid_address(src->group_address)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_proto_msg(E2ees__ProtoMsg *src) {
    if (src != NULL) {
        // if (!is_valid_address(src->from)) {
        //     return false;
        // }
        if (!is_valid_address(src->to)) {
            return false;
        }
        if (!is_valid_server_signed_signature_list(src->signature_list, src->n_signature_list)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_subject(E2ees__Subject *src) {
    if (src != NULL) {
        if (!is_valid_string(src->cn)) {
            return false;
        }
        if (!is_valid_string(src->domain)) {
            return false;
        }
        if (!is_valid_string(src->o)) {
            return false;
        }
        if (!is_valid_string_list(src->ou, src->n_ou)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_cert(E2ees__Cert *src) {
    if (src != NULL) {
        if (!is_valid_subject(src->issuee)) {
            return false;
        }
        if (!is_valid_protobuf(&(src->public_key))) {
            return false;
        }
        if (!is_valid_subject(src->issuer)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_certificate(E2ees__Certificate *src) {
    if (src != NULL) {
        if (!is_valid_cert(src->cert)) {
            return false;
        }
        if (!is_valid_protobuf(&(src->cert_fingerprint))) {
            return false;
        }
        if (!is_valid_protobuf(&(src->signing_public_key_fingerprint))) {
            return false;
        }
        if (!is_valid_protobuf(&(src->signature))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_server_signed_signature(E2ees__ServerSignedSignature *src) {
    if (src != NULL) {
        if (!is_valid_subject(src->signer)) {
            return false;
        }
        if (!is_valid_protobuf(&(src->signing_public_key_fingerprint))) {
            return false;
        }
        if (!is_valid_protobuf(&(src->msg_fingerprint))) {
            return false;
        }
        if (!is_valid_protobuf(&(src->signature))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool is_valid_server_signed_signature_list(E2ees__ServerSignedSignature **src, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        if (!is_valid_server_signed_signature(src[i])) {
            return false;
        }
    }

    return true;
}
