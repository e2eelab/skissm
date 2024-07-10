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
#include "skissm/safe_check.h"

///-----------------accuracy-----------------///
bool accurate_key_pair(Skissm__KeyPair *key_pair, uint32_t pub_key_len, uint32_t priv_key_len) {
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

bool safe_cipher_suite(const cipher_suite_t *cipher_suite) {
    if (cipher_suite != NULL) {
        if (cipher_suite->digital_signature_suite != NULL) {
            if (cipher_suite->digital_signature_suite->get_crypto_param == NULL)
                return false;
            if (cipher_suite->digital_signature_suite->sign == NULL)
                return false;
            if (cipher_suite->digital_signature_suite->sign_key_gen == NULL)
                return false;
            if (cipher_suite->digital_signature_suite->verify == NULL)
                return false;
        } else {
            return false;
        }
        if (cipher_suite->kem_suite != NULL) {
            if (cipher_suite->kem_suite->asym_key_gen == NULL)
                return false;
            if (cipher_suite->kem_suite->get_crypto_param == NULL)
                return false;
            if (cipher_suite->kem_suite->ss_key_gen == NULL)
                return false;
        } else {
            return false;
        }
        if (cipher_suite->symmetric_encryption_suite != NULL) {
            if (cipher_suite->symmetric_encryption_suite->decrypt == NULL)
                return false;
            if (cipher_suite->symmetric_encryption_suite->encrypt == NULL)
                return false;
            if (cipher_suite->symmetric_encryption_suite->get_crypto_param == NULL)
                return false;
            if (cipher_suite->hash_suite->hash == NULL)
                return false;
            if (cipher_suite->hash_suite->hkdf == NULL)
                return false;
            if (cipher_suite->hash_suite->hmac == NULL)
                return false;
        } else {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_e2ee_pack_id(uint32_t e2ee_pack_id) {
    cipher_suite_t *cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;

    return safe_cipher_suite(cipher_suite);
}

bool safe_protobuf(const ProtobufCBinaryData *src) {
    if (src->len > 0 && src->data == NULL) {
        return false;
    }
    return true;
}

bool safe_protobuf_list(ProtobufCBinaryData *src, size_t len) {
    if (len > 0 && src == NULL)
        return false;
    if (len == 0 && src != NULL)
        return false;
    size_t i;
    for (i = 0; i < len; i++) {
        if (!safe_protobuf(&(src[i]))) {
            return false;
        }
    }

    return true;
}

bool nonempty_string(const char *src) {
    if (src != NULL) {
        if (src[0] == '\0') {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_address(Skissm__E2eeAddress *src) {
    if (src != NULL) {
        if (!nonempty_string(src->domain)) {
            return false;
        }
        if (src->peer_case == SKISSM__E2EE_ADDRESS__PEER__NOT_SET) {
            return false;
        } else if (src->peer_case == SKISSM__E2EE_ADDRESS__PEER_USER) {
            if (src->user != NULL) {
                if (!nonempty_string(src->user->user_name)) {
                    return false;
                }
                if (!nonempty_string(src->user->user_id)) {
                    return false;
                }
                if (!nonempty_string(src->user->device_id)) {
                    return false;
                }
            } else {
                return false;
            }
        } else if (src->peer_case == SKISSM__E2EE_ADDRESS__PEER_GROUP) {
            if (src->group != NULL) {
                if (!nonempty_string(src->group->group_name)) {
                    return false;
                }
                if (!nonempty_string(src->group->group_id)) {
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

bool safe_address_list(Skissm__E2eeAddress **src, size_t len) {
    if (len > 0 && src == NULL)
        return false;
    if (len == 0 && src != NULL)
        return false;
    size_t i;
    for (i = 0; i < len; i++) {
        if (!safe_address(src[i])) {
            return false;
        }
    }

    return true;
}

bool safe_key_pair(Skissm__KeyPair *src) {
    if (src != NULL) {
        if (!safe_protobuf(&(src->private_key))) {
            return false;
        }
        if (!safe_protobuf(&(src->public_key))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_identity_key(Skissm__IdentityKey *src) {
    if (src != NULL) {
        if (!safe_key_pair(src->asym_key_pair)) {
            return false;
        }
        if (!safe_key_pair(src->sign_key_pair)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_signed_pre_key(Skissm__SignedPreKey *src) {
    if (src != NULL) {
        if (!safe_key_pair(src->key_pair)) {
            return false;
        }
        if (!safe_protobuf(&(src->signature))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_one_time_pre_key_list(Skissm__OneTimePreKey **src, size_t len) {
    if (len > 0 && src == NULL)
        return false;
    if (len == 0 && src != NULL)
        return false;
    size_t i;
    for (i = 0; i < len; i++) {
        if (src[i] != NULL) {
            if (!safe_key_pair(src[i]->key_pair)) {
                return false;
            }
        } else {
            return false;
        }
    }

    return true;
}

bool safe_unregistered_account(Skissm__Account *src) {
    if (src->version == NULL) {
        return false;
    }
    if (!safe_e2ee_pack_id(src->e2ee_pack_id)) {
        return false;
    }
    if (!safe_identity_key(src->identity_key)) {
        return false;
    }
    if (!safe_signed_pre_key(src->signed_pre_key)) {
        return false;
    }
    if (!safe_one_time_pre_key_list(src->one_time_pre_key_list, src->n_one_time_pre_key_list)) {
        return false;
    }
    // the address, password and auth should not be available in an unregistered account
    if (safe_address(src->address)) {
        return false;
    }
    if (nonempty_string(src->password)) {
        return false;
    }
    if (nonempty_string(src->auth)) {
        return false;
    }

    return true;
}

bool safe_registered_account(Skissm__Account *src) {
    if (src->version == NULL) {
        return false;
    }
    if (!safe_e2ee_pack_id(src->e2ee_pack_id)) {
        return false;
    }
    if (!safe_address(src->address)) {
        return false;
    }
    if (!safe_identity_key(src->identity_key)) {
        return false;
    }
    if (!safe_signed_pre_key(src->signed_pre_key)) {
        return false;
    }
    if (!safe_one_time_pre_key_list(src->one_time_pre_key_list, src->n_one_time_pre_key_list)) {
        return false;
    }
    if (!nonempty_string(src->password)) {
        return false;
    }
    if (!nonempty_string(src->auth)) {
        return false;
    }

    return true;
}

bool safe_msg_key(const Skissm__MsgKey *msg_key) {
    if (msg_key != NULL) {
        return safe_protobuf(&(msg_key->derived_key));
    } else {
        return false;
    }
}

bool safe_chain_key(const Skissm__ChainKey *chain_key) {
    if (chain_key != NULL) {
        return safe_protobuf(&(chain_key->shared_key));
    } else {
        return false;
    }
}

bool safe_sender_chain(Skissm__SenderChainNode *sender_chain) {
    if (sender_chain != NULL) {
        if (!safe_protobuf(&(sender_chain->our_ratchet_public_key))) {
            return false;
        }
        if (!safe_protobuf(&(sender_chain->their_ratchet_public_key))) {
            return false;
        }
        return safe_chain_key(sender_chain->chain_key);
    } else {
        return false;
    }
}

bool safe_receiver_chain(Skissm__ReceiverChainNode *receiver_chain) {
    if (receiver_chain != NULL) {
        if (!safe_protobuf(&(receiver_chain->our_ratchet_private_key))) {
            return false;
        }
        if (!safe_protobuf(&(receiver_chain->their_ratchet_public_key))) {
            return false;
        }
        return safe_chain_key(receiver_chain->chain_key);
    } else {
        return false;
    }
}

bool safe_skipped_msg_key_node(Skissm__SkippedMsgKeyNode *skipped_msg_key_node) {
    if (skipped_msg_key_node != NULL) {
        if (!safe_protobuf(&(skipped_msg_key_node->ratchet_key_public))) {
            return false;
        }
        return safe_msg_key(skipped_msg_key_node->msg_key);
    } else {
        return false;
    }
}

bool safe_skipped_msg_key_list(
    Skissm__SkippedMsgKeyNode **skipped_msg_key_list,
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
        if (!safe_skipped_msg_key_node(skipped_msg_key_list[i])) {
            return false;
        }
    }

    return true;
}

bool safe_ratchet(const Skissm__Ratchet *ratchet) {
    if (ratchet != NULL) {
        if (!safe_protobuf(&(ratchet->root_key))) {
            return false;
        }
        if (!safe_sender_chain(ratchet->sender_chain)) {
            return false;
        }
        if (ratchet->root_sequence > 0) {
            if (!safe_receiver_chain(ratchet->receiver_chain)) {
                return false;
            }
        } else {
            // if the root sequence is equal to zero
            if (ratchet->receiver_chain != NULL) {
                if (!safe_protobuf(&(ratchet->receiver_chain->our_ratchet_private_key))) {
                    return false;
                }
            } else {
                return false;
            }
        }
        if (!safe_skipped_msg_key_list(ratchet->skipped_msg_key_list, ratchet->n_skipped_msg_key_list)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_uncompleted_session(Skissm__Session *src) {
    if (src != NULL) {
        if (!nonempty_string(src->version)) {
            return false;
        }
        if (!safe_e2ee_pack_id(src->e2ee_pack_id)) {
            return false;
        }
        if (!nonempty_string(src->session_id)) {
            return false;
        }
        if (!safe_address(src->our_address)) {
            return false;
        }
        if (!safe_address(src->their_address)) {
            return false;
        }
        if (!safe_protobuf(&(src->temp_shared_secret))) {
            return false;
        }
        if (!safe_protobuf(&(src->fingerprint))) {
            return false;
        }
        if (!safe_key_pair(src->alice_base_key)) {
            return false;
        }
        if (!safe_protobuf_list(src->pre_shared_input_list, src->n_pre_shared_input_list)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_completed_session(Skissm__Session *src) {
    if (src != NULL) {
        if (!nonempty_string(src->version)) {
            return false;
        }
        if (!safe_e2ee_pack_id(src->e2ee_pack_id)) {
            return false;
        }
        if (!nonempty_string(src->session_id)) {
            return false;
        }
        if (!safe_address(src->our_address)) {
            return false;
        }
        if (!safe_address(src->their_address)) {
            return false;
        }
        if (!safe_ratchet(src->ratchet)) {
            return false;
        }
        if (!safe_protobuf(&(src->associated_data))) {
            return false;
        }
        if (!safe_protobuf(&(src->temp_shared_secret))) {
            return false;
        }
        if (!safe_protobuf(&(src->fingerprint))) {
            return false;
        }
        if (!safe_key_pair(src->alice_base_key)) {
            return false;
        }
        if (!safe_protobuf_list(src->pre_shared_input_list, src->n_pre_shared_input_list)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_identity_key_public(Skissm__IdentityKeyPublic *src) {
    if (src != NULL) {
        if (!safe_protobuf(&(src->asym_public_key))) {
            return false;
        }
        if (!safe_protobuf(&(src->sign_public_key))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_signed_pre_key_public(Skissm__SignedPreKeyPublic *src) {
    if (src != NULL) {
        if (!safe_protobuf(&(src->public_key))) {
            return false;
        }
        if (!safe_protobuf(&(src->signature))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_one_time_pre_key_public(Skissm__OneTimePreKeyPublic *src) {
    if (src != NULL) {
        if (!safe_protobuf(&(src->public_key))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_pre_key_bundle(Skissm__PreKeyBundle *src) {
    if (src != NULL) {
        if (!safe_address(src->user_address)) {
            return false;
        }
        if (!safe_identity_key_public(src->identity_key_public)) {
            return false;
        }
        if (!safe_signed_pre_key_public(src->signed_pre_key_public)) {
            return false;
        }
        if (!safe_one_time_pre_key_public(src->one_time_pre_key_public)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_pre_key_bundle_list(Skissm__PreKeyBundle **src, size_t len) {
    if (len > 0 && src == NULL)
        return false;
    if (len == 0 && src != NULL)
        return false;
    size_t i;
    for (i = 0; i < len; i++) {
        if (!safe_pre_key_bundle(src[i])) {
            return false;
        }
    }

    return true;
}

bool safe_one2one_msg_payload(const Skissm__One2oneMsgPayload *payload) {
    if (payload != NULL) {
        if (!safe_protobuf(&(payload->ratchet_key))) {
            // there is some wrong with the ratchet key data in the payload
            return false;
        }
        if (!safe_protobuf(&(payload->ciphertext))) {
            // there is some wrong with the ciphertext data in the payload
            return false;
        }
    } else {
        // the payload is NULL
        return false;
    }

    return true;
}

bool safe_group_member(Skissm__GroupMember *src) {
    if (src != NULL) {
        if (!nonempty_string(src->user_id)) {
            return false;
        }
        if (!nonempty_string(src->domain)) {
            return false;
        }
        if ((src->role != SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER) &&
            (src->role != SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER) &&
            (src->role != SKISSM__GROUP_ROLE__GROUP_ROLE_PENDING_MEMBER) &&
            (src->role != SKISSM__GROUP_ROLE__GROUP_ROLE_PENDING_MANAGER)
        ) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_group_member_list(Skissm__GroupMember **src, size_t len) {
    if (len > 0 && src == NULL)
        return false;
    if (len == 0 && src != NULL)
        return false;
    size_t i;
    for (i = 0; i < len; i++) {
        if (!safe_group_member(src[i])) {
            return false;
        }
    }

    return true;
}

bool safe_group_info(const Skissm__GroupInfo *src) {
    if (src != NULL) {
        if (!nonempty_string(src->group_name)) {
            return false;
        }
        if (!safe_address(src->group_address)) {
            return false;
        }
        if (!safe_group_member_list(src->group_member_list, src->n_group_member_list)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_group_info_list(const Skissm__GroupInfo **src, size_t len) {
    if (len > 0 && src == NULL)
        return false;
    if (len == 0 && src != NULL)
        return false;
    size_t i;
    for (i = 0; i < len; i++) {
        if (!safe_group_info(src[i])) {
            return false;
        }
    }

    return true;
}

bool safe_group_member_info(const Skissm__GroupMemberInfo *src) {
    if (src != NULL) {
        if (!safe_address(src->member_address)) {
            return false;
        }
        if (!safe_protobuf(&(src->sign_public_key))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_group_member_info_list(const Skissm__GroupMemberInfo **src, size_t len) {
    if (len > 0 && src == NULL)
        return false;
    if (len == 0 && src != NULL)
        return false;
    size_t i;
    for (i = 0; i < len; i++) {
        if (!safe_group_member_info(src[i])) {
            return false;
        }
    }

    return true;
}

bool safe_group_session(Skissm__GroupSession *src) {
    if (src != NULL) {
        if (!nonempty_string(src->version)) {
            return false;
        }
        if (!safe_e2ee_pack_id(src->e2ee_pack_id)) {
            return false;
        }
        if (!nonempty_string(src->session_id)) {
            return false;
        }
        if (!safe_address(src->sender)) {
            return false;
        }
        if (!safe_address(src->session_owner)) {
            return false;
        }
        if (!safe_group_info(src->group_info)) {
            return false;
        }
        if (!safe_protobuf(&(src->chain_key))) {
            return false;
        }
        if (!safe_protobuf(&(src->group_seed))) {
            return false;
        }
        if (!safe_protobuf(&(src->associated_data))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_group_update_key_bundle(Skissm__GroupUpdateKeyBundle *src) {
    if (src != NULL) {
        if (!nonempty_string(src->version)) {
            return false;
        }
        if (!safe_e2ee_pack_id(src->e2ee_pack_id)) {
            return false;
        }
        if (!safe_address(src->sender)) {
            return false;
        }
        if (!nonempty_string(src->session_id)) {
            return false;
        }
        if (!safe_group_info(src->group_info)) {
            return false;
        }
        if (!safe_protobuf(&(src->chain_key))) {
            return false;
        }
        if (!safe_protobuf(&(src->sign_public_key))) {
            return false;
        }
        if (!safe_group_member_info_list(src->adding_member_info_list, src->n_adding_member_info_list)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_group_pre_key_bundle(Skissm__GroupPreKeyBundle *src) {
    if (src != NULL) {
        if (!nonempty_string(src->version)) {
            return false;
        }
        if (!safe_e2ee_pack_id(src->e2ee_pack_id)) {
            return false;
        }
        if (!safe_address(src->sender)) {
            return false;
        }
        if (!nonempty_string(src->session_id)) {
            return false;
        }
        if (!safe_group_info(src->group_info)) {
            return false;
        }
        if (!safe_protobuf(&(src->group_seed))) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_register_user_response(Skissm__RegisterUserResponse *src) {
    if (src != NULL) {
        if (src->code != SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
        if (!safe_address(src->address)) {
            return false;
        }
        if (!nonempty_string(src->username)) {
            return false;
        }
        if (!nonempty_string(src->password)) {
            return false;
        }
        if (!nonempty_string(src->auth)) {
            return false;
        }
        if (!safe_address_list(src->other_device_address_list, src->n_other_device_address_list)) {
            return false;
        }
        if (!safe_address_list(src->other_user_address_list, src->n_other_user_address_list)) {
            return false;
        }
        if (!safe_group_info_list(src->group_info_list, src->n_group_info_list)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_publish_spk_response(Skissm__PublishSpkResponse *src) {
    if (src != NULL) {
        if (src->code != SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_supply_opks_response(Skissm__SupplyOpksResponse *src) {
    if (src != NULL) {
        if (src->code != SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_get_pre_key_bundle_response(Skissm__GetPreKeyBundleResponse *src) {
    if (src != NULL) {
        if (src->code != SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
        if (!nonempty_string(src->user_id)) {
            return false;
        }
        if (!safe_pre_key_bundle_list(src->pre_key_bundles, src->n_pre_key_bundles)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_invite_response(Skissm__InviteResponse *src) {
    if (src != NULL) {
        if (src->code != SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
        if (!nonempty_string(src->session_id)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_accept_response(Skissm__AcceptResponse *src) {
    if (src != NULL) {
        if (src->code != SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_create_group_response(Skissm__CreateGroupResponse *src) {
    if (src != NULL) {
        if (src->code != SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
        if (!safe_address(src->group_address)) {
            return false;
        }
        if (!safe_group_member_info_list(src->member_info_list, src->n_member_info_list)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_add_group_members_response(Skissm__AddGroupMembersResponse *src) {
    if (src != NULL) {
        if (src->code != SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
        if (!safe_group_member_list(src->added_group_member_list, src->n_added_group_member_list)) {
            return false;
        }
        if (!safe_group_member_list(src->group_member_list, src->n_group_member_list)) {
            return false;
        }
        if (!safe_group_member_info_list(src->adding_member_info_list, src->n_adding_member_info_list)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_add_group_member_device_response(Skissm__AddGroupMemberDeviceResponse *src) {
    if (src != NULL) {
        if (src->code != SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
        if (!safe_group_member_list(src->group_member_list, src->n_group_member_list)) {
            return false;
        }
        if (!safe_group_member_info(src->adding_member_device_info)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_remove_group_members_response(Skissm__RemoveGroupMembersResponse *src) {
    if (src != NULL) {
        if (src->code != SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
        if (!safe_group_member_list(src->removed_group_member_list, src->n_removed_group_member_list)) {
            return false;
        }
        if (!safe_group_member_list(src->group_member_list, src->n_group_member_list)) {
            return false;
        }
        if (!safe_group_member_info_list(src->member_info_list, src->n_member_info_list)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_leave_group_response(Skissm__LeaveGroupResponse *src) {
    if (src != NULL) {
        if (src->code != SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
        if (!safe_address(src->leave_group_member_address)) {
            return false;
        }
        if (!safe_address(src->group_address)) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

bool safe_send_group_msg_response(Skissm__SendGroupMsgResponse *src) {
    if (src != NULL) {
        if (src->code != SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}
