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
#include "test_util.h"

#include <stdio.h>
#include <string.h>

#include "skissm/account.h"
#include "skissm/mem_util.h"

void print_hex(char *title, uint8_t *msg, size_t msg_len) {
    printf("%s", title);
    size_t i;
    for (i = 0; i < msg_len; i++) {
        if (i % 16 == 0)
            printf("\n| ");
        printf("0x%02x ", msg[i]);

        if (i % 8 == 7)
            printf("| ");
    }

    printf("\n");
}

void print_msg(char *title, uint8_t *msg, size_t len) {
    printf("😊 %s [msg len=%zu]: %.*s\n", title, len, (int)len, msg);
}

void print_log(char *log_msg, int log_code) {
    if (log_code == DEBUG_LOG)
        printf("🔭 : %s\n", log_msg);
    else
        printf("💀 [ErrorCode=%d]: %s\n", log_code, log_msg);
}

void print_result(char *title, bool success) {
    if (success)
        printf("%s: success\n", title);
    else
        printf("%s: failed\n", title);
}

bool is_null(void *pointer_1, void *pointer_2) {
    if ((pointer_1 == NULL) && (pointer_2 == NULL)) {
        return true;
    }
    return false;
}

bool is_not_null(void *pointer_1, void *pointer_2) {
    if ((pointer_1 != NULL) && (pointer_2 != NULL)) {
        return true;
    }
    return false;
}

bool is_equal_data(ProtobufCBinaryData *data1, ProtobufCBinaryData *data2) {
    if (data1->len != data2->len) {
        return false;
    }

    size_t i;
    for (i = 0; i < data1->len; i++) {
        if (data1->data[i] != data2->data[i]) {
            return false;
        }
    }

    return true;
}

bool is_equal_str(char *str1, char *str2) {
    size_t len1 = strlen(str1);
    size_t len2 = strlen(str2);

    if (len1 != len2) {
        return false;
    }

    size_t i;
    for (i = 0; i < len1; i++) {
        if (str1[i] != str2[i]) {
            return false;
        }
    }

    return true;
}

bool is_equal_keypair(Skissm__KeyPair *keypair1, Skissm__KeyPair *keypair2) {
    if (!is_equal_data(&(keypair1->public_key), &(keypair2->public_key))) {
        return false;
    }
    if (!is_equal_data(&(keypair1->private_key), &(keypair2->private_key))) {
        return false;
    }

    return true;
}

bool is_equal_spk(Skissm__SignedPreKey *spk1, Skissm__SignedPreKey *spk2) {
    if (spk1->spk_id != spk2->spk_id) {
        return false;
    }
    if (is_not_null(spk1->key_pair, spk2->key_pair)) {
        if (!is_equal_keypair(spk1->key_pair, spk2->key_pair)) {
            return false;
        }
    } else {
        if (!is_null(spk1->key_pair, spk2->key_pair)) {
            return false;
        }
    }
    if (!is_equal_data(&(spk1->signature), &(spk2->signature))) {
        return false;
    }
    if (spk1->ttl != spk2->ttl) {
        return false;
    }

    return true;
}

bool is_equal_opk(Skissm__OneTimePreKey *opk1, Skissm__OneTimePreKey *opk2) {
    if (opk1->opk_id != opk2->opk_id) {
        return false;
    }
    if (is_not_null(opk1->key_pair, opk2->key_pair)) {
        if (!is_equal_keypair(opk1->key_pair, opk2->key_pair)) {
            return false;
        }
    } else {
        if (!is_null(opk1->key_pair, opk2->key_pair)) {
            return false;
        }
    }

    return true;
}

bool is_equal_account(Skissm__Account *account1, Skissm__Account *account2) {
    if (!safe_strcmp(account1->version, account2->version)) {
        printf("version not match");
        return false;
    }
    if (account1->e2ee_pack_id != account2->e2ee_pack_id) {
        printf("e2ee_pack_id not match");
        return false;
    }
    if (account1->saved != account2->saved) {
        printf("saved not match");
        return false;
    }
    if (is_not_null(account1->address, account2->address)) {
        if (!compare_address(account1->address, account2->address)) {
            printf("address not match");
            return false;
        }
    } else {
        if (!is_null(account1->address, account2->address)) {
            printf("address not match");
            return false;
        }
    }
    if (is_not_null(account1->identity_key, account2->identity_key)) {
        if (is_not_null(account1->identity_key->asym_key_pair, account2->identity_key->asym_key_pair)) {
            if (!is_equal_keypair(account1->identity_key->asym_key_pair, account2->identity_key->asym_key_pair)) {
                printf("keypair not match");
                return false;
            }
        } else {
            if (!is_null(account1->identity_key->asym_key_pair, account2->identity_key->asym_key_pair)) {
                printf("keypair not match");
                return false;
            }
        }
        if (is_not_null(account1->identity_key->sign_key_pair, account2->identity_key->sign_key_pair)) {
            if (!is_equal_keypair(account1->identity_key->sign_key_pair, account2->identity_key->sign_key_pair)) {
                printf("keypair not match");
                return false;
            }
        } else {
            if (!is_null(account1->identity_key->sign_key_pair, account2->identity_key->sign_key_pair)) {
                printf("keypair not match");
                return false;
            }
        }
    } else {
        if (!is_null(account1->identity_key, account2->identity_key)) {
            printf("keypair not match");
            return false;
        }
    }
    if (is_not_null(account1->signed_pre_key, account2->signed_pre_key)) {
        if (!is_equal_spk(account1->signed_pre_key, account2->signed_pre_key)) {
            printf("spk not match");
            return false;
        }
    } else {
        if (!is_null(account1->signed_pre_key, account2->signed_pre_key)) {
            printf("spk not match");
            return false;
        }
    }
    if (account1->n_one_time_pre_key_list != account2->n_one_time_pre_key_list) {
        printf("1: %zu\n", account1->n_one_time_pre_key_list);
        printf("2: %zu\n", account2->n_one_time_pre_key_list);
        printf("n_one_time_pre_key_list not match");
        return false;
    }
    size_t i;
    for (i = 0; i < account1->n_one_time_pre_key_list; i++) {
        if (!is_equal_opk(account1->one_time_pre_key_list[i], account2->one_time_pre_key_list[i])) {
            printf("1: %u\n", account1->one_time_pre_key_list[i]->opk_id);
            printf("2: %u\n", account2->one_time_pre_key_list[i]->opk_id);
            printf("%zu opk not match\n", i);
            return false;
        }
    }
    if (account1->next_one_time_pre_key_id != account2->next_one_time_pre_key_id) {
        printf("next_one_time_pre_key_id not match");
        return false;
    }

    return true;
}

bool is_equal_message_key(Skissm__MsgKey *message_key_1, Skissm__MsgKey *message_key_2) {
    if (message_key_1->index != message_key_2->index) {
        printf("index of message_key not match");
        return false;
    }
    if (!is_equal_data(&(message_key_1->derived_key), &(message_key_2->derived_key))) {
        printf("derived_key not match");
        return false;
    }

    return true;
}

bool is_equal_chain(Skissm__ChainKey *chain_key_1, Skissm__ChainKey *chain_key_2) {
    if (chain_key_1->index != chain_key_2->index) {
        printf("index of chain_key not match");
        return false;
    }
    if (!is_equal_data(&(chain_key_1->shared_key), &(chain_key_2->shared_key))) {
        printf("shared_key not match");
        return false;
    }

    return true;
}

bool is_equal_sender_chain(Skissm__SenderChainNode *sender_chain_1, Skissm__SenderChainNode *sender_chain_2) {
    if (!is_equal_data(&(sender_chain_1->our_ratchet_public_key), &(sender_chain_2->our_ratchet_public_key))) {
        printf("our_ratchet_public_key not match");
        return false;
    }
    if (!is_equal_data(&(sender_chain_1->their_ratchet_public_key), &(sender_chain_2->their_ratchet_public_key))) {
        printf("their_ratchet_public_key not match");
        return false;
    }
    if (is_not_null(sender_chain_1->chain_key, sender_chain_2->chain_key)) {
        if (!is_equal_chain(sender_chain_1->chain_key, sender_chain_2->chain_key)) {
            printf("chain_key not match");
            return false;
        }
    } else {
        if (!is_null(sender_chain_1->chain_key, sender_chain_2->chain_key)) {
            printf("chain_key not match");
            return false;
        }
    }

    return true;
}

bool is_equal_receiver_chain(Skissm__ReceiverChainNode *receiver_chain_node_1, Skissm__ReceiverChainNode *receiver_chain_node_2) {
    if (!is_equal_data(&(receiver_chain_node_1->their_ratchet_public_key), &(receiver_chain_node_2->their_ratchet_public_key))) {
        printf("their_ratchet_public_key not match");
        return false;
    }
    if (!is_equal_data(&(receiver_chain_node_1->our_ratchet_private_key), &(receiver_chain_node_2->our_ratchet_private_key))) {
        printf("our_ratchet_private_key not match");
        return false;
    }
    if (is_not_null(receiver_chain_node_1->chain_key, receiver_chain_node_2->chain_key)) {
        if (!is_equal_chain(receiver_chain_node_1->chain_key, receiver_chain_node_2->chain_key)) {
            printf("chain_key not match");
            return false;
        }
    } else {
        if (!is_null(receiver_chain_node_1->chain_key, receiver_chain_node_2->chain_key)) {
            printf("chain_key not match");
            return false;
        }
    }

    return true;
}

bool is_equal_skipped_message_key(Skissm__SkippedMsgKeyNode *skipped_msg_key_node_1, Skissm__SkippedMsgKeyNode *skipped_msg_key_node_2) {
    if (!is_equal_data(&(skipped_msg_key_node_1->ratchet_key_public), &(skipped_msg_key_node_2->ratchet_key_public))) {
        printf("ratchet_key_public not match");
        return false;
    }
    if (is_not_null(skipped_msg_key_node_1->msg_key, skipped_msg_key_node_2->msg_key)) {
        if (!is_equal_message_key(skipped_msg_key_node_1->msg_key, skipped_msg_key_node_2->msg_key)) {
            printf("message_key not match");
            return false;
        }
    } else {
        if (!is_null(skipped_msg_key_node_1->msg_key, skipped_msg_key_node_2->msg_key)) {
            printf("message_key not match");
            return false;
        }
    }

    return true;
}

bool is_equal_ratchet(Skissm__Ratchet *ratchet_1, Skissm__Ratchet *ratchet_2) {
    if (!is_equal_data(&(ratchet_1->root_key), &(ratchet_2->root_key))) {
        printf("root_key not match");
        return false;
    }
    if (ratchet_1->root_sequence != ratchet_2->root_sequence) {
        printf("root_sequence not match");
        return false;
    }
    if (is_not_null(ratchet_1->sender_chain, ratchet_2->sender_chain)) {
        if (!is_equal_sender_chain(ratchet_1->sender_chain, ratchet_2->sender_chain)) {
            printf("sender_chain not match");
            return false;
        }
    } else {
        if (!is_null(ratchet_1->sender_chain, ratchet_2->sender_chain)) {
            printf("sender_chain not match");
            return false;
        }
    }
    if (!is_equal_receiver_chain(ratchet_1->receiver_chain, ratchet_2->receiver_chain)) {
        printf("receiver_chain not match");
        return false;
    }
    if (ratchet_1->n_skipped_msg_key_list != ratchet_2->n_skipped_msg_key_list) {
        printf("n_skipped_msg_key_list not match");
        return false;
    }
    size_t i;
    for (i = 0; i < ratchet_1->n_skipped_msg_key_list; i++) {
        if (!is_equal_skipped_message_key(ratchet_1->skipped_msg_key_list[i], ratchet_2->skipped_msg_key_list[i])) {
            printf("skipped_msg_key_list not match");
            return false;
        }
    }

    return true;
}

bool is_equal_session(Skissm__Session *session_1, Skissm__Session *session_2) {
    if (!safe_strcmp(session_1->version, session_2->version)) {
        printf("version not match");
        return false;
    }
    if (!safe_strcmp(session_1->session_id, session_2->session_id)) {
        printf("session_id not match");
        return false;
    }
    if (is_not_null(session_1->our_address, session_2->our_address)) {
        if (!compare_address(session_1->our_address, session_2->our_address)) {
            printf("our_address not match");
            return false;
        }
    } else {
        if (!is_null(session_1->our_address, session_2->our_address)) {
            printf("our_address not match");
            return false;
        }
    }
    if (is_not_null(session_1->their_address, session_2->their_address)) {
        if (!compare_address(session_1->their_address, session_2->their_address)) {
            printf("their_address not match");
            return false;
        }
    } else {
        if (!is_null(session_1->their_address, session_2->their_address)) {
            printf("their_address not match");
            return false;
        }
    }
    if (session_1->n_pre_shared_input_list != session_2->n_pre_shared_input_list) {
        printf("n_pre_shared_input_list not match");
        return false;
    }
    size_t i;
    for (i = 0; i < session_1->n_pre_shared_input_list; i++) {
        if (!is_equal_data(&(session_1->pre_shared_input_list[i]), &(session_2->pre_shared_input_list[i]))) {
            printf("pre_shared_input_list not match");
            return false;
        }
    }
    if (!is_equal_data(&(session_1->associated_data), &(session_2->associated_data))) {
        printf("associated_data not match");
        return false;
    }

    return true;
}

bool is_equal_sessions(Skissm__Session **sessions_1, Skissm__Session **sessions_2, size_t session_num) {
    size_t i;
    for (i = 0; i < session_num; i++) {
        if (is_equal_session(sessions_1[i], sessions_2[i]) == false) {
            return false;
        }
    }

    return true;
}

bool is_equal_group_session(Skissm__GroupSession *group_session_1, Skissm__GroupSession *group_session_2) {
    if (!safe_strcmp(group_session_1->version, group_session_2->version)) {
        printf("version not match");
        return false;
    }
    if (!safe_strcmp(group_session_1->session_id, group_session_2->session_id)) {
        printf("session_id not match");
        return false;
    }
    if (is_not_null(group_session_1->session_owner, group_session_2->session_owner)) {
        if (!compare_address(group_session_1->session_owner, group_session_2->session_owner)) {
            printf("session_owner not match");
            return false;
        }
    } else {
        if (!is_null(group_session_1->session_owner, group_session_2->session_owner)) {
            printf("session_owner not match");
            return false;
        }
    }
    if (is_not_null(group_session_1->group_info, group_session_2->group_info) && is_not_null(group_session_1->group_info->group_address, group_session_2->group_info->group_address)) {
        if (!compare_address(group_session_1->group_info->group_address, group_session_2->group_info->group_address)) {
            printf("group_address not match");
            return false;
        }
    } else {
        if (!is_null(group_session_1->group_info, group_session_2->group_info)) {
            printf("group_address not match");
            return false;
        }
    }
    if (!is_equal_data(&(group_session_1->chain_key), &(group_session_2->chain_key))) {
        printf("chain_key not match");
        return false;
    }
    if (!is_equal_data(&(group_session_1->group_seed), &(group_session_2->group_seed))) {
        printf("group_seed not match");
        return false;
    }
    if (!is_equal_data(&(group_session_1->associated_data), &(group_session_2->associated_data))) {
        printf("associated_data not match");
        return false;
    }

    return true;
}

void mock_data(ProtobufCBinaryData *to, const char *from) {
    size_t from_len = strlen(from);
    to->data = (uint8_t *)malloc(from_len);
    memcpy(to->data, from, from_len);
    to->len = from_len;
}

void mock_string(char **to, const char *from) {
    size_t from_len = sizeof(from);
    *to = (char *)malloc(from_len);
    memcpy(*to, from, from_len);
}

void mock_address(Skissm__E2eeAddress **address, const char *user_id, const char *domain, const char *device_id) {
    *address = malloc(sizeof(Skissm__E2eeAddress));
    skissm__e2ee_address__init(*address);
    (*address)->user = (Skissm__PeerUser *)malloc(sizeof(Skissm__PeerUser));
    skissm__peer_user__init((*address)->user);
    (*address)->peer_case = SKISSM__E2EE_ADDRESS__PEER_USER;
    (*address)->domain = strdup(domain);
    (*address)->user->user_name = strdup(user_id);
    (*address)->user->user_id = strdup(user_id);
    (*address)->user->device_id = strdup(device_id);
}

char *mock_domain_str() {
    char *domain_str = strdup(E2EELAB_DOMAIN);
    return domain_str;
}

void mock_random_user_address(Skissm__E2eeAddress **address) {
    *address = (Skissm__E2eeAddress *)malloc(sizeof(Skissm__E2eeAddress));
    skissm__e2ee_address__init(*address);
    (*address)->user = (Skissm__PeerUser *)malloc(sizeof(Skissm__PeerUser));
    skissm__peer_user__init((*address)->user);
    (*address)->peer_case = SKISSM__E2EE_ADDRESS__PEER_USER;
    (*address)->domain = mock_domain_str();
    (*address)->user->user_id = generate_uuid_str();
    (*address)->user->device_id = generate_uuid_str();
}

void mock_random_group_address(Skissm__E2eeAddress **address) {
    *address = (Skissm__E2eeAddress *)malloc(sizeof(Skissm__E2eeAddress));
    skissm__e2ee_address__init(*address);
    (*address)->group = (Skissm__PeerGroup *)malloc(sizeof(Skissm__PeerGroup));
    skissm__peer_group__init((*address)->group);
    (*address)->peer_case = SKISSM__E2EE_ADDRESS__PEER_GROUP;
    (*address)->domain = mock_domain_str();
    (*address)->group->group_id = generate_uuid_str();
}

void mock_keypair(Skissm__KeyPair **keypair, const char *public_key, const char *private_key) {
    *keypair = malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(*keypair);

    mock_data(&((*keypair)->public_key), public_key);
    mock_data(&((*keypair)->private_key), private_key);
}

void mock_identity_keypair(Skissm__IdentityKey **identity_keypair, const char *public_key, const char *private_key) {
    *identity_keypair = malloc(sizeof(Skissm__IdentityKey));
    skissm__identity_key__init(*identity_keypair);
    mock_keypair(&((*identity_keypair)->asym_key_pair), public_key, private_key);
    mock_keypair(&((*identity_keypair)->sign_key_pair), public_key, private_key);
}

void mock_signed_pre_keypair(Skissm__SignedPreKey **signed_pre_keypair, uint32_t spk_id, const char *public_key, const char *private_key, const char *signature) {
    *signed_pre_keypair = malloc(sizeof(Skissm__SignedPreKey));
    skissm__signed_pre_key__init(*signed_pre_keypair);
    mock_data(&((*signed_pre_keypair)->signature), signature);
    mock_keypair(&((*signed_pre_keypair)->key_pair), public_key, private_key);
    (*signed_pre_keypair)->spk_id = spk_id;
}

void mock_one_time_pre_keypair(Skissm__OneTimePreKey **one_time_pre_keypair, uint32_t opk_id, protobuf_c_boolean used, const char *public_key, const char *private_key) {
    *one_time_pre_keypair = malloc(sizeof(Skissm__OneTimePreKey));
    skissm__one_time_pre_key__init(*one_time_pre_keypair);
    mock_keypair(&((*one_time_pre_keypair)->key_pair), public_key, private_key);
    (*one_time_pre_keypair)->opk_id = opk_id;
    (*one_time_pre_keypair)->used = used;
}

void free_account(Skissm__Account *account) {
    skissm__account__free_unpacked(account, NULL);
    account = NULL;
}

void free_keypair(Skissm__KeyPair *keypair) {
    skissm__key_pair__free_unpacked(keypair, NULL);
    keypair = NULL;
}

void free_signed_pre_keypair(Skissm__SignedPreKey *signed_pre_key) {
    skissm__signed_pre_key__free_unpacked(signed_pre_key, NULL);
    signed_pre_key = NULL;
}

void free_one_time_pre_key_pair(Skissm__OneTimePreKey *one_time_pre_key) {
    skissm__one_time_pre_key__free_unpacked(one_time_pre_key, NULL);
    one_time_pre_key = NULL;
}

void free_address(Skissm__E2eeAddress *address) {
    skissm__e2ee_address__free_unpacked(address, NULL);
    address = NULL;
}
