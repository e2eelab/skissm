#ifndef SAFE_CHECK_H_
#define SAFE_CHECK_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm/skissm.h"

bool accurate_key_pair(const Skissm__KeyPair *key_pair, uint32_t pub_key_len, uint32_t priv_key_len);

bool safe_cipher_suite(const cipher_suite_t *cipher_suite);

bool safe_e2ee_pack_id(const uint32_t e2ee_pack_id);

bool safe_protobuf(const ProtobufCBinaryData *src);

bool safe_protobuf_list(const ProtobufCBinaryData *src, size_t len);

bool nonempty_string(const char *src);

bool safe_address(const Skissm__E2eeAddress *src);

bool safe_address_list(const Skissm__E2eeAddress **src, size_t len);

bool safe_key_pair(const Skissm__KeyPair *src);

bool safe_identity_key(const Skissm__IdentityKey *src);

bool safe_signed_pre_key(const Skissm__SignedPreKey *src);

bool safe_one_time_pre_key_list(const Skissm__OneTimePreKey **src, size_t len);

bool safe_unregistered_account(const Skissm__Account *src);

bool safe_registered_account(const Skissm__Account *src);

bool safe_msg_key(const Skissm__MsgKey *msg_key);

bool safe_chain_key(const Skissm__ChainKey *chain_key);

bool safe_sender_chain(const Skissm__SenderChainNode *sender_chain);

bool safe_receiver_chain(const Skissm__ReceiverChainNode *receiver_chain);

bool safe_skipped_msg_key_node(const Skissm__SkippedMsgKeyNode *skipped_msg_key_node);

bool safe_skipped_msg_key_list(
    const Skissm__SkippedMsgKeyNode **skipped_msg_key_list,
    size_t skipped_msg_key_list_len
);

bool safe_ratchet(const Skissm__Ratchet *ratchet);

bool safe_uncompleted_session(const Skissm__Session *src);

bool safe_completed_session(const Skissm__Session *src);

bool safe_identity_key_public(const Skissm__IdentityKeyPublic *src);

bool safe_signed_pre_key_public(const Skissm__SignedPreKeyPublic *src);

bool safe_one_time_pre_key_public(const Skissm__OneTimePreKeyPublic *src);

bool safe_pre_key_bundle(const Skissm__PreKeyBundle *src);

bool safe_pre_key_bundle_list(const Skissm__PreKeyBundle **src, size_t len);

bool safe_one2one_msg_payload(const Skissm__One2oneMsgPayload *payload);

bool safe_group_member(const Skissm__GroupMember *src);

bool safe_group_member_list(const Skissm__GroupMember **src, size_t len);

bool safe_group_info(const Skissm__GroupInfo *src);

bool safe_group_info_list(const Skissm__GroupInfo **src, size_t len);

bool safe_register_user_response(const Skissm__RegisterUserResponse *src);

bool safe_get_pre_key_bundle_response(const Skissm__GetPreKeyBundleResponse *src);

bool safe_invite_response(const Skissm__InviteResponse *src);

bool safe_accept_response(const Skissm__AcceptResponse *src);

#ifdef __cplusplus
}
#endif

#endif /* SAFE_CHECK_H_ */
