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
#ifndef SKISSM_H_
#define SKISSM_H_

#include <stdint.h>
#include <stdlib.h>

#include "skissm/AcceptMsg.pb-c.h"
#include "skissm/AcceptRequest.pb-c.h"
#include "skissm/AcceptResponse.pb-c.h"
#include "skissm/Account.pb-c.h"
#include "skissm/AddGroupMembersMsg.pb-c.h"
#include "skissm/AddGroupMembersRequest.pb-c.h"
#include "skissm/AddGroupMembersResponse.pb-c.h"
#include "skissm/ChainKey.pb-c.h"
#include "skissm/ConsumeProtoMsgRequest.pb-c.h"
#include "skissm/ConsumeProtoMsgResponse.pb-c.h"
#include "skissm/CreateGroupMsg.pb-c.h"
#include "skissm/CreateGroupRequest.pb-c.h"
#include "skissm/CreateGroupResponse.pb-c.h"
#include "skissm/E2eeAddress.pb-c.h"
#include "skissm/E2eeMsg.pb-c.h"
#include "skissm/GetGroupRequest.pb-c.h"
#include "skissm/GetGroupResponse.pb-c.h"
#include "skissm/GetPreKeyBundleRequest.pb-c.h"
#include "skissm/GetPreKeyBundleResponse.pb-c.h"
#include "skissm/GroupMsgPayload.pb-c.h"
#include "skissm/GroupPreKeyPayload.pb-c.h"
#include "skissm/GroupSession.pb-c.h"
#include "skissm/IdentityKey.pb-c.h"
#include "skissm/IdentityKeyPublic.pb-c.h"
#include "skissm/InviteMsg.pb-c.h"
#include "skissm/InviteRequest.pb-c.h"
#include "skissm/InviteResponse.pb-c.h"
#include "skissm/KeyPair.pb-c.h"
#include "skissm/MsgKey.pb-c.h"
#include "skissm/One2oneMsgPayload.pb-c.h"
#include "skissm/OneTimePreKey.pb-c.h"
#include "skissm/OneTimePreKeyPublic.pb-c.h"
#include "skissm/PendingGroupPreKey.pb-c.h"
#include "skissm/Plaintext.pb-c.h"
#include "skissm/PreKeyBundle.pb-c.h"
#include "skissm/ProtoMsg.pb-c.h"
#include "skissm/PublishSpkRequest.pb-c.h"
#include "skissm/PublishSpkResponse.pb-c.h"
#include "skissm/Ratchet.pb-c.h"
#include "skissm/ReceiverChainNode.pb-c.h"
#include "skissm/RegisterUserRequest.pb-c.h"
#include "skissm/RegisterUserResponse.pb-c.h"
#include "skissm/RemoveGroupMembersMsg.pb-c.h"
#include "skissm/RemoveGroupMembersRequest.pb-c.h"
#include "skissm/RemoveGroupMembersResponse.pb-c.h"
#include "skissm/SendGroupMsgRequest.pb-c.h"
#include "skissm/SendGroupMsgResponse.pb-c.h"
#include "skissm/SendOne2oneMsgRequest.pb-c.h"
#include "skissm/SendOne2oneMsgResponse.pb-c.h"
#include "skissm/SenderChainNode.pb-c.h"
#include "skissm/Session.pb-c.h"
#include "skissm/SignedPreKey.pb-c.h"
#include "skissm/SignedPreKeyPublic.pb-c.h"
#include "skissm/SkippedMsgKeyNode.pb-c.h"
#include "skissm/SupplyOpksMsg.pb-c.h"
#include "skissm/SupplyOpksRequest.pb-c.h"
#include "skissm/SupplyOpksResponse.pb-c.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm/session.h"
#include "skissm/cipher.h"
#include "skissm/error.h"

#define PROTOCOL_VERSION 0x01
#define GROUP_VERSION 0x01
#define PLAINTEXT_VERSION 0x01
#define UUID_LEN 16
#define SIGNED_PRE_KEY_EXPIRATION 604800

typedef struct e2ee_pack_t {
    uint32_t e2ee_pack_id;
    const struct cipher_suite_t *cipher_suite;
    const struct session_suite_t *session_suite;
} e2ee_pack_t;

struct e2ee_pack_list_t {
  const struct e2ee_pack_t *e2ee_pack_0;
  const struct e2ee_pack_t *e2ee_pack_1;
};

typedef struct crypto_param_t {
    uint32_t asym_key_len;
    uint32_t sign_key_len;
    uint32_t sig_len;
    uint32_t hash_len;
    uint32_t aead_key_len;
    uint32_t aead_iv_len;
    uint32_t aead_tag_len;
} crypto_param_t;

typedef struct skissm_common_handler_t {
    int64_t (*handle_get_ts)();
    void (*handle_gen_rand)(uint8_t *, size_t);
    void (*handle_gen_uuid)(uint8_t uuid[UUID_LEN]);
    int (*handle_send)(uint8_t *, size_t);
} skissm_common_handler_t;

typedef struct skissm_db_handler_t {
    // account related handlers
    /**
     * @brief store account to db
     * @param account
     */
    void (*store_account)(Skissm__Account *);
    /**
     * @brief load account from db
     * @param account_id
     * @param account
     */
    void (*load_account)(uint64_t, Skissm__Account **);
    /**
     * @brief load all accounts from db
     * @param accounts
     * @return number of loaded accounts
     */
    size_t (*load_accounts)(Skissm__Account ***);
    /**
     * @brief load account from db by giving address
     * @param address
     * @param account
     */
    void (*load_account_by_address)(Skissm__E2eeAddress *,
                                    Skissm__Account **);
    /**
     * @brief update identity key of account to db
     * @param account_id
     * @param identity_key
     */
    void (*update_identity_key)(uint64_t, Skissm__IdentityKey *);
    /**
     * @brief update signed pre key of account to db
     * @param account_id
     * @param signed_pre_key
     */
    void (*update_signed_pre_key)(uint64_t, Skissm__SignedPreKey *);
    /**
     * @brief load old signed pre key by spk_id
     * @param account_id
     * @param spk_id
     * @param signed_pre_key
     */
    void (*load_signed_pre_key)(uint64_t, uint32_t, Skissm__SignedPreKey **);
    /**
     * @brief remove expired signed pre key of account from db
     * @param account_id
     */
    void (*remove_expired_signed_pre_key)(uint64_t);
    /**
     * @brief update address of account to db
     * @param account_id
     * @param address
     */
    void (*update_address)(uint64_t, Skissm__E2eeAddress *);
    /**
     * @brief add an one time pre key of account to db
     * @param account_id
     * @param one_time_pre_key
     */
    void (*add_one_time_pre_key)(uint64_t,
                                 Skissm__OneTimePreKey *);
    /**
     * @brief remove an one time pre key of account to db
     * @param account_id
     * @param one_time_pre_key_id
     */
    void (*remove_one_time_pre_key)(uint64_t, uint32_t);
    /**
     * @brief update an one time pre key of acount from db
     * @param account_id
     * @param one_time_pre_key_id
     */
    void (*update_one_time_pre_key)(uint64_t, uint32_t);

    // session related handlers
    /**
     * @brief find inbound session
     * @param session_id
     * @param owner
     * @param inbound_session
     */
    void (*load_inbound_session)(char *, Skissm__E2eeAddress *,
                                 Skissm__Session **);
    /**
     * @brief find outbound session
     * @param owner
     * @param to
     * @param outbound_session
     */
    void (*load_outbound_session)(Skissm__E2eeAddress *,
                                  Skissm__E2eeAddress *,
                                  Skissm__Session **);
    /**
     * @brief store session
     * @param session
     */
    void (*store_session)(Skissm__Session *);
    /**
     * @brief delete old inbound session
     * @param owner
     * @param from
     * @param to
     */
    void (*unload_session)(Skissm__E2eeAddress *, Skissm__E2eeAddress *,
                           Skissm__E2eeAddress *);

    // group session related handlers
    /**
     * @brief find outbound group session
     * @param sender_address
     * @param group_address
     * @param inbound_group_session
     */
    void (*load_outbound_group_session)(Skissm__E2eeAddress *,
                                        Skissm__E2eeAddress *,
                                        Skissm__GroupSession **);
    /**
     * @brief find inbound group session
     * @param receiver_address
     * @param group_address
     * @param outbound_group_session
     */
    void (*load_inbound_group_session)(Skissm__E2eeAddress *,
                                       Skissm__E2eeAddress *,
                                       Skissm__GroupSession **);
    /**
     * @brief store group session
     * @param group_session
     */
    void (*store_group_session)(Skissm__GroupSession *);
    /**
     * @brief delete group session
     * @param group_session
     */
    void (*unload_group_session)(Skissm__GroupSession *);
    /**
     * @brief delete old inbound group session
     * @param user_address
     * @param old_session_id
     */
    void (*unload_inbound_group_session)(Skissm__E2eeAddress *, char *);

    // group pre-key related handlers
    /**
     * @brief store group pre-key
     * @param member_address
     * @param group_pre_key_plaintext
     * @param group_pre_key_plaintext_len
     */
    void (*store_group_pre_key)(Skissm__E2eeAddress *, uint8_t *, size_t);
    /**
     * @brief load group pre-keys
     * @param member_address
     * @param e2ee_plaintext_data_list
     * @param e2ee_plaintext_data_len_list
     * @return number of loaded group pre-keys
     */
    uint32_t (*load_group_pre_keys)(Skissm__E2eeAddress *, uint8_t ***, size_t **);
    /**
     * @brief delete group pre-key
     * @param member_address
     */
    void (*unload_group_pre_key)(Skissm__E2eeAddress *);
} skissm_db_handler_t;

typedef struct e2ee_proto_handler_t {
    /**
     * @brief send_register
     * @param request
     * @return response
     */
    Skissm__RegisterUserResponse * (*register_user)(Skissm__RegisterUserRequest *);

    Skissm__GetPreKeyBundleResponse * (*get_pre_key_bundle)(Skissm__GetPreKeyBundleRequest *);

    Skissm__InviteResponse * (*invite)(Skissm__InviteRequest *);

    Skissm__AcceptResponse * (*accept)(Skissm__AcceptRequest *);

    Skissm__PublishSpkResponse * (*publish_spk)(Skissm__PublishSpkRequest *);

    Skissm__SupplyOpksResponse * (*supply_opks)(Skissm__SupplyOpksRequest *);

    Skissm__SendOne2oneMsgResponse * (*send_one2one_msg)(Skissm__SendOne2oneMsgRequest *);

    Skissm__CreateGroupResponse * (*create_group)(Skissm__CreateGroupRequest *);

    Skissm__AddGroupMembersResponse * (*add_group_members)(Skissm__AddGroupMembersRequest *);

    Skissm__RemoveGroupMembersResponse * (*remove_group_members)(Skissm__RemoveGroupMembersRequest *);

    Skissm__SendGroupMsgResponse * (*send_group_msg)(Skissm__SendGroupMsgRequest *);

    Skissm__ConsumeProtoMsgResponse * (*consume_proto_msg)(Skissm__ConsumeProtoMsgRequest *);

} e2ee_proto_handler_t;

typedef struct skissm_event_handler_t {
    /**
     * @brief notify error
     * @param error_code
     * @param error_msg
     */
    void (*on_error)(ErrorCode, char *);
    /**
     * @brief notify user registered event
     * @param account
     */
    void (*on_user_registered)(Skissm__Account *);
    /**
     * @brief notify inbound session invited
     * @param from
     */
    void (*on_inbound_session_invited)(Skissm__E2eeAddress *);
    /**
     * @brief notify inbound session ready
     * @param inbound_session
     */
    void (*on_inbound_session_ready)(Skissm__Session *);
    /**
     * @brief notify outbound session ready
     * @param outbound_session
     */
    void (*on_outbound_session_ready)(Skissm__Session *);
    /**
     * @brief notify one2one msg received event
     * @param from_address
     * @param to_address
     * @param plaintext
     * @param plaintext_len
     */
    void (*on_one2one_msg_received)(Skissm__E2eeAddress *,
                                    Skissm__E2eeAddress *, uint8_t *, size_t);

    /**
     * @brief notify group msg received event
     * @param from_address
     * @param group_address
     * @param plaintext
     * @param plaintext_len
     */
    void (*on_group_msg_received)(Skissm__E2eeAddress *,
                                  Skissm__E2eeAddress *, uint8_t *, size_t);

    /**
     * @brief notify group created event
     * @param group_address
     * @param group_name
     */
    void (*on_group_created)(Skissm__E2eeAddress *, char *);

    /**
     * @brief notify group members added
     * @param group_address
     * @param group_name
     * @param member_addresses
     */
    void (*on_group_members_added)(Skissm__E2eeAddress *, char *, Skissm__E2eeAddress **);

    /**
     * @brief notify group members removed
     * @param group_address
     * @param group_name
     * @param member_addresses
     */
    void (*on_group_members_removed)(Skissm__E2eeAddress *, char *, Skissm__E2eeAddress **);
} skissm_event_handler_t;

typedef struct skissm_plugin_t {
    skissm_common_handler_t common_handler;
    skissm_db_handler_t db_handler;
    e2ee_proto_handler_t proto_handler;
    skissm_event_handler_t event_handler;
} skissm_plugin_t;

const e2ee_pack_t *get_e2ee_pack(uint32_t e2ee_pack_id);

void skissm_begin(skissm_plugin_t *ssm_plugin);

void skissm_end();

skissm_plugin_t *get_skissm_plugin();

void ssm_notify_error(ErrorCode, char *);
void ssm_notify_user_registered(Skissm__Account *account);
void ssm_notify_inbound_session_invited(Skissm__E2eeAddress *from);
void ssm_notify_inbound_session_ready(Skissm__Session *inbound_session);
void ssm_notify_outbound_session_ready(Skissm__Session *outbound_session);
void ssm_notify_one2one_msg(Skissm__E2eeAddress *from_address,
                            Skissm__E2eeAddress *to_address, uint8_t *plaintext,
                            size_t plaintext_len);
void ssm_notify_group_msg(Skissm__E2eeAddress *from_address,
                          Skissm__E2eeAddress *group_address, uint8_t *plaintext,
                          size_t plaintext_len);
void ssm_notify_group_created(Skissm__E2eeAddress *group_address, char *group_name);
void ssm_notify_group_members_added(Skissm__E2eeAddress *group_address,
                                    char *group_name,
                                    Skissm__E2eeAddress **member_addresses);
void ssm_notify_group_members_removed(Skissm__E2eeAddress *group_address,
                                      char *group_name,
                                      Skissm__E2eeAddress **member_addresses);

#ifdef __cplusplus
}
#endif

#endif /* SKISSM_H_ */
