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
#include "skissm/AddGroupMemberDeviceMsg.pb-c.h"
#include "skissm/AddGroupMemberDeviceRequest.pb-c.h"
#include "skissm/AddGroupMemberDeviceResponse.pb-c.h"
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
#include "skissm/GroupMember.pb-c.h"
#include "skissm/GroupMemberInfo.pb-c.h"
#include "skissm/GroupMsgPayload.pb-c.h"
#include "skissm/GroupPreKeyBundle.pb-c.h"
#include "skissm/GroupUpdateKeyBundle.pb-c.h"
#include "skissm/GroupSession.pb-c.h"
#include "skissm/IdentityKey.pb-c.h"
#include "skissm/IdentityKeyPublic.pb-c.h"
#include "skissm/InviteMsg.pb-c.h"
#include "skissm/InviteRequest.pb-c.h"
#include "skissm/InviteResponse.pb-c.h"
#include "skissm/KeyPair.pb-c.h"
#include "skissm/LeaveGroupMsg.pb-c.h"
#include "skissm/LeaveGroupRequest.pb-c.h"
#include "skissm/LeaveGroupResponse.pb-c.h"
#include "skissm/MsgKey.pb-c.h"
#include "skissm/NewUserDeviceMsg.pb-c.h"
#include "skissm/NotifLevel.pb-c.h"
#include "skissm/One2oneMsgPayload.pb-c.h"
#include "skissm/OneTimePreKey.pb-c.h"
#include "skissm/OneTimePreKeyPublic.pb-c.h"
#include "skissm/PendingRequest.pb-c.h"
#include "skissm/Plaintext.pb-c.h"
#include "skissm/PreKeyBundle.pb-c.h"
#include "skissm/ProtoMsg.pb-c.h"
#include "skissm/ProtoMsgTag.pb-c.h"
#include "skissm/PublishSpkRequest.pb-c.h"
#include "skissm/PublishSpkResponse.pb-c.h"
#include "skissm/Ratchet.pb-c.h"
#include "skissm/ReceiverChainNode.pb-c.h"
#include "skissm/RegisterUserRequest.pb-c.h"
#include "skissm/RegisterUserResponse.pb-c.h"
#include "skissm/RemoveGroupMembersMsg.pb-c.h"
#include "skissm/RemoveGroupMembersRequest.pb-c.h"
#include "skissm/RemoveGroupMembersResponse.pb-c.h"
#include "skissm/ResponseCode.pb-c.h"
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
#include "skissm/UserDevicesBundle.pb-c.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm/cipher.h"
#include "skissm/log_code.h"
#include "skissm/session.h"

#define E2EE_PROTOCOL_VERSION           "E2EE_PROTOCOL_v1.0"
#define E2EE_PLAINTEXT_VERSION          "E2EE_PLAINTEXT_v1.0"
#define UUID_LEN 16
#define SIGNED_PRE_KEY_EXPIRATION_MS    604800000       // 7 days
#define INVITE_WAITING_TIME_MS          60000           // 1 minute

#define E2EE_PACK_ALG_DIGITAL_SIGNATURE_CURVE25519           0
#define E2EE_PACK_ALG_DIGITAL_SIGNATURE_DILITHIUM2           1
#define E2EE_PACK_ALG_DIGITAL_SIGNATURE_DILITHIUM3           9
#define E2EE_PACK_ALG_DIGITAL_SIGNATURE_DILITHIUM5           17
#define E2EE_PACK_ALG_DIGITAL_SIGNATURE_FALCON512            33
#define E2EE_PACK_ALG_DIGITAL_SIGNATURE_FALCON1024           41
#define E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_128F    65
#define E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_128S    69
#define E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_192F    73
#define E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_192S    77
#define E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_256F    81
#define E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_256S    85
#define E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHAKE_128F   89
#define E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHAKE_128S   93
#define E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHAKE_192F   97
#define E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHAKE_192S   101
#define E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHAKE_256F   105
#define E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHAKE_256S   109

#define E2EE_PACK_ALG_KEM_CURVE25519                         0
#define E2EE_PACK_ALG_KEM_HQC128                             1
#define E2EE_PACK_ALG_KEM_HQC192                             9
#define E2EE_PACK_ALG_KEM_HQC256                             17
#define E2EE_PACK_ALG_KEM_KYBER512                           33
#define E2EE_PACK_ALG_KEM_KYBER768                           41
#define E2EE_PACK_ALG_KEM_KYBER1024                          49
#define E2EE_PACK_ALG_KEM_MCELIECE348864                     65
#define E2EE_PACK_ALG_KEM_MCELIECE348864F                    69
#define E2EE_PACK_ALG_KEM_MCELIECE460896                     73
#define E2EE_PACK_ALG_KEM_MCELIECE460896F                    77
#define E2EE_PACK_ALG_KEM_MCELIECE6688128                    81
#define E2EE_PACK_ALG_KEM_MCELIECE6688128F                   85
#define E2EE_PACK_ALG_KEM_MCELIECE6960119                    89
#define E2EE_PACK_ALG_KEM_MCELIECE6960119F                   93
#define E2EE_PACK_ALG_KEM_MCELIECE8192128                    97
#define E2EE_PACK_ALG_KEM_MCELIECE8192128F                   101

#define E2EE_PACK_ALG_SYMMETRIC_ENCRYPTION_AES256_SHA256     1

#define CIPHER_SUITE_PART_LEN_IN_BITS 8

typedef struct e2ee_pack_id_t {
    unsigned ver:CIPHER_SUITE_PART_LEN_IN_BITS;
    unsigned digital_signature:CIPHER_SUITE_PART_LEN_IN_BITS;
    unsigned kem:CIPHER_SUITE_PART_LEN_IN_BITS;
    unsigned symmetric_encryption:CIPHER_SUITE_PART_LEN_IN_BITS;
} e2ee_pack_id_t;

/**
 * @brief Type definition of end-to-end encryption pack.
 *        A e2ee_pack consists of cipher suite and session suite.
 */
typedef struct e2ee_pack_t {
    struct cipher_suite_t *cipher_suite;
    struct session_suite_t *session_suite;
} e2ee_pack_t;

typedef struct crypto_digital_signature_param_t {
    bool pqc_param;
    uint32_t sign_pub_key_len;
    uint32_t sign_priv_key_len;
    uint32_t sig_len;
} crypto_digital_signature_param_t;

typedef struct crypto_kem_param_t {
    bool pqc_param;
    uint32_t asym_pub_key_len;
    uint32_t asym_priv_key_len;
    uint32_t kem_ciphertext_len;
    uint32_t shared_secret_len;
} crypto_kem_param_t;

typedef struct crypto_symmetric_encryption_param_t {
    uint32_t hash_len;
    uint32_t aead_key_len;
    uint32_t aead_iv_len;
    uint32_t aead_tag_len;
} crypto_symmetric_encryption_param_t;

typedef struct skissm_common_handler_t {
    /**
     * @brief generate time stamp
     * @return current timestamp in milliseconds since 1970
     */
    int64_t (*gen_ts)();

    /**
     * @brief generate random number
     * @param rand_data pre-allocated memory to be filled with random data
     * @param rand_data_len length of random data
     */
    void (*gen_rand)(uint8_t *rand_data, size_t rand_data_len);
    void (*gen_uuid)(uint8_t uuid[UUID_LEN]);
} skissm_common_handler_t;

typedef struct skissm_db_handler_t {
    // account related handlers
    /**
     * @brief store account to db
     * @param account
     */
    void (*store_account)(
        Skissm__Account *account
    );
    /**
     * @brief load account from db by giving user address
     * @param user_address
     * @param account
     */
    void (*load_account_by_address)(
        Skissm__E2eeAddress *user_address,
        Skissm__Account **account
    );
    /**
     * @brief load all accounts from db
     * @param accounts
     * @return number of loaded accounts
     */
    size_t (*load_accounts)(
        Skissm__Account ***accounts
    );
    /**
     * @brief update signed pre-key of account to db
     * @param user_address
     * @param signed_pre_key
     */
    bool (*update_signed_pre_key)(
        Skissm__E2eeAddress *user_address,
        Skissm__SignedPreKey *signed_pre_key
    );
    /**
     * @brief load old signed pre-key by spk_id
     * @param user_address
     * @param spk_id
     * @param signed_pre_key
     */
    void (*load_signed_pre_key)(
        Skissm__E2eeAddress *user_address,
        uint32_t spk_id,
        Skissm__SignedPreKey **signed_pre_key
    );
    /**
     * @brief remove expired signed pre-key (keep last two) of account from db
     * @param user_address
     */
    bool (*remove_expired_signed_pre_key)(
        Skissm__E2eeAddress *user_address
    );
    /**
     * @brief add an one time pre-key of account to db
     * @param user_address
     * @param one_time_pre_key
     */
    bool (*add_one_time_pre_key)(
        Skissm__E2eeAddress *user_address,
        Skissm__OneTimePreKey *one_time_pre_key
    );
    /**
     * @brief remove an one time pre-key of account to db
     * @param user_address
     * @param one_time_pre_key_id
     */
    bool (*remove_one_time_pre_key)(
        Skissm__E2eeAddress *user_address,
        uint32_t one_time_pre_key_id
    );
    /**
     * @brief update an one time pre-key of acount from db
     * @param user_address
     * @param one_time_pre_key_id
     */
    bool (*update_one_time_pre_key)(
        Skissm__E2eeAddress *user_address,
        uint32_t one_time_pre_key_id
    );
    /**
     * @brief load auth from the account given by the user address
     * @param user_address
     * @param auth
     */
    void (*load_auth)(
        Skissm__E2eeAddress *user_address,
        char **auth
    );
    // session related handlers
    /**
     * @brief find inbound session
     * @param session_id
     * @param our_address
     * @param inbound_session
     */
    void (*load_inbound_session)(
        char *session_id,
        Skissm__E2eeAddress *our_address,
        Skissm__Session **inbound_session
    );
    /**
     * @brief find the lastest outbound session
     * @param our_address
     * @param their_address
     * @param outbound_session
     */
    void (*load_outbound_session)(
        Skissm__E2eeAddress *our_address,
        Skissm__E2eeAddress *their_address,
        Skissm__Session **outbound_session
    );

    /**
     * @brief find the list of outbound sessions that are related to their_user_id and their_domain
     * @param our_address
     * @param their_user_id
     * @param their_domain
     * @param outbound_sessions
     */
    size_t (*load_outbound_sessions)(
        Skissm__E2eeAddress *our_address,
        const char *their_user_id,
        const char *their_domain,
        Skissm__Session ***outbound_sessions
    );

    /**
     * @brief store session
     * @param session
     */
    void (*store_session)(
        Skissm__Session *session
    );
    /**
     * @brief delete all sessions
     * @param our_address
     * @param their_address
     */
    void (*unload_session)(
        Skissm__E2eeAddress *our_address,
        Skissm__E2eeAddress *their_address
    );
    /**
     * @brief delete old sessions that older tha
     * @param our_address
     * @param their_address
     */
    void (*unload_old_session)(
        Skissm__E2eeAddress *our_address,
        Skissm__E2eeAddress *their_address
    );

    // group session related handlers
    /**
     * @brief find a group session by address
     * @param sender_address
     * @param session_owner_address
     * @param group_address
     * @param group_session
     */
    void (*load_group_session_by_address)(
        Skissm__E2eeAddress *sender_address,
        Skissm__E2eeAddress *session_owner_address,
        Skissm__E2eeAddress *group_address,
        Skissm__GroupSession **group_session
    );
    /**
     * @brief find a group session by id
     * @param sender_address
     * @param session_owner_address
     * @param group_session_id
     * @param group_session
     */
    void (*load_group_session_by_id)(
        Skissm__E2eeAddress *sender_address,
        Skissm__E2eeAddress *session_owner_address,
        char *group_session_id,
        Skissm__GroupSession **group_session
    );
    /**
     * @brief load group sessions
     * @param session_owner_address
     * @param group_address
     * @param group_sessions
     */
    size_t (*load_group_sessions)(
        Skissm__E2eeAddress *session_owner_address,
        Skissm__E2eeAddress *group_address,
        Skissm__GroupSession ***group_sessions
    );
    /**
     * @brief load group addresses
     * @param sender_address
     * @param session_owner_address
     * @param group_addresses
     */
    size_t (*load_group_addresses)(
        Skissm__E2eeAddress *sender_address,
        Skissm__E2eeAddress *session_owner_address,
        Skissm__E2eeAddress ***group_addresses
    );
    /**
     * @brief store group session
     * @param group_session
     */
    void (*store_group_session)(
        Skissm__GroupSession *group_session
    );
    /**
     * @brief delete group sessions by address
     * @param session_owner_address
     * @param group_address
     */
    void (*unload_group_session_by_address)(
        Skissm__E2eeAddress *session_owner_address,
        Skissm__E2eeAddress *group_address
    );
    /**
     * @brief delete group sessions by session id
     * @param session_owner_address
     * @param group_session_id
     */
    void (*unload_group_session_by_id)(
        Skissm__E2eeAddress *session_owner_address,
        char *group_session_id
    );

    // pending plaintext related handlers
    /**
     * @brief store pending plaintext data
     * @param from_address
     * @param to_address
     * @param plaintext_id
     * @param plaintext_data
     * @param plaintext_data_len
     * @param notif_level
     */
    void (*store_pending_plaintext_data)(
        Skissm__E2eeAddress *from_address,
        Skissm__E2eeAddress *to_address,
        char *plaintext_id,
        uint8_t *plaintext_data,
        size_t plaintext_data_len,
        Skissm__NotifLevel notif_level
    );
    /**
     * @brief load pending plaintext data
     * @param from_address
     * @param to_address
     * @param plaintext_id_list
     * @param plaintext_data_list
     * @param plaintext_data_len_list
     * @param notif_level_list
     * @return number of loaded plaintext_data list
     */
    size_t (*load_pending_plaintext_data)(
        Skissm__E2eeAddress *from_address,
        Skissm__E2eeAddress *to_address,
        char ***plaintext_id_list,
        uint8_t ***plaintext_data_list,
        size_t **plaintext_data_len_list,
        Skissm__NotifLevel **notif_level_list
    );
    /**
     * @brief delete pending plaintext data
     * @param from_address
     * @param to_address
     * @param plaintext_id
     */
    void (*unload_pending_plaintext_data)(
        Skissm__E2eeAddress *from_address,
        Skissm__E2eeAddress *to_address,
        char *plaintext_id
    );
    /**
     * @brief store pending request data
     * @param user_address
     * @param request_id
     * @param request_type
     * @param request_data
     * @param request_data_len
     */
    void (*store_pending_request_data)(
        Skissm__E2eeAddress *user_address,
        char *request_id,
        uint8_t request_type,
        uint8_t *request_data,
        size_t request_data_len
    );
    /**
     * @brief load pending request data
     * @param user_address
     * @param request_id_list
     * @param request_type_list
     * @param request_data_list
     * @param request_data_len_list
     * @return number of loaded request_data list
     */
    size_t (*load_pending_request_data)(
        Skissm__E2eeAddress * user_address,
        char ***request_id_list,
        uint8_t **request_type_list,
        uint8_t ***request_data_list,
        size_t **request_data_len_list
    );
    /**
     * @brief delete pending request data
     * @param user_address
     * @param request_id
     */
    void (*unload_pending_request_data)(
        Skissm__E2eeAddress *user_address,
        char *request_id
    );
} skissm_db_handler_t;

typedef struct e2ee_proto_handler_t {
    /**
     * @brief Register user
     * @param request
     * @return response
     */
    Skissm__RegisterUserResponse *(*register_user)(
        Skissm__RegisterUserRequest *request
    );
    /**
     * @brief Get pre-key bundle
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__GetPreKeyBundleResponse *(*get_pre_key_bundle)(
        Skissm__E2eeAddress *from,
        const char *auth,
        Skissm__GetPreKeyBundleRequest *request
    );
    /**
     * @brief Invite
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__InviteResponse *(*invite)(
        Skissm__E2eeAddress *from,
        const char *auth,
        Skissm__InviteRequest *request
    );
    /**
     * @brief Accept
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__AcceptResponse *(*accept)(
        Skissm__E2eeAddress *from,
        const char *auth,
        Skissm__AcceptRequest *request
    );
    /**
     * @brief Publish signed pre-key
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__PublishSpkResponse *(*publish_spk)(
        Skissm__E2eeAddress *from,
        const char *auth,
        Skissm__PublishSpkRequest *request
    );
    /**
     * @brief Supply onetime pre-key
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__SupplyOpksResponse *(*supply_opks)(
        Skissm__E2eeAddress *from,
        const char *auth,
        Skissm__SupplyOpksRequest *request
    );
    /**
     * @brief Send one2one message
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__SendOne2oneMsgResponse *(*send_one2one_msg)(
        Skissm__E2eeAddress *from,
        const char *auth,
        Skissm__SendOne2oneMsgRequest *request
    );
    /**
     * @brief Create group
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__CreateGroupResponse *(*create_group)(
        Skissm__E2eeAddress *from,
        const char *auth,
        Skissm__CreateGroupRequest *request
    );
    /**
     * @brief Add group members
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__AddGroupMembersResponse *(*add_group_members)(
        Skissm__E2eeAddress *from,
        const char *auth,
        Skissm__AddGroupMembersRequest *request
    );
    /**
     * @brief Add group member device
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__AddGroupMemberDeviceResponse *(*add_group_member_device)(
        Skissm__E2eeAddress *from,
        const char *auth,
        Skissm__AddGroupMemberDeviceRequest *request
    );
    /**
     * @brief Remove group members
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__RemoveGroupMembersResponse *(*remove_group_members)(
        Skissm__E2eeAddress *from,
        const char *auth,
        Skissm__RemoveGroupMembersRequest *request
    );
    /**
     * @brief Leave group
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__LeaveGroupResponse *(*leave_group)(
        Skissm__E2eeAddress *from,
        const char *auth,
        Skissm__LeaveGroupRequest *request
    );
    /**
     * @brief Send group message
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__SendGroupMsgResponse *(*send_group_msg)(
        Skissm__E2eeAddress *from,
        const char *auth,
        Skissm__SendGroupMsgRequest *request
    );
    /**
     * @brief Consume a ProtoMsg
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__ConsumeProtoMsgResponse *(*consume_proto_msg)(
        Skissm__E2eeAddress *from,
        const char *auth,
        Skissm__ConsumeProtoMsgRequest *request
    );
} e2ee_proto_handler_t;

typedef struct skissm_event_handler_t {
    /**
     * @brief notify log msg
     * @param user_address
     * @param log_code
     * @param log_msg
     */
    void (*on_log)(
        Skissm__E2eeAddress *user_address,
        LogCode log_code,
        const char *log_msg
    );
    /**
     * @brief notify user registered event
     * @param account
     */
    void (*on_user_registered)(
        Skissm__Account *account
    );
    /**
     * @brief notify inbound session invited
     * @param user_address
     * @param from
     */
    void (*on_inbound_session_invited)(
        Skissm__E2eeAddress *user_address,
        Skissm__E2eeAddress *from
    );
    /**
     * @brief notify inbound session ready
     * @param user_address
     * @param inbound_session
     */
    void (*on_inbound_session_ready)(
        Skissm__E2eeAddress *user_address,
        Skissm__Session *inbound_session
    );
    /**
     * @brief notify outbound session ready
     * @param user_address
     * @param outbound_session
     */
    void (*on_outbound_session_ready)(
        Skissm__E2eeAddress *user_address,
        Skissm__Session *outbound_session
    );
    /**
     * @brief notify one2one msg received event
     * @param user_address
     * @param from_address
     * @param to_address
     * @param plaintext
     * @param plaintext_len
     */
    void (*on_one2one_msg_received)(
        Skissm__E2eeAddress *user_address,
        Skissm__E2eeAddress *from_address,
        Skissm__E2eeAddress *to_address,
        uint8_t *plaintext,
        size_t plaintext_len
    );

    /**
     * @brief notify messages from other devices received event
     * @param user_address
     * @param from_address
     * @param to_address
     * @param plaintext
     * @param plaintext_len
     */
    void (*on_other_device_msg_received)(
        Skissm__E2eeAddress *user_address,
        Skissm__E2eeAddress *from_address,
        Skissm__E2eeAddress *to_address,
        uint8_t *plaintext,
        size_t plaintext_len
    );

    /**
     * @brief notify group msg received event
     * @param user_address
     * @param from_address
     * @param group_address
     * @param plaintext
     * @param plaintext_len
     */
    void (*on_group_msg_received)(
        Skissm__E2eeAddress *user_address,
        Skissm__E2eeAddress *from_address,
        Skissm__E2eeAddress *group_address,
        uint8_t *plaintext,
        size_t plaintext_len
    );

    /**
     * @brief notify group created event
     * @param user_address
     * @param group_address
     * @param group_name
     * @param group_members
     * @param group_members_num
     */
    void (*on_group_created)(
        Skissm__E2eeAddress *user_address,
        Skissm__E2eeAddress *group_address,
        const char *group_name,
        Skissm__GroupMember **group_members,
        size_t group_members_num
    );

    /**
     * @brief notify group members added
     * @param user_address
     * @param group_address
     * @param group_name
     * @param group_members
     * @param group_members_num
     * @param added_group_members
     * @param added_group_members_num
     */
    void (*on_group_members_added)(
        Skissm__E2eeAddress *user_address,
        Skissm__E2eeAddress *group_address,
        const char *group_name,
        Skissm__GroupMember **group_members,
        size_t group_members_num,
        Skissm__GroupMember **added_group_members,
        size_t added_group_members_num
    );

    /**
     * @brief notify group members removed
     * @param user_address
     * @param group_address
     * @param group_name
     * @param group_members
     * @param group_members_num
     * @param removed_group_members
     * @param removed_group_members_num
     */
    void (*on_group_members_removed)(
        Skissm__E2eeAddress *user_address,
        Skissm__E2eeAddress *group_address,
        const char *group_name,
        Skissm__GroupMember **group_members,
        size_t group_members_num,
        Skissm__GroupMember **removed_group_members,
        size_t removed_group_members_num
    );
} skissm_event_handler_t;

/**
 * @brief Type definition of SKISSM plugin.
 */
typedef struct skissm_plugin_t {
    skissm_common_handler_t common_handler;
    skissm_db_handler_t db_handler;
    e2ee_proto_handler_t proto_handler;
    skissm_event_handler_t event_handler;
} skissm_plugin_t;


/**
 * @brief Generate the e2ee pack id raw number.
 * @param ver
 * @param digital_signature
 * @param kem
 * @param symmetric_encryption
 */
uint32_t gen_e2ee_pack_id_raw(
    unsigned ver, unsigned digital_signature, unsigned kem, unsigned symmetric_encryption);

/**
 * @brief Get the e2ee_pack by given e2ee_pack_id raw number.
 * @param e2ee_pack_id_raw
 */
e2ee_pack_t *get_e2ee_pack(uint32_t e2ee_pack_id_raw);

/**
 * @brief The begining function for starting SKISSM.
 * @param ssm_plugin
 */
void skissm_begin(skissm_plugin_t *ssm_plugin);

/**
 * @brief The ending function for terminating SKISSM.
 */
void skissm_end();

/**
 * @brief Get the current plugin of SKISSM.
 */
skissm_plugin_t *get_skissm_plugin();

/**
 * @brief Convert e2ee_pack_id_t to raw number.
 */
uint32_t e2ee_pack_id_to_raw(e2ee_pack_id_t e2ee_pack_id);

/**
 * @brief Convert raw number to e2ee_pack_id_t.
 */
e2ee_pack_id_t raw_to_e2ee_pack_id(uint32_t e2ee_pack_id_raw);

/**
 * @brief Log function with additional arguments.
 * @param user_address
 * @param log_code
 * @param log_msg
 */
void ssm_notify_log(Skissm__E2eeAddress *user_address, LogCode log_code, const char *log_msg, ...);

/**
 * @brief Event for notifying that user is registered.
 * @param account
 */
void ssm_notify_user_registered(Skissm__Account *account);

/**
 * @brief Event for notifying that an inbound session is invited.
 * @param user_address
 * @param from
 */
void ssm_notify_inbound_session_invited(Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *from);

/**
 * @brief Event for notifying that an inbound session is ready.
 * @param user_address
 * @param inbound_session
 */
void ssm_notify_inbound_session_ready(Skissm__E2eeAddress *user_address, Skissm__Session *inbound_session);

/**
 * @brief Event for notifying that an outbound session is ready.
 * @param user_address
 * @param outbound_session
 */
void ssm_notify_outbound_session_ready(Skissm__E2eeAddress *user_address, Skissm__Session *outbound_session);

/**
 * @brief Event for notifying that an one2one msg is received.
 * @param user_address
 * @param from_address
 * @param to_address
 * @param plaintext
 * @param plaintext_len
 */
void ssm_notify_one2one_msg(
    Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
);

/**
 * @brief Event for notifying that a msg from user of other device is received.
 * @param user_address
 * @param from_address
 * @param to_address
 * @param plaintext
 * @param plaintext_len
 */
void ssm_notify_other_device_msg(
    Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
);

/**
 * @brief Event for notifying that a group is received.
 * @param user_address
 * @param from_address
 * @param group_address
 * @param plaintext
 * @param plaintext_len
 */
void ssm_notify_group_msg(
    Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *group_address,
    uint8_t *plaintext, size_t plaintext_len
);

/**
 * @brief Event for notifying that a group is created.
 * @param user_address
 * @param group_address
 * @param group_name
 * @param group_members
 * @param group_members_num
 */
void ssm_notify_group_created(
    Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *group_address, const char *group_name,
    Skissm__GroupMember **group_members, size_t group_members_num
);

/**
 * @brief Event for notifying that some group members are added.
 * @param user_address
 * @param group_address
 * @param group_name
 * @param group_members
 * @param group_members_num
 * @param added_group_members
 * @param added_group_members_num
 */
void ssm_notify_group_members_added(
    Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *group_address, const char *group_name,
    Skissm__GroupMember **group_members, size_t group_members_num,
    Skissm__GroupMember **added_group_members, size_t added_group_members_num
);

/**
 * @brief Event for notifying that some group members are removed.
 * @param user_address
 * @param group_address
 * @param group_name
 * @param group_members
 * @param group_members_num
 * @param removed_group_members
 * @param removed_group_members_num
 */
void ssm_notify_group_members_removed(
    Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *group_address, const char *group_name,
    Skissm__GroupMember **group_members, size_t group_members_num,
    Skissm__GroupMember **removed_group_members, size_t removed_group_members_num
);

#ifdef __cplusplus
}
#endif

#endif /* SKISSM_H_ */
