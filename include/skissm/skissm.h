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

#ifdef __cplusplus
extern "C" {
#endif

#include "error.h"

#include "skissm/add_group_members_request_payload.pb-c.h"
#include "skissm/chain_key.pb-c.h"
#include "skissm/create_group_request_payload.pb-c.h"
#include "skissm/create_group_response_payload.pb-c.h"
#include "skissm/e2ee_accept_payload.pb-c.h"
#include "skissm/e2ee_account.pb-c.h"
#include "skissm/e2ee_address.pb-c.h"
#include "skissm/e2ee_commands.pb-c.h"
#include "skissm/e2ee_group_msg_payload.pb-c.h"
#include "skissm/e2ee_group_pre_key_payload.pb-c.h"
#include "skissm/e2ee_group_session.pb-c.h"
#include "skissm/e2ee_invite_payload.pb-c.h"
#include "skissm/e2ee_msg.pb-c.h"
#include "skissm/e2ee_msg_type.pb-c.h"
#include "skissm/e2ee_msg_payload.pb-c.h"
#include "skissm/e2ee_plaintext.pb-c.h"
#include "skissm/e2ee_plaintext_type.pb-c.h"
#include "skissm/e2ee_pre_key_bundle.pb-c.h"
#include "skissm/e2ee_protocol_msg.pb-c.h"
#include "skissm/e2ee_ratchet.pb-c.h"
#include "skissm/e2ee_session.pb-c.h"
#include "skissm/get_group_request_payload.pb-c.h"
#include "skissm/get_group_response_payload.pb-c.h"
#include "skissm/get_pre_key_bundle_request_payload.pb-c.h"
#include "skissm/get_pre_key_bundle_response_payload.pb-c.h"
#include "skissm/identity_key_public.pb-c.h"
#include "skissm/identity_key.pb-c.h"
#include "skissm/key_pair.pb-c.h"
#include "skissm/message_key.pb-c.h"
#include "skissm/one_time_pre_key.pb-c.h"
#include "skissm/one_time_pre_key_public.pb-c.h"
#include "skissm/pending_group_pre_key.pb-c.h"
#include "skissm/publish_spk_request_payload.pb-c.h"
#include "skissm/receiver_chain_node.pb-c.h"
#include "skissm/register_user_request_payload.pb-c.h"
#include "skissm/register_user_response_payload.pb-c.h"
#include "skissm/remove_group_members_request_payload.pb-c.h"
#include "skissm/sender_chain_node.pb-c.h"
#include "skissm/signed_pre_key.pb-c.h"
#include "skissm/signed_pre_key_public.pb-c.h"
#include "skissm/skipped_message_key_node.pb-c.h"
#include "skissm/supply_opks_request_payload.pb-c.h"
#include "skissm/supply_opks_response_payload.pb-c.h"
#include "skissm/response_data.pb-c.h"

#define PROTOCOL_VERSION 0x01

#define GROUP_VERSION 0x01

#define PLAINTEXT_VERSION 0x01

#define UUID_LEN 16

#define SIGNED_PRE_KEY_EXPIRATION 604800

typedef struct crypto_param_t {
    int asym_key_len;
    int sign_key_len;
    int sig_len;
    int hash_len;
    int aead_key_len;
    int aead_iv_len;
    int aead_tag_len;
} crypto_param_t;

typedef struct skissm_common_handler_t {
    int64_t (*handle_get_ts)();
    void (*handle_rg)(uint8_t *, size_t);
    void (*handle_generate_uuid)(uint8_t uuid[UUID_LEN]);
    int (*handle_send)(uint8_t *, size_t);
} skissm_common_handler_t;

typedef struct skissm_db_handler_t {
    // account related handlers
    /**
     * @brief store account to db
     * @param account
     */
    void (*store_account)(Skissm__E2eeAccount *);
    /**
     * @brief load account from db
     * @param account_id
     * @param account
     */
    void (*load_account)(uint64_t, Skissm__E2eeAccount **);
    /**
     * @brief load all accounts from db
     * @param accounts
     * @return number of loaded accounts
     */
    size_t (*load_accounts)(Skissm__E2eeAccount ***);
    /**
     * @brief load account from db by giving address
     * @param address
     * @param account
     */
    void (*load_account_by_address)(Skissm__E2eeAddress *,
                                    Skissm__E2eeAccount **);
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
    void (*update_signed_pre_key)(uint64_t,
                                  Skissm__SignedPreKey *);
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
                                 Skissm__E2eeSession **);
    /**
     * @brief find outbound session
     * @param owner
     * @param to
     * @param outbound_session
     */
    void (*load_outbound_session)(Skissm__E2eeAddress *,
                                  Skissm__E2eeAddress *,
                                  Skissm__E2eeSession **);
    /**
     * @brief store session
     * @param session
     */
    void (*store_session)(Skissm__E2eeSession *);
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
                                        Skissm__E2eeGroupSession **);
    /**
     * @brief find inbound group session
     * @param receiver_address
     * @param group_address
     * @param outbound_group_session
     */
    void (*load_inbound_group_session)(Skissm__E2eeAddress *,
                                       Skissm__E2eeAddress *,
                                       Skissm__E2eeGroupSession **);
    /**
     * @brief store group session
     * @param group_session
     */
    void (*store_group_session)(Skissm__E2eeGroupSession *);
    /**
     * @brief delete group session
     * @param group_session
     */
    void (*unload_group_session)(Skissm__E2eeGroupSession *);
    /**
     * @brief delete old inbound group session
     * @param user_address
     * @param old_session_id
     */
    void (*unload_inbound_group_session)(Skissm__E2eeAddress *, char *);

    // group pre-key related handlers
    /**
     * @brief store group pre-key
     * @param outbound_group_session_id
     * @param member_address
     * @param group_pre_key_plaintext
     * @param group_pre_key_plaintext_len
     */
    void (*store_group_pre_key)(char *, Skissm__E2eeAddress *, uint8_t *, size_t);
    /**
     * @brief load group pre-key
     * @param outbound_group_session_id
     * @param member_address
     * @param pending_group_pre_key
     */
    void (*load_group_pre_key)(char *, Skissm__E2eeAddress *, Skissm__PendingGroupPreKey **);
    /**
     * @brief delete group pre-key
     * @param outbound_group_session_id
     * @param member_address
     */
    void (*unload_group_pre_key)(char *, Skissm__E2eeAddress *);
} skissm_db_handler_t;

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
    void (*on_user_registered)(Skissm__E2eeAccount *);
    /**
     * @brief notify inbound session ready
     * @param inbound_session
     */
    void (*on_inbound_session_ready)(Skissm__E2eeSession *);
    /**
     * @brief notify outbound session ready
     * @param outbound_session
     */
    void (*on_outbound_session_ready)(Skissm__E2eeSession *);
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
    skissm_event_handler_t event_handler;
} skissm_plugin_t;


void skissm_begin(skissm_plugin_t *ssm_plugin);

void skissm_end();

skissm_plugin_t *get_skissm_plugin();

void ssm_notify_error(ErrorCode, char *);
void ssm_notify_user_registered(Skissm__E2eeAccount *account);
void ssm_notify_inbound_session_ready(Skissm__E2eeSession *inbound_session);
void ssm_notify_outbound_session_ready(Skissm__E2eeSession *outbound_session);
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
