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
#include "skissm/e2ee_client.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "skissm/mem_util.h"
#include "skissm/safe_check.h"
#include "skissm/account.h"
#include "skissm/account_cache.h"
#include "skissm/account_manager.h"
#include "skissm/e2ee_client_internal.h"
#include "skissm/group_session_manager.h"
#include "skissm/session.h"
#include "skissm/session_manager.h"

int register_user(
    Skissm__RegisterUserResponse **response_out,
    uint32_t e2ee_pack_id,
    const char *user_name,
    const char *user_id,
    const char *device_id,
    const char *authenticator,
    const char *auth_code
) {
    int ret = 0;

    Skissm__Account *account = NULL;
    Skissm__RegisterUserRequest *register_user_request = NULL;
    Skissm__RegisterUserResponse *response = NULL;

    if (!safe_e2ee_pack_id(e2ee_pack_id)) {
        ssm_notify_log(NULL, BAD_E2EE_PACK, "register_user(): no e2ee_pack_id");
        ret = -1;
    }
    if (!nonempty_string(user_name)) {
        ssm_notify_log(NULL, BAD_USER_NAME, "register_user(): no user_name");
        ret = -1;
    }
    if (!nonempty_string(user_id)) {
        ssm_notify_log(NULL, BAD_USER_ID, "register_user(): no user_id");
        ret = -1;
    }
    if (!nonempty_string(device_id)) {
        ssm_notify_log(NULL, BAD_DEVICE_ID, "register_user(): no device_id");
        ret = -1;
    }
    if (!nonempty_string(authenticator)) {
        ssm_notify_log(NULL, BAD_AUTHENTICATOR, "register_user(): no authenticator");
        ret = -1;
    }
    if (!nonempty_string(auth_code)) {
        ssm_notify_log(NULL, BAD_AUTH, "register_user(): no auth_code");
        ret = -1;
    }

    if (ret == 0) {
        // generate an account
        ret = create_account(&account, e2ee_pack_id);
    }

    if (ret == 0) {
        // register account to server
        ret = produce_register_request(&register_user_request, account);
    }

    if (ret == 0) {
        register_user_request->user_name = strdup(user_name);
        register_user_request->user_id = strdup(user_id);
        register_user_request->device_id = strdup(device_id);
        register_user_request->authenticator = strdup(authenticator);
        register_user_request->auth_code = strdup(auth_code);
        register_user_request->e2ee_pack_id = e2ee_pack_id;

        response = get_skissm_plugin()->proto_handler.register_user(register_user_request);

        if (safe_register_user_response(response)) {
            bool consumed = consume_register_response(account, response);
        } else {
            ssm_notify_log(NULL, BAD_RESPONSE, "register_user()");
            ret = -1;
        }
    }

    if (ret == 0) {
        *response_out = response;
    }

    // release
    free_proto(account);
    free_proto(register_user_request);

    // done
    return ret;
}

Skissm__InviteResponse *reinvite(Skissm__Session *outbound_session) {
    int ret = 0;

    Skissm__InviteResponse *response = NULL;
    // only reinvite the outbound session that is not responded
    if (!outbound_session->responded) {
        // check the time we invited last time
        int64_t now = get_skissm_plugin()->common_handler.gen_ts();
        if (now < outbound_session->invite_t + INVITE_WAITING_TIME_MS) {
            ssm_notify_log(
                outbound_session->our_address,
                DEBUG_LOG,
                "reinvite(): skipped for not exceed INVITE_WAITING_TIME_MS(60s)"
            );
            return NULL;
        }

        // update the invitation time and resend
        outbound_session->invite_t = get_skissm_plugin()->common_handler.gen_ts();
        get_skissm_plugin()->db_handler.store_session(outbound_session);
        ret = invite_internal(&response, outbound_session);

        if (response == NULL || response->code != SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
            // keep outbound session to enable retry
            ssm_notify_log(
                outbound_session->our_address,
                DEBUG_LOG,
                "reinvite(): from [%s:%s] to[%s:%s] failed need another try",
                outbound_session->our_address->user->user_id,
                outbound_session->our_address->user->device_id,
                outbound_session->their_address->user->user_id,
                outbound_session->their_address->user->device_id
            );
        }
    }

    return response;
}

Skissm__InviteResponse *invite(
    Skissm__E2eeAddress *from, const char *to_user_id, const char *to_domain
) {
    int ret = 0;

    char *auth = NULL;
    Skissm__InviteResponse *invite_response = NULL;
    Skissm__InviteResponse **invite_response_list = NULL;
    size_t invite_response_num;

    if (safe_address(from)) {
        get_skissm_plugin()->db_handler.load_auth(from, &auth);
        if (auth == NULL) {
            ssm_notify_log(
                from, BAD_ACCOUNT, "invite() from [%s:%s] to [%s@%s]",
                from->user->user_id,
                from->user->device_id,
                to_user_id,
                to_domain
            );
            ret = -1;
        }
    } else {
        ssm_notify_log(NULL, BAD_ADDRESS, "invite()");
        ret = -1;
    }
    if (!nonempty_string(to_user_id)) {
        ssm_notify_log(NULL, BAD_USER_ID, "invite()");
        ret = -1;
    }
    if (!nonempty_string(to_domain)) {
        ssm_notify_log(NULL, BAD_DOMAIN, "invite()");
        ret = -1;
    }

    // ssm_notify_log(from, DEBUG_LOG, "invite(): from [%s:%s] to_user_id [%s]", from->user->user_id, from->user->device_id, to_user_id);

    // we should always call get_pre_key_bundle_internal() since there may be new devices for to_user_id@to_domain
    // not just check outbound sessions in db currently.

    if (ret == 0) {
        ret = get_pre_key_bundle_internal(
            &invite_response_list,
            &invite_response_num,
            from,
            auth,
            to_user_id,
            to_domain,
            NULL,
            true,
            NULL, 0
        );
    }

    // release
    free_string(&auth);
    free_invite_response_list(&invite_response_list, invite_response_num);

    // done
    return invite_response;
}

// Skissm__InviteResponse *new_invite(Skissm__E2eeAddress *from, const char *to_user_id, const char *to_domain) {
//     char *auth = NULL;
//     get_skissm_plugin()->db_handler.load_auth(from, &auth);

//     if (auth == NULL) {
//         ssm_notify_log(from, BAD_ACCOUNT, "invite() from [%s:%s] to [%s@%s]",
//             from->user->user_id,
//             from->user->device_id,
//             to_user_id,
//             to_domain);
//         return NULL;
//     }

//     Skissm__InviteResponse *invite_response = NULL;
//     invite_response = get_pre_key_bundle_internal(from, auth, to_user_id, to_domain, NULL, true, NULL, 0);

//     // release
//     free(auth);

//     // done
//     // response can be NULL
//     return invite_response;
// }

void send_sync_msg(Skissm__E2eeAddress *from, const uint8_t *plaintext_data, size_t plaintext_data_len) {
    Skissm__Session **self_outbound_sessions = NULL;
    size_t self_outbound_sessions_num = get_skissm_plugin()->db_handler.load_outbound_sessions(from, from->user->user_id, from->domain, &self_outbound_sessions);

    if (self_outbound_sessions_num > 0) {
        ssm_notify_log(
            from,
            DEBUG_LOG,
            "send_sync_msg(): self_outbound_sessions_num = %zu",
            self_outbound_sessions_num
        );
        // pack syncing plaintext before sending it
        uint8_t *common_plaintext_data = NULL;
        size_t common_plaintext_data_len;
        pack_common_plaintext(
            plaintext_data, plaintext_data_len,
            SKISSM__PLAINTEXT__PAYLOAD_COMMON_SYNC_MSG,
            &common_plaintext_data, &common_plaintext_data_len
        );

        size_t i;
        for (i = 0; i < self_outbound_sessions_num; i++) {
            Skissm__Session *self_outbound_session = self_outbound_sessions[i];
            // if the device is different from the sender's
            if (strcmp(self_outbound_session->their_address->user->device_id, from->user->device_id) != 0) {
                if (self_outbound_session->responded == true) {
                    // send syncing plaintext to server
                    Skissm__SendOne2oneMsgResponse *sync_response = send_one2one_msg_internal(
                        self_outbound_session,
                        SKISSM__NOTIF_LEVEL__NOTIF_LEVEL_NORMAL,
                        common_plaintext_data,
                        common_plaintext_data_len
                    );
                    // release
                    skissm__send_one2one_msg_response__free_unpacked(sync_response, NULL);
                } else {
                    ssm_notify_log(
                        from,
                        DEBUG_LOG,
                        "send_sync_msg(): outbound session[%s] (user_id:deviceid = %s, %s) not responded, store common_plaintext_data",
                        self_outbound_session->session_id,
                        self_outbound_session->their_address->user->user_id,
                        self_outbound_session->their_address->user->device_id
                    );
                    // store pending common_plaintext_data
                    store_pending_common_plaintext_data_internal(
                        self_outbound_session->our_address,
                        self_outbound_session->their_address,
                        common_plaintext_data,
                        common_plaintext_data_len,
                        SKISSM__NOTIF_LEVEL__NOTIF_LEVEL_NORMAL
                    );
                }
            }
            // release
            skissm__session__free_unpacked(self_outbound_session, NULL);
        }

        // release
        free_mem((void **)&common_plaintext_data, common_plaintext_data_len);
        free_mem((void **)&self_outbound_sessions, sizeof(Skissm__Session *) * self_outbound_sessions_num);
    }
}

void send_sync_invite_msg(Skissm__E2eeAddress *from, const char *to_user_id, const char *to_domain, char **to_device_id_list, size_t to_device_num) {
    Skissm__Session **self_outbound_sessions = NULL;
    size_t self_outbound_sessions_num = get_skissm_plugin()->db_handler.load_outbound_sessions(from, from->user->user_id, from->domain, &self_outbound_sessions);

    if (self_outbound_sessions_num > 0) {
        ssm_notify_log(
            from,
            DEBUG_LOG,
            "send_sync_msg(): self_outbound_sessions_num = %zu",
            self_outbound_sessions_num
        );
        // pack syncing plaintext before sending it
        Skissm__Plaintext *plaintext = (Skissm__Plaintext *)malloc(sizeof(Skissm__Plaintext));
        skissm__plaintext__init(plaintext);
        plaintext->version = strdup(E2EE_PLAINTEXT_VERSION);
        plaintext->payload_case = SKISSM__PLAINTEXT__PAYLOAD_USER_DEVICES_BUNDLE;
        plaintext->user_devices_bundle = (Skissm__UserDevicesBundle *)malloc(sizeof(Skissm__UserDevicesBundle));
        skissm__user_devices_bundle__init(plaintext->user_devices_bundle);
        plaintext->user_devices_bundle->domain = strdup(to_domain);
        plaintext->user_devices_bundle->user_id = strdup(to_user_id);
        plaintext->user_devices_bundle->n_device_id_list = to_device_num;
        plaintext->user_devices_bundle->device_id_list = (char **)malloc(sizeof(char *) * to_device_num);
        size_t k;
        for (k = 0; k < to_device_num; k++) {
            (plaintext->user_devices_bundle->device_id_list)[k] = strdup(to_device_id_list[k]);
        }

        size_t invite_msg_data_len = skissm__plaintext__get_packed_size(plaintext);
        uint8_t *invite_msg_data = (uint8_t *)malloc(sizeof(uint8_t) * invite_msg_data_len);
        skissm__plaintext__pack(plaintext, invite_msg_data);

        size_t i;
        for (i = 0; i < self_outbound_sessions_num; i++) {
            Skissm__Session *self_outbound_session = self_outbound_sessions[i];
            // if the device is different from the sender's
            if (strcmp(self_outbound_session->their_address->user->device_id, from->user->device_id) != 0) {
                if (self_outbound_session->responded == true) {
                    // send syncing plaintext to server
                    Skissm__SendOne2oneMsgResponse *sync_response = send_one2one_msg_internal(
                        self_outbound_session,
                        SKISSM__NOTIF_LEVEL__NOTIF_LEVEL_NORMAL,
                        invite_msg_data,
                        invite_msg_data_len
                    );
                    // release
                    skissm__send_one2one_msg_response__free_unpacked(sync_response, NULL);
                } else {
                    ssm_notify_log(
                        from,
                        DEBUG_LOG,
                        "send_sync_msg(): outbound session[%s] (user_id:deviceid = %s, %s) not responded, store common_plaintext_data",
                        self_outbound_session->session_id,
                        self_outbound_session->their_address->user->user_id,
                        self_outbound_session->their_address->user->device_id
                    );
                    // store pending common_plaintext_data
                    store_pending_common_plaintext_data_internal(
                        self_outbound_session->our_address,
                        self_outbound_session->their_address,
                        invite_msg_data,
                        invite_msg_data_len,
                        SKISSM__NOTIF_LEVEL__NOTIF_LEVEL_NORMAL
                    );
                }
            }
            // release
            skissm__session__free_unpacked(self_outbound_session, NULL);
        }

        // release
        skissm__plaintext__free_unpacked(plaintext, NULL);
        free_mem((void **)&invite_msg_data, invite_msg_data_len);
        free_mem((void **)&self_outbound_sessions, sizeof(Skissm__Session *) * self_outbound_sessions_num);
    }
}

Skissm__SendOne2oneMsgResponse *send_one2one_msg(
    Skissm__E2eeAddress *from, const char *to_user_id, const char *to_domain,
    uint32_t notif_level,
    const uint8_t *plaintext_data, size_t plaintext_data_len
) {
    // pack common plaintext before sending it
    uint8_t *common_plaintext_data = NULL;
    size_t common_plaintext_data_len;
    pack_common_plaintext(
        plaintext_data, plaintext_data_len,
        SKISSM__PLAINTEXT__PAYLOAD_COMMON_MSG,
        &common_plaintext_data, &common_plaintext_data_len
    );

    Skissm__Session **outbound_sessions = NULL;
    size_t outbound_sessions_num = get_skissm_plugin()->db_handler.load_outbound_sessions(from, to_user_id, to_domain, &outbound_sessions);
    if (outbound_sessions_num == 0 || outbound_sessions == NULL) {
        // save common_plaintext_data and will be resent after the first outbound session established
        ssm_notify_log(
            from,
            DEBUG_LOG,
            "send_one2one_msg(): outbound_sessions_num = %zu, store common_plaintext_data",
            outbound_sessions_num
        );
        Skissm__E2eeAddress *to = (Skissm__E2eeAddress *)malloc(sizeof(Skissm__E2eeAddress));
        skissm__e2ee_address__init(to);
        to->domain = strdup(to_domain);
        Skissm__PeerUser *peer_user = (Skissm__PeerUser *)malloc(sizeof(Skissm__PeerUser));
        skissm__peer_user__init(peer_user);
        peer_user->user_id = strdup(to_user_id);
        // no specific deviceId currently
        to->peer_case = SKISSM__E2EE_ADDRESS__PEER_USER;
        to->user = peer_user;
        store_pending_common_plaintext_data_internal(
            from,
            to,
            common_plaintext_data,
            common_plaintext_data_len,
            notif_level
        );
        // release
        skissm__e2ee_address__free_unpacked(to, NULL);
        free_mem((void **)&common_plaintext_data, common_plaintext_data_len);
        // done
        Skissm__SendOne2oneMsgResponse *response = (Skissm__SendOne2oneMsgResponse *)malloc(sizeof(Skissm__SendOne2oneMsgResponse));
        skissm__send_one2one_msg_response__init(response);
        response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_REQUEST_TIMEOUT;
        return response;
    }

    size_t i;
    bool succ = false;
    for (i = 0; i < outbound_sessions_num; i++) {
        Skissm__Session *outbound_session = outbound_sessions[i];
        if (outbound_session->responded == false) {
            ssm_notify_log(
                from,
                DEBUG_LOG,
                "send_one2one_msg(): outbound session %zu of %zu [%s] not responded, store common_plaintext_data",
                i+1,
                outbound_sessions_num,
                outbound_session->session_id
            );
            // store pending common_plaintext_data
            store_pending_common_plaintext_data_internal(
                outbound_session->our_address,
                outbound_session->their_address,
                common_plaintext_data,
                common_plaintext_data_len,
                notif_level
            );
            // release
            skissm__session__free_unpacked(outbound_session, NULL);
            continue;
        }

        // send message to server
        Skissm__SendOne2oneMsgResponse *response = send_one2one_msg_internal(
            outbound_session,
            notif_level,
            common_plaintext_data, common_plaintext_data_len
        );
        ssm_notify_log(
            from,
            DEBUG_LOG,
            "send_one2one_msg(): outbound session %zu of %zu [%s] response code: %d",
            i+1,
            outbound_sessions_num,
            outbound_session->session_id,
            response->code
        );
        if (response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
            succ = true;
        }
        // release
        skissm__send_one2one_msg_response__free_unpacked(response, NULL);
        skissm__session__free_unpacked(outbound_session, NULL);
    }

    // release
    free_mem((void **)&common_plaintext_data, common_plaintext_data_len);
    free_mem((void **)&outbound_sessions, sizeof(Skissm__Session *) * outbound_sessions_num);

    // send the message to other self devices
    send_sync_msg(from, plaintext_data, plaintext_data_len);

    // done
    // return ok response if there is at least one session sent successfully
    Skissm__SendOne2oneMsgResponse *response = (Skissm__SendOne2oneMsgResponse *)malloc(sizeof(Skissm__SendOne2oneMsgResponse));
    skissm__send_one2one_msg_response__init(response);
    response->code = (succ ? SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK : SKISSM__RESPONSE_CODE__RESPONSE_CODE_REQUEST_TIMEOUT);
    return response;
}

int create_group(
    Skissm__CreateGroupResponse **response_out,
    Skissm__E2eeAddress *sender_address,
    const char *group_name,
    Skissm__GroupMember **group_members,
    size_t group_members_num
) {
    int ret = 0;

    Skissm__CreateGroupRequest *create_group_request = NULL;
    Skissm__CreateGroupResponse *response = NULL;
    Skissm__Account *account = NULL;
    char *auth = NULL;
    uint32_t e2ee_pack_id = 0;

    if (!safe_address(sender_address)) {
        ssm_notify_log(NULL, BAD_ADDRESS, "create_group()");
        ret = -1;
    }
    if (!nonempty_string(group_name)) {
        ssm_notify_log(NULL, BAD_INPUT_DATA, "create_group()");
        ret = -1;
    }
    if (!safe_group_member_list(group_members, group_members_num)) {
        ssm_notify_log(NULL, BAD_INPUT_DATA, "create_group()");
        ret = -1;
    }

    if (ret == 0) {
        load_e2ee_pack_id_from_cache(&e2ee_pack_id, sender_address);

        if (e2ee_pack_id == 0) {
            get_skissm_plugin()->db_handler.load_account_by_address(sender_address, &account);
            if (account == NULL) {
                ssm_notify_log(sender_address, BAD_ACCOUNT, "create_group()");
                ret = -1;
            }
            e2ee_pack_id = account->e2ee_pack_id;
            auth = strdup(account->auth);
        } else {
            get_skissm_plugin()->db_handler.load_auth(sender_address, &auth);
        }
    }

    if (ret == 0) {
        ret = produce_create_group_request(&create_group_request, sender_address, group_name, group_members, group_members_num);
    }

    if (ret == 0) {
        // send message to server
        response = get_skissm_plugin()->proto_handler.create_group(sender_address, auth, create_group_request);

        if (!safe_create_group_response(response)) {
            ssm_notify_log(sender_address, BAD_RESPONSE, "create_group()");
            ret = -1;
            // pack reuest to request_data
            size_t request_data_len = skissm__create_group_request__get_packed_size(create_group_request);
            uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
            skissm__create_group_request__pack(create_group_request, request_data);
            store_pending_request_internal(sender_address, SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_CREATE_GROUP, request_data, request_data_len, NULL, 0);
            // release
            free_mem((void *)&request_data, request_data_len);
        }
    }

    if (ret == 0) {
        ret = consume_create_group_response(e2ee_pack_id, sender_address, group_name, group_members, group_members_num, response);
    }

    if (ret == 0) {
        *response_out = response;
    }

    // release
    free_proto(account);
    free_string(&auth);
    free_proto(create_group_request);

    // done
    return ret;
}

int add_group_members(
    Skissm__AddGroupMembersResponse **response_out,
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address,
    Skissm__GroupMember **adding_members,
    size_t adding_members_num
) {
    int ret = 0;

    Skissm__AddGroupMembersRequest *add_group_members_request = NULL;
    Skissm__AddGroupMembersResponse *response = NULL;
    Skissm__GroupSession *outbound_group_session = NULL;
    char *auth = NULL;

    if (safe_address(sender_address)) {
        get_skissm_plugin()->db_handler.load_auth(sender_address, &auth);
        if (auth != NULL) {
            if (safe_address(group_address)) {
                get_skissm_plugin()->db_handler.load_group_session_by_address(
                    sender_address, sender_address, group_address, &outbound_group_session
                );

                if (outbound_group_session == NULL) {
                    ssm_notify_log(
                        sender_address,
                        BAD_GROUP_SESSION,
                        "add_group_members() outbound_group_session does not exist, return a response with response code not found"
                    );        
                    response = (Skissm__AddGroupMembersResponse *)malloc(sizeof(Skissm__AddGroupMembersResponse));
                    skissm__add_group_members_response__init(response);
                    response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND;

                    ret = -1;
                }
            }
        } else {
            ssm_notify_log(sender_address, BAD_AUTH, "add_group_members()");
            ret = -1;
        }
    } else {
        ssm_notify_log(NULL, BAD_ADDRESS, "add_group_members()");
        ret = -1;
    }
    if (!safe_group_member_list(adding_members, adding_members_num)) {
        ssm_notify_log(NULL, BAD_INPUT_DATA, "add_group_members()");
        ret = -1;
    }

    if (ret == 0) {
        ret = produce_add_group_members_request(&add_group_members_request, outbound_group_session, adding_members, adding_members_num);
    }

    if (ret == 0) {
        response = get_skissm_plugin()->proto_handler.add_group_members(sender_address, auth, add_group_members_request);
        // TODO: replace adding_members, adding_members_num by using response->added_group_member_list

        if (!safe_add_group_members_response(response)) {
            ssm_notify_log(NULL, BAD_RESPONSE, "add_group_members()");
            ret = -1;
            // pack reuest to request_data
            size_t request_data_len = skissm__add_group_members_request__get_packed_size(add_group_members_request);
            uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
            skissm__add_group_members_request__pack(add_group_members_request, request_data);
            store_pending_request_internal(sender_address, SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_ADD_GROUP_MEMBERS, request_data, request_data_len, NULL, 0);
            // release
            free_mem((void *)&request_data, request_data_len);
        }
    }

    if (ret == 0) {
        ret = consume_add_group_members_response(outbound_group_session, response, adding_members, adding_members_num);
    }

    if (ret == 0) {
        *response_out = response;
    }

    // release
    free_string(&auth);
    free_proto(add_group_members_request);
    if (outbound_group_session != NULL) {
        skissm__group_session__free_unpacked(outbound_group_session, NULL);
        outbound_group_session = NULL;
    }

    // done
    return ret;
}

int remove_group_members(
    Skissm__RemoveGroupMembersResponse **response_out,
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address,
    Skissm__GroupMember **removing_members,
    size_t removing_members_num
) {
    int ret = 0;

    Skissm__RemoveGroupMembersRequest *remove_group_members_request = NULL;
    Skissm__RemoveGroupMembersResponse *response = NULL;
    Skissm__GroupSession *outbound_group_session = NULL;
    char *auth = NULL;

    if (safe_address(sender_address)) {
        get_skissm_plugin()->db_handler.load_auth(sender_address, &auth);
        if (auth != NULL) {
            if (safe_address(group_address)) {
                get_skissm_plugin()->db_handler.load_group_session_by_address(
                    sender_address, sender_address, group_address, &outbound_group_session
                );

                if (outbound_group_session == NULL) {
                    ssm_notify_log(
                        sender_address,
                        BAD_GROUP_SESSION,
                        "remove_group_members(), outbound_group_session is null, return a response with response code not found"
                    );        
                    response = (Skissm__RemoveGroupMembersResponse *)malloc(sizeof(Skissm__RemoveGroupMembersResponse));
                    skissm__remove_group_members_response__init(response);
                    response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND;

                    ret = -1;
                }
            }
        } else {
            ssm_notify_log(sender_address, BAD_AUTH, "remove_group_members()");
            ret = -1;
        }
    } else {
        ssm_notify_log(NULL, BAD_ADDRESS, "remove_group_members()");
        ret = -1;
    }
    if (!safe_group_member_list(removing_members, removing_members_num)) {
        ssm_notify_log(NULL, BAD_INPUT_DATA, "remove_group_members()");
        ret = -1;
    }

    if (ret == 0) {
        ret = produce_remove_group_members_request(&remove_group_members_request, outbound_group_session, removing_members, removing_members_num);
    }

    if (ret == 0) {
        response = get_skissm_plugin()->proto_handler.remove_group_members(sender_address, auth, remove_group_members_request);

        if (!safe_remove_group_members_response(response)) {
            ssm_notify_log(NULL, BAD_RESPONSE, "remove_group_members()");
            ret = -1;
            // pack request to request_data
            size_t request_data_len = skissm__remove_group_members_request__get_packed_size(remove_group_members_request);
            uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
            skissm__remove_group_members_request__pack(remove_group_members_request, request_data);
            store_pending_request_internal(sender_address, SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_REMOVE_GROUP_MEMBERS, request_data, request_data_len, NULL, 0);
            // release
            free_mem((void *)&request_data, request_data_len);
        }
    }

    if (ret == 0) {
        ret = consume_remove_group_members_response(outbound_group_session, response, removing_members, removing_members_num);
    }

    if (ret == 0) {
        *response_out = response;
    }

    // release
    free_string(&auth);
    free_proto(remove_group_members_request);
    if (outbound_group_session != NULL) {
        skissm__group_session__free_unpacked(outbound_group_session, NULL);
        outbound_group_session = NULL;
    }

    // done
    return ret;
}

int leave_group(
    Skissm__LeaveGroupResponse **response_out,
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address
) {
    int ret = 0;

    Skissm__LeaveGroupRequest *leave_group_request = NULL;
    Skissm__LeaveGroupResponse *response = NULL;
    char *auth = NULL;

    if (safe_address(sender_address)) {
        get_skissm_plugin()->db_handler.load_auth(sender_address, &auth);

        if (auth == NULL) {
            ssm_notify_log(sender_address, BAD_AUTH, "leave_group()");
            ret = -1;
        }
    } else {
        ssm_notify_log(NULL, BAD_ADDRESS, "leave_group()");
        ret = -1;
    }
    if (!safe_address(group_address)) {
        ssm_notify_log(NULL, BAD_ADDRESS, "leave_group()");
        ret = -1;
    }

    if (ret == 0) {
        ret = produce_leave_group_request(&leave_group_request, sender_address, group_address);
    }

    if (ret == 0) {
        response = get_skissm_plugin()->proto_handler.leave_group(sender_address, auth, leave_group_request);

        if (!safe_leave_group_response(response)) {
            ssm_notify_log(NULL, BAD_RESPONSE, "leave_group()");
            ret = -1;
            // pack request to request_data
            size_t request_data_len = skissm__leave_group_request__get_packed_size(leave_group_request);
            uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
            skissm__leave_group_request__pack(leave_group_request, request_data);
            store_pending_request_internal(sender_address, SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_LEAVE_GROUP, request_data, request_data_len, NULL, 0);
            // release
            free_mem((void *)&request_data, request_data_len);
        }
    }

    if (ret == 0) {
        ret = consume_leave_group_response(sender_address, response);
    }

    if (ret == 0) {
        *response_out = response;
    }

    // release
    free_string(&auth);
    free_proto(leave_group_request);

    // done
    return ret;
}

int send_group_msg_with_filter(
    Skissm__SendGroupMsgResponse **response_out,
    Skissm__E2eeAddress *sender_address, Skissm__E2eeAddress *group_address,
    uint32_t notif_level,
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    Skissm__E2eeAddress **allow_list,
    size_t allow_list_len,
    Skissm__E2eeAddress **deny_list,
    size_t deny_list_len
) {
    int ret = 0;

    Skissm__SendGroupMsgRequest *send_group_msg_request = NULL;
    Skissm__SendGroupMsgResponse *response = NULL;
    Skissm__GroupSession *outbound_group_session = NULL;
    char *auth = NULL;

    if (safe_address(sender_address)) {
        get_skissm_plugin()->db_handler.load_auth(sender_address, &auth);
        if (auth != NULL) {
            if (safe_address(group_address)) {
                get_skissm_plugin()->db_handler.load_group_session_by_address(
                    sender_address, sender_address, group_address, &outbound_group_session
                );

                if (outbound_group_session == NULL) {
                    ssm_notify_log(
                        sender_address,
                        BAD_GROUP_SESSION,
                        "send_group_msg() outbound_group_session does not exist, return a response with response code not found"
                    );        
                    response = (Skissm__SendGroupMsgResponse *)malloc(sizeof(Skissm__SendGroupMsgResponse));
                    skissm__send_group_msg_response__init(response);
                    response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND;

                    ret = -1;
                }
            }
        } else {
            ssm_notify_log(sender_address, BAD_AUTH, "send_group_msg()");
            ret = -1;
        }
    } else {
        ssm_notify_log(NULL, BAD_ADDRESS, "send_group_msg()");
        ret = -1;
    }
    if (plaintext_data == NULL) {
        ssm_notify_log(NULL, BAD_INPUT_DATA, "send_group_msg()");
        ret = -1;
    }
    if (plaintext_data_len == 0) {
        ssm_notify_log(NULL, BAD_INPUT_DATA, "send_group_msg()");
        ret = -1;
    }
    if (!safe_address_list(allow_list, allow_list_len)) {
        ssm_notify_log(NULL, BAD_ADDRESS, "send_group_msg()");
        ret = -1;
    }
    if (!safe_address_list(deny_list, deny_list_len)) {
        ssm_notify_log(NULL, BAD_ADDRESS, "send_group_msg()");
        ret = -1;
    }

    if (ret == 0) {
        ret = produce_send_group_msg_request(
            &send_group_msg_request,
            outbound_group_session,
            notif_level,
            plaintext_data,
            plaintext_data_len,
            allow_list,
            allow_list_len,
            deny_list,
            deny_list_len
        );
    }

    if (ret == 0) {
        response = get_skissm_plugin()->proto_handler.send_group_msg(sender_address, auth, send_group_msg_request);

        if (!safe_send_group_msg_response(response)) {
            ssm_notify_log(NULL, BAD_RESPONSE, "send_group_msg()");
            ret = -1;
            // pack request to request_data
            size_t request_data_len = skissm__send_group_msg_request__get_packed_size(send_group_msg_request);
            uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
            skissm__send_group_msg_request__pack(send_group_msg_request, request_data);

            store_pending_request_internal(sender_address, SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_SEND_GROUP_MSG, request_data, request_data_len, NULL, 0);
            // release
            free_mem((void *)&request_data, request_data_len);
        }
    }

    if (ret == 0) {   
        ret = consume_send_group_msg_response(outbound_group_session, response);
        if (ret != 0) {
            // // pack request to request_data
            // size_t request_data_len = skissm__send_group_msg_request__get_packed_size(request);
            // uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
            // skissm__send_group_msg_request__pack(request, request_data);

            // store_pending_request_internal(sender_address, SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_SEND_GROUP_MSG, request_data, request_data_len, NULL, 0);
            // // release
            // free_mem((void *)&request_data, request_data_len);
            // skissm__send_group_msg_response__free_unpacked(response, NULL);

            // // replace response code to enable another try
            // response = (Skissm__SendGroupMsgResponse *)malloc(sizeof(Skissm__SendGroupMsgResponse));
            // skissm__send_group_msg_response__init(response);
            // response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_REQUEST_TIMEOUT;
        }
    }

    if (ret == 0) {
        *response_out = response;
    }

    // release
    free_string(&auth);
    free_proto(send_group_msg_request);
    if (outbound_group_session != NULL) {
        skissm__group_session__free_unpacked(outbound_group_session, NULL);
        outbound_group_session = NULL;
    }

    // done
    return ret;
}

int send_group_msg(
    Skissm__SendGroupMsgResponse **response_out,
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address,
    uint32_t notif_level,
    const uint8_t *plaintext_data,
    size_t plaintext_data_len
) {
    return send_group_msg_with_filter(
        response_out,
        sender_address, group_address, notif_level,
        plaintext_data, plaintext_data_len,
        NULL, 0, NULL, 0
    );
}

Skissm__ConsumeProtoMsgResponse *consume_proto_msg(Skissm__E2eeAddress *sender_address, const char *proto_msg_id) {
    char *auth = NULL;
    get_skissm_plugin()->db_handler.load_auth(sender_address, &auth);

    if (auth == NULL) {
        ssm_notify_log(sender_address, BAD_ACCOUNT, "consume_proto_msg()");
        return NULL;
    }

    Skissm__ConsumeProtoMsgRequest *request = (Skissm__ConsumeProtoMsgRequest *)malloc(sizeof(Skissm__ConsumeProtoMsgRequest));
    skissm__consume_proto_msg_request__init(request);
    request->proto_msg_id = strdup(proto_msg_id);
    Skissm__ConsumeProtoMsgResponse *response = get_skissm_plugin()->proto_handler.consume_proto_msg(sender_address, auth, request);

    // release
    free_string(&auth);
    skissm__consume_proto_msg_request__free_unpacked(request, NULL);

    // done
    return response;
}

Skissm__ConsumeProtoMsgResponse *process_proto_msg(uint8_t *proto_msg_data, size_t proto_msg_data_len) {
    int ret = 0;
    int server_check = 0;
    bool consumed = false;

    digital_signature_suite_t *digital_signature_suite = NULL;
    Skissm__E2eeAddress *receiver_address = NULL;
    ProtobufCBinaryData server_public_key;
    Skissm__ConsumeProtoMsgResponse *response = NULL;
    Skissm__ProtoMsg *proto_msg = skissm__proto_msg__unpack(NULL, proto_msg_data_len, proto_msg_data);
    size_t i;

    if (safe_proto_msg(proto_msg)) {
        receiver_address = proto_msg->to;
        load_server_public_key_from_cache(&server_public_key, receiver_address);
        for (i = 0; i < proto_msg->n_signature_list; i++) {
            digital_signature_suite = get_digital_signature_suite(proto_msg->signature_list[i]->signing_alg);
            server_check = digital_signature_suite->verify(
                proto_msg->signature_list[i]->signature.data,
                proto_msg->signature_list[i]->signature.len,
                proto_msg->signature_list[i]->msg_fingerprint.data,
                proto_msg->signature_list[i]->msg_fingerprint.len,
                server_public_key.data
            );
            if (server_check < 0) {
                ssm_notify_log(NULL, BAD_SERVER_SIGNATURE, "process_proto_msg()");
            }
        }
    } else {
        ret = -1;
    }

    if (ret == 0) {
        switch(proto_msg->payload_case) {
            case SKISSM__PROTO_MSG__PAYLOAD_SUPPLY_OPKS_MSG:
                consumed = consume_supply_opks_msg(receiver_address, proto_msg->supply_opks_msg);
                break;
            case SKISSM__PROTO_MSG__PAYLOAD_ADD_USER_DEVICE_MSG:
                consumed = consume_add_user_device_msg(receiver_address, proto_msg->add_user_device_msg);
                break;
            case SKISSM__PROTO_MSG__PAYLOAD_REMOVE_USER_DEVICE_MSG:
                consumed = consume_remove_user_device_msg(receiver_address, proto_msg->remove_user_device_msg);
                break;
            case SKISSM__PROTO_MSG__PAYLOAD_INVITE_MSG:
                consumed = consume_invite_msg(receiver_address, proto_msg->invite_msg);
                break;
            case SKISSM__PROTO_MSG__PAYLOAD_ACCEPT_MSG:
                consumed = consume_accept_msg(receiver_address, proto_msg->accept_msg);
                break;
            case SKISSM__PROTO_MSG__PAYLOAD_E2EE_MSG:
                if (proto_msg->e2ee_msg->payload_case == SKISSM__E2EE_MSG__PAYLOAD_ONE2ONE_MSG)
                    consumed = consume_one2one_msg(receiver_address, proto_msg->e2ee_msg);
                else if (proto_msg->e2ee_msg->payload_case == SKISSM__E2EE_MSG__PAYLOAD_GROUP_MSG)
                    consumed = consume_group_msg(receiver_address, proto_msg->e2ee_msg);
                break;
            case SKISSM__PROTO_MSG__PAYLOAD_CREATE_GROUP_MSG:
                consumed = consume_create_group_msg(receiver_address, proto_msg->create_group_msg);
                break;
            case SKISSM__PROTO_MSG__PAYLOAD_ADD_GROUP_MEMBERS_MSG:
                consumed = consume_add_group_members_msg(receiver_address, proto_msg->add_group_members_msg);
                break;
            case SKISSM__PROTO_MSG__PAYLOAD_ADD_GROUP_MEMBER_DEVICE_MSG:
                consumed = consume_add_group_member_device_msg(receiver_address, proto_msg->add_group_member_device_msg);
                break;
            case SKISSM__PROTO_MSG__PAYLOAD_REMOVE_GROUP_MEMBERS_MSG:
                consumed = consume_remove_group_members_msg(receiver_address, proto_msg->remove_group_members_msg);
                break;
            case SKISSM__PROTO_MSG__PAYLOAD_LEAVE_GROUP_MSG:
                consumed = consume_leave_group_msg(receiver_address, proto_msg->leave_group_msg);
                break;
            default:
                // consume the message that is arriving here
                consumed = true;
                break;
        };
    }

    // notify server that the proto_msg has been consumed
    if (consumed) {
        if (proto_msg->tag != NULL) {
            response = consume_proto_msg(receiver_address, proto_msg->tag->proto_msg_id);
            bool save_pending_request = false;
            if (response != NULL) {
                if (response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK ||
                    response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND) {
                    // server consumed
                } else {
                    save_pending_request = true;
                }
            } else {
                save_pending_request = true;
                response = (Skissm__ConsumeProtoMsgResponse *)malloc(sizeof(Skissm__ConsumeProtoMsgResponse));
                skissm__consume_proto_msg_response__init(response);
                response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_SERVICE_UNAVAILABLE;
            }
            if (save_pending_request) {
                // pack and save as pending request
                size_t request_data_len = skissm__proto_msg__get_packed_size(proto_msg);
                uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
                skissm__proto_msg__pack(proto_msg, request_data);
                
                store_pending_request_internal(proto_msg->to, SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_PROTO_MSG, request_data, request_data_len, NULL, 0);
                // release
                free_mem((void *)&request_data, request_data_len);
            }
        } else {
            response = (Skissm__ConsumeProtoMsgResponse *)malloc(sizeof(Skissm__ConsumeProtoMsgResponse));
            skissm__consume_proto_msg_response__init(response);
            response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK;
        }
    } else {
        ssm_notify_log(
            receiver_address, DEBUG_LOG, "process_proto_msg() proto_msg is not consumed payload_case: %d, proto_msg_id: %s",
            proto_msg->payload_case,
            proto_msg->tag == NULL ? "" : proto_msg->tag->proto_msg_id
        );
    }

    // release
    free_proto(proto_msg);

    // done
    return response;
}

void resume_connection() {
    // loop on all accounts
    Skissm__Account **accounts = NULL;
    size_t account_num = get_skissm_plugin()->db_handler.load_accounts(&accounts);

    Skissm__Account *cur_account = NULL;
    size_t i;
    for (i = 0; i < account_num; i++) {
        cur_account = accounts[i];
        resume_connection_internal(cur_account);
        // release
        skissm__account__free_unpacked(cur_account, NULL);
    }

    // release
    if (accounts != NULL)
        free(accounts);
}
