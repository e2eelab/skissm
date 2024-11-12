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
#include "skissm/log_code.h"

static const char * LOG_CODE_STRINGS[] = {
    "DEBUG_LOG",

    // cipher suite
    "BAD_CIPHER_SUITE",
    "BAD_E2EE_PACK",

    // account
    "BAD_ACCOUNT",
    "BAD_KEY_PAIR",
    "BAD_SIGNED_PRE_KEY",
    "BAD_SIGNATURE",
    "BAD_ONE_TIME_PRE_KEY",
    "BAD_AUTH",
    "BAD_AUTHENTICATOR",
    "BAD_PRIVATE_KEY",
    "BAD_PUBLIC_KEY",
    "BAD_REMOVE_OPK",

    // address
    "BAD_ADDRESS",
    "BAD_USER_ID",
    "BAD_DEVICE_ID",
    "BAD_DOMAIN",
    "BAD_USER_NAME",

    // ratchet
    "BAD_MESSAGE_ENCRYPTION",
    "BAD_MESSAGE_DECRYPTION",
    "BAD_FILE_ENCRYPTION",
    "BAD_FILE_DECRYPTION",
    "BAD_MESSAGE_KEY",
    "BAD_MESSAGE_SEQUENCE",
    "BAD_RATCHET_KEY",

    // session
    "BAD_SESSION",
    "BAD_SESSION_ID",
    "BAD_PRE_KEY_BUNDLE",

    // group session
    "BAD_GROUP_SESSION",
    "BAD_GROUP_SESSION_ID",
    "BAD_GROUP_NAME",
    "BAD_GROUP_ADDRESS",
    "BAD_GROUP_MEMBERS",
    "BAD_GROUP_MEMBER_INFO",
    "BAD_GROUP_INFO",
    "BAD_GROUP_SEED",
    "BAD_GROUP_CHAIN_KEY",
    "BAD_GROUP_PRE_KEY_BUNDLE",
    "BAD_GROUP_UPDATE_KEY_BUNDLE",

    // request
    "BAD_ACCEPT_REQUEST",
    "BAD_ADD_GROUP_MEMBER_DEVICE_REQUEST",
    "BAD_ADD_GROUP_MEMBERS_REQUEST",
    "BAD_CONSUME_PROTO_MSG_REQUEST",
    "BAD_CREATE_GROUP_REQUEST",
    "BAD_GET_GROUP_REQUEST",
    "BAD_GET_PRE_KEY_BUNDLE_REQUEST",
    "BAD_INVITE_REQUEST",
    "BAD_LEAVE_GROUP_REQUEST",
    "BAD_PUBLISH_SPK_REQUEST",
    "BAD_REGISTER_USER_REQUEST",
    "BAD_REMOVE_GROUP_MEMBERS_REQUEST",
    "BAD_SEND_GROUP_MSG_REQUEST",
    "BAD_SEND_ONE2ONE_MSG_REQUEST",
    "BAD_SUPPLY_OPKS_REQUEST",
    "BAD_UPDATE_USER_REQUEST",
    // response
    "BAD_ACCEPT_RESPONSE",
    "BAD_ADD_GROUP_MEMBER_DEVICE_RESPONSE",
    "BAD_ADD_GROUP_MEMBERS_RESPONSE",
    "BAD_CONSUME_PROTO_MSG_RESPONSE",
    "BAD_CREATE_GROUP_RESPONSE",
    "BAD_GET_GROUP_RESPONSE",
    "BAD_GET_PRE_KEY_BUNDLE_RESPONSE",
    "BAD_INVITE_RESPONSE",
    "BAD_LEAVE_GROUP_RESPONSE",
    "BAD_PUBLISH_SPK_RESPONSE",
    "BAD_REGISTER_USER_RESPONSE",
    "BAD_REMOVE_GROUP_MEMBERS_RESPONSE",
    "BAD_SEND_GROUP_MSG_RESPONSE",
    "BAD_SEND_ONE2ONE_MSG_RESPONSE",
    "BAD_SUPPLY_OPKS_RESPONSE",
    "BAD_UPDATE_USER_RESPONSE",
    // msg
    "BAD_ACCEPT_MSG",
    "BAD_ADD_GROUP_MEMBER_DEVICE_MSG",
    "BAD_ADD_GROUP_MEMBERS_MSG",
    "BAD_ADD_USER_DEVICE_MSG",
    "BAD_CREATE_GROUP_MSG",
    "BAD_GET_GROUP_MSG",
    "BAD_GET_PRE_KEY_BUNDLE_MSG",
    "BAD_INVITE_MSG",
    "BAD_LEAVE_GROUP_MSG",
    "BAD_PUBLISH_SPK_MSG",
    "BAD_REGISTER_USER_MSG",
    "BAD_REMOVE_GROUP_MEMBERS_MSG",
    "BAD_SUPPLY_OPKS_MSG",
    "BAD_UPDATE_USER_MSG",

    // plaintext
    "BAD_PLAINTEXT",

    // server signature
    "BAD_SERVER_SIGNATURE"
};

const char *logcode_string(LogCode log_code){
    if (log_code < (sizeof(LOG_CODE_STRINGS)/sizeof(LOG_CODE_STRINGS[0]))) {
        return LOG_CODE_STRINGS[log_code];
    } else {
        return "UNKNOWN_LOG_CODE";
    }
}
