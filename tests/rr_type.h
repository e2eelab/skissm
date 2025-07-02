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
#ifndef RR_TYPE_H_
#define RR_TYPE_H_

#include "skissm/skissm.h"

typedef struct proto_msg_package {
    int type;
    Skissm__E2eeAddress *address_data;
    size_t proto_msg_len;
    uint8_t *proto_msg_data;
} proto_msg_package;


enum Resquest_Response_type {
    DEBUG = 0,
    REGISTER_USER = 1,
    GET_PRE_KEY_BUNDLE = 2,
    INVITE = 3,
    ACCEPT = 4,
    PUBLISH_SPK = 5,
    SUPPLY_OPKS = 6,
    SEND_ONE2ONE_MSG = 7,
    CREATE_GROUP = 8,
    ADD_GROUP_MEMBERS = 9,
    ADD_GROUP_MEMBER_DEVICE = 10,
    REMOVE_GROUP_MEMBERS = 11,
    LEAVE_GROUP = 12,
    SEND_GROUP_MSG = 13,
    CONSUME_PROTO_MSG = 14,
};

#endif /* RR_TYPE_H_ */
