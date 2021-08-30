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
#ifndef GROUP_SESSION_MANAGER_H_
#define GROUP_SESSION_MANAGER_H_

#include <stddef.h>
#include <stdint.h>

#include "skissm.h"
#include "e2ee_protocol_handler.h"

/**
 * @brief Create a group object
 *
 * @param user_address
 * @param group_name
 * @param member_addresses
 * @param member_num
 */
void create_group(Org__E2eelab__Skissm__Proto__E2eeAddress *user_address,
                  ProtobufCBinaryData *group_name,
                  Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses,
                  size_t member_num);

/**
 * @brief Get the group members
 *
 * @param group_address
 */
get_group_response_handler *get_group_members(Org__E2eelab__Skissm__Proto__E2eeAddress *group_address);

/**
 * @brief Add group members
 *
 * @param sender_address
 * @param group_address
 * @param new_member_addresses
 * @param new_member_num
 */
size_t add_group_members(
    Org__E2eelab__Skissm__Proto__E2eeAddress *sender_address,
    Org__E2eelab__Skissm__Proto__E2eeAddress *group_address,
    Org__E2eelab__Skissm__Proto__E2eeAddress **new_member_addresses,
    size_t new_member_num);

/**
 * @brief Remove group members
 *
 * @param sender_address
 * @param group_address
 * @param old_member_addresses
 * @param old_member_num
 */
void remove_group_members(
    Org__E2eelab__Skissm__Proto__E2eeAddress *sender_address,
    Org__E2eelab__Skissm__Proto__E2eeAddress *group_address,
    Org__E2eelab__Skissm__Proto__E2eeAddress **old_member_addresses,
    size_t old_member_num);

#endif /* GROUP_SESSION_MANAGER_H_ */
