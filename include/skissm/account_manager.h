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

#ifndef ACCOUNT_MANAGER_H_
#define ACCOUNT_MANAGER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm/skissm.h"

/**
 * @brief Create a RegisterUserRequest message to be sent to server.
 *
 * @param account
 * @return Skissm__RegisterUserRequest*
 */
Skissm__RegisterUserRequest *produce_register_request(Skissm__Account *account);

/**
 * @brief Process an incoming RegisterUserResponse message.
 *
 * @param account
 * @param payload
 */
void consume_register_response(Skissm__Account *account, Skissm__RegisterUserResponse *payload);

/**
 * @brief Create a PublishSpkRequest message to be sent to server.
 *
 * @param account
 * @return Skissm__PublishSpkRequest*
 */
Skissm__PublishSpkRequest *produce_publish_spk_request(Skissm__Account *account);

/**
 * @brief Process an incoming PublishSpkResponse message.
 *
 * @param account
 * @param response
 */
void consume_publish_spk_response(Skissm__Account *account, Skissm__PublishSpkResponse *response);

/**
 * @brief Create a SupplyOpksRequest message to be sent to server.
 *
 * @param account
 * @param opks_num
 * @return Skissm__SupplyOpksRequest*
 */
Skissm__SupplyOpksRequest *produce_supply_opks_request(Skissm__Account *account, uint32_t opks_num);

/**
 * @brief Process an incoming SupplyOpksResponse message.
 *
 * @param account
 * @param response
 */
void consume_supply_opks_response(Skissm__Account *account, Skissm__SupplyOpksResponse *response);

/**
 * @brief Process an incoming SupplyOpksMsg message.
 *
 * @param receiver_address
 * @param msg
 * @return true
 * @return false
 */
bool consume_supply_opks_msg(Skissm__E2eeAddress *receiver_address, Skissm__SupplyOpksMsg *msg);

#ifdef __cplusplus
}
#endif

#endif // ACCOUNT_MANAGER_H_
