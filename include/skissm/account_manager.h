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

#include "e2ee_protocol_handler.h"

/**
 * @brief Handle the request for suplying opks
 *
 * @param response_handler The response handler
 */
void supply_opks(supply_opks_handler *response_handler);

/**
 * @brief Register an account
 *
 */
void register_account();

/**
 * @brief Publish new spk to messaging server
 *
 * @param account The account to be processed
 */
void publish_spk(Skissm__E2eeAccount *account);

/**
 * @brief Produce a register request payload object
 * Copy all of the public keys stored in the account that will be published
 * to the messaging server.
 * @param account The account to be processed
 * @return The request payload data
 */
Skissm__RegisterUserRequestPayload *produce_register_request_payload(Skissm__E2eeAccount *account);

/**
 * @brief Consume a register response payload object
 * Keep the address of a registered account to db
 * @param account The account to be processed
 * @param payload The response payload data
 */
void consume_register_response_payload(Skissm__E2eeAccount *account, Skissm__RegisterUserResponsePayload *payload);

Skissm__PublishSpkRequestPayload *produce_publish_spk_request_payload(Skissm__E2eeAccount *account);
void consume_publish_spk_response_payload(Skissm__E2eeAccount *account);

#ifdef __cplusplus
}
#endif

#endif
