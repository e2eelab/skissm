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
#ifndef E2EE_PROTOCOL_H_
#define E2EE_PROTOCOL_H_

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm/e2ee_protocol_handler.h"

typedef struct handler_entry {
    uint32_t key;
    void *handler;
} handler_entry;

/**
 * @see [HTTP/1.1 Status Code Definitions](https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html)
 */
typedef enum response_code {
    OK = 200,                     // The request has succeeded.
    Created = 201,                // The request has been fulfilled and resulted in a new resource being created.
    Accepted = 202,               // The request has been accepted for processing, but the processing has not been completed.
    No_Content = 204,             // The server has fulfilled the request but does not need to return an entity-body, and might want to return updated metainformation.
    Bad_Request = 400,            // The request could not be understood by the server due to malformed syntax.
    Unauthorized = 401,           // The request requires user authentication.
    Forbidden = 403,              // The server understood the request, but is refusing to fulfill it.
    Not_Found = 404,              // The server has not found anything matching the Request-URI.
    Internal_Server_Error = 500   // The server encountered an unexpected condition which prevented it from fulfilling the request.
} response_code;

/**
 * @brief Generate next request id
 *
 * @return
 */
uint32_t next_request_id();

/**
 * @brief Add a request handler
 *
 * @param entry
 */
void add_request_handler(handler_entry *entry);

/**
 * @brief Remove a request handler
 *
 * @param entry
 */
void remove_request_handler(handler_entry *entry);

/**
 * @brief Get the request handler by given command.
 *
 * @param cmd
 * @return
 */
void *get_request_handler(Skissm__E2eeCommands cmd);

/**
 * @brief Insert a response handler with id
 *
 * @param id
 * @param response_handler
 */
void insert_response_handler(uint32_t id, void *response_handler);

/**
 * @brief Delete a response handler by given id
 *
 * @param id
 */
void delete_response_handler(uint32_t id);

/**
 * @brief Get the response handler by given id
 *
 * @param id
 * @return
 */
void *get_response_handler(uint32_t id);

/**
 * @brief Release the response handlers map
 *
 */
void destroy_response_handlers_map();

/**
 * @brief Protocol begin
 *
 */
void protocol_begin();

/**
 * @brief Protocol end
 *
 */
void protocol_end();

/**
 * @brief Send a register user request to messaging server
 *
 * @param account
 * @param response_handler
 */
void send_register_user_request(
    Skissm__E2eeAccount *account,
    register_user_response_handler *response_handler);

/**
 * @brief Send a publish spk request to messaging server
 *
 * @param account
 * @param response_handler
 */
void send_publish_spk_request(Skissm__E2eeAccount *account,
                              publish_spk_response_handler *response_handler);

/**
 * @brief send a supply opks response to messaging server
 *
 * @param request_id
 * @param response_data
 * @param handler
 * @param user_address
 */
void send_supply_opks_response(
    uint32_t request_id,
    Skissm__ResponseData *response_data,
    supply_opks_handler *handler,
    Skissm__E2eeAddress *user_address);

/**
 * @brief Send a create group response to messaging server
 *
 * @param request_id
 * @param response_data
 */
void send_create_group_response(
    uint32_t request_id, Skissm__ResponseData *response_data);

/**
 * @brief Send an add group members response to messaging server
 *
 * @param request_id
 * @param response_data
 */
void send_add_group_members_response(
    uint32_t request_id,
    Skissm__ResponseData *response_data);

/**
 * @brief Send a remove group members response to messaging server
 *
 * @param request_id
 * @param response_data
 */
void send_remove_group_members_response(
    uint32_t request_id,
    Skissm__ResponseData *response_data);

/**
 * @brief Send a get pre-key bundle request to messaging server
 *
 * @param to
 * @param response_handler
 */
void send_get_pre_key_bundle_request(
    Skissm__E2eeAddress *to,
    pre_key_bundle_response_handler *response_handler);

/**
 * @brief Send one-to-one encrypted message to messaging server
 *
 * @param outbound_session
 * @param e2ee_plaintext
 * @param e2ee_plaintext_len
 */
void send_one2one_msg(Skissm__E2eeSession *outbound_session, const uint8_t *e2ee_plaintext, size_t e2ee_plaintext_len);

/**
 * @brief Send group encrypted message to messaging server
 *
 * @param group_session
 * @param plaintext
 * @param plaintext_len
 */
void send_group_msg(Skissm__E2eeGroupSession *group_session, const uint8_t *plaintext, size_t plaintext_len) ;

void send_invite_request(Skissm__E2eeSession *outbound_session, ProtobufCBinaryData *ciphertext_2,
                         ProtobufCBinaryData *ciphertext_3, ProtobufCBinaryData *ciphertext_4
);

void send_accept_request(ProtobufCBinaryData *ciphertext_1);

/**
 * @brief Send a create group request to messaging server
 *
 * @param response_handler
 */
void send_create_group_request(create_group_response_handler *response_handler);

/**
 * @brief Send a get group request to messaging server
 *
 * @param response_handler
 */
void send_get_group_request(get_group_response_handler *response_handler);

/**
 * @brief Send a add group members request to messaging server
 *
 * @param response_handler
 */
void send_add_group_members_request(add_group_members_response_handler *response_handler);

/**
 * @brief Send a remove group members request to messaging server
 *
 * @param response_handler
 */
void send_remove_group_members_request(remove_group_members_response_handler *response_handler);

/**
 * @brief Process a protocol msg received from messaging server
 *
 * @param server_msg
 * @param server_msg_len
 * @param receiver_address
 */
void process_protocol_msg(
    uint8_t *server_msg, size_t server_msg_len,
    Skissm__E2eeAddress *receiver_address);

#ifdef __cplusplus
}
#endif

#endif /* E2EE_PROTOCOL_H_ */
