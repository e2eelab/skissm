#ifndef E2EE_CLIENT_H_
#define E2EE_CLIENT_H_

#include "skissm/skissm.h"

#ifdef __cplusplus
extern "C" {
#endif

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
 * @brief Register a new account.
 *
 * @param account_id The unique account id.
 * @param e2ee_pack_id The e2ee package id to be used.
 */
void register_user(uint64_t account_id, uint32_t e2ee_pack_id);

/**
 * @brief Send invite request and create a new outbound session
 * that needs to be responded before it can be used
 * to send encryption message.
 * @param from From address
 * @param to To Address
 * @return  0 outbound session initialized, wait for being responded.
 *         -1 outbound session is already responded and ready to use.
 *         -2 outbound session is wait for responding.
 */
size_t invite(Skissm__E2eeAddress *from, Skissm__E2eeAddress *to);

/**
 * @brief Get an outbound session that is responded and ready for use.
 * @param from From address
 * @param to To Address
 * @return A responded outbound session or NULL
 */
Skissm__Session *get_outbound_session(Skissm__E2eeAddress *from, Skissm__E2eeAddress *to);

/**
 * @brief Send one2one msg.
 *
 * @param outbound_session
 * @param plaintext_data
 * @param plaintext_data_len
 * @return size_t
 */
size_t send_one2one_msg(Skissm__Session *outbound_session, const uint8_t *plaintext_data, size_t plaintext_data_len);

/**
 * @brief Create a group.
 *
 * @param sender_address
 * @param group_name
 * @param member_num
 * @param member_addresses
 */
void create_group(Skissm__E2eeAddress *sender_address, char *group_name, size_t member_num, Skissm__E2eeAddress **member_addresses);

/**
 * @brief Add group members.
 *
 * @param sender_address
 * @param group_address
 * @param adding_member_addresses
 * @param adding_member_num
 * @return size_t
 */
size_t add_group_members(
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address,
    const Skissm__E2eeAddress **adding_member_addresses,
    size_t adding_member_num);

/**
 * @brief Remove group members.
 *
 * @param sender_address
 * @param group_address
 * @param removing_member_addresses
 * @param removing_member_num
 * @return size_t
 */
size_t remove_group_members(
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address,
    const Skissm__E2eeAddress **removing_member_addresses,
    size_t removing_member_num
);

/**
 * @brief Send group msg.
 *
 * @param sender_address
 * @param group_address
 * @param plaintext_data
 * @param plaintext_data_len
 */
void send_group_msg(Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address, const uint8_t *plaintext_data, size_t plaintext_data_len);

/**
 * @brief Process incoming protocol messages.
 *
 * @param proto_msg_data
 * @param proto_msg_data_len
 */
void process_proto_msg(uint8_t *proto_msg_data, size_t proto_msg_data_len);

#ifdef __cplusplus
}
#endif

#endif // E2EE_CLIENT_H_