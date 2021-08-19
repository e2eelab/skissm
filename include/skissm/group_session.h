#ifndef GROUP_SESSION_H_
#define GROUP_SESSION_H_

#include <stdint.h>
#include <stddef.h>

#include "skissm.h"

/**
 * @brief Create an outbound group session
 * 
 * @param user_address 
 * @param group_address 
 * @param member_addresses 
 * @param member_num 
 */
void create_outbound_group_session(
    Org__E2eelab__Lib__Protobuf__E2eeAddress *user_address,
    Org__E2eelab__Lib__Protobuf__E2eeAddress *group_address,
    Org__E2eelab__Lib__Protobuf__E2eeAddress **member_addresses,
    size_t member_num
);

/**
 * @brief Create an inbound group session object
 * 
 * @param group_pre_key_payload
 * @param user_address
 */
void create_inbound_group_session(
    Org__E2eelab__Lib__Protobuf__E2eeGroupPreKeyPayload *group_pre_key_payload,
    Org__E2eelab__Lib__Protobuf__E2eeAddress *user_address
);

/**
 * @brief  Encrypt group message
 *
 * @param user_address
 * @param group_address
 * @param plaintext
 * @param plaintext_len
 */
void encrypt_group_session(
    Org__E2eelab__Lib__Protobuf__E2eeAddress *user_address,
    Org__E2eelab__Lib__Protobuf__E2eeAddress *group_address,
    const uint8_t *plaintext, size_t plaintext_len
);


/**
 * @brief Decrypt group message
 *
 * @param user_address
 * @param group_msg
 */
void decrypt_group_session(
    Org__E2eelab__Lib__Protobuf__E2eeAddress *user_address,
    Org__E2eelab__Lib__Protobuf__E2eeMessage *group_msg
);

#endif /* GROUP_SESSION_H_ */
