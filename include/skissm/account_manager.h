#ifndef ACCOUNT_MANAGER_H_
#define ACCOUNT_MANAGER_H_

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
void publish_spk(Org__E2eelab__Lib__Protobuf__E2eeAccount *account);

#endif
