#ifndef TEST_ENV_H_
#define TEST_ENV_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "skissm.h"

extern const char *db_name;

void setup();
void tear_down();

void random_session_id(ProtobufCBinaryData *session_id);
void print_hex(char *title, uint8_t *msg, size_t msg_len);
void print_result(char *title, bool success);

void load_account(ProtobufCBinaryData *id, Org__E2eelab__Skissm__Proto__E2eeAccount **account);
void load_account_by_address(Org__E2eelab__Skissm__Proto__E2eeAddress *address_p, Org__E2eelab__Skissm__Proto__E2eeAccount **account_pp);
void init_account(Org__E2eelab__Skissm__Proto__E2eeAccount *account);
#endif /* TEST_ENV_H_ */
