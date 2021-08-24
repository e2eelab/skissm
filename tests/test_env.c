#include "test_env.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <string.h>
#include <sqlite3.h>

#include "cipher.h"
#include "crypto.h"
#include "mem_util.h"
#include "e2ee_protocol_simulator.h"
#include "e2ee_protocol.h"

#include "db.h"

// test case interface

void setup()
{
  init_db();
  protocol_begin();
}

void tear_down()
{
  close_db();
  protocol_end();
}

// utility functions
void random_session_id(ProtobufCBinaryData *session_id)
{
  session_id->len = SHA256_OUTPUT_LENGTH;
  session_id->data = (uint8_t *)malloc(SHA256_OUTPUT_LENGTH * sizeof(uint8_t));
  ssm_handler.handle_rg(session_id->data, SHA256_OUTPUT_LENGTH);
}

void print_hex(char *title, uint8_t *msg, size_t msg_len)
{
  printf("%s", title);
  for (int i = 0; i < msg_len; i++)
  {
    if (i % 16 == 0)
      printf("\n| ");
    printf("0x%02x ", msg[i]);

    if (i % 8 == 7)
      printf("| ");
  }
    
  printf("\n");
}

void print_result(char *title, bool success)
{
  if (success)
      printf("%s: success\n", title);
  else
      printf("%s: failed\n", title);
}

// common handlers
static int64_t handle_get_ts()
{
  time_t now = time(0);
  return now;
}

static void handle_rg(uint8_t *rand_out, size_t rand_out_len)
{
  srand((unsigned int)time(NULL));
  for (int i = 0; i < rand_out_len; i++)
  {
      rand_out[i] = random() % UCHAR_MAX;
  }
}

static void handle_generate_uuid(uint8_t uuid[UUID_LEN])
{
  handle_rg(uuid, UUID_LEN);
}

static int handle_send(u_int8_t *msg, size_t msg_len)
{
  // printf("mock handle_send ==> %s", msg);
  mock_protocol_receive(msg, msg_len);
  return 0;
}

// account related handlers
void load_account(ProtobufCBinaryData *account_id, Org__E2eelab__Skissm__Proto__E2eeAccount **account)
{
  if (account_id == NULL)
  {
    load_id(&account_id);
    load_account(account_id, account);
    free(account_id);
    return;
  }

  *account = (Org__E2eelab__Skissm__Proto__E2eeAccount *)malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAccount));
  Org__E2eelab__Skissm__Proto__e2ee_account__init((*account));

  (*account)->version = load_version(account_id);
  (*account)->saved = load_saved(account_id);
  load_address(account_id, &((*account)->address));

  load_signed_pre_key_pair(account_id, &((*account)->signed_pre_key_pair));
  load_identity_key_pair(account_id, &((*account)->identity_key_pair));
  (*account)->n_one_time_pre_keys = load_one_time_pre_keys(account_id, &((*account)->one_time_pre_keys));
  (*account)->next_signed_pre_key_id = load_next_signed_pre_key_id(account_id);
  (*account)->next_one_time_pre_key_id = load_next_one_time_pre_key_id(account_id);
}

void load_account_by_address(Org__E2eelab__Skissm__Proto__E2eeAddress *address, Org__E2eelab__Skissm__Proto__E2eeAccount **account)
{
  ProtobufCBinaryData *account_id;
  load_id_by_address(address, &account_id);
  load_account(account_id, account);
}

void init_account(Org__E2eelab__Skissm__Proto__E2eeAccount *account)
{
  // insert address
  sqlite_int64 address_id = insert_address(account->address);

  // insert identity_key_pair
  sqlite_int64 identity_key_pair_id = insert_key_pair(account->identity_key_pair);

  // insert signed_pre_key_pair
  sqlite_int64 signed_pre_key_id = insert_signed_pre_key(account->signed_pre_key_pair);

  // insert one_time_pre_keys
  sqlite_int64 one_time_pre_key_ids[account->n_one_time_pre_keys];
  for (int i = 0; i < account->n_one_time_pre_keys; i++)
  {
    one_time_pre_key_ids[i] = insert_one_time_pre_key(account->one_time_pre_keys[i]);
  }

  // insert account
  sqlite_int64 account_id = insert_account(&(account->account_id),
                                  account->version,
                                  account->saved,
                                  address_id,
                                  identity_key_pair_id,
                                  signed_pre_key_id,
                                  account->next_signed_pre_key_id,
                                  account->next_one_time_pre_key_id);

  // insert ACCOUNT_ONE_TIME_PRE_KEY_PAIR
  insert_account_signed_pre_key_id(account_id, signed_pre_key_id);

  // insert ACCOUNT_ONE_TIME_PRE_KEY_PAIR
  for (int i = 0; i < account->n_one_time_pre_keys; i++)
  {
    insert_account_one_time_pre_key_id(account_id, one_time_pre_key_ids[i]);
  }
}

// callback handlers
static void on_one2one_msg_received(
      Org__E2eelab__Skissm__Proto__E2eeAddress *from_address,
      Org__E2eelab__Skissm__Proto__E2eeAddress *to_address,
      uint8_t *plaintext, size_t plaintext_len) {
    printf("😊 on_one2one_msg_received: plaintext[len=%zu]: %s\n", plaintext_len, plaintext);
}

static void on_group_msg_received(
      Org__E2eelab__Skissm__Proto__E2eeAddress *from_address,
      Org__E2eelab__Skissm__Proto__E2eeAddress *group_address,
      uint8_t *plaintext, size_t plaintext_len) {
    printf("😊 on_group_msg_received: plaintext[len=%zu]: %s\n", plaintext_len, plaintext);
}

const struct skissm_handler ssm_handler = {
    // common
    handle_get_ts,
    handle_rg,
    handle_generate_uuid,
    handle_send,
    // account
    init_account,
    load_account,
    load_account_by_address,
    update_identity_key,
    update_signed_pre_key,
    update_address,
    add_one_time_pre_key,
    remove_one_time_pre_key,
    // session
    load_inbound_session,
    store_session,
    load_outbound_session,
    unload_session,
    load_outbound_group_session,
    load_inbound_group_session,
    store_group_session,
    unload_group_session,
    unload_inbound_group_session,
};
