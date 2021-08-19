#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "skissm.h"
#include "e2ee_protocol.h"
#include "account.h"
#include "cipher.h"
#include "mem_util.h"

#include "test_env.h"

// -----------------
#include "account.h"
#include "db.h"
#include "test_env.h"
#include "test_util.h"

// i haven't release the memory after testing yet

// test about account db
void test_setup()
{
  fprintf(stderr, "test_setup\n");
  setup();
  tear_down();
}

void test_setup_call_twice()
{
  fprintf(stderr, "test_setup_call_twice\n");
  setup();
  tear_down();
  setup();
  tear_down();
}

void test_insert_address()
{
  fprintf(stderr, "test_insert_address\n");
  setup();

  // create address
  Org__E2eelab__Lib__Protobuf__E2eeAddress *address;
  mock_address(&address, "alice", "alice's domain", "alice's device");

  // insert to the db
  insert_address(address);

  // free
  free_address(address);

  tear_down();
}

void test_insert_key_pair()
{
  fprintf(stderr, "test_insert_key_pair\n");
  setup();

  // create keypair
  Org__E2eelab__Lib__Protobuf__KeyPair *keypair;
  mock_keypair(&keypair, "hello public key", "hello private key");

  // insert to the db
  insert_key_pair(keypair);

  // free
  free_keypair(keypair);

  tear_down();
}

void test_insert_signed_pre_key()
{
  fprintf(stderr, "test_insert_signed_pre_key\n");
  setup();

  // create spk
  Org__E2eelab__Lib__Protobuf__SignedPreKeyPair *signed_pre_keypair;
  mock_signed_pre_keypair(&signed_pre_keypair, 0, "hello public key", "hello private key", "hello signature");

  // insert to the db
  insert_signed_pre_key(signed_pre_keypair);

  // free spk
  free_signed_pre_keypair(signed_pre_keypair);

  tear_down();
}

void test_insert_one_time_pre_key()
{
  fprintf(stderr, "test_insert_one_time_pre_key\n");
  setup();

  // create opk
  Org__E2eelab__Lib__Protobuf__OneTimePreKeyPair *onetime_pre_keypiar;
  mock_onetime_pre_keypiar(&onetime_pre_keypiar, 0, 0, "hello public key", "hello private key");

  // insert to the db
  insert_one_time_pre_key(onetime_pre_keypiar);

  // free
  free_onetime_pre_keypiar(onetime_pre_keypiar);

  tear_down();
}

void test_insert_account()
{
  // todo
}

void test_insert_account_one_time_pre_key_id()
{
  // todo
}

void test_init_account()
{
  fprintf(stderr, "test_init_account\n");
  setup();

  // create account
  Org__E2eelab__Lib__Protobuf__E2eeAccount *account = create_account();
  mock_address(&(account->address), "alice", "alice's domain", "alice's device");

  // insert to the db
  init_account(account);

  // free
  free_account(account);

  tear_down();
}

void test_update_identity_key()
{
  fprintf(stderr, "test_update_identity_key\n");
  setup();

  // create account
  Org__E2eelab__Lib__Protobuf__E2eeAccount *account = create_account();
  mock_address(&(account->address), "alice", "alice's domain", "alice's device");

  // insert to the db
  init_account(account);

  // keypair used to update
  Org__E2eelab__Lib__Protobuf__KeyPair *kp_p;
  mock_keypair(&kp_p, "new public key", "new private key");

  // update_identity_key
  update_identity_key(account, kp_p);

  // free
  free_account(account);

  tear_down();
}

void test_update_signed_pre_key()
{
  fprintf(stderr, "test_update_signed_pre_key\n");
  setup();

  // create account
  Org__E2eelab__Lib__Protobuf__E2eeAccount *account = create_account();
  mock_address(&(account->address), "alice", "alice's domain", "alice's device");

  // insert to the db
  init_account(account);

  // create spk
  Org__E2eelab__Lib__Protobuf__SignedPreKeyPair *signed_pre_keypair;
  mock_signed_pre_keypair(&signed_pre_keypair, 1, "hello public key", "hello private key", "hello signature");

  // update_signed_pre_key
  update_signed_pre_key(account, signed_pre_keypair);

  // free
  free_account(account);
  free_signed_pre_keypair(signed_pre_keypair);

  tear_down();
}

void test_update_address()
{
  fprintf(stderr, "test_update_address\n");
  setup();

  // create account
  Org__E2eelab__Lib__Protobuf__E2eeAccount *account = create_account();
  mock_address(&(account->address), "alice", "alice's domain", "alice's device");

  // insert to the db
  init_account(account);

  // create address
  Org__E2eelab__Lib__Protobuf__E2eeAddress *new_address;
  mock_address(&(new_address), "bob", "bob's domain", "bob's device");

  // update_address
  update_address(account, new_address);

  // free
  free_account(account);
  free_address(new_address);

  tear_down();
}

void test_add_one_time_pre_key()
{
  fprintf(stderr, "test_add_one_time_pre_key\n");
  setup();

  // create account
  Org__E2eelab__Lib__Protobuf__E2eeAccount *account = create_account();
  mock_address(&(account->address), "alice", "alice's domain", "alice's device");

  // insert to the db
  init_account(account);

  // create opk
  Org__E2eelab__Lib__Protobuf__OneTimePreKeyPair *onetime_pre_keypiar;
  mock_onetime_pre_keypiar(&onetime_pre_keypiar, 101, 0, "hello public key", "hello private key");

  // add_one_time_pre_key
  add_one_time_pre_key(account, onetime_pre_keypiar);

  // free
  free_account(account);
  free_onetime_pre_keypiar(onetime_pre_keypiar);

  tear_down();
}

void test_remove_one_time_pre_key()
{
  fprintf(stderr, "test_remove_one_time_pre_key\n");
  setup();

  // create account
  Org__E2eelab__Lib__Protobuf__E2eeAccount *account = create_account();
  mock_address(&(account->address), "alice", "alice's domain", "alice's device");

  // insert to the db
  init_account(account);

  // remove_one_time_pre_key
  remove_one_time_pre_key(account, 0);

  // free
  free_account(account);

  tear_down();
}

void test_load_account()
{
  fprintf(stderr, "test_load_account\n");
  setup();

  // create account
  Org__E2eelab__Lib__Protobuf__E2eeAccount *account = create_account();
  mock_address(&(account->address), "alice", "alice's domain", "alice's device");

  // insert to the db
  init_account(account);

  // load_account
  Org__E2eelab__Lib__Protobuf__E2eeAccount *account_copy;
  load_account(&(account->account_id), &account_copy);

  // assert account equals to account_copy
  printf("%d\n", is_equal_account(account, account_copy));

  // free
  free_account(account);
  free_account(account_copy);

  tear_down();
}

void test_two_accounts()
{
  fprintf(stderr, "test_two_accounts\n");
  setup();

  // create the first account
  Org__E2eelab__Lib__Protobuf__E2eeAccount *account_1 = create_account();
  mock_address(&(account_1->address), "alice", "alice's domain", "alice's device");

  // insert to the db
  init_account(account_1);

  // create the first account
  Org__E2eelab__Lib__Protobuf__E2eeAccount *account_2 = create_account();
  mock_address(&(account_2->address), "bob", "bob's domain", "bob's device");

  // insert to the db
  init_account(account_2);

  // load the first account
  Org__E2eelab__Lib__Protobuf__E2eeAccount *account_copy_1;
  load_account(&(account_1->account_id), &account_copy_1);

  // assert account_1 equals to account_copy_1
  printf("%d\n", is_equal_account(account_1, account_copy_1));

  // load the second account
  Org__E2eelab__Lib__Protobuf__E2eeAccount *account_copy_2;
  load_account(&(account_2->account_id), &account_copy_2);

  // assert account_2 equals to account_copy_2
  printf("%d\n", is_equal_account(account_2, account_copy_2));

  // free
  free_account(account_1);

  tear_down();
}

int main()
{
  test_setup();
  test_setup_call_twice();
  test_insert_address();
  test_insert_key_pair();
  test_insert_signed_pre_key();
  test_insert_one_time_pre_key();
  test_insert_account();
  test_insert_account_one_time_pre_key_id();
  test_init_account();
  test_update_identity_key();
  test_update_signed_pre_key();
  test_update_address();
  test_add_one_time_pre_key();
  test_remove_one_time_pre_key();
  test_load_account();
  test_two_accounts();
}
