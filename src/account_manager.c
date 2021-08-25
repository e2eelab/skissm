#include "account_manager.h"
#include "e2ee_protocol.h"
#include "account.h"
#include "mem_util.h"

/* registration related */
static void handle_register_user_response(
    register_user_response_handler *response_handler,
    Org__E2eelab__Skissm__Proto__E2eeAddress *address
) {
    copy_address_from_address(&(response_handler->account->address), address);
    // save to db
    response_handler->account->saved = true;
    ssm_handler.store_account(response_handler->account);
}

register_user_response_handler register_user_response_handler_store = {
    NULL,
    handle_register_user_response
};

/* spk related */
static void handle_publish_spk_response(publish_spk_response_handler *response_handler) {
    // save to db
    if (response_handler->account->saved == true)
        ssm_handler.update_signed_pre_key(response_handler->account, response_handler->account->signed_pre_key_pair);
}

publish_spk_response_handler publish_spk_response_handler_store = {
    NULL,
    handle_publish_spk_response
};

/* opk related */
void supply_opks(struct supply_opks_handler *response_handler) {
    // save to db
    unsigned int i;
    if (response_handler->account->saved == true){
        for (i = 0; i < response_handler->account->n_one_time_pre_keys; i++){
            ssm_handler.add_one_time_pre_key(response_handler->account, response_handler->account->one_time_pre_keys[i]);
        }
    }
}

/* send to the server */
void register_account(){
    Org__E2eelab__Skissm__Proto__E2eeAccount *account = create_account();

    // register account to server
    register_user_response_handler_store.account = account;
    send_register_user_request(account, &register_user_response_handler_store);
}

void publish_spk(Org__E2eelab__Skissm__Proto__E2eeAccount *account){
    // publish account spk to server
    publish_spk_response_handler_store.account = account;
    send_publish_spk_request(account, &publish_spk_response_handler_store);
}
