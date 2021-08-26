#include <string.h>
#include <stdio.h>

#include "test_env.h"
#include "e2ee_protocol_simulator.h"
#include "e2ee_protocol.h"
#include "mem_util.h"

static const char DOMAIN[] = "e2eelab.org";

typedef struct user_data{
    Org__E2eelab__Skissm__Proto__E2eeAddress *address;
    Org__E2eelab__Skissm__Proto__RegisterUserRequestPayload *pre_key;
} user_data;

typedef struct group_data{
    Org__E2eelab__Skissm__Proto__E2eeAddress *group_address;
    ProtobufCBinaryData group_name;
    size_t member_num;
    Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses;
} group_data;

#define user_data_max 8

#define group_data_max 8

static user_data user_data_set[user_data_max] = {{NULL, NULL},
                                                 {NULL, NULL},
                                                 {NULL, NULL},
                                                 {NULL, NULL},
                                                 {NULL, NULL},
                                                 {NULL, NULL},
                                                 {NULL, NULL},
                                                 {NULL, NULL}};

static group_data group_data_set[user_data_max] = {{NULL, {0, NULL}, 0, NULL},
                                                   {NULL, {0, NULL}, 0, NULL},
                                                   {NULL, {0, NULL}, 0, NULL},
                                                   {NULL, {0, NULL}, 0, NULL},
                                                   {NULL, {0, NULL}, 0, NULL},
                                                   {NULL, {0, NULL}, 0, NULL},
                                                   {NULL, {0, NULL}, 0, NULL},
                                                   {NULL, {0, NULL}, 0, NULL}};

static uint8_t user_data_set_insert_pos = 0;

static uint8_t group_data_set_insert_pos = 0;

void protocol_simulator_release(){
    uint8_t i, j;
    for (i = 0; i < user_data_set_insert_pos; i++){
        org__e2eelab__skissm__proto__e2ee_address__free_unpacked(user_data_set[i].address, NULL);
        user_data_set[i].address = NULL;
        org__e2eelab__skissm__proto__register_user_request_payload__free_unpacked(user_data_set[i].pre_key, NULL);
        user_data_set[i].pre_key = NULL;
    }
    user_data_set_insert_pos = 0;
    for (i = 0; i < group_data_set_insert_pos; i++){
        org__e2eelab__skissm__proto__e2ee_address__free_unpacked(group_data_set[i].group_address, NULL);
        group_data_set[i].group_address = NULL;
        free_mem((void **)&(group_data_set[i].group_name.data), group_data_set[i].group_name.len);
        group_data_set[i].group_name.len = 0;
        for (j = 0; j < group_data_set[i].member_num; j++){
            org__e2eelab__skissm__proto__e2ee_address__free_unpacked(group_data_set[i].member_addresses[j], NULL);
            group_data_set[i].member_addresses[j] = NULL;
        }
        group_data_set[i].member_num = 0;
    }
    group_data_set_insert_pos = 0;
}

static void mock_protocol_send(
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *response,
    Org__E2eelab__Skissm__Proto__E2eeAddress *receiver_address
) {
    /* pack response */
    size_t server_msg_len = org__e2eelab__skissm__proto__e2ee_protocol_msg__get_packed_size(response);
    uint8_t *server_msg = (uint8_t *) malloc(sizeof(uint8_t) * server_msg_len);
    org__e2eelab__skissm__proto__e2ee_protocol_msg__pack(response, server_msg);

    /* send to client */
    process_protocol_msg(server_msg, server_msg_len, receiver_address);

    /* release */
    free_mem((void **)&server_msg, server_msg_len);
}

static void process_register_user_request(
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *request,
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *response
) {
    response->cmd = ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__register_user_response;

    /* unpack */
    Org__E2eelab__Skissm__Proto__RegisterUserRequestPayload *payload = org__e2eelab__skissm__proto__register_user_request_payload__unpack(NULL, request->payload.len, request->payload.data);

    /* prepare to store */
    user_data_set[user_data_set_insert_pos].pre_key = (Org__E2eelab__Skissm__Proto__RegisterUserRequestPayload *) malloc(sizeof(Org__E2eelab__Skissm__Proto__RegisterUserRequestPayload));
    org__e2eelab__skissm__proto__register_user_request_payload__init(user_data_set[user_data_set_insert_pos].pre_key);

    copy_protobuf_from_protobuf(&(user_data_set[user_data_set_insert_pos].pre_key->identity_key_public), &(payload->identity_key_public));
    user_data_set[user_data_set_insert_pos].pre_key->signed_pre_key_public = (Org__E2eelab__Skissm__Proto__SignedPreKeyPublic *) malloc(sizeof(Org__E2eelab__Skissm__Proto__SignedPreKeyPublic));
    org__e2eelab__skissm__proto__signed_pre_key_public__init(user_data_set[user_data_set_insert_pos].pre_key->signed_pre_key_public);
    user_data_set[user_data_set_insert_pos].pre_key->signed_pre_key_public->spk_id = payload->signed_pre_key_public->spk_id;
    copy_protobuf_from_protobuf(&(user_data_set[user_data_set_insert_pos].pre_key->signed_pre_key_public->public_key), &(payload->signed_pre_key_public->public_key));
    copy_protobuf_from_protobuf(&(user_data_set[user_data_set_insert_pos].pre_key->signed_pre_key_public->signature), &(payload->signed_pre_key_public->signature));
    user_data_set[user_data_set_insert_pos].pre_key->n_one_time_pre_keys = payload->n_one_time_pre_keys;
    user_data_set[user_data_set_insert_pos].pre_key->one_time_pre_keys = (Org__E2eelab__Skissm__Proto__OneTimePreKeyPublic **) malloc(sizeof(Org__E2eelab__Skissm__Proto__OneTimePreKeyPublic *) * user_data_set[user_data_set_insert_pos].pre_key->n_one_time_pre_keys);
    unsigned int i;
    for (i = 0; i < user_data_set[user_data_set_insert_pos].pre_key->n_one_time_pre_keys; i++){
        user_data_set[user_data_set_insert_pos].pre_key->one_time_pre_keys[i] = (Org__E2eelab__Skissm__Proto__OneTimePreKeyPublic *) malloc(sizeof(Org__E2eelab__Skissm__Proto__OneTimePreKeyPublic));
        org__e2eelab__skissm__proto__one_time_pre_key_public__init(user_data_set[user_data_set_insert_pos].pre_key->one_time_pre_keys[i]);
        user_data_set[user_data_set_insert_pos].pre_key->one_time_pre_keys[i]->opk_id = payload->one_time_pre_keys[i]->opk_id;
        copy_protobuf_from_protobuf(&(user_data_set[user_data_set_insert_pos].pre_key->one_time_pre_keys[i]->public_key), &(payload->one_time_pre_keys[i]->public_key));
    }

    Org__E2eelab__Skissm__Proto__RegisterUserResponsePayload *register_user_response_payload = (Org__E2eelab__Skissm__Proto__RegisterUserResponsePayload *) malloc(sizeof(Org__E2eelab__Skissm__Proto__RegisterUserResponsePayload));
    org__e2eelab__skissm__proto__register_user_response_payload__init(register_user_response_payload);

    /* Generate a random address */
    Org__E2eelab__Skissm__Proto__E2eeAddress *random_address = (Org__E2eelab__Skissm__Proto__E2eeAddress *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAddress));
    org__e2eelab__skissm__proto__e2ee_address__init(random_address);
    random_address->user_id.len = 32;
    random_address->user_id.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    ssm_handler.handle_rg(random_address->user_id.data, 32);
    random_address->domain.len = sizeof(DOMAIN);
    random_address->domain.data = (uint8_t *) malloc(sizeof(uint8_t) * sizeof(DOMAIN));
    memcpy(random_address->domain.data, DOMAIN, sizeof(DOMAIN));
    random_address->device_id.len = 32;
    random_address->device_id.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    ssm_handler.handle_rg(random_address->device_id.data, 32);

    copy_address_from_address(&(user_data_set[user_data_set_insert_pos].address), random_address);

    user_data_set_insert_pos++;

    register_user_response_payload->address = random_address;
    register_user_response_payload->code = OK;
    response->id = request->id;
    
    /* pack */
    response->payload.len = org__e2eelab__skissm__proto__register_user_response_payload__get_packed_size(register_user_response_payload);
    response->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * response->payload.len);
    org__e2eelab__skissm__proto__register_user_response_payload__pack(register_user_response_payload, response->payload.data);

    /* release */
    org__e2eelab__skissm__proto__register_user_request_payload__free_unpacked(payload, NULL);
    org__e2eelab__skissm__proto__register_user_response_payload__free_unpacked(register_user_response_payload, NULL);
}

static void process_delete_user_request(
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *request,
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *response
) {
    response->cmd = ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__delete_user_response;

    /* unpack */
    Org__E2eelab__Skissm__Proto__DeleteUserRequestPayload *payload = org__e2eelab__skissm__proto__delete_user_request_payload__unpack(NULL, request->payload.len, request->payload.data);

    uint8_t user_data_find = 0;
    while (user_data_find < user_data_set_insert_pos)
    {
        if ((user_data_set[user_data_find].address) && (payload->address)
            && compare_address(user_data_set[user_data_find].address, payload->address)
        ) {
            break;
        }
        user_data_find++;
    }

    Org__E2eelab__Skissm__Proto__DeleteUserResponsePayload *delete_user_response_payload = (Org__E2eelab__Skissm__Proto__DeleteUserResponsePayload *) malloc(sizeof(Org__E2eelab__Skissm__Proto__DeleteUserResponsePayload));
    org__e2eelab__skissm__proto__delete_user_response_payload__init(delete_user_response_payload);
    
    if (user_data_find == user_data_set_insert_pos){
        delete_user_response_payload->code = Internal_Server_Error;
    } else{
        delete_user_response_payload->code = OK;
        org__e2eelab__skissm__proto__register_user_request_payload__free_unpacked(user_data_set[user_data_find].pre_key, NULL);
        user_data_set[user_data_find].pre_key = NULL;
        org__e2eelab__skissm__proto__e2ee_address__free_unpacked(user_data_set[user_data_find].address, NULL);
        user_data_set[user_data_find].address = NULL;
        unset((void volatile *)&user_data_set[user_data_find], sizeof(user_data));
    }

    response->id = request->id;

    /* pack */
    response->payload.len = org__e2eelab__skissm__proto__delete_user_response_payload__get_packed_size(delete_user_response_payload);
    response->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * response->payload.len);
    org__e2eelab__skissm__proto__delete_user_response_payload__pack(delete_user_response_payload, response->payload.data);

    /* release */
    org__e2eelab__skissm__proto__delete_user_request_payload__free_unpacked(payload, NULL);
    org__e2eelab__skissm__proto__delete_user_response_payload__free_unpacked(delete_user_response_payload, NULL);
}

static void process_get_pre_key_bundle_request(
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *request,
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *response
) {
    response->cmd = ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__get_pre_key_bundle_response;

    /* unpack */
    Org__E2eelab__Skissm__Proto__GetPreKeyBundleRequestPayload *payload = org__e2eelab__skissm__proto__get_pre_key_bundle_request_payload__unpack(NULL, request->payload.len, request->payload.data);

    /* prepare a response payload */
    Org__E2eelab__Skissm__Proto__GetPreKeyBundleResponsePayload *get_pre_key_bundle_response_payload = (Org__E2eelab__Skissm__Proto__GetPreKeyBundleResponsePayload *) malloc(sizeof(Org__E2eelab__Skissm__Proto__GetPreKeyBundleResponsePayload));
    org__e2eelab__skissm__proto__get_pre_key_bundle_response_payload__init(get_pre_key_bundle_response_payload);

    uint8_t user_data_find = 0;
    while (user_data_find < user_data_set_insert_pos)
    {
        if ((user_data_set[user_data_find].address) && (payload->peer_address)
            && compare_address(user_data_set[user_data_find].address, payload->peer_address)
        ) {
            break;
        }
        user_data_find++;
    }

    if (user_data_find == user_data_set_insert_pos){
        get_pre_key_bundle_response_payload->code = Internal_Server_Error;
        goto complete;
    }

    get_pre_key_bundle_response_payload->pre_key_bundle = (Org__E2eelab__Skissm__Proto__E2eePreKeyBundle *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eePreKeyBundle));
    org__e2eelab__skissm__proto__e2ee_pre_key_bundle__init(get_pre_key_bundle_response_payload->pre_key_bundle);

    copy_address_from_address(&(get_pre_key_bundle_response_payload->pre_key_bundle->peer_address), payload->peer_address);
    copy_protobuf_from_protobuf(&(get_pre_key_bundle_response_payload->pre_key_bundle->identity_key_public), &(user_data_set[user_data_find].pre_key->identity_key_public));
    get_pre_key_bundle_response_payload->pre_key_bundle->signed_pre_key_public = (Org__E2eelab__Skissm__Proto__SignedPreKeyPublic *) malloc(sizeof(Org__E2eelab__Skissm__Proto__SignedPreKeyPublic));
    org__e2eelab__skissm__proto__signed_pre_key_public__init(get_pre_key_bundle_response_payload->pre_key_bundle->signed_pre_key_public);
    get_pre_key_bundle_response_payload->pre_key_bundle->signed_pre_key_public->spk_id = user_data_set[user_data_find].pre_key->signed_pre_key_public->spk_id;
    copy_protobuf_from_protobuf(&(get_pre_key_bundle_response_payload->pre_key_bundle->signed_pre_key_public->public_key), &(user_data_set[user_data_find].pre_key->signed_pre_key_public->public_key));
    copy_protobuf_from_protobuf(&(get_pre_key_bundle_response_payload->pre_key_bundle->signed_pre_key_public->signature), &(user_data_set[user_data_find].pre_key->signed_pre_key_public->signature));
    uint8_t i;
    for (i = 0; i < user_data_set[user_data_find].pre_key->n_one_time_pre_keys; i++){
        if (user_data_set[user_data_find].pre_key->one_time_pre_keys[i]){
            get_pre_key_bundle_response_payload->pre_key_bundle->one_time_pre_key_public = (Org__E2eelab__Skissm__Proto__OneTimePreKeyPublic *) malloc(sizeof(Org__E2eelab__Skissm__Proto__OneTimePreKeyPublic));
            org__e2eelab__skissm__proto__one_time_pre_key_public__init(get_pre_key_bundle_response_payload->pre_key_bundle->one_time_pre_key_public);
            get_pre_key_bundle_response_payload->pre_key_bundle->one_time_pre_key_public->opk_id = user_data_set[user_data_find].pre_key->one_time_pre_keys[i]->opk_id;
            copy_protobuf_from_protobuf(&(get_pre_key_bundle_response_payload->pre_key_bundle->one_time_pre_key_public->public_key), &(user_data_set[user_data_find].pre_key->one_time_pre_keys[i]->public_key));
            break;
        }
    }
    /* release the one-time pre-key */
    org__e2eelab__skissm__proto__one_time_pre_key_public__free_unpacked(user_data_set[user_data_find].pre_key->one_time_pre_keys[i], NULL);
    user_data_set[user_data_find].pre_key->one_time_pre_keys[i] = NULL;

    get_pre_key_bundle_response_payload->code = OK;

complete:
    response->id = request->id;

    /* pack */
    response->payload.len = org__e2eelab__skissm__proto__get_pre_key_bundle_response_payload__get_packed_size(get_pre_key_bundle_response_payload);
    response->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * response->payload.len);
    org__e2eelab__skissm__proto__get_pre_key_bundle_response_payload__pack(get_pre_key_bundle_response_payload, response->payload.data);

    /* release */
    org__e2eelab__skissm__proto__get_pre_key_bundle_request_payload__free_unpacked(payload, NULL);
    org__e2eelab__skissm__proto__get_pre_key_bundle_response_payload__free_unpacked(get_pre_key_bundle_response_payload, NULL);
}

static void process_publish_spk_request(
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *request,
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *response
) {
    response->cmd = ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__publish_spk_response;

    Org__E2eelab__Skissm__Proto__PublishSpkRequestPayload *payload = org__e2eelab__skissm__proto__publish_spk_request_payload__unpack(NULL, request->payload.len, request->payload.data);

    /* prepare response payload */
    Org__E2eelab__Skissm__Proto__PublishSpkResponsePayload *publish_spk_response_payload = (Org__E2eelab__Skissm__Proto__PublishSpkResponsePayload *) malloc(sizeof(Org__E2eelab__Skissm__Proto__PublishSpkResponsePayload));
    org__e2eelab__skissm__proto__publish_spk_response_payload__init(publish_spk_response_payload);

    uint8_t user_data_find = 0;
    while (user_data_find < user_data_set_insert_pos)
    {
        if ((user_data_set[user_data_find].address) && (payload->user_address)
            && compare_address(user_data_set[user_data_find].address, payload->user_address)
        ) {
            break;
        }
        user_data_find++;
    }

    if (user_data_find == user_data_set_insert_pos){
        publish_spk_response_payload->code = Internal_Server_Error;
        goto complete;
    }

    user_data_set[user_data_find].pre_key->signed_pre_key_public->spk_id = payload->signed_pre_key_public->spk_id;

    /* release old memory */
    free_mem((void **)&(user_data_set[user_data_find].pre_key->signed_pre_key_public->public_key.data), user_data_set[user_data_find].pre_key->signed_pre_key_public->public_key.len);
    free_mem((void **)&(user_data_set[user_data_find].pre_key->signed_pre_key_public->signature.data), user_data_set[user_data_find].pre_key->signed_pre_key_public->signature.len);

    copy_protobuf_from_protobuf(&(user_data_set[user_data_find].pre_key->signed_pre_key_public->public_key), &(payload->signed_pre_key_public->public_key));
    copy_protobuf_from_protobuf(&(user_data_set[user_data_find].pre_key->signed_pre_key_public->signature), &(payload->signed_pre_key_public->signature));

    publish_spk_response_payload->code = OK;

complete:
    /* pack */
    response->payload.len = org__e2eelab__skissm__proto__publish_spk_response_payload__get_packed_size(publish_spk_response_payload);
    response->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * response->payload.len);
    org__e2eelab__skissm__proto__publish_spk_response_payload__pack(publish_spk_response_payload, response->payload.data);
    response->id = request->id;

    /* release */
    org__e2eelab__skissm__proto__publish_spk_request_payload__free_unpacked(payload, NULL);
    org__e2eelab__skissm__proto__publish_spk_response_payload__free_unpacked(publish_spk_response_payload, NULL);
}

static void process_supply_opks_response(
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *in
) {
    Org__E2eelab__Skissm__Proto__SupplyOpksResponsePayload *payload = org__e2eelab__skissm__proto__supply_opks_response_payload__unpack(NULL, in->payload.len, in->payload.data);

    uint8_t user_data_find = 0;
    while (user_data_find < user_data_set_insert_pos)
    {
        if ((user_data_set[user_data_find].address) && (payload->user_address)
            && compare_address(user_data_set[user_data_find].address, payload->user_address)
        ) {
            break;
        }
        user_data_find++;
    }

    if (user_data_find == user_data_set_insert_pos){
        goto complete;
    }

    size_t old_num = user_data_set[user_data_find].pre_key->n_one_time_pre_keys;

    user_data_set[user_data_find].pre_key->n_one_time_pre_keys += payload->n_one_time_pre_key_public;
    Org__E2eelab__Skissm__Proto__OneTimePreKeyPublic **temp;
    temp = (Org__E2eelab__Skissm__Proto__OneTimePreKeyPublic **) malloc(sizeof(Org__E2eelab__Skissm__Proto__OneTimePreKeyPublic *) * user_data_set[user_data_find].pre_key->n_one_time_pre_keys);
    size_t i;
    for (i = 0; i < old_num; i++){
        temp[i] = (Org__E2eelab__Skissm__Proto__OneTimePreKeyPublic *) malloc(sizeof(Org__E2eelab__Skissm__Proto__OneTimePreKeyPublic));
        org__e2eelab__skissm__proto__one_time_pre_key_public__init(temp[i]);
        temp[i]->opk_id = user_data_set[user_data_find].pre_key->one_time_pre_keys[i]->opk_id;
        copy_protobuf_from_protobuf(&(temp[i]->public_key), &(user_data_set[user_data_find].pre_key->one_time_pre_keys[i]->public_key));
        org__e2eelab__skissm__proto__one_time_pre_key_public__free_unpacked(user_data_set[user_data_find].pre_key->one_time_pre_keys[i], NULL);
        user_data_set[user_data_find].pre_key->one_time_pre_keys[i] = NULL;
    }
    free(user_data_set[user_data_find].pre_key->one_time_pre_keys);
    user_data_set[user_data_find].pre_key->one_time_pre_keys = temp;

    for (i = old_num; i < user_data_set[user_data_find].pre_key->n_one_time_pre_keys; i++){
        user_data_set[user_data_find].pre_key->one_time_pre_keys[i] = (Org__E2eelab__Skissm__Proto__OneTimePreKeyPublic *) malloc(sizeof(Org__E2eelab__Skissm__Proto__OneTimePreKeyPublic));
        org__e2eelab__skissm__proto__one_time_pre_key_public__init(user_data_set[user_data_find].pre_key->one_time_pre_keys[i]);
        user_data_set[user_data_find].pre_key->one_time_pre_keys[i]->opk_id = payload->one_time_pre_key_public[i - old_num]->opk_id;
        copy_protobuf_from_protobuf(&(user_data_set[user_data_find].pre_key->one_time_pre_keys[i]->public_key), &(payload->one_time_pre_key_public[i - old_num]->public_key));
    }

complete:
    /* release */
    org__e2eelab__skissm__proto__supply_opks_response_payload__free_unpacked(payload, NULL);
}

static void process_create_group_request(
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *request,
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *response
) {
    response->cmd = ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__create_group_response;

    /* unpack */
    Org__E2eelab__Skissm__Proto__CreateGroupRequestPayload *payload = org__e2eelab__skissm__proto__create_group_request_payload__unpack(NULL, request->payload.len, request->payload.data);

    /* prepare to store */
    copy_protobuf_from_protobuf(&(group_data_set[group_data_set_insert_pos].group_name), &(payload->group_name));
    group_data_set[group_data_set_insert_pos].member_num = payload->n_member_addresses;
    copy_member_addresses_from_member_addresses(&(group_data_set[group_data_set_insert_pos].member_addresses), (const Org__E2eelab__Skissm__Proto__E2eeAddress **)payload->member_addresses, payload->n_member_addresses);

    /* Generate a random address */
    Org__E2eelab__Skissm__Proto__E2eeAddress *random_address = (Org__E2eelab__Skissm__Proto__E2eeAddress *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAddress));
    org__e2eelab__skissm__proto__e2ee_address__init(random_address);
    random_address->domain.len = sizeof(DOMAIN);
    random_address->domain.data = (uint8_t *) malloc(sizeof(uint8_t) * sizeof(DOMAIN));
    memcpy(random_address->domain.data, DOMAIN, sizeof(DOMAIN));
    random_address->group_id.len = 32;
    random_address->group_id.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    ssm_handler.handle_rg(random_address->group_id.data, 32);

    copy_address_from_address(&(group_data_set[group_data_set_insert_pos].group_address), random_address);

    Org__E2eelab__Skissm__Proto__CreateGroupResponsePayload *create_group_response_payload = (Org__E2eelab__Skissm__Proto__CreateGroupResponsePayload *) malloc(sizeof(Org__E2eelab__Skissm__Proto__CreateGroupResponsePayload));
    org__e2eelab__skissm__proto__create_group_response_payload__init(create_group_response_payload);

    create_group_response_payload->group_address = random_address;
    create_group_response_payload->code = OK;

    response->id = request->id;

    /* pack */
    response->payload.len = org__e2eelab__skissm__proto__create_group_response_payload__get_packed_size(create_group_response_payload);
    response->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * response->payload.len);
    org__e2eelab__skissm__proto__create_group_response_payload__pack(create_group_response_payload, response->payload.data);

    /* prepare a new request */
    copy_address_from_address(&(payload->group_address), random_address);

    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *new_request = (Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeProtocolMsg));
    org__e2eelab__skissm__proto__e2ee_protocol_msg__init(new_request);
    new_request->cmd = request->cmd;
    new_request->id = request->id;
    new_request->payload.len = org__e2eelab__skissm__proto__create_group_request_payload__get_packed_size(payload);
    new_request->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * new_request->payload.len);
    org__e2eelab__skissm__proto__create_group_request_payload__pack(payload, new_request->payload.data);

    /* send the message to all the other members in the group */
    size_t i;
    for (i = 0; i < group_data_set[group_data_set_insert_pos].member_num; i++){
        if (compare_address(payload->sender_address, group_data_set[group_data_set_insert_pos].member_addresses[i]) == false){
            mock_protocol_send(new_request, group_data_set[group_data_set_insert_pos].member_addresses[i]);
        }
    }

    group_data_set_insert_pos++;

    /* release */
    org__e2eelab__skissm__proto__create_group_request_payload__free_unpacked(payload, NULL);
    org__e2eelab__skissm__proto__create_group_response_payload__free_unpacked(create_group_response_payload, NULL);
}

static void process_get_group_request(
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *request,
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *response
) {
    response->cmd = ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__get_group_response;

    /* prepare a response payload */
    Org__E2eelab__Skissm__Proto__GetGroupResponsePayload *get_group_response_payload = (Org__E2eelab__Skissm__Proto__GetGroupResponsePayload *) malloc(sizeof(Org__E2eelab__Skissm__Proto__GetGroupResponsePayload));
    org__e2eelab__skissm__proto__get_group_response_payload__init(get_group_response_payload);

    /* unpack */
    Org__E2eelab__Skissm__Proto__GetGroupRequestPayload *payload = org__e2eelab__skissm__proto__get_group_request_payload__unpack(NULL, request->payload.len, request->payload.data);

    uint8_t group_data_find = 0;
    while (group_data_find < group_data_set_insert_pos){
        if ((group_data_set[group_data_find].group_address) && (payload->group_address)
            && compare_address(group_data_set[group_data_find].group_address, payload->group_address)
        ) {
            break;
        }
        group_data_find++;
    }

    if (group_data_find == group_data_set_insert_pos){
        get_group_response_payload->code = Internal_Server_Error;
        goto complete;
    }

    copy_protobuf_from_protobuf(&(get_group_response_payload->group_name), &(group_data_set[group_data_find].group_name));
    get_group_response_payload->n_member_addresses = group_data_set[group_data_find].member_num;
    copy_member_addresses_from_member_addresses(&(get_group_response_payload->member_addresses), (const Org__E2eelab__Skissm__Proto__E2eeAddress **)group_data_set[group_data_find].member_addresses, get_group_response_payload->n_member_addresses);

    get_group_response_payload->code = OK;

complete:
    response->id = request->id;

    /* pack */
    response->payload.len = org__e2eelab__skissm__proto__get_group_response_payload__get_packed_size(get_group_response_payload);
    response->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * response->payload.len);
    org__e2eelab__skissm__proto__get_group_response_payload__pack(get_group_response_payload, response->payload.data);

    /* release */
    org__e2eelab__skissm__proto__get_group_request_payload__free_unpacked(payload, NULL);
    org__e2eelab__skissm__proto__get_group_response_payload__free_unpacked(get_group_response_payload, NULL);
}

static void process_add_group_members_request(
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *request,
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *response
) {
    response->cmd = ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__add_group_members_response;

    /* prepare a response payload */
    Org__E2eelab__Skissm__Proto__AddGroupMembersResponsePayload *add_group_members_response_payload = (Org__E2eelab__Skissm__Proto__AddGroupMembersResponsePayload *) malloc(sizeof(Org__E2eelab__Skissm__Proto__AddGroupMembersResponsePayload));
    org__e2eelab__skissm__proto__add_group_members_response_payload__init(add_group_members_response_payload);

    /* unpack */
    Org__E2eelab__Skissm__Proto__AddGroupMembersRequestPayload *payload = org__e2eelab__skissm__proto__add_group_members_request_payload__unpack(NULL, request->payload.len, request->payload.data);

    /* find the group */
    uint8_t group_data_find = 0;
    while (group_data_find < group_data_set_insert_pos){
        if ((group_data_set[group_data_find].group_address) && (payload->group_address)
            && compare_address(group_data_set[group_data_find].group_address, payload->group_address)
        ) {
            break;
        }
        group_data_find++;
    }

    if (group_data_find == group_data_set_insert_pos){
        add_group_members_response_payload->code = Internal_Server_Error;
        goto complete;
    }

    /* update the data */
    size_t old_member_num = group_data_set[group_data_find].member_num;
    size_t new_member_num = group_data_set[group_data_find].member_num + payload->n_member_addresses;
    group_data_set[group_data_find].member_num = new_member_num;

    Org__E2eelab__Skissm__Proto__E2eeAddress **temp_member_addresses = NULL;
    temp_member_addresses = (Org__E2eelab__Skissm__Proto__E2eeAddress **) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAddress *) * new_member_num);
    size_t i;
    for (i = 0; i < old_member_num; i++){
        copy_address_from_address(&(temp_member_addresses[i]), group_data_set[group_data_find].member_addresses[i]);
        org__e2eelab__skissm__proto__e2ee_address__free_unpacked(group_data_set[group_data_find].member_addresses[i], NULL);
    }
    free(group_data_set[group_data_find].member_addresses);
    group_data_set[group_data_find].member_addresses = temp_member_addresses;

    for (i = old_member_num; i < new_member_num; i++){
        copy_address_from_address(&(group_data_set[group_data_find].member_addresses[i]), (payload->member_addresses)[i - old_member_num]);
    }

    /* send the message to all the other members in the group */
    for (i = 0; i < group_data_set[group_data_find].member_num; i++){
        if (compare_address(payload->sender_address, group_data_set[group_data_find].member_addresses[i]) == false){
            mock_protocol_send(request, group_data_set[group_data_find].member_addresses[i]);
        }
    }

    add_group_members_response_payload->code = OK;

complete:
    response->id = request->id;

    /* pack */
    response->payload.len = org__e2eelab__skissm__proto__add_group_members_response_payload__get_packed_size(add_group_members_response_payload);
    response->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * response->payload.len);
    org__e2eelab__skissm__proto__add_group_members_response_payload__pack(add_group_members_response_payload, response->payload.data);

    /* release */
    org__e2eelab__skissm__proto__add_group_members_request_payload__free_unpacked(payload, NULL);
}

static void process_remove_group_members_request(
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *request,
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *response
) {
    response->cmd = ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__remove_group_members_response;

    /* prepare a response payload */
    Org__E2eelab__Skissm__Proto__RemoveGroupMembersResponsePayload *remove_group_members_response_payload = (Org__E2eelab__Skissm__Proto__RemoveGroupMembersResponsePayload *) malloc(sizeof(Org__E2eelab__Skissm__Proto__RemoveGroupMembersResponsePayload));
    org__e2eelab__skissm__proto__remove_group_members_response_payload__init(remove_group_members_response_payload);

    /* unpack */
    Org__E2eelab__Skissm__Proto__RemoveGroupMembersRequestPayload *payload = org__e2eelab__skissm__proto__remove_group_members_request_payload__unpack(NULL, request->payload.len, request->payload.data);

    /* find the group */
    uint8_t group_data_find = 0;
    while (group_data_find < group_data_set_insert_pos){
        if ((group_data_set[group_data_find].group_address) && (payload->group_address)
            && compare_address(group_data_set[group_data_find].group_address, payload->group_address)
        ) {
            break;
        }
        group_data_find++;
    }

    if (group_data_find == group_data_set_insert_pos){
        remove_group_members_response_payload->code = Internal_Server_Error;
        goto complete;
    }

    /* update the data */
    size_t original_member_num = group_data_set[group_data_find].member_num;
    size_t new_member_num = original_member_num - payload->n_member_addresses;
    group_data_set[group_data_find].member_num = new_member_num;

    size_t i,j;
    for (j = 0; j < payload->n_member_addresses; j++){
        for (i = 0; i < original_member_num; i++){
            if (compare_address(group_data_set[group_data_find].member_addresses[i], payload->member_addresses[j])){
                org__e2eelab__skissm__proto__e2ee_address__free_unpacked(group_data_set[group_data_find].member_addresses[i], NULL);
                group_data_set[group_data_find].member_addresses[i] = NULL;
                break;
            }
        }
    }

    Org__E2eelab__Skissm__Proto__E2eeAddress **temp_member_addresses;
    temp_member_addresses = (Org__E2eelab__Skissm__Proto__E2eeAddress **) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAddress *) * new_member_num);
    i = 0; j = 0;
    while (i < new_member_num && j < original_member_num){
        if (group_data_set[group_data_find].member_addresses[j] != NULL){
            copy_address_from_address(&(temp_member_addresses[i]), group_data_set[group_data_find].member_addresses[j]);
            i++; j++;
        } else{
            j++;
        }
    }

    i = 0;
    for (i = 0; i < original_member_num; i++){
        org__e2eelab__skissm__proto__e2ee_address__free_unpacked(group_data_set[group_data_find].member_addresses[i], NULL);
        group_data_set[group_data_find].member_addresses[i] = NULL;
    }
    free(group_data_set[group_data_find].member_addresses);
    group_data_set[group_data_find].member_addresses = temp_member_addresses;

    /* send the message to all the other members in the group */
    for (i = 0; i < group_data_set[group_data_find].member_num; i++){
        if (compare_address(payload->sender_address, group_data_set[group_data_find].member_addresses[i]) == false){
            mock_protocol_send(request, group_data_set[group_data_find].member_addresses[i]);
        }
    }

    remove_group_members_response_payload->code = OK;
    
complete:
    response->id = request->id;

    /* pack */
    response->payload.len = org__e2eelab__skissm__proto__remove_group_members_response_payload__get_packed_size(remove_group_members_response_payload);
    response->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * response->payload.len);
    org__e2eelab__skissm__proto__remove_group_members_response_payload__pack(remove_group_members_response_payload, response->payload.data);

    /* release */
    org__e2eelab__skissm__proto__remove_group_members_request_payload__free_unpacked(payload, NULL);
}

static void process_send_msg_request(
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *request,
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *response
) {
    response->cmd = ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__e2ee_msg_response;

    /* prepare a response payload */
    Org__E2eelab__Skissm__Proto__E2eeMsgResponsePayload *e2ee_msg_response_payload = (Org__E2eelab__Skissm__Proto__E2eeMsgResponsePayload *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeMsgResponsePayload));
    org__e2eelab__skissm__proto__e2ee_msg_response_payload__init(e2ee_msg_response_payload);

    /* sending */
    mock_protocol_send(request, NULL);

    e2ee_msg_response_payload->code = OK;

    response->id = request->id;

    /* pack */
    response->payload.len = org__e2eelab__skissm__proto__e2ee_msg_response_payload__get_packed_size(e2ee_msg_response_payload);
    response->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * response->payload.len);
    org__e2eelab__skissm__proto__e2ee_msg_response_payload__pack(e2ee_msg_response_payload, response->payload.data);
}

static void process_send_group_msg_request(
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *request,
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *response
) {
    response->cmd = ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__e2ee_group_msg_response;

    /* prepare a response payload */
    Org__E2eelab__Skissm__Proto__E2eeGroupMsgResponsePayload *e2ee_group_msg_response_payload = (Org__E2eelab__Skissm__Proto__E2eeGroupMsgResponsePayload *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeGroupMsgResponsePayload));
    org__e2eelab__skissm__proto__e2ee_group_msg_response_payload__init(e2ee_group_msg_response_payload);

    /* unpack */
    Org__E2eelab__Skissm__Proto__E2eeMessage *e2ee_msg = org__e2eelab__skissm__proto__e2ee_message__unpack(NULL, request->payload.len, request->payload.data);

    /* find the group */
    uint8_t group_data_find = 0;
    while (group_data_find < group_data_set_insert_pos){
        if ((group_data_set[group_data_find].group_address) && (e2ee_msg->to)
            && compare_address(group_data_set[group_data_find].group_address, e2ee_msg->to)
        ) {
            break;
        }
        group_data_find++;
    }

    if (group_data_find == group_data_set_insert_pos){
        e2ee_group_msg_response_payload->code = Internal_Server_Error;
        goto complete;
    }

    /* send the message to all the other members in the group */
    size_t i;
    for (i = 0; i < group_data_set[group_data_find].member_num; i++){
        if (compare_address(e2ee_msg->from, group_data_set[group_data_find].member_addresses[i]) == false){
            mock_protocol_send(request, group_data_set[group_data_find].member_addresses[i]);
        }
    }

    e2ee_group_msg_response_payload->code = OK;

complete:
    response->id = request->id;

    /* pack */
    response->payload.len = org__e2eelab__skissm__proto__e2ee_group_msg_response_payload__get_packed_size(e2ee_group_msg_response_payload);
    response->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * response->payload.len);
    org__e2eelab__skissm__proto__e2ee_group_msg_response_payload__pack(e2ee_group_msg_response_payload, response->payload.data);

    /* release */
    org__e2eelab__skissm__proto__e2ee_message__free_unpacked(e2ee_msg, NULL);
}

void mock_protocol_receive(u_int8_t *msg, size_t msg_len){
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *client_msg = org__e2eelab__skissm__proto__e2ee_protocol_msg__unpack(NULL, msg_len, msg);

    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *response = (Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeProtocolMsg));
    org__e2eelab__skissm__proto__e2ee_protocol_msg__init(response);

    switch (client_msg->cmd)
    {
    case ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__register_user:
        process_register_user_request(client_msg, response);
        break;
    case ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__delete_user:
        process_delete_user_request(client_msg, response);
        break;
    case ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__get_pre_key_bundle:
        process_get_pre_key_bundle_request(client_msg, response);
        break;
    case ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__publish_spk:
        process_publish_spk_request(client_msg, response);
        break;
    case ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__supply_opks_response:
        process_supply_opks_response(client_msg);
        return;
        break;
    case ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__create_group:
        process_create_group_request(client_msg, response);
        break;
    case ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__create_group_response:
        return;
        break;
    case ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__get_group:
        process_get_group_request(client_msg, response);
        break;
    case ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__add_group_members:
        process_add_group_members_request(client_msg, response);
        break;
    case ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__add_group_members_response:
        return;
        break;
    case ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__remove_group_members:
        process_remove_group_members_request(client_msg, response);
        break;
    case ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__remove_group_members_response:
        return;
        break;
    case ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__e2ee_msg:
        process_send_msg_request(client_msg, response);
        break;
    case ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__e2ee_msg_response:
        return;
        break;
    case ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__e2ee_group_msg:
        process_send_group_msg_request(client_msg, response);
        break;
    case ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__e2ee_group_msg_response:
        return;
        break;

    default:
        break;
    }

    mock_protocol_send(response, NULL);

    /* release */
    org__e2eelab__skissm__proto__e2ee_protocol_msg__free_unpacked(client_msg, NULL);
    org__e2eelab__skissm__proto__e2ee_protocol_msg__free_unpacked(response, NULL);
}

