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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "skissm/account.h"
#include "skissm/account_manager.h"
#include "skissm/e2ee_client.h"
#include "skissm/group_session.h"
#include "skissm/group_session_manager.h"
#include "skissm/mem_util.h"

#include "mock_server_sending.h"
#include "test_util.h"
#include "test_plugin.h"

#define account_data_max 205

static char *mock_user_name[200] = {
    "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
    "AA", "AB", "AC", "AD", "AE", "AF", "AG", "AH", "AI", "AJ", "AK", "AL", "AM", "AN", "AO", "AP", "AQ", "AR", "AS", "AT", "AU", "AV", "AW", "AX", "AY", "AZ",
    "BA", "BB", "BC", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BK", "BL", "BM", "BN", "BO", "BP", "BQ", "BR", "BS", "BT", "BU", "BV", "BW", "BX", "BY", "BZ",
    "CA", "CB", "CC", "CD", "CE", "CF", "CG", "CH", "CI", "CJ", "CK", "CL", "CM", "CN", "CO", "CP", "CQ", "CR", "CS", "CT", "CU", "CV", "CW", "CX", "CY", "CZ",
    "DA", "DB", "DC", "DD", "DE", "DF", "DG", "DH", "DI", "DJ", "DK", "DL", "DM", "DN", "DO", "DP", "DQ", "DR", "DS", "DT", "DU", "DV", "DW", "DX", "DY", "DZ",
    "EA", "EB", "EC", "ED", "EE", "EF", "EG", "EH", "EI", "EJ", "EK", "EL", "EM", "EN", "EO", "EP", "EQ", "ER", "ES", "ET", "EU", "EV", "EW", "EX", "EY", "EZ",
    "FA", "FB", "FC", "FD", "FE", "FF", "FG", "FH", "FI", "FJ", "FK", "FL", "FM", "FN", "FO", "FP", "FQ", "FR", "FS", "FT", "FU", "FV", "FW", "FX", "FY", "FZ",
    "GA", "GB", "GC", "GD", "GE", "GF", "GG", "GH", "GI", "GJ", "GK", "GL", "GM", "GN", "GO", "GP", "GQ", "GR"
};

static char *mock_authenticator[200] = {
    "a@domain.com.tw", "b@domain.com.tw", "c@domain.com.tw", "d@domain.com.tw", "e@domain.com.tw",
    "f@domain.com.tw", "g@domain.com.tw", "h@domain.com.tw", "i@domain.com.tw", "j@domain.com.tw",
    "k@domain.com.tw", "l@domain.com.tw", "m@domain.com.tw", "n@domain.com.tw", "o@domain.com.tw",
    "p@domain.com.tw", "q@domain.com.tw", "r@domain.com.tw", "s@domain.com.tw", "t@domain.com.tw",
    "u@domain.com.tw", "v@domain.com.tw", "w@domain.com.tw", "x@domain.com.tw", "y@domain.com.tw",
    "z@domain.com.tw", "aa@domain.com.tw", "ab@domain.com.tw", "ac@domain.com.tw", "ad@domain.com.tw",
    "ae@domain.com.tw", "af@domain.com.tw", "ag@domain.com.tw", "ah@domain.com.tw", "ai@domain.com.tw",
    "aj@domain.com.tw", "ak@domain.com.tw", "al@domain.com.tw", "am@domain.com.tw", "an@domain.com.tw",
    "ao@domain.com.tw", "ap@domain.com.tw", "aq@domain.com.tw", "ar@domain.com.tw", "as@domain.com.tw",
    "at@domain.com.tw", "au@domain.com.tw", "av@domain.com.tw", "aw@domain.com.tw", "ax@domain.com.tw",
    "ay@domain.com.tw", "az@domain.com.tw", "ba@domain.com.tw", "bb@domain.com.tw", "bc@domain.com.tw",
    "bd@domain.com.tw", "be@domain.com.tw", "bf@domain.com.tw", "bg@domain.com.tw", "bh@domain.com.tw",
    "bi@domain.com.tw", "bj@domain.com.tw", "bk@domain.com.tw", "bl@domain.com.tw", "bm@domain.com.tw",
    "bn@domain.com.tw", "bo@domain.com.tw", "bp@domain.com.tw", "bq@domain.com.tw", "br@domain.com.tw",
    "bs@domain.com.tw", "bt@domain.com.tw", "bu@domain.com.tw", "bv@domain.com.tw", "bw@domain.com.tw",
    "bx@domain.com.tw", "by@domain.com.tw", "bz@domain.com.tw", "ca@domain.com.tw", "cb@domain.com.tw",
    "cc@domain.com.tw", "cd@domain.com.tw", "ce@domain.com.tw", "cf@domain.com.tw", "cg@domain.com.tw",
    "ch@domain.com.tw", "ci@domain.com.tw", "cj@domain.com.tw", "ck@domain.com.tw", "cl@domain.com.tw",
    "cm@domain.com.tw", "cn@domain.com.tw", "co@domain.com.tw", "cp@domain.com.tw", "cqe@domain.com.tw",
    "cr@domain.com.tw", "cs@domain.com.tw", "ct@domain.com.tw", "cu@domain.com.tw", "cv@domain.com.tw",
    "cw@domain.com.tw", "cx@domain.com.tw", "cy@domain.com.tw", "cz@domain.com.tw", "da@domain.com.tw",
    "db@domain.com.tw", "dc@domain.com.tw", "dd@domain.com.tw", "de@domain.com.tw", "df@domain.com.tw",
    "dg@domain.com.tw", "dh@domain.com.tw", "di@domain.com.tw", "dj@domain.com.tw", "dk@domain.com.tw",
    "dl@domain.com.tw", "dm@domain.com.tw", "dn@domain.com.tw", "do@domain.com.tw", "dp@domain.com.tw",
    "dq@domain.com.tw", "dr@domain.com.tw", "ds@domain.com.tw", "dt@domain.com.tw", "du@domain.com.tw",
    "dv@domain.com.tw", "dw@domain.com.tw", "dx@domain.com.tw", "dy@domain.com.tw", "dz@domain.com.tw",
    "ea@domain.com.tw", "eb@domain.com.tw", "ec@domain.com.tw", "ed@domain.com.tw", "ee@domain.com.tw",
    "ef@domain.com.tw", "eg@domain.com.tw", "eh@domain.com.tw", "ei@domain.com.tw", "ej@domain.com.tw",
    "ek@domain.com.tw", "el@domain.com.tw", "em@domain.com.tw", "en@domain.com.tw", "eo@domain.com.tw",
    "ep@domain.com.tw", "eq@domain.com.tw", "er@domain.com.tw", "es@domain.com.tw", "et@domain.com.tw",
    "eu@domain.com.tw", "ev@domain.com.tw", "ew@domain.com.tw", "ex@domain.com.tw", "ey@domain.com.tw",
    "ez@domain.com.tw", "fa@domain.com.tw", "fb@domain.com.tw", "fc@domain.com.tw", "fd@domain.com.tw",
    "fe@domain.com.tw", "ff@domain.com.tw", "fg@domain.com.tw", "fh@domain.com.tw", "fi@domain.com.tw",
    "fj@domain.com.tw", "fk@domain.com.tw", "fl@domain.com.tw", "fm@domain.com.tw", "fn@domain.com.tw",
    "fo@domain.com.tw", "fp@domain.com.tw", "fq@domain.com.tw", "fr@domain.com.tw", "fs@domain.com.tw",
    "ft@domain.com.tw", "fu@domain.com.tw", "fv@domain.com.tw", "fw@domain.com.tw", "fx@domain.com.tw",
    "fy@domain.com.tw", "fz@domain.com.tw", "ga@domain.com.tw", "gb@domain.com.tw", "gc@domain.com.tw",
    "gd@domain.com.tw", "ge@domain.com.tw", "gf@domain.com.tw", "gg@domain.com.tw", "gh@domain.com.tw",
    "gi@domain.com.tw", "gj@domain.com.tw", "gk@domain.com.tw", "gl@domain.com.tw", "gm@domain.com.tw",
    "gn@domain.com.tw", "go@domain.com.tw", "gp@domain.com.tw", "gq@domain.com.tw", "gr@domain.com.tw"
};

static char *mock_auth_code[200] = {
    "000001", "000002", "000003", "000004", "000005", "000006", "000007", "000008", "000009", "000010",
    "000011", "000012", "000013", "000014", "000015", "000016", "000017", "000018", "000019", "000020",
    "000021", "000022", "000023", "000024", "000025", "000026", "000027", "000028", "000029", "000030",
    "000031", "000032", "000033", "000034", "000035", "000036", "000037", "000038", "000039", "000040",
    "000041", "000042", "000043", "000044", "000045", "000046", "000047", "000048", "000049", "000050",
    "000051", "000052", "000053", "000054", "000055", "000056", "000057", "000058", "000059", "000060",
    "000061", "000062", "000063", "000064", "000065", "000066", "000067", "000068", "000069", "000070",
    "000071", "000072", "000073", "000074", "000075", "000076", "000077", "000078", "000079", "000080",
    "000081", "000082", "000083", "000084", "000085", "000086", "000087", "000088", "000089", "000090",
    "000091", "000092", "000093", "000094", "000095", "000096", "000097", "000098", "000099", "000100",
    "000101", "000102", "000103", "000104", "000105", "000106", "000107", "000108", "000109", "000110",
    "000111", "000112", "000113", "000114", "000115", "000116", "000117", "000118", "000119", "000120",
    "000121", "000122", "000123", "000124", "000125", "000126", "000127", "000128", "000129", "000130",
    "000131", "000132", "000133", "000134", "000135", "000136", "000137", "000138", "000139", "000140",
    "000141", "000142", "000143", "000144", "000145", "000146", "000147", "000148", "000149", "000150",
    "000151", "000152", "000153", "000154", "000155", "000156", "000157", "000158", "000159", "000160",
    "000161", "000162", "000163", "000164", "000165", "000166", "000167", "000168", "000169", "000170",
    "000171", "000172", "000173", "000174", "000175", "000176", "000177", "000178", "000179", "000180",
    "000181", "000182", "000183", "000184", "000185", "000186", "000187", "000188", "000189", "000190",
    "000191", "000192", "000193", "000194", "000195", "000196", "000197", "000198", "000199", "000200"
};

static Skissm__Account *account_data[account_data_max];

static uint8_t account_data_insert_pos;

typedef struct store_group {
    Skissm__E2eeAddress *group_address;
    char *group_name;
} store_group;

store_group group = {NULL, NULL};

static void on_log(Skissm__E2eeAddress *user_address, LogCode log_code, const char *log_msg) {
    if (log_code == 0)
        return;
    print_log((char *)log_msg, log_code);
}

static void on_user_registered(Skissm__Account *account) {
    print_msg("on_user_registered: user_id", (uint8_t *)account->address->user->user_id, strlen(account->address->user->user_id));

    copy_account_from_account(&(account_data[account_data_insert_pos]), account);
    account_data_insert_pos++;
}

static void on_inbound_session_invited(Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *from){
    printf("on_inbound_session_invited\n");
}

static void on_inbound_session_ready(Skissm__E2eeAddress *user_address, Skissm__Session *inbound_session){
    printf("on_inbound_session_ready\n");
}

static void on_outbound_session_ready(Skissm__E2eeAddress *user_address, Skissm__Session *outbound_session){
    printf("on_outbound_session_ready\n");
}

static void on_one2one_msg_received(Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *to_address, uint8_t *plaintext, size_t plaintext_len) {
    print_msg("on_one2one_msg_received: plaintext", plaintext, plaintext_len);
}

static void on_other_device_msg_received(Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *to_address, uint8_t *plaintext, size_t plaintext_len) {
    print_msg("on_other_device_msg_received: plaintext", plaintext, plaintext_len);
}

static void on_group_msg_received(Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *group_address, uint8_t *plaintext, size_t plaintext_len) {
    if (safe_strcmp(user_address->user->user_id, from_address->user->user_id)) {
        print_msg("on_group_msg_received(from other devices): plaintext", plaintext, plaintext_len);
    } else {
        print_msg("on_group_msg_received(from other users): plaintext", plaintext, plaintext_len);
    }
}

static void on_group_created(
    Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *group_address, const char *group_name,
    Skissm__GroupMember **group_members, size_t group_members_num
) {
    print_msg("on_group_created: group_name", (uint8_t *)group_name, strlen(group_name));

    copy_address_from_address(&(group.group_address), group_address);
    group.group_name = strdup(group_name);
}

static void on_group_members_added(
    Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *group_address, const char *group_name,
    Skissm__GroupMember **group_members, size_t group_members_num,
    Skissm__GroupMember **added_group_members, size_t added_group_members_num
) {
    print_msg("on_group_members_added: group_name", (uint8_t *)group_name, strlen(group_name));
    size_t i;
    for (i = 0; i < added_group_members_num; i++) {
        print_msg("    member_id", (uint8_t *)(added_group_members[i]->user_id), strlen(added_group_members[i]->user_id));
    }
}

static void on_group_members_removed(
    Skissm__E2eeAddress *user_address, Skissm__E2eeAddress *group_address, const char *group_name,
    Skissm__GroupMember **group_members, size_t group_members_num,
    Skissm__GroupMember **removed_group_members, size_t removed_group_members_num
) {
    print_msg("on_group_members_removed: group_name", (uint8_t *)group_name, strlen(group_name));
    size_t i;
    for (i = 0; i < removed_group_members_num; i++) {
        print_msg("    member_id", (uint8_t *)(removed_group_members[i]->user_id), strlen(removed_group_members[i]->user_id));
    }
}

static skissm_event_handler_t test_event_handler = {
    on_log,
    on_user_registered,
    on_inbound_session_invited,
    on_inbound_session_ready,
    on_outbound_session_ready,
    on_one2one_msg_received,
    on_other_device_msg_received,
    on_group_msg_received,
    on_group_created,
    on_group_members_added,
    on_group_members_removed
};

static void test_begin() {
    int i;
    for (i = 0; i < account_data_max; i++) {
        account_data[i] = NULL;
    }
    account_data_insert_pos = 0;

    group.group_address = NULL;
    group.group_name = NULL;

    get_skissm_plugin()->event_handler = test_event_handler;

    start_mock_server_sending();
}

static void test_end() {
    stop_mock_server_sending();

    int i;
    for (i = 0; i < account_data_max; i++) {
        if (account_data[i] != NULL) {
            skissm__account__free_unpacked(account_data[i], NULL);
            account_data[i] = NULL;
        }
    }
    account_data_insert_pos = 0;

    if (group.group_address != NULL) {
        skissm__e2ee_address__free_unpacked(group.group_address, NULL);
    }
    if (group.group_name != NULL) {
        free(group.group_name);
    }
}

static void mock_alice_account(const char *user_name) {
    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_CURVE25519,
        E2EE_PACK_ALG_KEM_CURVE25519,
        E2EE_PACK_ALG_SYMMETRIC_ENCRYPTION_AES256_SHA256
    );
    char *device_id = generate_uuid_str();
    const char *authenticator = "alice@domain.com.tw";
    const char *auth_code = "123456";
    Skissm__RegisterUserResponse *response =
        register_user(
            e2ee_pack_id,
            user_name,
            user_name,
            device_id,
            authenticator,
            auth_code
        );
    assert(safe_strcmp(device_id, response->address->user->device_id));
    printf("Test user registered: \"%s@%s\"\n", response->address->user->user_id, response->address->domain);

    // release
    free(device_id);
    skissm__register_user_response__free_unpacked(response, NULL);
}

static void mock_bob_account(const char *user_name) {
    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_CURVE25519,
        E2EE_PACK_ALG_KEM_CURVE25519,
        E2EE_PACK_ALG_SYMMETRIC_ENCRYPTION_AES256_SHA256
    );
    char *device_id = generate_uuid_str();
    const char *authenticator = "bob@domain.com.tw";
    const char *auth_code = "654321";
    Skissm__RegisterUserResponse *response =
        register_user(
            e2ee_pack_id,
            user_name,
            user_name,
            device_id,
            authenticator,
            auth_code
        );
    assert(safe_strcmp(device_id, response->address->user->device_id));
    printf("Test user registered: \"%s@%s\"\n", response->address->user->user_id, response->address->domain);

    // release
    free(device_id);
    skissm__register_user_response__free_unpacked(response, NULL);
}

static void mock_claire_account(const char *user_name) {
    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_CURVE25519,
        E2EE_PACK_ALG_KEM_CURVE25519,
        E2EE_PACK_ALG_SYMMETRIC_ENCRYPTION_AES256_SHA256
    );
    char *device_id = generate_uuid_str();
    const char *authenticator = "claire@domain.com.tw";
    const char *auth_code = "987654";
    Skissm__RegisterUserResponse *response =
        register_user(
            e2ee_pack_id,
            user_name,
            user_name,
            device_id,
            authenticator,
            auth_code
        );
    assert(safe_strcmp(device_id, response->address->user->device_id));
    printf("Test user registered: \"%s@%s\"\n", response->address->user->user_id, response->address->domain);

    // release
    free(device_id);
    skissm__register_user_response__free_unpacked(response, NULL);
}

static void mock_alice_pqc_account(const char *user_name) {
    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_256F,
        E2EE_PACK_ALG_KEM_KYBER1024,
        E2EE_PACK_ALG_SYMMETRIC_ENCRYPTION_AES256_SHA256
    );
    char *device_id = generate_uuid_str();
    const char *authenticator = "alice@domain.com.tw";
    const char *auth_code = "123456";
    Skissm__RegisterUserResponse *response =
        register_user(
            e2ee_pack_id,
            user_name,
            user_name,
            device_id,
            authenticator,
            auth_code
        );
    assert(safe_strcmp(device_id, response->address->user->device_id));
    printf("Test user registered: \"%s@%s\"\n", response->address->user->user_id, response->address->domain);

    // release
    free(device_id);
    skissm__register_user_response__free_unpacked(response, NULL);
}

static void mock_bob_pqc_account(const char *user_name) {
    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_256F,
        E2EE_PACK_ALG_KEM_KYBER1024,
        E2EE_PACK_ALG_SYMMETRIC_ENCRYPTION_AES256_SHA256
    );
    char *device_id = generate_uuid_str();
    const char *authenticator = "bob@domain.com.tw";
    const char *auth_code = "654321";
    Skissm__RegisterUserResponse *response =
        register_user(
            e2ee_pack_id,
            user_name,
            user_name,
            device_id,
            authenticator,
            auth_code
        );
    assert(safe_strcmp(device_id, response->address->user->device_id));
    printf("Test user registered: \"%s@%s\"\n", response->address->user->user_id, response->address->domain);

    // release
    free(device_id);
    skissm__register_user_response__free_unpacked(response, NULL);
}

static void mock_claire_pqc_account(const char *user_name) {
    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_256F,
        E2EE_PACK_ALG_KEM_KYBER1024,
        E2EE_PACK_ALG_SYMMETRIC_ENCRYPTION_AES256_SHA256
    );
    char *device_id = generate_uuid_str();
    const char *authenticator = "claire@domain.com.tw";
    const char *auth_code = "987654";
    Skissm__RegisterUserResponse *response =
        register_user(
            e2ee_pack_id,
            user_name,
            user_name,
            device_id,
            authenticator,
            auth_code
        );
    assert(safe_strcmp(device_id, response->address->user->device_id));
    printf("Test user registered: \"%s@%s\"\n", response->address->user->user_id, response->address->domain);

    // release
    free(device_id);
    skissm__register_user_response__free_unpacked(response, NULL);
}

static void mock_user_pqc_account(const char *user_name, const char *authenticator, const char *auth_code) {
    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_SPHINCS_SHA2_256F,
        E2EE_PACK_ALG_KEM_KYBER1024,
        E2EE_PACK_ALG_SYMMETRIC_ENCRYPTION_AES256_SHA256
    );
    char *device_id = generate_uuid_str();
    Skissm__RegisterUserResponse *response = register_user(
        e2ee_pack_id, user_name, user_name, device_id, authenticator, auth_code
    );
    assert(safe_strcmp(device_id, response->address->user->device_id));
    printf("Test user registered: \"%s@%s\"\n", response->address->user->user_id, response->address->domain);

    // release
    free(device_id);
    skissm__register_user_response__free_unpacked(response, NULL);
}

static void test_encryption(Skissm__E2eeAddress *sender_address, Skissm__E2eeAddress *group_address, uint8_t *plaintext_data, size_t plaintext_data_len) {
    Skissm__SendGroupMsgResponse *response = send_group_msg(
        sender_address,
        group_address,
        SKISSM__NOTIF_LEVEL__NOTIF_LEVEL_NORMAL,
        plaintext_data, plaintext_data_len);
    
    assert(response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK);
    
    // release
    skissm__send_group_msg_response__free_unpacked(response, NULL);
}

static void test_create_group() {
    // test start
    printf("test_create_group begin!!!\n");
    tear_up();
    test_begin();

    // Prepare account
    mock_alice_account("alice");
    mock_bob_account("bob");

    // Alice invites Bob to create a group
    Skissm__InviteResponse *response = invite(account_data[0]->address, account_data[1]->address->user->user_id, account_data[1]->address->domain);

    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 2);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(account_data[0]->address->user->user_id);
    group_members[0]->domain = strdup(account_data[0]->address->domain);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(account_data[1]->address->user->user_id);
    group_members[1]->domain = strdup(account_data[1]->address->domain);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(account_data[0]->address, "Group name", group_members, 2);

    assert(create_group_response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK);
    Skissm__E2eeAddress *group_address = create_group_response->group_address;

    sleep(2);
    // Alice sends a message to the group
    uint8_t plaintext_data[] = "This is the group session test.";
    size_t plaintext_data_len = sizeof(plaintext_data) - 1;
    test_encryption(account_data[0]->address, group_address, plaintext_data, plaintext_data_len);

    // release
    skissm__invite_response__free_unpacked(response, NULL);
    skissm__group_member__free_unpacked(group_members[0], NULL);
    skissm__group_member__free_unpacked(group_members[1], NULL);
    free(group_members);
    skissm__create_group_response__free_unpacked(create_group_response, NULL);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_add_group_members() {
    // test start
    printf("test_add_group_members begin!!!\n");
    tear_up();
    test_begin();

    // Prepare account
    mock_alice_account("alice");
    mock_bob_account("bob");
    mock_claire_account("claire");

    // Alice invites Bob to create a group
    Skissm__InviteResponse *response = invite(account_data[0]->address, account_data[1]->address->user->user_id, account_data[1]->address->domain);

    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 2);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(account_data[0]->address->user->user_id);
    group_members[0]->domain = strdup(account_data[0]->address->domain);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(account_data[1]->address->user->user_id);
    group_members[1]->domain = strdup(account_data[1]->address->domain);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(account_data[0]->address, "Group name", group_members, 2);

    sleep(2);
    // Alice invites Claire to join the group
    Skissm__InviteResponse *response2 = invite(account_data[0]->address, account_data[2]->address->user->user_id, account_data[2]->address->domain);
    // the new group member is Claire
    Skissm__GroupMember **new_group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *));
    new_group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(new_group_members[0]);
    new_group_members[0]->user_id = strdup(account_data[2]->address->user->user_id);
    new_group_members[0]->domain = strdup(account_data[2]->address->domain);
    new_group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    size_t new_group_member_num = 1;
    // add the new group member to the group
    Skissm__AddGroupMembersResponse *add_group_members_response = add_group_members(account_data[0]->address, group.group_address, new_group_members, new_group_member_num);
    assert(add_group_members_response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK);

    sleep(4);
    // Alice sends a message to the group
    uint8_t plaintext_data[] = "This message will be sent to Bob and Claire.";
    size_t plaintext_data_len = sizeof(plaintext_data) - 1;
    test_encryption(account_data[0]->address, group.group_address, plaintext_data, plaintext_data_len);

    // release
    skissm__invite_response__free_unpacked(response, NULL);
    skissm__invite_response__free_unpacked(response2, NULL);
    skissm__group_member__free_unpacked(group_members[0], NULL);
    skissm__group_member__free_unpacked(group_members[1], NULL);
    free(group_members);
    skissm__create_group_response__free_unpacked(create_group_response, NULL);
    skissm__group_member__free_unpacked(new_group_members[0], NULL);
    free(new_group_members);
    skissm__add_group_members_response__free_unpacked(add_group_members_response, NULL);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_remove_group_members() {
    // test start
    printf("test_remove_group_members begin!!!\n");
    tear_up();
    test_begin();

    // Prepare account
    mock_alice_account("alice");
    mock_bob_account("bob");
    mock_claire_account("claire");

    // Alice invites Bob and Claire to join the group
    Skissm__InviteResponse *response = invite(account_data[0]->address, account_data[1]->address->user->user_id, account_data[1]->address->domain);
    Skissm__InviteResponse *response2 = invite(account_data[0]->address, account_data[2]->address->user->user_id, account_data[2]->address->domain);

    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 3);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(account_data[0]->address->user->user_id);
    group_members[0]->domain = strdup(account_data[0]->address->domain);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(account_data[1]->address->user->user_id);
    group_members[1]->domain = strdup(account_data[1]->address->domain);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the third group member is Claire
    group_members[2] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[2]);
    group_members[2]->user_id = strdup(account_data[2]->address->user->user_id);
    group_members[2]->domain = strdup(account_data[2]->address->domain);
    group_members[2]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(account_data[0]->address, "Group name", group_members, 3);

    sleep(2);
    // the removing group member is Claire
    Skissm__GroupMember **removing_group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *));
    removing_group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(removing_group_members[0]);
    removing_group_members[0]->user_id = strdup(account_data[2]->address->user->user_id);
    removing_group_members[0]->domain = strdup(account_data[2]->address->domain);
    removing_group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    size_t removing_group_member_num = 1;

    // Alice removes Claire out of the group
    Skissm__RemoveGroupMembersResponse *remove_group_members_response = remove_group_members(account_data[0]->address, group.group_address, removing_group_members, removing_group_member_num);
    assert(remove_group_members_response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK);

    sleep(4);
    // Alice sends a message to the group
    uint8_t plaintext[] = "This message will be sent to Bob only.";
    size_t plaintext_len = sizeof(plaintext) - 1;
    test_encryption(account_data[0]->address, group.group_address, plaintext, plaintext_len);

    // release
    skissm__invite_response__free_unpacked(response, NULL);
    skissm__invite_response__free_unpacked(response2, NULL);
    skissm__group_member__free_unpacked(group_members[0], NULL);
    skissm__group_member__free_unpacked(group_members[1], NULL);
    skissm__group_member__free_unpacked(group_members[2], NULL);
    free(group_members);
    skissm__create_group_response__free_unpacked(create_group_response, NULL);
    skissm__group_member__free_unpacked(removing_group_members[0], NULL);
    free(removing_group_members);
    skissm__remove_group_members_response__free_unpacked(remove_group_members_response, NULL);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_create_add_remove() {
    // test start
    printf("test_create_add_remove begin!!!\n");
    tear_up();
    test_begin();

    // Prepare account
    mock_alice_account("alice");
    mock_bob_account("bob");
    mock_claire_account("claire");

    // Alice invites Bob to create a group
    Skissm__InviteResponse *response = invite(account_data[0]->address, account_data[1]->address->user->user_id, account_data[1]->address->domain);

    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 2);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(account_data[0]->address->user->user_id);
    group_members[0]->domain = strdup(account_data[0]->address->domain);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(account_data[1]->address->user->user_id);
    group_members[1]->domain = strdup(account_data[1]->address->domain);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(account_data[0]->address, "Group name", group_members, 2);

    sleep(2);
    // Alice sends a message to the group
    uint8_t plaintext[] = "This is the group session test.";
    size_t plaintext_len = sizeof(plaintext) - 1;
    test_encryption(account_data[0]->address, group.group_address, plaintext, plaintext_len);

    sleep(1);
    // Alice invites Claire to join the group
    Skissm__InviteResponse *response2 = invite(account_data[0]->address, account_data[2]->address->user->user_id, account_data[2]->address->domain);
    // the new group member is Claire
    Skissm__GroupMember **new_group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *));
    new_group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(new_group_members[0]);
    new_group_members[0]->user_id = strdup(account_data[2]->address->user->user_id);
    new_group_members[0]->domain = strdup(account_data[2]->address->domain);
    new_group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    size_t new_group_member_num = 1;
    // add the new group member to the group
    Skissm__AddGroupMembersResponse *add_group_members_response = add_group_members(account_data[0]->address, group.group_address, new_group_members, new_group_member_num);

    sleep(4);
    // Alice sends a message to the group
    uint8_t plaintext_2[] = "This message will be sent to Bob and Claire.";
    size_t plaintext_len_2 = sizeof(plaintext_2) - 1;
    test_encryption(account_data[0]->address, group.group_address, plaintext_2, plaintext_len_2);

    sleep(1);
    // Alice removes Claire out of the group
    Skissm__RemoveGroupMembersResponse *remove_group_members_response = remove_group_members(account_data[0]->address, group.group_address, new_group_members, new_group_member_num);

    sleep(2);
    // Alice sends a message to the group
    uint8_t plaintext_3[] = "This message will be sent to Bob only.";
    size_t plaintext_len_3 = sizeof(plaintext_3) - 1;
    test_encryption(account_data[0]->address, group.group_address, plaintext_3, plaintext_len_3);

    // release
    skissm__invite_response__free_unpacked(response, NULL);
    skissm__invite_response__free_unpacked(response2, NULL);
    skissm__group_member__free_unpacked(group_members[0], NULL);
    skissm__group_member__free_unpacked(group_members[1], NULL);
    free(group_members);
    skissm__create_group_response__free_unpacked(create_group_response, NULL);
    skissm__group_member__free_unpacked(new_group_members[0], NULL);
    free(new_group_members);
    skissm__add_group_members_response__free_unpacked(add_group_members_response, NULL);
    skissm__remove_group_members_response__free_unpacked(remove_group_members_response, NULL);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_interaction() {
    // test start
    printf("test_interaction begin!!!\n");
    tear_up();
    test_begin();

    // Prepare account
    mock_alice_account("alice");
    mock_bob_account("bob");
    mock_claire_account("claire");

    // Alice invites Bob and Claire to join the group
    Skissm__InviteResponse *response_1 = invite(account_data[0]->address, account_data[1]->address->user->user_id, account_data[1]->address->domain);
    Skissm__InviteResponse *response_2 = invite(account_data[0]->address, account_data[2]->address->user->user_id, account_data[2]->address->domain);
    // Bob invites Alice and Claire to join the group
    Skissm__InviteResponse *response_4 = invite(account_data[1]->address, account_data[2]->address->user->user_id, account_data[2]->address->domain);

    sleep(3);
    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 3);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(account_data[0]->address->user->user_id);
    group_members[0]->domain = strdup(account_data[0]->address->domain);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(account_data[1]->address->user->user_id);
    group_members[1]->domain = strdup(account_data[1]->address->domain);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the third group member is Claire
    group_members[2] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[2]);
    group_members[2]->user_id = strdup(account_data[2]->address->user->user_id);
    group_members[2]->domain = strdup(account_data[2]->address->domain);
    group_members[2]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(account_data[0]->address, "Group name", group_members, 3);

    sleep(2);
    // Alice sends a message to the group
    uint8_t plaintext_data_a[] = "This message will be sent to Bob and Claire.";
    size_t plaintext_data_a_len = sizeof(plaintext_data_a) - 1;
    test_encryption(account_data[0]->address, group.group_address, plaintext_data_a, plaintext_data_a_len);

    // Bob sends a message to the group
    uint8_t plaintext_data_b[] = "This message will be sent to Alice and Claire.";
    size_t plaintext_data_b_len = sizeof(plaintext_data_b) - 1;
    test_encryption(account_data[1]->address, group.group_address, plaintext_data_b, plaintext_data_b_len);

    // Claire sends a message to the group
    uint8_t plaintext_data_c[] = "This message will be sent to Alice and Bob.";
    size_t plaintext_data_c_len = sizeof(plaintext_data_c) - 1;
    test_encryption(account_data[2]->address, group.group_address, plaintext_data_c, plaintext_data_c_len);

    // release
    skissm__invite_response__free_unpacked(response_1, NULL);
    skissm__invite_response__free_unpacked(response_2, NULL);
    skissm__invite_response__free_unpacked(response_4, NULL);
    skissm__group_member__free_unpacked(group_members[0], NULL);
    skissm__group_member__free_unpacked(group_members[1], NULL);
    skissm__group_member__free_unpacked(group_members[2], NULL);
    free(group_members);
    skissm__create_group_response__free_unpacked(create_group_response, NULL);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_continual() {
    // test start
    printf("test_continual begin!!!\n");
    tear_up();
    test_begin();

    // Prepare account
    mock_alice_account("alice");
    mock_bob_account("bob");
    mock_claire_account("claire");

    // Alice invites Bob and Claire to join the group
    Skissm__InviteResponse *response_1 = invite(account_data[0]->address, account_data[1]->address->user->user_id, account_data[1]->address->domain);
    Skissm__InviteResponse *response_2 = invite(account_data[0]->address, account_data[2]->address->user->user_id, account_data[2]->address->domain);
    // Bob invites Alice and Claire to join the group
    Skissm__InviteResponse *response_4 = invite(account_data[1]->address, account_data[2]->address->user->user_id, account_data[2]->address->domain);

    sleep(3);
    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 3);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(account_data[0]->address->user->user_id);
    group_members[0]->domain = strdup(account_data[0]->address->domain);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(account_data[1]->address->user->user_id);
    group_members[1]->domain = strdup(account_data[1]->address->domain);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the third group member is Claire
    group_members[2] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[2]);
    group_members[2]->user_id = strdup(account_data[2]->address->user->user_id);
    group_members[2]->domain = strdup(account_data[2]->address->domain);
    group_members[2]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(account_data[0]->address, "Group name", group_members, 3);

    sleep(2);

    int i;
    // Alice sends a message to the group
    uint8_t plaintext_data_a[] = "This message will be sent to Bob and Claire by 1000 times.";
    size_t plaintext_data_a_len = sizeof(plaintext_data_a) - 1;
    for (i = 0; i < 1000; i++) {
        test_encryption(account_data[0]->address, group.group_address, plaintext_data_a, plaintext_data_a_len);
    }

    // Bob sends a message to the group
    uint8_t plaintext_data_b[] = "This message will be sent to Alice and Claire by 1000 times.";
    size_t plaintext_data_b_len = sizeof(plaintext_data_b) - 1;
    for (i = 0; i < 1000; i++) {
        test_encryption(account_data[1]->address, group.group_address, plaintext_data_b, plaintext_data_b_len);
    }

    // Claire sends a message to the group
    uint8_t plaintext_data_c[] = "This message will be sent to Alice and Bob by 1000 times.";
    size_t plaintext_data_c_len = sizeof(plaintext_data_c) - 1;
    for (i = 0; i < 1000; i++) {
        test_encryption(account_data[2]->address, group.group_address, plaintext_data_c, plaintext_data_c_len);
    }

    // release
    skissm__invite_response__free_unpacked(response_1, NULL);
    skissm__invite_response__free_unpacked(response_2, NULL);
    skissm__invite_response__free_unpacked(response_4, NULL);
    skissm__group_member__free_unpacked(group_members[0], NULL);
    skissm__group_member__free_unpacked(group_members[1], NULL);
    skissm__group_member__free_unpacked(group_members[2], NULL);
    free(group_members);
    skissm__create_group_response__free_unpacked(create_group_response, NULL);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_multiple_devices() {
    // test start
    printf("test_multiple_devices begin!!!\n");
    tear_up();
    test_begin();

    // Prepare account
    mock_alice_account("Alice");
    mock_alice_account("Alice");
    mock_bob_account("Bob");
    mock_bob_account("Bob");
    mock_claire_account("Claire");
    mock_claire_account("Claire");

    Skissm__E2eeAddress *alice_address_1 = account_data[0]->address;
    Skissm__E2eeAddress *alice_address_2 = account_data[1]->address;
    char *alice_user_id = alice_address_1->user->user_id;
    char *alice_domain = alice_address_1->domain;
    Skissm__E2eeAddress *bob_address_1 = account_data[2]->address;
    Skissm__E2eeAddress *bob_address_2 = account_data[3]->address;
    char *bob_user_id = bob_address_1->user->user_id;
    char *bob_domain = bob_address_1->domain;
    Skissm__E2eeAddress *claire_address_1 = account_data[4]->address;
    Skissm__E2eeAddress *claire_address_2 = account_data[5]->address;
    char *claire_user_id = claire_address_1->user->user_id;
    char *claire_domain = claire_address_1->domain;

    sleep(3);

    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 3);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(alice_user_id);
    group_members[0]->domain = strdup(alice_domain);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(bob_user_id);
    group_members[1]->domain = strdup(bob_domain);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the third group member is Claire
    group_members[2] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[2]);
    group_members[2]->user_id = strdup(claire_user_id);
    group_members[2]->domain = strdup(claire_domain);
    group_members[2]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(alice_address_1, "Group name", group_members, 3);

    sleep(2);
    // Alice sends a message to the group via the first device
    uint8_t plaintext_1[] = "This message is from Alice's first device.";
    size_t plaintext_1_len = sizeof(plaintext_1) - 1;
    test_encryption(account_data[0]->address, group.group_address, plaintext_1, plaintext_1_len);

    // Bob sends a message to the group via the second device
    uint8_t plaintext_2[] = "This message is from Bob's second device.";
    size_t plaintext_2_len = sizeof(plaintext_2) - 1;
    test_encryption(account_data[3]->address, group.group_address, plaintext_2, plaintext_2_len);

    // Claire sends a message to the group via the second device
    uint8_t plaintext_3[] = "This message is from Claire's second device.";
    size_t plaintext_3_len = sizeof(plaintext_3) - 1;
    test_encryption(account_data[5]->address, group.group_address, plaintext_3, plaintext_3_len);

    // release
    skissm__group_member__free_unpacked(group_members[0], NULL);
    skissm__group_member__free_unpacked(group_members[1], NULL);
    skissm__group_member__free_unpacked(group_members[2], NULL);
    free(group_members);
    skissm__create_group_response__free_unpacked(create_group_response, NULL);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_pqc_create_group() {
    // test start
    printf("test_pqc_create_group begin!!!\n");
    tear_up();
    test_begin();

    // prepare account
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");
    mock_user_pqc_account("Claire", "claire@domain.com.tw", "345678");
    mock_user_pqc_account("David", "david@domain.com.tw", "456789");

    Skissm__E2eeAddress *alice_address = account_data[0]->address;
    char *alice_user_id = alice_address->user->user_id;
    char *alice_domain = alice_address->domain;
    Skissm__E2eeAddress *bob_address = account_data[1]->address;
    char *bob_user_id = bob_address->user->user_id;
    char *bob_domain = bob_address->domain;
    Skissm__E2eeAddress *claire_address = account_data[2]->address;
    char *claire_user_id = claire_address->user->user_id;
    char *claire_domain = claire_address->domain;
    Skissm__E2eeAddress *david_address = account_data[3]->address;
    char *david_user_id = david_address->user->user_id;
    char *david_domain = david_address->domain;

    sleep(2);
    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 4);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(alice_user_id);
    group_members[0]->domain = strdup(alice_domain);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(bob_user_id);
    group_members[1]->domain = strdup(bob_domain);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the third group member is Claire
    group_members[2] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[2]);
    group_members[2]->user_id = strdup(claire_user_id);
    group_members[2]->domain = strdup(claire_domain);
    group_members[2]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the fourth group member is David
    group_members[3] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[3]);
    group_members[3]->user_id = strdup(david_user_id);
    group_members[3]->domain = strdup(david_domain);
    group_members[3]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(alice_address, "Group name", group_members, 4);

    assert(create_group_response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK);
    Skissm__E2eeAddress *group_address = create_group_response->group_address;

    sleep(5);
    // Everyone sends a message to the group
    uint8_t plaintext_1[] = "Alice's message(PQC version).";
    size_t plaintext_1_len = sizeof(plaintext_1) - 1;
    test_encryption(alice_address, group_address, plaintext_1, plaintext_1_len);

    uint8_t plaintext_2[] = "Bob's message(PQC version).";
    size_t plaintext_2_len = sizeof(plaintext_2) - 1;
    test_encryption(bob_address, group_address, plaintext_2, plaintext_2_len);

    uint8_t plaintext_3[] = "Claire's message(PQC version).";
    size_t plaintext_3_len = sizeof(plaintext_3) - 1;
    test_encryption(claire_address, group_address, plaintext_3, plaintext_3_len);

    uint8_t plaintext_4[] = "David's message(PQC version).";
    size_t plaintext_4_len = sizeof(plaintext_4) - 1;
    test_encryption(david_address, group_address, plaintext_4, plaintext_4_len);

    // release
    skissm__group_member__free_unpacked(group_members[0], NULL);
    skissm__group_member__free_unpacked(group_members[1], NULL);
    skissm__group_member__free_unpacked(group_members[2], NULL);
    skissm__group_member__free_unpacked(group_members[3], NULL);
    free(group_members);
    skissm__create_group_response__free_unpacked(create_group_response, NULL);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_pqc_add_group_members() {
    // test start
    printf("test_pqc_add_group_members begin!!!\n");
    tear_up();
    test_begin();

    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");
    mock_user_pqc_account("Claire", "claire@domain.com.tw", "345678");
    mock_user_pqc_account("David", "david@domain.com.tw", "456789");

    Skissm__E2eeAddress *alice_address = account_data[0]->address;
    char *alice_user_id = alice_address->user->user_id;
    char *alice_domain = alice_address->domain;
    Skissm__E2eeAddress *bob_address = account_data[1]->address;
    char *bob_user_id = bob_address->user->user_id;
    char *bob_domain = bob_address->domain;
    Skissm__E2eeAddress *claire_address = account_data[2]->address;
    char *claire_user_id = claire_address->user->user_id;
    char *claire_domain = claire_address->domain;
    Skissm__E2eeAddress *david_address = account_data[3]->address;
    char *david_user_id = david_address->user->user_id;
    char *david_domain = david_address->domain;

    sleep(2);
    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 3);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(alice_user_id);
    group_members[0]->domain = strdup(alice_domain);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(bob_user_id);
    group_members[1]->domain = strdup(bob_domain);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the third group member is Claire
    group_members[2] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[2]);
    group_members[2]->user_id = strdup(claire_user_id);
    group_members[2]->domain = strdup(claire_domain);
    group_members[2]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(alice_address, "Group name", group_members, 3);
    Skissm__E2eeAddress *group_address = create_group_response->group_address;

    sleep(4);
    // the new group member is David
    Skissm__GroupMember **new_group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *));
    new_group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(new_group_members[0]);
    new_group_members[0]->user_id = strdup(david_user_id);
    new_group_members[0]->domain = strdup(david_domain);
    new_group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    size_t new_group_member_num = 1;
    // add the new group member to the group
    Skissm__AddGroupMembersResponse *add_group_members_response = add_group_members(alice_address, group_address, new_group_members, new_group_member_num);
    assert(add_group_members_response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK);

    sleep(3);
    // Everyone sends a message to the group
    uint8_t plaintext_1[] = "Alice's message(David joined).";
    size_t plaintext_1_len = sizeof(plaintext_1) - 1;
    test_encryption(alice_address, group_address, plaintext_1, plaintext_1_len);

    uint8_t plaintext_2[] = "Bob's message(David joined).";
    size_t plaintext_2_len = sizeof(plaintext_2) - 1;
    test_encryption(bob_address, group_address, plaintext_2, plaintext_2_len);

    uint8_t plaintext_3[] = "Claire's message(David joined).";
    size_t plaintext_3_len = sizeof(plaintext_3) - 1;
    test_encryption(claire_address, group_address, plaintext_3, plaintext_3_len);

    uint8_t plaintext_4[] = "David's message(David joined).";
    size_t plaintext_4_len = sizeof(plaintext_4) - 1;
    test_encryption(david_address, group_address, plaintext_4, plaintext_4_len);

    // release
    skissm__group_member__free_unpacked(group_members[0], NULL);
    skissm__group_member__free_unpacked(group_members[1], NULL);
    skissm__group_member__free_unpacked(group_members[2], NULL);
    free(group_members);
    skissm__create_group_response__free_unpacked(create_group_response, NULL);
    skissm__group_member__free_unpacked(new_group_members[0], NULL);
    free(new_group_members);
    skissm__add_group_members_response__free_unpacked(add_group_members_response, NULL);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_pqc_remove_group_members() {
    // test start
    printf("test_pqc_remove_group_members begin!!!\n");
    tear_up();
    test_begin();

    // prepare account
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");
    mock_user_pqc_account("Claire", "claire@domain.com.tw", "345678");
    mock_user_pqc_account("David", "david@domain.com.tw", "456789");

    Skissm__E2eeAddress *alice_address = account_data[0]->address;
    char *alice_user_id = alice_address->user->user_id;
    char *alice_domain = alice_address->domain;
    Skissm__E2eeAddress *bob_address = account_data[1]->address;
    char *bob_user_id = bob_address->user->user_id;
    char *bob_domain = bob_address->domain;
    Skissm__E2eeAddress *claire_address = account_data[2]->address;
    char *claire_user_id = claire_address->user->user_id;
    char *claire_domain = claire_address->domain;
    Skissm__E2eeAddress *david_address = account_data[3]->address;
    char *david_user_id = david_address->user->user_id;
    char *david_domain = david_address->domain;

    sleep(2);
    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 4);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(alice_user_id);
    group_members[0]->domain = strdup(alice_domain);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(bob_user_id);
    group_members[1]->domain = strdup(bob_domain);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the third group member is Claire
    group_members[2] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[2]);
    group_members[2]->user_id = strdup(claire_user_id);
    group_members[2]->domain = strdup(claire_domain);
    group_members[2]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the fourth group member is David
    group_members[3] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[3]);
    group_members[3]->user_id = strdup(david_user_id);
    group_members[3]->domain = strdup(david_domain);
    group_members[3]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(alice_address, "Group name", group_members, 4);
    Skissm__E2eeAddress *group_address = create_group_response->group_address;

    sleep(5);
    // the removing group member is Claire
    Skissm__GroupMember **removing_group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *));
    removing_group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(removing_group_members[0]);
    removing_group_members[0]->user_id = strdup(claire_user_id);
    removing_group_members[0]->domain = strdup(claire_domain);
    removing_group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    size_t removing_group_member_num = 1;
    // Alice removes Claire out of the group
    Skissm__RemoveGroupMembersResponse *remove_group_members_response = remove_group_members(
        alice_address, group_address, removing_group_members, removing_group_member_num
    );
    assert(remove_group_members_response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK);

    sleep(4);
    // Everyone sends a message to the group
    uint8_t plaintext_1[] = "Alice's message(Claire removed).";
    size_t plaintext_1_len = sizeof(plaintext_1) - 1;
    test_encryption(alice_address, group_address, plaintext_1, plaintext_1_len);

    uint8_t plaintext_2[] = "Bob's message(Claire removed).";
    size_t plaintext_2_len = sizeof(plaintext_2) - 1;
    test_encryption(bob_address, group_address, plaintext_2, plaintext_2_len);

    uint8_t plaintext_4[] = "David's message(Claire removed).";
    size_t plaintext_4_len = sizeof(plaintext_4) - 1;
    test_encryption(david_address, group_address, plaintext_4, plaintext_4_len);

    // release
    skissm__group_member__free_unpacked(group_members[0], NULL);
    skissm__group_member__free_unpacked(group_members[1], NULL);
    skissm__group_member__free_unpacked(group_members[2], NULL);
    skissm__group_member__free_unpacked(group_members[3], NULL);
    free(group_members);
    skissm__create_group_response__free_unpacked(create_group_response, NULL);
    skissm__group_member__free_unpacked(removing_group_members[0], NULL);
    free(removing_group_members);
    skissm__remove_group_members_response__free_unpacked(remove_group_members_response, NULL);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_pqc_leave_group() {
    // test start
    printf("test_pqc_leave_group begin!!!\n");
    tear_up();
    test_begin();

    // prepare account
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");
    mock_user_pqc_account("Claire", "claire@domain.com.tw", "345678");
    mock_user_pqc_account("David", "david@domain.com.tw", "456789");

    Skissm__E2eeAddress *alice_address = account_data[0]->address;
    char *alice_user_id = alice_address->user->user_id;
    char *alice_domain = alice_address->domain;
    Skissm__E2eeAddress *bob_address = account_data[1]->address;
    char *bob_user_id = bob_address->user->user_id;
    char *bob_domain = bob_address->domain;
    Skissm__E2eeAddress *claire_address = account_data[2]->address;
    char *claire_user_id = claire_address->user->user_id;
    char *claire_domain = claire_address->domain;
    Skissm__E2eeAddress *david_address = account_data[3]->address;
    char *david_user_id = david_address->user->user_id;
    char *david_domain = david_address->domain;

    sleep(2);
    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 4);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(alice_user_id);
    group_members[0]->domain = strdup(alice_domain);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(bob_user_id);
    group_members[1]->domain = strdup(bob_domain);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the third group member is Claire
    group_members[2] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[2]);
    group_members[2]->user_id = strdup(claire_user_id);
    group_members[2]->domain = strdup(claire_domain);
    group_members[2]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the fourth group member is David
    group_members[3] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[3]);
    group_members[3]->user_id = strdup(david_user_id);
    group_members[3]->domain = strdup(david_domain);
    group_members[3]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(alice_address, "Group name", group_members, 4);
    Skissm__E2eeAddress *group_address = create_group_response->group_address;

    sleep(5);
    // Claire leaves the group
    Skissm__LeaveGroupResponse *leave_group_response = leave_group(claire_address, group_address);

    sleep(4);
    // Everyone sends a message to the group
    uint8_t plaintext_1[] = "Alice's message(Claire removed her self).";
    size_t plaintext_1_len = sizeof(plaintext_1) - 1;
    test_encryption(alice_address, group_address, plaintext_1, plaintext_1_len);

    uint8_t plaintext_2[] = "Bob's message(Claire removed her self).";
    size_t plaintext_2_len = sizeof(plaintext_2) - 1;
    test_encryption(bob_address, group_address, plaintext_2, plaintext_2_len);

    uint8_t plaintext_4[] = "David's message(Claire removed her self).";
    size_t plaintext_4_len = sizeof(plaintext_4) - 1;
    test_encryption(david_address, group_address, plaintext_4, plaintext_4_len);

    // release
    skissm__group_member__free_unpacked(group_members[0], NULL);
    skissm__group_member__free_unpacked(group_members[1], NULL);
    skissm__group_member__free_unpacked(group_members[2], NULL);
    skissm__group_member__free_unpacked(group_members[3], NULL);
    free(group_members);
    skissm__create_group_response__free_unpacked(create_group_response, NULL);
    skissm__leave_group_response__free_unpacked(leave_group_response, NULL);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_pqc_multiple_devices() {
    // test start
    printf("test_pqc_multiple_devices begin!!!\n");
    tear_up();
    test_begin();

    // prepare account
    mock_alice_pqc_account("Alice");
    mock_alice_pqc_account("Alice");
    mock_bob_pqc_account("Bob");
    mock_bob_pqc_account("Bob");
    mock_claire_pqc_account("Claire");
    mock_claire_pqc_account("Claire");

    sleep(2);

    Skissm__E2eeAddress *alice_address_1 = account_data[0]->address;
    Skissm__E2eeAddress *alice_address_2 = account_data[1]->address;
    char *alice_user_id = alice_address_1->user->user_id;
    char *alice_domain = alice_address_1->domain;
    Skissm__E2eeAddress *bob_address_1 = account_data[2]->address;
    Skissm__E2eeAddress *bob_address_2 = account_data[3]->address;
    char *bob_user_id = bob_address_1->user->user_id;
    char *bob_domain = bob_address_1->domain;
    Skissm__E2eeAddress *claire_address_1 = account_data[4]->address;
    Skissm__E2eeAddress *claire_address_2 = account_data[5]->address;
    char *claire_user_id = claire_address_1->user->user_id;
    char *claire_domain = claire_address_1->domain;

    sleep(3);

    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 3);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(alice_user_id);
    group_members[0]->domain = strdup(alice_domain);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(bob_user_id);
    group_members[1]->domain = strdup(bob_domain);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the third group member is Claire
    group_members[2] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[2]);
    group_members[2]->user_id = strdup(claire_user_id);
    group_members[2]->domain = strdup(claire_domain);
    group_members[2]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(alice_address_1, "Group name", group_members, 3);

    sleep(2);
    // Alice sends a message to the group via the first device
    uint8_t plaintext_1[] = "This message is from Alice's first device via pqc session.";
    size_t plaintext_1_len = sizeof(plaintext_1) - 1;
    test_encryption(alice_address_1, group.group_address, plaintext_1, plaintext_1_len);

    // Bob sends a message to the group via the second device
    uint8_t plaintext_2[] = "This message is from Bob's second device via pqc session.";
    size_t plaintext_2_len = sizeof(plaintext_2) - 1;
    test_encryption(bob_address_2, group.group_address, plaintext_2, plaintext_2_len);

    // Claire sends a message to the group via the second device
    uint8_t plaintext_3[] = "This message is from Claire's second device via pqc session.";
    size_t plaintext_3_len = sizeof(plaintext_3) - 1;
    test_encryption(claire_address_2, group.group_address, plaintext_3, plaintext_3_len);

    // release
    skissm__group_member__free_unpacked(group_members[0], NULL);
    skissm__group_member__free_unpacked(group_members[1], NULL);
    skissm__group_member__free_unpacked(group_members[2], NULL);
    free(group_members);
    skissm__create_group_response__free_unpacked(create_group_response, NULL);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_pqc_add_new_device() {
    // test start
    printf("test_pqc_add_new_device begin!!!\n");
    tear_up();
    test_begin();

    mock_alice_pqc_account("Alice");
    mock_bob_pqc_account("Bob");
    mock_claire_pqc_account("Claire");

    sleep(2);

    Skissm__E2eeAddress *alice_address = account_data[0]->address;
    char *alice_user_id = alice_address->user->user_id;
    char *alice_domain = alice_address->domain;
    Skissm__E2eeAddress *bob_address = account_data[1]->address;
    char *bob_user_id = bob_address->user->user_id;
    char *bob_domain = bob_address->domain;
    Skissm__E2eeAddress *claire_address = account_data[2]->address;
    char *claire_user_id = claire_address->user->user_id;
    char *claire_domain = claire_address->domain;

    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 3);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(alice_user_id);
    group_members[0]->domain = strdup(alice_domain);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(bob_user_id);
    group_members[1]->domain = strdup(bob_domain);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the third group member is Claire
    group_members[2] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[2]);
    group_members[2]->user_id = strdup(claire_user_id);
    group_members[2]->domain = strdup(claire_domain);
    group_members[2]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;

    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(alice_address, "Group name", group_members, 3);

    sleep(2);

    // add new device
    mock_alice_pqc_account("Alice");

    sleep(2);

    // Alice sends a message to the group via the first device
    uint8_t plaintext_1[] = "This message is from Alice's first device via pqc session.";
    size_t plaintext_1_len = sizeof(plaintext_1) - 1;
    test_encryption(alice_address, group.group_address, plaintext_1, plaintext_1_len);

    // release
    skissm__group_member__free_unpacked(group_members[0], NULL);
    skissm__group_member__free_unpacked(group_members[1], NULL);
    skissm__group_member__free_unpacked(group_members[2], NULL);
    free(group_members);
    skissm__create_group_response__free_unpacked(create_group_response, NULL);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_medium_group() {
    // test start
    printf("test_medium_group begin!!!\n");
    tear_up();
    test_begin();

    // prepare account
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");
    mock_user_pqc_account("Claire", "claire@domain.com.tw", "345678");
    mock_user_pqc_account("David", "david@domain.com.tw", "456789");
    mock_user_pqc_account("Emily", "emily@domain.com.tw", "567890");
    mock_user_pqc_account("Frank", "frank@domain.com.tw", "678901");
    mock_user_pqc_account("Grace", "grace@domain.com.tw", "789012");
    mock_user_pqc_account("Harry", "harry@domain.com.tw", "890123");
    mock_user_pqc_account("Ivy", "ivy@domain.com.tw", "901234");
    mock_user_pqc_account("Jack", "jack@domain.com.tw", "012345");
    mock_user_pqc_account("Karen", "karen@domain.com.tw", "111111");
    mock_user_pqc_account("Leo", "leo@domain.com.tw", "222222");
    mock_user_pqc_account("Mary", "mary@domain.com.tw", "333333");
    mock_user_pqc_account("Nick", "nick@domain.com.tw", "444444");

    sleep(10);

    Skissm__E2eeAddress *alice_address = account_data[0]->address;
    char *alice_user_id = alice_address->user->user_id;
    char *alice_domain = alice_address->domain;
    Skissm__E2eeAddress *bob_address = account_data[1]->address;
    char *bob_user_id = bob_address->user->user_id;
    char *bob_domain = bob_address->domain;
    Skissm__E2eeAddress *claire_address = account_data[2]->address;
    char *claire_user_id = claire_address->user->user_id;
    char *claire_domain = claire_address->domain;
    Skissm__E2eeAddress *david_address = account_data[3]->address;
    char *david_user_id = david_address->user->user_id;
    char *david_domain = david_address->domain;
    Skissm__E2eeAddress *emily_address = account_data[4]->address;
    char *emily_user_id = emily_address->user->user_id;
    char *emily_domain = emily_address->domain;
    Skissm__E2eeAddress *frank_address = account_data[5]->address;
    char *frank_user_id = frank_address->user->user_id;
    char *frank_domain = frank_address->domain;
    Skissm__E2eeAddress *grace_address = account_data[6]->address;
    char *grace_user_id = grace_address->user->user_id;
    char *grace_domain = grace_address->domain;
    Skissm__E2eeAddress *harry_address = account_data[7]->address;
    char *harry_user_id = harry_address->user->user_id;
    char *harry_domain = harry_address->domain;
    Skissm__E2eeAddress *ivy_address = account_data[8]->address;
    char *ivy_user_id = ivy_address->user->user_id;
    char *ivy_domain = ivy_address->domain;
    Skissm__E2eeAddress *jack_address = account_data[9]->address;
    char *jack_user_id = jack_address->user->user_id;
    char *jack_domain = jack_address->domain;
    Skissm__E2eeAddress *karen_address = account_data[10]->address;
    char *karen_user_id = karen_address->user->user_id;
    char *karen_domain = karen_address->domain;
    Skissm__E2eeAddress *leo_address = account_data[11]->address;
    char *leo_user_id = leo_address->user->user_id;
    char *leo_domain = leo_address->domain;
    Skissm__E2eeAddress *mary_address = account_data[12]->address;
    char *mary_user_id = mary_address->user->user_id;
    char *mary_domain = mary_address->domain;
    Skissm__E2eeAddress *nick_address = account_data[13]->address;
    char *nick_user_id = nick_address->user->user_id;
    char *nick_domain = nick_address->domain;

    // the first group member is Alice
    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 10);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(alice_user_id);
    group_members[0]->domain = strdup(alice_domain);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(bob_user_id);
    group_members[1]->domain = strdup(bob_domain);
    group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the third group member is Claire
    group_members[2] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[2]);
    group_members[2]->user_id = strdup(claire_user_id);
    group_members[2]->domain = strdup(claire_domain);
    group_members[2]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the fourth group member is David
    group_members[3] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[3]);
    group_members[3]->user_id = strdup(david_user_id);
    group_members[3]->domain = strdup(david_domain);
    group_members[3]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the fifth group member is Emily
    group_members[4] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[4]);
    group_members[4]->user_id = strdup(emily_user_id);
    group_members[4]->domain = strdup(emily_domain);
    group_members[4]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the sixth group member is Frank
    group_members[5] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[5]);
    group_members[5]->user_id = strdup(frank_user_id);
    group_members[5]->domain = strdup(frank_domain);
    group_members[5]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the seventh group member is Grace
    group_members[6] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[6]);
    group_members[6]->user_id = strdup(grace_user_id);
    group_members[6]->domain = strdup(grace_domain);
    group_members[6]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the eighth group member is Harry
    group_members[7] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[7]);
    group_members[7]->user_id = strdup(harry_user_id);
    group_members[7]->domain = strdup(harry_domain);
    group_members[7]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the ninth group member is Ivy
    group_members[8] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[8]);
    group_members[8]->user_id = strdup(ivy_user_id);
    group_members[8]->domain = strdup(ivy_domain);
    group_members[8]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // the tenth group member is Jack
    group_members[9] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[9]);
    group_members[9]->user_id = strdup(jack_user_id);
    group_members[9]->domain = strdup(jack_domain);
    group_members[9]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;

    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(alice_address, "Group name", group_members, 10);

    sleep(10);

    // group message
    uint8_t plaintext_1[] = "Alice's message.";
    size_t plaintext_1_len = sizeof(plaintext_1) - 1;
    test_encryption(alice_address, group.group_address, plaintext_1, plaintext_1_len);

    uint8_t plaintext_2[] = "David's message.";
    size_t plaintext_2_len = sizeof(plaintext_2) - 1;
    test_encryption(david_address, group.group_address, plaintext_2, plaintext_2_len);

    uint8_t plaintext_3[] = "Grace's message.";
    size_t plaintext_3_len = sizeof(plaintext_3) - 1;
    test_encryption(grace_address, group.group_address, plaintext_3, plaintext_3_len);

    sleep(3);

    // new group members
    Skissm__GroupMember **new_group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 4);
    new_group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(new_group_members[0]);
    new_group_members[0]->user_id = strdup(karen_user_id);
    new_group_members[0]->domain = strdup(karen_domain);
    new_group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    new_group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(new_group_members[1]);
    new_group_members[1]->user_id = strdup(leo_user_id);
    new_group_members[1]->domain = strdup(leo_domain);
    new_group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    new_group_members[2] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(new_group_members[2]);
    new_group_members[2]->user_id = strdup(mary_user_id);
    new_group_members[2]->domain = strdup(mary_domain);
    new_group_members[2]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    new_group_members[3] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(new_group_members[3]);
    new_group_members[3]->user_id = strdup(nick_user_id);
    new_group_members[3]->domain = strdup(nick_domain);
    new_group_members[3]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    size_t new_group_member_num = 4;

    // add new group members to the group
    Skissm__AddGroupMembersResponse *add_group_members_response = add_group_members(
        alice_address, group.group_address, new_group_members, new_group_member_num
    );

    sleep(10);

    // group message
    uint8_t plaintext_4[] = "Jack's message.";
    size_t plaintext_4_len = sizeof(plaintext_4) - 1;
    test_encryption(jack_address, group.group_address, plaintext_4, plaintext_4_len);

    uint8_t plaintext_5[] = "Karen's message.";
    size_t plaintext_5_len = sizeof(plaintext_5) - 1;
    test_encryption(karen_address, group.group_address, plaintext_5, plaintext_5_len);

    uint8_t plaintext_6[] = "Nick's message.";
    size_t plaintext_6_len = sizeof(plaintext_6) - 1;
    test_encryption(nick_address, group.group_address, plaintext_6, plaintext_6_len);

    sleep(5);

    // remove group members
    Skissm__GroupMember **removing_group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 4);
    removing_group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(removing_group_members[0]);
    removing_group_members[0]->user_id = strdup(david_user_id);
    removing_group_members[0]->domain = strdup(david_domain);
    removing_group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    removing_group_members[1] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(removing_group_members[1]);
    removing_group_members[1]->user_id = strdup(ivy_user_id);
    removing_group_members[1]->domain = strdup(ivy_domain);
    removing_group_members[1]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    removing_group_members[2] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(removing_group_members[2]);
    removing_group_members[2]->user_id = strdup(karen_user_id);
    removing_group_members[2]->domain = strdup(karen_domain);
    removing_group_members[2]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    removing_group_members[3] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(removing_group_members[3]);
    removing_group_members[3]->user_id = strdup(leo_user_id);
    removing_group_members[3]->domain = strdup(leo_domain);
    removing_group_members[3]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    size_t removing_group_member_num = 4;

    Skissm__RemoveGroupMembersResponse *remove_group_members_response = remove_group_members(
        alice_address, group.group_address, removing_group_members, removing_group_member_num
    );

    sleep(10);

    // group message
    uint8_t plaintext_7[] = "Bob's message.";
    size_t plaintext_7_len = sizeof(plaintext_7) - 1;
    test_encryption(bob_address, group.group_address, plaintext_7, plaintext_7_len);

    uint8_t plaintext_8[] = "Mary's message.";
    size_t plaintext_8_len = sizeof(plaintext_8) - 1;
    test_encryption(mary_address, group.group_address, plaintext_8, plaintext_8_len);

    // release
    int i;
    for (i = 0; i < 10; i++) {
        skissm__group_member__free_unpacked(group_members[i], NULL);
    }
    free(group_members);
    skissm__create_group_response__free_unpacked(create_group_response, NULL);
    for (i = 0; i < 4; i++) {
        skissm__group_member__free_unpacked(new_group_members[i], NULL);
        skissm__group_member__free_unpacked(removing_group_members[i], NULL);
    }
    free(new_group_members);
    free(removing_group_members);
    skissm__add_group_members_response__free_unpacked(add_group_members_response, NULL);
    skissm__remove_group_members_response__free_unpacked(remove_group_members_response, NULL);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_create_group_time() {
    // test start
    printf("test_create_group_time begin!!!\n");
    tear_up();
    test_begin();

    // prepare account
    int i;
    for (i = 0; i < 200; i++) {
        mock_user_pqc_account(mock_user_name[i], mock_authenticator[i], mock_auth_code[i]);
    }

    sleep(10);

    Skissm__GroupMember **group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * 200);
    group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(account_data[0]->address->user->user_id);
    group_members[0]->domain = strdup(account_data[0]->address->domain);
    group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MANAGER;
    for (i = 1; i < 200; i++) {
        group_members[i] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
        skissm__group_member__init(group_members[i]);
        group_members[i]->user_id = strdup(account_data[i]->address->user->user_id);
        group_members[i]->domain = strdup(account_data[i]->address->domain);
        group_members[i]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    }

    time_t start, end;
    start = time(NULL);
    // create the group
    Skissm__CreateGroupResponse *create_group_response = create_group(account_data[0]->address, "Group name", group_members, 200);

    // test stop
    test_end();
    tear_down();

    end = time(NULL);
    printf("Creating group time: %ld seconds\n\n", end - start);

    printf("====================================\n");
}

int main() {
    // test_create_group();
    // test_add_group_members();
    // test_remove_group_members();
    test_create_add_remove();
    test_interaction();
    test_continual();
    // test_multiple_devices();
    // test_pqc_create_group();
    // test_pqc_add_group_members();
    // test_pqc_remove_group_members();
    test_pqc_leave_group();
    test_pqc_multiple_devices();
    test_pqc_add_new_device();
    test_medium_group();
    // test_create_group_time();

    return 0;
}
