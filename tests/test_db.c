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

#include "mem_util.h"
#include "test_db.h"

// global variable
static const char *db_name = (char *)"test.db";
static sqlite3 *db;

// util function
static void sqlite_connect(const char *db_name) {
    int rc = sqlite3_open(db_name, &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        exit(1);
    }
}

static int sqlite_callback(void *data, int argc, char **argv, char **azColName) {
    fprintf(stderr, "%s: ", (const char *)data);
    for (int i = 0; i < argc; i++) {
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    printf("\n");

    return 0;
}

static void sqlite_execute(const char *sql) {
    char *errMsg = NULL;
    const char *data = (char *)"Callback function called";

    int rc = sqlite3_exec(db, sql, sqlite_callback, (void *)data, &errMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
    }
}

static bool sqlite_prepare(const char *sql, sqlite3_stmt **stmt) {
    int rc = sqlite3_prepare(db, sql, -1, stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot prepare statement: %s\n", sqlite3_errmsg(db));
        return false;
    }

    return true;
}

static bool sqlite_step(sqlite3_stmt *stmt, int return_code) {
    int rc = sqlite3_step(stmt);
    if (rc != return_code) {
        fprintf(stderr, "Cannot step correctly.");
        return false;
    }

    return true;
}

// SQLs
// session related
static const char *SESSION_DROP_TABLE = "DROP TABLE IF EXISTS SESSION;";
static const char *SESSION_CREATE_TABLE = "CREATE TABLE SESSION( "
                                          "ID BLOB NOT NULL, "
                                          "OWNER INTEGER NOT NULL, "
                                          "FROM_ADDRESS INTEGER NOT NULL, "
                                          "TO_ADDRESS INTEGER NOT NULL, "
                                          "TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, "
                                          "DATA BLOB NOT NULL, "
                                          "FOREIGN KEY(FROM_ADDRESS) REFERENCES ADDRESS(ID), "
                                          "FOREIGN KEY(TO_ADDRESS) REFERENCES ADDRESS(ID), "
                                          "PRIMARY KEY (ID, TO_ADDRESS));";

static const char *SESSION_LOAD_DATA_BY_OWNER_AND_TO = "SELECT DATA FROM SESSION "
                                                       "INNER JOIN ADDRESS AS a1 "
                                                       "ON SESSION.OWNER = a1.ID "
                                                       "INNER JOIN ADDRESS AS a2 "
                                                       "ON SESSION.TO_ADDRESS = a2.ID "
                                                       "WHERE a1.USER_ID = (?) AND a2.USER_ID = (?) "
                                                       "ORDER BY TIMESTAMP DESC "
                                                       "LIMIT 1;";

static const char *SESSION_INSERT_OR_REPLACE = "INSERT OR REPLACE INTO SESSION "
                                               "(ID, OWNER, FROM_ADDRESS, TO_ADDRESS, DATA) "
                                               "VALUES (?, ?, ?, ?, ?);";

static const char *SESSION_LOAD_DATA_BY_ID_AND_OWNER = "SELECT DATA FROM SESSION "
                                                       "INNER JOIN ADDRESS "
                                                       "ON SESSION.OWNER = ADDRESS.ID "
                                                       "WHERE SESSION.ID = (?) AND ADDRESS.USER_ID = (?);";

static const char *SESSION_DELETE_DATA_BY_OWNER_FROM_AND_TO = "DELETE FROM SESSION "
                                                              "WHERE OWNER IN "
                                                              "(SELECT ID FROM ADDRESS WHERE USER_ID = (?)) "
                                                              "AND FROM_ADDRESS IN "
                                                              "(SELECT ID FROM ADDRESS WHERE USER_ID = (?)) "
                                                              "AND TO_ADDRESS IN "
                                                              "(SELECT ID FROM ADDRESS WHERE USER_ID = (?));";

static const char *GROUP_SESSION_DROP_TABLE = "DROP TABLE IF EXISTS GROUP_SESSION;";
static const char *GROUP_SESSION_CREATE_TABLE = "CREATE TABLE GROUP_SESSION( "
                                                "ID BLOB NOT NULL, "
                                                "OWNER INTEGER NOT NULL, "
                                                "ADDRESS INTEGER NOT NULL, "
                                                "TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, "
                                                "GROUP_DATA BLOB NOT NULL, "
                                                "HAS_SIGNATURE_PRIVATE_KEY INTEGER NOT NULL, "
                                                "FOREIGN KEY(OWNER) REFERENCES ADDRESS(ID), "
                                                "FOREIGN KEY(ADDRESS) REFERENCES ADDRESS(ID), "
                                                "PRIMARY KEY (ADDRESS, OWNER), "
                                                "UNIQUE (ID, OWNER));";

static const char *GROUP_SESSION_INSERT_OR_REPLACE = "INSERT OR REPLACE INTO GROUP_SESSION "
                                                     "(ID, OWNER, ADDRESS, GROUP_DATA, HAS_SIGNATURE_PRIVATE_KEY) "
                                                     "VALUES (?, ?, ?, ?, ?);";

static const char *GROUP_SESSION_LOAD_DATA_BY_ID_AND_OWNER =
    "SELECT GROUP_DATA FROM GROUP_SESSION "
    "INNER JOIN ADDRESS "
    "ON GROUP_SESSION.OWNER = ADDRESS.ID "
    "WHERE GROUP_SESSION.ID = (?) AND ADDRESS.USER_ID = (?) AND ADDRESS.DOMAIN "
    "= (?) AND ADDRESS.DEVICE_ID = (?);";

static const char *GROUP_SESSION_LOAD_DATA_BY_OWNER_AND_ADDRESS =
    "SELECT GROUP_DATA FROM GROUP_SESSION "
    "INNER JOIN ADDRESS as a1 "
    "ON GROUP_SESSION.OWNER = a1.ID "
    "INNER JOIN ADDRESS as a2 "
    "ON GROUP_SESSION.ADDRESS = a2.ID "
    "WHERE a1.USER_ID = (?) AND a1.DOMAIN = (?) AND a1.DEVICE_ID = (?) AND "
    "a2.GROUP_ID = (?) AND HAS_SIGNATURE_PRIVATE_KEY = 1 "
    "LIMIT 1;";

static const char *GROUP_SESSION_DELETE_DATA_BY_OWNER_AND_ADDRESS = "DELETE FROM GROUP_SESSION "
                                                                    "WHERE OWNER IN "
                                                                    "(SELECT ID FROM ADDRESS WHERE USER_ID = (?)) "
                                                                    "AND ADDRESS IN "
                                                                    "(SELECT ID FROM ADDRESS WHERE GROUP_ID = (?));";

static const char *GROUP_SESSION_DELETE_DATA_BY_OWNER_AND_ID = "DELETE FROM GROUP_SESSION "
                                                               "WHERE OWNER IN "
                                                               "(SELECT ID FROM ADDRESS WHERE USER_ID = (?)) "
                                                               "AND ID = (?);";

// account related
static const char *ADDRESS_DROP_TABLE = "DROP TABLE IF EXISTS ADDRESS;";
static const char *ADDRESS_CREATE_TABLE = "CREATE TABLE ADDRESS( "
                                          "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
                                          "USER_ID BLOB, "
                                          "DOMAIN BLOB NOT NULL, "
                                          "DEVICE_ID BLOB, "
                                          "GROUP_ID BLOB, "
                                          "UNIQUE (USER_ID, DOMAIN, DEVICE_ID, GROUP_ID));";

static const char *KEYPAIR_DROP_TABLE = "DROP TABLE IF EXISTS KEYPAIR;";
static const char *KEYPAIR_CREATE_TABLE = "CREATE TABLE KEYPAIR( "
                                          "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
                                          "PUBLIC_KEY BLOB NOT NULL, "
                                          "PRIVATE_KEY BLOB NOT NULL);";

static const char *SIGNED_PRE_KEYPAIR_DROP_TABLE = "DROP TABLE IF EXISTS SIGNED_PRE_KEYPAIR;";
static const char *SIGNED_PRE_KEYPAIR_CREATE_TABLE = "CREATE TABLE SIGNED_PRE_KEYPAIR( "
                                                     "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                     "SPK_ID INTEGER NOT NULL, "
                                                     "KEYPAIR INTEGER NOT NULL, "
                                                     "SIGNATURE BLOB NOT NULL, "
                                                     "TTL INTEGER NOT NULL, "
                                                     "FOREIGN KEY(KEYPAIR) REFERENCES KEYPAIR(ID));";

static const char *DROP_TABLE_ONETIME_PRE_KEYPAIR = "DROP TABLE IF EXISTS ONETIME_PRE_KEYPAIR;";
static const char *ONETIME_PRE_KEYPAIR_CREATE_TABLE = "CREATE TABLE ONETIME_PRE_KEYPAIR(  "
                                                      "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                      "OPK_ID INTEGER NOT NULL, "
                                                      "USED INTEGER NOT NULL, "
                                                      "KEYPAIR INTEGER NOT NULL, "
                                                      "FOREIGN KEY(KEYPAIR) REFERENCES KEYPAIR(ID));";

static const char *DROP_TABLE_ACCOUNT = "DROP TABLE IF EXISTS ACCOUNT;";
static const char *ACCOUNT_CREATE_TABLE = "CREATE TABLE ACCOUNT( "
                                          "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
                                          "ACCOUNT_ID BLOB UNIQUE, "
                                          "VERSION INTEGER NOT NULL, "
                                          "SAVED INTEGER NOT NULL, "
                                          "ADDRESS INTEGER NOT NULL, "
                                          "IDENTITY_KEYPAIR INTEGER NOT NULL, "
                                          "SIGNED_PRE_KEYPAIR INTEGER NOT NULL, "
                                          "NEXT_SIGNED_PRE_KEY_ID INTEGER NOT NULL, "
                                          "NEXT_ONETIME_PRE_KEY_ID INTEGER NOT NULL, "
                                          "FOREIGN KEY(ADDRESS) REFERENCES ADDRESS(ID), "
                                          "FOREIGN KEY(IDENTITY_KEYPAIR) REFERENCES KEYPAIR(ID), "
                                          "FOREIGN KEY(SIGNED_PRE_KEYPAIR) REFERENCES SIGNED_PRE_KEYPAIR(ID));";

static const char *ACCOUNT_SIGNED_PRE_KEYPAIR_DROP_TABLE = "DROP TABLE IF EXISTS ACCOUNT_SIGNED_PRE_KEYPAIR;";
static const char *ACCOUNT_SIGNED_PRE_KEYPAIR_CREATE_TABLE =
    "CREATE TABLE ACCOUNT_SIGNED_PRE_KEYPAIR( "
    "ACCOUNT INTEGER NOT NULL, "
    "SIGNED_PRE_KEYPAIR INTEGER NOT NULL, "
    "FOREIGN KEY(ACCOUNT) REFERENCES ACCOUNT(ID), "
    "FOREIGN KEY(SIGNED_PRE_KEYPAIR) REFERENCES SIGNED_PRE_KEYPAIR(ID));";

static const char *ACCOUNT_ONETIME_PRE_KEYPAIR_DROP_TABLE = "DROP TABLE IF EXISTS ACCOUNT_ONETIME_PRE_KEYPAIR;";
static const char *ACCOUNT_ONETIME_PRE_KEYPAIR_CREATE_TABLE =
    "CREATE TABLE ACCOUNT_ONETIME_PRE_KEYPAIR( "
    "ACCOUNT INTEGER NOT NULL, "
    "ONETIME_PRE_KEYPAIR INTEGER NOT NULL, "
    "FOREIGN KEY(ACCOUNT) REFERENCES ACCOUNT(ID), "
    "FOREIGN KEY(ONETIME_PRE_KEYPAIR) REFERENCES ONETIME_PRE_KEYPAIR(ID));";

static const char *ACCOUNTS_NUM = "SELECT COUNT(*) FROM ACCOUNT;";

static const char *ACCOUNT_LOAD_ID = "SELECT ID "
                                     "FROM ACCOUNT "
                                     "WHERE ACCOUNT_ID = (?);";

static const char *ACCOUNT_LOAD_FIRST_ACCOUNT_ID = "SELECT ACCOUNT_ID "
                                                   "FROM ACCOUNT "
                                                   "WHERE ID = 1;";

static const char *ACCOUNT_LOAD_ALL_ACCOUNT_IDS = "SELECT ACCOUNT_ID FROM ACCOUNT;";

static const char *ACCOUNT_LOAD_VERSION = "SELECT VERSION "
                                          "FROM ACCOUNT "
                                          "WHERE ACCOUNT_ID = (?);";

static const char *ACCOUNT_LOAD_SAVED = "SELECT SAVED "
                                        "FROM ACCOUNT "
                                        "WHERE ACCOUNT.ACCOUNT_ID = (?);";

static const char *ACCOUNT_LOAD_ADDRESS = "SELECT "
                                          "ADDRESS.USER_ID, "
                                          "ADDRESS.DOMAIN, "
                                          "ADDRESS.DEVICE_ID "
                                          "FROM ACCOUNT "
                                          "INNER JOIN ADDRESS "
                                          "ON ACCOUNT.ADDRESS = ADDRESS.ID "
                                          "WHERE ACCOUNT.ACCOUNT_ID = (?);";

static const char *ACCOUNT_LOAD_KEYPAIR = "SELECT KEYPAIR.PUBLIC_KEY, "
                                          "KEYPAIR.PRIVATE_KEY "
                                          "FROM ACCOUNT "
                                          "INNER JOIN KEYPAIR "
                                          "ON ACCOUNT.IDENTITY_KEYPAIR = KEYPAIR.ID "
                                          "WHERE ACCOUNT.ACCOUNT_ID = (?);";

static const char *ACCOUNT_LOAD_SINGED_PRE_KEYPAIR = "SELECT SIGNED_PRE_KEYPAIR.SPK_ID, "
                                                     "KEYPAIR.PUBLIC_KEY, "
                                                     "KEYPAIR.PRIVATE_KEY, "
                                                     "SIGNED_PRE_KEYPAIR.SIGNATURE, "
                                                     "SIGNED_PRE_KEYPAIR.TTL "
                                                     "FROM ACCOUNT "
                                                     "INNER JOIN SIGNED_PRE_KEYPAIR "
                                                     "ON ACCOUNT.SIGNED_PRE_KEYPAIR = SIGNED_PRE_KEYPAIR.ID "
                                                     "INNER JOIN KEYPAIR "
                                                     "ON SIGNED_PRE_KEYPAIR.KEYPAIR = KEYPAIR.ID "
                                                     "WHERE ACCOUNT.ACCOUNT_ID = (?)";

static const char *ACCOUNT_LOAD_N_ONETIME_PRE_KEYPAIRS = "SELECT COUNT(*) "
                                                         "FROM ACCOUNT_ONETIME_PRE_KEYPAIR "
                                                         "INNER JOIN ACCOUNT "
                                                         "ON ACCOUNT_ONETIME_PRE_KEYPAIR.ACCOUNT = ACCOUNT.ID "
                                                         "WHERE ACCOUNT.ACCOUNT_ID = (?);";

static const char *ACCOUNT_LOAD_ONETIME_PRE_KEYPAIRS = "SELECT ONETIME_PRE_KEYPAIR.OPK_ID, "
                                                       "ONETIME_PRE_KEYPAIR.USED, "
                                                       "KEYPAIR.PUBLIC_KEY, "
                                                       "KEYPAIR.PRIVATE_KEY "
                                                       "FROM ACCOUNT_ONETIME_PRE_KEYPAIR "
                                                       "INNER JOIN ACCOUNT "
                                                       "ON ACCOUNT_ONETIME_PRE_KEYPAIR.ACCOUNT = ACCOUNT.ID "
                                                       "INNER JOIN ONETIME_PRE_KEYPAIR "
                                                       "ON ACCOUNT_ONETIME_PRE_KEYPAIR.ONETIME_PRE_KEYPAIR = "
                                                       "ONETIME_PRE_KEYPAIR.ID "
                                                       "INNER JOIN KEYPAIR "
                                                       "ON ONETIME_PRE_KEYPAIR.KEYPAIR = KEYPAIR.ID "
                                                       "WHERE ACCOUNT.ACCOUNT_ID = (?);";

static const char *ACCOUNT_LOAD_ONETIME_PRE_KEYPAIR = "SELECT ONETIME_PRE_KEYPAIR.ID "
                                                      "FROM ACCOUNT_ONETIME_PRE_KEYPAIR "
                                                      "INNER JOIN ACCOUNT "
                                                      "ON ACCOUNT_ONETIME_PRE_KEYPAIR.ACCOUNT = ACCOUNT.ID "
                                                      "INNER JOIN ONETIME_PRE_KEYPAIR "
                                                      "ON ACCOUNT_ONETIME_PRE_KEYPAIR.ONETIME_PRE_KEYPAIR = "
                                                      "ONETIME_PRE_KEYPAIR.ID "
                                                      "WHERE ACCOUNT.ACCOUNT_ID = (?) AND ONETIME_PRE_KEYPAIR.OPK_ID = (?);";

static const char *ACCOUNT_LOAD_NEXT_SIGNED_PRE_KEYPAIR_ID = "SELECT NEXT_SIGNED_PRE_KEY_ID "
                                                             "FROM ACCOUNT "
                                                             "WHERE ACCOUNT_ID = (?);";

static const char *ACCOUNT_LOAD_NEXT_ONETIME_PRE_KEYPAIR_ID = "SELECT NEXT_ONETIME_PRE_KEY_ID "
                                                              "FROM ACCOUNT "
                                                              "WHERE ACCOUNT_ID = (?);";

static const char *LOAD_ACCOUNT_ID_BY_ADDRESS = "SELECT ACCOUNT_ID "
                                                "FROM ACCOUNT "
                                                "INNER JOIN ADDRESS "
                                                "ON ACCOUNT.ADDRESS = ADDRESS.ID "
                                                "WHERE ADDRESS.USER_ID = (?);";

static const char *ADDRESS_INSERT = "INSERT INTO ADDRESS "
                                    "(USER_ID, DOMAIN, DEVICE_ID, GROUP_ID) "
                                    "VALUES (?, ?, ?, ?);";

static const char *SIGNED_PRE_KEYPAIR_INSERT = "INSERT INTO SIGNED_PRE_KEYPAIR "
                                               "(SPK_ID, KEYPAIR, SIGNATURE, TTL) "
                                               "VALUES (?, ?, ?, ?);";

static const char *SIGNED_PRE_KEYPAIR_DELETE = "DELETE FROM SIGNED_PRE_KEYPAIR "
                                               "WHERE ID = (?);";

static const char *KEYPAIR_INSERT = "INSERT INTO KEYPAIR "
                                    "(PUBLIC_KEY, PRIVATE_KEY) "
                                    "VALUES (?, ?);";
static const char *ONETIME_PRE_KEYPAIR_INSERT = "INSERT INTO ONETIME_PRE_KEYPAIR "
                                                "(OPK_ID, USED, KEYPAIR) "
                                                "VALUES (?, ?, ?);";

static const char *ONETIME_PRE_KEYPAIR_DELETE = "DELETE FROM ONETIME_PRE_KEYPAIR "
                                                "WHERE ID = (?);";

static const char *ACCOUNT_INSERT = "INSERT INTO ACCOUNT "
                                    "(ACCOUNT_ID, "
                                    "VERSION, "
                                    "SAVED, "
                                    "ADDRESS, "
                                    "IDENTITY_KEYPAIR, "
                                    "SIGNED_PRE_KEYPAIR, "
                                    "NEXT_SIGNED_PRE_KEY_ID, "
                                    "NEXT_ONETIME_PRE_KEY_ID) "
                                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";

static const char *ACCOUNT_SIGNED_PRE_KEYPAIR_INSERT = "INSERT INTO ACCOUNT_SIGNED_PRE_KEYPAIR "
                                                       "(ACCOUNT, SIGNED_PRE_KEYPAIR) "
                                                       "VALUES (?, ?);";

static const char *ACCOUNT_SIGNED_PRE_KEYPAIR_DELETE = "DELETE FROM ACCOUNT_SIGNED_PRE_KEYPAIR "
                                                       "WHERE ACCOUNT = (?) AND SIGNED_PRE_KEYPAIR = (?);";

static const char *ACCOUNT_SIGNED_PRE_KEYPAIR_SELECT_MORE_THAN_2 = "SELECT SIGNED_PRE_KEYPAIR "
                                               "FROM ACCOUNT_SIGNED_PRE_KEYPAIR "
                                               "WHERE ACCOUNT = (?) AND "
                                               "(SIGNED_PRE_KEYPAIR < ((SELECT MAX(SIGNED_PRE_KEYPAIR) FROM ACCOUNT_SIGNED_PRE_KEYPAIR) - 1));";

static const char *ACCOUNT_ONETIME_PRE_KEYPAIR_INSERT = "INSERT INTO ACCOUNT_ONETIME_PRE_KEYPAIR "
                                                        "(ACCOUNT, ONETIME_PRE_KEYPAIR) "
                                                        "VALUES (?, ?);";

static const char *ACCOUNT_ONETIME_PRE_KEYPAIR_DELETE = "DELETE FROM ACCOUNT_ONETIME_PRE_KEYPAIR "
                                                        "WHERE ACCOUNT = (?) AND ONETIME_PRE_KEYPAIR = (?);";

static const char *ACCOUNT_UPDATE_ADDRESS = "UPDATE ACCOUNT "
                                            "SET ADDRESS = (?) "
                                            "WHERE ACCOUNT_ID = (?);";

static const char *ACCOUNT_UPDATE_SIGNED_PRE_KEYPAIR = "UPDATE ACCOUNT "
                                                       "SET SIGNED_PRE_KEYPAIR = (?) "
                                                       "WHERE ACCOUNT_ID = (?);";

static const char *LOAD_OLD_SIGNED_PRE_KEYPAIR = "SELECT SIGNED_PRE_KEYPAIR.SPK_ID, "
                                                 "KEYPAIR.PUBLIC_KEY, "
                                                 "KEYPAIR.PRIVATE_KEY, "
                                                 "SIGNED_PRE_KEYPAIR.SIGNATURE, "
                                                 "SIGNED_PRE_KEYPAIR.TTL "
                                                 "FROM ACCOUNT_SIGNED_PRE_KEYPAIR "
                                                 "INNER JOIN ACCOUNT "
                                                 "ON ACCOUNT_SIGNED_PRE_KEYPAIR.ACCOUNT = ACCOUNT.ID "
                                                 "INNER JOIN SIGNED_PRE_KEYPAIR "
                                                 "ON ACCOUNT_SIGNED_PRE_KEYPAIR.SIGNED_PRE_KEYPAIR = SIGNED_PRE_KEYPAIR.ID "
                                                 "INNER JOIN KEYPAIR "
                                                 "ON SIGNED_PRE_KEYPAIR.KEYPAIR = KEYPAIR.ID "
                                                 "WHERE ACCOUNT.ACCOUNT_ID = (?) AND SIGNED_PRE_KEYPAIR.SPK_ID = (?);";

static const char *ACCOUNT_UPDATE_IDENTITY_KEYPAIR = "UPDATE ACCOUNT "
                                                     "SET IDENTITY_KEYPAIR = (?) "
                                                     "WHERE ACCOUNT_ID = (?);";

static const char *ONETIME_PRE_KEYPAIR_UPDATE_USED = "UPDATE ONETIME_PRE_KEYPAIR "
                                                     "SET USED = 1 "
                                                     "WHERE ID = (?);";

void test_db_begin() {
    // connect
    sqlite_connect(db_name);

    // session
    sqlite_execute(SESSION_DROP_TABLE);
    sqlite_execute(SESSION_CREATE_TABLE);

    // group_session
    sqlite_execute(GROUP_SESSION_DROP_TABLE);
    sqlite_execute(GROUP_SESSION_CREATE_TABLE);

    // address
    sqlite_execute(ADDRESS_DROP_TABLE);
    sqlite_execute(ADDRESS_CREATE_TABLE);

    // key pair
    sqlite_execute(KEYPAIR_DROP_TABLE);
    sqlite_execute(KEYPAIR_CREATE_TABLE);

    // signed_pre_key_pair
    sqlite_execute(SIGNED_PRE_KEYPAIR_DROP_TABLE);
    sqlite_execute(SIGNED_PRE_KEYPAIR_CREATE_TABLE);

    // one_time_pre_key_pair
    sqlite_execute(DROP_TABLE_ONETIME_PRE_KEYPAIR);
    sqlite_execute(ONETIME_PRE_KEYPAIR_CREATE_TABLE);

    // account
    sqlite_execute(DROP_TABLE_ACCOUNT);
    sqlite_execute(ACCOUNT_CREATE_TABLE);

    // account_signed_pre_key_pair
    sqlite_execute(ACCOUNT_SIGNED_PRE_KEYPAIR_DROP_TABLE);
    sqlite_execute(ACCOUNT_SIGNED_PRE_KEYPAIR_CREATE_TABLE);

    // account_one_time_pre_key_pair
    sqlite_execute(ACCOUNT_ONETIME_PRE_KEYPAIR_DROP_TABLE);
    sqlite_execute(ACCOUNT_ONETIME_PRE_KEYPAIR_CREATE_TABLE);
}

void test_db_end() { sqlite3_close(db); }

// this function is using for real user to take their id
void load_id(ProtobufCBinaryData **account_id) {
    // allocate memory
    *account_id = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_FIRST_ACCOUNT_ID, &stmt);

    // step
    sqlite_step(stmt, SQLITE_ROW);
    (*account_id)->len = sqlite3_column_bytes(stmt, 0);
    (*account_id)->data = (uint8_t *)sqlite3_column_blob(stmt, 0);

    // release
    sqlite3_finalize(stmt);
}

size_t load_ids(ProtobufCBinaryData ***account_ids) {
    // find num of account_ids
    // prepare
    sqlite3_stmt *stmt1;
    sqlite_prepare(ACCOUNTS_NUM, &stmt1);
    // step
    sqlite_step(stmt1, SQLITE_ROW);
    size_t num = (size_t)sqlite3_column_int64(stmt1, 0);
    // release
    sqlite3_finalize(stmt1);

    if (num == 0) {
        *account_ids = NULL;
        return num;
    }

    // allocate memory
    *account_ids = (ProtobufCBinaryData **)malloc(sizeof(ProtobufCBinaryData *) * num);

    // prepare
    sqlite3_stmt *stmt2;
    sqlite_prepare(ACCOUNT_LOAD_ALL_ACCOUNT_IDS, &stmt2);
    // step
    int i = 0;
    while (sqlite3_step(stmt2) != SQLITE_DONE) {
        (*account_ids)[i] = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
        ((*account_ids)[i])->len = sqlite3_column_bytes(stmt2, 0);
        ((*account_ids)[i])->data = (uint8_t *)sqlite3_column_blob(stmt2, 0);
    }
    // release
    sqlite3_finalize(stmt2);

    // done
    return num;
}

uint32_t load_version(ProtobufCBinaryData *account_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_VERSION, &stmt);
    sqlite3_bind_blob(stmt, 1, (const char *)account_id->data, account_id->len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    uint32_t version = (uint32_t)sqlite3_column_int(stmt, 0);

    // release
    sqlite3_finalize(stmt);

    return version;
}

protobuf_c_boolean load_saved(ProtobufCBinaryData *account_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_SAVED, &stmt);
    sqlite3_bind_blob(stmt, 1, (const char *)account_id->data, account_id->len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    protobuf_c_boolean saved = (protobuf_c_boolean)sqlite3_column_int(stmt, 0);

    // release
    sqlite3_finalize(stmt);

    return saved;
}

void load_address(ProtobufCBinaryData *account_id, Org__E2eelab__Skissm__Proto__E2eeAddress **address) {
    // allocate memory
    *address = (Org__E2eelab__Skissm__Proto__E2eeAddress *)malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAddress));
    org__e2eelab__skissm__proto__e2ee_address__init(*address);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_ADDRESS, &stmt);
    sqlite3_bind_blob(stmt, 1, (const uint8_t *)account_id->data, account_id->len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    copy_protobuf_from_array(&((*address)->user_id), (uint8_t *)sqlite3_column_blob(stmt, 0),
                             sqlite3_column_bytes(stmt, 0));
    copy_protobuf_from_array(&((*address)->domain), (uint8_t *)sqlite3_column_blob(stmt, 1),
                             sqlite3_column_bytes(stmt, 1));
    copy_protobuf_from_array(&((*address)->device_id), (uint8_t *)sqlite3_column_blob(stmt, 2),
                             sqlite3_column_bytes(stmt, 2));

    // release
    sqlite3_finalize(stmt);
}

static sqlite_int64 load_account_id(ProtobufCBinaryData *account_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_ID, &stmt);
    sqlite3_bind_blob(stmt, 1, (const uint8_t *)account_id->data, account_id->len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_ROW);
    sqlite_int64 id = sqlite3_column_int(stmt, 0);

    // release
    sqlite3_finalize(stmt);

    // done
    return id;
}

void load_identity_key_pair(ProtobufCBinaryData *account_id, Org__E2eelab__Skissm__Proto__KeyPair **identity_key_pair) {
    // allocate memory
    *identity_key_pair = (Org__E2eelab__Skissm__Proto__KeyPair *)malloc(sizeof(Org__E2eelab__Skissm__Proto__KeyPair));
    org__e2eelab__skissm__proto__key_pair__init(*identity_key_pair);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_KEYPAIR, &stmt);
    sqlite3_bind_blob(stmt, 1, (const char *)account_id->data, account_id->len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    copy_protobuf_from_array(&((*identity_key_pair)->public_key), (uint8_t *)sqlite3_column_blob(stmt, 0),
                             sqlite3_column_bytes(stmt, 0));
    copy_protobuf_from_array(&((*identity_key_pair)->private_key), (uint8_t *)sqlite3_column_blob(stmt, 1),
                             sqlite3_column_bytes(stmt, 1));

    // release
    sqlite3_finalize(stmt);
}

void load_signed_pre_key_pair(ProtobufCBinaryData *account_id,
                              Org__E2eelab__Skissm__Proto__SignedPreKeyPair **signed_pre_key_pair) {
    // allocate memory
    *signed_pre_key_pair =
        (Org__E2eelab__Skissm__Proto__SignedPreKeyPair *)malloc(sizeof(Org__E2eelab__Skissm__Proto__SignedPreKeyPair));
    org__e2eelab__skissm__proto__signed_pre_key_pair__init(*signed_pre_key_pair);

    Org__E2eelab__Skissm__Proto__KeyPair *key_pair =
        (Org__E2eelab__Skissm__Proto__KeyPair *)malloc(sizeof(Org__E2eelab__Skissm__Proto__KeyPair));
    org__e2eelab__skissm__proto__key_pair__init(key_pair);
    (*signed_pre_key_pair)->key_pair = key_pair;

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_SINGED_PRE_KEYPAIR, &stmt);
    sqlite3_bind_blob(stmt, 1, (const char *)account_id->data, account_id->len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    (*signed_pre_key_pair)->spk_id = (uint32_t)sqlite3_column_int(stmt, 0);
    copy_protobuf_from_array(&((*signed_pre_key_pair)->key_pair->public_key), (uint8_t *)sqlite3_column_blob(stmt, 1),
                             sqlite3_column_bytes(stmt, 1));
    copy_protobuf_from_array(&((*signed_pre_key_pair)->key_pair->private_key), (uint8_t *)sqlite3_column_blob(stmt, 2),
                             sqlite3_column_bytes(stmt, 2));
    copy_protobuf_from_array(&((*signed_pre_key_pair)->signature), (uint8_t *)sqlite3_column_blob(stmt, 3),
                             sqlite3_column_bytes(stmt, 3));
    (*signed_pre_key_pair)->ttl = (uint64_t)sqlite3_column_int(stmt, 4);

    // release
    sqlite3_finalize(stmt);
}

int load_n_one_time_pre_keys(ProtobufCBinaryData *account_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_N_ONETIME_PRE_KEYPAIRS, &stmt);
    sqlite3_bind_blob(stmt, 1, (const char *)account_id->data, account_id->len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    int n_one_time_pre_keys = (int)sqlite3_column_int(stmt, 0);

    // release
    sqlite3_finalize(stmt);

    return n_one_time_pre_keys;
}

uint32_t load_one_time_pre_keys(ProtobufCBinaryData *account_id,
                                Org__E2eelab__Skissm__Proto__OneTimePreKeyPair ***one_time_pre_keys) {
    // allocate memory
    size_t n_one_time_pre_keys = load_n_one_time_pre_keys(account_id);
    (*one_time_pre_keys) = (Org__E2eelab__Skissm__Proto__OneTimePreKeyPair **)malloc(
        n_one_time_pre_keys * sizeof(Org__E2eelab__Skissm__Proto__OneTimePreKeyPair *));

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_ONETIME_PRE_KEYPAIRS, &stmt);
    sqlite3_bind_blob(stmt, 1, (const char *)account_id->data, account_id->len, SQLITE_STATIC);

    // step
    for (int i = 0; i < n_one_time_pre_keys; i++) {
        sqlite3_step(stmt);

        // allocate
        (*one_time_pre_keys)[i] = (Org__E2eelab__Skissm__Proto__OneTimePreKeyPair *)malloc(
            sizeof(Org__E2eelab__Skissm__Proto__OneTimePreKeyPair));
        org__e2eelab__skissm__proto__one_time_pre_key_pair__init((*one_time_pre_keys)[i]);

        Org__E2eelab__Skissm__Proto__KeyPair *key_pair =
            (Org__E2eelab__Skissm__Proto__KeyPair *)malloc(sizeof(Org__E2eelab__Skissm__Proto__KeyPair));
        org__e2eelab__skissm__proto__key_pair__init(key_pair);
        (*one_time_pre_keys)[i]->key_pair = key_pair;

        // load
        (*one_time_pre_keys)[i]->opk_id = (uint32_t)sqlite3_column_int(stmt, 0);
        (*one_time_pre_keys)[i]->used = sqlite3_column_int(stmt, 1);
        copy_protobuf_from_array(&((*one_time_pre_keys)[i]->key_pair->public_key),
                                 (uint8_t *)sqlite3_column_blob(stmt, 2), sqlite3_column_bytes(stmt, 2));
        copy_protobuf_from_array(&((*one_time_pre_keys)[i]->key_pair->private_key),
                                 (uint8_t *)sqlite3_column_blob(stmt, 3), sqlite3_column_bytes(stmt, 3));
    }

    // release
    sqlite3_finalize(stmt);

    return n_one_time_pre_keys;
}

uint32_t load_next_signed_pre_key_id(ProtobufCBinaryData *account_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_NEXT_SIGNED_PRE_KEYPAIR_ID, &stmt);
    sqlite3_bind_blob(stmt, 1, (const char *)account_id->data, account_id->len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    uint32_t next_signed_pre_key_id = (uint32_t)sqlite3_column_int(stmt, 0);

    // release
    sqlite3_finalize(stmt);

    return next_signed_pre_key_id;
}

uint32_t load_next_one_time_pre_key_id(ProtobufCBinaryData *account_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_NEXT_ONETIME_PRE_KEYPAIR_ID, &stmt);
    sqlite3_bind_blob(stmt, 1, (const char *)account_id->data, account_id->len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    uint32_t next_one_time_pre_key_id = (uint32_t)sqlite3_column_int(stmt, 0);

    // release
    sqlite3_finalize(stmt);

    return next_one_time_pre_key_id;
}

void load_id_by_address(Org__E2eelab__Skissm__Proto__E2eeAddress *address, ProtobufCBinaryData **account_id) {
    // allocate memory
    *account_id = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(LOAD_ACCOUNT_ID_BY_ADDRESS, &stmt);
    sqlite3_bind_blob(stmt, 1, address->user_id.data, address->user_id.len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    copy_protobuf_from_array(*account_id, (uint8_t *)sqlite3_column_blob(stmt, 0), sqlite3_column_bytes(stmt, 0));

    // release
    sqlite3_finalize(stmt);
}

sqlite_int64 insert_address(Org__E2eelab__Skissm__Proto__E2eeAddress *address) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ADDRESS_INSERT, &stmt);

    // bind
    sqlite3_bind_blob(stmt, 1, address->user_id.data, address->user_id.len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, address->domain.data, address->domain.len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, address->device_id.data, address->device_id.len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, address->group_id.data, address->group_id.len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite3_finalize(stmt);

    return sqlite3_last_insert_rowid(db);
}

sqlite_int64 insert_key_pair(Org__E2eelab__Skissm__Proto__KeyPair *key_pair) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(KEYPAIR_INSERT, &stmt);

    // bind
    sqlite3_bind_blob(stmt, 1, key_pair->public_key.data, key_pair->public_key.len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, key_pair->private_key.data, key_pair->private_key.len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite3_finalize(stmt);

    return sqlite3_last_insert_rowid(db);
}

sqlite_int64 insert_signed_pre_key(Org__E2eelab__Skissm__Proto__SignedPreKeyPair *signed_pre_key) {
    sqlite_int64 key_pair_id = insert_key_pair(signed_pre_key->key_pair);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(SIGNED_PRE_KEYPAIR_INSERT, &stmt);

    // bind
    sqlite3_bind_int(stmt, 1, signed_pre_key->spk_id);
    sqlite3_bind_int(stmt, 2, key_pair_id);
    sqlite3_bind_blob(stmt, 3, signed_pre_key->signature.data, signed_pre_key->signature.len, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, signed_pre_key->ttl);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite3_finalize(stmt);

    return sqlite3_last_insert_rowid(db);
}

sqlite_int64 insert_one_time_pre_key(Org__E2eelab__Skissm__Proto__OneTimePreKeyPair *one_time_pre_key) {
    sqlite_int64 key_pair_id = insert_key_pair(one_time_pre_key->key_pair);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ONETIME_PRE_KEYPAIR_INSERT, &stmt);

    // bind
    sqlite3_bind_int(stmt, 1, one_time_pre_key->opk_id);
    sqlite3_bind_int(stmt, 2, one_time_pre_key->used);
    sqlite3_bind_int(stmt, 3, key_pair_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite3_finalize(stmt);

    return sqlite3_last_insert_rowid(db);
}

sqlite_int64 insert_account(ProtobufCBinaryData *account_id, int version, protobuf_c_boolean saved,
                            sqlite_int64 address_id, sqlite_int64 identity_key_pair_id, sqlite_int64 signed_pre_key_id,
                            sqlite_int64 next_signed_pre_key_id, sqlite_int64 next_one_time_pre_key_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_INSERT, &stmt);

    // bind
    sqlite3_bind_blob(stmt, 1, (const char *)account_id->data, account_id->len, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, version);
    sqlite3_bind_int(stmt, 3, (int)saved);
    sqlite3_bind_int(stmt, 4, address_id);
    sqlite3_bind_int(stmt, 5, identity_key_pair_id);
    sqlite3_bind_int(stmt, 6, signed_pre_key_id);
    sqlite3_bind_int(stmt, 7, next_signed_pre_key_id);
    sqlite3_bind_int(stmt, 8, next_one_time_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite3_finalize(stmt);

    return sqlite3_last_insert_rowid(db);
}

void insert_account_signed_pre_key_id(sqlite_int64 account_id, sqlite_int64 signed_pre_key_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_SIGNED_PRE_KEYPAIR_INSERT, &stmt);

    // bind
    sqlite3_bind_int(stmt, 1, account_id);
    sqlite3_bind_int(stmt, 2, signed_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite3_finalize(stmt);
}

void insert_account_one_time_pre_key_id(sqlite_int64 account_id, sqlite_int64 one_time_pre_key_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_ONETIME_PRE_KEYPAIR_INSERT, &stmt);

    // bind
    sqlite3_bind_int(stmt, 1, account_id);
    sqlite3_bind_int(stmt, 2, one_time_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite3_finalize(stmt);
}

void update_identity_key(ProtobufCBinaryData *account_id,
                         Org__E2eelab__Skissm__Proto__KeyPair *identity_key_pair) {
    int key_pair_id = insert_key_pair(identity_key_pair);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_UPDATE_IDENTITY_KEYPAIR, &stmt);

    // bind
    sqlite3_bind_int(stmt, 1, key_pair_id);
    sqlite3_bind_blob(stmt, 2, account_id->data, account_id->len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite3_finalize(stmt);
}

void update_signed_pre_key(ProtobufCBinaryData *account_id,
                           Org__E2eelab__Skissm__Proto__SignedPreKeyPair *signed_pre_key) {
    sqlite_int64 signed_pre_key_id = insert_signed_pre_key(signed_pre_key);

    sqlite_int64 id = load_account_id(account_id);

    insert_account_signed_pre_key_id(id, signed_pre_key_id);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_UPDATE_SIGNED_PRE_KEYPAIR, &stmt);

    // bind
    sqlite3_bind_int(stmt, 1, signed_pre_key_id);
    sqlite3_bind_blob(stmt, 2, (const char *)account_id->data, account_id->len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite3_finalize(stmt);
}

void load_old_signed_pre_key(ProtobufCBinaryData *account_id, uint32_t spk_id,
                             Org__E2eelab__Skissm__Proto__SignedPreKeyPair **signed_pre_key_pair) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(LOAD_OLD_SIGNED_PRE_KEYPAIR, &stmt);
    sqlite3_bind_blob(stmt, 1, account_id->data, account_id->len, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, spk_id);

    // step
    if (!sqlite_step(stmt, SQLITE_ROW)) {
        *signed_pre_key_pair = NULL;
        sqlite3_finalize(stmt);
        return;
    }

    // allocate memory
    *signed_pre_key_pair =
        (Org__E2eelab__Skissm__Proto__SignedPreKeyPair *)malloc(sizeof(Org__E2eelab__Skissm__Proto__SignedPreKeyPair));
    org__e2eelab__skissm__proto__signed_pre_key_pair__init(*signed_pre_key_pair);

    Org__E2eelab__Skissm__Proto__KeyPair *key_pair =
        (Org__E2eelab__Skissm__Proto__KeyPair *)malloc(sizeof(Org__E2eelab__Skissm__Proto__KeyPair));
    org__e2eelab__skissm__proto__key_pair__init(key_pair);
    (*signed_pre_key_pair)->key_pair = key_pair;

    // load
    (*signed_pre_key_pair)->spk_id = (uint32_t)sqlite3_column_int(stmt, 0);
    copy_protobuf_from_array(&((*signed_pre_key_pair)->key_pair->public_key), (uint8_t *)sqlite3_column_blob(stmt, 1),
                             sqlite3_column_bytes(stmt, 1));
    copy_protobuf_from_array(&((*signed_pre_key_pair)->key_pair->private_key), (uint8_t *)sqlite3_column_blob(stmt, 2),
                             sqlite3_column_bytes(stmt, 2));
    copy_protobuf_from_array(&((*signed_pre_key_pair)->signature), (uint8_t *)sqlite3_column_blob(stmt, 3),
                             sqlite3_column_bytes(stmt, 3));
    (*signed_pre_key_pair)->ttl = (uint64_t)sqlite3_column_int(stmt, 4);

    // release
    sqlite3_finalize(stmt);
}

static void delete_signed_pre_key(sqlite_int64 signed_pre_key_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(SIGNED_PRE_KEYPAIR_DELETE, &stmt);
    sqlite3_bind_int(stmt, 1, signed_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite3_finalize(stmt);
}

static void delete_account_signed_pre_key(sqlite_int64 account_id, sqlite_int64 signed_pre_key_id){
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_SIGNED_PRE_KEYPAIR_DELETE, &stmt);
    sqlite3_bind_int(stmt, 1, account_id);
    sqlite3_bind_int(stmt, 2, signed_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite3_finalize(stmt);
}

void remove_expired_signed_pre_key(ProtobufCBinaryData *account_id) {
    // delete old signed pre keys and keep last two
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_SIGNED_PRE_KEYPAIR_SELECT_MORE_THAN_2, &stmt);
    sqlite_int64 id = load_account_id(account_id);
    sqlite3_bind_int(stmt, 1, id);

    // step
    while (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite_int64 signed_pre_key_id = sqlite3_column_int(stmt, 0);
        delete_signed_pre_key(signed_pre_key_id);
        delete_account_signed_pre_key(id, signed_pre_key_id);
    }

    // release
    sqlite3_finalize(stmt);
}

void update_address(ProtobufCBinaryData *account_id,
                    Org__E2eelab__Skissm__Proto__E2eeAddress *address) {
    int address_id = insert_address(address);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_UPDATE_ADDRESS, &stmt);

    // bind
    sqlite3_bind_int(stmt, 1, address_id);
    sqlite3_bind_blob(stmt, 2, account_id->data, account_id->len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite3_finalize(stmt);
}

void add_one_time_pre_key(ProtobufCBinaryData *account_id,
                          Org__E2eelab__Skissm__Proto__OneTimePreKeyPair *one_time_pre_key) {
    int one_time_pre_key_id = insert_one_time_pre_key(one_time_pre_key);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_ONETIME_PRE_KEYPAIR_INSERT, &stmt);

    // bind
    sqlite3_bind_blob(stmt, 1, account_id->data, account_id->len, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, one_time_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite3_finalize(stmt);
}

static void delete_one_time_pre_key(sqlite_int64 one_time_pre_key_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ONETIME_PRE_KEYPAIR_DELETE, &stmt);
    sqlite3_bind_int(stmt, 1, one_time_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite3_finalize(stmt);
}

static void delete_account_one_time_pre_key(sqlite_int64 account_id, sqlite_int64 one_time_pre_key_id){
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_ONETIME_PRE_KEYPAIR_DELETE, &stmt);
    sqlite3_bind_int(stmt, 1, account_id);
    sqlite3_bind_int(stmt, 2, one_time_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite3_finalize(stmt);
}

void remove_one_time_pre_key(ProtobufCBinaryData *account_id, uint32_t one_time_pre_key_id){
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_ONETIME_PRE_KEYPAIR, &stmt);
    sqlite_int64 a_id = load_account_id(account_id);

    // bind
    sqlite3_bind_blob(stmt, 1, account_id->data, account_id->len, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, one_time_pre_key_id);

    // step
    if ((sqlite3_step(stmt) != SQLITE_DONE)){
        sqlite_int64 id = sqlite3_column_int(stmt, 0);
        delete_one_time_pre_key(id);
        delete_account_one_time_pre_key(a_id, id);
    }

    // release
    sqlite3_finalize(stmt);
}

static void mark_one_time_pre_key_as_used(sqlite_int64 one_time_pre_key_id){
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ONETIME_PRE_KEYPAIR_UPDATE_USED, &stmt);

    // bind
    sqlite3_bind_int(stmt, 1, one_time_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite3_finalize(stmt);
}

void update_one_time_pre_key(ProtobufCBinaryData *account_id, uint32_t one_time_pre_key_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_ONETIME_PRE_KEYPAIR, &stmt);

    // bind
    sqlite3_bind_blob(stmt, 1, account_id->data, account_id->len, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, one_time_pre_key_id);

    // step
    if ((sqlite3_step(stmt) != SQLITE_DONE)){
        sqlite_int64 id = sqlite3_column_int(stmt, 0);
        mark_one_time_pre_key_as_used(id);
    }

    // release
    sqlite3_finalize(stmt);
}

// session related handlers
void load_inbound_session(ProtobufCBinaryData session_id, Org__E2eelab__Skissm__Proto__E2eeAddress *owner,
                          Org__E2eelab__Skissm__Proto__E2eeSession **session) {
    // prepare
    sqlite3_stmt *stmt;
    if (!sqlite_prepare(SESSION_LOAD_DATA_BY_ID_AND_OWNER, &stmt)) {
        *session = NULL;
        return;
    }

    // bind
    sqlite3_bind_blob(stmt, 1, session_id.data, session_id.len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, owner->user_id.data, owner->user_id.len, SQLITE_STATIC);

    // step
    if (!sqlite_step(stmt, SQLITE_ROW)) {
        *session = NULL;
        sqlite3_finalize(stmt);
        return;
    }

    // load
    size_t session_data_len = sqlite3_column_bytes(stmt, 0);
    uint8_t *session_data = (uint8_t *)sqlite3_column_blob(stmt, 0);

    // no data
    if (session_data_len == 0) {
        *session = NULL;
        sqlite3_finalize(stmt);
        return;
    }

    // unpack
    *session = org__e2eelab__skissm__proto__e2ee_session__unpack(NULL, session_data_len, session_data);

    // release
    sqlite3_finalize(stmt);

    return;
}

void store_session(Org__E2eelab__Skissm__Proto__E2eeSession *session) {
    // pack
    ProtobufCBinaryData session_id = session->session_id;
    size_t session_data_len = org__e2eelab__skissm__proto__e2ee_session__get_packed_size(session);
    uint8_t *session_data = (uint8_t *)malloc(session_data_len);
    org__e2eelab__skissm__proto__e2ee_session__pack(session, session_data);

    int owner_id = insert_address(session->session_owner);
    int from_id = insert_address(session->from);
    int to_id = insert_address(session->to);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(SESSION_INSERT_OR_REPLACE, &stmt);

    // bind
    sqlite3_bind_blob(stmt, 1, session_id.data, session_id.len, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, owner_id);
    sqlite3_bind_int(stmt, 3, from_id);
    sqlite3_bind_int(stmt, 4, to_id);
    sqlite3_bind_blob(stmt, 5, session_data, session_data_len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite3_finalize(stmt);
    free_mem((void **)(&session_data), session_data_len);
}

// return the lastest updated session
void load_outbound_session(Org__E2eelab__Skissm__Proto__E2eeAddress *owner,
                           Org__E2eelab__Skissm__Proto__E2eeAddress *to,
                           Org__E2eelab__Skissm__Proto__E2eeSession **session) {
    // prepare
    sqlite3_stmt *stmt;
    if (!sqlite_prepare(SESSION_LOAD_DATA_BY_OWNER_AND_TO, &stmt)) {
        *session = NULL;
        return;
    }

    // bind
    sqlite3_bind_blob(stmt, 1, owner->user_id.data, owner->user_id.len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, to->user_id.data, to->user_id.len, SQLITE_STATIC);

    // step
    if (!sqlite_step(stmt, SQLITE_ROW)) {
        *session = NULL;
        sqlite3_finalize(stmt);
        return;
    }

    // load
    size_t session_data_len = sqlite3_column_bytes(stmt, 0);
    uint8_t *session_data = (uint8_t *)sqlite3_column_blob(stmt, 0);

    // no data
    if (session_data_len == 0) {
        *session = NULL;
        sqlite3_finalize(stmt);
        return;
    }

    // unpack
    *session = org__e2eelab__skissm__proto__e2ee_session__unpack(NULL, session_data_len, session_data);

    // release
    sqlite3_finalize(stmt);

    return;
}

void unload_session(Org__E2eelab__Skissm__Proto__E2eeAddress *owner, Org__E2eelab__Skissm__Proto__E2eeAddress *from,
                    Org__E2eelab__Skissm__Proto__E2eeAddress *to) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(SESSION_DELETE_DATA_BY_OWNER_FROM_AND_TO, &stmt);

    // bind
    sqlite3_bind_blob(stmt, 1, owner->user_id.data, owner->user_id.len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, from->user_id.data, from->user_id.len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, to->user_id.data, to->user_id.len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite3_finalize(stmt);
}

// return the first signature which is not null
void load_outbound_group_session(Org__E2eelab__Skissm__Proto__E2eeAddress *sender_address,
                                 Org__E2eelab__Skissm__Proto__E2eeAddress *group_address,
                                 Org__E2eelab__Skissm__Proto__E2eeGroupSession **group_session) {
    // prepare
    sqlite3_stmt *stmt;
    if (!sqlite_prepare(GROUP_SESSION_LOAD_DATA_BY_OWNER_AND_ADDRESS, &stmt)) {
        *group_session = NULL;
        return;
    }

    // bind
    sqlite3_bind_blob(stmt, 1, sender_address->user_id.data, sender_address->user_id.len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, sender_address->domain.data, sender_address->domain.len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, sender_address->device_id.data, sender_address->device_id.len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, group_address->group_id.data, group_address->group_id.len, SQLITE_STATIC);

    // step
    if (!sqlite_step(stmt, SQLITE_ROW)) {
        *group_session = NULL;
        sqlite3_finalize(stmt);
        return;
    }

    // load
    size_t group_session_data_len = sqlite3_column_bytes(stmt, 0);
    uint8_t *group_session_data = (uint8_t *)sqlite3_column_blob(stmt, 0);

    // no data
    if (group_session_data_len == 0) {
        *group_session = NULL;
        sqlite3_finalize(stmt);
        return;
    }

    // unpack
    *group_session =
        org__e2eelab__skissm__proto__e2ee_group_session__unpack(NULL, group_session_data_len, group_session_data);

    // release
    sqlite3_finalize(stmt);

    return;
}

// signature_private_key is null
void load_inbound_group_session(ProtobufCBinaryData group_session_id,
                                Org__E2eelab__Skissm__Proto__E2eeAddress *user_address,
                                Org__E2eelab__Skissm__Proto__E2eeGroupSession **group_session) {
    // prepare
    sqlite3_stmt *stmt;
    if (!sqlite_prepare(GROUP_SESSION_LOAD_DATA_BY_ID_AND_OWNER, &stmt)) {
        *group_session = NULL;
        return;
    }

    // bind
    sqlite3_bind_blob(stmt, 1, group_session_id.data, group_session_id.len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, user_address->user_id.data, user_address->user_id.len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, user_address->domain.data, user_address->domain.len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, user_address->device_id.data, user_address->device_id.len, SQLITE_STATIC);

    // step
    if (!sqlite_step(stmt, SQLITE_ROW)) {
        *group_session = NULL;
        sqlite3_finalize(stmt);
        return;
    }

    // load
    size_t group_session_data_len = sqlite3_column_bytes(stmt, 0);
    uint8_t *group_session_data = (uint8_t *)sqlite3_column_blob(stmt, 0);

    // no data
    if (group_session_data_len == 0) {
        *group_session = NULL;
        sqlite3_finalize(stmt);
        return;
    }

    // unpack
    *group_session =
        org__e2eelab__skissm__proto__e2ee_group_session__unpack(NULL, group_session_data_len, group_session_data);

    // release
    sqlite3_finalize(stmt);

    return;
}

void store_group_session(Org__E2eelab__Skissm__Proto__E2eeGroupSession *group_session) {
    // pack
    size_t group_session_data_len = org__e2eelab__skissm__proto__e2ee_group_session__get_packed_size(group_session);
    uint8_t *group_session_data = (uint8_t *)malloc(group_session_data_len);
    org__e2eelab__skissm__proto__e2ee_group_session__pack(group_session, group_session_data);

    int owner_id = insert_address(group_session->session_owner);
    int address_id = insert_address(group_session->group_address);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(GROUP_SESSION_INSERT_OR_REPLACE, &stmt);

    // bind
    sqlite3_bind_blob(stmt, 1, group_session->session_id.data, group_session->session_id.len, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, owner_id);
    sqlite3_bind_int(stmt, 3, address_id);
    sqlite3_bind_blob(stmt, 4, group_session_data, group_session_data_len, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, group_session->signature_private_key.len ? 1 : 0);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite3_finalize(stmt);
    free_mem((void **)(&group_session_data), group_session_data_len);
}

void unload_group_session(Org__E2eelab__Skissm__Proto__E2eeGroupSession *group_session) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(GROUP_SESSION_DELETE_DATA_BY_OWNER_AND_ADDRESS, &stmt);

    // bind
    sqlite3_bind_blob(stmt, 1, group_session->session_owner->user_id.data, group_session->session_owner->user_id.len,
                      SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, group_session->group_address->group_id.data, group_session->group_address->group_id.len,
                      SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite3_finalize(stmt);
}

void unload_inbound_group_session(Org__E2eelab__Skissm__Proto__E2eeAddress *user_address,
                                  ProtobufCBinaryData *old_session_id) {
    if (old_session_id->data == NULL){
        return;
    }
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(GROUP_SESSION_DELETE_DATA_BY_OWNER_AND_ID, &stmt);

    // bind
    sqlite3_bind_blob(stmt, 1, user_address->user_id.data, user_address->user_id.len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, old_session_id->data, old_session_id->len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite3_finalize(stmt);
}
