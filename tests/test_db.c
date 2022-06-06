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
#include "test_db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "skissm/mem_util.h"

// global variable
static const char *db_name = (char *)"file:test.db?mode=memory&cache=shared";
static sqlite3 *db;

// util function
static void sqlite_connect(const char *db_name) {
    sqlite3_config(SQLITE_CONFIG_MULTITHREAD);
    int rc = sqlite3_open_v2(db_name, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK) {
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

    sqlite3_exec(db, "BEGIN", 0, 0, 0);
    int rc = sqlite3_exec(db, sql, sqlite_callback, (void *)data, &errMsg);
    sqlite3_exec(db, "COMMIT", 0, 0, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
    }

    sqlite3_exec(db, "COMMIT TRANSACTION;", NULL, NULL, NULL);
}

static bool sqlite_prepare(const char *sql, sqlite3_stmt **stmt) {
    int rc = sqlite3_prepare_v2(db, sql, -1, stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot prepare statement: %s\n", sqlite3_errmsg(db));
        return false;
    }

    return true;
}

static bool sqlite_step(sqlite3_stmt *stmt, int return_code) {
    sqlite3_exec(db, "BEGIN", 0, 0, 0);
    int rc = sqlite3_step(stmt);
    if (rc != return_code) {
        // fprintf(stderr, "Cannot step correctly.");
        return false;
    }
    return true;
}

static void sqlite_finalize(sqlite3_stmt *stmt) {
    sqlite3_exec(db, "COMMIT", 0, 0, 0);
    sqlite3_finalize(stmt);
}

// SQLs
// session related
static const char *SESSION_DROP_TABLE = "DROP TABLE IF EXISTS SESSION;";
static const char *SESSION_CREATE_TABLE = "CREATE TABLE SESSION( "
                                          "ID TEXT NOT NULL, "
                                          "OWNER INTEGER NOT NULL, "
                                          "FROM_ADDRESS INTEGER NOT NULL, "
                                          "TO_ADDRESS INTEGER NOT NULL, "
                                          "TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, "
                                          "DATA BLOB NOT NULL, "
                                          "FOREIGN KEY(FROM_ADDRESS) REFERENCES ADDRESS(ID), "
                                          "FOREIGN KEY(TO_ADDRESS) REFERENCES ADDRESS(ID), "
                                          "PRIMARY KEY (ID, OWNER, FROM_ADDRESS, TO_ADDRESS));";

static const char *SESSION_LOAD_DATA_BY_OWNER_AND_TO = "SELECT DATA FROM SESSION "
                                                       "INNER JOIN ADDRESS AS a1 "
                                                       "ON SESSION.OWNER = a1.ID "
                                                       "INNER JOIN ADDRESS AS a2 "
                                                       "ON SESSION.TO_ADDRESS = a2.ID "
                                                       "WHERE a1.USER_ID is (?) AND a2.USER_ID is (?) "
                                                       "ORDER BY TIMESTAMP DESC "
                                                       "LIMIT 1;";

static const char *SESSION_INSERT_OR_REPLACE = "INSERT OR REPLACE INTO SESSION "
                                               "(ID, OWNER, FROM_ADDRESS, TO_ADDRESS, DATA) "
                                               "VALUES (?, ?, ?, ?, ?);";

static const char *SESSION_LOAD_DATA_BY_ID_AND_OWNER = "SELECT DATA FROM SESSION "
                                                       "INNER JOIN ADDRESS "
                                                       "ON SESSION.OWNER = ADDRESS.ID "
                                                       "WHERE SESSION.ID is (?) AND ADDRESS.USER_ID is (?);";

static const char *SESSION_LOAD_N_OUTBOUND_SESSION = "SELECT COUNT(*) "
                                                     "FROM SESSION "
                                                     "INNER JOIN ADDRESS AS a1 "
                                                     "ON SESSION.OWNER = a1.ID "
                                                     "INNER JOIN ADDRESS AS a2 "
                                                     "ON SESSION.TO_ADDRESS = a2.ID "
                                                     "WHERE a1.USER_ID is (?) AND a2.USER_ID is (?);";

static const char *SESSION_LOAD_OUTBOUND_SESSIONS = "SELECT DATA "
                                                    "FROM SESSION "
                                                    "INNER JOIN ADDRESS AS a1 "
                                                    "ON SESSION.OWNER = a1.ID "
                                                    "INNER JOIN ADDRESS AS a2 "
                                                    "ON SESSION.TO_ADDRESS = a2.ID "
                                                    "WHERE a1.USER_ID is (?) AND a2.USER_ID is (?);";

static const char *SESSION_DELETE_DATA_BY_OWNER_FROM_AND_TO = "DELETE FROM SESSION "
                                                              "WHERE OWNER IN "
                                                              "(SELECT ID FROM ADDRESS WHERE USER_ID is (?)) "
                                                              "AND FROM_ADDRESS IN "
                                                              "(SELECT ID FROM ADDRESS WHERE USER_ID is (?)) "
                                                              "AND TO_ADDRESS IN "
                                                              "(SELECT ID FROM ADDRESS WHERE USER_ID is (?));";

static const char *GROUP_SESSION_DROP_TABLE = "DROP TABLE IF EXISTS GROUP_SESSION;";
static const char *GROUP_SESSION_CREATE_TABLE = "CREATE TABLE GROUP_SESSION( "
                                                "ID TEXT NOT NULL, "
                                                "OWNER INTEGER NOT NULL, "
                                                "ADDRESS INTEGER NOT NULL, "
                                                "TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, "
                                                "GROUP_DATA BLOB NOT NULL, "
                                                "IS_OUTBOUND INTEGER NOT NULL, "
                                                "FOREIGN KEY(OWNER) REFERENCES ADDRESS(ID), "
                                                "FOREIGN KEY(ADDRESS) REFERENCES ADDRESS(ID), "
                                                "PRIMARY KEY (ADDRESS, OWNER), "
                                                "UNIQUE (ID, OWNER));";

static const char *GROUP_SESSION_INSERT_OR_REPLACE = "INSERT OR REPLACE INTO GROUP_SESSION "
                                                     "(ID, OWNER, ADDRESS, GROUP_DATA, IS_OUTBOUND) "
                                                     "VALUES (?, ?, ?, ?, ?);";

static const char *GROUP_SESSION_LOAD_DATA_BY_ID_AND_OWNER =
    "SELECT GROUP_DATA FROM GROUP_SESSION "
    "INNER JOIN ADDRESS "
    "ON GROUP_SESSION.OWNER = ADDRESS.ID "
    "WHERE GROUP_SESSION.ID is (?) AND ADDRESS.USER_ID is (?) AND ADDRESS.DOMAIN "
    "is (?) AND ADDRESS.DEVICE_ID is (?);";

static const char *GROUP_SESSION_LOAD_OUTBOUND =
    "SELECT GROUP_DATA FROM GROUP_SESSION "
    "INNER JOIN ADDRESS as a1 "
    "ON GROUP_SESSION.OWNER = a1.ID "
    "INNER JOIN ADDRESS as a2 "
    "ON GROUP_SESSION.ADDRESS = a2.ID "
    "WHERE a1.DOMAIN is (?) AND a1.USER_ID is (?) AND a1.DEVICE_ID is (?) AND "
    "a2.GROUP_ID is (?) AND IS_OUTBOUND = 1 "
    "LIMIT 1;";

static const char *GROUP_SESSION_LOAD_INBOUND =
    "SELECT GROUP_DATA FROM GROUP_SESSION "
    "INNER JOIN ADDRESS as a1 "
    "ON GROUP_SESSION.OWNER = a1.ID "
    "INNER JOIN ADDRESS as a2 "
    "ON GROUP_SESSION.ADDRESS = a2.ID "
    "WHERE a1.DOMAIN is (?) AND a1.USER_ID is (?) AND a1.DEVICE_ID is (?) AND "
    "a2.GROUP_ID is (?) AND IS_OUTBOUND = 0 "
    "LIMIT 1;";

static const char *GROUP_SESSION_DELETE_DATA_BY_OWNER_AND_ADDRESS = "DELETE FROM GROUP_SESSION "
                                                                    "WHERE OWNER IN "
                                                                    "(SELECT ID FROM ADDRESS WHERE USER_ID is (?)) "
                                                                    "AND ADDRESS IN "
                                                                    "(SELECT ID FROM ADDRESS WHERE GROUP_ID is (?));";

static const char *GROUP_SESSION_DELETE_DATA_BY_OWNER_AND_ID = "DELETE FROM GROUP_SESSION "
                                                               "WHERE OWNER IN "
                                                               "(SELECT ID FROM ADDRESS WHERE USER_ID is (?)) "
                                                               "AND ID is (?);";

static const char *PENDING_GROUP_PRE_KEY_DROP_TABLE = "DROP TABLE IF EXISTS PENDING_GROUP_PRE_KEY;";
static const char *PENDING_GROUP_PRE_KEY_CREATE_TABLE = "CREATE TABLE PENDING_GROUP_PRE_KEY( "
                                                        "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                        "MEMBER_ADDRESS INTEGER NOT NULL, "
                                                        "GROUP_PRE_KEY_DATA BLOB NOT NULL, "
                                                        "FOREIGN KEY(MEMBER_ADDRESS) REFERENCES ADDRESS(ID));";

static const char *PENDING_GROUP_PRE_KEY_INSERT = "INSERT INTO PENDING_GROUP_PRE_KEY "
                                                  "(MEMBER_ADDRESS, GROUP_PRE_KEY_DATA) "
                                                  "VALUES (?, ?);";

static const char *N_PENDING_GROUP_PRE_KEY_LOAD = "SELECT COUNT(*) "
                                                  "FROM PENDING_GROUP_PRE_KEY "
                                                  "INNER JOIN ADDRESS "
                                                  "ON PENDING_GROUP_PRE_KEY.MEMBER_ADDRESS = ADDRESS.ID "
                                                  "WHERE ADDRESS.DOMAIN is (?) AND "
                                                  "ADDRESS.USER_ID is (?) AND "
                                                  "ADDRESS.DEVICE_ID is (?);";

static const char *PENDING_GROUP_PRE_KEY_LOAD = "SELECT GROUP_PRE_KEY_DATA "
                                                "FROM PENDING_GROUP_PRE_KEY "
                                                "INNER JOIN ADDRESS "
                                                "ON PENDING_GROUP_PRE_KEY.MEMBER_ADDRESS = ADDRESS.ID "
                                                "WHERE ADDRESS.DOMAIN is (?) AND "
                                                "ADDRESS.USER_ID is (?) AND "
                                                "ADDRESS.DEVICE_ID is (?);";

static const char *PENDING_GROUP_PRE_KEY_DELETE_DATA = "DELETE FROM PENDING_GROUP_PRE_KEY "
                                                       "WHERE MEMBER_ADDRESS IN "
                                                       "(SELECT ID FROM ADDRESS WHERE USER_ID is (?));";

// account related
static const char *ADDRESS_DROP_TABLE = "DROP TABLE IF EXISTS ADDRESS;";
static const char *ADDRESS_CREATE_TABLE = "CREATE TABLE ADDRESS( "
                                          "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
                                          "USER_ID TEXT, "
                                          "DOMAIN TEXT NOT NULL, "
                                          "DEVICE_ID TEXT, "
                                          "GROUP_ID TEXT, "
                                          "UNIQUE (USER_ID, DOMAIN, DEVICE_ID, GROUP_ID));";

static const char *KEYPAIR_DROP_TABLE = "DROP TABLE IF EXISTS KEYPAIR;";
static const char *KEYPAIR_CREATE_TABLE = "CREATE TABLE KEYPAIR( "
                                          "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
                                          "PUBLIC_KEY BLOB NOT NULL, "
                                          "PRIVATE_KEY BLOB NOT NULL);";

static const char *IDENTITY_KEY_DROP_TABLE = "DROP TABLE IF EXISTS IDENTITY_KEY;";
static const char *IDENTITY_KEY_CREATE_TABLE = "CREATE TABLE IDENTITY_KEY( "
                                               "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
                                               "ASYM_KEYPAIR INTEGER NOT NULL, "
                                               "SIGN_KEYPAIR INTEGER NOT NULL, "
                                               "FOREIGN KEY(ASYM_KEYPAIR) REFERENCES KEYPAIR(ID), "
                                               "FOREIGN KEY(SIGN_KEYPAIR) REFERENCES KEYPAIR(ID));";

static const char *SIGNED_PRE_KEY_DROP_TABLE = "DROP TABLE IF EXISTS SIGNED_PRE_KEY;";
static const char *SIGNED_PRE_KEY_CREATE_TABLE = "CREATE TABLE SIGNED_PRE_KEY( "
                                                 "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                 "SPK_ID INTEGER NOT NULL, "
                                                 "KEYPAIR INTEGER NOT NULL, "
                                                 "SIGNATURE BLOB NOT NULL, "
                                                 "TTL INTEGER NOT NULL, "
                                                 "FOREIGN KEY(KEYPAIR) REFERENCES KEYPAIR(ID));";

static const char *ONETIME_PRE_KEY_DROP_TABLE = "DROP TABLE IF EXISTS ONETIME_PRE_KEY;";
static const char *ONETIME_PRE_KEY_CREATE_TABLE = "CREATE TABLE ONETIME_PRE_KEY(  "
                                                  "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                  "OPK_ID INTEGER NOT NULL, "
                                                  "USED INTEGER NOT NULL, "
                                                  "KEYPAIR INTEGER NOT NULL, "
                                                  "FOREIGN KEY(KEYPAIR) REFERENCES KEYPAIR(ID));";

static const char *ACCOUNT_DROP_TABLE = "DROP TABLE IF EXISTS ACCOUNT;";
static const char *ACCOUNT_CREATE_TABLE = "CREATE TABLE ACCOUNT( "
                                          "ACCOUNT_ID INTEGER PRIMARY KEY AUTOINCREMENT, "
                                          "VERSION TEXT NOT NULL, "
                                          "SAVED INTEGER NOT NULL, "
                                          "ADDRESS INTEGER NOT NULL, "
                                          "PASSWORD TEXT NOT NULL, "
                                          "E2EE_PACK_ID TEXT NOT NULL, "
                                          "IDENTITY_KEY INTEGER NOT NULL, "
                                          "SIGNED_PRE_KEY INTEGER NOT NULL, "
                                          "NEXT_ONETIME_PRE_KEY_ID INTEGER NOT NULL, "
                                          "FOREIGN KEY(ADDRESS) REFERENCES ADDRESS(ID), "
                                          "FOREIGN KEY(IDENTITY_KEY) REFERENCES IDENTITY_KEY(ID), "
                                          "FOREIGN KEY(SIGNED_PRE_KEY) REFERENCES SIGNED_PRE_KEY(ID));";

static const char *ACCOUNT_IDENTITY_KEY_DROP_TABLE = "DROP TABLE IF EXISTS ACCOUNT_IDENTITY_KEY;";
static const char *ACCOUNT_IDENTITY_KEY_CREATE_TABLE =
    "CREATE TABLE ACCOUNT_IDENTITY_KEY( "
    "ACCOUNT INTEGER NOT NULL, "
    "IDENTITY_KEY INTEGER NOT NULL, "
    "FOREIGN KEY(ACCOUNT) REFERENCES ACCOUNT(ID), "
    "FOREIGN KEY(IDENTITY_KEY) REFERENCES IDENTITY_KEY(ID));";

static const char *ACCOUNT_SIGNED_PRE_KEY_DROP_TABLE = "DROP TABLE IF EXISTS ACCOUNT_SIGNED_PRE_KEY;";
static const char *ACCOUNT_SIGNED_PRE_KEY_CREATE_TABLE =
    "CREATE TABLE ACCOUNT_SIGNED_PRE_KEY( "
    "ACCOUNT INTEGER NOT NULL, "
    "SIGNED_PRE_KEY INTEGER NOT NULL, "
    "FOREIGN KEY(ACCOUNT) REFERENCES ACCOUNT(ID), "
    "FOREIGN KEY(SIGNED_PRE_KEY) REFERENCES SIGNED_PRE_KEY(ID));";

static const char *ACCOUNT_ONETIME_PRE_KEY_DROP_TABLE = "DROP TABLE IF EXISTS ACCOUNT_ONETIME_PRE_KEY;";
static const char *ACCOUNT_ONETIME_PRE_KEY_CREATE_TABLE =
    "CREATE TABLE ACCOUNT_ONETIME_PRE_KEY( "
    "ACCOUNT INTEGER NOT NULL, "
    "ONETIME_PRE_KEY INTEGER NOT NULL, "
    "FOREIGN KEY(ACCOUNT) REFERENCES ACCOUNT(ID), "
    "FOREIGN KEY(ONETIME_PRE_KEY) REFERENCES ONETIME_PRE_KEY(ID));";

static const char *ACCOUNTS_NUM = "SELECT COUNT(*) FROM ACCOUNT;";

static const char *ACCOUNT_LOAD_ALL_ACCOUNT_IDS = "SELECT ACCOUNT_ID FROM ACCOUNT;";

static const char *ACCOUNT_LOAD_VERSION = "SELECT VERSION "
                                          "FROM ACCOUNT "
                                          "WHERE ACCOUNT_ID is (?);";

static const char *ACCOUNT_LOAD_SAVED = "SELECT SAVED "
                                        "FROM ACCOUNT "
                                        "WHERE ACCOUNT.ACCOUNT_ID is (?);";

static const char *ACCOUNT_LOAD_ADDRESS = "SELECT "
                                          "ADDRESS.DOMAIN, "
                                          "ADDRESS.USER_ID, "
                                          "ADDRESS.DEVICE_ID "
                                          "FROM ACCOUNT "
                                          "INNER JOIN ADDRESS "
                                          "ON ACCOUNT.ADDRESS = ADDRESS.ID "
                                          "WHERE ACCOUNT.ACCOUNT_ID is (?);";

static const char *ACCOUNT_LOAD_PASSWORD = "SELECT PASSWORD "
                                           "FROM ACCOUNT "
                                           "WHERE ACCOUNT.ACCOUNT_ID is (?);";

static const char *ACCOUNT_LOAD_E2EE_PACK_ID = "SELECT E2EE_PACK_ID "
                                                  "FROM ACCOUNT "
                                                  "WHERE ACCOUNT_ID is (?);";

static const char *ACCOUNT_LOAD_KEYPAIR = "SELECT KEYPAIR.PUBLIC_KEY, "
                                          "KEYPAIR.PRIVATE_KEY "
                                          "FROM ACCOUNT "
                                          "INNER JOIN KEYPAIR "
                                          "ON ACCOUNT.IDENTITY_KEY = KEYPAIR.ID "
                                          "WHERE ACCOUNT.ACCOUNT_ID is (?);";

static const char *ACCOUNT_LOAD_IDENTITY_KEY_ID = "SELECT IDENTITY_KEY "
                                                  "FROM ACCOUNT "
                                                  "INNER JOIN IDENTITY_KEY "
                                                  "ON ACCOUNT.IDENTITY_KEY = IDENTITY_KEY.ID "
                                                  "WHERE ACCOUNT.ACCOUNT_ID is (?);";

static const char *ACCOUNT_LOAD_IDENTITY_KEY_ASYM = "SELECT "
                                                    "KEYPAIR.PUBLIC_KEY, "
                                                    "KEYPAIR.PRIVATE_KEY "
                                                    "FROM IDENTITY_KEY "
                                                    "INNER JOIN KEYPAIR "
                                                    "ON IDENTITY_KEY.ASYM_KEYPAIR = KEYPAIR.ID "
                                                    "WHERE IDENTITY_KEY.ID is (?);";

static const char *ACCOUNT_LOAD_IDENTITY_KEY_SIGN = "SELECT "
                                                    "KEYPAIR.PUBLIC_KEY, "
                                                    "KEYPAIR.PRIVATE_KEY "
                                                    "FROM IDENTITY_KEY "
                                                    "INNER JOIN KEYPAIR "
                                                    "ON IDENTITY_KEY.SIGN_KEYPAIR = KEYPAIR.ID "
                                                    "WHERE IDENTITY_KEY.ID is (?);";

static const char *ACCOUNT_LOAD_SIGNED_PRE_KEY = "SELECT SIGNED_PRE_KEY.SPK_ID, "
                                                 "KEYPAIR.PUBLIC_KEY, "
                                                 "KEYPAIR.PRIVATE_KEY, "
                                                 "SIGNED_PRE_KEY.SIGNATURE, "
                                                 "SIGNED_PRE_KEY.TTL "
                                                 "FROM ACCOUNT "
                                                 "INNER JOIN SIGNED_PRE_KEY "
                                                 "ON ACCOUNT.SIGNED_PRE_KEY = SIGNED_PRE_KEY.ID "
                                                 "INNER JOIN KEYPAIR "
                                                 "ON SIGNED_PRE_KEY.KEYPAIR = KEYPAIR.ID "
                                                 "WHERE ACCOUNT.ACCOUNT_ID is (?);";

static const char *ACCOUNT_LOAD_N_ONETIME_PRE_KEYS = "SELECT COUNT(*) "
                                                     "FROM ACCOUNT_ONETIME_PRE_KEY "
                                                     "INNER JOIN ACCOUNT "
                                                     "ON ACCOUNT_ONETIME_PRE_KEY.ACCOUNT = ACCOUNT.ACCOUNT_ID "
                                                     "WHERE ACCOUNT.ACCOUNT_ID is (?);";

static const char *ACCOUNT_LOAD_ONETIME_PRE_KEYS = "SELECT ONETIME_PRE_KEY.OPK_ID, "
                                                   "ONETIME_PRE_KEY.USED, "
                                                   "KEYPAIR.PUBLIC_KEY, "
                                                   "KEYPAIR.PRIVATE_KEY "
                                                   "FROM ACCOUNT_ONETIME_PRE_KEY "
                                                   "INNER JOIN ACCOUNT "
                                                   "ON ACCOUNT_ONETIME_PRE_KEY.ACCOUNT = ACCOUNT.ACCOUNT_ID "
                                                   "INNER JOIN ONETIME_PRE_KEY "
                                                   "ON ACCOUNT_ONETIME_PRE_KEY.ONETIME_PRE_KEY = "
                                                   "ONETIME_PRE_KEY.ID "
                                                   "INNER JOIN KEYPAIR "
                                                   "ON ONETIME_PRE_KEY.KEYPAIR = KEYPAIR.ID "
                                                   "WHERE ACCOUNT.ACCOUNT_ID is (?);";

static const char *ACCOUNT_LOAD_ONETIME_PRE_KEY = "SELECT ONETIME_PRE_KEY.ID "
                                                  "FROM ACCOUNT_ONETIME_PRE_KEY "
                                                  "INNER JOIN ACCOUNT "
                                                  "ON ACCOUNT_ONETIME_PRE_KEY.ACCOUNT = ACCOUNT.ACCOUNT_ID "
                                                  "INNER JOIN ONETIME_PRE_KEY "
                                                  "ON ACCOUNT_ONETIME_PRE_KEY.ONETIME_PRE_KEY = "
                                                  "ONETIME_PRE_KEY.ID "
                                                  "WHERE ACCOUNT.ACCOUNT_ID is (?) AND ONETIME_PRE_KEY.OPK_ID is (?);";

static const char *ACCOUNT_LOAD_NEXT_ONETIME_PRE_KEY_ID = "SELECT NEXT_ONETIME_PRE_KEY_ID "
                                                          "FROM ACCOUNT "
                                                          "WHERE ACCOUNT_ID is (?);";

static const char *LOAD_ACCOUNT_ID_BY_ADDRESS = "SELECT ACCOUNT_ID "
                                                "FROM ACCOUNT "
                                                "INNER JOIN ADDRESS "
                                                "ON ACCOUNT.ADDRESS = ADDRESS.ID "
                                                "WHERE ADDRESS.USER_ID is (?);";

static const char *ADDRESS_LOAD = "SELECT ROWID "
                                  "FROM ADDRESS "
                                  "WHERE ADDRESS.DOMAIN is (?) AND "
                                  "ADDRESS.USER_ID is (?) AND "
                                  "ADDRESS.DEVICE_ID is (?) AND "
                                  "ADDRESS.GROUP_ID is (?);";

static const char *ADDRESS_INSERT = "INSERT OR IGNORE INTO ADDRESS "
                                    "(DOMAIN, USER_ID, DEVICE_ID, GROUP_ID) "
                                    "VALUES (?, ?, ?, ?);";

static const char *IDENTITY_KEY_INSERT = "INSERT INTO IDENTITY_KEY "
                                         "(ASYM_KEYPAIR, SIGN_KEYPAIR) "
                                         "VALUES (?, ?);";

static const char *SIGNED_PRE_KEY_INSERT = "INSERT INTO SIGNED_PRE_KEY "
                                           "(SPK_ID, KEYPAIR, SIGNATURE, TTL) "
                                           "VALUES (?, ?, ?, ?);";

static const char *SIGNED_PRE_KEY_DELETE = "DELETE FROM SIGNED_PRE_KEY "
                                           "WHERE ID is (?);";

static const char *KEYPAIR_INSERT = "INSERT INTO KEYPAIR "
                                    "(PUBLIC_KEY, PRIVATE_KEY) "
                                    "VALUES (?, ?);";
static const char *ONETIME_PRE_KEY_INSERT = "INSERT INTO ONETIME_PRE_KEY "
                                            "(OPK_ID, USED, KEYPAIR) "
                                            "VALUES (?, ?, ?);";

static const char *ONETIME_PRE_KEY_DELETE = "DELETE FROM ONETIME_PRE_KEY "
                                            "WHERE ID is (?);";

static const char *ACCOUNT_INSERT = "INSERT INTO ACCOUNT "
                                    "(ACCOUNT_ID, "
                                    "VERSION, "
                                    "SAVED, "
                                    "ADDRESS, "
                                    "PASSWORD, "
                                    "E2EE_PACK_ID, "
                                    "IDENTITY_KEY, "
                                    "SIGNED_PRE_KEY, "
                                    "NEXT_ONETIME_PRE_KEY_ID) "
                                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";

static const char *ACCOUNT_IDENTITY_KEY_INSERT = "INSERT INTO ACCOUNT_IDENTITY_KEY "
                                                 "(ACCOUNT, IDENTITY_KEY) "
                                                 "VALUES (?, ?);";

static const char *ACCOUNT_SIGNED_PRE_KEY_INSERT = "INSERT INTO ACCOUNT_SIGNED_PRE_KEY "
                                                   "(ACCOUNT, SIGNED_PRE_KEY) "
                                                   "VALUES (?, ?);";

static const char *ACCOUNT_SIGNED_PRE_KEY_DELETE = "DELETE FROM ACCOUNT_SIGNED_PRE_KEY "
                                                   "WHERE ACCOUNT is (?) AND SIGNED_PRE_KEY is (?);";

static const char *ACCOUNT_SIGNED_PRE_KEY_SELECT_MORE_THAN_2 = "SELECT SIGNED_PRE_KEY "
                                                               "FROM ACCOUNT_SIGNED_PRE_KEY "
                                                               "WHERE ACCOUNT is (?) AND "
                                                               "(SIGNED_PRE_KEY < ((SELECT MAX(SIGNED_PRE_KEY) FROM ACCOUNT_SIGNED_PRE_KEY) - 1));";

static const char *ACCOUNT_ONETIME_PRE_KEY_INSERT = "INSERT INTO ACCOUNT_ONETIME_PRE_KEY "
                                                    "(ACCOUNT, ONETIME_PRE_KEY) "
                                                    "VALUES (?, ?);";

static const char *ACCOUNT_ONETIME_PRE_KEY_DELETE = "DELETE FROM ACCOUNT_ONETIME_PRE_KEY "
                                                    "WHERE ACCOUNT is (?) AND ONETIME_PRE_KEY is (?);";

static const char *ACCOUNT_UPDATE_ADDRESS = "UPDATE ACCOUNT "
                                            "SET ADDRESS = (?) "
                                            "WHERE ACCOUNT_ID is (?);";

static const char *ACCOUNT_UPDATE_SIGNED_PRE_KEY = "UPDATE ACCOUNT "
                                                   "SET SIGNED_PRE_KEY = (?) "
                                                   "WHERE ACCOUNT_ID is (?);";

static const char *LOAD_OLD_SIGNED_PRE_KEY = "SELECT SIGNED_PRE_KEY.SPK_ID, "
                                             "KEYPAIR.PUBLIC_KEY, "
                                             "KEYPAIR.PRIVATE_KEY, "
                                             "SIGNED_PRE_KEY.SIGNATURE, "
                                             "SIGNED_PRE_KEY.TTL "
                                             "FROM ACCOUNT_SIGNED_PRE_KEY "
                                             "INNER JOIN ACCOUNT "
                                             "ON ACCOUNT_SIGNED_PRE_KEY.ACCOUNT = ACCOUNT.ACCOUNT_ID "
                                             "INNER JOIN SIGNED_PRE_KEY "
                                             "ON ACCOUNT_SIGNED_PRE_KEY.SIGNED_PRE_KEY = SIGNED_PRE_KEY.ID "
                                             "INNER JOIN KEYPAIR "
                                             "ON SIGNED_PRE_KEY.KEYPAIR = KEYPAIR.ID "
                                             "WHERE ACCOUNT.ACCOUNT_ID is (?) AND SIGNED_PRE_KEY.SPK_ID is (?);";

static const char *ACCOUNT_UPDATE_IDENTITY_KEY = "UPDATE ACCOUNT "
                                                 "SET IDENTITY_KEY = (?) "
                                                 "WHERE ACCOUNT_ID is (?);";

static const char *ONETIME_PRE_KEY_UPDATE_USED = "UPDATE ONETIME_PRE_KEY "
                                                 "SET USED = 1 "
                                                 "WHERE ID is (?);";

void test_db_begin() {
    sqlite3_initialize();

    // connect
    sqlite_connect(db_name);

    // session
    sqlite_execute(SESSION_DROP_TABLE);
    sqlite_execute(SESSION_CREATE_TABLE);

    // group_session
    sqlite_execute(GROUP_SESSION_DROP_TABLE);
    sqlite_execute(GROUP_SESSION_CREATE_TABLE);

    // group_pre_key
    sqlite_execute(PENDING_GROUP_PRE_KEY_DROP_TABLE);
    sqlite_execute(PENDING_GROUP_PRE_KEY_CREATE_TABLE);

    // address
    sqlite_execute(ADDRESS_DROP_TABLE);
    sqlite_execute(ADDRESS_CREATE_TABLE);

    // key pair
    sqlite_execute(KEYPAIR_DROP_TABLE);
    sqlite_execute(KEYPAIR_CREATE_TABLE);

    // identity_key
    sqlite_execute(IDENTITY_KEY_DROP_TABLE);
    sqlite_execute(IDENTITY_KEY_CREATE_TABLE);

    // signed_pre_key
    sqlite_execute(SIGNED_PRE_KEY_DROP_TABLE);
    sqlite_execute(SIGNED_PRE_KEY_CREATE_TABLE);

    // one_time_pre_key
    sqlite_execute(ONETIME_PRE_KEY_DROP_TABLE);
    sqlite_execute(ONETIME_PRE_KEY_CREATE_TABLE);

    // account
    sqlite_execute(ACCOUNT_DROP_TABLE);
    sqlite_execute(ACCOUNT_CREATE_TABLE);

    // account_identity_key_pair
    sqlite_execute(ACCOUNT_IDENTITY_KEY_DROP_TABLE);
    sqlite_execute(ACCOUNT_IDENTITY_KEY_CREATE_TABLE);

    // account_signed_pre_key_pair
    sqlite_execute(ACCOUNT_SIGNED_PRE_KEY_DROP_TABLE);
    sqlite_execute(ACCOUNT_SIGNED_PRE_KEY_CREATE_TABLE);

    // account_one_time_pre_key_pair
    sqlite_execute(ACCOUNT_ONETIME_PRE_KEY_DROP_TABLE);
    sqlite_execute(ACCOUNT_ONETIME_PRE_KEY_CREATE_TABLE);
}

void test_db_end() {
    sqlite3_close(db);
    sqlite3_shutdown();
}

size_t load_ids(sqlite_int64 **account_ids) {
    // find num of account_ids
    // prepare
    sqlite3_stmt *stmt1;
    sqlite_prepare(ACCOUNTS_NUM, &stmt1);
    // step
    sqlite_step(stmt1, SQLITE_ROW);
    size_t num = (size_t)sqlite3_column_int64(stmt1, 0);
    // release
    sqlite_finalize(stmt1);

    if (num == 0) {
        *account_ids = NULL;
        return num;
    }

    // allocate memory
    *account_ids = (sqlite_int64 *)malloc(sizeof(sqlite_int64) * num);

    // prepare
    sqlite3_stmt *stmt2;
    sqlite_prepare(ACCOUNT_LOAD_ALL_ACCOUNT_IDS, &stmt2);
    // step
    int i = 0;
    while (sqlite3_step(stmt2) != SQLITE_DONE) {
        sqlite_int64 account_id = sqlite3_column_int64(stmt2, 0);
        (*account_ids)[i++] = account_id;
    }
    // release
    sqlite_finalize(stmt2);

    // done
    return num;
}

char *load_version(uint64_t account_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_VERSION, &stmt);
    sqlite3_bind_int64(stmt, 1, account_id);

    // step
    bool succ = sqlite_step(stmt, SQLITE_ROW);

    // load
    char *version = succ?strdup((char *)sqlite3_column_text(stmt, 0)):NULL;

    // release
    sqlite_finalize(stmt);

    return version;
}

protobuf_c_boolean load_saved(uint64_t account_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_SAVED, &stmt);
    sqlite3_bind_int64(stmt, 1, account_id);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    protobuf_c_boolean saved = (protobuf_c_boolean)sqlite3_column_int(stmt, 0);

    // release
    sqlite_finalize(stmt);

    return saved;
}

void load_address(uint64_t account_id, Skissm__E2eeAddress **address) {
    // allocate memory
    *address = (Skissm__E2eeAddress *)malloc(sizeof(Skissm__E2eeAddress));
    skissm__e2ee_address__init(*address);

    (*address)->user = (Skissm__PeerUser *)malloc(sizeof(Skissm__PeerUser));
    skissm__peer_user__init((*address)->user);
    (*address)->peer_case = SKISSM__E2EE_ADDRESS__PEER_USER;

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_ADDRESS, &stmt);
    sqlite3_bind_int64(stmt, 1, account_id);

    // step
    bool succ = sqlite_step(stmt, SQLITE_ROW);

    // load
    if (succ) {
        (*address)->domain = strdup((char *)sqlite3_column_text(stmt, 0));
        (*address)->user->user_id = strdup((char *)sqlite3_column_text(stmt, 1));
        (*address)->user->device_id = strdup((char *)sqlite3_column_text(stmt, 2));
    }

    // release
    sqlite_finalize(stmt);
}

void load_password(uint64_t account_id, char *password) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_PASSWORD, &stmt);
    sqlite3_bind_int64(stmt, 1, account_id);

    // step
    bool succ = sqlite_step(stmt, SQLITE_ROW);

    // load
    password = succ?strdup((char *)sqlite3_column_text(stmt, 0)):NULL;

    // release
    sqlite_finalize(stmt);
}

char *load_e2ee_pack_id(uint64_t account_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_E2EE_PACK_ID, &stmt);
    sqlite3_bind_int64(stmt, 1, account_id);

    // step
    bool succ = sqlite_step(stmt, SQLITE_ROW);

    // load
    char *e2ee_pack_id = succ?strdup((char *)sqlite3_column_text(stmt, 0)):NULL;

    // release
    sqlite_finalize(stmt);

    return e2ee_pack_id;
}

static void load_identity_key_asym(sqlite_int64 identity_key_id, Skissm__KeyPair **asym_key_pair) {
    // allocate memory
    *asym_key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(*asym_key_pair);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_IDENTITY_KEY_ASYM, &stmt);
    sqlite3_bind_int(stmt, 1, identity_key_id);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    copy_protobuf_from_array(&((*asym_key_pair)->public_key), (uint8_t *)sqlite3_column_blob(stmt, 0),
                             sqlite3_column_bytes(stmt, 0));
    copy_protobuf_from_array(&((*asym_key_pair)->private_key), (uint8_t *)sqlite3_column_blob(stmt, 1),
                             sqlite3_column_bytes(stmt, 1));

    // release
    sqlite_finalize(stmt);
}

static void load_identity_key_sign(sqlite_int64 identity_key_id, Skissm__KeyPair **sign_key_pair) {
    // allocate memory
    *sign_key_pair = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(*sign_key_pair);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_IDENTITY_KEY_SIGN, &stmt);
    sqlite3_bind_int(stmt, 1, identity_key_id);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    copy_protobuf_from_array(&((*sign_key_pair)->public_key), (uint8_t *)sqlite3_column_blob(stmt, 0),
                             sqlite3_column_bytes(stmt, 0));
    copy_protobuf_from_array(&((*sign_key_pair)->private_key), (uint8_t *)sqlite3_column_blob(stmt, 1),
                             sqlite3_column_bytes(stmt, 1));

    // release
    sqlite_finalize(stmt);
}

void load_identity_key_pair(uint64_t account_id, Skissm__IdentityKey **identity_key) {
    // allocate memory
    *identity_key = (Skissm__IdentityKey *)malloc(sizeof(Skissm__IdentityKey));
    skissm__identity_key__init(*identity_key);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_IDENTITY_KEY_ID, &stmt);
    sqlite3_bind_int64(stmt, 1, account_id);

    // step
    sqlite_step(stmt, SQLITE_ROW);
    sqlite_int64 identity_key_id = sqlite3_column_int(stmt, 0);

    // load
    load_identity_key_asym(identity_key_id, &((*identity_key)->asym_key_pair));
    load_identity_key_sign(identity_key_id, &((*identity_key)->sign_key_pair));

    // release
    sqlite_finalize(stmt);
}

void load_signed_pre_key_pair(uint64_t account_id,
                              Skissm__SignedPreKey **signed_pre_key) {
    // allocate memory
    *signed_pre_key =
        (Skissm__SignedPreKey *)malloc(sizeof(Skissm__SignedPreKey));
    skissm__signed_pre_key__init(*signed_pre_key);

    Skissm__KeyPair *key_pair =
        (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(key_pair);
    (*signed_pre_key)->key_pair = key_pair;

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_SIGNED_PRE_KEY, &stmt);
    sqlite3_bind_int64(stmt, 1, account_id);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    (*signed_pre_key)->spk_id = (uint32_t)sqlite3_column_int(stmt, 0);
    copy_protobuf_from_array(&((*signed_pre_key)->key_pair->public_key), (uint8_t *)sqlite3_column_blob(stmt, 1),
                             sqlite3_column_bytes(stmt, 1));
    copy_protobuf_from_array(&((*signed_pre_key)->key_pair->private_key), (uint8_t *)sqlite3_column_blob(stmt, 2),
                             sqlite3_column_bytes(stmt, 2));
    copy_protobuf_from_array(&((*signed_pre_key)->signature), (uint8_t *)sqlite3_column_blob(stmt, 3),
                             sqlite3_column_bytes(stmt, 3));
    (*signed_pre_key)->ttl = (uint64_t)sqlite3_column_int64(stmt, 4);

    // release
    sqlite_finalize(stmt);
}

int load_n_one_time_pre_keys(uint64_t account_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_N_ONETIME_PRE_KEYS, &stmt);
    sqlite3_bind_int64(stmt, 1, account_id);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    int n_one_time_pre_keys = (int)sqlite3_column_int(stmt, 0);

    // release
    sqlite_finalize(stmt);

    return n_one_time_pre_keys;
}

uint32_t load_one_time_pre_keys(uint64_t account_id,
                                Skissm__OneTimePreKey ***one_time_pre_keys) {
    // allocate memory
    size_t n_one_time_pre_keys = load_n_one_time_pre_keys(account_id);
    (*one_time_pre_keys) = (Skissm__OneTimePreKey **)malloc(
        n_one_time_pre_keys * sizeof(Skissm__OneTimePreKey *));

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_ONETIME_PRE_KEYS, &stmt);
    sqlite3_bind_int64(stmt, 1, account_id);

    // step
    for (int i = 0; i < n_one_time_pre_keys; i++) {
        sqlite3_step(stmt);

        // allocate
        (*one_time_pre_keys)[i] = (Skissm__OneTimePreKey *)malloc(
            sizeof(Skissm__OneTimePreKey));
        skissm__one_time_pre_key__init((*one_time_pre_keys)[i]);

        Skissm__KeyPair *key_pair =
            (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
        skissm__key_pair__init(key_pair);
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
    sqlite_finalize(stmt);

    return n_one_time_pre_keys;
}

uint32_t load_next_one_time_pre_key_id(uint64_t account_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_NEXT_ONETIME_PRE_KEY_ID, &stmt);
    sqlite3_bind_int64(stmt, 1, account_id);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    uint32_t next_one_time_pre_key_id = (uint32_t)sqlite3_column_int(stmt, 0);

    // release
    sqlite_finalize(stmt);

    return next_one_time_pre_key_id;
}

void load_id_by_address(Skissm__E2eeAddress *address, sqlite_int64 *account_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(LOAD_ACCOUNT_ID_BY_ADDRESS, &stmt);
    sqlite3_bind_text(stmt, 1, address->user->user_id, -1, SQLITE_TRANSIENT);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    *account_id = sqlite3_column_int64(stmt, 0);

    // release
    sqlite_finalize(stmt);
}

static sqlite_int64 address_row_id(Skissm__E2eeAddress *address) {
    sqlite_int64 rol_id = 0;

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ADDRESS_LOAD, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, address->domain, -1, SQLITE_TRANSIENT);
    if (address->peer_case == SKISSM__E2EE_ADDRESS__PEER_USER) {
        sqlite3_bind_text(stmt, 2, address->user->user_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, address->user->device_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_null(stmt, 4);
    } else if (address->peer_case == SKISSM__E2EE_ADDRESS__PEER_GROUP) {
        sqlite3_bind_null(stmt, 2);
        sqlite3_bind_null(stmt, 3);
        sqlite3_bind_text(stmt, 4, address->group->group_id, -1, SQLITE_TRANSIENT);
    }

    // step
    bool succ = sqlite_step(stmt, SQLITE_ROW);
    if (succ)
        rol_id = (sqlite_int64)sqlite3_column_int64(stmt, 0);

    // release
    sqlite_finalize(stmt);

    return rol_id;
}

sqlite_int64 insert_address(Skissm__E2eeAddress *address) {
    // address exists
    sqlite_int64 row_id = address_row_id(address);
    if (row_id > 0)
        return row_id;

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ADDRESS_INSERT, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, address->domain, -1, SQLITE_TRANSIENT);
    if (address->peer_case == SKISSM__E2EE_ADDRESS__PEER_USER) {
        sqlite3_bind_text(stmt, 2, address->user->user_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, address->user->device_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_null(stmt, 4);
    } else if (address->peer_case == SKISSM__E2EE_ADDRESS__PEER_GROUP) {
        sqlite3_bind_null(stmt, 2);
        sqlite3_bind_null(stmt, 3);
        sqlite3_bind_text(stmt, 4, address->group->group_id, -1, SQLITE_TRANSIENT);
    }

    // step
    bool succ = sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);

    return sqlite3_last_insert_rowid(db);
}

sqlite_int64 insert_key_pair(Skissm__KeyPair *key_pair) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(KEYPAIR_INSERT, &stmt);

    // bind
    sqlite3_bind_blob(stmt, 1, key_pair->public_key.data, key_pair->public_key.len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, key_pair->private_key.data, key_pair->private_key.len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);

    return sqlite3_last_insert_rowid(db);
}

sqlite_int64 insert_identity_key(Skissm__IdentityKey *identity_key) {
    sqlite_int64 key_pair_id_1 = insert_key_pair(identity_key->asym_key_pair);
    sqlite_int64 key_pair_id_2 = insert_key_pair(identity_key->sign_key_pair);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(IDENTITY_KEY_INSERT, &stmt);

    // bind
    sqlite3_bind_int(stmt, 1, key_pair_id_1);
    sqlite3_bind_int(stmt, 2, key_pair_id_2);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);

    return sqlite3_last_insert_rowid(db);
}

sqlite_int64 insert_signed_pre_key(Skissm__SignedPreKey *signed_pre_key) {
    sqlite_int64 key_pair_id = insert_key_pair(signed_pre_key->key_pair);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(SIGNED_PRE_KEY_INSERT, &stmt);

    // bind
    sqlite3_bind_int(stmt, 1, signed_pre_key->spk_id);
    sqlite3_bind_int(stmt, 2, key_pair_id);
    sqlite3_bind_blob(stmt, 3, signed_pre_key->signature.data, signed_pre_key->signature.len, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, signed_pre_key->ttl);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);

    return sqlite3_last_insert_rowid(db);
}

sqlite_int64 insert_one_time_pre_key(Skissm__OneTimePreKey *one_time_pre_key) {
    sqlite_int64 key_pair_id = insert_key_pair(one_time_pre_key->key_pair);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ONETIME_PRE_KEY_INSERT, &stmt);

    // bind
    sqlite3_bind_int(stmt, 1, one_time_pre_key->opk_id);
    sqlite3_bind_int(stmt, 2, one_time_pre_key->used);
    sqlite3_bind_int(stmt, 3, key_pair_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);

    return sqlite3_last_insert_rowid(db);
}

sqlite_int64 insert_account(uint64_t account_id, const char *version, protobuf_c_boolean saved,
                            sqlite_int64 address_id, const char *password, const char *e2ee_pack_id,
                            sqlite_int64 identity_key_pair_id, sqlite_int64 signed_pre_key_id,
                            sqlite_int64 next_one_time_pre_key_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_INSERT, &stmt);

    // bind
    sqlite3_bind_int64(stmt, 1, account_id);
    sqlite3_bind_text(stmt, 2, version, strlen(version), NULL);
    sqlite3_bind_int(stmt, 3, (int)saved);
    sqlite3_bind_int(stmt, 4, address_id);
    sqlite3_bind_text(stmt, 5, password, strlen(password), NULL);
    sqlite3_bind_text(stmt, 6, e2ee_pack_id, strlen(e2ee_pack_id), NULL);
    sqlite3_bind_int(stmt, 7, identity_key_pair_id);
    sqlite3_bind_int(stmt, 8, signed_pre_key_id);
    sqlite3_bind_int(stmt, 9, next_one_time_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);

    return sqlite3_last_insert_rowid(db);
}

void insert_account_identity_key_id(uint64_t account_id, sqlite_int64 identity_key_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_IDENTITY_KEY_INSERT, &stmt);

    // bind
    sqlite3_bind_int(stmt, 1, account_id);
    sqlite3_bind_int(stmt, 2, identity_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

void insert_account_signed_pre_key_id(uint64_t account_id, sqlite_int64 signed_pre_key_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_SIGNED_PRE_KEY_INSERT, &stmt);

    // bind
    sqlite3_bind_int(stmt, 1, account_id);
    sqlite3_bind_int(stmt, 2, signed_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

void insert_account_one_time_pre_key_id(uint64_t account_id, sqlite_int64 one_time_pre_key_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_ONETIME_PRE_KEY_INSERT, &stmt);

    // bind
    sqlite3_bind_int(stmt, 1, account_id);
    sqlite3_bind_int(stmt, 2, one_time_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

void update_identity_key(uint64_t account_id,
                         Skissm__IdentityKey *identity_key) {
    sqlite_int64 identity_key_id = insert_identity_key(identity_key);

    insert_account_identity_key_id(account_id, identity_key_id);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_UPDATE_IDENTITY_KEY, &stmt);

    // bind
    sqlite3_bind_int(stmt, 1, identity_key_id);
    sqlite3_bind_int64(stmt, 2, account_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

void update_signed_pre_key(uint64_t account_id,
                           Skissm__SignedPreKey *signed_pre_key) {
    sqlite_int64 signed_pre_key_id = insert_signed_pre_key(signed_pre_key);

    insert_account_signed_pre_key_id(account_id, signed_pre_key_id);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_UPDATE_SIGNED_PRE_KEY, &stmt);

    // bind
    sqlite3_bind_int(stmt, 1, signed_pre_key_id);
    sqlite3_bind_int64(stmt, 2, account_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

void load_signed_pre_key(uint64_t account_id, uint32_t spk_id,
                         Skissm__SignedPreKey **signed_pre_key) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(LOAD_OLD_SIGNED_PRE_KEY, &stmt);
    sqlite3_bind_int64(stmt, 1, account_id);
    sqlite3_bind_int(stmt, 2, spk_id);

    // step
    if (!sqlite_step(stmt, SQLITE_ROW)) {
        *signed_pre_key = NULL;
        sqlite_finalize(stmt);
        return;
    }

    // allocate memory
    *signed_pre_key =
        (Skissm__SignedPreKey *)malloc(sizeof(Skissm__SignedPreKey));
    skissm__signed_pre_key__init(*signed_pre_key);

    Skissm__KeyPair *key_pair =
        (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(key_pair);
    (*signed_pre_key)->key_pair = key_pair;

    // load
    (*signed_pre_key)->spk_id = (uint32_t)sqlite3_column_int(stmt, 0);
    copy_protobuf_from_array(&((*signed_pre_key)->key_pair->public_key), (uint8_t *)sqlite3_column_blob(stmt, 1),
                             sqlite3_column_bytes(stmt, 1));
    copy_protobuf_from_array(&((*signed_pre_key)->key_pair->private_key), (uint8_t *)sqlite3_column_blob(stmt, 2),
                             sqlite3_column_bytes(stmt, 2));
    copy_protobuf_from_array(&((*signed_pre_key)->signature), (uint8_t *)sqlite3_column_blob(stmt, 3),
                             sqlite3_column_bytes(stmt, 3));
    (*signed_pre_key)->ttl = (uint64_t)sqlite3_column_int(stmt, 4);

    // release
    sqlite_finalize(stmt);
}

static void delete_signed_pre_key(sqlite_int64 signed_pre_key_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(SIGNED_PRE_KEY_DELETE, &stmt);
    sqlite3_bind_int(stmt, 1, signed_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

static void delete_account_signed_pre_key(uint64_t account_id, sqlite_int64 signed_pre_key_id){
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_SIGNED_PRE_KEY_DELETE, &stmt);
    sqlite3_bind_int(stmt, 1, account_id);
    sqlite3_bind_int(stmt, 2, signed_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

void remove_expired_signed_pre_key(uint64_t account_id) {
    // delete old signed pre-keys and keep last two
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_SIGNED_PRE_KEY_SELECT_MORE_THAN_2, &stmt);
    sqlite3_bind_int(stmt, 1, account_id);

    // step
    while (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite_int64 signed_pre_key_id = sqlite3_column_int(stmt, 0);
        delete_signed_pre_key(signed_pre_key_id);
        delete_account_signed_pre_key(account_id, signed_pre_key_id);
    }

    // release
    sqlite_finalize(stmt);
}

void update_address(uint64_t account_id,
                    Skissm__E2eeAddress *address) {
    int address_id = insert_address(address);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_UPDATE_ADDRESS, &stmt);

    // bind
    sqlite3_bind_int(stmt, 1, address_id);
    sqlite3_bind_int64(stmt, 2, account_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

void add_one_time_pre_key(uint64_t account_id,
                          Skissm__OneTimePreKey *one_time_pre_key) {
    int one_time_pre_key_id = insert_one_time_pre_key(one_time_pre_key);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_ONETIME_PRE_KEY_INSERT, &stmt);

    // bind
    sqlite3_bind_int64(stmt, 1, account_id);
    sqlite3_bind_int(stmt, 2, one_time_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

static void delete_one_time_pre_key(sqlite_int64 one_time_pre_key_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ONETIME_PRE_KEY_DELETE, &stmt);
    sqlite3_bind_int(stmt, 1, one_time_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

static void delete_account_one_time_pre_key(uint64_t account_id, sqlite_int64 one_time_pre_key_id){
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_ONETIME_PRE_KEY_DELETE, &stmt);
    sqlite3_bind_int(stmt, 1, account_id);
    sqlite3_bind_int(stmt, 2, one_time_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

void remove_one_time_pre_key(uint64_t account_id, uint32_t one_time_pre_key_id){
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_ONETIME_PRE_KEY, &stmt);

    // bind
    sqlite3_bind_int64(stmt, 1, account_id);
    sqlite3_bind_int(stmt, 2, one_time_pre_key_id);

    // step
    if ((sqlite3_step(stmt) != SQLITE_DONE)){
        sqlite_int64 id = sqlite3_column_int(stmt, 0);
        delete_one_time_pre_key(id);
        delete_account_one_time_pre_key(account_id, id);
    }

    // release
    sqlite_finalize(stmt);
}

static void mark_one_time_pre_key_as_used(sqlite_int64 one_time_pre_key_id){
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ONETIME_PRE_KEY_UPDATE_USED, &stmt);

    // bind
    sqlite3_bind_int(stmt, 1, one_time_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

void update_one_time_pre_key(uint64_t account_id, uint32_t one_time_pre_key_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_ONETIME_PRE_KEY, &stmt);

    // bind
    sqlite3_bind_int64(stmt, 1, account_id);
    sqlite3_bind_int(stmt, 2, one_time_pre_key_id);

    // step
    if ((sqlite3_step(stmt) != SQLITE_DONE)){
        sqlite_int64 id = sqlite3_column_int(stmt, 0);
        mark_one_time_pre_key_as_used(id);
    }

    // release
    sqlite_finalize(stmt);
}

void store_account(Skissm__Account *account) {
    // insert address
    sqlite_int64 address_id = insert_address(account->address);

    // insert identity_key
    sqlite_int64 identity_key_pair_id = insert_identity_key(account->identity_key);

    // insert signed_pre_key
    sqlite_int64 signed_pre_key_id = insert_signed_pre_key(account->signed_pre_key);

    // insert one_time_pre_keys
    sqlite_int64 one_time_pre_key_ids[account->n_one_time_pre_keys];
    for (int i = 0; i < account->n_one_time_pre_keys; i++) {
        one_time_pre_key_ids[i] = insert_one_time_pre_key(account->one_time_pre_keys[i]);
    }

    // insert account
    sqlite_int64 account_id = account->account_id;
    insert_account(account_id, account->version, account->saved, address_id, account->password, account->e2ee_pack_id,
                   identity_key_pair_id, signed_pre_key_id, account->next_one_time_pre_key_id);

    // insert ACCOUNT_SIGNED_PRE_KEY_PAIR
    insert_account_signed_pre_key_id(account_id, signed_pre_key_id);

    // insert ACCOUNT_ONE_TIME_PRE_KEY_PAIR
    for (int i = 0; i < account->n_one_time_pre_keys; i++) {
        insert_account_one_time_pre_key_id(account_id, one_time_pre_key_ids[i]);
    }
}

void load_account(uint64_t account_id, Skissm__Account **account) {
    *account = (Skissm__Account *)malloc(sizeof(Skissm__Account));
    skissm__account__init((*account));

    (*account)->account_id = account_id;
    (*account)->version = load_version(account_id);
    (*account)->saved = load_saved(account_id);
    (*account)->e2ee_pack_id = load_e2ee_pack_id(account_id);
    load_address(account_id, &((*account)->address));
    load_password(account_id, (*account)->password);

    load_signed_pre_key_pair(account_id, &((*account)->signed_pre_key));
    load_identity_key_pair(account_id, &((*account)->identity_key));
    (*account)->n_one_time_pre_keys = load_one_time_pre_keys(account_id, &((*account)->one_time_pre_keys));
    (*account)->next_one_time_pre_key_id = load_next_one_time_pre_key_id(account_id);
}

void load_account_by_address(Skissm__E2eeAddress *address, Skissm__Account **account) {
    sqlite_int64 account_id;
    load_id_by_address(address, &account_id);
    load_account(account_id, account);
}

size_t load_accounts(Skissm__Account ***accounts) {
    // load all account_ids
    sqlite_int64 *account_ids;
    size_t num = load_ids(&account_ids);

    // load all account by account_ids
    if (num == 0) {
        *accounts = NULL;
    } else {
        *accounts = (Skissm__Account **)malloc(sizeof(Skissm__Account *) * num);
        for (int i = 0; i < num; i++) {
            load_account(account_ids[i], &(*accounts)[i]);
        }

        // release account_ids array
        free(account_ids);
    }

    // done
    return num;
}

// session related handlers
void load_inbound_session(char *session_id, Skissm__E2eeAddress *owner,
                          Skissm__Session **session) {
    // prepare
    sqlite3_stmt *stmt;
    if (!sqlite_prepare(SESSION_LOAD_DATA_BY_ID_AND_OWNER, &stmt)) {
        *session = NULL;
        return;
    }

    // bind
    sqlite3_bind_text(stmt, 1, session_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, owner->user->user_id, -1, SQLITE_TRANSIENT);

    // step
    if (!sqlite_step(stmt, SQLITE_ROW)) {
        *session = NULL;
        sqlite_finalize(stmt);
        return;
    }

    // load
    size_t session_data_len = sqlite3_column_bytes(stmt, 0);
    uint8_t *session_data = (uint8_t *)sqlite3_column_blob(stmt, 0);

    // no data
    if (session_data_len == 0) {
        *session = NULL;
        sqlite_finalize(stmt);
        return;
    }

    // unpack
    *session = skissm__session__unpack(NULL, session_data_len, session_data);

    // release
    sqlite_finalize(stmt);

    return;
}

// return the lastest updated session
void load_outbound_session(Skissm__E2eeAddress *owner,
                           Skissm__E2eeAddress *to,
                           Skissm__Session **session) {
    // prepare
    sqlite3_stmt *stmt;
    if (!sqlite_prepare(SESSION_LOAD_DATA_BY_OWNER_AND_TO, &stmt)) {
        *session = NULL;
        return;
    }

    // bind
    sqlite3_bind_text(stmt, 1, owner->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, to->user->user_id, -1, SQLITE_TRANSIENT);

    // step
    if (!sqlite_step(stmt, SQLITE_ROW)) {
        *session = NULL;
        sqlite_finalize(stmt);
        return;
    }

    // load
    size_t session_data_len = sqlite3_column_bytes(stmt, 0);
    uint8_t *session_data = (uint8_t *)sqlite3_column_blob(stmt, 0);

    // no data
    if (session_data_len == 0) {
        *session = NULL;
        sqlite_finalize(stmt);
        return;
    }

    // unpack
    *session = skissm__session__unpack(NULL, session_data_len, session_data);

    // release
    sqlite_finalize(stmt);

    return;
}

int load_n_outbound_sessions(Skissm__E2eeAddress *owner, const char *to_user_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(SESSION_LOAD_N_OUTBOUND_SESSION, &stmt);
    sqlite3_bind_text(stmt, 1, owner->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, to_user_id, -1, SQLITE_TRANSIENT);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    int n_outbound_sessions = (int)sqlite3_column_int(stmt, 0);

    // release
    sqlite_finalize(stmt);

    return n_outbound_sessions;
}

size_t load_outbound_sessions(Skissm__E2eeAddress *owner,
                              const char *to_user_id,
                              Skissm__Session ***outbound_sessions) {
    // allocate memory
    size_t n_outbound_sessions = load_n_outbound_sessions(owner, to_user_id);
    (*outbound_sessions) = (Skissm__Session **)malloc(
        n_outbound_sessions * sizeof(Skissm__Session *));

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(SESSION_LOAD_OUTBOUND_SESSIONS, &stmt);
    sqlite3_bind_text(stmt, 1, owner->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, to_user_id, -1, SQLITE_TRANSIENT);

    // step
    for (int i = 0; i < n_outbound_sessions; i++) {
        sqlite3_step(stmt);

        // load
        size_t session_data_len = sqlite3_column_bytes(stmt, 0);
        uint8_t *session_data = (uint8_t *)sqlite3_column_blob(stmt, 0);

        // unpack
        (*outbound_sessions)[i] = skissm__session__unpack(NULL, session_data_len, session_data);
    }

    // release
    sqlite_finalize(stmt);

    return n_outbound_sessions;
}

void store_session(Skissm__Session *session) {
    // pack
    char *session_id = session->session_id;
    size_t session_data_len = skissm__session__get_packed_size(session);
    uint8_t *session_data = (uint8_t *)malloc(session_data_len);
    skissm__session__pack(session, session_data);

    sqlite_int64 owner_id = insert_address(session->session_owner);
    sqlite_int64 from_id = insert_address(session->from);
    sqlite_int64 to_id = insert_address(session->to);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(SESSION_INSERT_OR_REPLACE, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, session_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, owner_id);
    sqlite3_bind_int(stmt, 3, from_id);
    sqlite3_bind_int(stmt, 4, to_id);
    sqlite3_bind_blob(stmt, 5, session_data, session_data_len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
    free_mem((void **)(&session_data), session_data_len);
}

void unload_session(Skissm__E2eeAddress *owner, Skissm__E2eeAddress *from,
                    Skissm__E2eeAddress *to) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(SESSION_DELETE_DATA_BY_OWNER_FROM_AND_TO, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, owner->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, from->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, to->user->user_id, -1, SQLITE_TRANSIENT);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

// return the first signature which is not null
void load_outbound_group_session(Skissm__E2eeAddress *sender_address,
                                 Skissm__E2eeAddress *group_address,
                                 Skissm__GroupSession **group_session) {
    // prepare
    sqlite3_stmt *stmt;
    if (!sqlite_prepare(GROUP_SESSION_LOAD_OUTBOUND, &stmt)) {
        *group_session = NULL;
        return;
    }

    // bind
    sqlite3_bind_text(stmt, 1, sender_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, sender_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, sender_address->user->device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, group_address->group->group_id, -1, SQLITE_TRANSIENT);

    // step
    if (!sqlite_step(stmt, SQLITE_ROW)) {
        *group_session = NULL;
        sqlite_finalize(stmt);
        return;
    }

    // load
    size_t group_session_data_len = sqlite3_column_bytes(stmt, 0);
    uint8_t *group_session_data = (uint8_t *)sqlite3_column_blob(stmt, 0);

    // no data
    if (group_session_data_len == 0) {
        *group_session = NULL;
        sqlite_finalize(stmt);
        return;
    }

    // unpack
    *group_session =
        skissm__group_session__unpack(NULL, group_session_data_len, group_session_data);

    // release
    sqlite_finalize(stmt);

    return;
}

void load_inbound_group_session(Skissm__E2eeAddress *receiver_address,
                                Skissm__E2eeAddress *group_address,
                                Skissm__GroupSession **group_session) {
    // prepare
    sqlite3_stmt *stmt;
    if (!sqlite_prepare(GROUP_SESSION_LOAD_INBOUND, &stmt)) {
        *group_session = NULL;
        return;
    }

    // bind
    sqlite3_bind_text(stmt, 1, receiver_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, receiver_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, receiver_address->user->device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, group_address->group->group_id, -1, SQLITE_TRANSIENT);
    // step
    if (!sqlite_step(stmt, SQLITE_ROW)) {
        *group_session = NULL;
        sqlite_finalize(stmt);
        return;
    }

    // load
    size_t group_session_data_len = sqlite3_column_bytes(stmt, 0);
    uint8_t *group_session_data = (uint8_t *)sqlite3_column_blob(stmt, 0);

    // no data
    if (group_session_data_len == 0) {
        *group_session = NULL;
        sqlite_finalize(stmt);
        return;
    }

    // unpack
    *group_session =
        skissm__group_session__unpack(NULL, group_session_data_len, group_session_data);

    // release
    sqlite_finalize(stmt);

    return;
}

void store_group_session(Skissm__GroupSession *group_session) {
    // pack
    size_t group_session_data_len = skissm__group_session__get_packed_size(group_session);
    uint8_t *group_session_data = (uint8_t *)malloc(group_session_data_len);
    skissm__group_session__pack(group_session, group_session_data);

    int owner_id = insert_address(group_session->session_owner);
    int address_id = insert_address(group_session->group_address);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(GROUP_SESSION_INSERT_OR_REPLACE, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, group_session->session_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, owner_id);
    sqlite3_bind_int(stmt, 3, address_id);
    sqlite3_bind_blob(stmt, 4, group_session_data, group_session_data_len, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, group_session->signature_private_key.len ? 1 : 0);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
    free_mem((void **)(&group_session_data), group_session_data_len);
}

void unload_group_session(Skissm__GroupSession *group_session) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(GROUP_SESSION_DELETE_DATA_BY_OWNER_AND_ADDRESS, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, group_session->session_owner->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, group_session->group_address->group->group_id, -1, SQLITE_TRANSIENT);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

void unload_inbound_group_session(Skissm__E2eeAddress *receiver_address,
                                  char *session_id) {
    if (session_id == NULL){
        return;
    }
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(GROUP_SESSION_DELETE_DATA_BY_OWNER_AND_ID, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, receiver_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, session_id, -1, SQLITE_TRANSIENT);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

void store_group_pre_key(Skissm__E2eeAddress *member_address,
                         uint8_t *group_pre_key_plaintext,
                         size_t group_pre_key_plaintext_len) {
    // insert member's address
    int member_address_id = insert_address(member_address);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(PENDING_GROUP_PRE_KEY_INSERT, &stmt);

    // bind
    sqlite3_bind_int(stmt, 1, member_address_id);
    sqlite3_bind_blob(stmt, 2, group_pre_key_plaintext, group_pre_key_plaintext_len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

int load_n_group_pre_keys(Skissm__E2eeAddress *member_address) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(N_PENDING_GROUP_PRE_KEY_LOAD, &stmt);
    sqlite3_bind_text(stmt, 1, member_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, member_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, member_address->user->device_id, -1, SQLITE_TRANSIENT);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    int n_group_pre_keys = (int)sqlite3_column_int(stmt, 0);

    // release
    sqlite_finalize(stmt);

    return n_group_pre_keys;
}

size_t load_group_pre_keys(Skissm__E2eeAddress *member_address,
    uint8_t ***e2ee_plaintext_data_list,
    size_t **e2ee_plaintext_data_len_list) {
    // allocate memory
    size_t n_group_pre_keys = load_n_group_pre_keys(member_address);
    if (n_group_pre_keys == 0){
        *e2ee_plaintext_data_list = NULL;
        *e2ee_plaintext_data_len_list = NULL;
        return 0;
    }
    (*e2ee_plaintext_data_list) = (uint8_t **)malloc(n_group_pre_keys * sizeof(uint8_t *));

    *e2ee_plaintext_data_len_list = (size_t *)malloc(n_group_pre_keys * sizeof(size_t));

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(PENDING_GROUP_PRE_KEY_LOAD, &stmt);
    sqlite3_bind_text(stmt, 1, member_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, member_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, member_address->user->device_id, -1, SQLITE_TRANSIENT);

    // step
    for (int i = 0; i < n_group_pre_keys; i++) {
        sqlite3_step(stmt);

        // load
        size_t e2ee_plaintext_data_len = sqlite3_column_bytes(stmt, 0);
        uint8_t *e2ee_plaintext_data = (uint8_t *)sqlite3_column_blob(stmt, 0);

        // assign
        (*e2ee_plaintext_data_list)[i] = (uint8_t *)malloc(e2ee_plaintext_data_len * sizeof(uint8_t));
        memcpy((*e2ee_plaintext_data_list)[i], e2ee_plaintext_data, e2ee_plaintext_data_len);
        (*e2ee_plaintext_data_len_list)[i] = e2ee_plaintext_data_len;
    }

    // release
    sqlite_finalize(stmt);

    return n_group_pre_keys;
}

void unload_group_pre_key(Skissm__E2eeAddress *member_address) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(PENDING_GROUP_PRE_KEY_DELETE_DATA, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, member_address->user->user_id, -1, SQLITE_TRANSIENT);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}
