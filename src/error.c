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
#include "skissm/error.h"

static const char * ERROR_STRINGS[] = {
  "SUCCESS",
  "BAD_SESSION",
  "BAD_SIGNATURE",
  "BAD_PRE_KEY_BUNDLE",
  "BAD_SERVER_MESSAGE",
  "NOT_ENOUGH_RANDOM",
  "NOT_ENOUGH_MEMORY",
  "NOT_ENOUGH_SPACE",
  "ERROR_REMOVE_OPK",
  "BAD_MESSAGE_VERSION",
  "BAD_MESSAGE_FORMAT",
  "BAD_MESSAGE_MAC",
  "BAD_MESSAGE_SEQUENCE",
  "BAD_SIGNED_PRE_KEY",
  "BAD_ONE_TIME_PRE_KEY",
  "BAD_MESSAGE_ENCRYPTION",
  "BAD_MESSAGE_DECRYPTION",
  "BAD_GROUP_SESSION",
  "BAD_LOAD_ACCOUNTS",
};

const char *error_string(ErrorCode error_code){
    if (error_code < (sizeof(ERROR_STRINGS)/sizeof(ERROR_STRINGS[0]))) {
        return ERROR_STRINGS[error_code];
    } else {
        return "UNKNOWN_ERROR";
    }
}
