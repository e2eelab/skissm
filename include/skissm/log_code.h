/**
 * @file
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
#ifndef LOG_CODE_H_
#define LOG_CODE_H_

#ifdef __cplusplus
extern "C" {
#endif

enum LogCode {
  DEBUG_LOG = 0,

  BAD_CIPHER_SUITE = 1001,
  BAD_E2EE_PACK = 1002,

  BAD_ACCOUNT = 2001,
  BAD_KEY_PAIR = 2002,
  BAD_SIGNED_PRE_KEY = 2003,
  BAD_SIGNATURE = 2004,
  BAD_ONE_TIME_PRE_KEY = 2005,
  BAD_AUTH = 2006,
  BAD_AUTHENTICATOR = 2007,
  BAD_PRIVATE_KEY = 2008,
  BAD_PUBLIC_KEY = 2009,
  BAD_REMOVE_OPK = 2010,

  BAD_ADDRESS = 3001,
  BAD_USER_ID = 3002,
  BAD_DEVICE_ID = 3003,
  BAD_DOMAIN = 3004,
  BAD_USER_NAME = 3005,

  BAD_MESSAGE_ENCRYPTION = 4001,
  BAD_MESSAGE_DECRYPTION = 4002,
  BAD_FILE_ENCRYPTION = 4003,
  BAD_FILE_DECRYPTION = 4004,
  BAD_MESSAGE_KEY = 4005,
  BAD_MESSAGE_SEQUENCE = 4006,

  BAD_SESSION = 5001,

  BAD_GROUP_SESSION = 6001,

  BAD_PRE_KEY_BUNDLE = 7001,
  BAD_MESSAGE_FORMAT = 7002,
  BAD_RESPONSE = 7003,
  BAD_SERVER_MESSAGE = 7004,
  BAD_SERVER_SIGNATURE = 7005,
  BAD_INPUT_DATA = 7006,

  NOT_ENOUGH_RANDOM = 10001,
  NOT_ENOUGH_MEMORY = 10002,
  NOT_ENOUGH_SPACE = 10003
};

typedef enum LogCode LogCode;

/**
 * @brief Get the string representation of a given log code.
 *
 * @param log_code The log code
 * @return The log code string
 */
const char *logcode_string(LogCode log_code);

#ifdef __cplusplus
}
#endif

#endif /* LOG_CODE_H_ */
