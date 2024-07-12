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
#ifndef LOG_CODE_H_
#define LOG_CODE_H_

#ifdef __cplusplus
extern "C" {
#endif

enum LogCode {
  DEBUG_LOG = 0,
  BAD_ACCOUNT = 1,
  BAD_ADDRESS = 31,
  BAD_AUTH = 2,
  BAD_AUTHENTICATOR = 3,
  BAD_CIPHER_SUITE = 4,
  BAD_DEVICE_ID = 5,
  BAD_DOMAIN = 32,
  BAD_E2EE_PACK = 6,
  BAD_FILE_DECRYPTION = 7,
  BAD_FILE_ENCRYPTION = 8,
  BAD_GROUP_SESSION = 9,
  BAD_INPUT_DATA = 33,
  BAD_KEY_PAIR = 40,
  BAD_MESSAGE_DECRYPTION = 10,
  BAD_MESSAGE_ENCRYPTION = 11,
  BAD_MESSAGE_FORMAT = 12,
  BAD_MESSAGE_KEY = 13,
  BAD_MESSAGE_MAC = 14,
  BAD_MESSAGE_SEQUENCE = 15,
  BAD_MESSAGE_VERSION = 16,
  BAD_ONE_TIME_PRE_KEY = 17,
  BAD_PRE_KEY_BUNDLE = 18,
  BAD_REMOVE_OPK = 19,
  BAD_RESPONSE = 30,
  BAD_SERVER_MESSAGE = 20,
  BAD_SERVER_SIGNATURE = 50,
  BAD_SESSION = 21,
  BAD_SIGN_KEY = 22,
  BAD_SIGNATURE = 23,
  BAD_SIGNED_PRE_KEY = 24,
  BAD_USER_ID = 25,
  BAD_USER_NAME = 26,
  NOT_ENOUGH_RANDOM = 27,
  NOT_ENOUGH_MEMORY = 28,
  NOT_ENOUGH_SPACE = 29
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
