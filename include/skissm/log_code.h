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
  BAD_E2EE_PACK = 1,
  BAD_ACCOUNT = 2,
  BAD_SESSION = 3,
  BAD_GROUP_SESSION = 4,
  BAD_SIGNATURE = 5,
  BAD_PRE_KEY_BUNDLE = 6,
  BAD_SERVER_MESSAGE = 7,
  BAD_REMOVE_OPK = 8,
  BAD_MESSAGE_VERSION = 9,
  BAD_MESSAGE_FORMAT = 10,
  BAD_MESSAGE_MAC = 11,
  BAD_MESSAGE_SEQUENCE = 12,
  BAD_MESSAGE_KEY = 13,
  BAD_SIGN_KEY = 14,
  BAD_SIGNED_PRE_KEY = 15,
  BAD_ONE_TIME_PRE_KEY = 16,
  BAD_MESSAGE_ENCRYPTION = 17,
  BAD_MESSAGE_DECRYPTION = 18,
  BAD_FILE_ENCRYPTION = 19,
  BAD_FILE_DECRYPTION = 20,
  NOT_ENOUGH_RANDOM = 21,
  NOT_ENOUGH_MEMORY = 22,
  NOT_ENOUGH_SPACE = 23
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
