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
#ifndef ERROR_H_
#define ERROR_H_

#ifdef __cplusplus
extern "C" {
#endif

enum ErrorCode {
  SUCCESS = 0,
  BAD_ACCOUNT = 1,
  BAD_SESSION = 2,
  BAD_GROUP_SESSION = 3,
  BAD_SIGNATURE = 4,
  BAD_PRE_KEY_BUNDLE = 5,
  BAD_SERVER_MESSAGE = 6,
  BAD_REMOVE_OPK = 7,
  BAD_MESSAGE_VERSION = 8,
  BAD_MESSAGE_FORMAT = 9,
  BAD_MESSAGE_MAC = 10,
  BAD_MESSAGE_SEQUENCE = 11,
  MESSAGE_KEY_NOT_FOUND = 12,
  BAD_SIGN_KEY = 13,
  BAD_SIGNED_PRE_KEY = 14,
  BAD_ONE_TIME_PRE_KEY = 15,
  BAD_MESSAGE_ENCRYPTION = 16,
  BAD_MESSAGE_DECRYPTION = 17,
  NOT_ENOUGH_RANDOM = 18,
  NOT_ENOUGH_MEMORY = 19,
  NOT_ENOUGH_SPACE = 20
};

typedef enum ErrorCode ErrorCode;

/**
 * @brief Get the string representation of a given error code.
 *
 * @param error_code The error code
 * @return The error string
 */
const char *error_string(ErrorCode error_code);

#ifdef __cplusplus
}
#endif

#endif /* ERROR_H_ */
