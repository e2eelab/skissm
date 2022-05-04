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
  BAD_SIGNATURE = 3,
  BAD_PRE_KEY_BUNDLE = 4,
  BAD_SERVER_MESSAGE = 5,
  NOT_ENOUGH_RANDOM = 6,
  NOT_ENOUGH_MEMORY = 7,
  NOT_ENOUGH_SPACE = 8,
  ERROR_REMOVE_OPK = 9,
  BAD_MESSAGE_VERSION = 10,
  BAD_MESSAGE_FORMAT = 11,
  BAD_MESSAGE_MAC = 12,
  BAD_MESSAGE_SEQUENCE = 13,
  BAD_SIGNED_PRE_KEY = 14,
  BAD_ONE_TIME_PRE_KEY = 15,
  BAD_MESSAGE_ENCRYPTION = 16,
  BAD_MESSAGE_DECRYPTION = 17,
  BAD_GROUP_SESSION = 18
};

typedef enum ErrorCode ErrorCode;

/**
 * @brief Get the string representation of a given error code.
 *
 * @param error The error code
 * @return The error string
 */
const char *error_string(ErrorCode error_code);

#ifdef __cplusplus
}
#endif

#endif /* ERROR_H_ */
