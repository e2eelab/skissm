#ifndef ERROR_H_
#define ERROR_H_

enum ErrorCode {
  SUCCESS = 0,
  BAD_SESSION_KEY = 1,
  BAD_SIGNATURE = 2,
  BAD_PRE_KEY_BUNDLE = 3,
  BAD_SERVER_MESSAGE = 4,
  NOT_ENOUGH_RANDOM = 5,
  NOT_ENOUGH_MEMORY = 6,
  NOT_ENOUGH_SPACE = 7,
  ERROR_REMOVE_OPK = 8,
  BAD_MESSAGE_VERSION = 9,
  BAD_MESSAGE_FORMAT = 10,
  BAD_MESSAGE_MAC = 11,
  BAD_MESSAGE_SEQUENCE = 12,
  BAD_MESSAGE_KEY_ID = 13,
  BAD_MESSAGE_ENCRYPTION = 14,
  BAD_MESSAGE_DECRYPTION = 15,
  BAD_GROUP_SESSION = 16,
};

typedef enum ErrorCode ErrorCode;

/**
 * @brief Get the string representation of a given error code.
 *
 * @param error The error code
 * @return The error string
 */
const char *error_string(ErrorCode error);

#endif /* ERROR_H_ */
