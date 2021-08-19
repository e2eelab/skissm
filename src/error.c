#include "error.h"

static const char * ERROR_STRINGS[] = {
  "SUCCESS",
  "BAD_SESSION_KEY",
  "BAD_SIGNATURE",
  "BAD_PRE_KEY_BUNDLE",
  "BAD_SERVER_MESSAGE",
  "NOT_ENOUGH_RANDOM",
  "NOT_ENOUGH_INPUT_BUFFER",
  "NOT_ENOUGH_OUTPUT_BUFFER",
  "NOT_ENOUGH_SPACE",
  "ERROR_REMOVE_OPK",
  "BAD_MESSAGE_VERSION",
  "BAD_MESSAGE_FORMAT",
  "BAD_MESSAGE_MAC",
  "BAD_MESSAGE_SEQUENCE",
  "BAD_MESSAGE_KEY_ID",
  "BAD_MESSAGE_ENCRYPTION",
  "BAD_MESSAGE_DECRYPTION",
};

const char *error_string(ErrorCode error_code){
    if (error_code < (sizeof(ERROR_STRINGS)/sizeof(ERROR_STRINGS[0]))) {
        return ERROR_STRINGS[error_code];
    } else {
        return "UNKNOWN_ERROR";
    }
}
