/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: E2eeMsg.proto */

#ifndef PROTOBUF_C_E2eeMsg_2eproto__INCLUDED
#define PROTOBUF_C_E2eeMsg_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1004000 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "skissm/E2eeAddress.pb-c.h"
#include "skissm/One2oneMsgPayload.pb-c.h"
#include "skissm/GroupMsgPayload.pb-c.h"

typedef struct Skissm__E2eeMsg Skissm__E2eeMsg;


/* --- enums --- */


/* --- messages --- */

typedef enum {
  SKISSM__E2EE_MSG__PAYLOAD__NOT_SET = 0,
  SKISSM__E2EE_MSG__PAYLOAD_ONE2ONE_MSG = 6,
  SKISSM__E2EE_MSG__PAYLOAD_GROUP_MSG = 7
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(SKISSM__E2EE_MSG__PAYLOAD__CASE)
} Skissm__E2eeMsg__PayloadCase;

struct  Skissm__E2eeMsg
{
  ProtobufCMessage base;
  char *version;
  Skissm__E2eeAddress *from;
  Skissm__E2eeAddress *to;
  char *msg_id;
  char *session_id;
  Skissm__E2eeMsg__PayloadCase payload_case;
  union {
    Skissm__One2oneMsgPayload *one2one_msg;
    Skissm__GroupMsgPayload *group_msg;
  };
};
#define SKISSM__E2EE_MSG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&skissm__e2ee_msg__descriptor) \
    , (char *)protobuf_c_empty_string, NULL, NULL, (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string, SKISSM__E2EE_MSG__PAYLOAD__NOT_SET, {0} }


/* Skissm__E2eeMsg methods */
void   skissm__e2ee_msg__init
                     (Skissm__E2eeMsg         *message);
size_t skissm__e2ee_msg__get_packed_size
                     (const Skissm__E2eeMsg   *message);
size_t skissm__e2ee_msg__pack
                     (const Skissm__E2eeMsg   *message,
                      uint8_t             *out);
size_t skissm__e2ee_msg__pack_to_buffer
                     (const Skissm__E2eeMsg   *message,
                      ProtobufCBuffer     *buffer);
Skissm__E2eeMsg *
       skissm__e2ee_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   skissm__e2ee_msg__free_unpacked
                     (Skissm__E2eeMsg *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Skissm__E2eeMsg_Closure)
                 (const Skissm__E2eeMsg *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor skissm__e2ee_msg__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_E2eeMsg_2eproto__INCLUDED */