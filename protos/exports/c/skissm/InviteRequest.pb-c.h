/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: InviteRequest.proto */

#ifndef PROTOBUF_C_InviteRequest_2eproto__INCLUDED
#define PROTOBUF_C_InviteRequest_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1004000 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "skissm/InviteMsg.pb-c.h"

typedef struct Skissm__InviteRequest Skissm__InviteRequest;


/* --- enums --- */


/* --- messages --- */

struct  Skissm__InviteRequest
{
  ProtobufCMessage base;
  Skissm__InviteMsg *msg;
};
#define SKISSM__INVITE_REQUEST__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&skissm__invite_request__descriptor) \
    , NULL }


/* Skissm__InviteRequest methods */
void   skissm__invite_request__init
                     (Skissm__InviteRequest         *message);
size_t skissm__invite_request__get_packed_size
                     (const Skissm__InviteRequest   *message);
size_t skissm__invite_request__pack
                     (const Skissm__InviteRequest   *message,
                      uint8_t             *out);
size_t skissm__invite_request__pack_to_buffer
                     (const Skissm__InviteRequest   *message,
                      ProtobufCBuffer     *buffer);
Skissm__InviteRequest *
       skissm__invite_request__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   skissm__invite_request__free_unpacked
                     (Skissm__InviteRequest *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Skissm__InviteRequest_Closure)
                 (const Skissm__InviteRequest *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor skissm__invite_request__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_InviteRequest_2eproto__INCLUDED */