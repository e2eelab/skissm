/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: OneTimePreKeyPublic.proto */

#ifndef PROTOBUF_C_OneTimePreKeyPublic_2eproto__INCLUDED
#define PROTOBUF_C_OneTimePreKeyPublic_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1004000 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct Skissm__OneTimePreKeyPublic Skissm__OneTimePreKeyPublic;


/* --- enums --- */


/* --- messages --- */

struct  Skissm__OneTimePreKeyPublic
{
  ProtobufCMessage base;
  uint32_t opk_id;
  ProtobufCBinaryData public_key;
};
#define SKISSM__ONE_TIME_PRE_KEY_PUBLIC__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&skissm__one_time_pre_key_public__descriptor) \
    , 0, {0,NULL} }


/* Skissm__OneTimePreKeyPublic methods */
void   skissm__one_time_pre_key_public__init
                     (Skissm__OneTimePreKeyPublic         *message);
size_t skissm__one_time_pre_key_public__get_packed_size
                     (const Skissm__OneTimePreKeyPublic   *message);
size_t skissm__one_time_pre_key_public__pack
                     (const Skissm__OneTimePreKeyPublic   *message,
                      uint8_t             *out);
size_t skissm__one_time_pre_key_public__pack_to_buffer
                     (const Skissm__OneTimePreKeyPublic   *message,
                      ProtobufCBuffer     *buffer);
Skissm__OneTimePreKeyPublic *
       skissm__one_time_pre_key_public__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   skissm__one_time_pre_key_public__free_unpacked
                     (Skissm__OneTimePreKeyPublic *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Skissm__OneTimePreKeyPublic_Closure)
                 (const Skissm__OneTimePreKeyPublic *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor skissm__one_time_pre_key_public__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_OneTimePreKeyPublic_2eproto__INCLUDED */