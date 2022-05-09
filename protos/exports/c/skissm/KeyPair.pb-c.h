/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: KeyPair.proto */

#ifndef PROTOBUF_C_KeyPair_2eproto__INCLUDED
#define PROTOBUF_C_KeyPair_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1004000 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct Skissm__KeyPair Skissm__KeyPair;


/* --- enums --- */


/* --- messages --- */

struct  Skissm__KeyPair
{
  ProtobufCMessage base;
  ProtobufCBinaryData public_key;
  ProtobufCBinaryData private_key;
};
#define SKISSM__KEY_PAIR__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&skissm__key_pair__descriptor) \
    , {0,NULL}, {0,NULL} }


/* Skissm__KeyPair methods */
void   skissm__key_pair__init
                     (Skissm__KeyPair         *message);
size_t skissm__key_pair__get_packed_size
                     (const Skissm__KeyPair   *message);
size_t skissm__key_pair__pack
                     (const Skissm__KeyPair   *message,
                      uint8_t             *out);
size_t skissm__key_pair__pack_to_buffer
                     (const Skissm__KeyPair   *message,
                      ProtobufCBuffer     *buffer);
Skissm__KeyPair *
       skissm__key_pair__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   skissm__key_pair__free_unpacked
                     (Skissm__KeyPair *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Skissm__KeyPair_Closure)
                 (const Skissm__KeyPair *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor skissm__key_pair__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_KeyPair_2eproto__INCLUDED */