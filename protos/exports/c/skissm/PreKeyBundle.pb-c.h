/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: PreKeyBundle.proto */

#ifndef PROTOBUF_C_PreKeyBundle_2eproto__INCLUDED
#define PROTOBUF_C_PreKeyBundle_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1004000 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "skissm/E2eeAddress.pb-c.h"
#include "skissm/IdentityKeyPublic.pb-c.h"
#include "skissm/SignedPreKeyPublic.pb-c.h"
#include "skissm/OneTimePreKeyPublic.pb-c.h"

typedef struct Skissm__PreKeyBundle Skissm__PreKeyBundle;


/* --- enums --- */


/* --- messages --- */

struct  Skissm__PreKeyBundle
{
  ProtobufCMessage base;
  Skissm__E2eeAddress *peer_address;
  char *e2ee_pack_id;
  Skissm__IdentityKeyPublic *identity_key_public;
  Skissm__SignedPreKeyPublic *signed_pre_key_public;
  Skissm__OneTimePreKeyPublic *one_time_pre_key_public;
};
#define SKISSM__PRE_KEY_BUNDLE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&skissm__pre_key_bundle__descriptor) \
    , NULL, (char *)protobuf_c_empty_string, NULL, NULL, NULL }


/* Skissm__PreKeyBundle methods */
void   skissm__pre_key_bundle__init
                     (Skissm__PreKeyBundle         *message);
size_t skissm__pre_key_bundle__get_packed_size
                     (const Skissm__PreKeyBundle   *message);
size_t skissm__pre_key_bundle__pack
                     (const Skissm__PreKeyBundle   *message,
                      uint8_t             *out);
size_t skissm__pre_key_bundle__pack_to_buffer
                     (const Skissm__PreKeyBundle   *message,
                      ProtobufCBuffer     *buffer);
Skissm__PreKeyBundle *
       skissm__pre_key_bundle__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   skissm__pre_key_bundle__free_unpacked
                     (Skissm__PreKeyBundle *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Skissm__PreKeyBundle_Closure)
                 (const Skissm__PreKeyBundle *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor skissm__pre_key_bundle__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_PreKeyBundle_2eproto__INCLUDED */