/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: GroupSession.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "GroupSession.pb-c.h"
void   skissm__group_session__init
                     (Skissm__GroupSession         *message)
{
  static const Skissm__GroupSession init_value = SKISSM__GROUP_SESSION__INIT;
  *message = init_value;
}
size_t skissm__group_session__get_packed_size
                     (const Skissm__GroupSession *message)
{
  assert(message->base.descriptor == &skissm__group_session__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t skissm__group_session__pack
                     (const Skissm__GroupSession *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &skissm__group_session__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t skissm__group_session__pack_to_buffer
                     (const Skissm__GroupSession *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &skissm__group_session__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Skissm__GroupSession *
       skissm__group_session__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Skissm__GroupSession *)
     protobuf_c_message_unpack (&skissm__group_session__descriptor,
                                allocator, len, data);
}
void   skissm__group_session__free_unpacked
                     (Skissm__GroupSession *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &skissm__group_session__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor skissm__group_session__field_descriptors[11] =
{
  {
    "version",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Skissm__GroupSession, version),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "e2ee_pack_id",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Skissm__GroupSession, e2ee_pack_id),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "session_id",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Skissm__GroupSession, session_id),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "session_owner",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Skissm__GroupSession, session_owner),
    &skissm__e2ee_address__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "group_address",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Skissm__GroupSession, group_address),
    &skissm__e2ee_address__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "group_members",
    6,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Skissm__GroupSession, n_group_members),
    offsetof(Skissm__GroupSession, group_members),
    &skissm__group_member__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "sequence",
    7,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(Skissm__GroupSession, sequence),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "chain_key",
    8,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Skissm__GroupSession, chain_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "signature_private_key",
    9,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Skissm__GroupSession, signature_private_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "signature_public_key",
    10,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Skissm__GroupSession, signature_public_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "associated_data",
    11,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Skissm__GroupSession, associated_data),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned skissm__group_session__field_indices_by_name[] = {
  10,   /* field[10] = associated_data */
  7,   /* field[7] = chain_key */
  1,   /* field[1] = e2ee_pack_id */
  4,   /* field[4] = group_address */
  5,   /* field[5] = group_members */
  6,   /* field[6] = sequence */
  2,   /* field[2] = session_id */
  3,   /* field[3] = session_owner */
  8,   /* field[8] = signature_private_key */
  9,   /* field[9] = signature_public_key */
  0,   /* field[0] = version */
};
static const ProtobufCIntRange skissm__group_session__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 11 }
};
const ProtobufCMessageDescriptor skissm__group_session__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "skissm.GroupSession",
  "GroupSession",
  "Skissm__GroupSession",
  "skissm",
  sizeof(Skissm__GroupSession),
  11,
  skissm__group_session__field_descriptors,
  skissm__group_session__field_indices_by_name,
  1,  skissm__group_session__number_ranges,
  (ProtobufCMessageInit) skissm__group_session__init,
  NULL,NULL,NULL    /* reserved[123] */
};