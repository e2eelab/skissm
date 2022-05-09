/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: InviteMsg.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "InviteMsg.pb-c.h"
void   skissm__invite_msg__init
                     (Skissm__InviteMsg         *message)
{
  static const Skissm__InviteMsg init_value = SKISSM__INVITE_MSG__INIT;
  *message = init_value;
}
size_t skissm__invite_msg__get_packed_size
                     (const Skissm__InviteMsg *message)
{
  assert(message->base.descriptor == &skissm__invite_msg__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t skissm__invite_msg__pack
                     (const Skissm__InviteMsg *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &skissm__invite_msg__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t skissm__invite_msg__pack_to_buffer
                     (const Skissm__InviteMsg *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &skissm__invite_msg__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Skissm__InviteMsg *
       skissm__invite_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Skissm__InviteMsg *)
     protobuf_c_message_unpack (&skissm__invite_msg__descriptor,
                                allocator, len, data);
}
void   skissm__invite_msg__free_unpacked
                     (Skissm__InviteMsg *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &skissm__invite_msg__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor skissm__invite_msg__field_descriptors[9] =
{
  {
    "version",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Skissm__InviteMsg, version),
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
    offsetof(Skissm__InviteMsg, e2ee_pack_id),
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
    offsetof(Skissm__InviteMsg, session_id),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "from",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Skissm__InviteMsg, from),
    &skissm__e2ee_address__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "to",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Skissm__InviteMsg, to),
    &skissm__e2ee_address__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "alice_identity_key",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Skissm__InviteMsg, alice_identity_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "pre_shared_keys",
    7,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_BYTES,
    offsetof(Skissm__InviteMsg, n_pre_shared_keys),
    offsetof(Skissm__InviteMsg, pre_shared_keys),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "bob_signed_pre_key_id",
    8,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(Skissm__InviteMsg, bob_signed_pre_key_id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "bob_one_time_pre_key_id",
    9,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(Skissm__InviteMsg, bob_one_time_pre_key_id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned skissm__invite_msg__field_indices_by_name[] = {
  5,   /* field[5] = alice_identity_key */
  8,   /* field[8] = bob_one_time_pre_key_id */
  7,   /* field[7] = bob_signed_pre_key_id */
  1,   /* field[1] = e2ee_pack_id */
  3,   /* field[3] = from */
  6,   /* field[6] = pre_shared_keys */
  2,   /* field[2] = session_id */
  4,   /* field[4] = to */
  0,   /* field[0] = version */
};
static const ProtobufCIntRange skissm__invite_msg__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 9 }
};
const ProtobufCMessageDescriptor skissm__invite_msg__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "skissm.InviteMsg",
  "InviteMsg",
  "Skissm__InviteMsg",
  "skissm",
  sizeof(Skissm__InviteMsg),
  9,
  skissm__invite_msg__field_descriptors,
  skissm__invite_msg__field_indices_by_name,
  1,  skissm__invite_msg__number_ranges,
  (ProtobufCMessageInit) skissm__invite_msg__init,
  NULL,NULL,NULL    /* reserved[123] */
};