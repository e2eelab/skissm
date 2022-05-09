/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: GroupMember.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "GroupMember.pb-c.h"
void   skissm__group_member__init
                     (Skissm__GroupMember         *message)
{
  static const Skissm__GroupMember init_value = SKISSM__GROUP_MEMBER__INIT;
  *message = init_value;
}
size_t skissm__group_member__get_packed_size
                     (const Skissm__GroupMember *message)
{
  assert(message->base.descriptor == &skissm__group_member__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t skissm__group_member__pack
                     (const Skissm__GroupMember *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &skissm__group_member__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t skissm__group_member__pack_to_buffer
                     (const Skissm__GroupMember *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &skissm__group_member__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Skissm__GroupMember *
       skissm__group_member__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Skissm__GroupMember *)
     protobuf_c_message_unpack (&skissm__group_member__descriptor,
                                allocator, len, data);
}
void   skissm__group_member__free_unpacked
                     (Skissm__GroupMember *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &skissm__group_member__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor skissm__group_member__field_descriptors[2] =
{
  {
    "user_id",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Skissm__GroupMember, user_id),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "role",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_ENUM,
    0,   /* quantifier_offset */
    offsetof(Skissm__GroupMember, role),
    &skissm__group_role__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned skissm__group_member__field_indices_by_name[] = {
  1,   /* field[1] = role */
  0,   /* field[0] = user_id */
};
static const ProtobufCIntRange skissm__group_member__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor skissm__group_member__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "skissm.GroupMember",
  "GroupMember",
  "Skissm__GroupMember",
  "skissm",
  sizeof(Skissm__GroupMember),
  2,
  skissm__group_member__field_descriptors,
  skissm__group_member__field_indices_by_name,
  1,  skissm__group_member__number_ranges,
  (ProtobufCMessageInit) skissm__group_member__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCEnumValue skissm__group_role__enum_values_by_number[2] =
{
  { "MEMBER", "SKISSM__GROUP_ROLE__MEMBER", 0 },
  { "MANAGER", "SKISSM__GROUP_ROLE__MANAGER", 1 },
};
static const ProtobufCIntRange skissm__group_role__value_ranges[] = {
{0, 0},{0, 2}
};
static const ProtobufCEnumValueIndex skissm__group_role__enum_values_by_name[2] =
{
  { "MANAGER", 1 },
  { "MEMBER", 0 },
};
const ProtobufCEnumDescriptor skissm__group_role__descriptor =
{
  PROTOBUF_C__ENUM_DESCRIPTOR_MAGIC,
  "skissm.GroupRole",
  "GroupRole",
  "Skissm__GroupRole",
  "skissm",
  2,
  skissm__group_role__enum_values_by_number,
  2,
  skissm__group_role__enum_values_by_name,
  1,
  skissm__group_role__value_ranges,
  NULL,NULL,NULL,NULL   /* reserved[1234] */
};