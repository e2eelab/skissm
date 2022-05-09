/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: SupplyOpksRequest.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "SupplyOpksRequest.pb-c.h"
void   skissm__supply_opks_request__init
                     (Skissm__SupplyOpksRequest         *message)
{
  static const Skissm__SupplyOpksRequest init_value = SKISSM__SUPPLY_OPKS_REQUEST__INIT;
  *message = init_value;
}
size_t skissm__supply_opks_request__get_packed_size
                     (const Skissm__SupplyOpksRequest *message)
{
  assert(message->base.descriptor == &skissm__supply_opks_request__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t skissm__supply_opks_request__pack
                     (const Skissm__SupplyOpksRequest *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &skissm__supply_opks_request__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t skissm__supply_opks_request__pack_to_buffer
                     (const Skissm__SupplyOpksRequest *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &skissm__supply_opks_request__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Skissm__SupplyOpksRequest *
       skissm__supply_opks_request__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Skissm__SupplyOpksRequest *)
     protobuf_c_message_unpack (&skissm__supply_opks_request__descriptor,
                                allocator, len, data);
}
void   skissm__supply_opks_request__free_unpacked
                     (Skissm__SupplyOpksRequest *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &skissm__supply_opks_request__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor skissm__supply_opks_request__field_descriptors[3] =
{
  {
    "e2ee_pack_id",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Skissm__SupplyOpksRequest, e2ee_pack_id),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "user_address",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Skissm__SupplyOpksRequest, user_address),
    &skissm__e2ee_address__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "one_time_pre_key_public",
    3,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Skissm__SupplyOpksRequest, n_one_time_pre_key_public),
    offsetof(Skissm__SupplyOpksRequest, one_time_pre_key_public),
    &skissm__one_time_pre_key_public__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned skissm__supply_opks_request__field_indices_by_name[] = {
  0,   /* field[0] = e2ee_pack_id */
  2,   /* field[2] = one_time_pre_key_public */
  1,   /* field[1] = user_address */
};
static const ProtobufCIntRange skissm__supply_opks_request__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor skissm__supply_opks_request__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "skissm.SupplyOpksRequest",
  "SupplyOpksRequest",
  "Skissm__SupplyOpksRequest",
  "skissm",
  sizeof(Skissm__SupplyOpksRequest),
  3,
  skissm__supply_opks_request__field_descriptors,
  skissm__supply_opks_request__field_indices_by_name,
  1,  skissm__supply_opks_request__number_ranges,
  (ProtobufCMessageInit) skissm__supply_opks_request__init,
  NULL,NULL,NULL    /* reserved[123] */
};