#ifndef MEM_UTIL_H_
#define MEM_UTIL_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "skissm.h"

/** Check if two buffers are equal in constant time. */
bool is_equal(
    const uint8_t *buffer_a,
    const uint8_t *buffer_b,
    size_t length
);

bool compare_protobuf(ProtobufCBinaryData *src_1, ProtobufCBinaryData *src_2);

bool compare_address(Org__E2eelab__Lib__Protobuf__E2eeAddress *address_1, Org__E2eelab__Lib__Protobuf__E2eeAddress *address_2);

bool compare_member_addresses(
    Org__E2eelab__Lib__Protobuf__E2eeAddress **member_addresses_1, size_t member_num_1,
    Org__E2eelab__Lib__Protobuf__E2eeAddress **member_addresses_2, size_t member_num_2
);

void copy_protobuf_from_protobuf(ProtobufCBinaryData *dest, const ProtobufCBinaryData *src);
void copy_protobuf_from_array(ProtobufCBinaryData *dest, const uint8_t *src, size_t len);
void overwrite_protobuf_from_array(ProtobufCBinaryData *dest, const uint8_t *src);

void copy_address_from_address(Org__E2eelab__Lib__Protobuf__E2eeAddress **dest, const Org__E2eelab__Lib__Protobuf__E2eeAddress *src);
void copy_member_addresses_from_member_addresses(
    Org__E2eelab__Lib__Protobuf__E2eeAddress ***dest,
    const Org__E2eelab__Lib__Protobuf__E2eeAddress **src,
    size_t member_num
);

void free_protobuf(ProtobufCBinaryData *output);

void free_mem(void **buffer, size_t buffer_len);

/**
 * Clear the memory held in the buffer.
 * This is more resilient to being optimised away than memset or bzero.
 */
void unset(void volatile *buffer, size_t buffer_len);

#endif /* MEM_UTIL_H_ */
