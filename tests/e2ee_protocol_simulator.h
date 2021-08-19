#ifndef E2EE_PROTOCOL_SIMULATOR_H_
#define E2EE_PROTOCOL_SIMULATOR_H_

#include <stdint.h>
#include <stddef.h>

void mock_protocol_receive(u_int8_t *msg, size_t msg_len);

#endif /* E2EE_PROTOCOL_SIMULATOR_H_ */