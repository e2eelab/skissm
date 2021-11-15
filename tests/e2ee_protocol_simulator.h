/*
 * Copyright © 2020-2021 by Academia Sinica
 *
 * This file is part of SKISSM.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SKISSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SKISSM.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef E2EE_PROTOCOL_SIMULATOR_H_
#define E2EE_PROTOCOL_SIMULATOR_H_

#include <stdint.h>
#include <stddef.h>

void protocol_simulator_begin();
void protocol_simulator_end();

void mock_protocol_receive(uint8_t *msg, size_t msg_len);

#endif /* E2EE_PROTOCOL_SIMULATOR_H_ */