/*
 * Copyright © 2021 Academia Sinica. All Rights Reserved.
 *
 * This file is part of E2EE Security.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * E2EE Security is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with E2EE Security.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef MOCK_SERVER_SENDING_H_
#define MOCK_SERVER_SENDING_H_

#include "e2ees/e2ees.h"

void send_proto_msg(E2ees__ProtoMsg *proto_msg);

void start_mock_server_sending();

void stop_mock_server_sending();

#endif /* MOCK_SERVER_SENDING_H_ */
