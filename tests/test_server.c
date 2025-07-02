/**
 * @file
 * @copyright © 2020-2021 by Academia Sinica
 * @brief server test
 *
 * @page test_server server documentation
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
 * 
 * 
 * @defgroup server_int cross server integration test
 * @ingroup Integration
 * This includes integration tests about server.
 * 
 * 
 * @defgroup test_cross_server_basic [v1.0ic01] cross server - basic test
 * @ingroup server_int
 * @{
 * @section sec51001 Test Case ID
 * v1.0_ic01
 * @section sec51002 Test Case Title
 * test_cross_server_basic
 * @section sec51003 Test Description
 * Alice is in Server1, and Bob is in Server2. They establish the session.
 * @section sec51004 Test Objectives
 * To assure that sessions can be successfully established after some invitation from different servers.
 * @section sec51005 Preconditions
 * @section sec51006 Test Steps
 * Step 1: Alice creates an account in Server1.\n
 * Step 2: Bob creates an account in Server2.\n
 * Step 3: Alice invites Bob.\n
 * Step 4: Alice sends a message to Bob and then Bob decrypts the message.
 * @section sec51007 Expected Results
 * No output.
 * @}
 * 
 * @defgroup test_cross_server_interaction [v1.0ic02] cross server - interaction test
 * @ingroup server_int
 * @{
 * @section sec51101 Test Case ID
 * v1.0_ic02
 * @section sec51102 Test Case Title
 * test_cross_server_interaction
 * @section sec51103 Test Description
 * Alice is in Server1, and Bob is in Server2. They establish the session.
 * @section sec51104 Test Objectives
 * To assure that sessions can be successfully established after some invitation from different servers.
 * @section sec51105 Preconditions
 * @section sec51106 Test Steps
 * Step 1: Alice creates an account in Server1.\n
 * Step 2: Bob creates an account in Server2.\n
 * Step 3: Alice invites Bob.\n
 * Step 4: Alice sends a message to Bob and then Bob decrypts the message.\n
 * Step 5: Bob sends a message to Alice and then Alice decrypts the message.
 * @section sec51107 Expected Results
 * No output.
 * @}
 * 
 * @defgroup test_cross_server_continual_messages [v1.0ic03] cross server - continual messages test
 * @ingroup server_int
 * @{
 * @section sec51201 Test Case ID
 * v1.0_ic03
 * @section sec51202 Test Case Title
 * test_cross_server_continual_messages
 * @section sec51203 Test Description
 * Alice sends 3000 messages to Bob.
 * @section sec51204 Test Objectives
 * To assure that a large number of messages can be decrypted.
 * @section sec51205 Preconditions
 * @section sec51206 Test Steps
 * Step 1: Alice creates an account in Server1.\n
 * Step 2: Bob creates an account in Server2.\n
 * Step 3: Alice invites Bob to create a session.\n
 * Step 4: Alice sends 3000 messages to Bob.\n
 * Step 5: Bob decrypts all of these messages.
 * @section sec51207 Expected Results
 * No output.
 * @}
 * 
 * @defgroup test_cross_server_one_to_many [v1.0ic04] cross server - multiple devices test: one to many
 * @ingroup server_int
 * @{
 * @section sec51401 Test Case ID
 * v1.0_ic04
 * @section sec51402 Test Case Title
 * test_cross_server_one_to_many
 * @section sec51403 Test Description
 * Alice has one device, and Bob has three devices. Alice sends a message to Bob.
 * @section sec51404 Test Objectives
 * To assure that the session mechanism is applicable to multiple devices.
 * @section sec51405 Preconditions
 * @section sec51406 Test Steps
 * Step 1: Alice creates an account in Server1.\n
 * Step 2: Bob creates an account in Server2.\n
 * Step 3: Alice invites Bob to create a session.\n
 * Step 4: Alice sends a message to Bob.\n
 * Step 5: Bob decrypts the message, using all of his devices.
 * @section sec51407 Expected Results
 * No output.
 * @}
 * 
 * @defgroup test_cross_server_many_to_one [v1.0ic05] cross server - multiple devices test: many to one
 * @ingroup server_int
 * @{
 * @section sec51501 Test Case ID
 * v1.0_ic05
 * @section sec51502 Test Case Title
 * test_cross_server_many_to_one
 * @section sec51503 Test Description
 * Alice has three devices, and Bob has one device. Alice sends a message to Bob.
 * @section sec51504 Test Objectives
 * To assure that the session mechanism is applicable to multiple devices.
 * @section sec51505 Preconditions
 * @section sec51506 Test Steps
 * Step 1: Alice creates an account in Server1.\n
 * Step 2: Bob creates an account in Server2.\n
 * Step 3: Alice invites Bob to create a session.\n
 * Step 4: Alice sends a message to Bob with one of her devices.\n
 * Step 5: Bob decrypts the message.
 * @section sec51507 Expected Results
 * No output.
 * @}
 * 
 * @defgroup test_cross_server_many_to_many [v1.0ic06] cross server - multiple devices test: many to many
 * @ingroup server_int
 * @{
 * @section sec51601 Test Case ID
 * v1.0_ic06
 * @section sec51602 Test Case Title
 * test_cross_server_many_to_many
 * @section sec51603 Test Description
 * Both Alice and Bob have three devices. Alice sends a message to Bob.
 * @section sec51604 Test Objectives
 * To assure that the session mechanism is applicable to multiple devices.
 * @section sec51605 Preconditions
 * @section sec51606 Test Steps
 * Step 1: Alice creates an account in Server1.\n
 * Step 2: Bob creates an account in Server2.\n
 * Step 3: Alice invites Bob to create a session.\n
 * Step 4: Alice sends a message to Bob with one of her devices.\n
 * Step 5: Bob decrypts the message, using all of his devices.
 * @section sec51607 Expected Results
 * No output.
 * @}
 * 
 * @defgroup test_cross_server_add_a_device [v1.0ic07] cross server - add a device test
 * @ingroup server_int
 * @{
 * @section sec51701 Test Case ID
 * v1.0_ic07
 * @section sec51702 Test Case Title
 * test_cross_server_add_a_device
 * @section sec51703 Test Description
 * Both Alice and Bob have two devices. Alice adds a new device. Then Alice sends a message to Bob. Next, Bob sends a message to Alice.
 * @section sec51704 Test Objectives
 * To assure that the session can be used once one of the both sides adds a new device.
 * @section sec51705 Preconditions
 * @section sec51706 Test Steps
 * Step 1: Alice creates an account in Server1.\n
 * Step 2: Bob creates an account in Server2.\n
 * Step 3: Alice invites Bob to create a session.\n
 * Step 4: Alice adds a new device.\n
 * Step 5: Alice uses the old device to send a message to Bob, and then Bob decrypts the message.\n
 * Step 6: Bob sends a message to Alice, and then Alice decrypts the message.
 * @section sec51707 Expected Results
 * No output.
 * @}
 * 
 * @defgroup test_cross_server_create_group [v1.0ic08] cross server - create group test
 * @ingroup server_int
 * @{
 * @section sec51801 Test Case ID
 * v1.0_ic08
 * @section sec51802 Test Case Title
 * test_cross_server_create_group
 * @section sec51803 Test Description
 * Alice creates a group with four members in it. Everyone in the group sends a message to the group.
 * @section sec51804 Test Objectives
 * To verify the create group protocol.
 * @section sec51805 Preconditions
 * @section sec51806 Test Steps
 * Step 1: Alice, Bob, Claire and David create an account in different servers.\n
 * Step 2: Alice invites Bob, Claire and David to create a group.\n
 * Step 3: Everyone in the group sends a message to the group.
 * @section sec51807 Expected Results
 * No output.
 * @}
 * 
 * @defgroup test_cross_server_add_group_members [v1.0ic09] cross server - add group members test
 * @ingroup server_int
 * @{
 * @section sec51901 Test Case ID
 * v1.0_ic09
 * @section sec51902 Test Case Title
 * test_cross_server_add_group_members
 * @section sec51903 Test Description
 * Alice creates a group with three members in it. Then Alice adds a group member.
 * Next, everyone in the group sends a message to the group.
 * @section sec51904 Test Objectives
 * To verify the add group members protocol.
 * @section sec51905 Preconditions
 * @section sec51906 Test Steps
 * Step 1: Alice, Bob, Claire create an account in different servers.\n
 * Step 2: Alice invites Bob and Claire to create a group.\n
 * Step 3: Alice invites David to join the group.\n
 * Step 4: Everyone in the group sends a message to the group.
 * @section sec51907 Expected Results
 * No output.
 * @}
 * 
 * @defgroup test_cross_server_remove_group_members [v1.0ic10] cross server - remove group members test
 * @ingroup server_int
 * @{
 * @section sec52001 Test Case ID
 * v1.0_ic10
 * @section sec52002 Test Case Title
 * test_cross_server_remove_group_members
 * @section sec52003 Test Description
 * Alice creates a group with four members in it. Then Alice removes a group member.
 * Next, everyone in the group sends a message to the group.
 * @section sec52004 Test Objectives
 * To verify the remove group members protocol.
 * @section sec52005 Preconditions
 * @section sec52006 Test Steps
 * Step 1: Alice, Bob, Claire and David create an account in different servers.\n
 * Step 2: Alice invites Bob, Claire and David to create a group.\n
 * Step 3: Alice removes Claire out of the group.\n
 * Step 4: Everyone in the group sends a message to the group.
 * @section sec52007 Expected Results
 * No output.
 * @}
 * 
 * @defgroup test_cross_server_create_add_remove [v1.0ic11] cross server - group test
 * @ingroup server_int
 * @{
 * @section sec52101 Test Case ID
 * v1.0_ic11
 * @section sec52102 Test Case Title
 * test_cross_server_create_add_remove
 * @section sec52103 Test Description
 * Alice creates a group with two members in it. Then Alice adds a group member.
 * Next, everyone in the group sends a message to the group. Then Alice removes a group member.
 * Next, everyone in the group sends a message to the group.
 * @section sec52104 Test Objectives
 * To assure that the action of creating a group, adding group members and removing group members can be processed in a small group.
 * @section sec52105 Preconditions
 * @section sec52106 Test Steps
 * Step 1: Alice, Bob, Claire create an account in different servers.\n
 * Step 2: Alice invites Bob to create a group.\n
 * Step 3: Alice sends a message to the group.\n
 * Step 4: Alice invites Claire to join the group.\n
 * Step 5: Alice sends a message to the group.\n
 * Step 6: Alice removes Bob out of the group.\n
 * Step 7: Alice sends a message to the group.
 * @section sec52107 Expected Results
 * No output.
 * @}
 * 
 * @defgroup test_cross_server_leave_group [v1.0ic12] cross server - leave group test
 * @ingroup server_int
 * @{
 * @section sec52201 Test Case ID
 * v1.0_ic12
 * @section sec52202 Test Case Title
 * test_cross_server_leave_group
 * @section sec52203 Test Description
 * Alice creates a group with four members in it. Then one of the group members leaves the group.
 * Next, everyone in the group sends a message to the group.
 * @section sec52204 Test Objectives
 * To verify the leave group protocol.
 * @section sec52205 Preconditions
 * @section sec52206 Test Steps
 * Step 1: Alice, Bob, Claire and David create an account in different servers.\n
 * Step 2: Alice invites Bob, Claire and David to create a group.\n
 * Step 3: Claire leaves the group.\n
 * Step 4: Everyone in the group sends a message to the group.
 * @section sec52207 Expected Results
 * No output.
 * @}
 * 
 * @defgroup test_cross_server_continual [v1.0ic13] cross server - group continual messages test
 * @ingroup server_int
 * @{
 * @section sec52301 Test Case ID
 * v1.0_ic13
 * @section sec52302 Test Case Title
 * test_cross_server_continual
 * @section sec52303 Test Description
 * Alice creates a group with three members in it. Then everyone in the group sends 1000 messages to the group.
 * @section sec52304 Test Objectives
 * To assure that a large number of messages can be decrypted by every group member.
 * @section sec52305 Preconditions
 * @section sec52306 Test Steps
 * Step 1: Alice, Bob, Claire create an account in different servers.\n
 * Step 2: Alice invites Bob and Claire to create a group.\n
 * Step 3: Everyone in the group sends 1000 messages to the group.
 * @section sec52307 Expected Results
 * No output.
 * @}
 * 
 * @defgroup test_cross_server_multiple_devices [v1.0ic14] cross server - group multiple devices test
 * @ingroup server_int
 * @{
 * @section sec52401 Test Case ID
 * v1.0_ic14
 * @section sec52402 Test Case Title
 * test_cross_server_multiple_devices
 * @section sec52403 Test Description
 * Everyone in the three-member group has two devices. Everyone in the group sends a message to the group.
 * @section sec52404 Test Objectives
 * To assure that the group session mechanism is applicable to multiple devices.
 * @section sec52405 Preconditions
 * @section sec52406 Test Steps
 * Step 1: Alice, Bob, Claire create an account in different servers.\n
 * Step 2: Alice invites Bob and Claire to create a group.\n
 * Step 3: Alice sends a message to the group with her first device.\n
 * Step 4: Bob sends a message to the group with his second device.\n
 * Step 5: Claire sends a message to the group with her second device.
 * @section sec52407 Expected Results
 * No output.
 * @}
 * 
 * @defgroup test_cross_server_add_new_device [v1.0ic15] cross server - new devices test
 * @ingroup server_int
 * @{
 * @section sec52501 Test Case ID
 * v1.0_ic15
 * @section sec52502 Test Case Title
 * test_cross_server_add_new_device
 * @section sec52503 Test Description
 * One of the group members adds a new device.
 * @section sec52504 Test Objectives
 * To assure that the group session can be used once one of the group members adds a new device.
 * @section sec52505 Preconditions
 * @section sec52506 Test Steps
 * Step 1: Alice, Bob, Claire create an account in different servers.\n
 * Step 2: Alice invites Bob and Claire to create a group.\n
 * Step 3: Alice adds a new device.\n
 * Step 4: Alice sends a message to the group with her first device.
 * @section sec52507 Expected Results
 * No output.
 * @}
 * 
 */



