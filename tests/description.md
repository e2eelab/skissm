# End-to-end Test


## Unit test

### e2ees

*   **get_digital_signature_suite**

*   **get_kem_suite**

*   **get_se_suite**

*   **get_hash_suite**

*   **get_cipher_suite**

*   **e2ees_pack_id_to_raw**

*   **raw_to_e2ees_pack_id**

*   **gen_e2ees_pack_id_raw**

*   **get_e2ees_pack**

### account

*   **account_begin**

*   **account_end**

*   **create_account**

*   **generate_identity_key**

*   **generate_signed_pre_key**

*   **lookup_one_time_pre_key**

*   **generate_opks**

*   **insert_opks**

*   **mark_opk_as_used**

*   **free_one_time_pre_key**

### ratchet

*   **initialise_as_alice**

*   **initialise_as_bob**

*   **encrypt_ratchet**

*   **decrypt_ratchet**

### account manager

*   **produce_register_request**

*   **consume_register_response**

*   **produce_publish_spk_request**

*   **consume_publish_spk_response**

*   **produce_supply_opks_request**

*   **consume_supply_opks_response**

### one2one manager

*   **produce_get_pre_key_bundle_request**

*   **produce_send_one2one_msg_request**

*   **consume_send_one2one_msg_response**

*   **consume_remove_user_device_msg**

*   **produce_invite_request**

*   **consume_invite_response**

*   **produce_accept_request**

*   **consume_accept_response**

### group manager

*   **produce_create_group_request**

*   **produce_add_group_members_request**

*   **produce_add_group_member_device_request**

*   **produce_remove_group_members_request**

*   **produce_leave_group_request**

*   **consume_leave_group_response**

*   **produce_send_group_msg_request**

*   **consume_send_group_msg_response**

*   **consume_group_msg**



## Integration test

### account

*   **register_user**

*   **publish_spk_internal**

    If the signed pre-key is expired, the client should generate a new signed pre-key and publish it to the server.

*   **supply_opks_internal**

    The client will be notified to generate a number of one-time pre-keys if the server finds that the one-time pre-keys are used up.

### ratchet

*   **test_alice_to_bob**

    Alice and Bob establish their ratchet. Alice encrypts a message. Bob should decrypt the message successfully.

*   **test_bob_to_alice**

    Alice and Bob establish their ratchet. Bob encrypts a message. Alice should decrypt the message successfully.

*   **test_interaction_alice_first**

    Alice and Bob establish their ratchet. Alice encrypts a message and Bob decrypts the message. Next, Bob encrypts a message and Alice decrypts the message.

*   **test_interaction_bob_first**

    Alice and Bob establish their ratchet. Bob encrypts a message and Alice decrypts the message. Next, Alice encrypts a message and Bob decrypts the message.

*   **test_out_of_order**

    Alice and Bob establish their ratchet. Alice encrypts two messages. Bob decrypts the second message first and then decrypts the first message.

*   **test_continual_message**

    Alice and Bob establish their ratchet. Alice encrypts 1000 messages. Bob decrypts these messages.

*   **test_interaction_v2**

    Alice and Bob establish their ratchet. Alice encrypts two messages and Bob decrypts the messages. Next, Bob encrypts two messages and Alice decrypts the messages.

*   **test_out_of_order_v2**

### one2one session

*   **test_basic_session**

    Alice and Bob establish their session. Alice sends a message to Bob. Bob should decrypt the message successfully.

*   **test_interaction**

    Alice and Bob establish their session. Alice sends a message to Bob. Next, Bob sends a message to Alice.

*   **test_continual_messages**

    Alice sends 3000 messages to Bob.

*   **test_multiple_devices**

*   **test_one_to_many**

    Alice has one device, and Bob has three devices. Alice sends a message to Bob.

*   **test_many_to_one**

    Alice has three devices, and Bob has one device. Alice sends a message to Bob.

*   **test_many_to_many**

    Both Alice and Bob have three devices. Alice sends a message to Bob.

*   **test_change_devices**

    Both Alice and Bob have two devices. Alice adds a new device. Then Alice sends a message to Bob. Next, Bob sends a message to Alice.

### group session

*   **test_create_group**

    Alice creates a group with four members in it. Everyone in the group sends a message to the group.

*   **test_add_group_members**

    Alice creates a group with three members in it. Then Alice adds a group member. Next, everyone in the group sends a message to the group.

*   **test_remove_group_members**

    Alice creates a group with four members in it. Then Alice removes a group member. Next, everyone in the group sends a message to the group.

*   **test_create_add_remove**

    Alice creates a group with two members in it. Then Alice adds a group member. Next, everyone in the group sends a message to the group. Then Alice removes a group member. Next, everyone in the group sends a message to the group.

*   **test_leave_group**

    Alice creates a group with four members in it. Then one of the group members leaves the group. Next, everyone in the group sends a message to the group.

*   **test_continual**

    Alice creates a group with three members in it. Then everyone in the group sends 1000 messages to the group.

*   **test_multiple_devices**

    Everyone in the three-member group has two devices. Everyone in the group sends a message to the group.

*   **test_add_new_device**

    One of the group members adds a new device.

*   **test_medium_group**

*   **test_several_members_and_groups**


