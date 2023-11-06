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
#include "skissm/ratchet.h"

#include <string.h>
#include <stdio.h>

#include "skissm/cipher.h"
#include "skissm/mem_util.h"

static const char MESSAGE_KEY_SEED[] = "MessageKeys";
static const uint8_t CHAIN_KEY_SEED[1] = {0x02};
static const size_t MAX_SKIPPED_MESSAGE_KEY_NODES = 8192;

static void copy_receiver_chain_node(
    Skissm__ReceiverChainNode **dest,
    Skissm__ReceiverChainNode **src,
    size_t num
) {
    size_t i;
    for (i = 0; i < num; i++){
        dest[i] = (Skissm__ReceiverChainNode *) malloc(sizeof(Skissm__ReceiverChainNode));
        skissm__receiver_chain_node__init(dest[i]);
        copy_protobuf_from_protobuf(&(dest[i]->ratchet_key_public), &(src[i]->ratchet_key_public));
        dest[i]->chain_key = (Skissm__ChainKey *) malloc(sizeof(Skissm__ChainKey));
        skissm__chain_key__init(dest[i]->chain_key);
        dest[i]->chain_key->index = src[i]->chain_key->index;
        copy_protobuf_from_protobuf(&(dest[i]->chain_key->shared_key), &(src[i]->chain_key->shared_key));
    }
}

static void copy_skipped_msg_key_node(
    Skissm__SkippedMsgKeyNode **dest,
    Skissm__SkippedMsgKeyNode **src,
    size_t num
) {
    size_t i;
    for (i = 0; i < num; i++){
        dest[i] = (Skissm__SkippedMsgKeyNode *) malloc(sizeof(Skissm__SkippedMsgKeyNode));
        skissm__skipped_msg_key_node__init(dest[i]);
        copy_protobuf_from_protobuf(&(dest[i]->ratchet_key_public), &(src[i]->ratchet_key_public));
        dest[i]->msg_key = (Skissm__MsgKey *) malloc(sizeof(Skissm__MsgKey));
        skissm__msg_key__init(dest[i]->msg_key);
        dest[i]->msg_key->index = src[i]->msg_key->index;
        copy_protobuf_from_protobuf(&(dest[i]->msg_key->derived_key), &(src[i]->msg_key->derived_key));
    }
}

static void free_receiver_chain(
    Skissm__ReceiverChainNode ***src,
    size_t num
) {
    size_t i;
    for (i = 0; i < num; i++){
        skissm__receiver_chain_node__free_unpacked((*src)[i], NULL);
        (*src)[i] = NULL;
    }
    free(*src);
    *src = NULL;
}

static void free_skipped_message_key(
    Skissm__SkippedMsgKeyNode ***src,
    size_t num
) {
    size_t i;
    for (i = 0; i < num; i++){
        skissm__skipped_msg_key_node__free_unpacked((*src)[i], NULL);
        (*src)[i] = NULL;
    }
    free(*src);
    *src = NULL;
}

static void create_chain_key(
    const cipher_suite_t *cipher_suite,
    const ProtobufCBinaryData root_key,
    const ProtobufCBinaryData *our_private_key,
    const ProtobufCBinaryData *their_key,
    ProtobufCBinaryData *new_root_key,
    Skissm__ChainKey *new_chain_key,
    ProtobufCBinaryData *ratchet_public_key
) {
    int shared_key_len = cipher_suite->get_crypto_param().hash_len;

    uint8_t secret[shared_key_len];
    memset(secret, 0, shared_key_len);
    uint8_t *ciphertext = cipher_suite->ss_key_gen(our_private_key, their_key, secret);
    uint8_t derived_secrets[2 * shared_key_len];
    cipher_suite->hkdf(
        secret, sizeof(secret),
        root_key.data, root_key.len,
        (uint8_t *)KDF_INFO_RATCHET, sizeof(KDF_INFO_RATCHET) - 1,
        derived_secrets, sizeof(derived_secrets)
    );

    if (new_root_key->data){
        overwrite_protobuf_from_array(new_root_key, derived_secrets);
    } else{
        copy_protobuf_from_array(new_root_key, derived_secrets, sizeof(derived_secrets));
    }

    if (ciphertext != NULL) {
        if (ratchet_public_key->data != NULL) {
            free_mem((void **)&(ratchet_public_key->data), ratchet_public_key->len);
            ratchet_public_key->len = 0;
        }
        uint32_t ciphertext_len = cipher_suite->get_crypto_param().kem_ciphertext_len;
        ratchet_public_key->data = (uint8_t *)malloc(sizeof(uint8_t) * ciphertext_len);
        memcpy(ratchet_public_key->data, ciphertext, ciphertext_len);
        ratchet_public_key->len = ciphertext_len;

        free_mem((void **)&ciphertext, ciphertext_len);
    }
    new_chain_key->index = 0;
    if (new_chain_key->shared_key.data) {
        overwrite_protobuf_from_array(&(new_chain_key->shared_key), derived_secrets + shared_key_len);
    } else {
        copy_protobuf_from_array(&(new_chain_key->shared_key), derived_secrets + shared_key_len, shared_key_len);
    }

    unset(derived_secrets, sizeof(derived_secrets));
    unset(secret, sizeof(secret));
}

static void advance_chain_key(
    const cipher_suite_t *cipher_suite,
    Skissm__ChainKey *chain_key
) {
    int shared_key_len = cipher_suite->get_crypto_param().hash_len;
    uint8_t shared_key[shared_key_len];
    memset(shared_key, 0, shared_key_len);
    cipher_suite->hmac(
        chain_key->shared_key.data, chain_key->shared_key.len,
        CHAIN_KEY_SEED, sizeof(CHAIN_KEY_SEED),
        shared_key
    );

    chain_key->index = chain_key->index + 1;
    overwrite_protobuf_from_array(&chain_key->shared_key, shared_key);
}

static void create_msg_keys(
    const cipher_suite_t *cipher_suite,
    const Skissm__ChainKey *chain_key,
    Skissm__MsgKey *msg_key
) {
    free_protobuf(&(msg_key->derived_key));
    int msg_key_len = cipher_suite->get_crypto_param().aead_key_len + cipher_suite->get_crypto_param().aead_iv_len;
    msg_key->derived_key.data = (uint8_t *) malloc(sizeof(uint8_t) * msg_key_len);
    msg_key->derived_key.len = msg_key_len;

    int hash_len = cipher_suite->get_crypto_param().hash_len;
    uint8_t salt[hash_len];
    memset(salt, 0, hash_len);
    cipher_suite->hkdf(
        chain_key->shared_key.data, chain_key->shared_key.len,
        salt, sizeof(salt),
        (uint8_t *)MESSAGE_KEY_SEED, sizeof(MESSAGE_KEY_SEED) - 1,
        msg_key->derived_key.data, msg_key->derived_key.len
    );
    msg_key->index = chain_key->index;
}

static size_t verify_and_decrypt(
    const cipher_suite_t *cipher_suite,
    ProtobufCBinaryData ad,
    const Skissm__MsgKey *message_key,
    const Skissm__One2oneMsgPayload *payload,
    uint8_t **plaintext_data
) {
    // debug log
    //char *derived_key_str;
    //size_t derived_key_str_len = to_hex_str(message_key->derived_key.data, message_key->derived_key.len, &derived_key_str);
    //ssm_notify_log(NULL, DEBUG_LOG, "verify_and_decrypt() derived_key[len = %d]: %s\n", message_key->derived_key.len, derived_key_str);
    //free(derived_key_str);
    //char *ciphertext_str;
    //size_t ciphertext_str_len = to_hex_str(payload->ciphertext.data, payload->ciphertext.len, &ciphertext_str);
    //ssm_notify_log(NULL, DEBUG_LOG, "verify_and_decrypt() ciphertext[len = %d]: %s\n", ciphertext_str_len, ciphertext_str);
    //free(ciphertext_str);
    
    size_t result = cipher_suite->decrypt(
        &ad,
        message_key->derived_key.data,
        payload->ciphertext.data, payload->ciphertext.len,
        plaintext_data
    );

    if (result == 0)
        ssm_notify_log(NULL, BAD_MESSAGE_DECRYPTION, "verify_and_decrypt()");

    return result;
}

static size_t verify_and_decrypt_for_existing_chain(
    const cipher_suite_t *cipher_suite,
    ProtobufCBinaryData ad,
    const Skissm__ChainKey *chain,
    const Skissm__One2oneMsgPayload *payload,
    uint8_t **plaintext_data
) {
    if (payload->sequence < chain->index) {
        ssm_notify_log(NULL, BAD_MESSAGE_SEQUENCE, "verify_and_decrypt_for_existing_chain()");
        return 0;
    }

    // limit the number of hashes we're prepared to compute
    if (payload->sequence - chain->index > MAX_CHAIN_INDEX) {
        ssm_notify_log(NULL, BAD_MESSAGE_SEQUENCE, "verify_and_decrypt_for_existing_chain()");
        return 0;
    }

    Skissm__ChainKey *new_chain = (Skissm__ChainKey *) malloc(sizeof(Skissm__ChainKey));
    skissm__chain_key__init(new_chain);
    new_chain->index = chain->index;
    copy_protobuf_from_protobuf(&new_chain->shared_key, &chain->shared_key);

    while (new_chain->index < payload->sequence) {
        advance_chain_key(cipher_suite, new_chain);
    }
    assert(new_chain->index == payload->sequence);

    Skissm__MsgKey *mk = (Skissm__MsgKey *) malloc(sizeof(Skissm__MsgKey));
    skissm__msg_key__init(mk);
    create_msg_keys(cipher_suite, new_chain, mk);

    size_t result = verify_and_decrypt(
        cipher_suite, ad, mk, payload,
        plaintext_data
    );

    skissm__chain_key__free_unpacked(new_chain, NULL);
    skissm__msg_key__free_unpacked(mk, NULL);

    return result;
}

static size_t verify_and_decrypt_for_new_chain(
    const cipher_suite_t *cipher_suite,
    const Skissm__Ratchet *ratchet, ProtobufCBinaryData ad,
    const Skissm__One2oneMsgPayload *payload,
    uint8_t **plaintext_data
) {
    ProtobufCBinaryData new_root_key = {0, NULL};
    Skissm__ReceiverChainNode new_chain;

    /** The sender_chain will not be released since we need our ratchet key
     * for ECDH or Decaps. */
    if (ratchet->sender_chain == NULL) {
        ssm_notify_log(NULL, BAD_MESSAGE_DECRYPTION, "verify_and_decrypt_for_new_chain()");
        return 0;
    }

    // limit the number of hashes we're prepared to compute
    if (payload->sequence > MAX_CHAIN_INDEX) {
        ssm_notify_log(NULL, BAD_MESSAGE_SEQUENCE, "verify_and_decrypt_for_new_chain()");
        return 0;
    }

    uint32_t coming_root_sequence = payload->root_sequence;
    uint32_t our_root_sequence = ratchet->root_sequence;

    // comint_root_sequence should be positive
    if (coming_root_sequence == 0) {
        ssm_notify_log(NULL, BAD_MESSAGE_FORMAT, "verify_and_decrypt_for_new_chain()");
        return 0;
    }
    if (cipher_suite->get_crypto_param().pqc_param == false) {
        assert(payload->ratchet_key[coming_root_sequence - 1].len == cipher_suite->get_crypto_param().asym_pub_key_len);
    } else {
        assert(payload->ratchet_key[coming_root_sequence - 1].len == cipher_suite->get_crypto_param().kem_ciphertext_len);
    }

    skissm__receiver_chain_node__init(&new_chain);

    new_chain.chain_key = (Skissm__ChainKey *) malloc(sizeof(Skissm__ChainKey));
    skissm__chain_key__init(new_chain.chain_key);

    uint32_t i;
    copy_protobuf_from_protobuf(&new_root_key, &(ratchet->root_key));
    ProtobufCBinaryData *our_private_key = &(ratchet->sender_chain->ratchet_key[0]);
    for (i = our_root_sequence; i < coming_root_sequence; i++) {
        create_chain_key(
            cipher_suite,
            new_root_key, our_private_key,
            &(payload->ratchet_key[i]), &new_root_key,
            new_chain.chain_key, NULL
        );
    }

    size_t result = verify_and_decrypt_for_existing_chain(
        cipher_suite,
        ad, new_chain.chain_key, payload,
        plaintext_data
    );

    free_protobuf(&new_root_key);
    unset((void volatile *)&new_root_key, sizeof(ProtobufCBinaryData));
    free_protobuf(&(new_chain.chain_key->shared_key));
    unset((void volatile *)&new_chain, sizeof(Skissm__ReceiverChainNode));

    return result;
}

void initialise_ratchet(Skissm__Ratchet **ratchet){
    *ratchet = (Skissm__Ratchet *) malloc(sizeof(Skissm__Ratchet));
    skissm__ratchet__init(*ratchet);
}

void initialise_as_bob(
    const cipher_suite_t *cipher_suite,
    Skissm__Ratchet *ratchet, const uint8_t *shared_secret, size_t shared_secret_length,
    const Skissm__KeyPair *our_ratchet_key
){
    int shared_key_len = cipher_suite->get_crypto_param().hash_len;
    // the ssk will be 64 bytes
    uint8_t derived_secrets[2 * shared_key_len];
    int hash_len = cipher_suite->get_crypto_param().hash_len;
    uint8_t salt[hash_len];
    memset(salt, 0, hash_len);
    cipher_suite->hkdf(
        shared_secret, shared_secret_length,
        salt, sizeof(salt),
        (uint8_t *)KDF_INFO_ROOT, sizeof(KDF_INFO_ROOT) - 1,
        derived_secrets, sizeof(derived_secrets)
    );

    ratchet->sender_chain = (Skissm__SenderChainNode *) malloc(sizeof(Skissm__SenderChainNode));
    Skissm__SenderChainNode *sender_chain = ratchet->sender_chain;
    skissm__sender_chain_node__init(sender_chain);
    sender_chain->chain_key = (Skissm__ChainKey *) malloc(sizeof(Skissm__ChainKey));
    skissm__chain_key__init(sender_chain->chain_key);
    sender_chain->chain_key->index = 0;

    /** The first half of the ssk will be the root key,
     *  and the second half will be the sending chain key */
    copy_protobuf_from_array(&(ratchet->root_key), derived_secrets, shared_key_len);

    copy_protobuf_from_array(&(sender_chain->chain_key->shared_key), derived_secrets + shared_key_len, shared_key_len);

    sender_chain->n_ratchet_key = 1;
    sender_chain->ratchet_key = (ProtobufCBinaryData *) malloc(sizeof(ProtobufCBinaryData));
    copy_protobuf_from_protobuf(sender_chain->ratchet_key, &(our_ratchet_key->private_key));

    unset(derived_secrets, sizeof(derived_secrets));
}

void initialise_as_alice(
    const cipher_suite_t *cipher_suite,
    Skissm__Ratchet *ratchet, const uint8_t *shared_secret, size_t shared_secret_length,
    const Skissm__KeyPair *our_ratchet_key, ProtobufCBinaryData *their_ratchet_key
){
    int shared_key_len = cipher_suite->get_crypto_param().hash_len;
    // the length of derived_secrets will be 64 bytes
    uint8_t derived_secrets[2 * shared_key_len];
    memset(derived_secrets, 0, 2 * shared_key_len);
    int hash_len = cipher_suite->get_crypto_param().hash_len;
    uint8_t salt[hash_len];
    memset(salt, 0, hash_len);

    // shared_secret_length may be 128 or 96
    cipher_suite->hkdf(
        shared_secret, shared_secret_length,
        salt, sizeof(salt),
        (uint8_t *)KDF_INFO_ROOT, sizeof(KDF_INFO_ROOT) - 1,
        derived_secrets, sizeof(derived_secrets)
    );
    ratchet->receiver_chains = (Skissm__ReceiverChainNode **) malloc(sizeof(Skissm__ReceiverChainNode *));
    ratchet->receiver_chains[0] = (Skissm__ReceiverChainNode *) malloc(sizeof(Skissm__ReceiverChainNode));
    skissm__receiver_chain_node__init(ratchet->receiver_chains[0]);
    ratchet->receiver_chains[0]->chain_key = (Skissm__ChainKey *) malloc(sizeof(Skissm__ChainKey));
    skissm__chain_key__init(ratchet->receiver_chains[0]->chain_key);

    /** The first half of the ssk will be the root key,
     *  and the second half will be the receiving chain key */
    copy_protobuf_from_array(&(ratchet->root_key), derived_secrets, shared_key_len);

    copy_protobuf_from_array(&(ratchet->receiver_chains[0]->chain_key->shared_key), derived_secrets + shared_key_len, shared_key_len);

    copy_protobuf_from_protobuf(&(ratchet->receiver_chains[0]->ratchet_key_public), their_ratchet_key);

    (ratchet->n_receiver_chains)++;

    // generate a new root key and a sending chain key
    ratchet->sender_chain = (Skissm__SenderChainNode *) malloc(sizeof(Skissm__SenderChainNode));
    Skissm__SenderChainNode *sender_chain = ratchet->sender_chain;
    skissm__sender_chain_node__init(sender_chain);

    sender_chain->chain_key = (Skissm__ChainKey *) malloc(sizeof(Skissm__ChainKey));
    skissm__chain_key__init(sender_chain->chain_key);

    // the ratchet_key will be reallocated in the future
    sender_chain->ratchet_key = (ProtobufCBinaryData *) malloc(sizeof(ProtobufCBinaryData));
    sender_chain->n_ratchet_key = 1;
    if (our_ratchet_key == NULL) {
        // PQC mode
        create_chain_key(
            cipher_suite, ratchet->root_key, NULL, their_ratchet_key,
            &(ratchet->root_key), sender_chain->chain_key, &((sender_chain->ratchet_key)[0])
        );
    } else {
        // ECC mode
        create_chain_key(
            cipher_suite, ratchet->root_key, &(our_ratchet_key->private_key), their_ratchet_key,
            &(ratchet->root_key), sender_chain->chain_key, NULL
        );
        copy_protobuf_from_protobuf(&((sender_chain->ratchet_key)[0]), &(our_ratchet_key->public_key));
    }
    (ratchet->root_sequence)++;

    unset(derived_secrets, sizeof(derived_secrets));
}

void encrypt_ratchet(
    const cipher_suite_t *cipher_suite,
    Skissm__Ratchet *ratchet,
    ProtobufCBinaryData ad,
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    Skissm__One2oneMsgPayload **payload
) {
    Skissm__SenderChainNode *sender_chain = ratchet->sender_chain;
    if (sender_chain->chain_key->index > MAX_CHAIN_INDEX) {
        // drop this chain if the chain is too long
        skissm__chain_key__free_unpacked(sender_chain->chain_key, NULL);
        sender_chain->chain_key = NULL;

        if (sender_chain->n_ratchet_key == MAX_RECEIVER_CHAIN_NODES) {
            ssm_notify_log(
                NULL,
                BAD_MESSAGE_ENCRYPTION,
                "encrypt_ratchet() the root tree is too long\n"
            );
            return;
        }

        size_t old_ratchet_key_num = sender_chain->n_ratchet_key;

        sender_chain->chain_key = (Skissm__ChainKey *) malloc(sizeof(Skissm__ChainKey));
        skissm__chain_key__init(sender_chain->chain_key);

        // reallocate
        ProtobufCBinaryData *temp_ratchet_key;
        temp_ratchet_key = (ProtobufCBinaryData *) malloc(sizeof(ProtobufCBinaryData) * (old_ratchet_key_num + 1));
        copy_protobuf_list_from_protobuf_list(temp_ratchet_key, sender_chain->ratchet_key, old_ratchet_key_num);
        free_protobuf_list(&(sender_chain->ratchet_key), old_ratchet_key_num);
        sender_chain->ratchet_key = temp_ratchet_key;

        if (cipher_suite->get_crypto_param().pqc_param == false) {
            // ECC mode
            Skissm__KeyPair *ratchet_key_pair = (Skissm__KeyPair *) malloc(sizeof(Skissm__KeyPair));
            skissm__key_pair__init(ratchet_key_pair);
            cipher_suite->asym_key_gen(&(ratchet_key_pair->public_key), &(ratchet_key_pair->private_key));
            copy_protobuf_from_protobuf(
                &((sender_chain->ratchet_key)[old_ratchet_key_num]),
                &(ratchet_key_pair->public_key)
            );
            create_chain_key(
                cipher_suite,
                ratchet->root_key,
                &(ratchet_key_pair->private_key),
                &(ratchet->receiver_chains[ratchet->n_receiver_chains - 1]->ratchet_key_public),
                &(ratchet->root_key), sender_chain->chain_key,
                NULL
            );
        } else {
            // PQC mode
            create_chain_key(
                cipher_suite,
                ratchet->root_key,
                NULL,
                &(ratchet->receiver_chains[ratchet->n_receiver_chains - 1]->ratchet_key_public),
                &(ratchet->root_key), sender_chain->chain_key,
                &((sender_chain->ratchet_key)[old_ratchet_key_num])
            );
        }
        (sender_chain->n_ratchet_key)++;
        (ratchet->root_sequence)++;
    }

    Skissm__MsgKey *msg_key;
    msg_key = (Skissm__MsgKey *) malloc(sizeof(Skissm__MsgKey));
    skissm__msg_key__init(msg_key);
    create_msg_keys(cipher_suite, sender_chain->chain_key, msg_key);
    advance_chain_key(cipher_suite, sender_chain->chain_key);

    uint32_t sequence = msg_key->index;

    size_t ratchet_key_num = sender_chain->n_ratchet_key;
    ProtobufCBinaryData *ratchet_key_list = (ProtobufCBinaryData *) malloc(sizeof(ProtobufCBinaryData) * ratchet_key_num);
    size_t i;
    for (i = 0; i < ratchet_key_num; i++) {
        copy_protobuf_from_protobuf(&(ratchet_key_list[i]), &((sender_chain->ratchet_key)[i]));
    }

    *payload = (Skissm__One2oneMsgPayload *) malloc(sizeof(Skissm__One2oneMsgPayload));
    skissm__one2one_msg_payload__init(*payload);
    (*payload)->sequence = sequence;
    (*payload)->n_ratchet_key = ratchet_key_num;
    (*payload)->ratchet_key = ratchet_key_list;
    (*payload)->root_sequence = ratchet->root_sequence;
    (*payload)->ciphertext.len = cipher_suite->encrypt(
        &ad,
        msg_key->derived_key.data,
        plaintext_data, plaintext_data_len,
        &((*payload)->ciphertext.data)
    );

    // debug log
    //char *derived_key_str;
    //size_t derived_key_str_len = to_hex_str(msg_key->derived_key.data, msg_key->derived_key.len, &derived_key_str);
    //ssm_notify_log(NULL, DEBUG_LOG, "encrypt_ratchet() seq: %d, derived_key[len = %d]: %s\n", sequence, msg_key->derived_key.len, derived_key_str);
    //free(derived_key_str);
    //char *plaintext_str;
    //size_t plaintext_str_len = to_hex_str(plaintext_data, plaintext_data_len, &plaintext_str);
    //ssm_notify_log(NULL, DEBUG_LOG, "encrypt_ratchet() seq: %d, plaintext[len = %d]: %s\n", sequence, plaintext_data_len, plaintext_str);
    //free(plaintext_str);

    // release
    skissm__msg_key__free_unpacked(msg_key, NULL);

    // done
    return;
}

size_t decrypt_ratchet(
    const cipher_suite_t *cipher_suite,
    Skissm__Ratchet *ratchet, ProtobufCBinaryData ad, Skissm__One2oneMsgPayload *payload,
    uint8_t **plaintext_data
) {
    if (payload->n_ratchet_key > MAX_RECEIVER_CHAIN_NODES) {
        ssm_notify_log(
            NULL,
            BAD_MESSAGE_SEQUENCE,
            "decrypt_ratchet() the root tree is too long\n"
        );
        return 0;
    }
    // ssm_notify_log(NULL, DEBUG_LOG, "decrypt_ratchet() seq: %d\n", payload->sequence);

    int ratchet_key_len;
    if (cipher_suite->get_crypto_param().pqc_param == false) {
        ratchet_key_len = cipher_suite->get_crypto_param().asym_pub_key_len;
    } else {
        ratchet_key_len = cipher_suite->get_crypto_param().kem_ciphertext_len;
    }

    if (!payload->ratchet_key || !payload->ciphertext.data) {
        ssm_notify_log(NULL, BAD_MESSAGE_FORMAT, "decrypt_ratchet()");
        return 0;
    }

    Skissm__ReceiverChainNode *receiver_chain = NULL;

    // find the corresponding receiving chain
    Skissm__ReceiverChainNode **cur = ratchet->receiver_chains;

    uint32_t coming_root_sequence = payload->root_sequence;
    // comint_root_sequence should be positive
    if (coming_root_sequence == 0) {
        ssm_notify_log(NULL, BAD_MESSAGE_FORMAT, "decrypt_ratchet()");
        return 0;
    }

    uint32_t our_root_sequence = ratchet->root_sequence;
    if (cur) {
        if (coming_root_sequence <= our_root_sequence) {
            if ((payload->ratchet_key[coming_root_sequence - 1].len == ratchet_key_len)
                && (0 == memcmp(
                        cur[coming_root_sequence - 1]->ratchet_key_public.data,
                        payload->ratchet_key[coming_root_sequence - 1].data,
                        ratchet_key_len
                    )
                )
            ) {
                // found out the corresponding receiving chain
                receiver_chain = cur[coming_root_sequence - 1];
            } else {
                ssm_notify_log(NULL, BAD_MESSAGE_FORMAT, "decrypt_ratchet()");
                return 0;
            }
        }
    }

    size_t result = 0;
    if (!receiver_chain) {
        if (ratchet->n_receiver_chains == MAX_RECEIVER_CHAIN_NODES) {
            ssm_notify_log(NULL, BAD_MESSAGE_SEQUENCE, "decrypt_ratchet()");
            return 0;
        }
        /* They have started using a new ephemeral ratchet key.
         * We will check if we can decrypt the message correctly.
         * We will not store our new chain key now.
         * We will store our new chain key later when decrypting the message correctly. */
        result = verify_and_decrypt_for_new_chain(
            cipher_suite,
            ratchet, ad, payload, plaintext_data
        );
        if (result == 0) {
            ssm_notify_log(NULL, BAD_MESSAGE_MAC, "verify_and_decrypt_for_new_chain() in decrypt_ratchet()");
            return 0;
        }
    } else if (receiver_chain->chain_key->index > payload->sequence) {
        /* receiver_chain already advanced beyond the key for this message
         * Check if the message keys are in the skipped key list. */
        size_t i, j;
        for (i = 0; i < ratchet->n_skipped_msg_keys; i++){
            if (payload->sequence == ratchet->skipped_msg_keys[i]->msg_key->index
                && 0 == memcmp(
                    ratchet->skipped_msg_keys[i]->ratchet_key_public.data,
                    payload->ratchet_key[coming_root_sequence - 1].data,
                    ratchet_key_len
                )
            ){
                result = verify_and_decrypt(
                    cipher_suite, ad, ratchet->skipped_msg_keys[i]->msg_key, payload,
                    plaintext_data
                );

                if (result > 0){
                    Skissm__SkippedMsgKeyNode **temp_skipped_message_keys = (Skissm__SkippedMsgKeyNode **) malloc(sizeof(Skissm__SkippedMsgKeyNode *) * (ratchet->n_skipped_msg_keys - 1));

                    size_t k = 0;
                    for (j = 0; j < ratchet->n_skipped_msg_keys; j++) {
                        if (j == i) {
                            // remove node
                            continue;
                        }
                        temp_skipped_message_keys[k] = (Skissm__SkippedMsgKeyNode *) malloc(sizeof(Skissm__SkippedMsgKeyNode));
                        skissm__skipped_msg_key_node__init(temp_skipped_message_keys[k]);
                        copy_protobuf_from_protobuf(&(temp_skipped_message_keys[k]->ratchet_key_public), &(ratchet->skipped_msg_keys[j]->ratchet_key_public));
                        temp_skipped_message_keys[k]->msg_key = (Skissm__MsgKey *) malloc(sizeof(Skissm__MsgKey));
                        skissm__msg_key__init(temp_skipped_message_keys[k]->msg_key);
                        temp_skipped_message_keys[k]->msg_key->index = ratchet->skipped_msg_keys[j]->msg_key->index;
                        copy_protobuf_from_protobuf(&(temp_skipped_message_keys[k]->msg_key->derived_key), &(ratchet->skipped_msg_keys[j]->msg_key->derived_key));
                        k++;
                    }
                    free_skipped_message_key(&(ratchet->skipped_msg_keys), ratchet->n_skipped_msg_keys);
                    ratchet->skipped_msg_keys = temp_skipped_message_keys;
                    (ratchet->n_skipped_msg_keys)--;
                    break;
                } else {
                    ssm_notify_log(NULL, BAD_MESSAGE_MAC, "verify_and_decrypt() in decrypt_ratchet()");
                    return 0;
                }
            }
        }
        if (result == 0) {
            // the corresponding message key not found
            ssm_notify_log(NULL, BAD_MESSAGE_KEY, "decrypt_ratchet()");
        }
    } else {
        /* They use the same ratchet key. The sequence of the payload(incoming message) 
         * may be bigger than or equal to the index of our receiver chain. */
        result = verify_and_decrypt_for_existing_chain(
            cipher_suite,
            ad, receiver_chain->chain_key,
            payload, plaintext_data
        );
        if (result == 0) {
            ssm_notify_log(NULL, BAD_MESSAGE_MAC, "verify_and_decrypt_for_existing_chain() in decrypt_ratchet()");
            return 0;
        }
    }

    // ready to advance chain key of receiver_chain
    if (!receiver_chain) {
        /* They have started using a new ephemeral ratchet key.
         * We need to derive a new set of chain keys.
         * We can discard our previous empheral ratchet key.
         * We will generate a new key when we send the next message. */

        size_t i, cur_receiver_chain_num;
        Skissm__ReceiverChainNode *cur_receiver_chain = NULL;
        for (i = our_root_sequence; i < coming_root_sequence; i++) {
            cur_receiver_chain_num = ratchet->n_receiver_chains;

            cur_receiver_chain = (Skissm__ReceiverChainNode *) malloc(sizeof(Skissm__ReceiverChainNode));
            skissm__receiver_chain_node__init(cur_receiver_chain);

            // copy their ratchet key
            copy_protobuf_from_protobuf(&(cur_receiver_chain->ratchet_key_public), &(payload->ratchet_key[i]));

            // create a new chain key
            cur_receiver_chain->chain_key = (Skissm__ChainKey *) malloc(sizeof(Skissm__ChainKey));
            skissm__chain_key__init(cur_receiver_chain->chain_key);
            create_chain_key(
                cipher_suite,
                ratchet->root_key, &(ratchet->sender_chain->ratchet_key[0]), &(cur_receiver_chain->ratchet_key_public),
                &(ratchet->root_key), cur_receiver_chain->chain_key, NULL
            );
            if (ratchet->receiver_chains == NULL){
                ratchet->receiver_chains = (Skissm__ReceiverChainNode **) malloc(sizeof(Skissm__ReceiverChainNode *));
            } else{
                Skissm__ReceiverChainNode **temp_receiver_chains;
                temp_receiver_chains = (Skissm__ReceiverChainNode **) malloc(sizeof(Skissm__ReceiverChainNode *) * (cur_receiver_chain_num + 1));
                copy_receiver_chain_node(temp_receiver_chains, ratchet->receiver_chains, cur_receiver_chain_num);
                free_receiver_chain(&(ratchet->receiver_chains), cur_receiver_chain_num);
                ratchet->receiver_chains = temp_receiver_chains;
            }
            ratchet->receiver_chains[cur_receiver_chain_num] = cur_receiver_chain;
            (ratchet->n_receiver_chains)++;

            (ratchet->root_sequence)++;
        }

        receiver_chain = cur_receiver_chain;
    }

    if (receiver_chain->chain_key->index < payload->sequence){
        /* We skipped some messages.
         * We will generate the corresponding message keys and store them
         * together with their ratchet key in the skipped message key list. */
        size_t skipped_num = payload->sequence - receiver_chain->chain_key->index;
        if (ratchet->skipped_msg_keys == NULL){
            ratchet->skipped_msg_keys = (Skissm__SkippedMsgKeyNode **) malloc(sizeof(Skissm__SkippedMsgKeyNode *) * skipped_num);
        } else{
            Skissm__SkippedMsgKeyNode **temp_skipped_message_keys;
            temp_skipped_message_keys = (Skissm__SkippedMsgKeyNode **) malloc(sizeof(Skissm__SkippedMsgKeyNode *) * (ratchet->n_skipped_msg_keys + skipped_num));
            copy_skipped_msg_key_node(temp_skipped_message_keys, ratchet->skipped_msg_keys, ratchet->n_skipped_msg_keys);
            free_skipped_message_key(&(ratchet->skipped_msg_keys), ratchet->n_skipped_msg_keys);
            ratchet->skipped_msg_keys = temp_skipped_message_keys;
        }
        while (receiver_chain->chain_key->index < payload->sequence){
            // insert data
            Skissm__SkippedMsgKeyNode *key = (Skissm__SkippedMsgKeyNode *) malloc(sizeof(Skissm__SkippedMsgKeyNode));
            skissm__skipped_msg_key_node__init(key);
            key->msg_key = (Skissm__MsgKey *) malloc(sizeof(Skissm__MsgKey));
            skissm__msg_key__init(key->msg_key);
            create_msg_keys(cipher_suite, receiver_chain->chain_key, key->msg_key);
            copy_protobuf_from_protobuf(&(key->ratchet_key_public), &(receiver_chain->ratchet_key_public));

            ratchet->skipped_msg_keys[ratchet->n_skipped_msg_keys] = key;
            (ratchet->n_skipped_msg_keys)++;
            advance_chain_key(cipher_suite, receiver_chain->chain_key);
        }
    }

    if (receiver_chain->chain_key->index == payload->sequence) {
        /* If we decrypt the incoming message by a skipped message key,
         * we will not need to advance the chain key. */
        advance_chain_key(cipher_suite, receiver_chain->chain_key);
    }

    return result;
}
