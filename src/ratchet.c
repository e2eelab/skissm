#include <string.h>

#include "skissm.h"
#include "ratchet.h"
#include "cipher.h"
#include "crypto.h"
#include "mem_util.h"
#include "error.h"

static const char MESSAGE_KEY_SEED[] = "MessageKeys";
static const uint8_t CHAIN_KEY_SEED[1] = {0x02};
static const size_t MAX_MESSAGE_GAP = 2000;

static const struct cipher CIPHER = CIPHER_INIT;

static void free_e2ee_msg_context(Org__E2eelab__Lib__Protobuf__E2eeMsgPayload *e2ee_msg_payload) {
    free_protobuf(&(e2ee_msg_payload->ratchet_key));
    free_protobuf(&(e2ee_msg_payload->ciphertext));
    unset((void volatile *)e2ee_msg_payload, sizeof(Org__E2eelab__Lib__Protobuf__E2eeMsgPayload));
}

static void free_message_key(Org__E2eelab__Lib__Protobuf__MessageKey *message_key) {
    free_protobuf(&(message_key->derived_key));
    unset((void volatile *)message_key, sizeof(Org__E2eelab__Lib__Protobuf__MessageKey));
}

static void create_chain_key(
    const ProtobufCBinaryData root_key,
    const Org__E2eelab__Lib__Protobuf__KeyPair *our_key,
    const ProtobufCBinaryData *their_key,
    ProtobufCBinaryData *new_root_key,
    Org__E2eelab__Lib__Protobuf__ChainKey *new_chain_key
) {
    shared_key secret;
    CIPHER.suit1->dh(our_key, their_key, secret);
    uint8_t derived_secrets[2 * SHARED_KEY_LENGTH];
    CIPHER.suit1->hkdf(
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

    new_chain_key->index = 0;
    copy_protobuf_from_array(&new_chain_key->shared_key, derived_secrets + 32, SHARED_KEY_LENGTH);

    unset(derived_secrets, sizeof(derived_secrets));
    unset(secret, sizeof(secret));
}

static void advance_chain_key(
    Org__E2eelab__Lib__Protobuf__ChainKey *chain_key
) {
    uint8_t shared_key[SHARED_KEY_LENGTH] = {0};
    CIPHER.suit1->hmac(
        chain_key->shared_key.data, chain_key->shared_key.len,
        CHAIN_KEY_SEED, sizeof(CHAIN_KEY_SEED),
        shared_key
    );

    chain_key->index = chain_key->index + 1;
    overwrite_protobuf_from_array(&chain_key->shared_key, shared_key);
}

static void create_message_keys(
    const Org__E2eelab__Lib__Protobuf__ChainKey *chain_key,
    Org__E2eelab__Lib__Protobuf__MessageKey *message_key
) {
    free_protobuf(&(message_key->derived_key));
    message_key->derived_key.data = (uint8_t *) malloc(sizeof(uint8_t) * MESSAGE_KEY_LENGTH);
    message_key->derived_key.len = MESSAGE_KEY_LENGTH;

    uint8_t salt[SHA256_OUTPUT_LENGTH] = {0};
    CIPHER.suit1->hkdf(
        chain_key->shared_key.data, chain_key->shared_key.len,
        salt, sizeof(salt),
        (uint8_t *)MESSAGE_KEY_SEED, sizeof(MESSAGE_KEY_SEED) - 1,
        message_key->derived_key.data, message_key->derived_key.len
    );
    message_key->index = chain_key->index;
}

static size_t verify_and_decrypt(
    const cipher *cipher,
    ProtobufCBinaryData ad,
    const Org__E2eelab__Lib__Protobuf__MessageKey *message_key,
    const Org__E2eelab__Lib__Protobuf__E2eeMsgPayload *e2ee_msg_payload,
    uint8_t **plaintext
) {
    size_t result = cipher->suit1->decrypt(
        ad.data,
        message_key->derived_key.data,
        e2ee_msg_payload->ciphertext.data, e2ee_msg_payload->ciphertext.len,
        plaintext
    );

    if (result == (size_t)(-1))
        ssm_notify_error(BAD_MESSAGE_DECRYPTION, "verify_mac_and_decrypt()");

    return result;
}

static size_t verify_and_decrypt_for_existing_chain(
    ProtobufCBinaryData ad,
    const Org__E2eelab__Lib__Protobuf__ChainKey *chain,
    const Org__E2eelab__Lib__Protobuf__E2eeMsgPayload *e2ee_msg_payload,
    uint8_t **plaintext
) {
    if (e2ee_msg_payload->sequence < chain->index) {
        ssm_notify_error(BAD_MESSAGE_SEQUENCE, "verify_mac_and_decrypt_for_existing_chain()");
        return (size_t)(-1);
    }

    /* Limit the number of hashes we're prepared to compute */
    if (e2ee_msg_payload->sequence - chain->index > MAX_MESSAGE_GAP) {
        ssm_notify_error(BAD_MESSAGE_SEQUENCE, "verify_mac_and_decrypt_for_existing_chain()");
        return (size_t)(-1);
    }

    Org__E2eelab__Lib__Protobuf__ChainKey *new_chain = (Org__E2eelab__Lib__Protobuf__ChainKey *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__ChainKey));
    org__e2eelab__lib__protobuf__chain_key__init(new_chain);
    new_chain->index = chain->index;
    copy_protobuf_from_protobuf(&new_chain->shared_key, &chain->shared_key);

    while (new_chain->index < e2ee_msg_payload->sequence) {
        advance_chain_key(new_chain);
    }
    assert(new_chain->index == e2ee_msg_payload->sequence);

    Org__E2eelab__Lib__Protobuf__MessageKey *mk = (Org__E2eelab__Lib__Protobuf__MessageKey *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__MessageKey));
    org__e2eelab__lib__protobuf__message_key__init(mk);
    create_message_keys(new_chain, mk);

    size_t result = verify_and_decrypt(
        &CIPHER, ad, mk, e2ee_msg_payload,
        plaintext
    );

    org__e2eelab__lib__protobuf__chain_key__free_unpacked(new_chain, NULL);

    return result;
}

static size_t verify_and_decrypt_for_new_chain(
    const Org__E2eelab__Lib__Protobuf__Ratchet *ratchet, ProtobufCBinaryData ad,
    const Org__E2eelab__Lib__Protobuf__E2eeMsgPayload *e2ee_msg_payload,
    uint8_t **plaintext
) {
    ProtobufCBinaryData new_root_key = {0, NULL};
    Org__E2eelab__Lib__Protobuf__ReceiverChainNode new_chain;

    /** The sendind chain will be released only when they used a new ratchet key
     * and we have "finished" decrypting the first message.
     * We are just trying to decrypt the first message at the moment. */
    if (ratchet->sender_chain == NULL) {
        ssm_notify_error(BAD_MESSAGE_DECRYPTION, "verify_mac_and_decrypt_for_new_chain()");
        return (size_t)(-1);
    }

    /* Limit the number of hashes we're prepared to compute */
    if (e2ee_msg_payload->sequence > MAX_MESSAGE_GAP) {
        ssm_notify_error(BAD_MESSAGE_SEQUENCE, "verify_mac_and_decrypt_for_new_chain()");
        return (size_t)(-1);
    }

    assert(e2ee_msg_payload->ratchet_key.len == CURVE25519_KEY_LENGTH);

    org__e2eelab__lib__protobuf__receiver_chain_node__init(&new_chain);
    copy_protobuf_from_protobuf(&(new_chain.ratchet_key_public), &(e2ee_msg_payload->ratchet_key));
    
    new_chain.chain_key = (Org__E2eelab__Lib__Protobuf__ChainKey *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__ChainKey));
    org__e2eelab__lib__protobuf__chain_key__init(new_chain.chain_key);

    create_chain_key(
        ratchet->root_key, ratchet->sender_chain->ratchet_key_pair,
        &(new_chain.ratchet_key_public), &new_root_key, new_chain.chain_key
    );
    size_t result = verify_and_decrypt_for_existing_chain(
        ad, new_chain.chain_key, e2ee_msg_payload,
        plaintext
    );

    free_protobuf(&new_root_key);
    unset((void volatile *)&new_root_key, sizeof(ProtobufCBinaryData));
    free_protobuf(&(new_chain.ratchet_key_public));
    free_protobuf(&(new_chain.chain_key->shared_key));
    unset((void volatile *)&new_chain, sizeof(Org__E2eelab__Lib__Protobuf__ReceiverChainNode));

    return result;
}

void initialise_ratchet(Org__E2eelab__Lib__Protobuf__Ratchet **ratchet){
    *ratchet = (Org__E2eelab__Lib__Protobuf__Ratchet *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__Ratchet));
    org__e2eelab__lib__protobuf__ratchet__init(*ratchet);
}

void initialise_as_bob(
    Org__E2eelab__Lib__Protobuf__Ratchet *ratchet, const uint8_t *shared_secret, size_t shared_secret_length,
    const Org__E2eelab__Lib__Protobuf__KeyPair *our_ratchet_key
){
    /* The ssk will be 64 bytes */
    uint8_t derived_secrets[2 * SHARED_KEY_LENGTH];
    uint8_t salt[SHA256_OUTPUT_LENGTH] = {0};
    CIPHER.suit1->hkdf(
        shared_secret, shared_secret_length,
        salt, sizeof(salt),
        (uint8_t *)KDF_INFO_ROOT, sizeof(KDF_INFO_ROOT) - 1,
        derived_secrets, sizeof(derived_secrets)
    );

    ratchet->sender_chain = (Org__E2eelab__Lib__Protobuf__SenderChainNode *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__SenderChainNode));
    org__e2eelab__lib__protobuf__sender_chain_node__init(ratchet->sender_chain);
    ratchet->sender_chain->chain_key = (Org__E2eelab__Lib__Protobuf__ChainKey *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__ChainKey));
    org__e2eelab__lib__protobuf__chain_key__init(ratchet->sender_chain->chain_key);
    ratchet->sender_chain->chain_key->index = 0;

    /* The first half of the ssk will be the root key, and the second half will be the sending chain key */
    copy_protobuf_from_array(&(ratchet->root_key), derived_secrets, SHARED_KEY_LENGTH);

    copy_protobuf_from_array(&(ratchet->sender_chain->chain_key->shared_key), derived_secrets + SHARED_KEY_LENGTH, SHARED_KEY_LENGTH);

    ratchet->sender_chain->ratchet_key_pair = (Org__E2eelab__Lib__Protobuf__KeyPair *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__KeyPair));
    org__e2eelab__lib__protobuf__key_pair__init(ratchet->sender_chain->ratchet_key_pair);
    copy_protobuf_from_protobuf(&(ratchet->sender_chain->ratchet_key_pair->public_key), &(our_ratchet_key->public_key));
    copy_protobuf_from_protobuf(&(ratchet->sender_chain->ratchet_key_pair->private_key), &(our_ratchet_key->private_key));

    unset(derived_secrets, sizeof(derived_secrets));
}

void initialise_as_alice(
    Org__E2eelab__Lib__Protobuf__Ratchet *ratchet, const uint8_t *shared_secret, size_t shared_secret_length,
    const Org__E2eelab__Lib__Protobuf__KeyPair *our_ratchet_key, ProtobufCBinaryData *their_ratchet_key
){
    /* The length of derived_secrets will be 64 bytes */
    uint8_t derived_secrets[2 * SHARED_KEY_LENGTH] = {0};
    uint8_t salt[SHA256_OUTPUT_LENGTH] = {0};

    /* shared_secret_length may be 128 or 96 */
    CIPHER.suit1->hkdf(
        shared_secret, shared_secret_length,
        salt, sizeof(salt),
        (uint8_t *)KDF_INFO_ROOT, sizeof(KDF_INFO_ROOT) - 1,
        derived_secrets, sizeof(derived_secrets)
    );
    ratchet->receiver_chains = (Org__E2eelab__Lib__Protobuf__ReceiverChainNode **) malloc(sizeof(Org__E2eelab__Lib__Protobuf__ReceiverChainNode *));
    ratchet->receiver_chains[0] = (Org__E2eelab__Lib__Protobuf__ReceiverChainNode *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__ReceiverChainNode));
    org__e2eelab__lib__protobuf__receiver_chain_node__init(ratchet->receiver_chains[0]);
    ratchet->receiver_chains[0]->chain_key = (Org__E2eelab__Lib__Protobuf__ChainKey *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__ChainKey));
    org__e2eelab__lib__protobuf__chain_key__init(ratchet->receiver_chains[0]->chain_key);

    /* The first half of the ssk will be the root key, and the second half will be the receiving chain key */
    copy_protobuf_from_array(&(ratchet->root_key), derived_secrets, SHARED_KEY_LENGTH);

    copy_protobuf_from_array(&(ratchet->receiver_chains[0]->chain_key->shared_key), derived_secrets + SHARED_KEY_LENGTH, SHARED_KEY_LENGTH);

    copy_protobuf_from_protobuf(&(ratchet->receiver_chains[0]->ratchet_key_public), their_ratchet_key);

    (ratchet->n_receiver_chains)++;

    /* Generate a new root key and a sending chain key */
    ratchet->sender_chain = (Org__E2eelab__Lib__Protobuf__SenderChainNode *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__SenderChainNode));
    org__e2eelab__lib__protobuf__sender_chain_node__init(ratchet->sender_chain);
    
    ratchet->sender_chain->chain_key = (Org__E2eelab__Lib__Protobuf__ChainKey *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__ChainKey));
    org__e2eelab__lib__protobuf__chain_key__init(ratchet->sender_chain->chain_key);
    
    create_chain_key(ratchet->root_key, our_ratchet_key, their_ratchet_key, &(ratchet->root_key), ratchet->sender_chain->chain_key);

    ratchet->sender_chain->ratchet_key_pair = (Org__E2eelab__Lib__Protobuf__KeyPair *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__KeyPair));
    org__e2eelab__lib__protobuf__key_pair__init(ratchet->sender_chain->ratchet_key_pair);
    copy_protobuf_from_protobuf(&(ratchet->sender_chain->ratchet_key_pair->public_key), &(our_ratchet_key->public_key));
    copy_protobuf_from_protobuf(&(ratchet->sender_chain->ratchet_key_pair->private_key), &(our_ratchet_key->private_key));

    unset(derived_secrets, sizeof(derived_secrets));
}

void encrypt_ratchet(
    Org__E2eelab__Lib__Protobuf__Ratchet *ratchet,
    ProtobufCBinaryData ad,
    const uint8_t *plaintext, size_t plaintext_length,
    Org__E2eelab__Lib__Protobuf__E2eeMsgPayload **e2ee_msg_payload
) {
    // Prepare sender_chain
    if (ratchet->sender_chain == NULL) {
        ratchet->sender_chain = (Org__E2eelab__Lib__Protobuf__SenderChainNode *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__SenderChainNode));
        org__e2eelab__lib__protobuf__sender_chain_node__init(ratchet->sender_chain);
        ratchet->sender_chain->ratchet_key_pair = (Org__E2eelab__Lib__Protobuf__KeyPair *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__KeyPair));
        org__e2eelab__lib__protobuf__key_pair__init(ratchet->sender_chain->ratchet_key_pair);
        CIPHER.suit1->gen_key_pair(ratchet->sender_chain->ratchet_key_pair);
        ratchet->sender_chain->chain_key = (Org__E2eelab__Lib__Protobuf__ChainKey *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__ChainKey));
        org__e2eelab__lib__protobuf__chain_key__init(ratchet->sender_chain->chain_key);
        create_chain_key(
            ratchet->root_key,
            ratchet->sender_chain->ratchet_key_pair,
            &(ratchet->receiver_chains[ratchet->n_receiver_chains - 1]->ratchet_key_public),
            &(ratchet->root_key), ratchet->sender_chain->chain_key
        );
    }

    Org__E2eelab__Lib__Protobuf__MessageKey *keys;
    keys = (Org__E2eelab__Lib__Protobuf__MessageKey *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__MessageKey));
    org__e2eelab__lib__protobuf__message_key__init(keys);
    create_message_keys(ratchet->sender_chain->chain_key, keys);
    advance_chain_key(ratchet->sender_chain->chain_key);

    uint32_t sequence = keys->index;
    const ProtobufCBinaryData *ratchet_key = &(ratchet->sender_chain->ratchet_key_pair->public_key);
    uint8_t *ratchet_key_data = (uint8_t *) malloc(CURVE25519_KEY_LENGTH);
    memcpy(ratchet_key_data, ratchet_key->data, CURVE25519_KEY_LENGTH);

    *e2ee_msg_payload = (Org__E2eelab__Lib__Protobuf__E2eeMsgPayload *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeMsgPayload));
    org__e2eelab__lib__protobuf__e2ee_msg_payload__init(*e2ee_msg_payload);
    (*e2ee_msg_payload)->sequence = sequence;
    (*e2ee_msg_payload)->ratchet_key.data = ratchet_key_data;
    (*e2ee_msg_payload)->ratchet_key.len = CURVE25519_KEY_LENGTH;
    (*e2ee_msg_payload)->ciphertext.len = CIPHER.suit1->encrypt(
        ad.data,
        keys->derived_key.data,
        plaintext, plaintext_length,
        &((*e2ee_msg_payload)->ciphertext.data)
    );

    // release
    org__e2eelab__lib__protobuf__message_key__free_unpacked(keys, NULL);

    // done
    return;
}

size_t decrypt_ratchet(
    Org__E2eelab__Lib__Protobuf__Ratchet *ratchet, ProtobufCBinaryData ad, Org__E2eelab__Lib__Protobuf__E2eeMsgPayload *e2ee_msg_payload,
    uint8_t **plaintext
) {
    if (!e2ee_msg_payload->ratchet_key.data
        || !e2ee_msg_payload->ciphertext.data) {
        ssm_notify_error(BAD_MESSAGE_FORMAT, "decrypt_ratchet()");
        return (size_t)(-1);
    }

    if (e2ee_msg_payload->ratchet_key.len != CURVE25519_KEY_LENGTH) {
        ssm_notify_error(BAD_MESSAGE_FORMAT, "decrypt_ratchet()");
        return (size_t)(-1);
    }

    Org__E2eelab__Lib__Protobuf__ReceiverChainNode *chain = NULL;

    /* Find the corresponding receiving chain */
    Org__E2eelab__Lib__Protobuf__ReceiverChainNode **cur = ratchet->receiver_chains;
    if (cur){
        unsigned int i;
        for (i = 0; i < ratchet->n_receiver_chains; i++){
            if (0 == memcmp(cur[i]->ratchet_key_public.data, e2ee_msg_payload->ratchet_key.data, CURVE25519_KEY_LENGTH)){
                chain = cur[i];
                break;
            }
        }
    }

    size_t result = (size_t)(-1);

    if (!chain) {
        /* They have started using a new ephemeral ratchet key.
         * We will check if we can decrypt the message correctly.
         * We will not store our new chain key now.
         * We will store our new chain key later when decrypting the message correctly. */
        result = verify_and_decrypt_for_new_chain(
            ratchet, ad, e2ee_msg_payload, plaintext
        );
        if (result == (size_t)(-1)) {
            ssm_notify_error(BAD_MESSAGE_MAC, "decrypt_ratchet()");
            return (size_t)(-1);
        }
    } else if (chain->chain_key->index > e2ee_msg_payload->sequence) {
        /* Chain already advanced beyond the key for this message
         * Check if the message keys are in the skipped key list. */
        unsigned int i;
        for (i = 0; i < ratchet->n_skipped_message_keys; i++){
            if (e2ee_msg_payload->sequence == ratchet->skipped_message_keys[i]->message_key->index
                && 0 == memcmp(ratchet->skipped_message_keys[i]->ratchet_key_public.data, e2ee_msg_payload->ratchet_key.data,
                CURVE25519_KEY_LENGTH
                )
            ){
                result = verify_and_decrypt(
                    &CIPHER, ad, ratchet->skipped_message_keys[i]->message_key, e2ee_msg_payload,
                    plaintext
                );

                if (result != (size_t)(-1)){
                    // free(ratchet->skipped_message_keys[i]);
                }
            }
        }
        if (result == (size_t)(-1)) {
            ssm_notify_error(BAD_MESSAGE_MAC, "decrypt_ratchet()");
            return (size_t)(-1);
        }
    } else {
        /* They use the same ratchet key. */
        result = verify_and_decrypt_for_existing_chain(
            ad, chain->chain_key,
            e2ee_msg_payload, plaintext
        );
        if (result == (size_t)(-1)) {
            ssm_notify_error(BAD_MESSAGE_MAC, "decrypt_ratchet()");
            return (size_t)(-1);
        }
    }

    if (!chain) {
        /* They have started using a new ephemeral ratchet key.
         * We need to derive a new set of chain keys.
         * We can discard our previous empheral ratchet key.
         * We will generate a new key when we send the next message. */

        chain = (Org__E2eelab__Lib__Protobuf__ReceiverChainNode *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__ReceiverChainNode));
        org__e2eelab__lib__protobuf__receiver_chain_node__init(chain);

        copy_protobuf_from_protobuf(&(chain->ratchet_key_public), &(e2ee_msg_payload->ratchet_key));

        // TODO: we've already done this once, in
        // verify_mac_and_decrypt_for_new_chain(). we could reuse the result.
        chain->chain_key = (Org__E2eelab__Lib__Protobuf__ChainKey *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__ChainKey));
        org__e2eelab__lib__protobuf__chain_key__init(chain->chain_key);
        create_chain_key(
            ratchet->root_key, ratchet->sender_chain->ratchet_key_pair, &(chain->ratchet_key_public),
            &(ratchet->root_key), chain->chain_key
        );
        if (ratchet->receiver_chains == NULL){
            ratchet->receiver_chains = (Org__E2eelab__Lib__Protobuf__ReceiverChainNode **) malloc(sizeof(Org__E2eelab__Lib__Protobuf__ReceiverChainNode *));
        } else{
            Org__E2eelab__Lib__Protobuf__ReceiverChainNode **temp_receiver_chains;
            temp_receiver_chains = (Org__E2eelab__Lib__Protobuf__ReceiverChainNode **) realloc(ratchet->receiver_chains, sizeof(Org__E2eelab__Lib__Protobuf__ReceiverChainNode *) * (ratchet->n_receiver_chains + 1));
            if (temp_receiver_chains == NULL){
                ssm_notify_error(NOT_ENOUGH_SPACE, "decrypt_ratchet()");
                return (size_t)(-1);
            }
            ratchet->receiver_chains = temp_receiver_chains;
        }
        ratchet->receiver_chains[ratchet->n_receiver_chains] = chain;
        (ratchet->n_receiver_chains)++;

        // ratchet->sender_chain will not be used anymore
        org__e2eelab__lib__protobuf__sender_chain_node__free_unpacked(ratchet->sender_chain, NULL);
        ratchet->sender_chain = NULL;
    }

    if (chain->chain_key->index < e2ee_msg_payload->sequence){
        /* We skipped some messages. 
         * We will generate the corresponding message keys and store them 
         * together with their ratchet key in the skipped message key list. */
        while (chain->chain_key->index < e2ee_msg_payload->sequence){
            Org__E2eelab__Lib__Protobuf__SkippedMessageKeyNode *key = (Org__E2eelab__Lib__Protobuf__SkippedMessageKeyNode *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__SkippedMessageKeyNode));
            org__e2eelab__lib__protobuf__skipped_message_key_node__init(key);
            key->message_key = (Org__E2eelab__Lib__Protobuf__MessageKey *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__MessageKey));
            org__e2eelab__lib__protobuf__message_key__init(key->message_key);
            create_message_keys(chain->chain_key, key->message_key);
            copy_protobuf_from_protobuf(&(key->ratchet_key_public), &(chain->ratchet_key_public));
            if (ratchet->skipped_message_keys == NULL){
                ratchet->skipped_message_keys = (Org__E2eelab__Lib__Protobuf__SkippedMessageKeyNode **) malloc(sizeof(Org__E2eelab__Lib__Protobuf__SkippedMessageKeyNode *));
            } else{
                Org__E2eelab__Lib__Protobuf__SkippedMessageKeyNode **temp_skipped_message_keys;
                temp_skipped_message_keys = (Org__E2eelab__Lib__Protobuf__SkippedMessageKeyNode **) realloc(ratchet->skipped_message_keys, sizeof(Org__E2eelab__Lib__Protobuf__SkippedMessageKeyNode *) * (ratchet->n_skipped_message_keys + 1));
                if (temp_skipped_message_keys == NULL){
                    ssm_notify_error(NOT_ENOUGH_MEMORY, "decrypt_ratchet()");
                    return (size_t)(-1);
                }
                ratchet->skipped_message_keys = temp_skipped_message_keys;
            }
            ratchet->skipped_message_keys[ratchet->n_skipped_message_keys] = key;
            (ratchet->n_skipped_message_keys)++;
            advance_chain_key(chain->chain_key);
        }
    }

    advance_chain_key(chain->chain_key);

    return result;
}
