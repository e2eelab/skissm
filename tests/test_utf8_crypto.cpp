extern "C"
{
#include <string.h>
#include <assert.h>

#include "ratchet.h"
#include "cipher.h"
#include "mem_util.h"
#include "test_env.h"
}

#include "./client.hpp"
#include "./echo_server.hpp"
#include <unistd.h>
#include <fstream>

using namespace std;

int main(int argc, char **argv)
{
  if (argc != 2)
  {
    cout << "usage: " << argv[0] << " [port]" << endl;
    exit(-1);
  }
  size_t port = atoi(argv[1]);

  Org__E2eelab__Lib__Protobuf__KeyPair alice_ratchet_key;
  crypto_curve25519_generate_key(&alice_ratchet_key);

  Org__E2eelab__Lib__Protobuf__KeyPair bob_spk;
  crypto_curve25519_generate_key(&bob_spk);

  uint8_t shared_secret[] = "shared_secret:nwjeldUbnjwcwkdt5q";

  {
    WebsoeketEchoServer server;
    server.run(port);

    WebsocketClient client;
    client.connect("ws://localhost:" + to_string(port));
    sleep(1);

    // unordered_set<string> test_data;
    /* Bob sends Alice a message */
    size_t tot_test = 2000;
    for (int i = 100; i < tot_test; i++)
    {
      cout << "\r" << "testing #" << i << " data..." << std::flush;

      // prepare ratchet
      Org__E2eelab__Lib__Protobuf__Ratchet alice_ratchet, bob_ratchet;
      initialise_ratchet(&alice_ratchet);
      initialise_ratchet(&bob_ratchet);

      initialise_as_alice(&alice_ratchet, shared_secret,
                          sizeof(shared_secret) - 1, &alice_ratchet_key,
                          &(bob_spk.public_key));
      initialise_as_bob(&bob_ratchet, shared_secret, sizeof(shared_secret) - 1,
                        &bob_spk);
      assert(
          memcmp(
              bob_spk.public_key.data,
              bob_ratchet.sender_chain->ratchet_key_pair->public_key.data,
              CURVE25519_KEY_LENGTH) == 0);
      assert(
          memcmp(
              bob_spk.private_key.data,
              bob_ratchet.sender_chain->ratchet_key_pair->private_key.data,
              CURVE25519_KEY_LENGTH) == 0);

      // load testing data
      ifstream ifs;
      ifs.open("./data/" + to_string(i), ifstream::in);
      ifs.seekg(0, ios::end);
      size_t plaintext_len = ifs.tellg();
      uint8_t plaintext[plaintext_len];

      ifs.seekg(0);
      ifs.read((char *)plaintext, plaintext_len);

      ifs.close();

      uint8_t associated_data[AD_LENGTH] = {0};
      ProtobufCBinaryData ad;
      ad.len = AD_LENGTH;
      ad.data = (uint8_t *) malloc(AD_LENGTH * sizeof(uint8_t));
      for (int j = 0; j < 64; j++) {
        ad.data[j] = associated_data[j];
      }

      // encrypt
      ProtobufCBinaryData session_id;
      random_session_id(&session_id);

      size_t plaintext_length = sizeof(plaintext);
      Org__E2eelab__Lib__Protobuf__E2eeMsgContext *message;
      encrypt_ratchet(&alice_ratchet, ad, plaintext, plaintext_length, &message);

      // send msg
      size_t message_length = org__e2eelab__lib__protobuf__e2ee_msg_context__get_packed_size(message);
      string message_str(reinterpret_cast<char const *>(message), message_length);
      assert(message_str.size() == message_length);

      client.send(message_str);

      // wait until recv
      bool stop = false;
      while (!stop)
      {
        size_t num_sent = client.get_num_msgs_sent();
        size_t num_recv = client.get_num_msgs_recv();
        stop = (num_sent == num_recv);
        usleep(10);
      }

      // get latest msg sent by server
      string enc_text_str = client.get_latest_msg_recv();

      // decrypt
      uint8_t *dec_text;
      const uint8_t *enc_text = reinterpret_cast<const uint8_t *>(enc_text_str.c_str());
      size_t enc_text_len = enc_text_str.size();

      Org__E2eelab__Lib__Protobuf__E2eeMsgContext *msg_context = org__e2eelab__lib__protobuf__e2ee_msg_context__unpack(NULL, enc_text_len, enc_text);

      size_t dec_text_len = decrypt_ratchet(&bob_ratchet, ad, msg_context, &dec_text);

      // test
      string dec_text_str(reinterpret_cast<char const *>(dec_text), dec_text_len);
      assert(dec_text_len == plaintext_len);
      assert(memcmp(dec_text_str.c_str(), plaintext, plaintext_len) == 0);
    }
    cout << endl;

    cout << "finished!" << endl;
  }

  return 0;
}
