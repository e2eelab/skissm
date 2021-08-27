extern "C"
{
#include <string.h>
#include <assert.h>

#include "mem_util.h"
#include "test_env.h"
}

#include <unistd.h>
#include <fstream>

#include "client.hpp"
#include "echo_server.hpp"

using namespace std;

static  size_t encrypt(uint8_t * plaintext, size_t plaintext_len, uint8_t **encrypted_msg) {
  *encrypted_msg = (uint8_t *)malloc(plaintext_len);
  size_t encrypted_msg_len = plaintext_len;
  memcpy(*encrypted_msg, plaintext, encrypted_msg_len);

  return encrypted_msg_len;
}

static  size_t decrypt(uint8_t * ciphertext, size_t ciphertext_len, uint8_t **decrypted_msg) {
  *decrypted_msg = (uint8_t *)malloc(ciphertext_len);
  size_t decrypted_msg_len = ciphertext_len;
  memcpy(*decrypted_msg, ciphertext, decrypted_msg_len);

  return decrypted_msg_len;
}

int main(int argc, char **argv)
{
  if (argc != 2)
  {
    cout << "usage: " << argv[0] << " [port]" << endl;
    exit(-1);
  }
  size_t port = atoi(argv[1]);

  Org__E2eelab__Skissm__Proto__KeyPair alice_ratchet_key;
  crypto_curve25519_generate_key(&alice_ratchet_key);

  Org__E2eelab__Skissm__Proto__KeyPair bob_spk;
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
    for (int i = 0; i < tot_test; i++)
    {
      cout << "\r" << "testing #" << i << " data..." << std::flush;
      // load testing data
      ifstream ifs;
      ifs.open("./data/" + to_string(i), ifstream::in);
      ifs.seekg(0, ios::end);
      size_t plaintext_len = ifs.tellg();
      uint8_t plaintext[plaintext_len];

      ifs.seekg(0);
      ifs.read((char *)plaintext, plaintext_len);
      ifs.close();

      // encrypt
      uint8_t *encrypted_text;
      size_t encrypted_text_len = encrypt(plaintext, plaintext_len, &encrypted_text);

      // send msg
      string message_str(reinterpret_cast<char const *>(encrypted_text), encrypted_text_len);
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
      string received_text_str = client.get_latest_msg_recv();
      const uint8_t *received_text = reinterpret_cast<const uint8_t *>(received_text_str.c_str());
      size_t received_text_len = received_text_str.size();

      // decrypt
      uint8_t *decrypted_text;
      size_t decrypted_text_len = decrypt(received_text, received_text_len, &decrypted_text);

      // compare
      assert(decrypted_text_len == plaintext_len);
      assert(memcmp(decrypted_text, plaintext, plaintext_len) == 0);

      // release
      free(encrypted_text);
      free(decrypted_text);
    }
    cout << endl;

    cout << "finished!" << endl;
  }

  return 0;
}
