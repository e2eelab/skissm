#include "echo_server.hpp"
#include "client.hpp"
#include <unistd.h> // for sleep
#include <fstream>

#include "test_env.h"
#include "mem_util.h"

using namespace std;
int main(int argc, char** argv) {
  if(argc != 2){
    cout << "usage: " << argv[0] << " [port]" << endl;
    exit(-1);
  }
  size_t port = atoi(argv[1]);

  WebsoeketEchoServer server;
  server.run(port);

  WebsocketClient client;
  client.connect("ws://localhost:" + to_string(port));
  sleep(1);

  for(int i=0; i<2000; i++){
    ifstream ifs;
    ifs.open("./data/"+to_string(i), ifstream::in);
    ifs.seekg(0, ios::end);
    size_t size = ifs.tellg();
    string msg(size, ' ');

    ifs.seekg(0);
    ifs.read(&msg[0], size);

    ifs.close();

    client.send(msg);
  }

  bool stop = false;
  while(!stop){
    size_t num_sent = client.get_num_msgs_sent();
    size_t num_recv = client.get_num_msgs_recv();
    stop = (num_sent == num_recv);
    usleep(100);
    cout << "\r" << setw(6) << num_recv << "/" << setw(6) << num_sent;
  }
  cout << endl;

  unordered_set<string> test_data;
  vector<string> msgs_sent = client.get_msgs_sent();
  vector<string> msgs_recv = client.get_msgs_recv();
  for(auto s: msgs_sent){
    test_data.insert(s);
  }

  for(auto s: msgs_recv){
    test_data.erase(s);
  }

  assert(test_data.size()==0);

  cout << "finished!" << endl;

  return 0;
}
