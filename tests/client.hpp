#define ASIO_STANDALONE

#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/client.hpp>

#include <websocketpp/common/thread.hpp>
#include <websocketpp/common/memory.hpp>

#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <sstream>

#include <unordered_set>
#include <mutex>

#include <functional>


typedef websocketpp::client<websocketpp::config::asio_client> Client;

class ConnectionMetadata{
public:
  ConnectionMetadata(websocketpp::connection_hdl& hdl, std::string& uri):
  m_hdl(hdl), m_status("Connecting"), m_uri(uri){

  }

  ConnectionMetadata(){

  }

  void set_uri(const std::string& uri){
    m_uri = uri;
  }

  void set_hdl(const websocketpp::connection_hdl& hdl){
    m_hdl = hdl;
  }

  void on_open(Client* client_p, const websocketpp::connection_hdl& hdl){
    m_status = "Open";
  }

  void on_fail(Client* client_p, const websocketpp::connection_hdl& hdl)
  {
    m_status = "Failed";

    Client::connection_ptr con_p = client_p->get_con_from_hdl(hdl);
    std::string error_reason = con_p->get_ec().message();

    std::cout << "error reason: " << error_reason << std::endl;
  }

  void on_close(Client* client_p, const websocketpp::connection_hdl& hdl)
  {
    m_status = "Closed";

    Client::connection_ptr con_p = client_p->get_con_from_hdl(hdl);
    std::cout 
      << "close code: " << con_p->get_remote_close_code() 
      << " (" << websocketpp::close::status::get_string(con_p->get_remote_close_code()) << "), "
      << "close reason: " << con_p->get_remote_close_reason();
  }

  void on_message(const websocketpp::connection_hdl& hdl, const Client::message_ptr& msg_p){
    m_mutex.lock();
    m_msgs_recv.push_back(msg_p->get_payload());
    m_mutex.unlock();
  }

  websocketpp::connection_hdl& get_hdl(){
    return m_hdl;
  }

  std::string& get_status(){
    return m_status;
  }

  void record_sent_msg(std::string& msg){
    m_mutex.lock();
    m_msgs_sent.push_back(msg);
    m_mutex.unlock();
  }

  size_t get_num_msgs_sent(){
    return m_msgs_sent.size();
  }

  size_t get_num_msgs_recv(){
    return m_msgs_recv.size();
  }

  std::vector<std::string> get_msgs_sent(){
    return m_msgs_sent;
  }

  std::vector<std::string> get_msgs_recv(){
    return m_msgs_recv;
  }

  std::string get_latest_msg_recv(){
    return m_msgs_recv.back();
  }

private:
  websocketpp::connection_hdl m_hdl;
  std::vector<std::string> m_msgs_sent;
  std::vector<std::string> m_msgs_recv;
  std::mutex m_mutex;
  std::string m_status;
  std::string m_uri;
};

class WebsocketClient
{
public:
  WebsocketClient(){
    m_client.clear_access_channels(websocketpp::log::alevel::all);
    m_client.clear_error_channels(websocketpp::log::elevel::all);

    m_client.init_asio();
    m_client.start_perpetual();

    m_thread = std::thread(&Client::run, &m_client);
  }

  ~WebsocketClient(){
    m_client.stop_perpetual();

    if(m_con_meta.get_status() == "Open"){
      std::cout << "Closing connection..." << std::endl;

      websocketpp::lib::error_code ec;
      m_client.close(m_con_meta.get_hdl(), websocketpp::close::status::going_away, "", ec);
      if (ec){
        std::cout << "Error closing connection: " << ec.message() << std::endl;
      }
    }

    m_thread.join();
  }

  bool connect(const std::string &uri){
    websocketpp::lib::error_code ec;
    Client::connection_ptr con_p = m_client.get_connection(uri, ec);

    if (ec){
      std::cout << "Connect initialization error: " << ec.message() << std::endl;
      return false;
    }

    m_con_meta.set_hdl(con_p->get_handle());
    m_con_meta.set_uri(uri);

    con_p->set_open_handler(std::bind(
      &ConnectionMetadata::on_open,
      &m_con_meta,
      &m_client,
      std::placeholders::_1));
    con_p->set_fail_handler(std::bind(
      &ConnectionMetadata::on_fail,
      &m_con_meta,
      &m_client,
      std::placeholders::_1));
    con_p->set_close_handler(std::bind(
      &ConnectionMetadata::on_close,
      &m_con_meta,
      &m_client,
      std::placeholders::_1));
    con_p->set_message_handler(std::bind(
      &ConnectionMetadata::on_message,
      &m_con_meta,
      std::placeholders::_1,
      std::placeholders::_2));

    m_client.connect(con_p);

    return true;
  }

  bool close(){
    websocketpp::close::status::value code;
    std::string reason;
    websocketpp::lib::error_code ec;

    m_client.close(m_con_meta.get_hdl(), code, reason, ec);
    if(ec){
      std::cout << "Error initiating close: " << ec.message() << std::endl;
      return false;
    }

    return true;
  }

  bool send(std::string& msg){
    websocketpp::lib::error_code ec;
    
    m_client.send(m_con_meta.get_hdl(), msg, websocketpp::frame::opcode::binary, ec);
    if(ec){
      std::cout << "Error sending message: " << ec.message() << std::endl;
      return false;
    }

    m_con_meta.record_sent_msg(msg);

    return true;
  }

  size_t get_num_msgs_sent(){
    return m_con_meta.get_num_msgs_sent();
  }

  size_t get_num_msgs_recv(){
    return m_con_meta.get_num_msgs_recv();
  }

  std::vector<std::string> get_msgs_sent(){
    return m_con_meta.get_msgs_sent();
  }

  std::vector<std::string> get_msgs_recv(){
    return m_con_meta.get_msgs_recv();
  }

  std::string get_latest_msg_recv(){
    return m_con_meta.get_latest_msg_recv();
  }

private:
  Client m_client;
  std::thread m_thread;
  ConnectionMetadata m_con_meta;
};
