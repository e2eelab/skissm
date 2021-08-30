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
#define ASIO_STANDALONE

#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>
#include <functional>

typedef websocketpp::server<websocketpp::config::asio> server;

class WebsoeketEchoServer
{
public:
  WebsoeketEchoServer(){
    // Set logging settings
    m_server.set_error_channels(websocketpp::log::elevel::none);
    m_server.set_access_channels(websocketpp::log::alevel::none);

    // Initialize Asio
    m_server.init_asio();

    // Set the default message handler to the echo handler
    m_server.set_message_handler(std::bind(&WebsoeketEchoServer::echo_handler, this, std::placeholders::_1, std::placeholders::_2));
  }

  ~WebsoeketEchoServer(){
    m_server.stop_listening();
    m_server.stop();
    m_thread.join();
  }

  void echo_handler(websocketpp::connection_hdl hdl, server::message_ptr msg){
    // write a new message
    m_server.send(hdl, msg->get_payload(), msg->get_opcode());
  }

  void run(int port){
    // Listen on port
    m_server.listen(port);

    // Queues a connection accept operation
    m_server.start_accept();

    // Start the Asio io_service run loop
    m_thread = std::thread(&server::run, &m_server);
  }

private:
  server m_server;
  std::thread m_thread;
};