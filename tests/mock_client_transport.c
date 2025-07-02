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

#include "mock_client_transport.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define SERV_PORT   5134
#define PORT        8003
#define BUF_LEN     100

int socket_fd_client;
struct sockaddr_in servaddr;

void send_to_server(uint8_t *cl_msg) {
    size_t cl_msg_len = strlen((const char *)cl_msg);

    if ((socket_fd_client = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(1);
    }
    // struct sockaddr_in our_addr;
    // bzero((char *)&our_addr, sizeof(our_addr));
    // our_addr.sin_family = AF_INET;
    // our_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    // our_addr.sin_port = htons(PORT);

    // set up the server address
    bzero((char *)&servaddr, sizeof(servaddr)); /* 清除位址內容 */
    servaddr.sin_family = AF_INET;    /* 設定協定格式 */
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); /* IP次序轉換 */
    servaddr.sin_port = htons(SERV_PORT);  /* 埠口位元次序轉換 */

    if (connect(socket_fd_client, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect failed!");
        exit(1);
    }

    // send
    send(socket_fd_client, cl_msg, cl_msg_len, 0);

    close(socket_fd_client);
}

void connect_to_server() {
    struct sockaddr_in our_addr;
    if ((socket_fd_client = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(1);
    }
    bzero((char *)&our_addr, sizeof(our_addr));
    our_addr.sin_family = AF_INET;
    our_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    our_addr.sin_port = htons(PORT);

    if (connect(socket_fd_client, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect failed!");
        exit(1);
    }

    // receive
    int recv_len;
    unsigned char recv_buf[BUF_LEN];
    memset(recv_buf, 0, BUF_LEN);
    recv_len = recv(socket_fd_client, recv_buf, BUF_LEN, 0);

    close(socket_fd_client);
}


