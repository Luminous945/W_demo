#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "ThreadPool.h"

class TcpServer {
public:
    TcpServer(int port);
    // return 0 表示成功，其他值表示失败
    int init();
    int start();
    void stop();
    void sendMessage(const char *message);
    void sendMessage(std::vector<std::uint8_t> &data,int clientfd);
    int recvMessage(std::string &msg);
    int recvMessage(std::vector<std::uint8_t> &data, int clientfd);
private:
    int m_port{0};
    int m_sockfd{-1};
    int m_clientSockfd{-1};
    ThreadPool *m_threadPool;
};