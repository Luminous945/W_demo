#pragma once
#include <string>


class TcpServer {
public:
    TcpServer(int port);
    // return 0 表示成功，其他值表示失败
    int init();
    bool start();
    void stop();
    void sendMessage(const char *message);
    void recvMessage(std::string &msg);
private:
    int m_port{0};
    int m_sockfd{-1};
    int m_clientSockfd{-1};
};