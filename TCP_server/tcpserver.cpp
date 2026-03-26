#include "tcpserver.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>


TcpServer::TcpServer(int port) : m_port(port), m_sockfd(-1)
{

}

int TcpServer::init()
{
    m_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (m_sockfd < 0) {
        return -1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(m_port);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(m_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        return -2;
    }

    if (listen(m_sockfd, 5) < 0) {
        return -3;
    }
    return 0;
}

bool TcpServer::start()
{
    //优化：可以在这里创建一个线程来处理客户端连接，这样主线程就不会被阻塞，可以继续接受新的连接
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    m_clientSockfd = accept(m_sockfd, (struct sockaddr *)&client_addr, &client_len);
    if (m_clientSockfd < 0) {
        return false;
    }
    return true;
}

void TcpServer::stop()
{
    if (m_clientSockfd >= 0) {
        close(m_clientSockfd);
        m_clientSockfd = -1;
    }
    if (m_sockfd >= 0) {
        close(m_sockfd);
        m_sockfd = -1;
    }
}

void TcpServer::sendMessage(const char *message)
{
    if (m_clientSockfd >= 0) {
        send(m_clientSockfd, message, strlen(message), 0);
    }
}

void TcpServer::recvMessage(std::string &msg)
{
    char buffer[1024];

    ssize_t n = recv(m_clientSockfd, buffer, sizeof(buffer), 0);

    if (n <= 0) {
        msg = "";
        return;
    }
    msg.assign(buffer, n);
}