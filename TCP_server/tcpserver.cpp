#include "tcpserver.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>

TcpServer::TcpServer(int port) : m_port(port), m_sockfd(-1)
{
    // 创建一个包含4个线程的线程池
    m_threadPool = new ThreadPool(4);
}

int TcpServer::init()
{
    m_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (m_sockfd < 0)
    {
        return -1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(m_port);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(m_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        return -2;
    }

    if (listen(m_sockfd, 5) < 0)
    {
        return -3;
    }
    return 0;
}

int TcpServer::start()
{
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int clientfd = accept(m_sockfd, (struct sockaddr *)&client_addr, &client_len);
    if (clientfd < 0)
    {
        return 0;
    }
    return clientfd;
}

void TcpServer::stop()
{
    if (m_clientSockfd >= 0)
    {
        close(m_clientSockfd);
        m_clientSockfd = -1;
    }
    if (m_sockfd >= 0)
    {
        close(m_sockfd);
        m_sockfd = -1;
    }
}

void TcpServer::sendMessage(const char *message)
{
    if (m_clientSockfd >= 0)
    {
        send(m_clientSockfd, message, strlen(message), 0);
    }
}

void TcpServer::sendMessage(std::vector<std::uint8_t> &data, int clientfd)
{
    if (clientfd >= 0)
    {
        send(clientfd, data.data(), data.size(), 0);
    }
}

int TcpServer::recvMessage(std::string &msg)
{
    char buffer[1024];

    ssize_t n = recv(m_clientSockfd, buffer, sizeof(buffer), 0);

    if (n <= 0)
    {
        msg = "";
        return n;
    }
    msg.assign(buffer, n);
    return n;
}

int TcpServer::recvMessage(std::vector<std::uint8_t> &data, int clientfd)
{
    char buffer[1024];

    if (clientfd <= 0)
    {
        return -1;
    }
    ssize_t n = recv(clientfd, buffer, sizeof(buffer), 0);

    if (n <= 0)
    {
        return n;
    }
    // data.assign(buffer, buffer + n);
    data.insert(data.end(), buffer, buffer + n);
    return n;
}