
#include "tcpserver.h"
#include "pro_808_2019.h"
#include "ThreadPool.h"
#include <iostream>
#include <sstream>
#include <vector>
#include <functional>
#include <atomic>

std::atomic<bool> running(true);
TcpServer server(9527);

void msgfunc(int clientfd)
{

    Pro_808_2019 pro;
    while (running.load())
    {
        std::vector<std::uint8_t> data;
        int ret = server.recvMessage(data, clientfd);
        if (ret <= 0)
        {
            std::cerr << "客户端断开连接" << std::endl;
            break;
        }
        std::uint16_t msgId = 0;
        messageHeader header;
        if (!data.empty())
        {

            msgId = pro.analysis(data, header);
            // server.sendMessage("Message received");
        }
        switch (msgId)
        {
        case 0x0100: // 终端注册
        {
            std::cout << "终端注册应答" << std::endl;
            std::vector<std::uint8_t> responseData = {0x38, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30,
                                                      0x30, 0x30, 0x30, 0x30, 0x36, 0x37, 0x30, 0x34, 0x36, 0x35, 0x37, 0x37, 0x37, 0x38, 0x30};
            std::vector<std::uint8_t> packagedMessage = pro.packageMessage(header, responseData);
            server.sendMessage(packagedMessage, clientfd);
            pro.analysis(packagedMessage, header);
            break;
        }
        case 0x0102: // 终端鉴权
        {
            std::cout << "终端鉴权应答" << std::endl;
            std::vector<std::uint8_t> responseData = {0x7E, 0x80, 0x01, 0x40, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x70, 0x46, 0x57, 0x77, 0x80, 0x00, 0x10, 0x00, 0x10, 0x01, 0x02, 0x00, 0x56, 0x7E};
            server.sendMessage(responseData, clientfd);
            pro.analysis(responseData, header);
            break;
        }
        case 0x0002: // 终端心跳
        {
            std::cout << "-----------------------------终端心跳应答" << std::endl;
            server.sendMessage(data, clientfd);
            break;
        }
        default:
        {
            printf("未找到相关消息ID:0x%04X\n", msgId);
            break;
        }
        }
    }
}

int main()
{
    
    if (server.init() != 0)
    {
        std::cerr << "Error initializing server" << std::endl;
        return 1;
    }
    ThreadPool threadPool(4); // 创建一个包含4个线程的线程池
    while (true)
    {
        int clientfd = server.start();
        if (clientfd <= 0)
        {
            std::cerr << "Error accepting client connection" << std::endl;
            continue;
        }
        std::cout << "客户端连接成功，fd: " << clientfd << std::endl;
        auto func = std::bind(msgfunc, clientfd);
        threadPool.addTask(func);
    }
    running.store(false);

    server.stop();
    return 0;
}