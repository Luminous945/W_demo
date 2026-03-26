
#include "tcpserver.h"
#include "pro_808_2019.h"
#include <iostream>
#include <sstream>
#include <vector>

int main()
{
    TcpServer server(9527);
    if (server.init() != 0)
    {
        std::cerr << "Error initializing server" << std::endl;
        return 1;
    }
    if (!server.start())
    {
        std::cerr << "Error starting server" << std::endl;
        return 1;
    }
    std::cout << "Server is running..." << std::endl;

    Pro_808_2019 pro;
    while (true)
    {
        std::string msg;
        server.recvMessage(msg);
        if (!msg.empty())
        {
            std::stringstream ss(msg);
            std::string byte;
            std::vector<std::uint8_t> data;
            while (ss >> byte)
            {
                data.push_back(static_cast<std::uint8_t>(std::stoi(byte, nullptr, 16)));
            }
            pro.analysis(data);
            server.sendMessage("Message received");
        }
    }

    server.stop();
    return 0;
}