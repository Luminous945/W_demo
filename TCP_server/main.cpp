
#include "tcpserver.h"
#include <iostream>

int main() {
    TcpServer server(9527);
    if (server.init() != 0) {
        std::cerr << "Error initializing server" << std::endl;
        return 1;
    }
    if (!server.start()) {
        std::cerr << "Error starting server" << std::endl;
        return 1;
    }
    std::cout << "Server is running..." << std::endl;
    
    while(true) {
        std::string msg;
        server.recvMessage(msg);
        if (!msg.empty()) {
            std::cout << "Received message: " << msg << std::endl;
            server.sendMessage("Message received");
        }
    }


    server.stop();
    return 0;
}