
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

class Timer
{
public:
    Timer(int interval, int clientfd) : interval_(interval), running_(false), clientfd_(clientfd) {}
    Timer(int interval)
        : interval_(interval), running_(false) {}

    void start()
    {
        running_ = true;
        thread_ = std::thread([this]()
                              {
            while (running_)
            {
                std::this_thread::sleep_for(std::chrono::seconds(interval_));
                if (!running_) break;

                task();
            } });
    }

    void stop()
    {
        running_ = false;
        if (thread_.joinable())
            thread_.join();
    }

private:
    void task()
    {
        std::cout << "定时器触发: "
                  << std::chrono::system_clock::to_time_t(
                         std::chrono::system_clock::now())
                  << std::endl;
        std::vector<std::uint8_t> responseData = {0x7E, 0x83, 0x00, 0x40, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x70, 0x46, 0x57, 0x77, 0x80, 0x49, 0x99, 0x01, 0x02, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x23, 0xAE, 0x7E};
        server.sendMessage(responseData, clientfd_);
        std::cout << "-------------文本消息下发---------------" << std::endl;
    }

private:
    int interval_;              // 定时周期（秒）
    std::atomic<bool> running_; // 是否运行
    std::thread thread_;

public:
    int clientfd_;
};

void processing_data(std::vector<std::uint8_t> &data)
{
    if (data[0] != 0x7E)
    {
        printf("数据包错误，缺少起始标识\n");
        return;
    }
    int n = data.size();
    for (int i = 1; i < n; i++)
    {
        if (data[i] == 0x7D)
        {
            if (i + 1 < n && data[i + 1] == 0x01)
            {
                data.erase(data.begin() + i + 1);
                n--;
            }
        }
    }
}

void msgfunc(int clientfd, std::shared_ptr<Timer> timer)
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
        processing_data(data);
        while (!data.empty())
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
            // 7E 83 00 40 09 01 00 00 00 00 06 70 46 57 77 80 49 99 01 02 73 65 72 76 65 72 23 AE 7E
            // std::vector<std::uint8_t> responseData = {0x7E, 0x83, 0x00, 0x40, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x70, 0x46, 0x57, 0x77, 0x80, 0x49, 0x99, 0x01, 0x02, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x23, 0xAE, 0x7E};
            // server.sendMessage(responseData, clientfd);
            printf("未找到相关消息ID:0x%04X\n", msgId);
            break;
        }
        }
    }
    timer->stop();
    std::cout << "客户端断开连接，fd: " << clientfd << std::endl;
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
        auto timer = std::make_shared<Timer>(5, clientfd);
        timer->start();
        auto func = std::bind(msgfunc, clientfd, timer);
        threadPool.addTask(func);
    }

    running.store(false);

    server.stop();
    return 0;
}

// 7E0002400001000000000670465777800014C77E