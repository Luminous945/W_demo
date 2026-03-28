cmake_minimum_required(VERSION 3.10)

project(TcpServer)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 添加头文件目录
include_directories(../ProtocolAnalysis)
include_directories(../ThreadPool)


add_executable(TcpServer  
    tcpserver.cpp
    main.cpp
    ../ProtocolAnalysis/pro_808_2019.cpp
    ../ThreadPool/ThreadPool.cpp
)

target_link_libraries(TcpServer pthread)