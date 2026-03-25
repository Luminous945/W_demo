cmake_minimum_required(VERSION 3.10)

project(ThreadPool)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(ThreadPool
    main.cpp
    ThreadPool.cpp
)

find_package(Threads REQUIRED)
target_link_libraries(ThreadPool Threads::Threads)