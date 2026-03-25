#include "pro_808_2019.h"
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
// 7E 81 00 40 19 01 00 00 00 00 06 70 46 57 77 80 00 0F 00 01 00 38 31 30 30 30 30 30 30 30 30 30 36 37 30 34 36 35 37 37 37 38 30 47 7E
int main()
{
    Pro_808_2019 pro;
    std::vector<std::uint8_t> data;
    std::string input;
    std::cout << "请输入数据（以空格分隔）：" << std::endl;
    std::getline(std::cin, input);
    std::stringstream ss(input);
    std::string byte;
    while(ss >> byte)
    {
        data.push_back(static_cast<std::uint8_t>(std::stoi(byte, nullptr, 16)));
    }
    pro.analysis(data);

    return 0;
}