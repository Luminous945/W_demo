#include "pro_808_2019.h"
#include <iostream>
#include <sstream>

Pro_808_2019::Pro_808_2019()
{
}

Pro_808_2019::~Pro_808_2019()
{
}

void doumy(std::vector<std::uint8_t>& data)
{
    printf("数据内容：\n");
    for(auto &item : data)
    {
        printf("%02X ", item);
    }
    printf("\n");
}

//BBC校验
uint8_t calculateBCC(const std::vector<std::uint8_t>& data, int start, int length)
{
    uint8_t bcc = 0;
    for(int i = start; i < start + length; ++i)
    {
        bcc ^= data[i];
    }
    return bcc;
}

void Pro_808_2019::analysis(std::vector<std::uint8_t>& data)
{
    //doumy(data);
    //开始解析数据
    int index = 0;
    //标识位
    if(data[index++] != 0x7E){
        printf("标识为错误 %02X\n", data[index-1]);
        return;
    }
    printf("标识位:0x%02X\n", data[index-1]);
    //消息ID
    uint16_t msgId = (data[index++] << 8) | data[index++];
    printf("消息ID:0x%04X\n", msgId);
    //消息体属性
    uint16_t msgBodyProps = (data[index++] << 8) | data[index++];
    printf("消息体属性:0x%04X\n", msgBodyProps);
    //解析消息体属性
    uint16_t msgBodyLength = msgBodyProps & 0x3FF; //消息体长度
    uint8_t encryption = (msgBodyProps >> 10) & 0x07; //数据加密方式
    uint8_t hasSubPackage = (msgBodyProps >> 13) & 0x01; //是否分包
    uint8_t Version = (msgBodyProps >> 14) & 0x01; //版本标识
    uint8_t reserved = (msgBodyProps >> 15) & 0x01; //保留位
    printf("保留位: %d\n", reserved);
    printf("版本标识: %d\n", Version);
    printf("是否有子包: %d\n", hasSubPackage);
    printf("数据加密方式: %d\n", encryption);
    printf("消息体长度: %d\n", msgBodyLength);
    //协议版本号
    uint8_t protocolVersion = data[index++];
    printf("协议版本号:0x%02X\n", protocolVersion);
    //终端手机号
    std::stringstream ss;
    for(int i=0;i<10;i++){
        ss << std::hex << std::uppercase <<(int)data[index++];
    }
    std::string iemi = ss.str();
    printf("终端手机号: %s\n", iemi.c_str());
    //消息流水号
    uint16_t msgFlowId = (data[index++] << 8) | data[index++];
    printf("消息流水号:0x%04X\n", msgFlowId);
    //消息体
    switch(msgId)
    {
        case 0x0100: //终端注册
            printf("消息体:终端注册\n");
            x0100(data, index);
            break;
        case 0x8100: //终端注册应答
            printf("消息体:终端注册应答\n");
            x8100(data, index);
            break;
        case 0x0102: //终端鉴权
            printf("消息体:终端鉴权\n");
            x0102(data, index);
            break;
        case 0x8001: //终端鉴权应答
            printf("消息体:终端鉴权应答\n");
            x8001(data, index);
            break;
        case 0x0701: //位置信息汇报
            printf("消息体:位置信息汇报\n");
            x0701(data, index);
            break;
        case 0x0200: //位置信息查询
            printf("消息体:位置信息查询\n");
            x0200(data, index);
            break;
        case 0x0002: //位置信息查询应答
            printf("消息体:位置信息查询应答\n");
            x0002(data, index);
            break;
        default:
            printf("消息体:未知消息ID\n");
            break;
    }
    //校验位
    uint8_t checksum = data[index+msgBodyLength];
    printf("校验位:0x%02X\n", checksum);
    uint8_t calculatedBCC = calculateBCC(data, 1, index+msgBodyLength-1);
    printf("计算出的BCC:0x%02X\n", calculatedBCC);
    //结束标识
    if(data[index+msgBodyLength+1] != 0x7E){
        printf("结束标识错误 %02X\n", data[index+msgBodyLength+1]);
        return;
    }
    printf("结束标识:0x%02X\n", data[index+msgBodyLength+1]);
}

void Pro_808_2019::x8100(std::vector<std::uint8_t>& data, int index)
{
    //解析终端注册应答消息体
    uint16_t replyFlowId = (data[index++] << 8) | data[index++];
    printf("回复消息流水号:0x%04X\n", replyFlowId);
    uint8_t result = data[index++];
    printf("结果: %d\n", result);
    if(result == 0) //成功
    {
        char authCode[22] = {0};
        for(int i=0;i<22;i++){
            authCode[i] = data[index++];
        }
        printf("鉴权码: %s\n", authCode);
    }
}

//8100000000067046577780d7vif 