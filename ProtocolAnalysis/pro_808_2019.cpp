#include "pro_808_2019.h"
#include <iostream>
#include <sstream>

Pro_808_2019::Pro_808_2019()
{
}

Pro_808_2019::~Pro_808_2019()
{
}

void doumy(std::vector<std::uint8_t> &data)
{
    for (auto &item : data)
    {
        printf("%02X ", item);
    }
    printf("\n");
}

// BBC校验
uint8_t calculateBCC(const std::vector<std::uint8_t> &data, int start, int length)
{
    uint8_t bcc = 0;
    for (int i = start; i < start + length; ++i)
    {
        bcc ^= data[i];
    }
    return bcc;
}

void Pro_808_2019::analysis(std::vector<std::uint8_t> &data)
{
    // doumy(data);
    // 开始解析数据
    int index = 0;
    // 标识位
    if (data[index++] != 0x7E)
    {
        printf("标识为错误 %02X\n", data[index - 1]);
        return;
    }
    printf("标识位:0x%02X\n", data[index - 1]);
    // 消息ID
    uint16_t msgId = (data[index++] << 8) | data[index++];
    printf("消息ID:0x%04X\n", msgId);
    // 消息体属性
    uint16_t msgBodyProps = (data[index++] << 8) | data[index++];
    printf("消息体属性:0x%04X\n", msgBodyProps);
    // 解析消息体属性
    uint16_t msgBodyLength = msgBodyProps & 0x3FF;       // 消息体长度
    uint8_t encryption = (msgBodyProps >> 10) & 0x07;    // 数据加密方式
    uint8_t hasSubPackage = (msgBodyProps >> 13) & 0x01; // 是否分包
    uint8_t Version = (msgBodyProps >> 14) & 0x01;       // 版本标识
    uint8_t reserved = (msgBodyProps >> 15) & 0x01;      // 保留位
    printf("保留位: %d\n", reserved);
    printf("版本标识: %d\n", Version);
    printf("是否有子包: %d\n", hasSubPackage);
    printf("数据加密方式: %d\n", encryption);
    printf("消息体长度: %d\n", msgBodyLength);
    // 协议版本号
    uint8_t protocolVersion = data[index++];
    printf("协议版本号:0x%02X\n", protocolVersion);
    // 终端手机号
    std::stringstream ss;
    for (int i = 0; i < 10; i++)
    {
        ss << std::hex << std::uppercase << (int)data[index++];
    }
    std::string iemi = ss.str();
    printf("终端手机号: %s\n", iemi.c_str());
    // 消息流水号
    uint16_t msgFlowId = (data[index++] << 8) | data[index++];
    printf("消息流水号:0x%04X\n", msgFlowId);
    // 消息体
    switch (msgId)
    {
    case 0x0100: // 终端注册
        printf("消息体:终端注册\n");
        x0100(data, index, msgBodyLength);
        break;
    case 0x8100: // 终端注册应答
        printf("消息体:终端注册应答\n");
        x8100(data, index);
        break;
    case 0x0102: // 终端鉴权
        printf("消息体:终端鉴权\n");
        x0102(data, index);
        break;
    case 0x8001: // 终端鉴权应答
        printf("消息体:终端鉴权应答\n");
        x8001(data, index);
        break;
    case 0x0701: // 位置信息汇报
        printf("消息体:位置信息汇报\n");
        x0701(data, index);
        break;
    case 0x0200: // 位置信息查询
        printf("消息体:位置信息查询\n");
        x0200(data, index);
        break;
    case 0x0002: // 位置信息查询应答
        printf("消息体:位置信息查询应答\n");
        x0002(data, index);
        break;
    default:
        printf("消息体:未知消息ID\n");
        break;
    }
    // 校验位
    uint8_t checksum = data[index + msgBodyLength];
    printf("校验位:0x%02X\n", checksum);
    uint8_t calculatedBCC = calculateBCC(data, 1, index + msgBodyLength - 1);
    printf("计算出的BCC:0x%02X\n", calculatedBCC);
    // 结束标识
    if (data[index + msgBodyLength + 1] != 0x7E)
    {
        printf("结束标识错误 %02X\n", data[index + msgBodyLength + 1]);
        return;
    }
    printf("结束标识:0x%02X\n", data[index + msgBodyLength + 1]);
}

void Pro_808_2019::x8100(std::vector<std::uint8_t> &data, int index)
{
    // 解析终端注册应答消息体
    uint16_t replyFlowId = (data[index++] << 8) | data[index++];
    printf("回复消息流水号:0x%04X\n", replyFlowId);
    uint8_t result = data[index++];
    printf("结果: %d\n", result);
    if (result == 0) // 成功
    {
        char authCode[22] = {0};
        for (int i = 0; i < 22; i++)
        {
            authCode[i] = data[index++];
        }
        printf("鉴权码: %s\n", authCode);
    }
}

// 7E 01 00 40 54 01 00 00 00 00 06 70 46 57 77 80 00 0F 00 2C 01 2C 58 59 52 00 00 00 00 00 00 00 00 56 4D 30 32 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 38 36 35 31 36 37 30 34 36 35 37 37 37 38 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 D4 C1 42 38 38 38 38 38  9D 7E
void Pro_808_2019::x0100(std::vector<std::uint8_t> &data, int index, std::uint16_t msgBodyLength)
{
    // 解析终端注册消息体
    uint16_t provinceId = (data[index++] << 8) | data[index++];
    uint16_t cityId = (data[index++] << 8) | data[index++];
    printf("省域ID: %d\n", provinceId);
    printf("市域ID: %d\n", cityId);
    // 制造商ID
    std::vector<std::uint8_t> manufacturerId(11);
    for (int i = 0; i < 11; i++)
    {
        manufacturerId[i] = data[index++];
    }
    printf("制造商ID: ");
    doumy(manufacturerId);
    // 终端型号
    std::vector<std::uint8_t> terminalModel(30);
    for (int i = 0; i < 30; i++)
    {
        terminalModel[i] = data[index++];
    }
    printf("终端型号: ");
    doumy(terminalModel);
    // 终端ID
    std::vector<std::uint8_t> terminalId(30);
    for (int i = 0; i < 30; i++)
    {
        terminalId[i] = data[index++];
    }
    printf("终端ID: ");
    doumy(terminalId);
    // 车牌颜色
    uint8_t plateColor = data[index++];
    printf("车牌颜色: %d\n", plateColor);
    // 车牌号码
    std::vector<std::uint8_t> plateNumber((msgBodyLength - 2 - 2 - 11 - 30 - 30 - 1));
    for (int i = 0; i < plateNumber.size(); i++)
    {
        plateNumber[i] = data[index++];
    }
    printf("车牌号码: ");
    doumy(plateNumber);
}

void Pro_808_2019::x0102(std::vector<std::uint8_t> &data, int index)
{
    // 解析终端鉴权消息体
    // 鉴权码长度
    int n = data[index++];
    printf("鉴权码长度: %d\n", n);
    // 鉴权码内容
    std::vector<std::uint8_t> authCode(n);
    for (int i = 0; i < n; i++)
    {
        authCode[i] = data[index++];
    }
    printf("鉴权码: ");
    doumy(authCode);
    // 终端IMIE
    std::vector<std::uint8_t> iemi(15);
    for (int i = 0; i < 15; i++)
    {
        iemi[i] = data[index++];
    }
    printf("终端IMEI: ");
    doumy(iemi);
    // 软件版本号
    std::vector<std::uint8_t> softwareVersion(20);
    for (int i = 0; i < 20; i++)
    {
        softwareVersion[i] = data[index++];
    }
    printf("软件版本号: ");
    doumy(softwareVersion);
}

void Pro_808_2019::x8001(std::vector<std::uint8_t> &data, int index)
{
    // 解析终端鉴权应答消息体
    uint16_t replyFlowId = (data[index++] << 8) | data[index++];
    printf("回复消息流水号:0x%04X\n", replyFlowId);
    uint8_t result = data[index++];
    printf("结果: %d\n", result);
}

void Pro_808_2019::x0701(std::vector<std::uint8_t> &data, int index)
{
    // 解析位置信息汇报消息体
    uint32_t alarmFlag = (data[index++] << 24) | (data[index++] << 16) | (data[index++] << 8) | data[index++];
    uint32_t statusFlag = (data[index++] << 24) | (data[index++] << 16) | (data[index++] << 8) | data[index++];
    uint32_t latitude = (data[index++] << 24) | (data[index++] << 16) | (data[index++] << 8) | data[index++];
    uint32_t longitude = (data[index++] << 24) | (data[index++] << 16) | (data[index++] << 8) | data[index++];
    uint16_t elevation = (data[index++] << 8) | data[index++];
    uint16_t speed = (data[index++] << 8) | data[index++];
    uint16_t direction = (data[index++] << 8) | data[index++];
    char timestamp[7] = {0};
    for (int i = 0; i < 6; i++)
    {
        timestamp[i] = data[index++];
    }
    printf("报警标志:0x%08X\n", alarmFlag);
    printf("状态标志:0x%08X\n", statusFlag);
    printf("纬度: %f\n", latitude / 1000000.0);
    printf("经度: %f\n", longitude / 1000000.0);
    printf("海拔: %d米\n", elevation);
    printf("速度: %d公里/小时\n", speed);
    printf("方向: %d度\n", direction);
    printf("时间戳:20%02d-%02d-%02d %02d:%02d:%02d\n",
           timestamp[0], timestamp[1], timestamp[2],
           timestamp[3], timestamp[4], timestamp[5]);
}

void Pro_808_2019::x0200(std::vector<std::uint8_t> &data, int index)
{
    // 解析位置信息查询消息体
    char queryType = data[index++];
    printf("查询类型: %d\n", queryType);
}

void Pro_808_2019::x0002(std::vector<std::uint8_t> &data, int index)
{
    // 解析位置信息查询应答消息体
    uint32_t latitude = (data[index++] << 24) | (data[index++] << 16) | (data[index++] << 8) | data[index++];
    uint32_t longitude = (data[index++] << 24) | (data[index++] << 16) | (data[index++] << 8) | data[index++];
    uint16_t elevation = (data[index++] << 8) | data[index++];
    uint16_t speed = (data[index++] << 8) | data[index++];
    uint16_t direction = (data[index++] << 8) | data[index++];
    char timestamp[7] = {0};
    for (int i = 0; i < 6; i++)
    {
        timestamp[i] = data[index++];
    }
    printf("纬度: %f\n", latitude / 1000000.0);
    printf("经度: %f\n", longitude / 1000000.0);
    printf("海拔: %d米\n", elevation);
    printf("速度: %d公里/小时\n", speed);
    printf("方向: %d度\n", direction);
    printf("时间戳:20%02d-%02d-%02d %02d:%02d:%02d\n",
           timestamp[0], timestamp[1], timestamp[2],
           timestamp[3], timestamp[4], timestamp[5]);
}
// 8100000000067046577780d7vif