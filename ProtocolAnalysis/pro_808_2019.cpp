#include "pro_808_2019.h"
#include <iostream>
#include <sstream>
#include <bitset>
#include <cmath>

const double PI = 3.14159265358979323846;
const double A = 6378245.0;
const double EE = 0.00669342162296594323;

double transformLat(double x, double y)
{
    double ret = -100.0 + 2.0 * x + 3.0 * y + 0.2 * y * y + 0.1 * x * y + 0.2 * sqrt(fabs(x));

    ret += (20.0 * sin(6.0 * x * PI) +
            20.0 * sin(2.0 * x * PI)) *
           2.0 / 3.0;

    ret += (20.0 * sin(y * PI) +
            40.0 * sin(y / 3.0 * PI)) *
           2.0 / 3.0;

    ret += (160.0 * sin(y / 12.0 * PI) +
            320 * sin(y * PI / 30.0)) *
           2.0 / 3.0;

    return ret;
}

double transformLon(double x, double y)
{
    double ret = 300.0 + x + 2.0 * y + 0.1 * x * x + 0.1 * x * y + 0.1 * sqrt(fabs(x));

    ret += (20.0 * sin(6.0 * x * PI) +
            20.0 * sin(2.0 * x * PI)) *
           2.0 / 3.0;

    ret += (20.0 * sin(x * PI) +
            40.0 * sin(x / 3.0 * PI)) *
           2.0 / 3.0;

    ret += (150.0 * sin(x / 12.0 * PI) +
            300.0 * sin(x / 30.0 * PI)) *
           2.0 / 3.0;

    return ret;
}

bool outOfChina(double lat, double lon)
{
    return (lon < 72.004 || lon > 137.8347 ||
            lat < 0.8293 || lat > 55.8271);
}

void wgs84_to_gcj02(double lat, double lon,
                    double &mgLat, double &mgLon)
{
    if (outOfChina(lat, lon))
    {
        mgLat = lat;
        mgLon = lon;
        return;
    }

    double dLat = transformLat(lon - 105.0, lat - 35.0);
    double dLon = transformLon(lon - 105.0, lat - 35.0);

    double radLat = lat / 180.0 * PI;
    double magic = sin(radLat);
    magic = 1 - EE * magic * magic;

    double sqrtMagic = sqrt(magic);

    dLat = (dLat * 180.0) /
           ((A * (1 - EE)) / (magic * sqrtMagic) * PI);

    dLon = (dLon * 180.0) /
           (A / sqrtMagic * cos(radLat) * PI);

    mgLat = lat + dLat;
    mgLon = lon + dLon;
}

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

uint16_t Pro_808_2019::analysis(std::vector<std::uint8_t> &data, messageHeader &header)
{
    doumy(data);
    // 开始解析数据
    int index = 0;
    // 标识位
    if (data[index++] != 0x7E)
    {
        printf("标识为错误 %02X\n", data[index - 1]);
        return 0;
    }
    printf("标识位:0x%02X\n", data[index - 1]);
    // 消息ID
    uint16_t msgId = (data[index++] << 8) | data[index++];
    header.msgId = msgId;
    printf("消息ID:0x%04X\n", msgId);
    // 消息体属性
    uint16_t msgBodyProps = (data[index++] << 8) | data[index++];
    header.msgBodyProps = msgBodyProps;
    printf("消息体属性:0x%04X\n", msgBodyProps);
    // 解析消息体属性
    uint16_t msgBodyLength = msgBodyProps & 0x3FF;       // 消息体长度
    uint8_t encryption = (msgBodyProps >> 10) & 0x07;    // 数据加密方式
    uint8_t hasSubPackage = (msgBodyProps >> 13) & 0x01; // 是否分包
    uint8_t Version = (msgBodyProps >> 14) & 0x01;       // 版本标识
    uint8_t reserved = (msgBodyProps >> 15) & 0x01;      // 保留位
    // printf("保留位: %d\n", reserved);
    // printf("版本标识: %d\n", Version);
    // printf("是否有子包: %d\n", hasSubPackage);
    // printf("数据加密方式: %d\n", encryption);
    // printf("消息体长度: %d\n", msgBodyLength);
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
    header.msgFlowId = msgFlowId;
    printf("消息流水号:0x%04X\n", msgFlowId);
    // 消息体
    switch (msgId)
    {
    case 0x0100: // 终端注册
        printf("-------------------消息体:终端注册\n");
        x0100(data, index, msgBodyLength);
        break;
    case 0x8100: // 终端注册应答
        printf("-------------------消息体:终端注册应答\n");
        x8100(data, index, msgBodyLength);
        break;
    case 0x0102: // 终端鉴权
        printf("-------------------消息体:终端鉴权\n");
        x0102(data, index);
        break;
    case 0x8001: // 终端鉴权应答
        printf("-------------------消息体:终端鉴权应答\n");
        x8001(data, index);
        break;
    case 0x0701: // 电子运单上报
        printf("-------------------消息体:电子运单上报\n");
        x0701(data, index);
        break;
    case 0x0200: // 位置信息汇报
        printf("-------------------消息体:位置信息汇报\n");
        x0200(data, index, msgBodyLength);
        break;
    case 0x0002: // 终端心跳
        printf("-------------------消息体:终端心跳\n");
        x0002(data, index);
        break;
    case 0x8300: // 文本消息下发
        printf("-------------------消息体:文本消息下发\n");
        x8300(data, index, msgBodyLength);
        break;
    default:
        printf("-------------------消息体:未知消息ID\n");
        break;
    }
    // 校验位
    uint8_t checksum = data[index + msgBodyLength];
    printf("校验位:0x%02X\n", checksum);
    uint8_t calculatedBCC = calculateBCC(data, 1, index + msgBodyLength - 1);
    printf("计算出的BCC:0x%02X\n", calculatedBCC);
    if(checksum==0x7D) index++; // 转义字符
    // 标识位
    uint8_t endFlag = data[index + msgBodyLength + 1];
    // 结束标识
    if (endFlag != 0x7E)
    {
        printf("结束标识错误 %02X\n", endFlag);
        return msgId;
    }
    printf("结束标识:0x%02X\n", endFlag);
    data.erase(data.begin(), data.begin() + index + msgBodyLength + 2);
    return msgId;
}

void Pro_808_2019::x8100(std::vector<std::uint8_t> &data, int index, std::uint16_t msgBodyLength)
{
    // 解析终端注册应答消息体
    uint16_t replyFlowId = (data[index++] << 8) | data[index++];
    printf("回复消息流水号:0x%04X\n", replyFlowId);
    uint8_t result = data[index++];
    printf("结果: %d\n", result);
    if (result == 0) // 成功
    {
        std::vector<std::uint8_t> authCode(msgBodyLength - 3);
        for (int i = 0; i < msgBodyLength - 3; i++)
        {
            authCode[i] = data[index++];
        }
        printf("鉴权码: ");
        doumy(authCode);
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
    // 解析平台通用应答消息体
    // 应答流水号
    uint16_t replyFlowId = (data[index++] << 8) | data[index++];
    printf("回复消息流水号:0x%04X\n", replyFlowId);
    // 应答ID
    uint16_t replyId = (data[index++] << 8) | data[index++];
    printf("应答ID: %d\n", replyId);
    // 结果
    uint8_t result = data[index++];
    printf("结果: %d\n", result);
}

void Pro_808_2019::x0701(std::vector<std::uint8_t> &data, int index)
{
    // 电子运单上报
    //  电子运单长度
    uint16_t waybillLength = (data[index++] << 8) | data[index++];
    printf("电子运单长度: %d\n", waybillLength);
    // 电子运单内容
    std::vector<std::uint8_t> waybillContent(waybillLength);
    for (int i = 0; i < waybillLength; i++)
    {
        waybillContent[i] = data[index++];
    }
    printf("电子运单内容: ");
    doumy(waybillContent);
}

void Pro_808_2019::x0200(std::vector<std::uint8_t> &data, int index, std::uint16_t msgBodyLength)
{
    // 位置信息汇报
    std::vector<std::uint8_t> locationInfo(msgBodyLength);
    for (int i = 0; i < msgBodyLength; i++)
    {
        locationInfo[i] = data[index++];
    }
    printf("位置信息查询消息体: ");
    doumy(locationInfo);
    // 00 00 00 00 00 4C 00 03 01 58 BB 81 06 C9 51 43 00 2C 00 00 00 00 26 03 28 10 16 34 01 04 00 00 00 01 30 01 17 31 01 20 10 01 64 56 02 0A 00 FE 02 00 7B
    uint32_t alarmFlag = (locationInfo[0] << 24) | (locationInfo[1] << 16) | (locationInfo[2] << 8) | locationInfo[3];
    uint32_t statusFlag = (locationInfo[4] << 24) | (locationInfo[5] << 16) | (locationInfo[6] << 8) | locationInfo[7];
    printf("报警标志: 0x%08X\n", alarmFlag);
    printf("状态标志: 0x%08X\n", statusFlag);
    // ACC状态
    bool accOn = (statusFlag & 0x00000001) != 0;
    printf("ACC状态: %s\n", accOn ? "ON" : "OFF");
    // 经纬度正负
    bool longitudePositive = (statusFlag & 0x00000004) == 1; // 纬度正负，0表示北纬，1表示南纬
    bool latitudePositive = (statusFlag & 0x00000008) == 1;  // 经度正负，0表示东经，1表示西经
    printf("经度正负: %s\n", longitudePositive ? "东经" : "西经");
    printf("纬度正负: %s\n", latitudePositive ? "北纬" : "南纬");

    // 纬度
    uint32_t latitude = (locationInfo[8] << 24) | (locationInfo[9] << 16) | (locationInfo[10] << 8) | locationInfo[11];
    // 经度
    uint32_t longitude = (locationInfo[12] << 24) | (locationInfo[13] << 16) | (locationInfo[14] << 8) | locationInfo[15];

    double lat;
    double lon;
    wgs84_to_gcj02(latitude / 1e6, longitude / 1e6, lat, lon);

    if (longitudePositive)
    {
        printf("WGS‑84纬度: -%f\n", latitude / 1e6);
        printf("GCJ‑02纬度: -%f\n", lat);
    }
    else
    {
        printf("WGS‑84纬度: %f\n", latitude / 1e6);
        printf("GCJ‑02纬度: %f\n", lat);
    }
    if (latitudePositive)
    {
        printf("WGS‑84经度: -%f\n", longitude / 1e6);
        printf("GCJ‑02经度: -%f\n", lon);
    }
    else
    {
        printf("WGS‑84经度: %f\n", longitude / 1e6);
        printf("GCJ‑02经度: %f\n", lon);
    }
    // 高度
    uint16_t altitude = (locationInfo[16] << 8) | locationInfo[17];
    printf("高度: %d米\n", altitude);
    // 速度
    uint16_t speed = (locationInfo[18] << 8) | locationInfo[19];
    printf("速度: %d公里/小时\n", speed);
    // 方向
    uint16_t direction = (locationInfo[20] << 8) | locationInfo[21];
    printf("方向: %d度\n", direction);
    // 时间
    std::vector<std::uint8_t> timestamp(6);
    for (int i = 0; i < 6; i++)
    {
        timestamp[i] = locationInfo[22 + i];
    }
    printf("时间:20%02d-%02d-%02d %02d:%02d:%02d\n", timestamp[0], timestamp[1], timestamp[2], timestamp[3], timestamp[4], timestamp[5]);
}

void Pro_808_2019::x0002(std::vector<std::uint8_t> &data, int index)
{
    // 终端心跳数据消息体为空
}
// 8100000000067046577780d7vif

void Pro_808_2019::x8300(std::vector<std::uint8_t> &data, int index, std::uint16_t msgBodyLength)
{
    // 文本消息下发
    //  标志
    uint8_t flag = data[index++];
    // 二进制打印
    printf("标志: %02X\n", flag);
    std::cout << std::bitset<8>(flag) << std::endl;
    // 文本类型
    uint8_t textType = data[index++];
    printf("文本类型: %d\n", textType);
    // 文本信息
    std::vector<std::uint8_t> textInfo(msgBodyLength - 2);
    for (int i = 0; i < textInfo.size(); i++)
    {
        textInfo[i] = data[index++];
    }
    printf("文本信息: ");
    doumy(textInfo);
}

std::vector<std::uint8_t> Pro_808_2019::packageMessage(const messageHeader &header, const std::vector<std::uint8_t> &body)
{
    std::vector<std::uint8_t> message{0x7E, 0x81, 0x00, 0x40, 0x19, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x70, 0x46, 0x57, 0x77, 0x80, 0x00, 0x01};
    // 消息体
    // message.push_back(header.msgFlowId >> 8); // 消息流水号高8位
    // message.push_back(header.msgFlowId & 0xFF); // 消息流水号低8位
    message.push_back(0x00); // 消息流水号高8位
    message.push_back(0x01); // 消息流水号低8位
    message.push_back(0x00);
    message.insert(message.end(), body.begin(), body.end());
    // std::vector<std::uint8_t> message;
    // // 标识位
    // message.push_back(0x7E);
    // // 消息ID
    // message.push_back(header.remsgId >> 8); // 消息ID高8位
    // message.push_back(header.remsgId & 0xFF); // 消息ID低8位
    // // 消息体属性
    // uint16_t msgBodyProps=0x4000;
    // 校验位
    uint8_t checksum = calculateBCC(message, 1, message.size() - 1);
    message.push_back(checksum);
    // 结束标识
    message.push_back(0x7E);
    return message;
}

void Pro_808_2019::package8001(std::vector<std::uint8_t> &message, const messageHeader &header)
{
    // 应答流水号
    message.push_back(header.msgFlowId >> 8);   // 消息流水号高8位
    message.push_back(header.msgFlowId & 0xFF); // 消息流水号低8位
    // 应答ID
    message.push_back(header.msgId >> 8);   // 消息ID高8位
    message.push_back(header.msgId & 0xFF); // 消息ID低8位
    // 结果
    message.push_back(0x00); // 成功
}