#include <vector>
#include <cstdint>


struct messageHeader
{
    uint16_t msgId;        // 消息ID
    uint16_t msgBodyProps; // 消息体属性
    uint16_t msgFlowId;    // 消息流水号
    uint16_t remsgId;      //回复消息ID
};

class Pro_808_2019
{
public:
    Pro_808_2019();
    ~Pro_808_2019();

    uint16_t analysis(std::vector<std::uint8_t> &data,messageHeader &header);

    // 协议封装
    std::vector<std::uint8_t> packageMessage(const messageHeader &header, const std::vector<std::uint8_t> &body);
    void package8001(std::vector<std::uint8_t> &message, const messageHeader &header);

private:
    void x8100(std::vector<std::uint8_t> &data, int index,std::uint16_t msgBodyLength);
    void x0100(std::vector<std::uint8_t> &data, int index,std::uint16_t msgBodyLength);
    void x0102(std::vector<std::uint8_t> &data, int index);
    void x8001(std::vector<std::uint8_t> &data, int index);
    void x0701(std::vector<std::uint8_t> &data, int index);
    void x0200(std::vector<std::uint8_t> &data, int index,std::uint16_t msgBodyLength);
    void x0002(std::vector<std::uint8_t> &data, int index);
    void x8300(std::vector<std::uint8_t> &data, int index,std::uint16_t msgBodyLength);
};