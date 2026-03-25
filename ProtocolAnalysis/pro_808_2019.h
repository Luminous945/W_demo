#include <vector>
#include <cstdint>

class Pro_808_2019
{
public:
    Pro_808_2019();
    ~Pro_808_2019();

    void analysis(std::vector<std::uint8_t> &data);

private:
    void x8100(std::vector<std::uint8_t> &data, int index);
    void x0100(std::vector<std::uint8_t> &data, int index);
    void x0102(std::vector<std::uint8_t> &data, int index);
    void x8001(std::vector<std::uint8_t> &data, int index);
    void x0701(std::vector<std::uint8_t> &data, int index);
    void x0200(std::vector<std::uint8_t> &data, int index);
    void x0002(std::vector<std::uint8_t> &data, int index);
};