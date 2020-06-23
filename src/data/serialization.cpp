#include "data/serialization.h"

namespace my
{

std::array<char, 2> write_bytes(std::uint16_t value)
{
    union
    {
        char buf[2];
        std::uint16_t val;
    };
    val = value;
    return { buf[0], buf[1] };
}

std::array<char, 4> write_bytes(std::uint32_t value)
{
    union
    {
        char buf[4];
        std::uint32_t val;
    };
    val = value;
    return { buf[0], buf[1], buf[2], buf[3] };
}

std::uint16_t read_bytes(char* buffer, std::uint16_t /*tag*/)
{
    union
    {
        char buf[2];
        std::uint16_t val;
    };
    buf[0] = buffer[0];
    buf[1] = buffer[1];
    return val;
}

std::uint32_t read_bytes(char* buffer, std::uint32_t /*tag*/)
{
    union
    {
        char buf[4];
        std::uint32_t val;
    };
    buf[0] = buffer[0];
    buf[1] = buffer[1];
    buf[2] = buffer[2];
    buf[3] = buffer[3];
    return val;
}

} // namespace my
