#ifndef SERIALIZATION_H
#define SERIALIZATION_H

#include <array>
#include <cstdint>

namespace my
{

using repo_sizeof_t   = std::uint16_t;
using branch_sizeof_t = std::uint16_t;
using json_sizeof_t   = std::uint32_t;

static constexpr inline repo_sizeof_t   REPO_TAG{};
static constexpr inline branch_sizeof_t BRANCH_TAG{};
static constexpr inline json_sizeof_t   JSON_TAG{};

std::array<char, 2> write_bytes(std::uint16_t value);
std::array<char, 4> write_bytes(std::uint32_t value);

std::uint16_t read_bytes(char* buffer, std::uint16_t /*tag*/);
std::uint32_t read_bytes(char* buffer, std::uint32_t /*tag*/);

} // namespace my

#endif // SERIALIZATION_H
