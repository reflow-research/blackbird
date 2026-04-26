#pragma once

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

namespace blackbird::common {

inline auto format_payload(
    std::string_view message,
    std::uint64_t seq,
    char* output,
    std::size_t capacity
) noexcept -> std::size_t {
    constexpr std::string_view seq_prefix = " seq=";
    constexpr auto seq_digits_max = std::size_t {20};

    const auto seq_reserved = std::size_t {seq_prefix.size() + seq_digits_max};
    const auto max_message =
        capacity > seq_reserved ? std::size_t {capacity - seq_reserved} : std::size_t {0};
    const auto message_bytes = std::size_t {std::min(message.size(), max_message)};

    std::memcpy(output, message.data(), message_bytes);
    auto offset = std::size_t {message_bytes};

    std::memcpy(output + offset, seq_prefix.data(), seq_prefix.size());
    offset += seq_prefix.size();

    const auto [ptr, ec] = std::to_chars(output + offset, output + capacity, seq);
    if (ec != std::errc()) {
        return offset;
    }
    return static_cast<std::size_t>(ptr - output);
}

}  // namespace blackbird::common
