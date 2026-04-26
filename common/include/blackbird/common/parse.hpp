#pragma once

#include <charconv>
#include <string_view>

namespace blackbird::common {

template <typename T>
auto parse_integer(std::string_view text, const T min_value, const T max_value, T& out) noexcept
    -> bool {
    auto value = 0LL;
    const auto begin = text.data();
    const auto end = begin + text.size();
    const auto [ptr, ec] = std::from_chars(begin, end, value);
    if (ec != std::errc() || ptr != end) {
        return false;
    }
    if (value < static_cast<long long>(min_value) ||
        value > static_cast<long long>(max_value)) {
        return false;
    }
    out = static_cast<T>(value);
    return true;
}

}  // namespace blackbird::common
