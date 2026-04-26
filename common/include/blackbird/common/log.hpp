#pragma once

#include <cstdarg>

namespace blackbird::common {

auto log_info(const char* fmt, ...) noexcept -> void;
auto log_warn(const char* fmt, ...) noexcept -> void;
auto log_error(const char* fmt, ...) noexcept -> void;
auto log_v(const char* level, const char* fmt, va_list args) noexcept -> void;

}  // namespace blackbird::common
