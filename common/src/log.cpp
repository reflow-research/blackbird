#include "blackbird/common/log.hpp"

#include <array>
#include <cstdio>
#include <cstring>

#include "blackbird/common/constants.hpp"

#if defined(BLACKBIRD_ENABLE_SPDLOG) && BLACKBIRD_ENABLE_SPDLOG
#include <spdlog/spdlog.h>
#endif

namespace blackbird::common {

auto log_v(const char* level, const char* fmt, va_list args) noexcept -> void {
#if defined(BLACKBIRD_ENABLE_SPDLOG) && BLACKBIRD_ENABLE_SPDLOG
    auto buffer = std::array<char, kLogLineBytes> {};
    const auto n = int {std::vsnprintf(buffer.data(), buffer.size(), fmt, args)};
    if (n < 0) {
        return;
    }
    if (std::strcmp(level, "ERROR") == 0) {
        spdlog::error("{}", buffer.data());
    } else if (std::strcmp(level, "WARN") == 0) {
        spdlog::warn("{}", buffer.data());
    } else {
        spdlog::info("{}", buffer.data());
    }
#else
    auto buffer = std::array<char, kLogLineBytes> {};
    const auto n = int {std::vsnprintf(buffer.data(), buffer.size(), fmt, args)};
    if (n < 0) {
        return;
    }

    std::fputs("[", stderr);
    std::fputs(level, stderr);
    std::fputs("] ", stderr);
    std::fputs(buffer.data(), stderr);
    std::fputc('\n', stderr);
#endif
}

auto log_info(const char* fmt, ...) noexcept -> void {
    va_list args;
    va_start(args, fmt);
    log_v("INFO", fmt, args);
    va_end(args);
}

auto log_warn(const char* fmt, ...) noexcept -> void {
    va_list args;
    va_start(args, fmt);
    log_v("WARN", fmt, args);
    va_end(args);
}

auto log_error(const char* fmt, ...) noexcept -> void {
    va_list args;
    va_start(args, fmt);
    log_v("ERROR", fmt, args);
    va_end(args);
}

}  // namespace blackbird::common
