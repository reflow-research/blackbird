#pragma once

#include "blackbird/common/constants.hpp"

namespace blackbird::common {

struct ProcessPerfConfig {
    int cpu_core = -1;
    bool lock_memory = true;
    bool set_realtime = true;
    bool set_high_priority = true;
};

auto tune_process(const ProcessPerfConfig& cfg) noexcept -> void;
auto tune_receiver_socket(int fd, int busy_poll_us = kDefaultBusyPollUs) noexcept -> void;
auto tune_sender_socket(int fd) noexcept -> void;

}  // namespace blackbird::common
