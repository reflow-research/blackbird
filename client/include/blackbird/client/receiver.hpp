#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <csignal>

#include <netinet/in.h>
#include <sys/socket.h>

#include "blackbird/common/constants.hpp"

namespace blackbird::client {

struct ReceiverConfig {
    const char* group_ip = "239.10.10.10";
    std::uint16_t port = 2003;
    const char* iface_ip = "0.0.0.0";
    std::uint32_t batch = 32;
    bool print_payload = false;
    int cpu_core = -1;
    bool aggressive_tuning = true;
};

class Receiver final {
  public:
    explicit Receiver(const ReceiverConfig& cfg) noexcept;
    ~Receiver() noexcept;

    Receiver(const Receiver&) = delete;
    Receiver& operator=(const Receiver&) = delete;
    Receiver(Receiver&&) = delete;
    Receiver& operator=(Receiver&&) = delete;

    auto Init() noexcept -> bool;
    auto Run(const volatile sig_atomic_t* stop_flag) noexcept -> void;

  private:
    auto LogStats() noexcept -> void;

    const ReceiverConfig cfg_{};
    int fd_ = -1;
    ip_mreq membership_{};
    bool membership_joined_ = false;

    alignas(common::kPageSize)
        std::array<std::array<char, common::kAlignedPayloadBytes>, common::kMaxBatch>
            buffers_{};
    std::array<iovec, common::kMaxBatch> iovecs_{};
    std::array<mmsghdr, common::kMaxBatch> msgs_{};
    std::array<sockaddr_in, common::kMaxBatch> src_addrs_{};

    std::uint64_t received_packets_ = 0;
    std::uint64_t received_bytes_ = 0;
    std::uint64_t recv_errors_ = 0;
    std::uint64_t truncated_ = 0;
    std::uint64_t prev_packets_ = 0;
    std::uint64_t prev_bytes_ = 0;
    std::chrono::steady_clock::time_point last_stats_ {};
};

auto parse_receiver_args(const int argc, char** argv, ReceiverConfig& out_cfg) noexcept -> bool;

}  // namespace blackbird::client
