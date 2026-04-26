#include "blackbird/client/receiver.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <unistd.h>

#include <array>
#include <chrono>

#include "blackbird/common/log.hpp"
#include "blackbird/common/parse.hpp"
#include "blackbird/common/perf.hpp"

namespace blackbird::client {

namespace {

auto print_usage(const char* prog) noexcept -> void {
    common::log_error(
        "Usage: %s [group_ip] [port] [iface_ip] [batch] [print_payload] [cpu_core]",
        prog
    );
}

}  // namespace

Receiver::Receiver(const ReceiverConfig& cfg) noexcept : cfg_(cfg) {
    last_stats_ = std::chrono::steady_clock::now();
}

Receiver::~Receiver() noexcept {
    if (fd_ >= 0) {
        if (::setsockopt(fd_, IPPROTO_IP, IP_DROP_MEMBERSHIP, &membership_, sizeof(membership_)) <
            0) {
            common::log_warn("setsockopt(IP_DROP_MEMBERSHIP) failed: %s", std::strerror(errno));
        }
        (void)::close(fd_);
        fd_ = -1;
    }
}

auto Receiver::Init() noexcept -> bool {
    if (cfg_.batch == 0 || cfg_.batch > common::kMaxBatch) {
        common::log_error(
            "invalid batch=%u max=%zu",
            static_cast<unsigned>(cfg_.batch),
            common::kMaxBatch
        );
        return false;
    }

    if (cfg_.aggressive_tuning) {
        auto perf_cfg = common::ProcessPerfConfig {};
        perf_cfg.cpu_core = cfg_.cpu_core;
        perf_cfg.lock_memory = true;
        perf_cfg.set_realtime = true;
        perf_cfg.set_high_priority = true;
        common::tune_process(perf_cfg);
    }

    fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_ < 0) {
        common::log_error("socket() failed: %s", std::strerror(errno));
        return false;
    }

    const auto reuse = int {1};
    if (::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        common::log_error("setsockopt(SO_REUSEADDR) failed: %s", std::strerror(errno));
        return false;
    }

#ifdef SO_REUSEPORT
    const auto reuse_port = int {1};
    if (::setsockopt(fd_, SOL_SOCKET, SO_REUSEPORT, &reuse_port, sizeof(reuse_port)) < 0) {
        common::log_warn("setsockopt(SO_REUSEPORT) failed: %s", std::strerror(errno));
    }
#endif

    const auto rcvbuf = int {common::kDefaultRecvBufBytes};
    if (::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
        common::log_warn("setsockopt(SO_RCVBUF) failed: %s", std::strerror(errno));
    }

    if (cfg_.aggressive_tuning) {
        common::tune_receiver_socket(fd_, common::kDefaultBusyPollUs);
    }

    auto rcv_timeout = timeval {};
    rcv_timeout.tv_sec = 0;
    rcv_timeout.tv_usec = 100'000;
    if (::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &rcv_timeout, sizeof(rcv_timeout)) < 0) {
        common::log_error("setsockopt(SO_RCVTIMEO) failed: %s", std::strerror(errno));
        return false;
    }

    auto local = sockaddr_in {};
    local.sin_family = AF_INET;
    local.sin_port = htons(cfg_.port);
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    if (::bind(fd_, reinterpret_cast<sockaddr*>(&local), sizeof(local)) < 0) {
        common::log_error("bind() failed: %s", std::strerror(errno));
        return false;
    }

    membership_ = ip_mreq {};
    if (::inet_pton(AF_INET, cfg_.group_ip, &membership_.imr_multiaddr) != 1) {
        common::log_error("invalid multicast group: %s", cfg_.group_ip);
        return false;
    }
    if (::inet_pton(AF_INET, cfg_.iface_ip, &membership_.imr_interface) != 1) {
        common::log_error("invalid interface IP: %s", cfg_.iface_ip);
        return false;
    }
    if (::setsockopt(fd_, IPPROTO_IP, IP_ADD_MEMBERSHIP, &membership_, sizeof(membership_)) < 0) {
        common::log_error("setsockopt(IP_ADD_MEMBERSHIP) failed: %s", std::strerror(errno));
        return false;
    }

    const auto batch = std::size_t {cfg_.batch};
    for (auto i = std::size_t {0}; i < batch; ++i) {
        msgs_[i] = mmsghdr {};
        src_addrs_[i] = sockaddr_in {};
        iovecs_[i].iov_base = buffers_[i].data();
        iovecs_[i].iov_len = common::kPayloadBytes;
        msgs_[i].msg_hdr.msg_name = &src_addrs_[i];
        msgs_[i].msg_hdr.msg_namelen = sizeof(sockaddr_in);
        msgs_[i].msg_hdr.msg_iov = &iovecs_[i];
        msgs_[i].msg_hdr.msg_iovlen = 1;
    }

    common::log_info(
        "receiver: group=%s port=%u iface=%s batch=%u payload_bytes=%zu cpu=%d",
        cfg_.group_ip,
        static_cast<unsigned>(cfg_.port),
        cfg_.iface_ip,
        static_cast<unsigned>(cfg_.batch),
        common::kPayloadBytes,
        cfg_.cpu_core
    );

    return true;
}

auto Receiver::LogStats() noexcept -> void {
    const auto now = std::chrono::steady_clock::now();
    if (now - last_stats_ < std::chrono::seconds(1)) {
        return;
    }

    const auto elapsed_s = double {std::chrono::duration<double>(now - last_stats_).count()};
    const auto packets_delta = std::uint64_t {received_packets_ - prev_packets_};
    const auto bytes_delta = std::uint64_t {received_bytes_ - prev_bytes_};
    const auto pps = double {static_cast<double>(packets_delta) / elapsed_s};
    const auto mib_per_s = double {static_cast<double>(bytes_delta) / (1024.0 * 1024.0) / elapsed_s};

    common::log_info(
        "receiver stats: pps=%.0f throughput_mib_s=%.2f received=%llu recv_errors=%llu truncated=%llu",
        pps,
        mib_per_s,
        static_cast<unsigned long long>(received_packets_),
        static_cast<unsigned long long>(recv_errors_),
        static_cast<unsigned long long>(truncated_)
    );

    last_stats_ = now;
    prev_packets_ = received_packets_;
    prev_bytes_ = received_bytes_;
}

auto Receiver::Run(const volatile sig_atomic_t* stop_flag) noexcept -> void {
    const auto batch = std::size_t {cfg_.batch};
    const auto recv_batch = static_cast<unsigned int>(cfg_.batch);

    while (*stop_flag == 0) {
        for (auto i = std::size_t {0}; i < batch; ++i) {
            msgs_[i].msg_hdr.msg_namelen = sizeof(sockaddr_in);
            msgs_[i].msg_len = 0;
        }

        const auto n = int {::recvmmsg(fd_, msgs_.data(), recv_batch, 0, nullptr)};
        if (n < 0) {
            if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                ++recv_errors_;
            }
            continue;
        }

        const auto received_now = std::size_t {static_cast<std::size_t>(n)};
        received_packets_ += static_cast<std::uint64_t>(received_now);

        if (!cfg_.print_payload) {
            for (auto i = std::size_t {0}; i < received_now; ++i) {
                received_bytes_ += msgs_[i].msg_len;
                if (msgs_[i].msg_len >= common::kPayloadBytes) {
                    ++truncated_;
                }
            }
            LogStats();
            continue;
        }

        for (auto i = std::size_t {0}; i < received_now; ++i) {
            received_bytes_ += msgs_[i].msg_len;
            if (msgs_[i].msg_len >= common::kPayloadBytes) {
                ++truncated_;
            }

            auto src_ip = std::array<char, INET_ADDRSTRLEN> {};
            if (::inet_ntop(
                    AF_INET,
                    &src_addrs_[i].sin_addr,
                    src_ip.data(),
                    static_cast<socklen_t>(src_ip.size())
                ) == nullptr) {
                std::strncpy(src_ip.data(), "unknown", src_ip.size() - 1U);
            }

            common::log_info(
                "from=%s:%u bytes=%u payload=%.*s",
                src_ip.data(),
                static_cast<unsigned>(ntohs(src_addrs_[i].sin_port)),
                static_cast<unsigned>(msgs_[i].msg_len),
                static_cast<int>(msgs_[i].msg_len),
                buffers_[i].data()
            );
        }

        LogStats();
    }
}

auto parse_receiver_args(const int argc, char** argv, ReceiverConfig& out_cfg) noexcept -> bool {
    if (argc > 1) {
        out_cfg.group_ip = argv[1];
    }
    if (argc > 2 &&
        !common::parse_integer<std::uint16_t>(
            argv[2],
            std::uint16_t {1},
            std::uint16_t {65535},
            out_cfg.port
        )) {
        print_usage(argv[0]);
        return false;
    }
    if (argc > 3) {
        out_cfg.iface_ip = argv[3];
    }
    if (argc > 4 &&
        !common::parse_integer<std::uint32_t>(
            argv[4],
            std::uint32_t {1},
            static_cast<std::uint32_t>(common::kMaxBatch),
            out_cfg.batch
        )) {
        print_usage(argv[0]);
        return false;
    }
    if (argc > 5) {
        auto print_payload_int = int {0};
        if (!common::parse_integer<int>(argv[5], int {0}, int {1}, print_payload_int)) {
            print_usage(argv[0]);
            return false;
        }
        out_cfg.print_payload = print_payload_int != 0;
    }
    if (argc > 6 &&
        !common::parse_integer<int>(argv[6], int {-1}, int {4095}, out_cfg.cpu_core)) {
        print_usage(argv[0]);
        return false;
    }

    return true;
}

}  // namespace blackbird::client
