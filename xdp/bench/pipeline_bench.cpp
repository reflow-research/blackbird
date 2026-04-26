#include <array>
#include <cstdint>

#include <benchmark/benchmark.h>

namespace {

constexpr auto kEthHeaderBytes = std::uint64_t {14};
constexpr auto kIpv4HeaderBytes = std::uint64_t {20};
constexpr auto kUdpHeaderBytes = std::uint64_t {8};
constexpr auto kEthAddrBytes = std::size_t {6};
constexpr auto kMaxFanout = std::size_t {16};

struct EthernetHeader final {
    std::array<std::uint8_t, kEthAddrBytes> dst = {};
    std::array<std::uint8_t, kEthAddrBytes> src = {};
    std::uint16_t ethertype = 0x0008;
};

struct Ipv4Header final {
    std::uint8_t version_ihl = 0x45;
    std::uint8_t tos = 0;
    std::uint16_t total_length = 0x0000;
    std::uint16_t id = 0x0000;
    std::uint16_t frag_off = 0x0000;
    std::uint8_t ttl = 64;
    std::uint8_t protocol = 17;
    std::uint16_t checksum = 0x1234;
    std::uint32_t saddr = 0x0a000001U;
    std::uint32_t daddr = 0xef0a0a0aU;
};

struct UdpHeader final {
    std::uint16_t source = 0xd307;
    std::uint16_t dest = 0xd307;
    std::uint16_t len = 0x7805;
    std::uint16_t checksum = 0xa55a;
};

struct PacketHeaders final {
    EthernetHeader eth = {};
    Ipv4Header ip = {};
    UdpHeader udp = {};
};

struct RewriteConfig final {
    std::uint32_t rewrite_dst_ip = 0xef0a0a0bU;
    std::uint16_t rewrite_dst_port = 0x0708;
    std::uint8_t rewrite_ttl = 1;
    std::array<std::uint8_t, kEthAddrBytes> rewrite_dst_mac = {
        0x01, 0x00, 0x5e, 0x0a, 0x0a, 0x0a
    };
    std::array<std::uint8_t, kEthAddrBytes> rewrite_src_mac = {
        0x3c, 0xfd, 0xfe, 0xaa, 0xbb, 0xcc
    };
};

struct RedirectStats final {
    std::uint64_t matched_packets = 0;
    std::uint64_t matched_bytes = 0;
    std::uint64_t redirect_packets = 0;
};

alignas(64) static auto g_base_packet = PacketHeaders {};
alignas(64) static auto g_cfg = RewriteConfig {};
alignas(64) static auto g_packets = std::array<PacketHeaders, kMaxFanout> {};
alignas(64) static auto g_stats = RedirectStats {};

auto bswap16(const std::uint16_t value) noexcept -> std::uint16_t {
    return __builtin_bswap16(value);
}

auto csum_fold(std::uint32_t sum) noexcept -> std::uint16_t {
    sum = (sum & 0xffffU) + (sum >> 16U);
    sum = (sum & 0xffffU) + (sum >> 16U);
    return static_cast<std::uint16_t>(~sum);
}

auto csum_replace_32(
    const std::uint16_t check,
    const std::uint32_t old_value,
    const std::uint32_t new_value
) noexcept -> std::uint16_t {
    auto sum = std::uint32_t {(~check) & 0xffffU};
    sum += (~old_value) & 0xffffU;
    sum += ((~old_value) >> 16U) & 0xffffU;
    sum += new_value & 0xffffU;
    sum += (new_value >> 16U) & 0xffffU;
    return csum_fold(sum);
}

auto csum_replace_16(
    const std::uint16_t check,
    const std::uint16_t old_value,
    const std::uint16_t new_value
) noexcept -> std::uint16_t {
    auto sum = std::uint32_t {(~check) & 0xffffU};
    sum += (~old_value) & 0xffffU;
    sum += new_value & 0xffffU;
    return csum_fold(sum);
}

auto set_rate_counters(
    benchmark::State& state,
    const std::uint64_t packets,
    const std::uint64_t frame_bytes
) -> void {
    const auto bits = static_cast<double>(packets * frame_bytes * 8U);
    state.counters["pps"] =
        benchmark::Counter(static_cast<double>(packets), benchmark::Counter::kIsRate);
    state.counters["gbps"] =
        benchmark::Counter(bits, benchmark::Counter::kIsRate, benchmark::Counter::kIs1000);
}

auto redirect_packet(PacketHeaders& packet, const RewriteConfig& cfg) noexcept -> void {
    const auto old_daddr = packet.ip.daddr;
    const auto old_dport = packet.udp.dest;

    packet.ip.daddr = cfg.rewrite_dst_ip;
    packet.udp.dest = cfg.rewrite_dst_port;
    packet.ip.checksum = csum_replace_32(packet.ip.checksum, old_daddr, packet.ip.daddr);

    if (cfg.rewrite_ttl != 0 && cfg.rewrite_ttl != packet.ip.ttl) {
        const auto old_ttl_proto = bswap16(
            static_cast<std::uint16_t>((static_cast<std::uint16_t>(packet.ip.ttl) << 8U) |
                                       packet.ip.protocol)
        );
        packet.ip.ttl = cfg.rewrite_ttl;
        const auto new_ttl_proto = bswap16(
            static_cast<std::uint16_t>((static_cast<std::uint16_t>(packet.ip.ttl) << 8U) |
                                       packet.ip.protocol)
        );
        packet.ip.checksum = csum_replace_16(packet.ip.checksum, old_ttl_proto, new_ttl_proto);
    }

    if (packet.udp.checksum != 0) {
        auto udp_csum = std::uint16_t {packet.udp.checksum};
        udp_csum = csum_replace_32(udp_csum, old_daddr, packet.ip.daddr);
        udp_csum = csum_replace_16(udp_csum, old_dport, packet.udp.dest);
        packet.udp.checksum = udp_csum == 0 ? std::uint16_t {0xffff} : udp_csum;
    }

    for (auto i = std::size_t {0}; i < kEthAddrBytes; ++i) {
        packet.eth.dst[i] = cfg.rewrite_dst_mac[i];
        packet.eth.src[i] = cfg.rewrite_src_mac[i];
    }
}

auto bench_redirect_pipeline_no_stats(benchmark::State& state) -> void {
    const auto payload_bytes = std::uint64_t {static_cast<std::uint64_t>(state.range(0))};
    const auto frame_bytes =
        std::uint64_t {kEthHeaderBytes + kIpv4HeaderBytes + kUdpHeaderBytes + payload_bytes};
    auto packet = g_base_packet;

    for (auto _ : state) {
        redirect_packet(packet, g_cfg);
        benchmark::DoNotOptimize(packet);
        benchmark::ClobberMemory();
    }

    const auto packets = std::uint64_t {static_cast<std::uint64_t>(state.iterations())};
    state.SetItemsProcessed(static_cast<int64_t>(packets));
    state.SetBytesProcessed(static_cast<int64_t>(packets * frame_bytes));
    set_rate_counters(state, packets, frame_bytes);
}

auto bench_redirect_pipeline_with_stats(benchmark::State& state) -> void {
    const auto payload_bytes = std::uint64_t {static_cast<std::uint64_t>(state.range(0))};
    const auto frame_bytes =
        std::uint64_t {kEthHeaderBytes + kIpv4HeaderBytes + kUdpHeaderBytes + payload_bytes};
    auto packet = g_base_packet;
    g_stats = RedirectStats {};

    for (auto _ : state) {
        redirect_packet(packet, g_cfg);
        g_stats.matched_packets += 1;
        g_stats.matched_bytes += frame_bytes;
        g_stats.redirect_packets += 1;
        benchmark::DoNotOptimize(packet);
        benchmark::DoNotOptimize(g_stats);
        benchmark::ClobberMemory();
    }

    const auto packets = std::uint64_t {static_cast<std::uint64_t>(state.iterations())};
    state.SetItemsProcessed(static_cast<int64_t>(packets));
    state.SetBytesProcessed(static_cast<int64_t>(packets * frame_bytes));
    set_rate_counters(state, packets, frame_bytes);
}

auto bench_userspace_unicast_fanout(benchmark::State& state) -> void {
    const auto fanout = std::uint64_t {static_cast<std::uint64_t>(state.range(0))};
    const auto payload_bytes = std::uint64_t {1400};
    const auto frame_bytes =
        std::uint64_t {kEthHeaderBytes + kIpv4HeaderBytes + kUdpHeaderBytes + payload_bytes};
    auto sink = std::uint32_t {0};

    for (auto _ : state) {
        for (auto i = std::size_t {0}; i < fanout; ++i) {
            g_packets[i] = g_base_packet;
            auto per_target_cfg = g_cfg;
            per_target_cfg.rewrite_dst_ip += static_cast<std::uint32_t>(i);
            per_target_cfg.rewrite_dst_port += static_cast<std::uint16_t>(i);
            redirect_packet(g_packets[i], per_target_cfg);
            sink ^= g_packets[i].ip.checksum;
            sink ^= g_packets[i].udp.checksum;
        }
        benchmark::DoNotOptimize(sink);
        benchmark::ClobberMemory();
    }

    const auto packets = std::uint64_t {
        static_cast<std::uint64_t>(state.iterations()) * static_cast<std::uint64_t>(fanout)
    };
    state.SetItemsProcessed(static_cast<int64_t>(packets));
    state.SetBytesProcessed(static_cast<int64_t>(packets * frame_bytes));
    set_rate_counters(state, packets, frame_bytes);
}

}  // namespace

BENCHMARK(bench_redirect_pipeline_no_stats)->Arg(64)->Arg(256)->Arg(512)->Arg(1400);
BENCHMARK(bench_redirect_pipeline_with_stats)->Arg(64)->Arg(256)->Arg(512)->Arg(1400);
BENCHMARK(bench_userspace_unicast_fanout)->Arg(1)->Arg(2)->Arg(4)->Arg(8)->Arg(10)->Arg(16);

BENCHMARK_MAIN();
