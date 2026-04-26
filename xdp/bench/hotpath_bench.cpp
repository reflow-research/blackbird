#include <array>
#include <cstdint>
#include <cstring>

#include <benchmark/benchmark.h>

namespace {

constexpr auto kEthAddrBytes = std::size_t {6};

struct Ipv4Header final {
    std::uint8_t version_ihl = 0x45;
    std::uint8_t tos = 0;
    std::uint16_t total_length = 0;
    std::uint16_t id = 0;
    std::uint16_t frag_off = 0;
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

static auto g_ip = Ipv4Header {};
static auto g_udp = UdpHeader {};
alignas(64) static auto g_dst_mac = std::array<std::uint8_t, kEthAddrBytes> {};
alignas(64) static auto g_src_mac = std::array<std::uint8_t, kEthAddrBytes> {};

auto bswap16(const std::uint16_t value) noexcept -> std::uint16_t {
    return __builtin_bswap16(value);
}

auto set_rate_counter(benchmark::State& state) -> void {
    const auto packets = static_cast<double>(state.iterations());
    state.counters["ops_s"] = benchmark::Counter(packets, benchmark::Counter::kIsRate);
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

auto ipv4_checksum_full(const Ipv4Header& ip) noexcept -> std::uint16_t {
    auto words = std::array<std::uint16_t, 10> {};
    std::memcpy(words.data(), &ip, sizeof(ip));
    words[5] = 0;

    auto sum = std::uint32_t {0};
    for (auto i = std::size_t {0}; i < words.size(); ++i) {
        sum += words[i];
    }
    return csum_fold(sum);
}

auto bench_csum_replace_32(benchmark::State& state) -> void {
    auto check = g_ip.checksum;
    auto old_daddr = g_ip.daddr;
    auto new_daddr = std::uint32_t {0xef0a0a0bU};
    for (auto _ : state) {
        check = csum_replace_32(check, old_daddr, new_daddr);
        benchmark::DoNotOptimize(check);
    }
    set_rate_counter(state);
}

auto bench_ipv4_checksum_full(benchmark::State& state) -> void {
    auto ip = g_ip;
    for (auto _ : state) {
        auto checksum = ipv4_checksum_full(ip);
        benchmark::DoNotOptimize(checksum);
    }
    set_rate_counter(state);
}

auto bench_ipv4_incremental_daddr_ttl(benchmark::State& state) -> void {
    auto check = g_ip.checksum;
    auto old_daddr = g_ip.daddr;
    auto new_daddr = std::uint32_t {0xef0a0a0bU};
    auto old_ttl = g_ip.ttl;
    auto new_ttl = std::uint8_t {63};
    auto old_ttl_proto = bswap16((static_cast<std::uint16_t>(old_ttl) << 8U) | g_ip.protocol);
    auto new_ttl_proto = bswap16((static_cast<std::uint16_t>(new_ttl) << 8U) | g_ip.protocol);

    for (auto _ : state) {
        check = csum_replace_32(check, old_daddr, new_daddr);
        check = csum_replace_16(check, old_ttl_proto, new_ttl_proto);
        benchmark::DoNotOptimize(check);
    }
    set_rate_counter(state);
}

auto bench_udp_incremental(benchmark::State& state) -> void {
    auto check = g_udp.checksum;
    auto old_daddr = g_ip.daddr;
    auto new_daddr = std::uint32_t {0xef0a0a0bU};
    auto old_dport = g_udp.dest;
    auto new_dport = std::uint16_t {0x0708};

    for (auto _ : state) {
        check = csum_replace_32(check, old_daddr, new_daddr);
        check = csum_replace_16(check, old_dport, new_dport);
        benchmark::DoNotOptimize(check);
    }
    set_rate_counter(state);
}

auto bench_mac_rewrite(benchmark::State& state) -> void {
    auto dst = std::array<std::uint8_t, kEthAddrBytes> {};
    auto src = std::array<std::uint8_t, kEthAddrBytes> {};
    g_dst_mac = {0x01, 0x00, 0x5e, 0x0a, 0x0a, 0x0a};
    g_src_mac = {0x3c, 0xfd, 0xfe, 0xaa, 0xbb, 0xcc};

    for (auto _ : state) {
        for (auto i = std::size_t {0}; i < kEthAddrBytes; ++i) {
            dst[i] = g_dst_mac[i];
            src[i] = g_src_mac[i];
        }
        benchmark::DoNotOptimize(dst);
        benchmark::DoNotOptimize(src);
        benchmark::ClobberMemory();
    }
    set_rate_counter(state);
}

}  // namespace

BENCHMARK(bench_csum_replace_32);
BENCHMARK(bench_ipv4_checksum_full);
BENCHMARK(bench_ipv4_incremental_daddr_ttl);
BENCHMARK(bench_udp_incremental);
BENCHMARK(bench_mac_rewrite);

BENCHMARK_MAIN();
