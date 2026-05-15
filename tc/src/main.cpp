#include <arpa/inet.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "blackbird/common/log.hpp"
#include "blackbird/common/parse.hpp"
#include "blackbird/xdp/forward_config.h"

namespace blackbird::tc {

namespace {

static_assert(sizeof(blackbird_xdp_forward_config) == 40U);
static_assert(sizeof(blackbird_xdp_stats) == 40U);

constexpr auto kCfgMapName = "cfg_map";
constexpr auto kTxPortsMapName = "tx_ports";
constexpr auto kStatsMapName = "stats_map";
constexpr auto kMapKeyZero = std::uint32_t {0};
constexpr auto kMaxStatsCpus = std::size_t {1024};
constexpr auto kArphrdPpp = int {512};
constexpr auto kArphrdRawIp = int {519};
constexpr auto kArphrdTunnel = int {768};
constexpr auto kArphrdTunnel6 = int {769};
constexpr auto kArphrdSit = int {776};
constexpr auto kArphrdIpGre = int {778};
constexpr auto kArphrdPimReg = int {779};
constexpr auto kArphrdIp6Gre = int {823};
constexpr auto kArphrdVoid = int {0xFFFF};
constexpr auto kArphrdNone = int {0xFFFE};

alignas(64) static auto g_percpu_stats = std::array<blackbird_xdp_stats, kMaxStatsCpus> {};

#ifdef BLACKBIRD_DEFAULT_TC_OBJ_PATH
constexpr auto kDefaultTcObjPath = BLACKBIRD_DEFAULT_TC_OBJ_PATH;
#else
constexpr auto kDefaultTcObjPath = "./blackbird_tc_kern.o";
#endif

auto ptr_to_u64(const void* ptr) noexcept -> __u64 {
    return static_cast<__u64>(reinterpret_cast<std::uintptr_t>(ptr));
}

auto sys_bpf(const bpf_cmd cmd, bpf_attr& attr) noexcept -> int {
    return static_cast<int>(::syscall(__NR_bpf, cmd, &attr, sizeof(attr)));
}

auto bpf_prog_get_fd_by_id(const std::uint32_t prog_id) noexcept -> int {
    auto attr = bpf_attr {};
    attr.prog_id = prog_id;
    return sys_bpf(BPF_PROG_GET_FD_BY_ID, attr);
}

auto bpf_map_get_fd_by_id(const std::uint32_t map_id) noexcept -> int {
    auto attr = bpf_attr {};
    attr.map_id = map_id;
    return sys_bpf(BPF_MAP_GET_FD_BY_ID, attr);
}

auto bpf_obj_get_info(const int fd, void* info, std::uint32_t& info_len) noexcept -> bool {
    auto attr = bpf_attr {};
    attr.info.bpf_fd = static_cast<__u32>(fd);
    attr.info.info = ptr_to_u64(info);
    attr.info.info_len = info_len;
    if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, attr) < 0) {
        return false;
    }
    info_len = attr.info.info_len;
    return true;
}

template <typename Key, typename Value>
auto bpf_map_update(const int map_fd, const Key& key, const Value& value) noexcept -> bool {
    auto attr = bpf_attr {};
    attr.map_fd = static_cast<__u32>(map_fd);
    attr.key = ptr_to_u64(&key);
    attr.value = ptr_to_u64(&value);
    attr.flags = BPF_ANY;
    return sys_bpf(BPF_MAP_UPDATE_ELEM, attr) == 0;
}

template <typename Key, typename Value>
auto bpf_map_lookup(const int map_fd, const Key& key, Value& value) noexcept -> bool {
    auto attr = bpf_attr {};
    attr.map_fd = static_cast<__u32>(map_fd);
    attr.key = ptr_to_u64(&key);
    attr.value = ptr_to_u64(&value);
    return sys_bpf(BPF_MAP_LOOKUP_ELEM, attr) == 0;
}

auto run_shell_command(const char* command) noexcept -> bool {
    const auto rc = int {std::system(command)};
    if (rc == -1) {
        common::log_error("system(\"%s\") failed: %s", command, std::strerror(errno));
        return false;
    }
    if (WIFEXITED(rc) == 0 || WEXITSTATUS(rc) != 0) {
        common::log_error("command failed (%d): %s", rc, command);
        return false;
    }
    return true;
}

auto run_shell_command_allow_failure(const char* command) noexcept -> bool {
    const auto rc = int {std::system(command)};
    if (rc == -1) {
        common::log_warn("system(\"%s\") failed: %s", command, std::strerror(errno));
        return false;
    }
    if (WIFEXITED(rc) == 0 || WEXITSTATUS(rc) != 0) {
        return false;
    }
    return true;
}

auto parse_ipv4_be(const char* text, std::uint32_t& out_be) noexcept -> bool {
    auto addr = in_addr {};
    if (::inet_pton(AF_INET, text, &addr) != 1) {
        return false;
    }
    out_be = addr.s_addr;
    return true;
}

auto parse_ipv4_be_or_any(const char* text, std::uint32_t& out_be) noexcept -> bool {
    if (std::strcmp(text, "any") == 0 || std::strcmp(text, "0") == 0 ||
        std::strcmp(text, "0.0.0.0") == 0) {
        out_be = 0;
        return true;
    }
    return parse_ipv4_be(text, out_be);
}

auto format_mac(const std::array<std::uint8_t, 6>& mac, std::array<char, 18>& out) noexcept
    -> void {
    (void)std::snprintf(
        out.data(),
        out.size(),
        "%02x:%02x:%02x:%02x:%02x:%02x",
        static_cast<unsigned>(mac[0]),
        static_cast<unsigned>(mac[1]),
        static_cast<unsigned>(mac[2]),
        static_cast<unsigned>(mac[3]),
        static_cast<unsigned>(mac[4]),
        static_cast<unsigned>(mac[5])
    );
}

auto read_iface_mac(const char* iface, std::array<std::uint8_t, 6>& out) noexcept -> bool {
    auto path = std::array<char, 256> {};
    if (std::snprintf(path.data(), path.size(), "/sys/class/net/%s/address", iface) <= 0) {
        return false;
    }

    auto* file = std::fopen(path.data(), "r");
    if (file == nullptr) {
        common::log_error("fopen(%s) failed: %s", path.data(), std::strerror(errno));
        return false;
    }

    auto line = std::array<char, 64> {};
    const auto ok = std::fgets(line.data(), static_cast<int>(line.size()), file) != nullptr;
    (void)std::fclose(file);
    if (!ok) {
        return false;
    }

    auto b0 = std::uint32_t {0};
    auto b1 = std::uint32_t {0};
    auto b2 = std::uint32_t {0};
    auto b3 = std::uint32_t {0};
    auto b4 = std::uint32_t {0};
    auto b5 = std::uint32_t {0};
    if (std::sscanf(line.data(), "%2x:%2x:%2x:%2x:%2x:%2x", &b0, &b1, &b2, &b3, &b4, &b5) != 6) {
        return false;
    }

    out[0] = static_cast<std::uint8_t>(b0);
    out[1] = static_cast<std::uint8_t>(b1);
    out[2] = static_cast<std::uint8_t>(b2);
    out[3] = static_cast<std::uint8_t>(b3);
    out[4] = static_cast<std::uint8_t>(b4);
    out[5] = static_cast<std::uint8_t>(b5);
    return true;
}

auto read_iface_type(const char* iface, int& out) noexcept -> bool {
    auto path = std::array<char, 256> {};
    if (std::snprintf(path.data(), path.size(), "/sys/class/net/%s/type", iface) <= 0) {
        return false;
    }

    auto* file = std::fopen(path.data(), "r");
    if (file == nullptr) {
        common::log_error("fopen(%s) failed: %s", path.data(), std::strerror(errno));
        return false;
    }

    const auto ok = std::fscanf(file, "%d", &out) == 1;
    (void)std::fclose(file);
    return ok;
}

auto iface_is_l3_egress_type(const int iface_type) noexcept -> bool {
    switch (iface_type) {
        case kArphrdTunnel:
        case kArphrdTunnel6:
        case kArphrdSit:
        case kArphrdIpGre:
        case kArphrdIp6Gre:
        case kArphrdVoid:
        case kArphrdNone:
        case kArphrdRawIp:
        case kArphrdPimReg:
        case kArphrdPpp:
            return true;
        default:
            return false;
    }
}

auto compute_multicast_mac(const std::uint32_t ip_be, std::array<std::uint8_t, 6>& out) noexcept
    -> void {
    const auto ip_host = std::uint32_t {ntohl(ip_be)};
    out[0] = std::uint8_t {0x01};
    out[1] = std::uint8_t {0x00};
    out[2] = std::uint8_t {0x5e};
    out[3] = static_cast<std::uint8_t>((ip_host >> 16U) & 0x7fU);
    out[4] = static_cast<std::uint8_t>((ip_host >> 8U) & 0xffU);
    out[5] = static_cast<std::uint8_t>(ip_host & 0xffU);
}

auto parse_u16(const char* text, std::uint16_t& out) noexcept -> bool {
    return common::parse_integer<std::uint16_t>(
        text,
        std::uint16_t {0},
        std::uint16_t {65535},
        out
    );
}

auto parse_bool_01(const char* text, bool& out) noexcept -> bool {
    auto as_int = int {0};
    if (!common::parse_integer<int>(text, int {0}, int {1}, as_int)) {
        return false;
    }
    out = as_int != 0;
    return true;
}

auto read_possible_cpu_count(std::size_t& out_count) noexcept -> bool {
    static auto cached_count = std::size_t {0};
    static auto cached_ok = false;
    if (cached_ok) {
        out_count = cached_count;
        return true;
    }

    auto* file = std::fopen("/sys/devices/system/cpu/possible", "r");
    if (file == nullptr) {
        common::log_error("fopen(cpu possible) failed: %s", std::strerror(errno));
        return false;
    }

    auto text = std::array<char, 256> {};
    const auto ok = std::fgets(text.data(), static_cast<int>(text.size()), file) != nullptr;
    (void)std::fclose(file);
    if (!ok) {
        return false;
    }

    auto max_cpu = int {-1};
    auto* cursor = text.data();
    while (*cursor != '\0') {
        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n' || *cursor == ',') {
            ++cursor;
        }
        if (*cursor == '\0') {
            break;
        }

        auto start = int {0};
        auto end = int {0};
        auto consumed = int {0};
        if (std::sscanf(cursor, "%d-%d%n", &start, &end, &consumed) == 2) {
            if (end > max_cpu) {
                max_cpu = end;
            }
            cursor += consumed;
            continue;
        }
        if (std::sscanf(cursor, "%d%n", &start, &consumed) == 1) {
            if (start > max_cpu) {
                max_cpu = start;
            }
            cursor += consumed;
            continue;
        }
        ++cursor;
    }

    if (max_cpu < 0) {
        return false;
    }

    cached_count = static_cast<std::size_t>(max_cpu + 1);
    cached_ok = true;
    out_count = cached_count;
    return true;
}

auto parse_prog_id_from_tc_line(const char* line, std::uint32_t& out_prog_id) noexcept -> bool {
    const auto* marker = std::strstr(line, " id ");
    if (marker == nullptr) {
        return false;
    }
    marker += 4;
    auto parsed = std::uint32_t {0};
    if (std::sscanf(marker, "%u", &parsed) != 1) {
        return false;
    }
    out_prog_id = parsed;
    return true;
}

auto get_tc_prog_id_for_iface(const char* iface, std::uint32_t& out_prog_id) noexcept -> bool {
    auto cmd = std::array<char, 256> {};
    (void)std::snprintf(cmd.data(), cmd.size(), "tc filter show dev %s ingress 2>/dev/null", iface);

    auto* pipe = ::popen(cmd.data(), "r");
    if (pipe == nullptr) {
        common::log_error("popen failed: %s", std::strerror(errno));
        return false;
    }

    auto line = std::array<char, 512> {};
    auto found = false;
    while (std::fgets(line.data(), static_cast<int>(line.size()), pipe) != nullptr) {
        auto parsed_id = std::uint32_t {0};
        if (parse_prog_id_from_tc_line(line.data(), parsed_id)) {
            out_prog_id = parsed_id;
            found = true;
            break;
        }
    }
    (void)::pclose(pipe);

    if (!found) {
        common::log_error("no TC BPF program found on interface %s ingress", iface);
    }
    return found;
}

struct MapFds final {
    int cfg = -1;
    int tx_ports = -1;
    int stats = -1;

    MapFds() = default;
    ~MapFds() noexcept {
        reset();
    }

    MapFds(const MapFds&) = delete;
    auto operator=(const MapFds&) -> MapFds& = delete;
    MapFds(MapFds&&) = delete;
    auto operator=(MapFds&&) -> MapFds& = delete;

    auto reset() noexcept -> void {
        if (cfg >= 0) {
            (void)::close(cfg);
            cfg = -1;
        }
        if (tx_ports >= 0) {
            (void)::close(tx_ports);
            tx_ports = -1;
        }
        if (stats >= 0) {
            (void)::close(stats);
            stats = -1;
        }
    }
};

auto get_named_map_fds_for_prog(const std::uint32_t prog_id, MapFds& out_fds) noexcept -> bool {
    out_fds.reset();

    const auto prog_fd = int {bpf_prog_get_fd_by_id(prog_id)};
    if (prog_fd < 0) {
        common::log_error("BPF_PROG_GET_FD_BY_ID(%u) failed: %s", prog_id, std::strerror(errno));
        return false;
    }

    auto prog_info = bpf_prog_info {};
    auto map_ids = std::array<std::uint32_t, 64> {};
    prog_info.nr_map_ids = static_cast<__u32>(map_ids.size());
    prog_info.map_ids = ptr_to_u64(map_ids.data());
    auto info_len = std::uint32_t {sizeof(prog_info)};

    if (!bpf_obj_get_info(prog_fd, &prog_info, info_len)) {
        common::log_error("BPF_OBJ_GET_INFO_BY_FD(prog) failed: %s", std::strerror(errno));
        (void)::close(prog_fd);
        return false;
    }
    (void)::close(prog_fd);

    for (auto i = std::uint32_t {0}; i < prog_info.nr_map_ids && i < map_ids.size(); ++i) {
        const auto map_id = std::uint32_t {map_ids[i]};
        if (map_id == 0) {
            continue;
        }

        const auto map_fd = int {bpf_map_get_fd_by_id(map_id)};
        if (map_fd < 0) {
            continue;
        }

        auto map_info = bpf_map_info {};
        auto map_info_len = std::uint32_t {sizeof(map_info)};
        if (!bpf_obj_get_info(map_fd, &map_info, map_info_len)) {
            (void)::close(map_fd);
            continue;
        }

        const auto* map_name = reinterpret_cast<const char*>(map_info.name);
        if (std::strncmp(map_name, kCfgMapName, BPF_OBJ_NAME_LEN) == 0) {
            out_fds.cfg = map_fd;
            continue;
        }
        if (std::strncmp(map_name, kTxPortsMapName, BPF_OBJ_NAME_LEN) == 0) {
            out_fds.tx_ports = map_fd;
            continue;
        }
        if (std::strncmp(map_name, kStatsMapName, BPF_OBJ_NAME_LEN) == 0) {
            out_fds.stats = map_fd;
            continue;
        }

        (void)::close(map_fd);
    }

    if (out_fds.cfg < 0 || out_fds.tx_ports < 0 || out_fds.stats < 0) {
        out_fds.reset();
        common::log_error("required TC maps not found (cfg_map / tx_ports / stats_map)");
        return false;
    }

    return true;
}

auto get_map_fds_for_iface(const char* iface, MapFds& out_fds) noexcept -> bool {
    auto prog_id = std::uint32_t {0};
    if (!get_tc_prog_id_for_iface(iface, prog_id)) {
        return false;
    }
    return get_named_map_fds_for_prog(prog_id, out_fds);
}

auto attach_tc(const char* iface, const char* obj_path) noexcept -> bool {
    auto qdisc_command = std::array<char, 512> {};
    (void)std::snprintf(
        qdisc_command.data(),
        qdisc_command.size(),
        "tc qdisc replace dev %s clsact",
        iface
    );
    if (!run_shell_command(qdisc_command.data())) {
        return false;
    }

    auto filter_command = std::array<char, 1024> {};
    (void)std::snprintf(
        filter_command.data(),
        filter_command.size(),
        "tc filter replace dev %s ingress bpf da obj %s sec tc",
        iface,
        obj_path
    );
    return run_shell_command(filter_command.data());
}

auto detach_tc(const char* iface) noexcept -> bool {
    auto filter_command = std::array<char, 512> {};
    (void)std::snprintf(
        filter_command.data(),
        filter_command.size(),
        "tc filter delete dev %s ingress",
        iface
    );
    (void)run_shell_command_allow_failure(filter_command.data());

    auto qdisc_command = std::array<char, 512> {};
    (void)std::snprintf(
        qdisc_command.data(),
        qdisc_command.size(),
        "tc qdisc delete dev %s clsact",
        iface
    );
    (void)run_shell_command_allow_failure(qdisc_command.data());
    return true;
}

auto action_to_text(const std::uint32_t action) noexcept -> const char* {
    if (action == BLACKBIRD_XDP_ACTION_REDIRECT) {
        return "redirect";
    }
    if (action == BLACKBIRD_XDP_ACTION_REWRITE_PASS) {
        return "rewrite-pass";
    }
    if (action == BLACKBIRD_XDP_ACTION_MIRROR) {
        return "mirror";
    }
    if (action == BLACKBIRD_XDP_ACTION_L3_MIRROR) {
        return "l3-mirror";
    }
    if (action == BLACKBIRD_XDP_ACTION_PASS) {
        return "pass";
    }
    if (action == BLACKBIRD_XDP_ACTION_DROP) {
        return "drop";
    }
    return "none";
}

auto configure_send_tc(
    const char* in_iface,
    const char* out_iface,
    const std::uint32_t action,
    const std::uint32_t match_ip_be,
    const std::uint16_t match_port,
    const std::uint32_t rewrite_ip_be,
    const std::uint16_t rewrite_port,
    const std::uint8_t rewrite_ttl,
    const bool collect_stats
) noexcept -> bool {
    auto map_fds = MapFds {};
    if (!get_map_fds_for_iface(in_iface, map_fds)) {
        return false;
    }

    const auto out_ifindex = std::uint32_t {if_nametoindex(out_iface)};
    if (out_ifindex == 0) {
        common::log_error("if_nametoindex(%s) failed", out_iface);
        return false;
    }

    if (action == BLACKBIRD_XDP_ACTION_L3_MIRROR) {
        auto out_iface_type = int {0};
        if (!read_iface_type(out_iface, out_iface_type)) {
            common::log_error("failed to read interface type for iface=%s", out_iface);
            return false;
        }
        if (!iface_is_l3_egress_type(out_iface_type)) {
            common::log_error(
                "iface=%s has ARPHRD type %d; use configure-mirror for Ethernet egress",
                out_iface,
                out_iface_type
            );
            return false;
        }
    }

    auto cfg = blackbird_xdp_forward_config {};
    cfg.enabled = 1;
    cfg.action = action;
    cfg.collect_stats = collect_stats ? 1U : 0U;
    cfg.match_dst_ip_be = match_ip_be;
    cfg.rewrite_dst_ip_be = rewrite_ip_be;
    cfg.match_dst_port_be = htons(match_port);
    cfg.rewrite_dst_port_be = htons(rewrite_port);
    cfg.rewrite_ttl = rewrite_ttl;
    const auto rewrite_l2 = action != BLACKBIRD_XDP_ACTION_L3_MIRROR;
    auto dst_mac = std::array<std::uint8_t, 6> {};
    auto src_mac = std::array<std::uint8_t, 6> {};
    if (rewrite_l2) {
        compute_multicast_mac(rewrite_ip_be, dst_mac);
        if (!read_iface_mac(out_iface, src_mac)) {
            common::log_error("failed to read source MAC for iface=%s", out_iface);
            return false;
        }
        for (auto i = std::size_t {0}; i < dst_mac.size(); ++i) {
            cfg.rewrite_dst_mac[i] = dst_mac[i];
            cfg.rewrite_src_mac[i] = src_mac[i];
        }
    }

    const auto update_cfg_ok = bpf_map_update(map_fds.cfg, kMapKeyZero, cfg);
    const auto update_tx_ok = bpf_map_update(map_fds.tx_ports, kMapKeyZero, out_ifindex);
    if (!update_cfg_ok) {
        common::log_error("cfg_map update failed: %s", std::strerror(errno));
    }
    if (!update_tx_ok) {
        common::log_error("tx_ports update failed: %s", std::strerror(errno));
    }

    auto verify = blackbird_xdp_forward_config {};
    const auto lookup_ok = bpf_map_lookup(map_fds.cfg, kMapKeyZero, verify);
    if (!update_cfg_ok || !update_tx_ok || !lookup_ok) {
        if (!lookup_ok) {
            common::log_error("cfg_map lookup failed: %s", std::strerror(errno));
        }
        return false;
    }

    auto match_ip_text = std::array<char, INET_ADDRSTRLEN> {};
    auto rewrite_ip_text = std::array<char, INET_ADDRSTRLEN> {};
    auto dst_mac_text = std::array<char, 18> {};
    auto src_mac_text = std::array<char, 18> {};
    auto match_addr = in_addr {match_ip_be};
    auto rewrite_addr = in_addr {rewrite_ip_be};
    (void)::inet_ntop(AF_INET, &match_addr, match_ip_text.data(), match_ip_text.size());
    (void)::inet_ntop(AF_INET, &rewrite_addr, rewrite_ip_text.data(), rewrite_ip_text.size());
    if (rewrite_l2) {
        format_mac(dst_mac, dst_mac_text);
        format_mac(src_mac, src_mac_text);
    } else {
        (void)std::snprintf(dst_mac_text.data(), dst_mac_text.size(), "%s", "n/a");
        (void)std::snprintf(src_mac_text.data(), src_mac_text.size(), "%s", "n/a");
    }

    common::log_info(
        "tc %s configured: in=%s out=%s ifindex=%u match=%s:%u rewrite=%s:%u "
        "dst_mac=%s src_mac=%s ttl=%u stats=%u",
        action_to_text(action),
        in_iface,
        out_iface,
        out_ifindex,
        match_ip_be == 0 ? "any" : match_ip_text.data(),
        static_cast<unsigned>(match_port),
        rewrite_ip_text.data(),
        static_cast<unsigned>(rewrite_port),
        dst_mac_text.data(),
        src_mac_text.data(),
        static_cast<unsigned>(rewrite_ttl),
        cfg.collect_stats
    );
    return true;
}

auto configure_local_tc(
    const char* iface,
    const std::uint32_t match_ip_be,
    const std::uint16_t match_port,
    const std::uint16_t local_port,
    const bool collect_stats
) noexcept -> bool {
    auto map_fds = MapFds {};
    if (!get_map_fds_for_iface(iface, map_fds)) {
        return false;
    }

    auto cfg = blackbird_xdp_forward_config {};
    cfg.enabled = 1;
    cfg.action = BLACKBIRD_XDP_ACTION_REWRITE_PASS;
    cfg.collect_stats = collect_stats ? 1U : 0U;
    cfg.match_dst_ip_be = match_ip_be;
    cfg.rewrite_dst_ip_be = 0;
    cfg.match_dst_port_be = htons(match_port);
    cfg.rewrite_dst_port_be = htons(local_port);
    cfg.rewrite_ttl = 0;

    const auto zero_ifindex = std::uint32_t {0};
    const auto update_cfg_ok = bpf_map_update(map_fds.cfg, kMapKeyZero, cfg);
    const auto update_tx_ok = bpf_map_update(map_fds.tx_ports, kMapKeyZero, zero_ifindex);
    if (!update_cfg_ok) {
        common::log_error("cfg_map update failed: %s", std::strerror(errno));
    }
    if (!update_tx_ok) {
        common::log_error("tx_ports update failed: %s", std::strerror(errno));
    }

    auto verify = blackbird_xdp_forward_config {};
    const auto lookup_ok = bpf_map_lookup(map_fds.cfg, kMapKeyZero, verify);
    if (!update_cfg_ok || !update_tx_ok || !lookup_ok) {
        if (!lookup_ok) {
            common::log_error("cfg_map lookup failed: %s", std::strerror(errno));
        }
        return false;
    }

    auto match_ip_text = std::array<char, INET_ADDRSTRLEN> {};
    auto match_addr = in_addr {match_ip_be};
    (void)::inet_ntop(AF_INET, &match_addr, match_ip_text.data(), match_ip_text.size());

    common::log_info(
        "tc local configured: iface=%s match=%s:%u local_port=%u action=rewrite-pass stats=%u",
        iface,
        match_ip_be == 0 ? "any" : match_ip_text.data(),
        static_cast<unsigned>(match_port),
        static_cast<unsigned>(local_port),
        cfg.collect_stats
    );
    return true;
}

auto disable_tc_rule(const char* iface) noexcept -> bool {
    auto map_fds = MapFds {};
    if (!get_map_fds_for_iface(iface, map_fds)) {
        return false;
    }

    auto cfg = blackbird_xdp_forward_config {};
    cfg.enabled = 0;
    cfg.action = BLACKBIRD_XDP_ACTION_NONE;
    cfg.collect_stats = 0;

    const auto zero_ifindex = std::uint32_t {0};
    const auto update_cfg_ok = bpf_map_update(map_fds.cfg, kMapKeyZero, cfg);
    const auto update_tx_ok = bpf_map_update(map_fds.tx_ports, kMapKeyZero, zero_ifindex);
    if (!update_cfg_ok || !update_tx_ok) {
        common::log_error("disable rule failed: %s", std::strerror(errno));
        return false;
    }

    common::log_info("tc rule disabled on iface=%s", iface);
    return true;
}

auto print_tc_stats(const char* iface) noexcept -> bool {
    auto map_fds = MapFds {};
    if (!get_map_fds_for_iface(iface, map_fds)) {
        return false;
    }

    auto cfg = blackbird_xdp_forward_config {};
    const auto cfg_ok = bpf_map_lookup(map_fds.cfg, kMapKeyZero, cfg);
    const auto stats_ok = bpf_map_lookup(map_fds.stats, kMapKeyZero, g_percpu_stats);
    if (!cfg_ok || !stats_ok) {
        common::log_error("stats lookup failed: %s", std::strerror(errno));
        return false;
    }

    auto cpu_count = std::size_t {0};
    if (!read_possible_cpu_count(cpu_count)) {
        common::log_error("failed to read possible cpu count");
        return false;
    }
    if (cpu_count > kMaxStatsCpus) {
        common::log_error("cpu count %zu exceeds max supported %zu", cpu_count, kMaxStatsCpus);
        return false;
    }

    auto total = blackbird_xdp_stats {};
    for (auto i = std::size_t {0}; i < cpu_count; ++i) {
        total.matched_packets += g_percpu_stats[i].matched_packets;
        total.matched_bytes += g_percpu_stats[i].matched_bytes;
        total.redirect_packets += g_percpu_stats[i].redirect_packets;
        total.pass_packets += g_percpu_stats[i].pass_packets;
        total.drop_packets += g_percpu_stats[i].drop_packets;
    }

    common::log_info(
        "tc stats: iface=%s enabled=%u action=%s collect_stats=%u matched_pkts=%" PRIu64
        " matched_bytes=%" PRIu64 " redirect=%" PRIu64 " pass=%" PRIu64 " drop=%" PRIu64,
        iface,
        cfg.enabled,
        action_to_text(cfg.action),
        cfg.collect_stats,
        total.matched_packets,
        total.matched_bytes,
        total.redirect_packets,
        total.pass_packets,
        total.drop_packets
    );
    return true;
}

auto clear_tc_stats(const char* iface) noexcept -> bool {
    auto map_fds = MapFds {};
    if (!get_map_fds_for_iface(iface, map_fds)) {
        return false;
    }

    g_percpu_stats = std::array<blackbird_xdp_stats, kMaxStatsCpus> {};
    const auto update_ok = bpf_map_update(map_fds.stats, kMapKeyZero, g_percpu_stats);
    if (!update_ok) {
        common::log_error("clear stats failed: %s", std::strerror(errno));
        return false;
    }

    common::log_info("tc stats reset on iface=%s", iface);
    return true;
}

auto print_usage(const char* prog) noexcept -> void {
    common::log_error("Usage:");
    common::log_error("  %s attach <iface> [tc_obj]", prog);
    common::log_error("  %s detach <iface>", prog);
    common::log_error(
        "  %s configure-send <in_iface> <out_iface> <match_ip|any> <match_port|0> "
        "<group_ip> <group_port> [ttl] [collect_stats_0_or_1]",
        prog
    );
    common::log_error(
        "  %s configure-mirror <in_iface> <out_iface> <match_ip|any> <match_port|0> "
        "<group_ip> <group_port> [ttl] [collect_stats_0_or_1]",
        prog
    );
    common::log_error(
        "  %s configure-l3-mirror <in_iface> <out_iface> <match_ip|any> <match_port|0> "
        "<dst_ip> <dst_port> [ttl] [collect_stats_0_or_1]",
        prog
    );
    common::log_error(
        "  %s configure-local <iface> <match_ip|any> <match_port|0> <local_port> [collect_stats_0_or_1]",
        prog
    );
    common::log_error("  %s disable <iface>", prog);
    common::log_error("  %s stats <iface>", prog);
    common::log_error("  %s clear-stats <iface>", prog);
}

}  // namespace

}  // namespace blackbird::tc

auto main(const int argc, char** argv) -> int {
    if (argc < 2) {
        blackbird::tc::print_usage(argv[0]);
        return 2;
    }

    if (std::strcmp(argv[1], "attach") == 0) {
        if (argc < 3 || argc > 4) {
            blackbird::tc::print_usage(argv[0]);
            return 2;
        }
        const auto* iface = argv[2];
        const auto* obj_path = argc == 4 ? argv[3] : blackbird::tc::kDefaultTcObjPath;
        return blackbird::tc::attach_tc(iface, obj_path) ? 0 : 1;
    }

    if (std::strcmp(argv[1], "detach") == 0) {
        if (argc != 3) {
            blackbird::tc::print_usage(argv[0]);
            return 2;
        }
        return blackbird::tc::detach_tc(argv[2]) ? 0 : 1;
    }

    const auto is_configure_send =
        std::strcmp(argv[1], "configure-send") == 0 || std::strcmp(argv[1], "configure") == 0;
    const auto is_configure_mirror =
        std::strcmp(argv[1], "configure-mirror") == 0 || std::strcmp(argv[1], "configure-clone") == 0;
    const auto is_configure_l3_mirror = std::strcmp(argv[1], "configure-l3-mirror") == 0 ||
        std::strcmp(argv[1], "configure-tunnel-mirror") == 0;
    if (is_configure_send || is_configure_mirror || is_configure_l3_mirror) {
        if (argc < 8 || argc > 10) {
            blackbird::tc::print_usage(argv[0]);
            return 2;
        }

        const auto* in_iface = argv[2];
        const auto* out_iface = argv[3];

        auto match_ip_be = std::uint32_t {0};
        if (!blackbird::tc::parse_ipv4_be_or_any(argv[4], match_ip_be)) {
            blackbird::common::log_error("invalid match_ip: %s", argv[4]);
            return 2;
        }

        auto match_port = std::uint16_t {0};
        if (!blackbird::tc::parse_u16(argv[5], match_port)) {
            blackbird::common::log_error("invalid match_port: %s", argv[5]);
            return 2;
        }

        auto rewrite_ip_be = std::uint32_t {0};
        if (!blackbird::tc::parse_ipv4_be(argv[6], rewrite_ip_be)) {
            blackbird::common::log_error(
                "invalid %s: %s",
                is_configure_l3_mirror ? "dst_ip" : "group_ip",
                argv[6]
            );
            return 2;
        }

        auto rewrite_port = std::uint16_t {0};
        if (!blackbird::tc::parse_u16(argv[7], rewrite_port) || rewrite_port == 0) {
            blackbird::common::log_error(
                "invalid %s: %s",
                is_configure_l3_mirror ? "dst_port" : "group_port",
                argv[7]
            );
            return 2;
        }

        auto ttl = std::uint8_t {1};
        auto collect_stats = true;
        if (argc >= 9) {
            auto ttl_int = int {0};
            if (!blackbird::common::parse_integer<int>(argv[8], int {1}, int {255}, ttl_int)) {
                blackbird::common::log_error("invalid ttl: %s", argv[8]);
                return 2;
            }
            ttl = static_cast<std::uint8_t>(ttl_int);
        }
        if (argc == 10 && !blackbird::tc::parse_bool_01(argv[9], collect_stats)) {
            blackbird::common::log_error("invalid collect_stats: %s", argv[9]);
            return 2;
        }

        auto action = std::uint32_t {BLACKBIRD_XDP_ACTION_REDIRECT};
        if (is_configure_mirror) {
            action = BLACKBIRD_XDP_ACTION_MIRROR;
        }
        if (is_configure_l3_mirror) {
            action = BLACKBIRD_XDP_ACTION_L3_MIRROR;
        }

        return blackbird::tc::configure_send_tc(
                   in_iface,
                   out_iface,
                   action,
                   match_ip_be,
                   match_port,
                   rewrite_ip_be,
                   rewrite_port,
                   ttl,
                   collect_stats
               )
            ? 0
            : 1;
    }

    if (std::strcmp(argv[1], "configure-local") == 0 ||
        std::strcmp(argv[1], "configure-port") == 0) {
        if (argc < 6 || argc > 7) {
            blackbird::tc::print_usage(argv[0]);
            return 2;
        }

        const auto* iface = argv[2];
        auto match_ip_be = std::uint32_t {0};
        if (!blackbird::tc::parse_ipv4_be_or_any(argv[3], match_ip_be)) {
            blackbird::common::log_error("invalid match_ip: %s", argv[3]);
            return 2;
        }

        auto match_port = std::uint16_t {0};
        if (!blackbird::tc::parse_u16(argv[4], match_port)) {
            blackbird::common::log_error("invalid match_port: %s", argv[4]);
            return 2;
        }

        auto local_port = std::uint16_t {0};
        if (!blackbird::tc::parse_u16(argv[5], local_port) || local_port == 0) {
            blackbird::common::log_error("invalid local_port: %s", argv[5]);
            return 2;
        }

        auto collect_stats = true;
        if (argc == 7 && !blackbird::tc::parse_bool_01(argv[6], collect_stats)) {
            blackbird::common::log_error("invalid collect_stats: %s", argv[6]);
            return 2;
        }

        return blackbird::tc::configure_local_tc(
                   iface,
                   match_ip_be,
                   match_port,
                   local_port,
                   collect_stats
               )
            ? 0
            : 1;
    }

    if (std::strcmp(argv[1], "disable") == 0) {
        if (argc != 3) {
            blackbird::tc::print_usage(argv[0]);
            return 2;
        }
        return blackbird::tc::disable_tc_rule(argv[2]) ? 0 : 1;
    }

    if (std::strcmp(argv[1], "stats") == 0) {
        if (argc != 3) {
            blackbird::tc::print_usage(argv[0]);
            return 2;
        }
        return blackbird::tc::print_tc_stats(argv[2]) ? 0 : 1;
    }

    if (std::strcmp(argv[1], "clear-stats") == 0) {
        if (argc != 3) {
            blackbird::tc::print_usage(argv[0]);
            return 2;
        }
        return blackbird::tc::clear_tc_stats(argv[2]) ? 0 : 1;
    }

    blackbird::tc::print_usage(argv[0]);
    return 2;
}
