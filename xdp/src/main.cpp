#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

#include "blackbird/common/log.hpp"
#include "blackbird/common/parse.hpp"
#include "blackbird/xdp/forward_config.h"

namespace blackbird::xdp {

namespace {

static_assert(sizeof(blackbird_xdp_forward_config) == 40U);
static_assert(sizeof(blackbird_xdp_stats) == 40U);

constexpr auto kCfgMapName = "cfg_map";
constexpr auto kTxPortsMapName = "tx_ports";
constexpr auto kStatsMapName = "stats_map";
constexpr auto kMapKeyZero = std::uint32_t {0};
constexpr auto kMaxStatsCpus = std::size_t {1024};

alignas(64) static auto g_percpu_stats = std::array<blackbird_xdp_stats, kMaxStatsCpus> {};

#ifdef BLACKBIRD_DEFAULT_XDP_OBJ_PATH
constexpr auto kDefaultXdpObjPath = BLACKBIRD_DEFAULT_XDP_OBJ_PATH;
#else
constexpr auto kDefaultXdpObjPath = "./blackbird_xdp_kern.o";
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

auto parse_mac(const char* text, std::array<std::uint8_t, 6>& out) noexcept -> bool {
    auto b0 = std::uint32_t {0};
    auto b1 = std::uint32_t {0};
    auto b2 = std::uint32_t {0};
    auto b3 = std::uint32_t {0};
    auto b4 = std::uint32_t {0};
    auto b5 = std::uint32_t {0};
    if (std::sscanf(
            text,
            "%2x:%2x:%2x:%2x:%2x:%2x",
            &b0,
            &b1,
            &b2,
            &b3,
            &b4,
            &b5
        ) != 6) {
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
    auto cursor = text.data();
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

    auto line_len = std::strlen(line.data());
    while (line_len > 0 &&
           (line[line_len - 1] == '\n' || line[line_len - 1] == '\r' ||
            line[line_len - 1] == ' ' || line[line_len - 1] == '\t')) {
        line[line_len - 1] = '\0';
        --line_len;
    }
    return parse_mac(line.data(), out);
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

auto parse_prog_id_from_line(const char* line, std::uint32_t& out_prog_id) noexcept -> bool {
    const auto* marker_1 = std::strstr(line, "prog/xdp id ");
    const auto* marker_2 = std::strstr(line, "xdp id ");
    auto* cursor = marker_1 != nullptr ? marker_1 : marker_2;
    if (cursor == nullptr) {
        return false;
    }

    while (*cursor != '\0' && (*cursor < '0' || *cursor > '9')) {
        ++cursor;
    }
    if (*cursor == '\0') {
        return false;
    }

    auto parsed = std::uint32_t {0};
    if (std::sscanf(cursor, "%u", &parsed) != 1) {
        return false;
    }
    out_prog_id = static_cast<std::uint32_t>(parsed);
    return true;
}

auto get_xdp_prog_id_for_iface(const char* iface, std::uint32_t& out_prog_id) noexcept -> bool {
    auto cmd = std::array<char, 256> {};
    (void)std::snprintf(
        cmd.data(),
        cmd.size(),
        "ip -details link show dev %s 2>/dev/null",
        iface
    );
    auto* pipe = ::popen(cmd.data(), "r");
    if (pipe == nullptr) {
        common::log_error("popen failed: %s", std::strerror(errno));
        return false;
    }

    auto line = std::array<char, 512> {};
    auto found = false;
    while (std::fgets(line.data(), static_cast<int>(line.size()), pipe) != nullptr) {
        auto parsed_id = std::uint32_t {0};
        if (parse_prog_id_from_line(line.data(), parsed_id)) {
            out_prog_id = parsed_id;
            found = true;
            break;
        }
    }

    (void)::pclose(pipe);
    if (!found) {
        common::log_error("no XDP program found on interface %s", iface);
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
        common::log_error("required XDP maps not found (cfg_map / tx_ports / stats_map)");
        return false;
    }

    return true;
}

auto attach_xdp(const char* iface, const char* obj_path) noexcept -> bool {
    auto command = std::array<char, 1024> {};
    (void)std::snprintf(
        command.data(),
        command.size(),
        "ip link set dev %s xdp obj %s sec xdp",
        iface,
        obj_path
    );
    return run_shell_command(command.data());
}

auto detach_xdp(const char* iface) noexcept -> bool {
    auto command = std::array<char, 256> {};
    (void)std::snprintf(command.data(), command.size(), "ip link set dev %s xdp off", iface);
    return run_shell_command(command.data());
}

auto get_map_fds_for_iface(const char* iface, MapFds& out_fds) noexcept -> bool {
    auto prog_id = std::uint32_t {0};
    if (!get_xdp_prog_id_for_iface(iface, prog_id)) {
        return false;
    }
    return get_named_map_fds_for_prog(prog_id, out_fds);
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

auto configure_send_xdp(
    const char* in_iface,
    const char* out_iface,
    const std::uint32_t match_ip_be,
    const std::uint16_t match_port,
    const std::uint32_t rewrite_ip_be,
    const std::uint16_t rewrite_port,
    const std::array<std::uint8_t, 6>& dst_mac,
    const std::array<std::uint8_t, 6>& src_mac,
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

    auto cfg = blackbird_xdp_forward_config {};
    cfg.enabled = 1;
    cfg.action = BLACKBIRD_XDP_ACTION_REDIRECT;
    cfg.collect_stats = collect_stats ? 1U : 0U;
    cfg.match_dst_ip_be = match_ip_be;
    cfg.rewrite_dst_ip_be = rewrite_ip_be;
    cfg.match_dst_port_be = htons(match_port);
    cfg.rewrite_dst_port_be = htons(rewrite_port);
    cfg.rewrite_ttl = rewrite_ttl;
    for (auto i = std::size_t {0}; i < dst_mac.size(); ++i) {
        cfg.rewrite_dst_mac[i] = dst_mac[i];
        cfg.rewrite_src_mac[i] = src_mac[i];
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

    auto dst_mac_text = std::array<char, 18> {};
    auto src_mac_text = std::array<char, 18> {};
    format_mac(dst_mac, dst_mac_text);
    format_mac(src_mac, src_mac_text);

    auto match_ip_text = std::array<char, INET_ADDRSTRLEN> {};
    auto rewrite_ip_text = std::array<char, INET_ADDRSTRLEN> {};
    auto match_addr = in_addr {match_ip_be};
    auto rewrite_addr = in_addr {rewrite_ip_be};
    (void)::inet_ntop(AF_INET, &match_addr, match_ip_text.data(), match_ip_text.size());
    (void)::inet_ntop(AF_INET, &rewrite_addr, rewrite_ip_text.data(), rewrite_ip_text.size());

    common::log_info(
        "xdp send configured: in=%s out=%s match=%s:%u rewrite=%s:%u dst_mac=%s src_mac=%s ttl=%u stats=%u",
        in_iface,
        out_iface,
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

auto configure_recv_xdp(
    const char* iface,
    const std::uint32_t match_ip_be,
    const std::uint16_t match_port,
    const bool drop_mode,
    const bool collect_stats
) noexcept -> bool {
    auto map_fds = MapFds {};
    if (!get_map_fds_for_iface(iface, map_fds)) {
        return false;
    }

    auto cfg = blackbird_xdp_forward_config {};
    cfg.enabled = 1;
    cfg.action = drop_mode ? BLACKBIRD_XDP_ACTION_DROP : BLACKBIRD_XDP_ACTION_PASS;
    cfg.collect_stats = collect_stats ? 1U : 0U;
    cfg.match_dst_ip_be = match_ip_be;
    cfg.rewrite_dst_ip_be = 0;
    cfg.match_dst_port_be = htons(match_port);
    cfg.rewrite_dst_port_be = 0;
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
        "xdp receive configured: iface=%s match=%s:%u action=%s stats=%u",
        iface,
        match_ip_be == 0 ? "any" : match_ip_text.data(),
        static_cast<unsigned>(match_port),
        drop_mode ? "drop" : "pass",
        cfg.collect_stats
    );
    return true;
}

auto configure_local_xdp(
    const char* iface,
    const std::uint32_t match_ip_be,
    const std::uint16_t match_port,
    const std::uint16_t rewrite_port,
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
    cfg.rewrite_dst_port_be = htons(rewrite_port);
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
        "xdp local configured: iface=%s match=%s:%u rewrite_port=%u action=rewrite-pass stats=%u",
        iface,
        match_ip_be == 0 ? "any" : match_ip_text.data(),
        static_cast<unsigned>(match_port),
        static_cast<unsigned>(rewrite_port),
        cfg.collect_stats
    );
    return true;
}

auto disable_xdp_rule(const char* iface) noexcept -> bool {
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
    common::log_info("xdp rule disabled on iface=%s", iface);
    return true;
}

auto print_xdp_stats(const char* iface) noexcept -> bool {
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
        "xdp stats: iface=%s enabled=%u action=%s collect_stats=%u matched_pkts=%" PRIu64
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

auto clear_xdp_stats(const char* iface) noexcept -> bool {
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
    common::log_info("xdp stats reset on iface=%s", iface);
    return true;
}

auto print_usage(const char* prog) noexcept -> void {
    common::log_error("Usage:");
    common::log_error("  %s attach <in_iface> [xdp_obj]", prog);
    common::log_error("  %s detach <in_iface>", prog);
    common::log_error(
        "  %s configure-send <in_iface> <out_iface> <match_ip|any> <match_port|0> "
        "<group_ip> <group_port> <dst_mac|auto> <src_mac|auto> [ttl] [collect_stats_0_or_1]",
        prog
    );
    common::log_error(
        "  %s configure-recv <iface> <group_ip|any> <group_port|0> [pass|drop] [collect_stats_0_or_1]",
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

}  // namespace blackbird::xdp

auto main(const int argc, char** argv) -> int {
    if (argc < 2) {
        blackbird::xdp::print_usage(argv[0]);
        return 2;
    }

    if (std::strcmp(argv[1], "attach") == 0) {
        if (argc < 3 || argc > 4) {
            blackbird::xdp::print_usage(argv[0]);
            return 2;
        }
        const auto* iface = argv[2];
        const auto* obj_path = argc == 4 ? argv[3] : blackbird::xdp::kDefaultXdpObjPath;
        return blackbird::xdp::attach_xdp(iface, obj_path) ? 0 : 1;
    }

    if (std::strcmp(argv[1], "detach") == 0) {
        if (argc != 3) {
            blackbird::xdp::print_usage(argv[0]);
            return 2;
        }
        return blackbird::xdp::detach_xdp(argv[2]) ? 0 : 1;
    }

    if (std::strcmp(argv[1], "configure-send") == 0 || std::strcmp(argv[1], "configure") == 0) {
        if (argc < 10 || argc > 12) {
            blackbird::xdp::print_usage(argv[0]);
            return 2;
        }

        const auto* in_iface = argv[2];
        const auto* out_iface = argv[3];

        auto match_ip_be = std::uint32_t {0};
        if (!blackbird::xdp::parse_ipv4_be_or_any(argv[4], match_ip_be)) {
            blackbird::common::log_error("invalid match_ip: %s", argv[4]);
            return 2;
        }

        auto match_port = std::uint16_t {0};
        if (!blackbird::xdp::parse_u16(argv[5], match_port)) {
            blackbird::common::log_error("invalid match_port: %s", argv[5]);
            return 2;
        }

        auto rewrite_ip_be = std::uint32_t {0};
        if (!blackbird::xdp::parse_ipv4_be(argv[6], rewrite_ip_be)) {
            blackbird::common::log_error("invalid group_ip: %s", argv[6]);
            return 2;
        }

        auto rewrite_port = std::uint16_t {0};
        if (!blackbird::xdp::parse_u16(argv[7], rewrite_port) || rewrite_port == 0) {
            blackbird::common::log_error("invalid group_port: %s", argv[7]);
            return 2;
        }

        auto dst_mac = std::array<std::uint8_t, 6> {};
        if (std::strcmp(argv[8], "auto") == 0) {
            blackbird::xdp::compute_multicast_mac(rewrite_ip_be, dst_mac);
        } else if (!blackbird::xdp::parse_mac(argv[8], dst_mac)) {
            blackbird::common::log_error("invalid dst_mac: %s", argv[8]);
            return 2;
        }

        auto src_mac = std::array<std::uint8_t, 6> {};
        if (std::strcmp(argv[9], "auto") == 0) {
            if (!blackbird::xdp::read_iface_mac(out_iface, src_mac)) {
                blackbird::common::log_error("failed to read source MAC for iface=%s", out_iface);
                return 2;
            }
        } else if (!blackbird::xdp::parse_mac(argv[9], src_mac)) {
            blackbird::common::log_error("invalid src_mac: %s", argv[9]);
            return 2;
        }

        auto ttl = std::uint8_t {1};
        auto collect_stats = false;
        if (argc >= 11) {
            auto ttl_int = int {0};
            if (!blackbird::common::parse_integer<int>(argv[10], int {1}, int {255}, ttl_int)) {
                blackbird::common::log_error("invalid ttl: %s", argv[10]);
                return 2;
            }
            ttl = static_cast<std::uint8_t>(ttl_int);
        }
        if (argc == 12 && !blackbird::xdp::parse_bool_01(argv[11], collect_stats)) {
            blackbird::common::log_error("invalid collect_stats: %s", argv[11]);
            return 2;
        }

        return blackbird::xdp::configure_send_xdp(
                   in_iface,
                   out_iface,
                   match_ip_be,
                   match_port,
                   rewrite_ip_be,
                   rewrite_port,
                   dst_mac,
                   src_mac,
                   ttl,
                   collect_stats
               )
            ? 0
            : 1;
    }

    if (std::strcmp(argv[1], "configure-recv") == 0) {
        if (argc < 5 || argc > 7) {
            blackbird::xdp::print_usage(argv[0]);
            return 2;
        }

        const auto* iface = argv[2];
        auto match_ip_be = std::uint32_t {0};
        if (!blackbird::xdp::parse_ipv4_be_or_any(argv[3], match_ip_be)) {
            blackbird::common::log_error("invalid group_ip: %s", argv[3]);
            return 2;
        }

        auto match_port = std::uint16_t {0};
        if (!blackbird::xdp::parse_u16(argv[4], match_port)) {
            blackbird::common::log_error("invalid group_port: %s", argv[4]);
            return 2;
        }

        auto drop_mode = false;
        auto collect_stats = true;
        if (argc == 6) {
            if (std::strcmp(argv[5], "drop") == 0) {
                drop_mode = true;
            } else if (std::strcmp(argv[5], "pass") == 0) {
                drop_mode = false;
            } else if (blackbird::xdp::parse_bool_01(argv[5], collect_stats)) {
                drop_mode = false;
            } else {
                blackbird::common::log_error(
                    "invalid arg: %s (expected pass|drop or collect_stats 0|1)",
                    argv[5]
                );
                return 2;
            }
        }
        if (argc == 7) {
            if (std::strcmp(argv[5], "drop") == 0) {
                drop_mode = true;
            } else if (std::strcmp(argv[5], "pass") == 0) {
                drop_mode = false;
            } else {
                blackbird::common::log_error("invalid mode: %s (expected pass|drop)", argv[5]);
                return 2;
            }
            if (!blackbird::xdp::parse_bool_01(argv[6], collect_stats)) {
                blackbird::common::log_error("invalid collect_stats: %s", argv[6]);
                return 2;
            }
        }

        return blackbird::xdp::configure_recv_xdp(
                   iface,
                   match_ip_be,
                   match_port,
                   drop_mode,
                   collect_stats
               )
            ? 0
            : 1;
    }

    if (std::strcmp(argv[1], "configure-local") == 0 ||
        std::strcmp(argv[1], "configure-port") == 0) {
        if (argc < 6 || argc > 7) {
            blackbird::xdp::print_usage(argv[0]);
            return 2;
        }

        const auto* iface = argv[2];
        auto match_ip_be = std::uint32_t {0};
        if (!blackbird::xdp::parse_ipv4_be_or_any(argv[3], match_ip_be)) {
            blackbird::common::log_error("invalid match_ip: %s", argv[3]);
            return 2;
        }

        auto match_port = std::uint16_t {0};
        if (!blackbird::xdp::parse_u16(argv[4], match_port)) {
            blackbird::common::log_error("invalid match_port: %s", argv[4]);
            return 2;
        }

        auto rewrite_port = std::uint16_t {0};
        if (!blackbird::xdp::parse_u16(argv[5], rewrite_port) || rewrite_port == 0) {
            blackbird::common::log_error("invalid local_port: %s", argv[5]);
            return 2;
        }

        auto collect_stats = true;
        if (argc == 7 && !blackbird::xdp::parse_bool_01(argv[6], collect_stats)) {
            blackbird::common::log_error("invalid collect_stats: %s", argv[6]);
            return 2;
        }

        return blackbird::xdp::configure_local_xdp(
                   iface,
                   match_ip_be,
                   match_port,
                   rewrite_port,
                   collect_stats
               )
            ? 0
            : 1;
    }

    if (std::strcmp(argv[1], "disable") == 0) {
        if (argc != 3) {
            blackbird::xdp::print_usage(argv[0]);
            return 2;
        }
        return blackbird::xdp::disable_xdp_rule(argv[2]) ? 0 : 1;
    }

    if (std::strcmp(argv[1], "stats") == 0) {
        if (argc != 3) {
            blackbird::xdp::print_usage(argv[0]);
            return 2;
        }
        return blackbird::xdp::print_xdp_stats(argv[2]) ? 0 : 1;
    }

    if (std::strcmp(argv[1], "clear-stats") == 0) {
        if (argc != 3) {
            blackbird::xdp::print_usage(argv[0]);
            return 2;
        }
        return blackbird::xdp::clear_xdp_stats(argv[2]) ? 0 : 1;
    }

    blackbird::xdp::print_usage(argv[0]);
    return 2;
}
