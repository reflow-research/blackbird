#include <linux/bpf.h>
#include <net/if.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "blackbird/common/log.hpp"

namespace blackbird::xdp::fast {

namespace {

constexpr auto kTxPortsMapName = "tx_ports";
constexpr auto kMapKeyZero = std::uint32_t {0};

#ifdef BLACKBIRD_DEFAULT_XDP_FAST_OBJ_PATH
constexpr auto kDefaultXdpFastObjPath = BLACKBIRD_DEFAULT_XDP_FAST_OBJ_PATH;
#else
constexpr auto kDefaultXdpFastObjPath = "./blackbird_xdp_fast_kern.o";
#endif

enum class AttachMode : std::uint8_t {
    kDrv,
    kSkb,
    kHw,
};

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
    out_prog_id = parsed;
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

auto get_tx_ports_map_fd_for_prog(const std::uint32_t prog_id, int& out_map_fd) noexcept -> bool {
    out_map_fd = -1;

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
        const auto map_id = map_ids[i];
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
        if (std::strncmp(map_name, kTxPortsMapName, BPF_OBJ_NAME_LEN) == 0) {
            out_map_fd = map_fd;
            return true;
        }

        (void)::close(map_fd);
    }

    common::log_error("tx_ports map not found on XDP program id %u", prog_id);
    return false;
}

auto get_tx_ports_map_fd_for_iface(const char* iface, int& out_map_fd) noexcept -> bool {
    auto prog_id = std::uint32_t {0};
    if (!get_xdp_prog_id_for_iface(iface, prog_id)) {
        return false;
    }
    return get_tx_ports_map_fd_for_prog(prog_id, out_map_fd);
}

auto parse_mode(const char* text, AttachMode& out_mode) noexcept -> bool {
    if (std::strcmp(text, "drv") == 0 || std::strcmp(text, "xdpdrv") == 0 ||
        std::strcmp(text, "native") == 0) {
        out_mode = AttachMode::kDrv;
        return true;
    }
    if (std::strcmp(text, "skb") == 0 || std::strcmp(text, "xdpgeneric") == 0 ||
        std::strcmp(text, "generic") == 0) {
        out_mode = AttachMode::kSkb;
        return true;
    }
    if (std::strcmp(text, "hw") == 0 || std::strcmp(text, "xdpoffload") == 0 ||
        std::strcmp(text, "offload") == 0) {
        out_mode = AttachMode::kHw;
        return true;
    }
    return false;
}

auto mode_to_attach_token(const AttachMode mode) noexcept -> const char* {
    if (mode == AttachMode::kDrv) {
        return "xdpdrv";
    }
    if (mode == AttachMode::kSkb) {
        return "xdpgeneric";
    }
    return "xdpoffload";
}

auto attach_xdp_fast(const char* iface, const char* obj_path, const AttachMode mode) noexcept
    -> bool {
    auto command = std::array<char, 1024> {};
    (void)std::snprintf(
        command.data(),
        command.size(),
        "ip link set dev %s %s obj %s sec xdp",
        iface,
        mode_to_attach_token(mode),
        obj_path
    );
    return run_shell_command(command.data());
}

auto detach_xdp_fast(const char* iface, const AttachMode mode) noexcept -> bool {
    auto command = std::array<char, 256> {};
    (void)std::snprintf(
        command.data(),
        command.size(),
        "ip link set dev %s %s off",
        iface,
        mode_to_attach_token(mode)
    );
    if (run_shell_command(command.data())) {
        return true;
    }

    auto fallback = std::array<char, 256> {};
    (void)std::snprintf(fallback.data(), fallback.size(), "ip link set dev %s xdp off", iface);
    return run_shell_command(fallback.data());
}

auto update_redirect_port(const char* in_iface, const std::uint32_t out_ifindex) noexcept -> bool {
    auto tx_ports_fd = int {-1};
    if (!get_tx_ports_map_fd_for_iface(in_iface, tx_ports_fd)) {
        return false;
    }

    const auto ok = bpf_map_update(tx_ports_fd, kMapKeyZero, out_ifindex);
    const auto saved_errno = errno;
    (void)::close(tx_ports_fd);

    if (!ok) {
        common::log_error("tx_ports map update failed: %s", std::strerror(saved_errno));
        return false;
    }

    return true;
}

auto configure_fast_redirect(const char* in_iface, const char* out_iface) noexcept -> bool {
    const auto out_ifindex = std::uint32_t {if_nametoindex(out_iface)};
    if (out_ifindex == 0) {
        common::log_error("if_nametoindex(%s) failed", out_iface);
        return false;
    }
    if (!update_redirect_port(in_iface, out_ifindex)) {
        return false;
    }

    common::log_info("xdp fast redirect configured: in=%s out=%s ifindex=%u", in_iface, out_iface, out_ifindex);
    return true;
}

auto disable_fast_redirect(const char* in_iface) noexcept -> bool {
    if (!update_redirect_port(in_iface, std::uint32_t {0})) {
        return false;
    }
    common::log_info("xdp fast redirect disabled on iface=%s", in_iface);
    return true;
}

auto connect_fast_redirect(
    const char* in_iface,
    const char* out_iface,
    const char* obj_path,
    const AttachMode mode
) noexcept -> bool {
    if (!attach_xdp_fast(in_iface, obj_path, mode)) {
        return false;
    }
    return configure_fast_redirect(in_iface, out_iface);
}

auto print_usage(const char* prog) noexcept -> void {
    common::log_error("Usage:");
    common::log_error("  %s attach <in_iface> [xdp_obj|mode] [mode]", prog);
    common::log_error("  %s detach <in_iface> [mode]", prog);
    common::log_error("  %s set-port <in_iface> <out_iface>", prog);
    common::log_error("  %s connect <in_iface> <out_iface> [xdp_obj|mode] [mode]", prog);
    common::log_error("  %s disable <in_iface>", prog);
    common::log_error("  modes: drv|hw|skb (default: drv)", prog);
}

}  // namespace

}  // namespace blackbird::xdp::fast

auto main(const int argc, char** argv) -> int {
    if (argc < 2) {
        blackbird::xdp::fast::print_usage(argv[0]);
        return 2;
    }

    if (std::strcmp(argv[1], "attach") == 0) {
        if (argc < 3 || argc > 5) {
            blackbird::xdp::fast::print_usage(argv[0]);
            return 2;
        }

        const auto* in_iface = argv[2];
        const auto* obj_path = blackbird::xdp::fast::kDefaultXdpFastObjPath;
        auto mode = blackbird::xdp::fast::AttachMode::kDrv;

        if (argc == 4) {
            if (!blackbird::xdp::fast::parse_mode(argv[3], mode)) {
                obj_path = argv[3];
            }
        }
        if (argc == 5) {
            obj_path = argv[3];
            if (!blackbird::xdp::fast::parse_mode(argv[4], mode)) {
                blackbird::common::log_error("invalid mode: %s", argv[4]);
                return 2;
            }
        }

        return blackbird::xdp::fast::attach_xdp_fast(in_iface, obj_path, mode) ? 0 : 1;
    }

    if (std::strcmp(argv[1], "detach") == 0) {
        if (argc < 3 || argc > 4) {
            blackbird::xdp::fast::print_usage(argv[0]);
            return 2;
        }

        auto mode = blackbird::xdp::fast::AttachMode::kDrv;
        if (argc == 4 && !blackbird::xdp::fast::parse_mode(argv[3], mode)) {
            blackbird::common::log_error("invalid mode: %s", argv[3]);
            return 2;
        }

        return blackbird::xdp::fast::detach_xdp_fast(argv[2], mode) ? 0 : 1;
    }

    if (std::strcmp(argv[1], "set-port") == 0) {
        if (argc != 4) {
            blackbird::xdp::fast::print_usage(argv[0]);
            return 2;
        }
        return blackbird::xdp::fast::configure_fast_redirect(argv[2], argv[3]) ? 0 : 1;
    }

    if (std::strcmp(argv[1], "connect") == 0) {
        if (argc < 4 || argc > 6) {
            blackbird::xdp::fast::print_usage(argv[0]);
            return 2;
        }

        const auto* in_iface = argv[2];
        const auto* out_iface = argv[3];
        const auto* obj_path = blackbird::xdp::fast::kDefaultXdpFastObjPath;
        auto mode = blackbird::xdp::fast::AttachMode::kDrv;

        if (argc == 5) {
            if (!blackbird::xdp::fast::parse_mode(argv[4], mode)) {
                obj_path = argv[4];
            }
        }
        if (argc == 6) {
            obj_path = argv[4];
            if (!blackbird::xdp::fast::parse_mode(argv[5], mode)) {
                blackbird::common::log_error("invalid mode: %s", argv[5]);
                return 2;
            }
        }

        return blackbird::xdp::fast::connect_fast_redirect(in_iface, out_iface, obj_path, mode)
            ? 0
            : 1;
    }

    if (std::strcmp(argv[1], "disable") == 0) {
        if (argc != 3) {
            blackbird::xdp::fast::print_usage(argv[0]);
            return 2;
        }
        return blackbird::xdp::fast::disable_fast_redirect(argv[2]) ? 0 : 1;
    }

    blackbird::xdp::fast::print_usage(argv[0]);
    return 2;
}
