#include "blackbird/common/perf.hpp"

#include <cerrno>
#include <cstring>

#include <netinet/ip.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include "blackbird/common/log.hpp"

namespace blackbird::common {

namespace {

auto tune_affinity(int cpu_core) noexcept -> void {
    auto cpus = cpu_set_t {};
    CPU_ZERO(&cpus);
    CPU_SET(static_cast<std::size_t>(cpu_core), &cpus);
    if (::sched_setaffinity(0, sizeof(cpus), &cpus) < 0) {
        log_warn("sched_setaffinity(cpu=%d) failed: %s", cpu_core, std::strerror(errno));
        return;
    }
    log_info("process pinned to cpu=%d", cpu_core);
}

}  // namespace

auto tune_process(const ProcessPerfConfig& cfg) noexcept -> void {
    if (cfg.cpu_core >= 0) {
        tune_affinity(cfg.cpu_core);
    }

    if (cfg.lock_memory) {
        if (::mlockall(MCL_CURRENT | MCL_FUTURE) < 0) {
            log_warn("mlockall failed: %s", std::strerror(errno));
        } else {
            log_info("mlockall enabled");
        }
    }

    if (cfg.set_high_priority) {
        if (::setpriority(PRIO_PROCESS, 0, -20) < 0) {
            log_warn("setpriority(-20) failed: %s", std::strerror(errno));
        } else {
            log_info("process niceness set to -20");
        }
    }

    if (cfg.set_realtime) {
        auto sched = sched_param {};
        sched.sched_priority = ::sched_get_priority_max(SCHED_FIFO) - 1;
        if (::sched_setscheduler(0, SCHED_FIFO, &sched) < 0) {
            log_warn("sched_setscheduler(SCHED_FIFO) failed: %s", std::strerror(errno));
        } else {
            log_info("process scheduler set to SCHED_FIFO prio=%d", sched.sched_priority);
        }
    }
}

auto tune_receiver_socket(int fd, int busy_poll_us) noexcept -> void {
    if (fd < 0) {
        return;
    }

#ifdef SO_BUSY_POLL
    const auto busy_poll = int {busy_poll_us};
    if (::setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, &busy_poll, sizeof(busy_poll)) < 0) {
        log_warn("setsockopt(SO_BUSY_POLL=%d) failed: %s", busy_poll_us, std::strerror(errno));
    }
#endif

#ifdef SO_BUSY_POLL_BUDGET
    const auto busy_budget = int {256};
    if (::setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL_BUDGET, &busy_budget, sizeof(busy_budget)) <
        0) {
        log_warn(
            "setsockopt(SO_BUSY_POLL_BUDGET=%d) failed: %s",
            busy_budget,
            std::strerror(errno)
        );
    }
#endif
}

auto tune_sender_socket(int fd) noexcept -> void {
    if (fd < 0) {
        return;
    }

#ifdef SO_PRIORITY
    const auto prio = int {6};
    if (::setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio)) < 0) {
        log_warn("setsockopt(SO_PRIORITY=%d) failed: %s", prio, std::strerror(errno));
    }
#endif

#ifdef IP_TOS
    const auto tos = int {0x2e};
    if (::setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) < 0) {
        log_warn("setsockopt(IP_TOS=0x%x) failed: %s", tos, std::strerror(errno));
    }
#endif
}

}  // namespace blackbird::common
