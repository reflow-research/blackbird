#include <csignal>

#include "blackbird/client/receiver.hpp"
#include "blackbird/common/log.hpp"

namespace {

volatile auto g_stop = sig_atomic_t {0};

auto handle_signal(int) -> void {
    g_stop = 1;
}

}  // namespace

auto main(int argc, char** argv) -> int {
    auto cfg = blackbird::client::ReceiverConfig {};
    if (!blackbird::client::parse_receiver_args(argc, argv, cfg)) {
        return 2;
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    auto receiver = blackbird::client::Receiver {cfg};
    if (!receiver.Init()) {
        blackbird::common::log_error("receiver initialization failed");
        return 1;
    }

    receiver.Run(&g_stop);
    return 0;
}
