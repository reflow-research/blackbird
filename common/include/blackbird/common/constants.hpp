#pragma once

#include <cstddef>
#include <cstdint>

namespace blackbird::common {

constexpr auto kPageSize = std::size_t {4096};
constexpr auto kMaxBatch = std::size_t {256};
constexpr auto kPayloadBytes = std::size_t {1400};
constexpr auto kAlignedPayloadBytes = kPageSize;
constexpr auto kMaxMessageBytes = kPayloadBytes - 32;
constexpr auto kLogLineBytes = std::size_t {512};
constexpr auto kDefaultSendBufBytes = int {8 * 1024 * 1024};
constexpr auto kDefaultRecvBufBytes = int {16 * 1024 * 1024};
constexpr auto kDefaultBusyPollUs = int {50};

static_assert(kAlignedPayloadBytes % kPageSize == 0);
static_assert(kPayloadBytes <= kAlignedPayloadBytes);
static_assert(kMaxBatch > 0);

}  // namespace blackbird::common
