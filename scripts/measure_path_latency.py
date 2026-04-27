#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import selectors
import socket
import struct
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass


SO_TIMESTAMPNS = getattr(socket, "SO_TIMESTAMPNS", 35)
ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8
IPPROTO_UDP = 17
PACKET_HOST = getattr(socket, "PACKET_HOST", 0)
PACKET_OUTGOING = getattr(socket, "PACKET_OUTGOING", 4)
SOCKET_RCVBUF_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class Config:
    local_source: str
    local_port: int
    local_ingress_iface: str
    local_flow_port: int
    local_flow_direction: str
    bind_ip: str
    mcast_group: str
    mcast_port: int
    mcast_iface_ip: str
    mcast_source: str
    local_udp_timestamp_source: str
    mcast_udp_timestamp_source: str
    mcast_egress_iface: str
    samples: int
    timeout_sec: float
    digest_size: int
    match_key: str
    payload_prefix: bytes
    max_unmatched_age_sec: float
    progress_interval_sec: float


def parse_args() -> Config:
    parser = argparse.ArgumentParser(
        description=(
            "Measure added latency between local path and multicast path by matching "
            "payload hashes and comparing receive timestamps."
        )
    )
    parser.add_argument(
        "--local-source",
        choices=("udp", "ingress-packet"),
        default="udp",
        help="Local side source: udp socket on --local-port, or packet capture on --local-ingress-iface.",
    )
    parser.add_argument(
        "--local-port",
        type=int,
        default=42069,
        help="Local UDP port when --local-source=udp.",
    )
    parser.add_argument(
        "--local-ingress-iface",
        default="doublezero0",
        help="Interface used when --local-source=ingress-packet.",
    )
    parser.add_argument(
        "--local-flow-port",
        type=int,
        default=0,
        help=(
            "UDP flow-port filter for --local-source=ingress-packet. "
            "0 means match all UDP."
        ),
    )
    parser.add_argument(
        "--local-flow-direction",
        choices=("dst", "either"),
        default="dst",
        help=(
            "Direction used with --local-flow-port when --local-source=ingress-packet. "
            "'dst' matches UDP dst port only. 'either' matches src or dst."
        ),
    )
    parser.add_argument("--bind-ip", default="0.0.0.0", help="Local bind address for local UDP mode.")
    parser.add_argument("--mcast-group", default="239.10.10.10", help="Multicast group.")
    parser.add_argument("--mcast-port", type=int, default=2003, help="Multicast UDP port.")
    parser.add_argument(
        "--mcast-iface-ip",
        default="0.0.0.0",
        help="Interface IPv4 used for UDP multicast join (0.0.0.0 means kernel chooses).",
    )
    parser.add_argument(
        "--mcast-source",
        choices=("auto", "udp", "egress-packet"),
        default="auto",
        help=(
            "Multicast side source: auto (prefer egress-packet, fallback udp), "
            "udp (join group), or egress-packet (capture on egress iface)."
        ),
    )
    parser.add_argument(
        "--local-udp-timestamp-source",
        choices=("kernel", "userspace"),
        default="kernel",
        help=(
            "Timestamp source when --local-source=udp. "
            "kernel uses SO_TIMESTAMPNS; userspace uses time.time_ns() after recv."
        ),
    )
    parser.add_argument(
        "--mcast-udp-timestamp-source",
        choices=("kernel", "userspace"),
        default="kernel",
        help=(
            "Timestamp source when multicast side runs in udp mode. "
            "kernel uses SO_TIMESTAMPNS; userspace uses time.time_ns() after recv."
        ),
    )
    parser.add_argument(
        "--mcast-egress-iface",
        default="enp5s0f1",
        help="Interface used when --mcast-source=egress-packet.",
    )
    parser.add_argument("--samples", type=int, default=20000, help="Target matched samples.")
    parser.add_argument("--timeout-sec", type=float, default=60.0, help="Total measurement timeout.")
    parser.add_argument(
        "--digest-size",
        type=int,
        default=8,
        help="blake2b digest size in bytes used to match packets (1..64).",
    )
    parser.add_argument(
        "--match-key",
        choices=("flow-payload", "payload"),
        default="flow-payload",
        help=(
            "Packet pairing key. flow-payload uses src_ip/src_port/udp_len+payload hash "
            "(best for mixed traffic, including UDP socket mode). payload uses payload hash only "
            "(useful when flow fields differ by design)."
        ),
    )
    parser.add_argument(
        "--payload-prefix-hex",
        default="",
        help=(
            "Optional payload prefix filter as hex (no 0x), applied on both local/mcast sides "
            "before matching. Example: bb420069."
        ),
    )
    parser.add_argument(
        "--max-unmatched-age-ms",
        type=float,
        default=2000.0,
        help="Drop unmatched packet keys older than this age; 0 disables expiry.",
    )
    parser.add_argument(
        "--progress-interval-sec",
        type=float,
        default=1.0,
        help="Progress print interval.",
    )
    args = parser.parse_args()

    if not (1 <= args.local_port <= 65535):
        parser.error("--local-port must be in [1, 65535]")
    if not (0 <= args.local_flow_port <= 65535):
        parser.error("--local-flow-port must be in [0, 65535]")
    if not (1 <= args.mcast_port <= 65535):
        parser.error("--mcast-port must be in [1, 65535]")
    if args.samples <= 0:
        parser.error("--samples must be > 0")
    if args.timeout_sec <= 0:
        parser.error("--timeout-sec must be > 0")
    if not (1 <= args.digest_size <= 64):
        parser.error("--digest-size must be in [1, 64]")
    if args.max_unmatched_age_ms < 0:
        parser.error("--max-unmatched-age-ms must be >= 0")
    if args.progress_interval_sec <= 0:
        parser.error("--progress-interval-sec must be > 0")
    try:
        payload_prefix = bytes.fromhex(args.payload_prefix_hex)
    except ValueError as exc:
        parser.error(f"--payload-prefix-hex must be valid hex: {exc}")

    return Config(
        local_source=args.local_source,
        local_port=args.local_port,
        local_ingress_iface=args.local_ingress_iface,
        local_flow_port=args.local_flow_port,
        local_flow_direction=args.local_flow_direction,
        bind_ip=args.bind_ip,
        mcast_group=args.mcast_group,
        mcast_port=args.mcast_port,
        mcast_iface_ip=args.mcast_iface_ip,
        mcast_source=args.mcast_source,
        local_udp_timestamp_source=args.local_udp_timestamp_source,
        mcast_udp_timestamp_source=args.mcast_udp_timestamp_source,
        mcast_egress_iface=args.mcast_egress_iface,
        samples=args.samples,
        timeout_sec=args.timeout_sec,
        digest_size=args.digest_size,
        match_key=args.match_key,
        payload_prefix=payload_prefix,
        max_unmatched_age_sec=args.max_unmatched_age_ms / 1000.0,
        progress_interval_sec=args.progress_interval_sec,
    )


def make_udp_socket(bind_ip: str, port: int, use_kernel_timestamp: bool) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_RCVBUF_BYTES)
    if use_kernel_timestamp:
        sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
    sock.bind((bind_ip, port))
    sock.setblocking(False)
    return sock


def make_multicast_udp_socket(cfg: Config) -> socket.socket:
    sock = make_udp_socket(
        "0.0.0.0",
        cfg.mcast_port,
        use_kernel_timestamp=(cfg.mcast_udp_timestamp_source == "kernel"),
    )
    membership = struct.pack(
        "4s4s",
        socket.inet_aton(cfg.mcast_group),
        socket.inet_aton(cfg.mcast_iface_ip),
    )
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
    return sock


def make_packet_socket(iface: str) -> socket.socket:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_RCVBUF_BYTES)
    sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
    sock.bind((iface, 0))
    sock.setblocking(False)
    return sock


def recv_with_kernel_timestamp(sock: socket.socket) -> tuple[bytes, int, object]:
    data, ancdata, _flags, addr = sock.recvmsg(65535, 256)
    timestamp_ns: int | None = None
    for level, msg_type, cmsg_data in ancdata:
        if level != socket.SOL_SOCKET or msg_type != SO_TIMESTAMPNS:
            continue
        if len(cmsg_data) >= 16:
            sec, nsec = struct.unpack("qq", cmsg_data[:16])
            timestamp_ns = sec * 1_000_000_000 + nsec
            break
    if timestamp_ns is None:
        timestamp_ns = time.time_ns()
    return data, timestamp_ns, addr


def recv_with_timestamp(sock: socket.socket, timestamp_source: str) -> tuple[bytes, int, object]:
    if timestamp_source == "userspace":
        data, addr = sock.recvfrom(65535)
        return data, time.time_ns(), addr
    return recv_with_kernel_timestamp(sock)


def packet_pkttype(addr: object) -> int | None:
    if isinstance(addr, tuple) and len(addr) >= 3 and isinstance(addr[2], int):
        return addr[2]
    return None


def udp_addr_to_flow(addr: object) -> tuple[int, int] | None:
    if not isinstance(addr, tuple) or len(addr) < 2:
        return None
    ip_text = addr[0]
    src_port = addr[1]
    if not isinstance(ip_text, str) or not isinstance(src_port, int):
        return None
    try:
        src_ip_be = int.from_bytes(socket.inet_aton(ip_text), byteorder="big", signed=False)
    except OSError:
        return None
    return src_ip_be, src_port


def extract_udp_payload(
    frame: bytes,
    expect_dst_ip_be: bytes | None,
    expect_port: int | None,
    port_match_either_direction: bool,
) -> tuple[bytes, int, int, int] | None:
    if len(frame) < 1:
        return None

    offset = 0
    first_nibble = frame[0] >> 4
    if first_nibble != 4:
        if len(frame) < 14:
            return None
        ether_type = int.from_bytes(frame[12:14], byteorder="big", signed=False)
        offset = 14
        while ether_type in (ETH_P_8021Q, ETH_P_8021AD):
            if len(frame) < offset + 4:
                return None
            ether_type = int.from_bytes(frame[offset + 2 : offset + 4], byteorder="big", signed=False)
            offset += 4
        if ether_type != ETH_P_IP:
            return None

    if len(frame) < offset + 20:
        return None

    version_ihl = frame[offset]
    version = version_ihl >> 4
    if version != 4:
        return None

    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20:
        return None
    if len(frame) < offset + ihl + 8:
        return None

    if frame[offset + 9] != IPPROTO_UDP:
        return None

    dst_ip = frame[offset + 16 : offset + 20]
    if expect_dst_ip_be is not None and dst_ip != expect_dst_ip_be:
        return None

    udp_offset = offset + ihl
    src_port = int.from_bytes(frame[udp_offset : udp_offset + 2], byteorder="big", signed=False)
    dst_port = int.from_bytes(frame[udp_offset + 2 : udp_offset + 4], byteorder="big", signed=False)

    if expect_port is not None:
        if port_match_either_direction:
            if src_port != expect_port and dst_port != expect_port:
                return None
        elif dst_port != expect_port:
            return None

    udp_len = int.from_bytes(frame[udp_offset + 4 : udp_offset + 6], byteorder="big", signed=False)
    if udp_len < 8:
        return None

    payload_offset = udp_offset + 8
    payload_end = min(len(frame), udp_offset + udp_len)
    if payload_offset > payload_end:
        return None
    payload = frame[payload_offset:payload_end]
    src_ip_be = int.from_bytes(frame[offset + 12 : offset + 16], byteorder="big", signed=False)
    return payload, src_ip_be, src_port, udp_len


def percentile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    index = int((len(sorted_values) - 1) * q)
    return sorted_values[index]


def choose_local_socket(cfg: Config) -> tuple[socket.socket, str]:
    if cfg.local_source == "udp":
        return make_udp_socket(
            cfg.bind_ip,
            cfg.local_port,
            use_kernel_timestamp=(cfg.local_udp_timestamp_source == "kernel"),
        ), "udp"
    return make_packet_socket(cfg.local_ingress_iface), "ingress-packet"


def choose_mcast_socket(cfg: Config) -> tuple[socket.socket, str]:
    if cfg.mcast_source == "udp":
        return make_multicast_udp_socket(cfg), "udp"
    if cfg.mcast_source == "egress-packet":
        return make_packet_socket(cfg.mcast_egress_iface), "egress-packet"
    try:
        return make_packet_socket(cfg.mcast_egress_iface), "egress-packet"
    except OSError as exc:
        print(
            f"[warn] egress-packet mode unavailable ({exc}); falling back to udp multicast join",
            file=sys.stderr,
        )
    return make_multicast_udp_socket(cfg), "udp"


def main() -> int:
    cfg = parse_args()
    mcast_dst_ip_be = socket.inet_aton(cfg.mcast_group)

    try:
        local_sock, local_mode = choose_local_socket(cfg)
    except OSError as exc:
        print(f"local socket setup failed: {exc}", file=sys.stderr)
        if cfg.local_source == "ingress-packet":
            print("hint: run with sudo for --local-source ingress-packet", file=sys.stderr)
        return 2

    try:
        mcast_sock, mcast_mode = choose_mcast_socket(cfg)
    except OSError as exc:
        print(f"multicast socket setup failed: {exc}", file=sys.stderr)
        if cfg.mcast_source == "egress-packet":
            print("hint: run with sudo for --mcast-source egress-packet", file=sys.stderr)
        return 2

    print(
        "config:"
        f" local_mode={local_mode}"
        f" local_udp_ts={cfg.local_udp_timestamp_source if local_mode == 'udp' else 'n/a'}"
        f" local_port={cfg.local_port if local_mode == 'udp' else 'n/a'}"
        f" local_ingress_iface={cfg.local_ingress_iface}"
        f" local_flow_port={cfg.local_flow_port}"
        f" local_flow_direction={cfg.local_flow_direction}"
        f" mcast_mode={mcast_mode}"
        f" mcast_udp_ts={cfg.mcast_udp_timestamp_source if mcast_mode == 'udp' else 'n/a'}"
        f" mcast={cfg.mcast_group}:{cfg.mcast_port}"
        f" mcast_egress_iface={cfg.mcast_egress_iface}"
        f" bind_ip={cfg.bind_ip}"
        f" mcast_iface_ip={cfg.mcast_iface_ip}"
        f" samples={cfg.samples}"
        f" timeout_sec={cfg.timeout_sec}"
        f" digest_size={cfg.digest_size}"
        f" match_key={cfg.match_key}"
        f" payload_prefix_len={len(cfg.payload_prefix)}"
        f" max_unmatched_age_sec={cfg.max_unmatched_age_sec:.3f}",
        flush=True,
    )

    selector = selectors.DefaultSelector()
    selector.register(local_sock, selectors.EVENT_READ, "local")
    selector.register(mcast_sock, selectors.EVENT_READ, "mcast")
    side_timestamp_source = {
        "local": cfg.local_udp_timestamp_source if local_mode == "udp" else "kernel",
        "mcast": cfg.mcast_udp_timestamp_source if mcast_mode == "udp" else "kernel",
    }

    pending_local: dict[bytes, deque[int]] = defaultdict(deque)
    pending_mcast: dict[bytes, deque[int]] = defaultdict(deque)
    deltas_us: list[float] = []

    local_packets = 0
    mcast_packets = 0
    matched_packets = 0
    dropped_unmatched = 0

    max_age_ns: int | None = None
    if cfg.max_unmatched_age_sec > 0.0:
        max_age_ns = int(cfg.max_unmatched_age_sec * 1_000_000_000)
    deadline_ns = time.time_ns() + int(cfg.timeout_sec * 1_000_000_000)
    next_progress_ns = time.time_ns() + int(cfg.progress_interval_sec * 1_000_000_000)

    interrupted = False
    try:
        while len(deltas_us) < cfg.samples and time.time_ns() < deadline_ns:
            timeout = max(0.0, (deadline_ns - time.time_ns()) / 1_000_000_000)
            timeout = min(timeout, cfg.progress_interval_sec)
            events = selector.select(timeout=timeout)

            for key, _ in events:
                raw_data, ts_ns, addr = recv_with_timestamp(
                    key.fileobj,
                    side_timestamp_source[key.data],
                )

                payload: bytes | None = None
                src_ip_be = 0
                src_port = 0
                udp_len = 0
                if key.data == "local":
                    if local_mode == "udp":
                        payload = raw_data
                        udp_len = len(raw_data) + 8
                        flow = udp_addr_to_flow(addr)
                        if flow is not None:
                            src_ip_be, src_port = flow
                    else:
                        pkttype = packet_pkttype(addr)
                        if cfg.local_ingress_iface != "lo" and pkttype == PACKET_OUTGOING:
                            continue
                        flow_port = cfg.local_flow_port if cfg.local_flow_port != 0 else None
                        parsed = extract_udp_payload(
                            raw_data,
                            expect_dst_ip_be=None,
                            expect_port=flow_port,
                            port_match_either_direction=(cfg.local_flow_direction == "either"),
                        )
                        if parsed is None:
                            continue
                        payload, src_ip_be, src_port, udp_len = parsed
                else:
                    if mcast_mode == "udp":
                        payload = raw_data
                        udp_len = len(raw_data) + 8
                        flow = udp_addr_to_flow(addr)
                        if flow is not None:
                            src_ip_be, src_port = flow
                    else:
                        pkttype = packet_pkttype(addr)
                        if pkttype is not None and pkttype != PACKET_OUTGOING:
                            continue
                        parsed = extract_udp_payload(
                            raw_data,
                            expect_dst_ip_be=mcast_dst_ip_be,
                            expect_port=cfg.mcast_port,
                            port_match_either_direction=False,
                        )
                        if parsed is None:
                            continue
                        payload, src_ip_be, src_port, udp_len = parsed

                if cfg.payload_prefix and not payload.startswith(cfg.payload_prefix):
                    continue

                payload_hash = hashlib.blake2b(payload, digest_size=cfg.digest_size).digest()
                if cfg.match_key == "payload":
                    packet_hash = payload_hash
                else:
                    packet_hash = struct.pack("!IHH", src_ip_be, src_port, udp_len) + payload_hash

                if key.data == "local":
                    local_packets += 1
                    peer_queue = pending_mcast[packet_hash]
                    if peer_queue:
                        m_ts = peer_queue.popleft()
                        deltas_us.append((m_ts - ts_ns) / 1_000.0)
                        matched_packets += 1
                        if not peer_queue:
                            del pending_mcast[packet_hash]
                    else:
                        pending_local[packet_hash].append(ts_ns)
                else:
                    mcast_packets += 1
                    peer_queue = pending_local[packet_hash]
                    if peer_queue:
                        l_ts = peer_queue.popleft()
                        deltas_us.append((ts_ns - l_ts) / 1_000.0)
                        matched_packets += 1
                        if not peer_queue:
                            del pending_local[packet_hash]
                    else:
                        pending_mcast[packet_hash].append(ts_ns)

            now_ns = time.time_ns()
            if max_age_ns is not None:
                cutoff_ns = now_ns - max_age_ns
                for side in (pending_local, pending_mcast):
                    stale_keys: list[bytes] = []
                    for key_hash, queue in side.items():
                        while queue and queue[0] < cutoff_ns:
                            queue.popleft()
                            dropped_unmatched += 1
                        if not queue:
                            stale_keys.append(key_hash)
                    for key_hash in stale_keys:
                        del side[key_hash]

            if now_ns >= next_progress_ns:
                print(
                    "progress:"
                    f" matched={matched_packets}/{cfg.samples}"
                    f" local_rx={local_packets}"
                    f" mcast_rx={mcast_packets}"
                    f" pending_local={sum(len(q) for q in pending_local.values())}"
                    f" pending_mcast={sum(len(q) for q in pending_mcast.values())}"
                    f" dropped_unmatched={dropped_unmatched}",
                    flush=True,
                )
                next_progress_ns = now_ns + int(cfg.progress_interval_sec * 1_000_000_000)
    except KeyboardInterrupt:
        interrupted = True
        print("interrupted by user", file=sys.stderr)

    if not deltas_us:
        print("no matched packets; check ports/rules and traffic presence", file=sys.stderr)
        if local_packets == 0 and mcast_packets > 0:
            print(
                "hint: local side saw zero packets while multicast side is active. "
                "Pick the correct local interface/flow port, or use --local-flow-port 0.",
                file=sys.stderr,
            )
        if local_mode == "udp":
            print(
                "hint: local udp mode only sees packets delivered to local socket. "
                "For wire-level compare use --local-source ingress-packet.",
                file=sys.stderr,
            )
        if mcast_mode == "udp":
            print(
                "hint: multicast udp mode only sees packets delivered to local stack. "
                "For tc egress compare use --mcast-source egress-packet (sudo).",
                file=sys.stderr,
            )
        return 130 if interrupted else 1

    deltas_us.sort()
    mean_us = sum(deltas_us) / len(deltas_us)
    print(f"matched={len(deltas_us)} local_rx={local_packets} mcast_rx={mcast_packets}")
    print(
        "latency_us:"
        f" min={deltas_us[0]:.2f}"
        f" p50={percentile(deltas_us, 0.50):.2f}"
        f" p90={percentile(deltas_us, 0.90):.2f}"
        f" p99={percentile(deltas_us, 0.99):.2f}"
        f" p999={percentile(deltas_us, 0.999):.2f}"
        f" max={deltas_us[-1]:.2f}"
        f" mean={mean_us:.2f}"
    )
    print(
        "note: delta is (multicast_ts - local_ts), so positive means multicast arrived later "
        "than local path."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
