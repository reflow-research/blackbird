# blackbird

XDP-first multicast tooling in C++23.

`send` is always XDP. `recv` can run in XDP mode (`configure-recv`) or optional socket fallback (`client/`).

## Project layout

- `common/`: shared helpers in namespace `blackbird::common`
- `xdp/`: XDP kernel program + `blackbird_xdp_ctl`
- `tc/`: TC ingress kernel program + `blackbird_tc_ctl`
- `client/`: optional socket multicast receiver fallback (`BLACKBIRD_BUILD_SOCKET_RECEIVER`)

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Performance/build options:

- `-DBLACKBIRD_ENABLE_LTO=ON` (default)
- `-DBLACKBIRD_ENABLE_NATIVE_ARCH=ON` (default)
- `-DBLACKBIRD_BUILD_SOCKET_RECEIVER=OFF` (default; optional non-XDP receiver fallback)
- `-DBLACKBIRD_ENABLE_SPDLOG=OFF` (default)
- `-DBLACKBIRD_WARNINGS_AS_ERRORS=OFF` (default)

`blackbird_xdp_kern.o` build requires `clang` with BPF target support.

## XDP Send (always XDP)

Attach:

```bash
sudo ./build/xdp/blackbird_xdp_ctl attach enp5s0f0 ./build/xdp/blackbird_xdp_kern.o
```

Configure send forwarding (`ingress UDP` -> `multicast rewrite` -> `redirect out_iface`):

```bash
sudo ./build/xdp/blackbird_xdp_ctl configure-send \
  enp5s0f0 enp5s0f1 \
  10.10.10.2 2003 \
  239.10.10.10 2003 \
  auto auto 1
```

## XDP Recv (default receive mode)

Configure receive classification on NIC:

```bash
sudo ./build/xdp/blackbird_xdp_ctl configure-recv enp5s0f1 239.10.10.10 2003 pass
```

- `pass`: keep packets going to network stack (usable with socket subscriber)
- `drop`: consume matching packets in XDP

Stats:

```bash
sudo ./build/xdp/blackbird_xdp_ctl stats enp5s0f1
sudo ./build/xdp/blackbird_xdp_ctl clear-stats enp5s0f1
```

Disable XDP rule or detach:

```bash
sudo ./build/xdp/blackbird_xdp_ctl disable enp5s0f1
sudo ./build/xdp/blackbird_xdp_ctl detach enp5s0f1
```

## Optional socket fallback receiver

If needed:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBLACKBIRD_BUILD_SOCKET_RECEIVER=ON
cmake --build build -j
./build/client/blackbird_client 239.10.10.10 2003 0.0.0.0 64 0
```

## Benchmarks

Microbenchmarks (checksum/MAC rewrite primitives):

```bash
./build/xdp/bench/blackbird_xdp_bench --benchmark_counters_tabular=true
```

Pipeline benchmarks (header rewrite path + userspace fanout cost model):

```bash
./build/xdp/bench/blackbird_xdp_pipeline_bench --benchmark_counters_tabular=true
```

Notes:

- These are synthetic CPU benchmarks, not NIC line-rate measurements.
- `redirect_pipeline_*` models header-only rewrite cost.
- `userspace_unicast_fanout` models why per-client rewrite/send loops scale worse than one multicast send.

NIC-level throughput/loss benchmark harness:

```bash
./benches/nic/run_nic_bench.sh --help
```

See [benches/nic/README.md](benches/nic/README.md) for dual-host setup and examples.

## TC ingress forwarder (for interfaces you cannot run Blackbird XDP on)

Use `tc` when ingress is already owned by another XDP program (for example, validator on `enp5s0f0`) or when ingress is a tunnel device (`doublezero0`).
Use `configure-send` for redirect mode (packet consumed by redirect), or `configure-mirror` for clone mode (packet is copied to egress and original continues in local stack/NAT).

### Single-source example (`doublezero0 -> 239.10.10.10:2003`)

Attach tc program on ingress:

```bash
sudo ./build/tc/blackbird_tc_ctl attach doublezero0 ./build/tc/blackbird_tc_kern.o
```

Mirror only UDP destination port `42069` to multicast while preserving local delivery:

```bash
sudo ./build/tc/blackbird_tc_ctl configure-mirror \
  doublezero0 enp5s0f1 \
  any 42069 \
  239.10.10.10 2003 \
  1 1
```

Show counters:

```bash
sudo ./build/tc/blackbird_tc_ctl stats doublezero0
```

### Dual-source merge example (`enp5s0f0 + doublezero0 -> same multicast`)

1. Attach tc program on both ingress interfaces.

```bash
sudo ./build/tc/blackbird_tc_ctl attach enp5s0f0 ./build/tc/blackbird_tc_kern.o
sudo ./build/tc/blackbird_tc_ctl attach doublezero0 ./build/tc/blackbird_tc_kern.o
```

2. Configure both sources to the same outbound multicast stream.

Use redirect mode on `enp5s0f0` and mirror mode on `doublezero0` when you need `doublezero0` packets to continue to local services/NAT.

```bash
sudo ./build/tc/blackbird_tc_ctl configure-send \
  enp5s0f0 enp5s0f1 \
  any 0 \
  239.10.10.10 2003 \
  1 1

sudo ./build/tc/blackbird_tc_ctl configure-mirror \
  doublezero0 enp5s0f1 \
  any 7733 \
  239.10.10.10 2003 \
  1 1
```

3. Monitor both paths.

```bash
watch -n1 'sudo ./build/tc/blackbird_tc_ctl stats enp5s0f0; sudo ./build/tc/blackbird_tc_ctl stats doublezero0'
```

4. Verify multicast egress on the send interface.

```bash
ip -s link show dev enp5s0f1 | sed -n '1,8p'
```

5. Optional: start a local subscriber for sanity checks.

```bash
./build/client/blackbird_client 239.10.10.10 2003 0.0.0.0 64 0
```

### Disable / detach

Disable forwarding rule but keep tc attached:

```bash
sudo ./build/tc/blackbird_tc_ctl disable enp5s0f0
sudo ./build/tc/blackbird_tc_ctl disable doublezero0
```

Remove tc filter/qdisc from interfaces:

```bash
sudo ./build/tc/blackbird_tc_ctl detach enp5s0f0
sudo ./build/tc/blackbird_tc_ctl detach doublezero0
```

## Operator Runbook (copy/paste)

This runbook forwards mixed UDP from `enp5s0f0` and only UDP `7733` from `doublezero0` into one multicast stream on `enp5s0f1`.

Note: current tc config supports one active match rule per ingress interface.

Build binaries:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Attach tc ingress program on both input interfaces:

```bash
sudo ./build/tc/blackbird_tc_ctl attach enp5s0f0 ./build/tc/blackbird_tc_kern.o
sudo ./build/tc/blackbird_tc_ctl attach doublezero0 ./build/tc/blackbird_tc_kern.o
```

Configure `enp5s0f0` to rewrite all UDP traffic to multicast `239.10.10.10:2003` and redirect out `enp5s0f1`:

```bash
sudo ./build/tc/blackbird_tc_ctl configure-send \
  enp5s0f0 enp5s0f1 \
  any 0 \
  239.10.10.10 2003 \
  1 1
```

Configure `doublezero0` in mirror mode so only port `7733` is cloned to multicast and original packets still hit your local NAT/`:8000` path:

```bash
sudo ./build/tc/blackbird_tc_ctl configure-mirror \
  doublezero0 enp5s0f1 \
  any 7733 \
  239.10.10.10 2003 \
  1 1
```

Reset counters before measurement:

```bash
sudo ./build/tc/blackbird_tc_ctl clear-stats enp5s0f0
sudo ./build/tc/blackbird_tc_ctl clear-stats doublezero0
```

Monitor forwarding counters on both ingress interfaces:

```bash
watch -n1 'sudo ./build/tc/blackbird_tc_ctl stats enp5s0f0; sudo ./build/tc/blackbird_tc_ctl stats doublezero0'
```

Monitor one-line per-second deltas (all RX/TX plus tc match/redirect/drop):

```bash
sudo ./scripts/ops_status.sh \
  --in-iface enp5s0f0 \
  --dz-iface doublezero0 \
  --out-iface enp5s0f1 \
  --interval 1
```

Measure added latency from ingress flow to multicast egress using kernel timestamps.
This avoids local socket-delivery issues and is the correct mode on sender hosts:

```bash
sudo python3 ./scripts/measure_path_latency.py \
  --local-source ingress-packet \
  --local-ingress-iface doublezero0 \
  --local-flow-port 42069 \
  --mcast-group 239.10.10.10 \
  --mcast-port 2003 \
  --mcast-source egress-packet \
  --mcast-egress-iface enp5s0f1 \
  --match-key flow-payload \
  --samples 20000 \
  --timeout-sec 60
```

For loopback-based tests (`--local-ingress-iface lo`), use `--match-key payload`.

Check egress packet/byte counters on the multicast send interface:

```bash
ip -s link show dev enp5s0f1 | sed -n '1,8p'
```

Sample multicast traffic on egress for sanity:

```bash
sudo tcpdump -ni enp5s0f1 -Q out 'udp and dst 239.10.10.10 and dst port 2003'
```

Client test with a simple multicast subscriber (local or remote host):

```bash
python3 - <<'PY'
import socket
import struct

group = "239.10.10.10"
port = 2003

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("", port))
membership = struct.pack("4s4s", socket.inet_aton(group), socket.inet_aton("0.0.0.0"))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)

for i in range(20):
    data, addr = sock.recvfrom(4096)
    print(f"{i+1:02d} len={len(data)} from={addr[0]}:{addr[1]}")
PY
```

Optional `blackbird_client` test:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBLACKBIRD_BUILD_SOCKET_RECEIVER=ON
cmake --build build -j
./build/client/blackbird_client 239.10.10.10 2003 0.0.0.0 64 0
```

Disable rules without detaching tc:

```bash
sudo ./build/tc/blackbird_tc_ctl disable enp5s0f0
sudo ./build/tc/blackbird_tc_ctl disable doublezero0
```

Fully detach tc from both ingress interfaces:

```bash
sudo ./build/tc/blackbird_tc_ctl detach enp5s0f0
sudo ./build/tc/blackbird_tc_ctl detach doublezero0
```
