# NIC-level Benchmark

This benchmark measures real interface-level throughput and forwarding loss on the XDP path.

It uses:

- kernel `pktgen` as UDP traffic generator
- `blackbird_xdp_ctl` + XDP stats map counters
- `/sys/class/net/<iface>/statistics/*` interface counters

## Topology

Recommended dual-host setup:

- Host A (generator): `pktgen` sends UDP to DUT ingress.
- Host B (DUT): runs Blackbird XDP forward (`in_iface -> out_iface`).
- Optional Host C (sink): subscribes to multicast to validate end delivery.

```
Host A (pktgen)  --->  DUT in_iface [XDP rewrite+redirect] DUT out_iface  --->  switch/sink
```

## Prerequisites

- root privileges
- built `blackbird_xdp_ctl`
- `modprobe` and kernel `pktgen` support on generator host
- physical connectivity and correct destination MAC toward DUT ingress

## 1) Run generator (Host A)

```bash
sudo ./benches/nic/run_nic_bench.sh generator \
  --iface enp1s0f0 \
  --dst-mac 3c:fd:fe:aa:bb:cc \
  --dst-ip 10.10.10.2 \
  --dst-port 2003 \
  --src-ip 10.10.10.1 \
  --src-port 12000 \
  --pkt-size 1400 \
  --threads 4 \
  --burst 64 \
  --duration 20
```

Use `--count 0` (default) for continuous stream during the measurement window.

## 2) Measure DUT forwarding (Host B)

```bash
sudo ./benches/nic/run_nic_bench.sh dut \
  --xdp-ctl ./build/xdp/blackbird_xdp_ctl \
  --in-iface enp5s0f0 \
  --out-iface enp5s0f1 \
  --match-ip 10.10.10.2 \
  --match-port 2003 \
  --group-ip 239.10.10.10 \
  --group-port 2003 \
  --ttl 1 \
  --collect-stats 1 \
  --duration 20
```

If you want the script to attach XDP first, add:

```bash
--attach-obj ./build/xdp/blackbird_xdp_kern.o
```

## Output fields

- `ingress_rx_mpps`, `ingress_rx_gbps`: measured ingress rate at DUT NIC
- `xdp_redirect_mpps`: packets redirected by XDP rule
- `egress_tx_mpps`, `egress_tx_gbps`: measured egress transmit rate at DUT NIC
- `estimated_redirect_to_egress_loss_pct`: rough loss estimate from XDP redirect vs egress tx deltas

## Notes

- Run generator and DUT measurement over the same time window.
- Keep test interfaces dedicated during measurement; background traffic skews deltas.
- This harness is for throughput/loss at NIC level, not precise one-way latency.
