#!/usr/bin/env bash
set -euo pipefail

log() {
    printf '[nic-bench] %s\n' "$*"
}

die() {
    printf '[nic-bench][error] %s\n' "$*" >&2
    exit 1
}

need_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "run as root"
    fi
}

need_cmd() {
    local cmd="${1}"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        die "missing command: ${cmd}"
    fi
}

need_iface() {
    local iface="${1}"
    if [[ ! -d "/sys/class/net/${iface}" ]]; then
        die "network interface does not exist: ${iface}"
    fi
}

read_net_counter() {
    local iface="${1}"
    local key="${2}"
    local path="/sys/class/net/${iface}/statistics/${key}"
    if [[ ! -r "${path}" ]]; then
        die "cannot read counter: ${path}"
    fi
    cat "${path}"
}

rate_per_sec() {
    local delta="${1}"
    local seconds="${2}"
    awk -v d="${delta}" -v s="${seconds}" 'BEGIN { if (s <= 0) { print "0.000"; exit } printf "%.3f", d / s }'
}

gbps_from_bytes() {
    local bytes="${1}"
    local seconds="${2}"
    awk -v b="${bytes}" -v s="${seconds}" 'BEGIN { if (s <= 0) { print "0.000"; exit } printf "%.3f", (b * 8.0) / (s * 1000000000.0) }'
}

extract_u64_field() {
    local text="${1}"
    local key="${2}"
    sed -n "s/.*${key}=\\([0-9][0-9]*\\).*/\\1/p" <<<"${text}"
}

xdp_stats_snapshot() {
    local xdp_ctl="${1}"
    local iface="${2}"
    local line
    line="$("${xdp_ctl}" stats "${iface}" 2>&1 | tr '\n' ' ')"

    local matched
    local matched_bytes
    local redirect
    local pass
    local drop

    matched="$(extract_u64_field "${line}" "matched_pkts")"
    matched_bytes="$(extract_u64_field "${line}" "matched_bytes")"
    redirect="$(extract_u64_field "${line}" "redirect")"
    pass="$(extract_u64_field "${line}" "pass")"
    drop="$(extract_u64_field "${line}" "drop")"

    if [[ -z "${matched}" || -z "${matched_bytes}" || -z "${redirect}" || -z "${pass}" || -z "${drop}" ]]; then
        die "failed to parse xdp stats output: ${line}"
    fi

    printf '%s %s %s %s %s\n' "${matched}" "${matched_bytes}" "${redirect}" "${pass}" "${drop}"
}

print_dut_usage() {
    cat <<'EOF'
Usage:
  run_nic_bench.sh dut \
    --in-iface IFACE \
    --out-iface IFACE \
    --match-ip IPV4 \
    --match-port PORT \
    --group-ip IPV4 \
    --group-port PORT \
    [--duration SEC] \
    [--ttl 1..255] \
    [--collect-stats 0|1] \
    [--xdp-ctl PATH] \
    [--attach-obj PATH]
EOF
}

print_generator_usage() {
    cat <<'EOF'
Usage:
  run_nic_bench.sh generator \
    --iface IFACE \
    --dst-mac MAC \
    --dst-ip IPV4 \
    --dst-port PORT \
    [--src-ip IPV4] \
    [--src-port PORT] \
    [--pkt-size BYTES] \
    [--duration SEC] \
    [--count COUNT] \
    [--threads N] \
    [--clone-skb N] \
    [--burst N]
EOF
}

run_dut_mode() {
    local in_iface=""
    local out_iface=""
    local match_ip=""
    local match_port=""
    local group_ip=""
    local group_port=""
    local duration="15"
    local ttl="1"
    local collect_stats="1"
    local xdp_ctl="./build/xdp/blackbird_xdp_ctl"
    local attach_obj=""

    while [[ $# -gt 0 ]]; do
        case "${1}" in
            --in-iface) in_iface="${2}"; shift 2 ;;
            --out-iface) out_iface="${2}"; shift 2 ;;
            --match-ip) match_ip="${2}"; shift 2 ;;
            --match-port) match_port="${2}"; shift 2 ;;
            --group-ip) group_ip="${2}"; shift 2 ;;
            --group-port) group_port="${2}"; shift 2 ;;
            --duration) duration="${2}"; shift 2 ;;
            --ttl) ttl="${2}"; shift 2 ;;
            --collect-stats) collect_stats="${2}"; shift 2 ;;
            --xdp-ctl) xdp_ctl="${2}"; shift 2 ;;
            --attach-obj) attach_obj="${2}"; shift 2 ;;
            -h | --help) print_dut_usage; exit 0 ;;
            *) die "unknown dut arg: ${1}" ;;
        esac
    done

    [[ -n "${in_iface}" ]] || die "--in-iface is required"
    [[ -n "${out_iface}" ]] || die "--out-iface is required"
    [[ -n "${match_ip}" ]] || die "--match-ip is required"
    [[ -n "${match_port}" ]] || die "--match-port is required"
    [[ -n "${group_ip}" ]] || die "--group-ip is required"
    [[ -n "${group_port}" ]] || die "--group-port is required"

    need_root
    need_cmd awk
    need_cmd sed
    need_iface "${in_iface}"
    need_iface "${out_iface}"
    [[ -x "${xdp_ctl}" ]] || die "xdp control binary is not executable: ${xdp_ctl}"

    if [[ -n "${attach_obj}" ]]; then
        [[ -r "${attach_obj}" ]] || die "xdp object not readable: ${attach_obj}"
        log "attaching XDP program to ${in_iface}"
        "${xdp_ctl}" attach "${in_iface}" "${attach_obj}"
    fi

    log "configuring XDP send rule on ${in_iface} -> ${out_iface}"
    "${xdp_ctl}" configure-send \
        "${in_iface}" "${out_iface}" \
        "${match_ip}" "${match_port}" \
        "${group_ip}" "${group_port}" \
        auto auto "${ttl}" "${collect_stats}"

    log "clearing XDP counters"
    "${xdp_ctl}" clear-stats "${in_iface}"

    local in_rx_packets_0
    local in_rx_bytes_0
    local in_rx_dropped_0
    local out_tx_packets_0
    local out_tx_bytes_0
    local out_tx_dropped_0
    in_rx_packets_0="$(read_net_counter "${in_iface}" "rx_packets")"
    in_rx_bytes_0="$(read_net_counter "${in_iface}" "rx_bytes")"
    in_rx_dropped_0="$(read_net_counter "${in_iface}" "rx_dropped")"
    out_tx_packets_0="$(read_net_counter "${out_iface}" "tx_packets")"
    out_tx_bytes_0="$(read_net_counter "${out_iface}" "tx_bytes")"
    out_tx_dropped_0="$(read_net_counter "${out_iface}" "tx_dropped")"

    local matched_0
    local matched_bytes_0
    local redirect_0
    local pass_0
    local drop_0
    read -r matched_0 matched_bytes_0 redirect_0 pass_0 drop_0 < <(xdp_stats_snapshot "${xdp_ctl}" "${in_iface}")

    log "measuring for ${duration}s"
    sleep "${duration}"

    local in_rx_packets_1
    local in_rx_bytes_1
    local in_rx_dropped_1
    local out_tx_packets_1
    local out_tx_bytes_1
    local out_tx_dropped_1
    in_rx_packets_1="$(read_net_counter "${in_iface}" "rx_packets")"
    in_rx_bytes_1="$(read_net_counter "${in_iface}" "rx_bytes")"
    in_rx_dropped_1="$(read_net_counter "${in_iface}" "rx_dropped")"
    out_tx_packets_1="$(read_net_counter "${out_iface}" "tx_packets")"
    out_tx_bytes_1="$(read_net_counter "${out_iface}" "tx_bytes")"
    out_tx_dropped_1="$(read_net_counter "${out_iface}" "tx_dropped")"

    local matched_1
    local matched_bytes_1
    local redirect_1
    local pass_1
    local drop_1
    read -r matched_1 matched_bytes_1 redirect_1 pass_1 drop_1 < <(xdp_stats_snapshot "${xdp_ctl}" "${in_iface}")

    local in_rx_packets_delta=$((in_rx_packets_1 - in_rx_packets_0))
    local in_rx_bytes_delta=$((in_rx_bytes_1 - in_rx_bytes_0))
    local in_rx_dropped_delta=$((in_rx_dropped_1 - in_rx_dropped_0))
    local out_tx_packets_delta=$((out_tx_packets_1 - out_tx_packets_0))
    local out_tx_bytes_delta=$((out_tx_bytes_1 - out_tx_bytes_0))
    local out_tx_dropped_delta=$((out_tx_dropped_1 - out_tx_dropped_0))

    local matched_delta=$((matched_1 - matched_0))
    local matched_bytes_delta=$((matched_bytes_1 - matched_bytes_0))
    local redirect_delta=$((redirect_1 - redirect_0))
    local pass_delta=$((pass_1 - pass_0))
    local drop_delta=$((drop_1 - drop_0))

    local in_rx_mpps
    local in_rx_gbps
    local out_tx_mpps
    local out_tx_gbps
    local redir_mpps
    local redir_gbps
    in_rx_mpps="$(awk -v p="$(rate_per_sec "${in_rx_packets_delta}" "${duration}")" 'BEGIN { printf "%.3f", p / 1000000.0 }')"
    in_rx_gbps="$(gbps_from_bytes "${in_rx_bytes_delta}" "${duration}")"
    out_tx_mpps="$(awk -v p="$(rate_per_sec "${out_tx_packets_delta}" "${duration}")" 'BEGIN { printf "%.3f", p / 1000000.0 }')"
    out_tx_gbps="$(gbps_from_bytes "${out_tx_bytes_delta}" "${duration}")"
    redir_mpps="$(awk -v p="$(rate_per_sec "${redirect_delta}" "${duration}")" 'BEGIN { printf "%.3f", p / 1000000.0 }')"
    redir_gbps="$(gbps_from_bytes "${matched_bytes_delta}" "${duration}")"

    local estimated_loss_pct="0.000000"
    if [[ "${redirect_delta}" -gt 0 ]]; then
        estimated_loss_pct="$(awk -v red="${redirect_delta}" -v tx="${out_tx_packets_delta}" '
            BEGIN {
                d = red - tx;
                if (d < 0) d = 0;
                printf "%.6f", (d * 100.0) / red;
            }
        ')"
    fi

    cat <<EOF
mode=dut
duration_s=${duration}
in_iface=${in_iface}
out_iface=${out_iface}
match=${match_ip}:${match_port}
rewrite_group=${group_ip}:${group_port}
collect_stats=${collect_stats}
ingress_rx_packets_delta=${in_rx_packets_delta}
ingress_rx_mpps=${in_rx_mpps}
ingress_rx_gbps=${in_rx_gbps}
ingress_rx_dropped_delta=${in_rx_dropped_delta}
xdp_matched_packets_delta=${matched_delta}
xdp_matched_bytes_delta=${matched_bytes_delta}
xdp_redirect_packets_delta=${redirect_delta}
xdp_redirect_mpps=${redir_mpps}
xdp_redirect_gbps_estimate=${redir_gbps}
xdp_pass_packets_delta=${pass_delta}
xdp_drop_packets_delta=${drop_delta}
egress_tx_packets_delta=${out_tx_packets_delta}
egress_tx_mpps=${out_tx_mpps}
egress_tx_gbps=${out_tx_gbps}
egress_tx_dropped_delta=${out_tx_dropped_delta}
estimated_redirect_to_egress_loss_pct=${estimated_loss_pct}
EOF
}

pgset() {
    local target="${1}"
    local cmd="${2}"
    printf '%s\n' "${cmd}" >"${target}"
}

stop_pktgen_safe() {
    if [[ -w /proc/net/pktgen/pgctrl ]]; then
        printf '%s\n' "stop" >/proc/net/pktgen/pgctrl || true
    fi
}

run_generator_mode() {
    local iface=""
    local dst_mac=""
    local dst_ip=""
    local dst_port=""
    local src_ip="198.18.0.10"
    local src_port="12000"
    local pkt_size="1400"
    local duration="15"
    local count="0"
    local threads="1"
    local clone_skb="0"
    local burst="64"

    while [[ $# -gt 0 ]]; do
        case "${1}" in
            --iface) iface="${2}"; shift 2 ;;
            --dst-mac) dst_mac="${2}"; shift 2 ;;
            --dst-ip) dst_ip="${2}"; shift 2 ;;
            --dst-port) dst_port="${2}"; shift 2 ;;
            --src-ip) src_ip="${2}"; shift 2 ;;
            --src-port) src_port="${2}"; shift 2 ;;
            --pkt-size) pkt_size="${2}"; shift 2 ;;
            --duration) duration="${2}"; shift 2 ;;
            --count) count="${2}"; shift 2 ;;
            --threads) threads="${2}"; shift 2 ;;
            --clone-skb) clone_skb="${2}"; shift 2 ;;
            --burst) burst="${2}"; shift 2 ;;
            -h | --help) print_generator_usage; exit 0 ;;
            *) die "unknown generator arg: ${1}" ;;
        esac
    done

    [[ -n "${iface}" ]] || die "--iface is required"
    [[ -n "${dst_mac}" ]] || die "--dst-mac is required"
    [[ -n "${dst_ip}" ]] || die "--dst-ip is required"
    [[ -n "${dst_port}" ]] || die "--dst-port is required"

    need_root
    need_cmd modprobe
    need_cmd awk
    need_iface "${iface}"

    modprobe pktgen
    [[ -d /proc/net/pktgen ]] || die "/proc/net/pktgen is unavailable"

    trap stop_pktgen_safe EXIT INT TERM

    local tx_packets_0
    local tx_bytes_0
    local tx_dropped_0
    tx_packets_0="$(read_net_counter "${iface}" "tx_packets")"
    tx_bytes_0="$(read_net_counter "${iface}" "tx_bytes")"
    tx_dropped_0="$(read_net_counter "${iface}" "tx_dropped")"

    pgset /proc/net/pktgen/pgctrl "stop"
    for ((t = 0; t < threads; ++t)); do
        local ctrl="/proc/net/pktgen/kpktgend_${t}"
        [[ -w "${ctrl}" ]] || die "pktgen thread file not writable: ${ctrl}"
        pgset "${ctrl}" "rem_device_all"
        pgset "${ctrl}" "add_device ${iface}@${t}"
    done

    for ((t = 0; t < threads; ++t)); do
        local dev="/proc/net/pktgen/${iface}@${t}"
        [[ -w "${dev}" ]] || die "pktgen device file not writable: ${dev}"
        pgset "${dev}" "count ${count}"
        pgset "${dev}" "clone_skb ${clone_skb}"
        pgset "${dev}" "pkt_size ${pkt_size}"
        pgset "${dev}" "delay 0"
        pgset "${dev}" "burst ${burst}"
        pgset "${dev}" "flag QUEUE_MAP_CPU"
        pgset "${dev}" "queue_map_min ${t}"
        pgset "${dev}" "queue_map_max ${t}"
        pgset "${dev}" "src_min ${src_ip}"
        pgset "${dev}" "src_max ${src_ip}"
        pgset "${dev}" "dst_min ${dst_ip}"
        pgset "${dev}" "dst_max ${dst_ip}"
        pgset "${dev}" "udp_src_min ${src_port}"
        pgset "${dev}" "udp_src_max ${src_port}"
        pgset "${dev}" "udp_dst_min ${dst_port}"
        pgset "${dev}" "udp_dst_max ${dst_port}"
        pgset "${dev}" "dst_mac ${dst_mac}"
    done

    log "starting pktgen on ${iface} with ${threads} thread(s)"
    pgset /proc/net/pktgen/pgctrl "start"
    sleep "${duration}"
    pgset /proc/net/pktgen/pgctrl "stop"
    trap - EXIT INT TERM

    local tx_packets_1
    local tx_bytes_1
    local tx_dropped_1
    tx_packets_1="$(read_net_counter "${iface}" "tx_packets")"
    tx_bytes_1="$(read_net_counter "${iface}" "tx_bytes")"
    tx_dropped_1="$(read_net_counter "${iface}" "tx_dropped")"

    local tx_packets_delta=$((tx_packets_1 - tx_packets_0))
    local tx_bytes_delta=$((tx_bytes_1 - tx_bytes_0))
    local tx_dropped_delta=$((tx_dropped_1 - tx_dropped_0))
    local tx_mpps
    local tx_gbps
    tx_mpps="$(awk -v p="$(rate_per_sec "${tx_packets_delta}" "${duration}")" 'BEGIN { printf "%.3f", p / 1000000.0 }')"
    tx_gbps="$(gbps_from_bytes "${tx_bytes_delta}" "${duration}")"

    cat <<EOF
mode=generator
duration_s=${duration}
iface=${iface}
dst=${dst_ip}:${dst_port}
threads=${threads}
pkt_size=${pkt_size}
clone_skb=${clone_skb}
burst=${burst}
tx_packets_delta=${tx_packets_delta}
tx_mpps=${tx_mpps}
tx_gbps=${tx_gbps}
tx_dropped_delta=${tx_dropped_delta}
EOF

    for ((t = 0; t < threads; ++t)); do
        local dev="/proc/net/pktgen/${iface}@${t}"
        log "pktgen result ${iface}@${t}:"
        grep -E "Result:|Current:[[:space:]]+|errors:" "${dev}" || true
    done
}

main() {
    if [[ $# -lt 1 ]]; then
        die "expected mode: dut|generator"
    fi

    local mode="${1}"
    shift
    case "${mode}" in
        dut) run_dut_mode "$@" ;;
        generator) run_generator_mode "$@" ;;
        -h | --help)
            print_dut_usage
            print_generator_usage
            ;;
        *) die "unknown mode: ${mode}" ;;
    esac
}

main "$@"
