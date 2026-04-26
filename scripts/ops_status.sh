#!/usr/bin/env bash

set -u -o pipefail

auto_usage() {
    cat <<'EOF'
Usage:
  ops_status.sh [--in-iface IFACE] [--dz-iface IFACE] [--out-iface IFACE] [--tc-ctl PATH] [--interval SEC]

Defaults:
  --in-iface  enp5s0f0
  --dz-iface  doublezero0
  --out-iface enp5s0f1
  --tc-ctl    ./build/tc/blackbird_tc_ctl (resolved from repo root)
  --interval  1

Notes:
  - Run with sudo if you want tc BPF stats.
  - Prints one line per interval with deltas and rates.
EOF
}

read_counter() {
    local iface="$1"
    local key="$2"
    local path="/sys/class/net/${iface}/statistics/${key}"
    if [[ -r "${path}" ]]; then
        cat "${path}"
        return
    fi
    printf '0\n'
}

read_link_snapshot() {
    local iface="$1"
    local rx_pkts
    local rx_bytes
    local tx_pkts
    local tx_bytes
    rx_pkts="$(read_counter "${iface}" rx_packets)"
    rx_bytes="$(read_counter "${iface}" rx_bytes)"
    tx_pkts="$(read_counter "${iface}" tx_packets)"
    tx_bytes="$(read_counter "${iface}" tx_bytes)"
    printf '%s %s %s %s\n' "${rx_pkts}" "${rx_bytes}" "${tx_pkts}" "${tx_bytes}"
}

parse_tc_field() {
    local line="$1"
    local field="$2"
    local value
    value="$(printf '%s\n' "${line}" | sed -n "s/.*${field}=\\([^ ]*\\).*/\\1/p")"
    if [[ -z "${value}" ]]; then
        printf '0\n'
        return
    fi
    printf '%s\n' "${value}"
}

read_tc_snapshot() {
    local tc_ctl="$1"
    local iface="$2"
    local line
    line="$("${tc_ctl}" stats "${iface}" 2>/dev/null | tail -n1)"
    if [[ -z "${line}" ]]; then
        printf 'na 0 0 0\n'
        return
    fi
    local action
    local matched
    local redirect
    local drop
    action="$(parse_tc_field "${line}" action)"
    matched="$(parse_tc_field "${line}" matched_pkts)"
    redirect="$(parse_tc_field "${line}" redirect)"
    drop="$(parse_tc_field "${line}" drop)"
    if [[ "${action}" == "0" ]]; then
        action="na"
    fi
    printf '%s %s %s %s\n' "${action}" "${matched}" "${redirect}" "${drop}"
}

delta_u64() {
    local now="$1"
    local prev="$2"
    if (( now >= prev )); then
        printf '%s\n' "$((now - prev))"
        return
    fi
    printf '0\n'
}

fmt_mpps() {
    local delta_packets="$1"
    local interval="$2"
    awk -v d="${delta_packets}" -v i="${interval}" 'BEGIN { printf "%.3f", (d / i) / 1000000.0 }'
}

fmt_gbps() {
    local delta_bytes="$1"
    local interval="$2"
    awk -v d="${delta_bytes}" -v i="${interval}" 'BEGIN { printf "%.3f", ((d * 8.0) / i) / 1000000000.0 }'
}

main() {
    local script_dir
    local repo_root
    script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
    repo_root="$(cd -- "${script_dir}/.." && pwd)"

    local in_iface="enp5s0f0"
    local dz_iface="doublezero0"
    local out_iface="enp5s0f1"
    local tc_ctl="${repo_root}/build/tc/blackbird_tc_ctl"
    local interval="1"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --in-iface)
                in_iface="$2"
                shift 2
                ;;
            --dz-iface)
                dz_iface="$2"
                shift 2
                ;;
            --out-iface)
                out_iface="$2"
                shift 2
                ;;
            --tc-ctl)
                tc_ctl="$2"
                shift 2
                ;;
            --interval)
                interval="$2"
                shift 2
                ;;
            -h|--help)
                auto_usage
                return 0
                ;;
            *)
                printf 'unknown argument: %s\n' "$1" >&2
                auto_usage
                return 2
                ;;
        esac
    done

    if [[ ! -d "/sys/class/net/${in_iface}" ]]; then
        printf 'interface not found: %s\n' "${in_iface}" >&2
        return 2
    fi
    if [[ ! -d "/sys/class/net/${dz_iface}" ]]; then
        printf 'interface not found: %s\n' "${dz_iface}" >&2
        return 2
    fi
    if [[ ! -d "/sys/class/net/${out_iface}" ]]; then
        printf 'interface not found: %s\n' "${out_iface}" >&2
        return 2
    fi

    if ! [[ "${interval}" =~ ^[0-9]+$ ]] || (( interval <= 0 )); then
        printf 'interval must be a positive integer: %s\n' "${interval}" >&2
        return 2
    fi

    local have_tc_stats="1"
    if [[ ! -x "${tc_ctl}" ]]; then
        have_tc_stats="0"
        printf '[warn] tc ctl not executable: %s (tc stats disabled)\n' "${tc_ctl}" >&2
    elif ! "${tc_ctl}" stats "${in_iface}" >/dev/null 2>&1; then
        have_tc_stats="0"
        printf '[warn] tc stats unavailable (run with sudo?): %s\n' "${tc_ctl}" >&2
    fi

    local prev_in_rx_pkts prev_in_rx_bytes prev_in_tx_pkts prev_in_tx_bytes
    local prev_dz_rx_pkts prev_dz_rx_bytes prev_dz_tx_pkts prev_dz_tx_bytes
    local prev_out_rx_pkts prev_out_rx_bytes prev_out_tx_pkts prev_out_tx_bytes
    read -r prev_in_rx_pkts prev_in_rx_bytes prev_in_tx_pkts prev_in_tx_bytes < <(read_link_snapshot "${in_iface}")
    read -r prev_dz_rx_pkts prev_dz_rx_bytes prev_dz_tx_pkts prev_dz_tx_bytes < <(read_link_snapshot "${dz_iface}")
    read -r prev_out_rx_pkts prev_out_rx_bytes prev_out_tx_pkts prev_out_tx_bytes < <(read_link_snapshot "${out_iface}")

    local prev_in_tc_action="na" prev_in_tc_match="0" prev_in_tc_redirect="0" prev_in_tc_drop="0"
    local prev_dz_tc_action="na" prev_dz_tc_match="0" prev_dz_tc_redirect="0" prev_dz_tc_drop="0"
    if [[ "${have_tc_stats}" == "1" ]]; then
        read -r prev_in_tc_action prev_in_tc_match prev_in_tc_redirect prev_in_tc_drop < <(read_tc_snapshot "${tc_ctl}" "${in_iface}")
        read -r prev_dz_tc_action prev_dz_tc_match prev_dz_tc_redirect prev_dz_tc_drop < <(read_tc_snapshot "${tc_ctl}" "${dz_iface}")
    fi

    printf '# interval=%ss in=%s dz=%s out=%s tc_ctl=%s\n' \
        "${interval}" "${in_iface}" "${dz_iface}" "${out_iface}" "${tc_ctl}"
    printf '# fields: time in_rx_mpps in_rx_gbps dz_rx_mpps dz_rx_gbps out_tx_mpps out_tx_gbps in_tc(match/redir/drop) dz_tc(match/redir/drop)\n'

    while true; do
        sleep "${interval}"

        local in_rx_pkts in_rx_bytes in_tx_pkts in_tx_bytes
        local dz_rx_pkts dz_rx_bytes dz_tx_pkts dz_tx_bytes
        local out_rx_pkts out_rx_bytes out_tx_pkts out_tx_bytes
        read -r in_rx_pkts in_rx_bytes in_tx_pkts in_tx_bytes < <(read_link_snapshot "${in_iface}")
        read -r dz_rx_pkts dz_rx_bytes dz_tx_pkts dz_tx_bytes < <(read_link_snapshot "${dz_iface}")
        read -r out_rx_pkts out_rx_bytes out_tx_pkts out_tx_bytes < <(read_link_snapshot "${out_iface}")

        local d_in_rx_pkts d_in_rx_bytes d_dz_rx_pkts d_dz_rx_bytes d_out_tx_pkts d_out_tx_bytes
        d_in_rx_pkts="$(delta_u64 "${in_rx_pkts}" "${prev_in_rx_pkts}")"
        d_in_rx_bytes="$(delta_u64 "${in_rx_bytes}" "${prev_in_rx_bytes}")"
        d_dz_rx_pkts="$(delta_u64 "${dz_rx_pkts}" "${prev_dz_rx_pkts}")"
        d_dz_rx_bytes="$(delta_u64 "${dz_rx_bytes}" "${prev_dz_rx_bytes}")"
        d_out_tx_pkts="$(delta_u64 "${out_tx_pkts}" "${prev_out_tx_pkts}")"
        d_out_tx_bytes="$(delta_u64 "${out_tx_bytes}" "${prev_out_tx_bytes}")"

        local in_rx_mpps in_rx_gbps dz_rx_mpps dz_rx_gbps out_tx_mpps out_tx_gbps
        in_rx_mpps="$(fmt_mpps "${d_in_rx_pkts}" "${interval}")"
        in_rx_gbps="$(fmt_gbps "${d_in_rx_bytes}" "${interval}")"
        dz_rx_mpps="$(fmt_mpps "${d_dz_rx_pkts}" "${interval}")"
        dz_rx_gbps="$(fmt_gbps "${d_dz_rx_bytes}" "${interval}")"
        out_tx_mpps="$(fmt_mpps "${d_out_tx_pkts}" "${interval}")"
        out_tx_gbps="$(fmt_gbps "${d_out_tx_bytes}" "${interval}")"

        local in_tc_action="na" in_tc_match="0" in_tc_redirect="0" in_tc_drop="0"
        local dz_tc_action="na" dz_tc_match="0" dz_tc_redirect="0" dz_tc_drop="0"
        local d_in_tc_match="0" d_in_tc_redirect="0" d_in_tc_drop="0"
        local d_dz_tc_match="0" d_dz_tc_redirect="0" d_dz_tc_drop="0"

        if [[ "${have_tc_stats}" == "1" ]]; then
            read -r in_tc_action in_tc_match in_tc_redirect in_tc_drop < <(read_tc_snapshot "${tc_ctl}" "${in_iface}")
            read -r dz_tc_action dz_tc_match dz_tc_redirect dz_tc_drop < <(read_tc_snapshot "${tc_ctl}" "${dz_iface}")

            d_in_tc_match="$(delta_u64 "${in_tc_match}" "${prev_in_tc_match}")"
            d_in_tc_redirect="$(delta_u64 "${in_tc_redirect}" "${prev_in_tc_redirect}")"
            d_in_tc_drop="$(delta_u64 "${in_tc_drop}" "${prev_in_tc_drop}")"

            d_dz_tc_match="$(delta_u64 "${dz_tc_match}" "${prev_dz_tc_match}")"
            d_dz_tc_redirect="$(delta_u64 "${dz_tc_redirect}" "${prev_dz_tc_redirect}")"
            d_dz_tc_drop="$(delta_u64 "${dz_tc_drop}" "${prev_dz_tc_drop}")"

            prev_in_tc_action="${in_tc_action}"
            prev_in_tc_match="${in_tc_match}"
            prev_in_tc_redirect="${in_tc_redirect}"
            prev_in_tc_drop="${in_tc_drop}"

            prev_dz_tc_action="${dz_tc_action}"
            prev_dz_tc_match="${dz_tc_match}"
            prev_dz_tc_redirect="${dz_tc_redirect}"
            prev_dz_tc_drop="${dz_tc_drop}"
        fi

        printf '%s in_rx=%sMpps/%sGbps dz_rx=%sMpps/%sGbps out_tx=%sMpps/%sGbps in_tc[%s]=%s/%s/%s dz_tc[%s]=%s/%s/%s\n' \
            "$(date +%H:%M:%S)" \
            "${in_rx_mpps}" "${in_rx_gbps}" \
            "${dz_rx_mpps}" "${dz_rx_gbps}" \
            "${out_tx_mpps}" "${out_tx_gbps}" \
            "${in_tc_action}" "${d_in_tc_match}" "${d_in_tc_redirect}" "${d_in_tc_drop}" \
            "${dz_tc_action}" "${d_dz_tc_match}" "${d_dz_tc_redirect}" "${d_dz_tc_drop}"

        prev_in_rx_pkts="${in_rx_pkts}"
        prev_in_rx_bytes="${in_rx_bytes}"
        prev_in_tx_pkts="${in_tx_pkts}"
        prev_in_tx_bytes="${in_tx_bytes}"
        prev_dz_rx_pkts="${dz_rx_pkts}"
        prev_dz_rx_bytes="${dz_rx_bytes}"
        prev_dz_tx_pkts="${dz_tx_pkts}"
        prev_dz_tx_bytes="${dz_tx_bytes}"
        prev_out_rx_pkts="${out_rx_pkts}"
        prev_out_rx_bytes="${out_rx_bytes}"
        prev_out_tx_pkts="${out_tx_pkts}"
        prev_out_tx_bytes="${out_tx_bytes}"
    done
}

main "$@"
