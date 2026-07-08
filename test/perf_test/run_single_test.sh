#!/usr/bin/env bash
# run_single_test.sh — Run one config and output a CSV row.
#
# Usage:
#   bash scripts/run_single_test.sh [WORKERS] [QUEUE_SIZE] [PCAP_PATH] [RUNS]
#
# Defaults:
#   WORKERS=2, QUEUE_SIZE=4096, PCAP_PATH=$DISCOVERY_PCAP or ./pcaps/sample.pcap
#   RUNS=1 (set >1 to average over multiple runs)
#
# Output: CSV line to stdout, log to stderr.
#   columns: workers,queue_size,pcap_file,run,packets_read,packets_processed,
#            observations_applied,internal_dropped,elapsed_ms,pps_in,pps_proc,
#            drop_pct

set -euo pipefail

# ── Args ──────────────────────────────────────────────────────────────────────
WORKERS="${1:-2}"
QUEUE_SIZE="${2:-4096}"
PCAP_PATH="${3:-${DISCOVERY_PCAP:-./pcaps/sample.pcap}}"
NUM_RUNS="${4:-1}"
BIN="./discovery"
LOG_DIR="/tmp/perf_logs"
TMP_OUTPUT=$(mktemp -d /tmp/perf_output.XXXXXX)
CSV_HEADER="workers,queue_size,pcap_file,run,packets_read,packets_processed,observations_applied,internal_dropped,elapsed_ms,pps_in,pps_proc,drop_pct"

# Cleanup temp dirs on exit
cleanup() { rm -rf "$TMP_OUTPUT"; }
trap cleanup EXIT

mkdir -p "$LOG_DIR"
PCAP_BASENAME="$(basename "$PCAP_PATH" .pcap)"

# ── Functions ─────────────────────────────────────────────────────────────────
run_once() {
    local run_num="$1"
    local log_file="${LOG_DIR}/${PCAP_BASENAME}_w${WORKERS}_q${QUEUE_SIZE}_run${run_num}.log"
    local out_dir="${TMP_OUTPUT}/run${run_num}"
    mkdir -p "$out_dir"

    # Drop page cache before cold run (skip if not root — needs CAP_SYS_ADMIN)
    if [[ -w /proc/sys/vm/drop_caches ]]; then
        echo 3 > /proc/sys/vm/drop_caches
    fi

    # Run discovery in new session so SIGINT doesn't escape to caller
    setsid "$BIN" \
        --pcap "$PCAP_PATH" \
        --workers "$WORKERS" \
        --queue-size "$QUEUE_SIZE" \
        --output "$out_dir" \
        --db "" \
        --log-level debug \
        --log-output "$log_file" \
        </dev/null 2>/dev/null &
    local pid=$!

    # Wait for pipeline_done marker (poll every 0.5s, timeout 240s for large PCAPs)
    local waited=0
    while [[ $waited -lt 240 ]]; do
        sleep 0.5
        waited=$((waited + 1))
        if grep -q 'pipeline_done' "$log_file" 2>/dev/null; then
            sleep 0.3  # give log flush time
            break
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            break
        fi
    done

    # Kill discovery (setsid isolates signal from shell)
    kill -INT "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true

    echo "$log_file"
}

parse_marker() {
    local log_file="$1"

    PACKETS_READ=$(grep 'pipeline_done' "$log_file" | grep -oP 'packets_read=\K\d+'   || echo "0")
    PACKETS_PROC=$(grep 'pipeline_done' "$log_file" | grep -oP 'packets_processed=\K\d+' || echo "0")
    OBS_APPLIED=$(grep 'pipeline_done' "$log_file" | grep -oP 'observations_applied=\K\d+' || echo "0")
    DROPPED=$(grep 'pipeline_done' "$log_file" | grep -oP 'internal_dropped=\K\d+' || echo "0")
    ELAPSED_MS=$(grep 'pipeline_done' "$log_file" | grep -oP 'elapsed_ms=\K\d+'     || echo "0")

    if [[ "$ELAPSED_MS" -eq 0 ]]; then
        echo "WARNING: pipeline_done marker not found in $log_file" >&2
        PACKETS_READ=0; PACKETS_PROC=0; OBS_APPLIED=0; DROPPED=0; ELAPSED_MS=0
    fi
}

calc_pps() {
    # $1 = count, $2 = elapsed_ms
    awk "BEGIN { if ($2 > 0) printf \"%.1f\", $1 / ($2 / 1000); else print 0 }"
}

calc_drop_pct() {
    awk "BEGIN { if ($1 > 0) printf \"%.4f\", $2 / $1 * 100; else print 0 }"
}

# ── CSV header ────────────────────────────────────────────────────────────────
echo "$CSV_HEADER"

# ── Main loop ─────────────────────────────────────────────────────────────────
for (( run=1; run<=NUM_RUNS; run++ )); do
    LOG=$(run_once "$run")
    parse_marker "$LOG"

    PPS_IN=$(calc_pps "$PACKETS_READ" "$ELAPSED_MS")
    PPS_PROC=$(calc_pps "$PACKETS_PROC" "$ELAPSED_MS")
    DROP_PCT=$(calc_drop_pct "$PACKETS_READ" "$DROPPED")

    echo "${WORKERS},${QUEUE_SIZE},${PCAP_BASENAME},${run},${PACKETS_READ},${PACKETS_PROC},${OBS_APPLIED},${DROPPED},${ELAPSED_MS},${PPS_IN},${PPS_PROC},${DROP_PCT}"
done
