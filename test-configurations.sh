#!/bin/bash
# Comprehensive test script for iridium-sniffer
# Tests all configurations: CPU scalar, CPU AVX2, GPU, --parsed mode
#
# Usage: ./test-configurations.sh <iq_file>
#
# The test file can be any supported format (cf32/ci16/ci8).
# Format is auto-detected from file extension, or specify with FORMAT env var.

set -e

# Configuration
SAMPLE_RATE=${SAMPLE_RATE:-10000000}
CENTER_FREQ=${CENTER_FREQ:-1622000000}
FORMAT=${FORMAT:-}

# Check arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 <iq_file>"
    echo ""
    echo "Environment variables:"
    echo "  SAMPLE_RATE   Sample rate in Hz (default: 10000000)"
    echo "  CENTER_FREQ   Center frequency in Hz (default: 1622000000)"
    echo "  FORMAT        IQ format: cf32/ci16/ci8 (default: auto-detect from extension)"
    exit 1
fi

IQ_FILE="$1"
if [ ! -f "$IQ_FILE" ]; then
    echo "Error: File not found: $IQ_FILE"
    exit 1
fi

FILESIZE=$(du -h "$IQ_FILE" | cut -f1)

# Auto-detect format from extension if not specified
if [ -z "$FORMAT" ]; then
    case "${IQ_FILE##*.}" in
        cf32|fc32|cfile) FORMAT=cf32 ;;
        ci16|cs16|sc16)  FORMAT=ci16 ;;
        ci8|cs8|sc8)     FORMAT=ci8 ;;
        *)
            echo "Warning: Cannot detect format from extension '${IQ_FILE##*.}'"
            echo "Defaulting to ci8. Set FORMAT env var to override."
            FORMAT=ci8
            ;;
    esac
fi

echo "=========================================="
echo "iridium-sniffer Configuration Test Suite"
echo "=========================================="
echo "Test file: $IQ_FILE ($FILESIZE)"
echo "Format: $FORMAT"
echo "Sample rate: $SAMPLE_RATE Hz"
echo "Center freq: $CENTER_FREQ Hz"
echo ""

# Create output directory
OUTDIR="test-results-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"
echo "Results will be saved to: $OUTDIR/"
echo ""

# Find the binary
SNIFFER=""
if [ -f "./iridium-sniffer" ]; then
    SNIFFER="./iridium-sniffer"
elif [ -f "../build/iridium-sniffer" ]; then
    SNIFFER="../build/iridium-sniffer"
elif command -v iridium-sniffer >/dev/null 2>&1; then
    SNIFFER="iridium-sniffer"
fi

if [ -z "$SNIFFER" ]; then
    echo "Error: iridium-sniffer binary not found"
    echo "Run from the build/ directory, project root, or ensure it is in PATH"
    exit 1
fi
echo "Binary: $SNIFFER"

# Detect build configuration
HAS_GPU=0
if strings "$SNIFFER" | grep -q "GPU acceleration\|OpenCL GPU\|VkFFT" 2>/dev/null; then
    HAS_GPU=1
    echo "GPU support: detected"
else
    echo "GPU support: not available in this build"
fi

HAS_AVX2=0
if grep -q avx2 /proc/cpuinfo 2>/dev/null; then
    HAS_AVX2=1
    echo "AVX2 support: detected in CPU"
else
    echo "AVX2 support: not available"
fi

HAS_PARSER=0
if command -v python3 >/dev/null 2>&1; then
    for dir in /usr/src/iridium-toolkit /opt/iridium-toolkit "$HOME/iridium-toolkit"; do
        if [ -f "$dir/iridium-parser.py" ]; then
            PARSER="$dir/iridium-parser.py"
            HAS_PARSER=1
            echo "External parser: $PARSER"
            break
        fi
    done
fi
[ $HAS_PARSER -eq 0 ] && echo "External parser: not found (skipping comparison)"
echo ""

# Format argument (auto-detection handles this, but be explicit for clarity)
FMT_ARG="--format=$FORMAT"

# Test function
run_test() {
    local name="$1"
    local args="$2"
    local outfile="$OUTDIR/${name}_out.txt"
    local errfile="$OUTDIR/${name}_err.txt"

    echo "========================================"
    echo "Test: $name"
    echo "Args: $FMT_ARG -r $SAMPLE_RATE -c $CENTER_FREQ $args"
    echo "----------------------------------------"

    # Run and capture wall/cpu time via bash built-in
    local start_time=$SECONDS
    "$SNIFFER" \
        -f "$IQ_FILE" $FMT_ARG \
        -r "$SAMPLE_RATE" -c "$CENTER_FREQ" \
        $args \
        >"$outfile" 2>"$errfile"
    local elapsed=$(( SECONDS - start_time ))

    local total=$(wc -l < "$outfile")
    local raw_count=$(grep -c "^RAW:" "$outfile" 2>/dev/null || echo 0)
    local ida_count=$(grep -c "^IDA:" "$outfile" 2>/dev/null || echo 0)
    local bursts=$(grep "tagged" "$errfile" 2>/dev/null | grep -o '[0-9]* bursts' | awk '{print $1}')
    local ok_line=$(grep "ok_avg:" "$errfile" | tail -1)
    local ok_pct=$(echo "$ok_line" | grep -o 'ok_avg: *[0-9]*%' | grep -o '[0-9]*')

    echo "  Output:    $total lines ($raw_count RAW, $ida_count IDA)"
    echo "  Detected:  ${bursts:-?} bursts"
    echo "  Ok rate:   ${ok_pct:-?}%"
    echo "  Wall time: ${elapsed}s"

    # Content hash (strip timestamps for cross-run comparison)
    awk '{$1=$2=$3=""; print}' "$outfile" | sort | md5sum | cut -d' ' -f1 > "$OUTDIR/${name}.md5"
    echo "  MD5:       $(cat "$OUTDIR/${name}.md5")"
    echo ""
}

# Run tests
echo "Starting tests..."
echo ""

# Test 1: Default (AVX2 + GPU if available)
run_test "default" ""

# Test 2: No GPU
if [ $HAS_GPU -eq 1 ]; then
    run_test "no-gpu" "--no-gpu"
fi

# Test 3: No SIMD
if [ $HAS_AVX2 -eq 1 ]; then
    run_test "no-simd" "--no-simd"
fi

# Test 4: No SIMD, No GPU (pure baseline)
if [ $HAS_AVX2 -eq 1 ] && [ $HAS_GPU -eq 1 ]; then
    run_test "baseline" "--no-simd --no-gpu"
fi

# Test 5: --parsed mode (IDA decode with Chase + Gardner)
run_test "parsed" "--parsed"

# External parser comparison
if [ $HAS_PARSER -eq 1 ]; then
    echo "========================================"
    echo "External iridium-parser.py comparison"
    echo "----------------------------------------"

    python3 "$PARSER" < "$OUTDIR/default_out.txt" > "$OUTDIR/ext_parsed.txt" 2>/dev/null

    echo "  Frame types from external parser:"
    cut -d: -f1 "$OUTDIR/ext_parsed.txt" | sort | uniq -c | sort -rn | \
        while read count type; do
            printf "    %-6s %5d\n" "$type" "$count"
        done

    ext_ida=$(grep -c "^IDA:" "$OUTDIR/ext_parsed.txt" 2>/dev/null || echo 0)
    int_ida=$(grep -c "^IDA:" "$OUTDIR/parsed_out.txt" 2>/dev/null || echo 0)
    echo ""
    echo "  IDA comparison:"
    echo "    Built-in --parsed (Chase+Gardner): $int_ida"
    echo "    External iridium-parser.py:        $ext_ida"
    if [ "$ext_ida" -gt 0 ] 2>/dev/null; then
        improvement=$(( (int_ida - ext_ida) * 100 / ext_ida ))
        echo "    Improvement: +${improvement}%"
    fi
    echo ""
fi

# Comparison summary
echo "========================================"
echo "Summary"
echo "========================================"
echo ""
printf "%-12s %6s %6s %6s %6s %s\n" "Config" "Lines" "RAW" "IDA" "Ok%" "MD5"
printf "%-12s %6s %6s %6s %6s %s\n" "------" "-----" "---" "---" "---" "---"

for f in "$OUTDIR"/*.md5; do
    name=$(basename "$f" .md5)
    outfile="$OUTDIR/${name}_out.txt"
    errfile="$OUTDIR/${name}_err.txt"
    [ -f "$outfile" ] || continue

    total=$(wc -l < "$outfile")
    raw_c=$(grep -c "^RAW:" "$outfile" 2>/dev/null || echo 0)
    ida_c=$(grep -c "^IDA:" "$outfile" 2>/dev/null || echo 0)
    ok_pct=$(grep "ok_avg:" "$errfile" 2>/dev/null | tail -1 | grep -o 'ok_avg: *[0-9]*%' | grep -o '[0-9]*')
    md5=$(cat "$f")
    printf "%-12s %6d %6d %6d %5s%% %.12s\n" "$name" "$total" "$raw_c" "$ida_c" "${ok_pct:-?}" "$md5"
done
echo ""

# Output integrity check
echo "Output integrity:"
MD5_LIST=$(cat "$OUTDIR"/*.md5 | sort -u)
MD5_COUNT=$(echo "$MD5_LIST" | wc -l)
if [ "$MD5_COUNT" -eq 1 ]; then
    echo "  All outputs are bit-identical (after stripping timestamps)"
elif [ "$MD5_COUNT" -eq 2 ]; then
    echo "  Two output groups detected (expected: GPU vs CPU FFT rounding)"
    echo "  GPU-on and GPU-off may differ by a few frames in burst detection"
else
    echo "  Warning: $MD5_COUNT distinct outputs detected"
fi
echo ""

echo "========================================"
echo "Test suite complete!"
echo "Results saved to: $OUTDIR/"
echo "========================================"
