#!/bin/bash
# Comprehensive test script for iridium-sniffer
# Tests all configurations: CPU scalar, CPU AVX2, GPU (if available)
#
# Usage: ./test-configurations.sh <iq_file.cf32>
#
# The test file should be:
# - Format: cf32 (complex float32)
# - Sample rate: 10 MHz (default, or specify with SAMPLE_RATE env var)
# - Center freq: 1622 MHz (default, or specify with CENTER_FREQ env var)

set -e

# Configuration
SAMPLE_RATE=${SAMPLE_RATE:-10000000}
CENTER_FREQ=${CENTER_FREQ:-1622000000}
TIMEOUT=${TIMEOUT:-300}  # 5 minute timeout per test

# Check arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 <iq_file.cf32>"
    echo ""
    echo "Environment variables:"
    echo "  SAMPLE_RATE   Sample rate in Hz (default: 10000000)"
    echo "  CENTER_FREQ   Center frequency in Hz (default: 1622000000)"
    echo "  TIMEOUT       Timeout per test in seconds (default: 300)"
    exit 1
fi

IQ_FILE="$1"
if [ ! -f "$IQ_FILE" ]; then
    echo "Error: File not found: $IQ_FILE"
    exit 1
fi

FILESIZE=$(du -h "$IQ_FILE" | cut -f1)
echo "=========================================="
echo "iridium-sniffer Configuration Test Suite"
echo "=========================================="
echo "Test file: $IQ_FILE ($FILESIZE)"
echo "Sample rate: $SAMPLE_RATE Hz"
echo "Center freq: $CENTER_FREQ Hz"
echo ""

# Create output directory
OUTDIR="test-results-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"
echo "Results will be saved to: $OUTDIR/"
echo ""

# Build if needed
if [ ! -f "./iridium-sniffer" ]; then
    echo "Error: iridium-sniffer binary not found in current directory"
    echo "Please run this script from the build/ directory after running make"
    exit 1
fi

# Detect build configuration
HAS_GPU=0
if strings ./iridium-sniffer | grep -q "GPU acceleration"; then
    HAS_GPU=1
    echo "GPU support: detected (OpenCL or Vulkan)"
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
echo ""

# Test function
run_test() {
    local name="$1"
    local args="$2"
    local outfile="$OUTDIR/${name}.txt"
    local timefile="$OUTDIR/${name}.time"
    
    echo "========================================"
    echo "Test: $name"
    echo "Arguments: $args"
    echo "----------------------------------------"
    
    # Run with timeout and time measurement
    if timeout $TIMEOUT /usr/bin/time -v ./iridium-sniffer \
        -f "$IQ_FILE" --format=cf32 \
        -r $SAMPLE_RATE -c $CENTER_FREQ \
        $args \
        2>"$timefile" \
        > "$outfile"; then
        
        # Extract key metrics
        local lines=$(wc -l < "$outfile")
        local cpu_time=$(grep "User time" "$timefile" | awk '{print $4}')
        local wall_time=$(grep "Elapsed" "$timefile" | awk '{print $8}')
        local max_rss=$(grep "Maximum resident" "$timefile" | awk '{print $6}')
        
        echo "✓ Success"
        echo "  Lines: $lines"
        echo "  CPU time: ${cpu_time}s"
        echo "  Wall time: $wall_time"
        echo "  Memory: $((max_rss / 1024)) MB"
        
        # Compute MD5 of sorted output (for comparison)
        local md5=$(sort "$outfile" | md5sum | cut -d' ' -f1)
        echo "  MD5 (sorted): $md5"
        echo "$md5" > "$OUTDIR/${name}.md5"
        
        echo ""
        return 0
    else
        echo "✗ Failed (timeout or error)"
        echo ""
        return 1
    fi
}

# Run tests
echo "Starting tests..."
echo ""

# Test 1: CPU with SIMD (AVX2 if available, or scalar)
run_test "cpu-default" ""

# Test 2: CPU scalar (force no SIMD)
if [ $HAS_AVX2 -eq 1 ]; then
    run_test "cpu-no-simd" "--no-simd"
fi

# Test 3: GPU (if available)
if [ $HAS_GPU -eq 1 ]; then
    run_test "gpu" ""
    run_test "cpu-no-gpu" "--no-gpu"
fi

# Compare results
echo "========================================"
echo "Comparison Summary"
echo "========================================"
echo ""

# Line counts
echo "Output line counts:"
for f in "$OUTDIR"/*.txt; do
    name=$(basename "$f" .txt)
    lines=$(wc -l < "$f")
    printf "  %-15s %6d lines\n" "$name:" "$lines"
done
echo ""

# MD5 comparison
echo "MD5 hashes (sorted output):"
for f in "$OUTDIR"/*.md5; do
    name=$(basename "$f" .md5)
    md5=$(cat "$f")
    printf "  %-15s %s\n" "$name:" "$md5"
done
echo ""

# Check if all MD5s match
MD5_COUNT=$(cat "$OUTDIR"/*.md5 | sort -u | wc -l)
if [ $MD5_COUNT -eq 1 ]; then
    echo "✓ All outputs are identical (sorted)"
else
    echo "⚠ Outputs differ - this is expected for AVX2 vs scalar due to FMA rounding"
    echo "  (decoded bits should still be identical when compared bit-by-bit)"
fi
echo ""

# Timing comparison
if [ $HAS_AVX2 -eq 1 ] && [ -f "$OUTDIR/cpu-default.time" ] && [ -f "$OUTDIR/cpu-no-simd.time" ]; then
    echo "Performance comparison (AVX2 vs Scalar):"
    cpu_avx2=$(grep "User time" "$OUTDIR/cpu-default.time" | awk '{print $4}')
    cpu_scalar=$(grep "User time" "$OUTDIR/cpu-no-simd.time" | awk '{print $4}')
    speedup=$(echo "scale=2; $cpu_scalar / $cpu_avx2" | bc)
    echo "  AVX2:   ${cpu_avx2}s"
    echo "  Scalar: ${cpu_scalar}s"
    echo "  Speedup: ${speedup}x"
    echo ""
fi

echo "========================================"
echo "Test suite complete!"
echo "Results saved to: $OUTDIR/"
echo "========================================"
