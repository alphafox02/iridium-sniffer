# iridium-sniffer

A standalone Iridium satellite burst detector and demodulator written in C. It provides an alternative to [gr-iridium](https://github.com/muccc/gr-iridium) by eliminating the GNU Radio dependency, while producing the same [iridium-toolkit](https://github.com/muccc/iridium-toolkit) compatible RAW output on stdout. For users who want a lighter-weight, dependency-free option or need embedded deployment, this offers similar functionality with a different architectural approach.

Supports HackRF, BladeRF, USRP (UHD), and SoapySDR for live capture, or processes IQ recordings from file. Optional GPU-accelerated burst detection is available via OpenCL (NVIDIA, AMD, Intel). Runs on Raspberry Pi 5 and other ARM boards in CPU-only mode with FFTW wisdom pre-generation.

A built-in web map (`--web`, beta) provides a real-time Leaflet.js visualization of decoded ring alert positions and active satellites -- no external tools or Python required.

Native GSMTAP output (`--gsmtap`) sends decoded IDA (Iridium Data) frames directly to Wireshark via UDP, eliminating the need for the Python `iridium-parser.py -m gsmtap` pipeline.

## Features

- Full Iridium L-band burst detection, downmix, and DQPSK demodulation pipeline
- Direct iridium-toolkit RAW output, compatible with iridium-parser.py and reassembler.py
- Parsed IDA output mode (`--parsed`) for direct reassembler.py piping (ACARS/SBD recovery)
- Chase BCH soft-decision decoding recovers 37% more IDA frames than iridium-parser.py
- Gardner timing recovery (enabled by default) for improved weak burst demodulation
- Native GSMTAP/LAPDm output to Wireshark (`--gsmtap`) for IDA frame analysis
- Built-in web map with live satellite and ring alert visualization
- GPU-accelerated FFT burst detection (OpenCL or Vulkan)
- Multi-threaded architecture: detection, downmix pool, demodulation, stats
- HackRF, BladeRF, USRP, and SoapySDR support
- Reads ci8, ci16, and cf32 IQ files with auto-detection from file extension

## Installation

### DragonOS Noble

DragonOS Noble ships with HackRF, BladeRF, USRP (UHD), SoapySDR, and OpenCL drivers pre-installed. Just clone and build:

```bash
git clone https://github.com/alphafox02/iridium-sniffer.git
cd iridium-sniffer
mkdir build && cd build
cmake ..
make -j$(nproc)
```

CMake auto-detects the available SDR libraries and GPU support. All SDR backends and OpenCL GPU acceleration should be enabled automatically.

### Ubuntu / Debian

```bash
git clone https://github.com/alphafox02/iridium-sniffer.git
cd iridium-sniffer

# Core dependencies
sudo apt install build-essential cmake libfftw3-dev

# SDR libraries (install only what you have)
sudo apt install libhackrf-dev      # HackRF One
sudo apt install libbladerf-dev     # BladeRF
sudo apt install libuhd-dev         # USRP (B2x0, N2x0, X3x0, etc.)
sudo apt install libsoapysdr-dev    # RTL-SDR, Airspy, LimeSDR, etc. via SoapySDR

# Optional: GPU-accelerated burst detection
sudo apt install ocl-icd-opencl-dev  # OpenCL (NVIDIA, AMD, Intel)

mkdir build && cd build
cmake ..
make -j$(nproc)
```

CMake output shows what was detected:

```
-- HackRF: enabled
-- BladeRF: enabled
-- USRP (UHD): enabled
-- SoapySDR: enabled
-- GPU acceleration: OpenCL
```

### Raspberry Pi 5 / ARM

The Pi 5's VideoCore VII GPU passes basic Vulkan compute tests but cannot sustain the throughput needed for real-time FFT batch processing. Build CPU-only and use `--no-gpu`:

```bash
git clone https://github.com/alphafox02/iridium-sniffer.git
cd iridium-sniffer
sudo apt install build-essential cmake libfftw3-dev libsoapysdr-dev

mkdir build && cd build
cmake .. -DUSE_OPENCL=OFF
make -j$(nproc)
```

**FFTW wisdom (important for ARM):** FFTW uses `FFTW_MEASURE` to benchmark FFT algorithms at plan creation time. On x86 this is fast and unnoticeable. On ARM it can block for 30-60+ seconds per plan, causing `q_max` to climb during live capture as samples queue up while plans are being built.

Pre-generate a wisdom file to avoid this. iridium-sniffer automatically loads wisdom from `~/.iridium-sniffer-fftw-wisdom` at startup and saves updated wisdom on shutdown. After the first successful run (or the command below), subsequent starts are immediate.

The required wisdom entries depend on sample rate. The burst detection FFT size varies, while the downmix FFTs are always the same (cof4096 for CFO estimation, cof2048/cob2048 for correlation):

| Sample Rate | Burst FFT | Wisdom Command |
|-------------|-----------|----------------|
| 2-2.4 MHz (RTL-SDR) | 2048 | `fftwf-wisdom -v -o ~/.iridium-sniffer-fftw-wisdom cof2048 cof4096 cob2048` |
| 6 MHz (Airspy Mini) | 8192 | `fftwf-wisdom -v -o ~/.iridium-sniffer-fftw-wisdom cof8192 cof4096 cof2048 cob2048` |
| 10 MHz (default) | 8192 | `fftwf-wisdom -v -o ~/.iridium-sniffer-fftw-wisdom cof8192 cof4096 cof2048 cob2048` |
| 20 MHz (HackRF, USRP) | 16384 | `fftwf-wisdom -v -o ~/.iridium-sniffer-fftw-wisdom cof16384 cof4096 cof2048 cob2048` |

The naming convention: `cof` = complex forward, `cob` = complex backward, followed by the FFT size. If running multiple sample rates on the same system, include all burst FFT sizes in one command (e.g., `cof2048 cof8192 cof4096 cob2048`). The "system-wisdom import failed" warning from `fftwf-wisdom` is normal on a fresh system and can be ignored.

GNU Radio manages FFTW wisdom automatically (in `~/.gr_fftw_wisdom`), which is why gr-iridium users never encounter this issue. Since iridium-sniffer replaces the GNU Radio dependency, it handles wisdom directly.

### Build Variants

```bash
# OpenCL GPU (default when available)
cmake .. -DUSE_OPENCL=ON

# Vulkan GPU
cmake .. -DUSE_VULKAN=ON -DUSE_OPENCL=OFF

# CPU only
cmake .. -DUSE_OPENCL=OFF

# Debug build with AddressSanitizer
cmake .. -DCMAKE_BUILD_TYPE=Debug
```

## Quick Start

```bash
# Live capture (auto-detect SDR)
./iridium-sniffer -l

# Live capture with web map (open http://localhost:8888)
./iridium-sniffer -l --web

# Process an IQ recording
./iridium-sniffer -f recording.cf32

# Pipe to iridium-toolkit
./iridium-sniffer -l | python3 iridium-toolkit/iridium-parser.py

# Direct ACARS/SBD recovery (bypasses iridium-parser.py)
./iridium-sniffer -l --parsed | python3 iridium-toolkit/reassembler.py -m acars

# Send IDA frames to Wireshark
./iridium-sniffer -l --gsmtap
```

## Performance

Tested against gr-iridium on a 60-second IQ recording (cf32, 10 MHz, 1622 MHz center, USRP B210):

**Default threshold (16 dB) -- maximum frame recovery:**

| Metric | iridium-sniffer | gr-iridium |
|--------|-----------------|------------|
| Detected bursts | 5468 | ~3666 |
| Demodulated RAW frames | 3228 | 2713 |
| Ok rate | 60% | 74% |
| IDA frames (internal `--parsed`) | 693 | -- |
| IDA frames (external iridium-parser.py) | 507 | 690 |

The default 16 dB threshold detects more bursts than gr-iridium, including weaker signals at the noise floor. Many of these marginal bursts fail demodulation, which lowers the ok percentage -- but the absolute frame count is 19% higher (3228 vs 2713). This is the recommended setting for maximum data recovery.

**Matched threshold (18 dB) -- apples-to-apples comparison:**

| Metric | iridium-sniffer | gr-iridium |
|--------|-----------------|------------|
| Detected bursts | 3668 | ~3666 |
| Demodulated RAW frames | 2559 | 2713 |
| Ok rate | 70% | 74% |
| IDA frames (internal `--parsed`) | 576 | -- |
| IDA frames (external iridium-parser.py) | 464 | 690 |

At 18 dB (gr-iridium's default), burst detection counts are nearly identical. The ok rate gap narrows to 70% vs 74%. The external parser IDA gap (464 vs 690) reflects that gr-iridium's GNU Radio-based demodulator produces cleaner bits -- more frames survive standard BCH correction. Chase soft-decision decoding in `--parsed` mode compensates for this (576 vs 464), but the demodulator quality gap is the area with the most room for improvement. Use `--threshold=18` if ok rate percentage is more important than total frame count.

**Processing speed (60s cf32 file, i7-11800H):**

| Configuration | Wall time | CPU time | Realtime factor |
|---------------|-----------|----------|-----------------|
| AVX2 + GPU | 15.1s | 23.6s | 4.0x |
| AVX2 only | 12.0s | 21.5s | 5.0x |
| Scalar + GPU | 16.1s | 42.6s | 3.7x |
| Scalar only (baseline) | 13.0s | 40.6s | 4.6x |

The AVX2 SIMD kernels provide a 1.9x CPU time reduction. GPU acceleration adds startup overhead for files this size but becomes beneficial for longer recordings and continuous live capture.

All configurations produce identical demodulated output (frame count, bit content). GPU vs CPU may differ by a few frames due to floating-point rounding in the burst detection FFT.

The IDA decoder uses Chase BCH soft-decision decoding. Standard BCH corrects up to 2 bit errors per 31-bit block. Chase decoding uses LLR (log-likelihood ratio) confidence from the demodulator to identify the least-reliable bit positions, flips them, and retries BCH correction. This recovers frames with 3+ corrupted positions where the errors cluster around low-confidence symbols. Combined with Gardner timing recovery, this yields 37% more IDA frames than `iridium-parser.py` on the same input (693 vs 507 at 16 dB threshold).

## Built-in Web Map (Beta)

The `--web` flag starts an embedded HTTP server that decodes IRA (ring alert) and IBC (broadcast) frames in real time and displays them on a map. This provides similar functionality to [Iridium Live](https://github.com/microp11/iridium-live) without any external dependencies.

**Note:** The web map feature is currently in beta. Position plotting and satellite tracking are functional but undergoing validation.

```bash
# Default port 8888
./iridium-sniffer -l --web

# Custom port
./iridium-sniffer -l --web=9090
```

Then open `http://localhost:8888` in a browser.

The map shows:

- **Ring alert positions** as colored circle markers, with color indicating the originating satellite. Click a marker for details including satellite ID, beam ID, coordinates, altitude, frequency, and TMSI (if a paging block is present).
- **Active satellite count** and IRA/IBC frame totals in a status bar.
- **Auto-centering** on the first received position, then free pan/zoom.

Data updates once per second via Server-Sent Events. The map uses Leaflet.js with OpenStreetMap tiles, loaded from CDN. No files need to be installed or served separately.

**API endpoints:**

| Endpoint | Description |
|----------|-------------|
| `GET /` | HTML map page |
| `GET /api/events` | SSE stream (1 Hz JSON updates) |
| `GET /api/state` | JSON snapshot of current state |

The web map runs alongside normal RAW output. Adding `--web` does not change what appears on stdout, so you can pipe to iridium-toolkit at the same time:

```bash
./iridium-sniffer -l --web | python3 iridium-toolkit/iridium-parser.py
```

## GSMTAP Output (Wireshark Integration)

The `--gsmtap` flag enables native IDA (Iridium Data Access) frame decoding and sends the decoded LAPDm frames to Wireshark via UDP. This replaces the `iridium-parser.py -m gsmtap` Python pipeline for protocol analysis.

```bash
# Start Wireshark listening for GSMTAP
wireshark -k -i lo -f "udp port 4729"

# In another terminal, run with GSMTAP enabled
./iridium-sniffer -l --gsmtap

# Custom destination host and port
./iridium-sniffer -l --gsmtap=192.168.1.100:4729

# Combined with web map
./iridium-sniffer -l --web --gsmtap
```

Wireshark decodes the packets as GSM/LAPDm signaling. Typical messages seen:

- **Immediate Assignment / Reject** -- channel management (most common)
- **Paging Request** -- satellite looking for a handset (contains TMSI)
- **Location Update Reject** -- satellite denying a registration attempt
- **System Information** -- broadcast parameters
- **SBD (Short Burst Data)** payloads

The IDA decoder implements:
- LCW (Link Control Word) extraction via 46-bit permutation table and 3 BCH components
- Payload descrambling: 124-bit block de-interleave, BCH(31,20) with poly=3545
- CRC-CCITT verification
- Multi-burst reassembly (16 concurrent slots, frequency/time/sequence matching)

GSMTAP runs alongside normal RAW output and the web map. Adding `--gsmtap` does not change stdout.

## Parsed IDA Output

The `--parsed` flag enables internal IDA frame decoding with Chase BCH error correction and outputs parsed IDA lines directly to stdout. This was added primarily for recovering ACARS, SBD, and other IDA-based message content without requiring the external Python `iridium-parser.py` pipeline.

```bash
# Direct to reassembler (no iridium-parser.py needed for IDA/ACARS/SBD)
./iridium-sniffer -l --parsed | python3 iridium-toolkit/reassembler.py -m acars

# Traditional pipeline (still works, decodes all frame types)
./iridium-sniffer -l | python3 iridium-toolkit/iridium-parser.py | python3 iridium-toolkit/reassembler.py -m acars
```

**Current capabilities and limitations:**

`--parsed` currently decodes **IDA frames only**. These are the data-carrying frames used for ACARS, SBD messaging, voice call setup, and other payload traffic. IDA is what the reassembler needs for message reconstruction.

Frame types **not yet decoded** by `--parsed` (these pass through as `RAW:` lines):
- IRA (ring alerts) -- satellite position and paging events
- IBC (broadcast channel) -- satellite ID, beam, Iridium time
- VOC/VOZ (voice) -- voice codec frames
- ISY, ITL, IIU, IMS, and other signaling types

For IRA and IBC, the `--web` map feature already decodes these frame types independently using a separate decoder. The `--parsed` limitation only affects stdout text output.

If all frame types are needed on stdout (not just IDA), use the traditional pipeline: `iridium-sniffer | iridium-parser.py`. The internal IDA decoder produces 37% more IDA frames than the external parser thanks to Chase soft-decision BCH decoding, but the external parser handles all frame types.

In parsed mode, decoded IDA frames appear as `IDA:` lines with fields matching `iridium-parser.py` output format. Non-IDA frames continue to appear as `RAW:` lines. The `--parsed` flag adds no measurable overhead.

## Burst IQ Capture

The `--save-bursts` option saves IQ samples from successfully decoded bursts to a directory for offline analysis, algorithm development, or research.

```bash
# Save all decoded bursts
./iridium-sniffer -l --save-bursts bursts/

# Process file and save bursts
./iridium-sniffer -f recording.cf32 --format=cf32 --save-bursts bursts/
```

**Output files per burst:**
- `<timestamp>_<freq>_<id>_<direction>.cf32` - Complex float32 IQ samples (RRC-filtered, aligned to unique word)
- `<timestamp>_<freq>_<id>_<direction>.meta` - Metadata (burst ID, frequency, SNR, sample rate, etc.)

**Use cases:**
- RF fingerprinting and satellite authentication research
- Algorithm development and testing without live satellite passes
- Building datasets for signal processing research
- Debugging demodulation issues on specific bursts
- Regression testing with real satellite data

Captured IQ is at 250 kHz sample rate, 10 samples per symbol, after RRC matched filtering. Each file contains one complete burst ready for demodulation.

## Usage

### File Input

The IQ format is auto-detected from the file extension (`.cf32`/`.fc32`/`.cfile` for cf32, `.ci16`/`.cs16`/`.sc16` for ci16). Files with unrecognized extensions default to ci8. Use `--format` to override.

```bash
# Auto-detected as cf32 from extension
./iridium-sniffer -f recording.cf32

# Auto-detected as ci16
./iridium-sniffer -f recording.cs16

# Explicit format override (e.g., .raw file that is actually cf32)
./iridium-sniffer -f recording.raw --format cf32

# Custom sample rate and center frequency
./iridium-sniffer -f recording.cf32 -r 10000000 -c 1622000000
```

### Live Capture

```bash
# Auto-detect SDR
./iridium-sniffer -l

# Specify interface (use --list to see your serial numbers)
./iridium-sniffer -l -i hackrf-YOUR_SERIAL_HERE
./iridium-sniffer -l -i usrp-B210-YOUR_SERIAL
./iridium-sniffer -l -i bladerf0
./iridium-sniffer -l -i soapy-0

# With gain and bias tee
./iridium-sniffer -l -B --hackrf-lna=40 --hackrf-vga=20
./iridium-sniffer -l --usrp-gain=50
```

### Piping to iridium-toolkit

```bash
# Real-time decode
./iridium-sniffer -l | python3 iridium-toolkit/iridium-parser.py

# Direct to reassembler (parsed mode, bypasses iridium-parser.py)
./iridium-sniffer -l --parsed | python3 iridium-toolkit/reassembler.py -m acars

# File processing with full reassembly (traditional pipeline)
./iridium-sniffer -f recording.cf32 --format cf32 | \
    python3 iridium-toolkit/iridium-parser.py | \
    python3 iridium-toolkit/reassembler.py
```

### List Available SDRs

```bash
./iridium-sniffer --list
```

## Command Reference

```
Usage: iridium-sniffer <-f FILE | -l> [options]

Input (one required):
    -f, --file=FILE         read IQ samples from file
    -l, --live              capture live from SDR
    --format=FMT            IQ file format: ci8 (default), ci16, cf32
                             Auto-detected from file extension when not specified

SDR options:
    -i, --interface=IFACE   SDR to use (hackrf-SERIAL, bladerf0, usrp-PROD-SERIAL, soapy-N)
    -c, --center-freq=HZ    center frequency in Hz (default: 1622000000)
    -r, --sample-rate=HZ    sample rate in Hz (default: 10000000)
    -B, --bias-tee          enable bias tee power

Gain options:
    --hackrf-lna=GAIN       HackRF LNA gain in dB (default: 40)
    --hackrf-vga=GAIN       HackRF VGA gain in dB (default: 20)
    --hackrf-amp            enable HackRF RF amplifier
    --bladerf-gain=GAIN     BladeRF gain in dB (default: 40)
    --usrp-gain=GAIN        USRP gain in dB (default: 40)
    --soapy-gain=GAIN       SoapySDR gain in dB (default: 40)

Detection:
    -d, --threshold=DB      burst detection threshold in dB (default: 16.0)
    --no-gpu                disable GPU acceleration (use CPU FFTW)

Web map:
    --web[=PORT]            enable live web map (default port: 8888)

GSMTAP:
    --gsmtap[=HOST:PORT]    send IDA frames as GSMTAP/LAPDm via UDP
                             (default: 127.0.0.1:4729, for Wireshark)

Output:
    --file-info=STR         file info string for RAW output (default: auto)
    --parsed                output parsed IDA lines (bypass iridium-parser.py)
    --save-bursts=DIR       save IQ samples of decoded bursts to directory
    --diagnostic            setup verification mode (suppresses RAW output)
    --no-gardner            disable Gardner timing recovery (enabled by default)
    --no-simd               disable AVX2/FMA SIMD acceleration
    -v, --verbose           verbose output to stderr
    -h, --help              show this help
    --list                  list available SDR interfaces
```

## Recommended Settings

**Center frequency:** 1622 MHz (default) covers the full authorized Iridium band. With 10 MHz sample rate, this captures 1617-1627 MHz, which includes:
- Iridium's exclusive band: 1618.725-1626.5 MHz (7.775 MHz)
- Shared Iridium/Globalstar: 1617.775-1618.725 MHz (0.95 MHz)
- Ring alert/simplex channels: 1626.0-1626.5 MHz

Below 1617.775 MHz is Globalstar's exclusive territory. The ITU allocation extends down to 1616 MHz, but Iridium is not authorized to transmit there.

**Sample rate:** 10 MHz (default) covers the full authorized Iridium band without processing empty spectrum. SDRs with 12 MHz capability can use `-r 12000000 -c 1621000000` to cover the entire ITU allocation including the unauthorized guard band, but this provides no additional Iridium signals.

**Narrowband SDRs (RTL-SDR):** For RTL-SDR and other SDRs limited to 2-3 MHz bandwidth, use `-c 1625500000 -r 2400000` to center on the ring alert and simplex channels (1624.3-1626.7 MHz). This captures the IRA frames needed for the web map. The default 1622 MHz center is optimized for wideband receivers and places ring alert channels outside narrowband capture range.

**Threshold:** 16 dB (default) balances sensitivity and false positives. Lower values (14 dB) catch weaker bursts at the cost of more noise. Higher values (18-20 dB) are more selective but may miss marginal signals.

## SDR Hardware

Any SDR that tunes to L-band (1616-1626.5 MHz) and samples at 2 MHz or above will work. Tested hardware:

| SDR | ADC | Max Rate | Notes |
|-----|-----|----------|-------|
| Ettus USRP B210 | 12-bit | 56 MHz | Best sensitivity, dual channel |
| HackRF One | 8-bit | 20 MHz | Widely available, good performance |
| BladeRF | 12-bit | 40 MHz | Good sensitivity |
| RTL-SDR (via SoapySDR) | 8-bit | 2.4 MHz | Limited bandwidth, but works |
| Airspy, LimeSDR, etc. | varies | varies | Via SoapySDR |

## GPU Acceleration

GPU acceleration offloads the burst detection FFT to the GPU. The rest of the signal processing pipeline (downmix, demod) runs on the CPU regardless.

| Platform | Backend | Notes |
|----------|---------|-------|
| NVIDIA | OpenCL | Full GPU pipeline, best performance |
| AMD | OpenCL | ROCm or Mesa drivers |
| Intel integrated | OpenCL | Via NEO or Beignet |
| Raspberry Pi 5 | Vulkan | V3D passes validation but cannot sustain batch FFT throughput; use `--no-gpu` |
| No GPU | CPU | FFTW fallback, handles 10 MHz fine on x86; ARM requires pre-generated wisdom (see above) |

On fast x86 CPUs at 10 MHz, the CPU FFTW path keeps up easily. GPU acceleration is most beneficial for continuous live capture on desktop/laptop systems. A startup validation test verifies GPU correctness by running a test FFT with a known input.

Both backends can be disabled at runtime with `--no-gpu`.

## Output Format

stdout produces the iridium-toolkit RAW format:

```
RAW: i-10-t1 0000442.4080 1624960925 N:10.77-71.83 I:00000003560  50% 0.11738 179 001100011011...
```

Fields are: file info, timestamp (ms), frequency (Hz), magnitude and noise floor (dB), burst ID, confidence (%), signal level, payload symbol count, and demodulated bits.

This output is consumed directly by [iridium-toolkit](https://github.com/muccc/iridium-toolkit) for higher-layer protocol decoding including ACARS, SBD messaging, pager data, voice, and satellite telemetry.

stderr shows a status line once per second in the same format as gr-iridium, so existing monitoring scripts work without changes.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for design documentation covering the signal processing pipeline, threading model, frame decoder internals, and demod optimization history.

## License

GNU General Public License v3.0 or later. See [LICENSE](LICENSE).

## Acknowledgments

This project builds on the work of several open-source projects:

- [gr-iridium](https://github.com/muccc/gr-iridium) (GPL-3.0-or-later) by Sec and schneider42 (muccc) -- the signal processing algorithms for burst detection, downmix, and QPSK demodulation are clean-room C ports of gr-iridium's GNU Radio blocks
- [ice9-bluetooth-sniffer](https://github.com/mikeryan/ice9-bluetooth-sniffer) (GPL-2.0) by Mike Ryan / ICE9 Consulting LLC -- the SDR backend abstraction, build system, and threading infrastructure are adapted from this project
- [VkFFT](https://github.com/DTolm/VkFFT) (MIT) by Dmitrii Tolmachev -- header-only GPU FFT library used for both OpenCL and Vulkan burst detection
- [iridium-toolkit](https://github.com/muccc/iridium-toolkit) (BSD-2-Clause) by Sec and schneider42 -- the downstream frame parser and reassembler, and the reference implementation for BCH error correction and de-interleaving algorithms
