# iridium-sniffer

A standalone Iridium satellite burst detector and demodulator written in C. It provides an alternative to [gr-iridium](https://github.com/muccc/gr-iridium) by eliminating the GNU Radio dependency, while producing the same [iridium-toolkit](https://github.com/muccc/iridium-toolkit) compatible RAW output on stdout. For users who want a lighter-weight, dependency-free option or need embedded deployment, this offers similar functionality with a different architectural approach.

Supports HackRF, BladeRF, USRP (UHD), and SoapySDR for live capture, or processes IQ recordings from file. Optional GPU-accelerated burst detection is available via OpenCL or Vulkan, including on the Raspberry Pi 5.

A built-in web map (`--web`, beta) provides a real-time Leaflet.js visualization of decoded ring alert positions and active satellites -- no external tools or Python required.

Native GSMTAP output (`--gsmtap`) sends decoded IDA (Iridium Data) frames directly to Wireshark via UDP, eliminating the need for the Python `iridium-parser.py -m gsmtap` pipeline.

## Features

- Full Iridium L-band burst detection, downmix, and DQPSK demodulation pipeline
- Direct iridium-toolkit RAW output, compatible with iridium-parser.py and reassembler.py
- Native GSMTAP/LAPDm output to Wireshark (`--gsmtap`) for IDA frame analysis
- Built-in web map with live satellite and ring alert visualization
- GPU-accelerated FFT burst detection (OpenCL or Vulkan)
- Multi-threaded architecture: detection, downmix pool, demodulation, stats
- HackRF, BladeRF, USRP, and SoapySDR support
- Reads ci8, ci16, and cf32 IQ file formats

## Quick Start

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt install build-essential cmake libfftw3-dev libhackrf-dev

# Build
mkdir build && cd build
cmake ..
make -j$(nproc)

# Live capture with web map
./iridium-sniffer -l --web

# Open http://localhost:8888 in a browser
```

## Performance

Tested against gr-iridium on a 60-second IQ recording at 10 MHz from a USRP B210:

| Metric | iridium-sniffer | gr-iridium |
|--------|-----------------|------------|
| Bursts detected | 3668 | ~3468 |
| UW pass rate | 71% | 74% |
| Decoded frames | 2577 | 2720 |
| Relative output | 94.7% | 100% |

In live capture, iridium-sniffer produces roughly twice as many decoded frames per second as gr-iridium. The burst detector is more aggressive and catches weaker signals that a conservative detector skips. The extra bursts that fail the unique word check are silently discarded and never appear in the output.

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

**API endpoints:**

| Endpoint | Description |
|----------|-------------|
| `GET /` | HTML map page |
| `GET /api/events` | SSE stream (1 Hz JSON updates) |
| `GET /api/state` | JSON snapshot of current state |

The frame decoder implements BCH(31,21) error correction with two-bit correction capability, three-way and two-way de-interleaving, and field extraction for IRA (satellite position, beam, paging TMSIs) and IBC (satellite ID, beam, Iridium time counter) frames. From a 60-second recording, it typically decodes 150+ ring alerts and 250+ broadcast frames across 50-60 unique satellites.

## Dependencies

### Minimal Build (CPU-only, file processing)

For processing IQ recordings without SDR or GPU support:

```bash
sudo apt install build-essential cmake libfftw3-dev
```

This builds a CPU-only binary that reads files but cannot capture from SDRs or use GPU acceleration.

### Standard Build (CPU + SDR)

Add at least one SDR backend for live capture:

```bash
# Start with minimal build, then add SDR libraries:
sudo apt install libhackrf-dev     # HackRF One
sudo apt install libbladerf-dev    # BladeRF
sudo apt install libuhd-dev        # USRP (B2x0, N2x0, X3x0, etc.)
sudo apt install libsoapysdr-dev   # SoapySDR (RTL-SDR, Airspy, LimeSDR, etc.)
```

Install only the libraries for SDRs you own. CMake auto-detects what's available.

### GPU-Accelerated Build

For GPU-accelerated burst detection on desktop/laptop:

```bash
# Standard build + OpenCL (NVIDIA, AMD, Intel)
sudo apt install ocl-icd-opencl-dev
```

### Raspberry Pi 5 Build

Pi 5 has no OpenCL support, use Vulkan instead:

```bash
# Minimal build + Vulkan (VideoCore VII GPU)
sudo apt install libvulkan-dev glslang-dev spirv-tools

# Plus SoapySDR for RTL-SDR/Airspy/etc.
sudo apt install libsoapysdr-dev
```

## Build

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

CMake auto-detects available SDR libraries and GPU support. The output tells you what it found:

```
-- HackRF: enabled
-- BladeRF: enabled
-- USRP (UHD): enabled
-- SoapySDR: enabled
-- GPU acceleration: OpenCL
```

### Build Variants

```bash
# OpenCL GPU (default when available)
cmake .. -DUSE_OPENCL=ON

# Vulkan GPU (required for Raspberry Pi 5)
cmake .. -DUSE_VULKAN=ON -DUSE_OPENCL=OFF

# CPU only
cmake .. -DUSE_OPENCL=OFF

# Debug build with AddressSanitizer
cmake .. -DCMAKE_BUILD_TYPE=Debug
```

## Usage

### File Input

```bash
# int8 IQ (default)
./iridium-sniffer -f recording.raw

# Complex float32
./iridium-sniffer -f recording.cf32 --format cf32

# Complex int16 with custom sample rate
./iridium-sniffer -f recording.ci16 --format ci16 -r 10000000 -c 1622000000
```

### Live Capture

```bash
# Auto-detect SDR
./iridium-sniffer -l

# Specify interface
./iridium-sniffer -l -i hackrf-0000000000000000
./iridium-sniffer -l -i usrp-B210-SERIAL
./iridium-sniffer -l -i bladerf0
./iridium-sniffer -l -i soapy-0

# With gain and bias tee
./iridium-sniffer -l -i hackrf-0000000000000000 -B --hackrf-lna=40 --hackrf-vga=20
./iridium-sniffer -l -i usrp-B210-SERIAL --usrp-gain=50
```

### Piping to iridium-toolkit

```bash
# Real-time decode
./iridium-sniffer -l | python3 iridium-toolkit/iridium-parser.py

# File processing with full reassembly
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
    -d, --threshold=DB      burst detection threshold in dB (default: 18.0)
    --no-gpu                disable GPU acceleration (use CPU FFTW)

Web map:
    --web[=PORT]            enable live web map (default port: 8888)

GSMTAP:
    --gsmtap[=HOST:PORT]    send IDA frames as GSMTAP/LAPDm via UDP
                             (default: 127.0.0.1:4729, for Wireshark)

Output:
    --file-info=STR         file info string for RAW output (default: auto)
    -v, --verbose           verbose output to stderr
    -h, --help              show this help
    --list                  list available SDR interfaces
```

## Recommended Settings

**Center frequency:** 1622 MHz centers the Iridium simplex downlink band (1616-1626.5 MHz) and is the default.

**Sample rate:** 10 MHz covers the full Iridium band without processing empty spectrum. This is the default.

**Threshold:** 18 dB is a good starting point. Lower values (14 dB) catch weaker bursts at the cost of more false detections. Higher values (22 dB) are more selective but miss marginal signals.

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
| Raspberry Pi 5 | Vulkan | Only GPU API available on VideoCore VII |
| Intel integrated | OpenCL | Via NEO or Beignet |
| No GPU | CPU | FFTW fallback, handles 10 MHz fine |

On fast x86 CPUs at 10 MHz, the CPU FFTW path keeps up easily. GPU acceleration helps most on weaker processors (Pi 5, embedded ARM) or at higher sample rates.

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
- [iridium-toolkit](https://github.com/muccc/iridium-toolkit) (BSD-2-Clause) by Sec and schneider42 -- the downstream frame parser and reassembler, and the reference for our BCH and de-interleaving implementations
