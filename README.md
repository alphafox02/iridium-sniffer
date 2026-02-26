# iridium-sniffer

A standalone Iridium satellite burst detector and demodulator written in C. It provides an alternative to [gr-iridium](https://github.com/muccc/gr-iridium) by eliminating the GNU Radio dependency, while producing the same [iridium-toolkit](https://github.com/muccc/iridium-toolkit) compatible RAW output on stdout. For users who want a lighter-weight, dependency-free option or need embedded deployment, this offers similar functionality with a different architectural approach.

Supports HackRF, BladeRF, USRP (UHD), and SoapySDR for live capture, or processes IQ recordings from file. Optional GPU-accelerated burst detection is available via OpenCL (NVIDIA, AMD, Intel). Runs on Raspberry Pi 5 and other ARM boards in CPU-only mode with FFTW wisdom pre-generation.

A built-in web map (`--web`, beta) provides a real-time Leaflet.js visualization of decoded ring alert positions and active satellites -- no external tools or Python required.

Built-in ACARS/SBD decoding (`--acars`) extracts aviation messages directly from IDA frames. When [libacars-2](https://github.com/szpajder/libacars) is installed, ARINC-622 application payloads (ADS-C, CPDLC, OHMA) are fully decoded -- no Python pipeline needed.

Native GSMTAP output (`--gsmtap`) sends decoded IDA (Iridium Data) frames directly to Wireshark via UDP, eliminating the need for the Python `iridium-parser.py -m gsmtap` pipeline.

## Features

- Full Iridium L-band burst detection, downmix, and DQPSK demodulation pipeline
- Direct iridium-toolkit RAW output, compatible with iridium-parser.py and reassembler.py
- Built-in ACARS/SBD decoding (`--acars`) with optional libacars-2 ARINC-622/ADS-C/CPDLC support
- Parsed IDA output mode (`--parsed`) for direct reassembler.py piping (ACARS/SBD recovery)
- Chase BCH soft-decision decoding recovers 37% more IDA frames than iridium-parser.py
- Gardner timing recovery (enabled by default) for improved weak burst demodulation
- Native GSMTAP/LAPDm output to Wireshark (`--gsmtap`) for IDA frame analysis
- Built-in web map with live satellite and ring alert visualization
- Doppler-based receiver positioning from decoded satellite signals (`--position`)
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

CMake auto-detects the available SDR libraries, GPU support, and libacars. All SDR backends, OpenCL GPU acceleration, and ACARS ARINC-622 decoding should be enabled automatically.

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

# Optional: ACARS ARINC-622/ADS-C/CPDLC decoding
sudo apt install libacars-dev        # libacars-2

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
-- libacars: enabled (ARINC-622/ADS-C/CPDLC decoding)
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
| 12 MHz (extended) | 16384 | `fftwf-wisdom -v -o ~/.iridium-sniffer-fftw-wisdom cof16384 cof4096 cof2048 cob2048` |

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
# List available SDR devices
./iridium-sniffer --list

# Live capture (specify your SDR with -i)
./iridium-sniffer -i soapy-0                          # RTL-SDR, Airspy, etc.
./iridium-sniffer -i hackrf-SERIAL                # HackRF
./iridium-sniffer -i usrp-PRODUCT-SERIAL             # USRP

# Live capture with web map (open http://localhost:8888)
./iridium-sniffer -i soapy-0 --web

# Process an IQ recording (no -i needed)
./iridium-sniffer -f recording.cf32

# Pipe to iridium-toolkit
./iridium-sniffer -i soapy-0 | python3 iridium-toolkit/iridium-parser.py

# Built-in ACARS/SBD decoding (no Python needed)
./iridium-sniffer -i soapy-0 --acars

# ACARS JSON to stdout (dumpvdl2/dumphfdl compatible format)
./iridium-sniffer -i soapy-0 --acars-json --station=MYSTATION

# Feed airframes.io directly (iridium-toolkit JSON format over TCP)
./iridium-sniffer -i soapy-0 --feed --station=MYSTATION

# Feed acarshub via UDP (iridium-toolkit JSON format)
./iridium-sniffer -i soapy-0 --feed=udp://127.0.0.1:5558 --station=MYSTATION

# Stream JSON via UDP (dumpvdl2 format, for future aggregator support)
./iridium-sniffer -i soapy-0 --acars-udp=192.168.1.100:5555 --station=MYSTATION

# Direct ACARS/SBD recovery via iridium-toolkit (bypasses iridium-parser.py)
./iridium-sniffer -i soapy-0 --parsed | python3 iridium-toolkit/reassembler.py -m acars

# Estimate receiver position from Doppler shift (with web map)
./iridium-sniffer -i soapy-0 --position

# Position with height aiding (100m above sea level)
./iridium-sniffer -i soapy-0 --position=100

# Send IDA frames to Wireshark
./iridium-sniffer -i soapy-0 --gsmtap
```

## Performance

Tested against gr-iridium on a 60-second IQ recording (cf32, 10 MHz, 1622 MHz center, USRP B210):

**Default threshold (16 dB) -- maximum frame recovery:**

| Metric | iridium-sniffer | gr-iridium |
|--------|-----------------|------------|
| Detected bursts | 5468 | ~3666 |
| Demodulated RAW frames | 3701 | 2713 |
| Ok rate | 68% | 74% |
| IDA frames (internal `--parsed`) | 743 | -- |
| IDA frames (external iridium-parser.py) | 373 | 690 |

The default 16 dB threshold detects more bursts than gr-iridium, including weaker signals at the noise floor. Many of these marginal bursts fail demodulation, which lowers the ok percentage -- but the absolute frame count is 36% higher (3701 vs 2713). This is the recommended setting for maximum data recovery.

**Matched threshold (18 dB) -- apples-to-apples comparison:**

| Metric | iridium-sniffer | gr-iridium |
|--------|-----------------|------------|
| Detected bursts | 3668 | ~3666 |
| Demodulated RAW frames | 2737 | 2713 |
| Ok rate | 75% | 74% |
| IDA frames (internal `--parsed`) | 605 | -- |
| IDA frames (external iridium-parser.py) | 361 | 690 |

At 18 dB (gr-iridium's default), burst detection counts are nearly identical. The ok rate now matches gr-iridium at 75% vs 74%. The external parser IDA gap (361 vs 690) reflects that gr-iridium's GNU Radio-based demodulator produces cleaner bits -- more frames survive standard BCH correction. Chase soft-decision decoding in `--parsed` mode compensates for this (605 vs 361), recovering nearly as many IDA frames from noisier bits. Use `--threshold=18` if ok rate percentage is more important than total frame count.

**A note on live ok% rates:** In live SDR capture, you may see ok\_avg of 35-50% with iridium-sniffer compared to 70-80% shown in gr-iridium guides. This is expected and not a problem. iridium-sniffer uses a lower default detection threshold (16 dB vs gr-iridium's 18 dB), which catches more weak bursts at the noise floor. These marginal detections lower the ok percentage but increase the total number of successfully decoded frames. The ok% statistic measures what fraction of detected bursts decode -- not how many frames you are actually recovering. What matters is decoded frames per second, and iridium-sniffer typically recovers more usable data than gr-iridium despite the lower ok% figure.

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
./iridium-sniffer -i soapy-0 --web

# Custom port
./iridium-sniffer -i soapy-0 --web=9090
```

Then open `http://localhost:8888` in a browser.

The map shows:

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
./iridium-sniffer -i soapy-0 --web | python3 iridium-toolkit/iridium-parser.py
```

## Doppler Positioning (Experimental)

The `--position` flag enables receiver geolocation from Doppler shift measurements. As Iridium LEO satellites pass overhead at ~7.5 km/s, each decoded burst's frequency offset encodes the satellite-receiver geometry. By collecting measurements from multiple satellite passes, an iterated weighted least-squares solver estimates the receiver's latitude and longitude -- no GPS required.

```bash
# Basic positioning (implies --web for map display)
./iridium-sniffer -i soapy-0 --position

# With height aiding for better accuracy (altitude in meters above sea level)
./iridium-sniffer -i soapy-0 --position=100
```

The solver runs every 10 seconds and requires at least 5 measurements from 2+ satellites before attempting a solution. Position estimates appear on stderr and as a green marker on the web map. With open sky and height aiding, expect convergence within 5-10 minutes. Accuracy improves with more satellite passes -- the solver uses motion-validated spatial clustering to reject corrupted IRA positions and outlier rejection (3-sigma) to filter bad measurements.

Height aiding constrains the altitude to a known value and significantly improves horizontal accuracy. Without it, the vertical component is poorly determined by Doppler-only measurements.

Based on: Z. Tan et al., "New Method for Positioning Using IRIDIUM Satellite Signals of Opportunity," IEEE Access, vol. 7, 2019.

## GSMTAP Output (Wireshark Integration)

The `--gsmtap` flag enables native IDA (Iridium Data Access) frame decoding and sends the decoded LAPDm frames to Wireshark via UDP. This replaces the `iridium-parser.py -m gsmtap` Python pipeline for protocol analysis.

```bash
# Start Wireshark listening for GSMTAP
wireshark -k -i lo -f "udp port 4729"

# In another terminal, run with GSMTAP enabled
./iridium-sniffer -i soapy-0 --gsmtap

# Custom destination host and port
./iridium-sniffer -i soapy-0 --gsmtap=192.168.1.100:4729

# Combined with web map
./iridium-sniffer -i soapy-0 --web --gsmtap
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

## Built-in ACARS / SBD Decoding

These flags control ACARS/SBD output, and can be combined:

| Flag | Output |
|------|--------|
| `--acars` | Human-readable text to stdout |
| `--acars-json` | JSON to stdout (dumpvdl2/dumphfdl format) |
| `--acars-udp=HOST:PORT` | JSON via UDP (dumpvdl2/dumphfdl format, repeatable, max 4) |
| `--feed[=PROTO://HOST:PORT]` | Feed aggregator (iridium-toolkit JSON format, UDP or TCP) |

This replaces the `reassembler.py -m acars` pipeline entirely -- no Python needed. When [libacars-2](https://github.com/szpajder/libacars) is installed, ARINC-622 application payloads (ADS-C, CPDLC, OHMA, MIAM) are fully decoded. Without libacars, basic ACARS field extraction still works.

```bash
# Human-readable text output
./iridium-sniffer -i usrp-B210-SERIAL --acars

# JSON output to stdout
./iridium-sniffer -i usrp-B210-SERIAL --acars-json --station=MYSTATION

# Stream JSON over UDP to a remote aggregator
./iridium-sniffer -i usrp-B210-SERIAL --acars-udp=192.168.1.100:5555 --station=MYSTATION

# Feed acarshub via UDP (iridium-toolkit JSON format)
./iridium-sniffer -i usrp-B210-SERIAL --feed=udp://127.0.0.1:5558 --station=MYSTATION

# Feed airframes.io directly via TCP (iridium-toolkit JSON format)
./iridium-sniffer -i usrp-B210-SERIAL --feed --station=MYSTATION

# Text on stdout + UDP JSON stream simultaneously
./iridium-sniffer -i usrp-B210-SERIAL --acars --acars-udp=192.168.1.100:5555 --station=MYSTATION
```

### Text Output

**Example (with libacars):**

```
ACARS: 2026-02-24T13:06:52Z DL [hdr:iridium]
ACARS:
 Reassembly: skipped
 Reg: .N-XXXXX
 Mode: 2 Label: H1 Blk id: F More: 0 Ack: !
 Sublabel: MD
 Message:
  MSG/RX24-FEB-26 1306Z /RXFLIGHT PLANS PXXXX AND PXXXX ARE AVAILABLE FOR UPLINK
```

Heartbeat pings (Label `_d`) are the most common ACARS message type on Iridium. H1-labeled messages carry ARINC-622 application data -- airline operational control (AOC) messages, flight plan uplinks, ADS-C position reports, and CPDLC clearances. When libacars is present, these payloads are decoded into structured fields rather than appearing as opaque binary.

Non-ACARS SBD traffic (IoT telemetry, maritime tracking, etc.) is also displayed:

```
SBD: 2026-02-24T12:56:07Z DL 6841542344504f4c4c203635313530 | hAT#DPOLL 65150
```

### JSON Format

JSON mode (`--acars-json` or `--acars-udp`) produces one JSON object per line. The envelope format matches [dumpvdl2](https://github.com/szpajder/dumpvdl2) and [dumphfdl](https://github.com/szpajder/dumphfdl), with `"iridium"` as the top-level protocol key (analogous to `"vdl2"` and `"hfdl"`). ACARS field names inside the `"acars"` object are identical to what libacars produces, so aggregation sites can ingest all three tools with one parser.

**With libacars** (ARINC-622/ADS-C/CPDLC decoded):

```json
{
  "iridium": {
    "app": { "name": "iridium-sniffer", "ver": "1.0" },
    "station": "MYSTATION",
    "t": { "sec": 1740412012, "usec": 555856 },
    "freq": 1623126868,
    "sig_level": 29.02,
    "acars": {
      "err": false,
      "crc_ok": true,
      "more": false,
      "reg": ".N12345",
      "mode": "2",
      "label": "H1",
      "blk_id": "F",
      "ack": "!",
      "sublabel": "DF",
      "mfi": "01",
      "msg_text": "...",
      "arinc622": { "...decoded application payload..." }
    }
  }
}
```

**Without libacars** (basic ACARS fields only):

```json
{
  "iridium": {
    "app": { "name": "iridium-sniffer", "ver": "1.0" },
    "station": "MYSTATION",
    "t": { "sec": 1740412012, "usec": 555856 },
    "freq": 1623126868,
    "sig_level": 29.02,
    "acars": {
      "err": false,
      "crc_ok": true,
      "more": false,
      "reg": ".N12345",
      "mode": "2",
      "label": "H1",
      "blk_id": "F",
      "ack": "!",
      "msg_text": "..."
    }
  }
}
```

The envelope (`app`, `station`, `t`, `freq`, `sig_level`) and ACARS field names (`err`, `crc_ok`, `more`, `reg`, `mode`, `label`, `blk_id`, `ack`, `flight`, `msg_num`, `msg_num_seq`, `msg_text`) are the same with or without libacars. The difference is that libacars adds decoded ARINC-622 application layer objects (`arinc622`, `adsc`, `cpdlc`, etc.) nested after the base ACARS fields. Sites that already ingest dumpvdl2 or dumphfdl JSON can use the same parser -- just check for the `"iridium"` key instead of `"vdl2"` or `"hfdl"`.

### UDP Streaming

`--acars-udp=HOST:PORT` sends each ACARS JSON object as a UDP datagram to a remote host. This flag can be specified multiple times (up to 4) to feed multiple aggregators simultaneously. Combine `--acars` (text on stdout) with `--acars-udp` to get human-readable local output while feeding remote sites. The JSON format is the same regardless of output method.

**Shutdown stats** are printed to stderr:

```
SBD: 339 packets from 15964 IDA messages (75 short, 260 single, 1 multi-pkt)
ACARS: 80 messages decoded (1 with errors)
```

### Installing libacars (optional but recommended)

libacars-2 is optional. Without it, ACARS messages are still decoded but ARINC-622 application payloads remain as raw text. With it, ADS-C, CPDLC, and other embedded protocols are fully decoded.

```bash
# Ubuntu / Debian / DragonOS
sudo apt install libacars-dev

# Or build from source
git clone https://github.com/szpajder/libacars.git
cd libacars && mkdir build && cd build
cmake .. && make -j$(nproc) && sudo make install
sudo ldconfig
```

CMake reports the detection status at build time:

```
-- libacars: enabled (ARINC-622/ADS-C/CPDLC decoding)
```

or:

```
-- libacars: not found (basic ACARS only)
```

### Feeding acarshub and airframes.io

The traditional Python pipeline for getting Iridium ACARS into aggregators requires four processes chained together:

```bash
# Traditional pipeline (gr-iridium + iridium-toolkit + acars.py)
iridium-extractor -D 4 rtl-sdr | iridium-parser.py | reassembler.py -m acars -a json | acars.py -s MYSTATION
```

iridium-sniffer replaces that entire chain with a single `--feed` flag. The feed output uses the iridium-toolkit JSON format (the same format produced by iridium-toolkit's `reassembler.py -m acars -a json`), so existing aggregators accept it without changes.

**Feed directly to airframes.io** (TCP, port 5590):

```bash
# Bare --feed defaults to tcp://feed.airframes.io:5590
./iridium-sniffer -i soapy-0 --feed --station=MYSTATION
```

**Feed a local acarshub instance** (UDP, port 5558):

```bash
./iridium-sniffer -i soapy-0 --feed=udp://127.0.0.1:5558 --station=MYSTATION
```

**Feed acarshub via TCP** (also supported):

```bash
./iridium-sniffer -i soapy-0 --feed=tcp://127.0.0.1:15590 --station=MYSTATION
```

Add `--acars` for human-readable text output locally while feeding:

```bash
./iridium-sniffer -i soapy-0 --acars --feed --station=MYSTATION
```

**Docker Compose (acarshub):** Set `ENABLE_IRDM=true` and configure the transport. For UDP: `IRDM_CONNECTIONS=udp` (default port 5558). For TCP: `IRDM_CONNECTIONS=tcp://HOST:PORT`. See the [docker-acarshub](https://github.com/sdr-enthusiasts/docker-acarshub) documentation for details.

**Two JSON formats:** iridium-sniffer produces two distinct ACARS JSON formats for different purposes:

- `--feed` currently outputs the **iridium-toolkit format** (`"app": {"name": "iridium-toolkit"}` at the top level). This is the established format that acarshub and airframes.io already accept. Use this for feeding aggregators today.

- `--acars-json` / `--acars-udp` output a **dumpvdl2/dumphfdl envelope format** (`"iridium"` as the top-level key, matching the structure of dumpvdl2's `"vdl2"` and dumphfdl's `"hfdl"`). This is a richer, more structured format with full libacars ARINC-622 decoding. Once aggregator sites accept the dumpvdl2 envelope, `--feed` will adopt it and `--acars-udp` can be retired -- `--feed` remains the single flag for feeding aggregators regardless of which wire format it carries.

## Parsed IDA Output

The `--parsed` flag enables internal IDA frame decoding with Chase BCH error correction and outputs parsed IDA lines directly to stdout. This was added primarily for recovering ACARS, SBD, and other IDA-based message content without requiring the external Python `iridium-parser.py` pipeline.

```bash
# Direct to reassembler (no iridium-parser.py needed for IDA/ACARS/SBD)
./iridium-sniffer -i soapy-0 --parsed | python3 iridium-toolkit/reassembler.py -m acars

# Traditional pipeline (still works, decodes all frame types)
./iridium-sniffer -i soapy-0 | python3 iridium-toolkit/iridium-parser.py | python3 iridium-toolkit/reassembler.py -m acars
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
./iridium-sniffer -i soapy-0 --save-bursts bursts/

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

Specifying `-i` selects an SDR interface and implies live capture (no `-l` needed). Use `--list` to see available devices:

```bash
./iridium-sniffer --list
```

Then specify the interface with `-i`. SoapySDR devices can be selected by index (`soapy-N`) or by device args (`soapy:driver=X,serial=Y`) for deterministic selection when multiple devices are connected:

```bash
# RTL-SDR / Airspy / other SoapySDR devices (by index)
./iridium-sniffer -i soapy-0

# SoapySDR device by serial number or driver args
./iridium-sniffer -i soapy:driver=airspy,serial=ABC123
./iridium-sniffer -i soapy:driver=rtlsdr,serial=00000001

# HackRF (use serial from --list)
./iridium-sniffer -i hackrf-SERIAL

# USRP (use serial from --list)
./iridium-sniffer -i usrp-PRODUCT-SERIAL

# BladeRF
./iridium-sniffer -i bladerf1

# With gain and bias tee
./iridium-sniffer -i soapy-0 -B --soapy-gain=40
./iridium-sniffer -i hackrf-SERIAL --hackrf-lna=40 --hackrf-vga=20
./iridium-sniffer -i usrp-PRODUCT-SERIAL --usrp-gain=50

# SoapySDR device-specific settings
./iridium-sniffer -i soapy:driver=airspy,serial=ABC --soapy-setting=bitpack:true
./iridium-sniffer -i soapy:driver=bladerf --soapy-setting=biastee_rx:true
```

### Piping to iridium-toolkit

```bash
# Real-time decode
./iridium-sniffer -i soapy-0 | python3 iridium-toolkit/iridium-parser.py

# Direct to reassembler (parsed mode, bypasses iridium-parser.py)
./iridium-sniffer -i soapy-0 --parsed | python3 iridium-toolkit/reassembler.py -m acars

# File processing with full reassembly (traditional pipeline)
./iridium-sniffer -f recording.cf32 --format cf32 | \
    python3 iridium-toolkit/iridium-parser.py | \
    python3 iridium-toolkit/reassembler.py
```

## Command Reference

```
Usage: iridium-sniffer <-f FILE | -i IFACE> [options]

Input (one required):
    -f, --file=FILE         read IQ samples from file
    -l, --live              capture live from SDR (implied by -i)
    --format=FMT            IQ file format: ci8 (default), ci16, cf32
                             Auto-detected from file extension when not specified

SDR options:
    -i, --interface=IFACE   SDR to use (see --list for available devices):
                             soapy-N (by index) or soapy:key=val,... (by args)
                             hackrf-SERIAL, bladerfN, usrp-PRODUCT-SERIAL
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
    --soapy-setting=K:V    SoapySDR device setting (repeatable)
                             e.g. bitpack:true (Airspy), biastee_rx:true (bladeRF)

Detection:
    -d, --threshold=DB      burst detection threshold in dB (default: 16.0)
    --no-gpu                disable GPU acceleration (use CPU FFTW)

Web map:
    --web[=PORT]            enable live web map (default port: 8888)

GSMTAP:
    --gsmtap[=HOST:PORT]    send IDA frames as GSMTAP/LAPDm via UDP
                             (default: 127.0.0.1:4729, for Wireshark)

ACARS:
    --acars                 decode and display ACARS/SBD messages from IDA
    --acars-json            output ACARS as JSON to stdout (dumpvdl2 format)
    --acars-udp=HOST:PORT   stream ACARS JSON via UDP (dumpvdl2 format, repeatable, max 4)
    --feed[=PROTO://HOST:PORT]  feed aggregator (iridium-toolkit JSON format)
                             udp://HOST:PORT for acarshub, tcp://HOST:PORT for airframes.io
                             bare --feed defaults to tcp://feed.airframes.io:5590
    --station=ID            station identifier for JSON output

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

**Sample rate:** 10 MHz (default) covers the full authorized Iridium band without processing empty spectrum. SDRs with 12 MHz capability can use `-r 12000000 -c 1621000000` to cover the entire ITU allocation including the unauthorized guard band, but this provides no additional Iridium signals. There is no decimation (`-D`) flag -- each detected burst is automatically downmixed and decimated to 250 kHz internally regardless of input sample rate.

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
- [libacars](https://github.com/szpajder/libacars) (MIT) by Tomasz Lemiech (szpajder) -- optional dependency for ARINC-622, ADS-C, and CPDLC decoding within ACARS messages
