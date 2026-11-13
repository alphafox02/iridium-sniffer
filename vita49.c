/*
 * VITA 49 (VRT) UDP input - receives IQ samples via VRT signal data packets
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "net_util.h"
#include "sdr.h"
#include "vita49.h"

/* Globals from main.c / options.c */
typedef enum { FMT_CI8 = 0, FMT_CI16, FMT_CF32 } iq_format_t;
extern volatile int running;
extern pid_t self_pid;
extern iq_format_t iq_format;
extern int vita49_enabled;
extern char *vita49_endpoint;
extern double samp_rate;
extern double center_freq;
extern int samp_rate_explicit;
extern int center_freq_explicit;
extern int iq_format_explicit;
extern pthread_mutex_t vita49_ctx_mutex;
extern pthread_cond_t vita49_ctx_cond;
extern int vita49_ctx_ready;

#define VITA49_DEFAULT_PORT 4991
#define VRT_MAX_PKT 65536

/* VRT packet types */
#define VRT_TYPE_SIGNAL_DATA_NO_SID  0x0
#define VRT_TYPE_SIGNAL_DATA         0x1
#define VRT_TYPE_IF_CONTEXT          0x4
#define VRT_TYPE_EXT_CONTEXT         0x5

/* Strip VRL wrapper if present. Returns offset to VRT packet start (0 or 8)
 * and adjusts *pkt_len to exclude the 4-byte VRL trailer. Callers use the
 * returned offset to find the VRT start, so (pkt_len - offset) = VRT length. */
static size_t vrl_strip(const uint8_t *pkt, size_t *pkt_len)
{
    if (*pkt_len >= 12) {
        uint32_t w0 = ntohl(*(const uint32_t *)pkt);
        if (w0 == 0x56524C50) {  /* "VRLP" */
            *pkt_len -= 4;  /* exclude trailer; header skipped via offset */
            return 8;
        }
    }
    return 0;
}

/* Read a 64-bit big-endian value from two consecutive 32-bit words */
static uint64_t read_be64(const uint32_t *p)
{
    return ((uint64_t)ntohl(p[0]) << 32) | (uint64_t)ntohl(p[1]);
}

/*
 * IF context indicator field bit positions (VITA 49.0 Section 7.1.5).
 * Each set bit means the corresponding field is present, in order from
 * MSB to LSB.  Fields appear in the body in MSB-first order.
 */
#define CIF_CHANGE_IND      (1u << 31)
#define CIF_REF_POINT_ID    (1u << 30)
#define CIF_BANDWIDTH       (1u << 29)
#define CIF_IF_REF_FREQ     (1u << 28)
#define CIF_RF_REF_FREQ     (1u << 27)
#define CIF_RF_FREQ_OFFSET  (1u << 26)
#define CIF_IF_BAND_OFFSET  (1u << 25)
#define CIF_REF_LEVEL       (1u << 24)
#define CIF_GAIN            (1u << 23)
#define CIF_OVER_RANGE      (1u << 22)
#define CIF_SAMPLE_RATE     (1u << 21)
#define CIF_DATA_FORMAT     (1u << 15)

/* CIF0 field table: bit flag and size in 32-bit words, MSB-first order.
 * Walk this table to find field offsets within context packet body. */
static const struct { uint32_t bit; unsigned words; } cif_fields[] = {
    { CIF_CHANGE_IND,     1 },  /* context field change indicator */
    { CIF_REF_POINT_ID,   1 },  /* reference point ID */
    { CIF_BANDWIDTH,      2 },  /* bandwidth */
    { CIF_IF_REF_FREQ,    2 },  /* IF reference frequency */
    { CIF_RF_REF_FREQ,    2 },  /* RF reference frequency */
    { CIF_RF_FREQ_OFFSET, 2 },  /* RF/IF frequency offset */
    { CIF_IF_BAND_OFFSET, 2 },  /* IF band offset */
    { CIF_REF_LEVEL,      1 },  /* reference level (16-bit in 32-bit word) */
    { CIF_GAIN,           1 },  /* gain (two 16-bit in 32-bit word) */
    { CIF_OVER_RANGE,     1 },  /* over-range count */
    { CIF_SAMPLE_RATE,    2 },  /* sample rate */
    { 1u << 20, 2 },  /* timestamp adjustment */
    { 1u << 19, 1 },  /* timestamp calibration time */
    { 1u << 18, 1 },  /* temperature */
    { 1u << 17, 2 },  /* device identifier */
    { 1u << 16, 1 },  /* state/event indicators */
    { CIF_DATA_FORMAT,    2 },  /* data packet payload format */
};

/*
 * Parse the data packet payload format field (VITA 49.0 section 7.1.5.18).
 * Returns the detected IQ format, or -1 if unrecognized.
 *
 * Word 1 layout:
 *   [31:30] real/complex: 0=real, 1=complex cartesian
 *   [28:24] data item format (DIF): 0=signed int, 14=float32, 15=float64,
 *           16=unsigned int
 *   [4:0]   data item size minus 1 (e.g. 7=8-bit, 15=16-bit, 31=32-bit)
 */
static int vrt_parse_data_format(uint32_t fmt_word1)
{
    unsigned real_cpx  = (fmt_word1 >> 29) & 0x3;
    unsigned dif       = (fmt_word1 >> 24) & 0x1F;
    unsigned data_bits = (fmt_word1 & 0x1F) + 1;

    /* Only handle complex formats (real_cpx == 1) */
    if (real_cpx != 1)
        return -1;

    if (dif == 0) {
        /* Signed integer */
        if (data_bits == 8)  return FMT_CI8;
        if (data_bits == 16) return FMT_CI16;
    } else if (dif == 14) {
        /* IEEE 754 float32 */
        return FMT_CF32;
    }

    return -1;  /* Unsupported format */
}

/*
 * Parse a VRT IF context packet (type 0x4) for sample rate, RF frequency,
 * and data format. Auto-applies values not explicitly set on command line.
 * Signals vita49_ctx_cond when context is received so main can proceed
 * with pipeline creation.
 */
static void vrt_handle_context(const uint8_t *vrt, size_t vrt_len,
                                int *ctx_logged)
{
    if (vrt_len < 8)
        return;

    uint32_t w0 = ntohl(*(const uint32_t *)vrt);
    /* Both IF context (0x4) and extension context (0x5) include stream ID */
    unsigned class_id   = (w0 >> 27) & 0x1;
    unsigned tsi        = (w0 >> 22) & 0x3;
    unsigned tsf        = (w0 >> 20) & 0x3;
    unsigned pkt_size_w = w0 & 0xFFFF;

    if ((size_t)pkt_size_w * 4 > vrt_len || pkt_size_w < 2)
        return;

    /* Walk past header to reach context indicator field (CIF0) */
    unsigned off_w = 1;
    off_w++;  /* stream ID (always present in context packets) */
    if (class_id) off_w += 2;
    if (tsi) off_w++;
    if (tsf) off_w += 2;

    if (off_w >= pkt_size_w)
        return;

    const uint32_t *words = (const uint32_t *)vrt;
    uint32_t cif0 = ntohl(words[off_w]);
    off_w++;  /* move past CIF0 */

    /* Walk the CIF0 fields in order to extract metadata */
    double rf_freq_hz = 0;
    int have_rf = 0;
    double ctx_samp_rate = 0;
    int have_sr = 0;
    int detected_format = -1;

    for (unsigned i = 0; i < sizeof(cif_fields)/sizeof(cif_fields[0]); i++) {
        if (!(cif0 & cif_fields[i].bit))
            continue;

        if (off_w + cif_fields[i].words > pkt_size_w)
            return;  /* truncated */

        if (cif_fields[i].bit == CIF_RF_REF_FREQ) {
            /* 64-bit fixed-point Hz, 20-bit fraction */
            uint64_t val = read_be64(&words[off_w]);
            rf_freq_hz = (double)(int64_t)val / (1LL << 20);
            have_rf = 1;
        } else if (cif_fields[i].bit == CIF_SAMPLE_RATE) {
            /* 64-bit fixed-point Hz, 20-bit fraction */
            uint64_t val = read_be64(&words[off_w]);
            ctx_samp_rate = (double)(int64_t)val / (1LL << 20);
            have_sr = 1;
        } else if (cif_fields[i].bit == CIF_DATA_FORMAT) {
            detected_format = vrt_parse_data_format(ntohl(words[off_w]));
        }

        off_w += cif_fields[i].words;
    }

    if (!have_rf && !have_sr && detected_format < 0)
        return;

    if (*ctx_logged)
        return;
    *ctx_logged = 1;

    /* Auto-apply or warn for sample rate */
    if (have_sr) {
        if (!samp_rate_explicit) {
            samp_rate = ctx_samp_rate;
            fprintf(stderr, "vita49: auto-detected sample_rate=%.0f Hz\n",
                    ctx_samp_rate);
        } else {
            fprintf(stderr, "vita49: context reports sample_rate=%.0f Hz\n",
                    ctx_samp_rate);
            if (ctx_samp_rate - samp_rate > 1.0 ||
                samp_rate - ctx_samp_rate > 1.0)
                fprintf(stderr, "vita49: WARNING: source sample rate %.0f Hz "
                        "differs from -r %.0f Hz\n", ctx_samp_rate, samp_rate);
        }
    }

    /* Auto-apply or warn for RF frequency */
    if (have_rf) {
        if (!center_freq_explicit) {
            center_freq = rf_freq_hz;
            fprintf(stderr, "vita49: auto-detected rf_freq=%.0f Hz\n",
                    rf_freq_hz);
        } else {
            fprintf(stderr, "vita49: context reports rf_freq=%.0f Hz\n",
                    rf_freq_hz);
            if (rf_freq_hz - center_freq > 1.0 ||
                center_freq - rf_freq_hz > 1.0)
                fprintf(stderr, "vita49: WARNING: source RF freq %.0f Hz "
                        "differs from -c %.0f Hz\n", rf_freq_hz, center_freq);
        }
    }

    /* Auto-apply or error on format mismatch (wrong format = garbage output) */
    if (detected_format >= 0) {
        const char *fmt_names[] = { "ci8", "ci16", "cf32" };
        if (!iq_format_explicit) {
            iq_format = (iq_format_t)detected_format;
            fprintf(stderr, "vita49: auto-detected format=%s\n",
                    fmt_names[detected_format]);
        } else if ((int)iq_format != detected_format) {
            errx(1, "vita49: source format is %s but --format %s was "
                 "specified (mismatched format produces unusable output)",
                 fmt_names[detected_format], fmt_names[iq_format]);
        }
    }

    /* Signal main thread that context has been received */
    pthread_mutex_lock(&vita49_ctx_mutex);
    vita49_ctx_ready = 1;
    pthread_cond_signal(&vita49_ctx_cond);
    pthread_mutex_unlock(&vita49_ctx_mutex);
}

/*
 * Parse the VRT 32-bit header word and return the payload offset and size.
 * Returns 0 on success, -1 if packet should be skipped.
 */
static int vrt_parse_header(const uint8_t *pkt, size_t pkt_len,
                            size_t *payload_off, size_t *payload_bytes)
{
    if (pkt_len < 4)
        return -1;

    /* Strip VRL wrapper if present */
    size_t vrl_off = vrl_strip(pkt, &pkt_len);
    uint32_t w0 = ntohl(*(const uint32_t *)(pkt + vrl_off));

    unsigned pkt_type    = (w0 >> 28) & 0xF;
    unsigned class_id    = (w0 >> 27) & 0x1;
    unsigned trailer     = (w0 >> 26) & 0x1;
    unsigned tsi         = (w0 >> 22) & 0x3;
    unsigned tsf         = (w0 >> 20) & 0x3;
    unsigned pkt_size_w  = w0 & 0xFFFF;  /* packet size in 32-bit words */

    /* Only accept signal data packets */
    if (pkt_type != VRT_TYPE_SIGNAL_DATA_NO_SID &&
        pkt_type != VRT_TYPE_SIGNAL_DATA)
        return -1;

    /* Validate packet size against received datagram (excluding VRL wrapper) */
    size_t vrt_len = pkt_len - vrl_off;
    size_t pkt_size_bytes = (size_t)pkt_size_w * 4;
    if (pkt_size_bytes > vrt_len || pkt_size_bytes < 4)
        return -1;

    /* Calculate header word count */
    unsigned hdr_words = 1;
    if (pkt_type == VRT_TYPE_SIGNAL_DATA)
        hdr_words++;  /* stream ID */
    if (class_id)
        hdr_words += 2;
    if (tsi != 0)
        hdr_words++;  /* integer timestamp */
    if (tsf != 0)
        hdr_words += 2;  /* fractional timestamp */

    /* Trailer takes 1 word if present (only valid on signal data) */
    unsigned trailer_words = trailer ? 1 : 0;

    if (hdr_words + trailer_words >= pkt_size_w)
        return -1;  /* no payload */

    unsigned payload_words = pkt_size_w - hdr_words - trailer_words;
    *payload_off = vrl_off + hdr_words * 4;
    *payload_bytes = payload_words * 4;
    return 0;
}

void *vita49_thread(void *arg)
{
    (void)arg;

    /* Parse bind address */
    const char *bind_addr = "0.0.0.0";
    int port = VITA49_DEFAULT_PORT;

    char *ep = NULL;
    if (vita49_endpoint) {
        /* Format: IP:PORT or just PORT */
        ep = strdup(vita49_endpoint);
        char *colon = strrchr(ep, ':');
        if (colon) {
            *colon = '\0';
            bind_addr = ep;
            port = atoi(colon + 1);
        } else {
            port = atoi(ep);
        }
        if (port <= 0 || port > 65535) {
            warnx("vita49: invalid port in '%s'", vita49_endpoint);
            free(ep);
            running = 0;
            kill(self_pid, SIGINT);
            return NULL;
        }
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        warn("vita49: socket");
        free(ep);
        running = 0;
        kill(self_pid, SIGINT);
        return NULL;
    }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    /* 4 MB receive buffer for bursty traffic */
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    /* 500ms timeout so the loop checks 'running' periodically */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 500000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };
    if (resolve_host_ipv4(bind_addr, &addr.sin_addr) < 0) {
        warnx("vita49: cannot resolve bind address '%s'", bind_addr);
        close(fd);
        free(ep);
        running = 0;
        kill(self_pid, SIGINT);
        return NULL;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        warn("vita49: bind %s:%d", bind_addr, port);
        close(fd);
        free(ep);
        running = 0;
        kill(self_pid, SIGINT);
        return NULL;
    }

    fprintf(stderr, "vita49: listening on %s:%d (format=%s)\n",
            bind_addr, port,
            iq_format == FMT_CF32 ? "cf32" :
            iq_format == FMT_CI16 ? "cs16" : "cs8");
    free(ep);       /* no longer needed after bind + log */

    uint8_t pkt_buf[VRT_MAX_PKT];
    unsigned last_count = 0;
    int have_count = 0;
    int ctx_logged = 0;
    unsigned long total_pkts = 0;
    unsigned long skipped_pkts = 0;
    unsigned long gap_pkts = 0;

    while (running) {
        ssize_t len = recvfrom(fd, pkt_buf, sizeof(pkt_buf), 0, NULL, NULL);
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;
            warn("vita49: recvfrom");
            break;
        }

        /* Check for context packets (IF context or extension context).
         * These carry metadata like sample rate and RF frequency. */
        {
            size_t ctx_len = (size_t)len;
            size_t ctx_off = vrl_strip(pkt_buf, &ctx_len);
            if (ctx_len > ctx_off + 4) {
                uint32_t cw0 = ntohl(*(const uint32_t *)(pkt_buf + ctx_off));
                unsigned ctype = (cw0 >> 28) & 0xF;
                if (ctype == VRT_TYPE_IF_CONTEXT ||
                    ctype == VRT_TYPE_EXT_CONTEXT) {
                    vrt_handle_context(pkt_buf + ctx_off,
                                       ctx_len - ctx_off, &ctx_logged);
                    continue;  /* context packets carry no IQ data */
                }
            }
        }

        size_t payload_off, payload_bytes;
        if (vrt_parse_header(pkt_buf, (size_t)len,
                             &payload_off, &payload_bytes) < 0) {
            skipped_pkts++;
            continue;
        }

        /* Sequence gap detection (4-bit counter in VRT header word 0).
         * payload_off includes any VRL offset, so VRT word 0 is at
         * payload_off minus the VRT header words that precede the payload. */
        size_t vrt_off = 0;
        if (ntohl(*(const uint32_t *)pkt_buf) == 0x56524C50)
            vrt_off = 8;
        uint32_t w0_seq = ntohl(*(const uint32_t *)(pkt_buf + vrt_off));
        unsigned count = (w0_seq >> 16) & 0xF;
        if (have_count) {
            unsigned expected = (last_count + 1) & 0xF;
            if (count != expected)
                gap_pkts++;
        }
        last_count = count;
        have_count = 1;
        total_pkts++;

        const uint8_t *payload = pkt_buf + payload_off;
        sample_buf_t *s;
        size_t num_samples;

        switch (iq_format) {
        case FMT_CF32: {
            /* 8 bytes per complex sample (2 x float32), big-endian in VRT */
            num_samples = payload_bytes / 8;
            if (num_samples == 0) continue;
            s = malloc(sizeof(*s) + num_samples * 8);
            if (!s) continue;
            s->format = SAMPLE_FMT_FLOAT;
            const uint32_t *src32 = (const uint32_t *)payload;
            uint32_t *dst32 = (uint32_t *)s->samples;
            for (size_t i = 0; i < num_samples * 2; i++)
                dst32[i] = ntohl(src32[i]);
            break;
        }

        case FMT_CI16: {
            /* 4 bytes per complex sample (2 x int16), big-endian in VRT */
            num_samples = payload_bytes / 4;
            if (num_samples == 0) continue;
            s = malloc(sizeof(*s) + num_samples * 8);
            if (!s) continue;
            s->format = SAMPLE_FMT_FLOAT;
            const uint16_t *src = (const uint16_t *)payload;
            float *out = (float *)s->samples;
            for (size_t i = 0; i < num_samples * 2; i++)
                out[i] = (int16_t)ntohs(src[i]) * (1.0f / 32768.0f);
            break;
        }

        case FMT_CI8:
        default:
            /* 2 bytes per complex sample (2 x int8) */
            num_samples = payload_bytes / 2;
            if (num_samples == 0) continue;
            s = malloc(sizeof(*s) + num_samples * 2);
            if (!s) continue;
            s->format = SAMPLE_FMT_INT8;
            memcpy(s->samples, payload, num_samples * 2);
            break;
        }

        s->num = num_samples;
        s->hw_timestamp_ns = 0;
        push_samples(s);
    }

    close(fd);

    if (total_pkts > 0)
        fprintf(stderr, "vita49: received %lu packets (%lu skipped, %lu gaps)\n",
                total_pkts, skipped_pkts, gap_pkts);

    running = 0;
    kill(self_pid, SIGINT);
    return NULL;
}
