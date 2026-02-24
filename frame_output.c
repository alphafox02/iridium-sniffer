/*
 * Frame output in iridium-toolkit RAW format
 * Port of gr-iridium's iridium_frame_printer_impl.cc
 *
 * Format:
 *   RAW: {file_info} {timestamp_ms:012.4f} {freq_hz:010d} N:{mag:05.2f}{noise:+06.2f}
 *        I:{id:011d} {conf:3d}% {level:.5f} {payload_symbols:3d} {bits...}
 *
 * Original work Copyright 2021 gr-iridium author
 * Modifications Copyright 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * Frame output in iridium-toolkit RAW format
 *
 * Format:
 *   RAW: {file_info} {timestamp_ms:012.4f} {freq_hz:010d} N:{mag:05.2f}{noise:+06.2f}
 *        I:{id:011d} {conf:3d}% {level:.5f} {payload_symbols:3d} {bits...}
 */

#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include "frame_output.h"
#include "iridium.h"

extern int diagnostic_mode;
extern int parsed_mode;
extern int acars_enabled;

static const char *out_file_info = NULL;
static uint64_t t0 = 0;
static int initialized = 0;

void frame_output_init(const char *fi)
{
    out_file_info = fi;
}

void frame_output_print(demod_frame_t *frame)
{
    /* Suppress RAW output in diagnostic or ACARS-only mode */
    if (diagnostic_mode || acars_enabled)
        return;

    /* Auto-initialize t0 from first frame timestamp */
    if (!initialized) {
        t0 = (frame->timestamp / 1000000000ULL) * 1000000000ULL;

        /* Auto-generate file_info if not provided */
        if (out_file_info == NULL || out_file_info[0] == '\0') {
            static char auto_info[64];
            snprintf(auto_info, sizeof(auto_info),
                     "i-%" PRIu64 "-t1", (uint64_t)(t0 / 1000000000ULL));
            out_file_info = auto_info;
        }
        initialized = 1;
    }

    /* Relative timestamp in milliseconds */
    double ts_ms = (double)(frame->timestamp - t0) / 1000000.0;

    /* Center frequency rounded to nearest Hz */
    int freq_hz = (int)(frame->center_frequency + 0.5);

    /* Payload symbols (after unique word) */
    int payload_syms = frame->n_payload_symbols;
    if (payload_syms < 0) payload_syms = 0;

    /* Print header fields */
    printf("RAW: %s %012.4f %010d N:%05.2f%+06.2f I:%011" PRIu64
           " %3d%% %.5f %3d ",
           out_file_info,
           ts_ms,
           freq_hz,
           frame->magnitude,
           frame->noise,
           frame->id,
           frame->confidence,
           frame->level,
           payload_syms);

    /* Print bits */
    for (int i = 0; i < frame->n_bits; i++)
        putchar('0' + frame->bits[i]);

    putchar('\n');
    fflush(stdout);
}

/* ---- Parsed IDA output (iridium-parser.py compatible) ---- */

void frame_output_print_ida(const ida_burst_t *burst)
{
    if (diagnostic_mode)
        return;

    /* Ensure t0 is initialized (same as RAW output) */
    if (!initialized) {
        t0 = (burst->timestamp / 1000000000ULL) * 1000000000ULL;
        if (out_file_info == NULL || out_file_info[0] == '\0') {
            static char auto_info[64];
            snprintf(auto_info, sizeof(auto_info),
                     "i-%" PRIu64 "-t1", (uint64_t)(t0 / 1000000000ULL));
            out_file_info = auto_info;
        }
        initialized = 1;
    }

    /* Derive parsed file_info: "i-XXXXX-t1" -> "p-XXXXX"
     * Matches iridium-parser.py Message.__init__ */
    char parsed_info[64];
    uint64_t start_ts = t0 / 1000000000ULL;
    snprintf(parsed_info, sizeof(parsed_info), "p-%" PRIu64, start_ts);

    /* Timestamp in milliseconds */
    double ts_ms = (double)(burst->timestamp - t0) / 1000000.0;

    /* Frequency */
    int freq_hz = (int)(burst->frequency + 0.5);

    /* Signal levels: leveldb = 20*log10(level), noise, snr=magnitude */
    double leveldb = (burst->level > 0) ? 20.0 * log10(burst->level) : -99.99;
    double noise = burst->noise;
    double snr = burst->magnitude;

    /* Direction */
    const char *dir = (burst->direction == DIR_UPLINK) ? "UL" : "DL";

    /* Symbol count (payload symbols after UW, minus 12 access code symbols) */
    int syms = burst->n_symbols;
    if (syms < 0) syms = 0;

    /* Print header: IDA: name timestamp frequency confidence% level|noise|snr symbols direction */
    printf("IDA: %s %014.4f %010d %3d%% %06.2f|%07.2f|%05.2f %3d %s ",
           parsed_info, ts_ms, freq_hz,
           burst->confidence, leveldb, noise, snr,
           syms, dir);

    /* LCW header (already padded to 110+1 chars) */
    printf("%s", burst->lcw_header);

    /* IDA-specific fields from bch_stream */
    const uint8_t *bs = burst->bch_stream;
    int bch_len = burst->bch_len;

    if (bch_len < 20) {
        printf("\n");
        fflush(stdout);
        return;
    }

    /* bits[0:3] */
    printf("%c%c%c", '0' + bs[0], '0' + bs[1], '0' + bs[2]);
    /* cont=bits[3:4] */
    printf(" cont=%c", '0' + bs[3]);
    /* bits[4:5] */
    printf(" %c", '0' + bs[4]);
    /* ctr=bits[5:8] */
    printf(" ctr=%c%c%c", '0' + bs[5], '0' + bs[6], '0' + bs[7]);
    /* bits[8:11] */
    printf(" %c%c%c", '0' + bs[8], '0' + bs[9], '0' + bs[10]);
    /* len=da_len */
    printf(" len=%02d", burst->da_len);
    /* 0:bits[16:20] (bitsparser.py hardcodes "0:" prefix) */
    printf(" 0:%c%c%c%c", '0' + bs[16], '0' + bs[17], '0' + bs[18], '0' + bs[19]);

    /* Hex data payload */
    printf(" [");
    if (burst->da_len > 0) {
        /* Check if trailing bytes are all zero */
        int all_zero = 1;
        for (int i = burst->da_len + 1; i < 20; i++) {
            if (burst->payload[i] != 0) { all_zero = 0; break; }
        }

        if (all_zero) {
            /* Print only da_len bytes */
            for (int i = 0; i < burst->da_len; i++) {
                if (i > 0) putchar('.');
                printf("%02x", burst->payload[i]);
            }
        } else {
            /* Print all 20 bytes with ! separator at da_len boundary */
            for (int i = 0; i < 20; i++) {
                if (i > 0) {
                    if (i == burst->da_len && burst->da_len > 0 && burst->da_len < 20)
                        putchar('!');
                    else
                        putchar('.');
                }
                printf("%02x", burst->payload[i]);
            }
        }
    } else {
        /* len=0: print all 20 bytes */
        for (int i = 0; i < 20; i++) {
            if (i > 0) putchar('.');
            printf("%02x", burst->payload[i]);
        }
    }

    /* Pad hex data + bracket to 60 chars */
    /* Calculate current hex string length */
    int hexlen;
    if (burst->da_len > 0) {
        int all_zero = 1;
        for (int i = burst->da_len + 1; i < 20; i++) {
            if (burst->payload[i] != 0) { all_zero = 0; break; }
        }
        int nbytes = all_zero ? burst->da_len : 20;
        hexlen = nbytes * 3 - 1 + 1;  /* hex.hex...hex] */
    } else {
        hexlen = 20 * 3 - 1 + 1;
    }
    printf("]");
    /* Pad to 60 chars total (including the closing bracket) */
    for (int i = hexlen; i < 60; i++)
        putchar(' ');

    /* CRC section */
    if (burst->da_len > 0) {
        printf(" %04x/%04x", burst->stored_crc, burst->computed_crc);
        if (burst->crc_ok)
            printf(" CRC:OK");
        else
            printf(" CRC:no");
    } else {
        printf("  ---   ");
    }

    /* Trailing bits (after CRC) */
    if (bch_len > 9 * 20 + 16) {
        printf(" ");
        for (int i = 9 * 20 + 16; i < bch_len; i++)
            printf("%c", '0' + bs[i]);
    } else {
        printf(" 0000");
    }

    /* SBD ASCII preview (if da_len > 0) */
    if (burst->da_len > 0 && bch_len >= 9 * 20) {
        printf(" SBD: ");
        for (int i = 0; i < 20; i++) {
            /* Extract byte from bch_stream bits[1*20 .. 9*20] */
            int byte = 0;
            for (int b = 0; b < 8; b++)
                byte = (byte << 1) | bs[1 * 20 + i * 8 + b];
            if (byte >= 32 && byte < 127)
                putchar(byte);
            else
                putchar('.');
        }
    }

    putchar('\n');
    fflush(stdout);
}
