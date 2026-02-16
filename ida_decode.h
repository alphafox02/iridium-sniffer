/*
 * IDA (Iridium Data) frame decoder
 * Based on iridium-toolkit bitsparser.py + ida.py (muccc)
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * IDA (Iridium Data) frame decoder + multi-burst reassembly
 */

#ifndef __IDA_DECODE_H__
#define __IDA_DECODE_H__

#include <stdint.h>
#include "qpsk_demod.h"
#include "burst_downmix.h"

/* LCW (Link Control Word) decoded fields */
typedef struct {
    int ft;             /* frame type: 0-3 */
    int lcw_ok;         /* all 3 LCW components decoded */
    int lcw_ft;         /* 2-bit type field from lcw1 */
    int lcw_code;       /* 4-bit code from lcw2 */
    uint32_t lcw3_val;  /* 21 data bits from lcw3 */
    int ec_lcw;         /* total LCW error corrections (-1 if none) */
} lcw_t;

/* Single IDA burst (after BCH decode, before reassembly) */
typedef struct {
    uint64_t timestamp;
    double frequency;
    ir_direction_t direction;
    float magnitude;
    float noise;
    float level;
    int confidence;
    int n_symbols;      /* payload symbols (after UW) */
    int da_ctr;         /* sequence counter 0-7 */
    int da_len;         /* payload length in bytes */
    int cont;           /* continuation expected */
    uint8_t payload[32];
    int payload_len;
    int crc_ok;
    uint16_t stored_crc;
    uint16_t computed_crc;
    int fixederrs;      /* BCH blocks with corrected errors */
    /* Full BCH-decoded bitstream for parsed output */
    uint8_t bch_stream[256];
    int bch_len;
    lcw_t lcw;
    char lcw_header[128];   /* formatted LCW(...) string */
} ida_burst_t;

/* Reassembly slot */
typedef struct {
    int active;
    ir_direction_t direction;
    double frequency;
    uint64_t last_timestamp;
    int last_ctr;
    uint8_t data[256];
    int data_len;
} ida_reassembly_t;

#define IDA_MAX_REASSEMBLY 16

/* Reassembly context */
typedef struct {
    ida_reassembly_t slots[IDA_MAX_REASSEMBLY];
} ida_context_t;

/* Callback for completed IDA messages */
typedef void (*ida_message_cb)(const uint8_t *data, int len,
                                uint64_t timestamp, double frequency,
                                ir_direction_t direction, float magnitude,
                                void *user);

/* Initialize IDA BCH syndrome tables. Call once at startup. */
void ida_decode_init(void);

/* Try to decode a demodulated frame as IDA.
 * Returns 1 if IDA detected, fills burst. 0 otherwise. */
int ida_decode(const demod_frame_t *frame, ida_burst_t *burst);

/* Feed a decoded burst into the reassembly engine.
 * Calls cb when a complete message is assembled. Returns 1 if emitted. */
int ida_reassemble(ida_context_t *ctx, const ida_burst_t *burst,
                   ida_message_cb cb, void *user);

/* Flush timed-out reassembly slots (call every frame). */
void ida_reassemble_flush(ida_context_t *ctx, uint64_t now_ns);

#endif
