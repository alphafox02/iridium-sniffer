/*
 * Iridium frame decoder (IRA/IBC)
 * Based on iridium-toolkit bitsparser.py (muccc)
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * Iridium frame decoder: BCH, de-interleave, IRA/IBC field extraction
 * Parses demodulated bits into structured frame data for web map display.
 */

#ifndef __FRAME_DECODE_H__
#define __FRAME_DECODE_H__

#include <stdint.h>
#include "qpsk_demod.h"

typedef enum {
    FRAME_UNKNOWN = 0,
    FRAME_IRA,
    FRAME_IBC,
} frame_type_t;

typedef struct {
    int sat_id;
    int beam_id;
    double lat, lon;
    int alt;                /* km */
    int pos_xyz[3];         /* raw 12-bit signed XYZ (Doppler positioning) */
    int n_pages;
    struct {
        uint32_t tmsi;
        int msc_id;
    } pages[12];            /* max 12 paging blocks per IRA */
} ira_data_t;

typedef struct {
    int sat_id;
    int beam_id;
    int timeslot;
    int sv_blocking;
    int bc_type;            /* block 2 type field */
    uint32_t iri_time;      /* LBFC if bc_type==1, else 0 */
} ibc_data_t;

typedef struct {
    frame_type_t type;
    uint64_t timestamp;
    double frequency;
    union {
        ira_data_t ira;
        ibc_data_t ibc;
    };
} decoded_frame_t;

/* Initialize BCH syndrome tables. Call once at startup. */
void frame_decode_init(void);

/* Decode a demodulated frame. Returns 1 if IRA or IBC detected, 0 otherwise. */
int frame_decode(const demod_frame_t *frame, decoded_frame_t *out);

/* BCH utility functions (shared with ida_decode.c) */
uint32_t gf2_remainder(uint32_t poly, uint32_t val);
uint32_t bits_to_uint(const uint8_t *bits, int n);
void uint_to_bits(uint32_t val, uint8_t *bits, int n);

/* BCH(31,21) syndrome correction. Returns error count (0,1,2) or -1.
 * On success, *locator is set to the error XOR mask. */
int bch_31_21_correct(uint32_t syndrome, uint32_t *locator);

#endif
