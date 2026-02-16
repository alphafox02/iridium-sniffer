/*
 * QPSK/DQPSK demodulator - port of gr-iridium's iridium_qpsk_demod
 *
 * Original work Copyright 2020 Free Software Foundation, Inc.
 * Modifications Copyright 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * QPSK/DQPSK demodulator - port of gr-iridium's iridium_qpsk_demod
 *
 * Pipeline: decimate -> PLL -> hard decision -> UW check ->
 *           DQPSK decode -> symbol-to-bits
 */

#ifndef __QPSK_DEMOD_H__
#define __QPSK_DEMOD_H__

#include <complex.h>
#include <stdint.h>
#include "burst_downmix.h"

/* Demodulated frame output */
typedef struct {
    uint64_t id;
    uint64_t timestamp;         /* nanoseconds */
    double center_frequency;    /* Hz */
    ir_direction_t direction;
    float magnitude;            /* dB */
    float noise;                /* dBFS/Hz */
    int confidence;             /* 0-100% */
    float level;                /* average signal amplitude */
    int n_symbols;              /* total symbols including UW */
    int n_payload_symbols;      /* symbols after UW */
    uint8_t *bits;              /* 2 bits per symbol (0 or 1 each) */
    float *llr;                 /* per-bit reliability (|distance from boundary|) */
    int n_bits;
} demod_frame_t;

/* Demodulate a downmixed frame. Returns 1 on success, 0 if frame invalid.
 * Caller owns returned frame and must free bits and frame. */
int qpsk_demod(downmix_frame_t *in, demod_frame_t **out);

/* Thread function: pulls from frame_queue, pushes to output_queue */
void *qpsk_demod_thread(void *arg);

#endif
