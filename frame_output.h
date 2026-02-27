/*
 * Frame output in iridium-toolkit RAW format
 * Port of gr-iridium's iridium_frame_printer
 *
 * Original work Copyright 2021 gr-iridium author
 * Modifications Copyright 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * Frame output in iridium-toolkit RAW format
 */

#ifndef __FRAME_OUTPUT_H__
#define __FRAME_OUTPUT_H__

#include "qpsk_demod.h"

/* Initialize frame output. file_info is borrowed, must remain valid.
 * If NULL, auto-generates from first timestamp. */
void frame_output_init(const char *file_info);

/* Print one demodulated frame in iridium-toolkit RAW format to stdout. */
void frame_output_print(demod_frame_t *frame);

#include "ida_decode.h"

/* Print one decoded IDA burst in iridium-parser.py parsed format to stdout. */
void frame_output_print_ida(const ida_burst_t *burst);

/* ZMQ PUB output for multi-consumer iridium-toolkit compatibility */
#ifdef HAVE_ZMQ
int frame_output_zmq_init(const char *endpoint);
void frame_output_zmq_shutdown(void);
#endif

#endif
