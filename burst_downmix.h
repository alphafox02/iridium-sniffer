/*
 * Burst downmix pipeline - port of gr-iridium's burst_downmix
 *
 * Original work Copyright 2020 Free Software Foundation, Inc.
 * Modifications Copyright 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * Burst downmix pipeline - port of gr-iridium's burst_downmix_impl
 *
 * Per-burst processing:
 *   1. Coarse CFO correction (frequency shift to center)
 *   2. Low-pass filter + decimation to output sample rate
 *   3. Burst start detection (magnitude threshold)
 *   4. Fine CFO estimation (squared signal FFT + interpolation)
 *   5. Fine CFO correction
 *   6. RRC matched filtering
 *   7. Sync word correlation (FFT-based, DL+UL)
 *   8. Phase alignment
 *   9. Frame extraction
 */

#ifndef __BURST_DOWNMIX_H__
#define __BURST_DOWNMIX_H__

#include <complex.h>
#include <stdint.h>
#include "burst_detect.h"

/* Direction of transmission */
typedef enum {
    DIR_UNDEF = 0,
    DIR_DOWNLINK = 1,
    DIR_UPLINK = 2,
} ir_direction_t;

/* Processed frame ready for demodulation */
typedef struct {
    uint64_t id;
    uint64_t timestamp;         /* nanoseconds */
    double center_frequency;    /* Hz, after all CFO corrections */
    float sample_rate;          /* output sample rate */
    float samples_per_symbol;
    ir_direction_t direction;
    float magnitude;            /* SNR dB from detector */
    float noise;                /* dBFS/Hz from detector */
    float uw_start;             /* sub-sample correction */
    size_t num_samples;
    float complex *samples;     /* IQ data starting at unique word */
} downmix_frame_t;

/* Downmix context (opaque, holds FFT plans and filters) */
typedef struct _burst_downmix burst_downmix_t;

/* Configuration */
typedef struct {
    int output_sample_rate;     /* 0 = auto (based on sps * symbol_rate) */
    int search_depth;           /* first-frame search with multiple frames,
                                   output samples (0 = 7 ms) */
    int handle_multiple_frames; /* allow multiple frames per burst */
} downmix_config_t;

/* Create a downmix context */
burst_downmix_t *burst_downmix_create(downmix_config_t *config);

/* Most frames taken from one burst */
#define DOWNMIX_MAX_FRAMES 8

/* Process one burst into up to max_frames frames (more than one only with
 * handle_multiple_frames). Each frame is malloc'd, as are its samples;
 * the caller frees both. Returns the number of frames. */
int burst_downmix_process(burst_downmix_t *dm, burst_data_t *burst,
                          downmix_frame_t **frames_out, int max_frames);

/* Destroy */
void burst_downmix_destroy(burst_downmix_t *dm);

/* Thread function: pulls from burst_queue, pushes frames to frame_queue */
void *burst_downmix_thread(void *arg);

#endif
