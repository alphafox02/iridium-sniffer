/*
 * FFT burst detector - port of gr-iridium's fft_burst_tagger
 *
 * Original work Copyright 2020 Free Software Foundation, Inc.
 * Modifications Copyright 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * FFT burst detector - port of gr-iridium's fft_burst_tagger
 *
 * Detects Iridium satellite bursts using sliding FFT with adaptive
 * noise floor estimation. Accumulates IQ samples per burst and pushes
 * complete burst buffers to burst_queue when burst ends.
 */

#ifndef __BURST_DETECT_H__
#define __BURST_DETECT_H__

#include <complex.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <fftw3.h>

/* Forward declaration */
struct _burst_detector;
typedef struct _burst_detector burst_detector_t;

/* Detected burst metadata */
typedef struct {
    uint64_t id;
    uint64_t start;         /* absolute sample index */
    uint64_t stop;          /* absolute sample index */
    uint64_t last_active;   /* last sample index above threshold */
    int center_bin;         /* FFT bin of burst center */
    float magnitude;        /* SNR in dB */
    float noise;            /* noise floor in dBFS/Hz */
} burst_info_t;

/* Complete burst, ready for downstream processing. Its IQ data stays in
 * the detector's ring and is read with burst_samples_begin/end; the
 * detector copies it out first if the ring is about to overwrite it. */
typedef struct {
    burst_info_t info;
    double center_frequency;  /* absolute center freq of capture */
    int sample_rate;          /* capture sample rate */
    int fft_size;             /* FFT size used for detection */
    uint64_t start_time_ns;   /* wall clock ns at sample 0 (base offset) */
    size_t num_samples;       /* number of complex float samples */

    /* Private to burst_detect.c */
    uint64_t data_start;            /* absolute index of the first sample */
    const float complex *seg[2];    /* the samples in the ring */
    size_t seg_len[2];
    float complex *copy;            /* set once copied out of the ring */
    atomic_int state;
    atomic_int refs;
} burst_data_t;

/* IQ data covering the burst lifetime, in up to two pieces (the second is
 * empty unless the data wraps the ring). Valid until burst_samples_end. */
void burst_samples_begin(burst_data_t *b, const float complex *seg[2],
                         size_t len[2]);
void burst_samples_end(burst_data_t *b);

/* Drop the consumer's reference (ends any read still open) */
void burst_release(burst_data_t *b);

/* Configuration */
typedef struct {
    double center_frequency;
    int sample_rate;
    int fft_size;           /* 0 = auto-calculate (~1ms window) */
    int burst_pre_len;      /* 0 = auto (2 * fft_size) */
    int burst_post_len;     /* 0 = auto (sample_rate * 16ms) */
    int burst_width;        /* Hz, default 40000 */
    int max_bursts;         /* 0 = auto (80% of channels) */
    int max_burst_len;      /* 0 = auto (sample_rate * 90ms) */
    float threshold;        /* dB, default 16.0 */
    int history_size;       /* default 512 */
    int use_gpu;            /* 1 = use OpenCL GPU FFT, 0 = FFTW CPU */
} burst_config_t;

/* Create a burst detector with the given configuration.
 * Unset fields (0) get reasonable defaults. */
burst_detector_t *burst_detector_create(burst_config_t *config);

/* Callback for completed bursts. Receives one reference to the burst,
 * dropped with burst_release. */
typedef void (*burst_callback_t)(burst_data_t *burst, void *user);

/* Feed int8 IQ samples to the detector. */
void burst_detector_feed(burst_detector_t *det, const int8_t *iq,
                         size_t num_samples, burst_callback_t cb, void *user);

/* Feed float32 interleaved IQ samples (no int8 quantization loss). */
void burst_detector_feed_cf32(burst_detector_t *det, const float *iq,
                              size_t num_samples, burst_callback_t cb, void *user);

/* Get number of active bursts */
int burst_detector_active_count(burst_detector_t *det);

/* Get total detected burst count */
uint64_t burst_detector_total_count(burst_detector_t *det);

/* Get average noise floor in dBFS/Hz (for diagnostic display) */
float burst_detector_noise_floor(burst_detector_t *det);

/* Get peak signal level in dB (for diagnostic display) */
float burst_detector_peak_signal(burst_detector_t *det);

/* Destroy and free all resources */
void burst_detector_destroy(burst_detector_t *det);

/* Thread function: pulls from samples_queue, pushes to burst_queue */
void *burst_detector_thread(void *arg);

#endif
