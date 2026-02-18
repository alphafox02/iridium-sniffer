/*
 * Burst detection pipeline - port of gr-iridium's fft_burst_tagger_impl.cc
 *
 * Windowed FFT → Magnitude computation → Threshold detection → Burst aggregation
 * with hysteresis and max-hold
 *
 * Original work Copyright 2020 Free Software Foundation, Inc.
 * Modifications Copyright 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#define _GNU_SOURCE
#include <complex.h>
#include <math.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <fftw3.h>

#include "burst_detect.h"
#include "fftw_lock.h"
#include "iridium.h"
#include "sdr.h"
#include "simd_kernels.h"
#include "window_func.h"

#include "blocking_queue.h"

#ifdef USE_GPU
#include "burst_fft.h"
#endif

/* ---- Internal types ---- */

typedef struct {
    uint64_t id;
    uint64_t start;
    uint64_t stop;
    uint64_t last_active;
    int center_bin;
    float magnitude;
    float noise;
} active_burst_t;

typedef struct {
    int bin;
    float relative_magnitude;
} peak_t;

/* ---- Burst detector state ---- */

struct _burst_detector {
    /* Configuration */
    double center_frequency;
    int sample_rate;
    int fft_size;
    int burst_pre_len;
    int burst_post_len;
    int burst_width;        /* in FFT bins */
    int max_bursts;
    int max_burst_len;
    float threshold;        /* pre-computed: pow(10, dB/10) / history_size / ENBW */
    int history_size;

    /* FFT */
    fftwf_plan fft_plan;
    float complex *fft_in;
    float complex *fft_out;

    /* Window */
    float *window;

    /* Noise floor estimation */
    float *baseline_history;    /* [history_size * fft_size] circular */
    float *baseline_sum;        /* [fft_size] running sum */
    int history_index;
    int history_primed;

    /* Per-FFT frame */
    float *magnitude_shifted;   /* [fft_size] DC-shifted mag^2 */
    float *relative_magnitude;  /* [fft_size] current / baseline */
    float *burst_mask;          /* [fft_size] 0 where burst active, 1 elsewhere */
    float *ones;                /* [fft_size] all 1.0 */

    /* Burst tracking */
    active_burst_t *bursts;
    int num_bursts;
    int bursts_cap;

    active_burst_t *new_bursts;
    int num_new_bursts;
    int new_bursts_cap;

    active_burst_t *gone_bursts;
    int num_gone_bursts;
    int gone_bursts_cap;

    peak_t *peaks;
    int num_peaks;

    uint64_t burst_id;
    uint64_t n_tagged_bursts;
    uint64_t sample_count;
    uint64_t index;             /* current absolute sample position */
    int squelch_count;

    /* Diagnostic tracking */
    float peak_signal_db;       /* maximum signal seen (for diagnostic mode) */

    /* IQ ringbuffer for burst sample extraction */
    float complex *ringbuf;
    size_t ringbuf_size;        /* total capacity in samples */
    size_t ringbuf_write;       /* write position (mod ringbuf_size) */
    uint64_t ringbuf_start;     /* absolute sample index of oldest sample */

    /* int8 -> float complex conversion buffer */
    float complex *convert_buf;
    size_t convert_buf_size;

    /* Timestamp */
    uint64_t start_time_ns;     /* nanosecond timestamp at sample 0 */

#ifdef USE_GPU
    /* GPU acceleration */
    gpu_burst_fft_t *gpu;
    int gpu_batch_size;         /* max frames per GPU dispatch */
    int gpu_batch_count;        /* frames accumulated so far */
    float *gpu_batch_input;     /* batch_size * fft_size * 2 floats (complex) */
    float *gpu_batch_output;    /* batch_size * fft_size floats (magnitude) */
#endif
};

/* ---- Externs for threading integration ---- */

extern Blocking_Queue samples_queue;
extern Blocking_Queue burst_queue;
extern volatile sig_atomic_t running;
extern int verbose;
extern atomic_ulong stat_n_detected;
extern atomic_ulong stat_n_dropped;

/* ---- Helper: dynamic array push ---- */

static void push_burst(active_burst_t **arr, int *count, int *cap, active_burst_t *b) {
    if (*count >= *cap) {
        *cap = *cap ? *cap * 2 : 64;
        *arr = realloc(*arr, *cap * sizeof(active_burst_t));
    }
    (*arr)[(*count)++] = *b;
}

static void remove_burst(active_burst_t *arr, int *count, int idx) {
    if (idx < *count - 1)
        memmove(&arr[idx], &arr[idx + 1], (*count - idx - 1) * sizeof(active_burst_t));
    (*count)--;
}

/* ---- Peak comparison for qsort (descending magnitude) ---- */

static int peak_cmp_desc(const void *a, const void *b) {
    float ma = ((const peak_t *)a)->relative_magnitude;
    float mb = ((const peak_t *)b)->relative_magnitude;
    if (ma > mb) return -1;
    if (ma < mb) return 1;
    return 0;
}

/* ---- Create burst detector ---- */

burst_detector_t *burst_detector_create(burst_config_t *config) {
    burst_detector_t *d = calloc(1, sizeof(*d));

    d->center_frequency = config->center_frequency;
    d->sample_rate = config->sample_rate;

    /* FFT size: ~1ms window, nearest power of 2 */
    if (config->fft_size > 0) {
        d->fft_size = config->fft_size;
    } else {
        int n = (int)round(log2(config->sample_rate / 1000.0));
        d->fft_size = 1 << n;
    }

    /* Burst pre/post lengths */
    d->burst_pre_len = config->burst_pre_len > 0
        ? config->burst_pre_len
        : 2 * d->fft_size;

    d->burst_post_len = config->burst_post_len > 0
        ? config->burst_post_len
        : (int)(config->sample_rate * 16e-3);

    /* Burst width in FFT bins */
    int burst_width_hz = config->burst_width > 0
        ? config->burst_width
        : IR_DEFAULT_BURST_WIDTH;
    d->burst_width = burst_width_hz / (config->sample_rate / d->fft_size);

    /* Max bursts */
    if (config->max_bursts > 0) {
        d->max_bursts = config->max_bursts;
    } else {
        d->max_bursts = (int)((config->sample_rate / (float)burst_width_hz) * 0.8f);
    }

    /* Max burst length in samples */
    d->max_burst_len = config->max_burst_len > 0
        ? config->max_burst_len
        : (int)(config->sample_rate * 0.09);

    d->history_size = config->history_size > 0
        ? config->history_size
        : IR_DEFAULT_HISTORY_SIZE;

    /* Threshold: convert from dB to linear, normalized */
    float threshold_db = config->threshold > 0
        ? config->threshold
        : IR_DEFAULT_THRESHOLD;

    /* ENBW of Blackman window */
    float window_enbw = 1.72f;
    d->threshold = powf(10.0f, threshold_db / 10.0f) / d->history_size / window_enbw;

    if (verbose) {
        fprintf(stderr, "burst_detect: fft_size=%d, threshold=%.1f dB (linear=%e), "
                "history=%d, burst_width=%d bins, max_bursts=%d, "
                "pre_len=%d, post_len=%d, max_len=%d\n",
                d->fft_size, threshold_db, d->threshold,
                d->history_size, d->burst_width, d->max_bursts,
                d->burst_pre_len, d->burst_post_len, d->max_burst_len);
    }

    /* Allocate FFT */
    d->fft_in = fftwf_alloc_complex(d->fft_size);
    d->fft_out = fftwf_alloc_complex(d->fft_size);
    fftw_lock();
    d->fft_plan = fftwf_plan_dft_1d(d->fft_size,
                                     d->fft_in, d->fft_out,
                                     FFTW_FORWARD, FFTW_MEASURE);
    fftw_unlock();

    /* Window: Blackman scaled by 1/0.42 for accurate SNR */
    d->window = aligned_alloc_32(sizeof(float) * d->fft_size);
    blackman_window(d->window, d->fft_size);
    for (int i = 0; i < d->fft_size; i++)
        d->window[i] /= 0.42f;

    /* Noise floor arrays (aligned for SIMD) */
    d->baseline_history = aligned_calloc_32(d->fft_size * d->history_size, sizeof(float));
    d->baseline_sum = aligned_calloc_32(d->fft_size, sizeof(float));
    d->magnitude_shifted = aligned_calloc_32(d->fft_size, sizeof(float));
    d->relative_magnitude = aligned_calloc_32(d->fft_size, sizeof(float));
    d->burst_mask = aligned_alloc_32(sizeof(float) * d->fft_size);
    d->ones = aligned_alloc_32(sizeof(float) * d->fft_size);

    for (int i = 0; i < d->fft_size; i++) {
        d->burst_mask[i] = 1.0f;
        d->ones[i] = 1.0f;
    }

    d->history_index = 0;
    d->history_primed = 0;

    /* Peak array */
    d->peaks = malloc(sizeof(peak_t) * d->fft_size);
    d->num_peaks = 0;

    /* Burst arrays (start small, grow as needed) */
    d->bursts_cap = 64;
    d->bursts = malloc(sizeof(active_burst_t) * d->bursts_cap);
    d->num_bursts = 0;

    d->new_bursts_cap = 64;
    d->new_bursts = malloc(sizeof(active_burst_t) * d->new_bursts_cap);
    d->num_new_bursts = 0;

    d->gone_bursts_cap = 64;
    d->gone_bursts = malloc(sizeof(active_burst_t) * d->gone_bursts_cap);
    d->num_gone_bursts = 0;

    d->burst_id = 0;
    d->n_tagged_bursts = 0;
    d->sample_count = 0;
    d->index = 0;
    d->squelch_count = 0;

    /* IQ ringbuffer: hold enough for max burst + pre + post + headroom */
    d->ringbuf_size = d->max_burst_len + d->burst_pre_len + d->burst_post_len
                      + d->fft_size * 4;
    /* Minimum 2 seconds */
    if (d->ringbuf_size < (size_t)(2 * d->sample_rate))
        d->ringbuf_size = 2 * d->sample_rate;
    d->ringbuf = malloc(sizeof(float complex) * d->ringbuf_size);
    d->ringbuf_write = 0;
    d->ringbuf_start = 0;

    /* Timestamp: set when first samples arrive */
    d->start_time_ns = 0;

#ifdef USE_GPU
    /* GPU acceleration */
    d->gpu = NULL;
    if (config->use_gpu) {
        d->gpu_batch_size = 16;
        d->gpu = gpu_burst_fft_create(d->fft_size, d->gpu_batch_size, d->window);
        if (d->gpu) {
            d->gpu_batch_count = 0;
            d->gpu_batch_input = malloc(sizeof(float) * 2 * d->fft_size
                                        * d->gpu_batch_size);
            d->gpu_batch_output = malloc(sizeof(float) * d->fft_size
                                         * d->gpu_batch_size);
        } else {
            fprintf(stderr, "burst_detect: GPU init failed, falling back to CPU\n");
        }
    }
#endif

    return d;
}

void burst_detector_destroy(burst_detector_t *d) {
    if (!d) return;
#ifdef USE_GPU
    if (d->gpu) {
        gpu_burst_fft_destroy(d->gpu);
        free(d->gpu_batch_input);
        free(d->gpu_batch_output);
    }
#endif
    fftwf_destroy_plan(d->fft_plan);
    fftwf_free(d->fft_in);
    fftwf_free(d->fft_out);
    free(d->window);
    free(d->baseline_history);
    free(d->baseline_sum);
    free(d->magnitude_shifted);
    free(d->relative_magnitude);
    free(d->burst_mask);
    free(d->ones);
    free(d->peaks);
    free(d->bursts);
    free(d->new_bursts);
    free(d->gone_bursts);
    free(d->ringbuf);
    free(d->convert_buf);
    fprintf(stderr, "burst_detect: tagged %lu bursts total\n",
            (unsigned long)d->n_tagged_bursts);
    free(d);
}

int burst_detector_active_count(burst_detector_t *d) {
    return d->num_bursts;
}

uint64_t burst_detector_total_count(burst_detector_t *d) {
    return d->n_tagged_bursts;
}

float burst_detector_noise_floor(burst_detector_t *d) {
    if (!d || !d->baseline_sum || d->history_size == 0)
        return 0.0f;

    /* Average baseline across all FFT bins */
    double sum = 0;
    for (int i = 0; i < d->fft_size; i++)
        sum += d->baseline_sum[i];

    float avg = (float)(sum / (d->fft_size * d->history_size));

    /* Convert to dBFS/Hz: 10*log10(mag^2 / bin_width) */
    float bin_width = (float)d->sample_rate / d->fft_size;
    if (avg > 0 && bin_width > 0)
        return 10.0f * log10f(avg / bin_width);

    return -120.0f;  /* Return very low value if no data */
}

float burst_detector_peak_signal(burst_detector_t *d) {
    if (!d)
        return 0.0f;
    return d->peak_signal_db;
}

/* ---- Internal: ringbuffer operations ---- */

static void ringbuf_write(burst_detector_t *d, const float complex *samples, size_t n) {
    for (size_t i = 0; i < n; i++) {
        d->ringbuf[d->ringbuf_write] = samples[i];
        d->ringbuf_write = (d->ringbuf_write + 1) % d->ringbuf_size;
    }
    /* Update the oldest available sample index */
    uint64_t total_written = d->sample_count;
    if (total_written > d->ringbuf_size)
        d->ringbuf_start = total_written - d->ringbuf_size;
}

static float complex *ringbuf_extract(burst_detector_t *d, uint64_t start,
                                       uint64_t stop, size_t *out_len) {
    /* Clamp to available range */
    if (start < d->ringbuf_start)
        start = d->ringbuf_start;
    if (stop <= start) {
        *out_len = 0;
        return NULL;
    }

    size_t len = (size_t)(stop - start);
    float complex *buf = malloc(sizeof(float complex) * len);
    size_t rb_pos = (size_t)(start % d->ringbuf_size);

    for (size_t i = 0; i < len; i++) {
        buf[i] = d->ringbuf[rb_pos];
        rb_pos = (rb_pos + 1) % d->ringbuf_size;
    }

    *out_len = len;
    return buf;
}

/* ---- Internal: update noise floor (pre) ---- */

static int update_filters_pre(burst_detector_t *d) {
    if (!d->history_primed)
        return 0;

    /* relative_magnitude = magnitude_shifted / baseline_sum (SIMD-accelerated) */
    simd_relative_mag(d->magnitude_shifted, d->baseline_sum,
                      d->relative_magnitude, d->fft_size);
    return 1;
}

/* ---- Internal: update noise floor (post) ---- */

static void update_filters_post(burst_detector_t *d, int force) {
    /* Only update average when no bursts active (or forced) */
    if (d->num_bursts == 0 || force) {
        float *hist = d->baseline_history + d->history_index * d->fft_size;

        /* Baseline update: sum = sum - old_hist + new_mag (SIMD-accelerated) */
        simd_baseline_update(d->baseline_sum, hist,
                             d->magnitude_shifted, d->fft_size);
        memcpy(hist, d->magnitude_shifted, sizeof(float) * d->fft_size);

        d->history_index++;
        if (d->history_index == d->history_size) {
            d->history_primed = 1;
            d->history_index = 0;
        }
    }
}

/* ---- Internal: update active bursts ---- */

static void update_bursts(burst_detector_t *d) {
    for (int i = 0; i < d->num_bursts; i++) {
        active_burst_t *b = &d->bursts[i];
        int cb = b->center_bin;
        /* Check center bin and neighbors */
        if ((cb > 0 && d->relative_magnitude[cb - 1] > d->threshold) ||
            d->relative_magnitude[cb] > d->threshold ||
            (cb < d->fft_size - 1 && d->relative_magnitude[cb + 1] > d->threshold)) {
            b->last_active = d->index;
        }
    }
}

/* ---- Internal: mask a burst's frequency range ---- */

static void mask_burst(burst_detector_t *d, active_burst_t *b) {
    int clear_start = b->center_bin - d->burst_width / 2;
    int clear_stop = b->center_bin + d->burst_width / 2;
    if (clear_start < 0) clear_start = 0;
    if (clear_stop >= d->fft_size) clear_stop = d->fft_size - 1;
    memset(d->burst_mask + clear_start, 0,
           (clear_stop - clear_start + 1) * sizeof(float));
}

static void update_burst_mask(burst_detector_t *d) {
    memcpy(d->burst_mask, d->ones, sizeof(float) * d->fft_size);
    for (int i = 0; i < d->num_bursts; i++)
        mask_burst(d, &d->bursts[i]);
}

/* ---- Internal: delete gone bursts ---- */

static void delete_gone_bursts(burst_detector_t *d) {
    int update_noise = 0;
    int i = 0;

    while (i < d->num_bursts) {
        active_burst_t *b = &d->bursts[i];
        int long_burst = 0;

        if (d->max_burst_len > 0) {
            if (b->last_active - b->start > (uint64_t)d->max_burst_len) {
                update_noise = 1;
                long_burst = 1;
            }
        }

        if ((b->last_active + d->burst_post_len) <= d->index || long_burst) {
            b->stop = d->index;
            push_burst(&d->gone_bursts, &d->num_gone_bursts,
                       &d->gone_bursts_cap, b);
            remove_burst(d->bursts, &d->num_bursts, i);
            /* don't increment i, next element slid into position */
        } else {
            i++;
        }
    }

    if (update_noise)
        update_filters_post(d, 1);
}

/* ---- Internal: remove peaks near existing bursts ---- */

static void remove_peaks_around_bursts(burst_detector_t *d) {
    for (int i = 0; i < d->fft_size; i++)
        d->relative_magnitude[i] *= d->burst_mask[i];
}

/* ---- Internal: extract peaks above threshold ---- */

static void extract_peaks(burst_detector_t *d) {
    d->num_peaks = 0;
    int half_bw = d->burst_width / 2;

    /* DC notch: skip bins near center frequency to reject LO leakage / ADC
     * offset spikes.  Width of 3 bins (~3.7 kHz at 10 MHz / 8192-pt FFT)
     * covers typical SDR DC spikes without losing any real Iridium signal
     * (channels are 41.667 kHz wide and never centered at DC). */
    int dc_bin = d->fft_size / 2;
    int dc_notch_half = 3;  /* ±3 bins around DC */

    for (int bin = half_bw; bin < d->fft_size - half_bw; bin++) {
        if (bin >= dc_bin - dc_notch_half && bin <= dc_bin + dc_notch_half)
            continue;
        if (d->relative_magnitude[bin] > d->threshold) {
            d->peaks[d->num_peaks].bin = bin;
            d->peaks[d->num_peaks].relative_magnitude = d->relative_magnitude[bin];
            d->num_peaks++;
        }
    }

    /* Sort by magnitude descending */
    qsort(d->peaks, d->num_peaks, sizeof(peak_t), peak_cmp_desc);
}

/* ---- Internal: create new bursts from peaks ---- */

static void create_new_bursts(burst_detector_t *d) {
    d->num_new_bursts = 0;

    for (int i = 0; i < d->num_peaks; i++) {
        peak_t *p = &d->peaks[i];

        if (d->burst_mask[p->bin] == 0.0f)
            continue;

        active_burst_t b;
        memset(&b, 0, sizeof(b));
        b.id = d->burst_id;
        b.center_bin = p->bin;
        d->burst_id += 10;  /* leave room for sub-IDs downstream */

        /* Normalize relative magnitude for SNR estimate */
        b.magnitude = 10.0f * log10f(p->relative_magnitude * d->history_size * 1.72f);

        /* Track peak signal for diagnostic mode */
        if (b.magnitude > d->peak_signal_db)
            d->peak_signal_db = b.magnitude;

        /* Burst might have started one FFT frame earlier */
        b.start = d->index - d->burst_pre_len;
        b.last_active = b.start;

        /* Noise floor in dBFS/Hz */
        b.noise = 10.0f * log10f(d->baseline_sum[b.center_bin] / d->history_size
                                  / ((float)d->fft_size * d->fft_size)
                                  / 1.72f
                                  / ((float)d->sample_rate / d->fft_size));

        push_burst(&d->bursts, &d->num_bursts, &d->bursts_cap, &b);
        push_burst(&d->new_bursts, &d->num_new_bursts, &d->new_bursts_cap, &b);
        mask_burst(d, &b);
    }

    /* Squelch check */
    if (d->max_bursts > 0 && d->num_bursts > d->max_bursts) {
        if (verbose)
            fprintf(stderr, "burst_detect: squelch at %.3f s\n",
                    d->index / (float)d->sample_rate);

        d->num_new_bursts = 0;

        /* Move all non-just-created bursts to gone */
        int i = 0;
        while (i < d->num_bursts) {
            if (d->bursts[i].start != d->index - (uint64_t)d->burst_pre_len) {
                d->bursts[i].stop = d->index;
                push_burst(&d->gone_bursts, &d->num_gone_bursts,
                           &d->gone_bursts_cap, &d->bursts[i]);
                remove_burst(d->bursts, &d->num_bursts, i);
            } else {
                i++;
            }
        }
        /* Clear remaining */
        d->num_bursts = 0;
        update_burst_mask(d);

        d->squelch_count += 3;
        if (d->squelch_count >= 10) {
            if (verbose)
                fprintf(stderr, "burst_detect: resetting noise estimate\n");
            d->history_index = 0;
            d->history_primed = 0;
            memset(d->baseline_history, 0,
                   sizeof(float) * d->fft_size * d->history_size);
            memset(d->baseline_sum, 0, sizeof(float) * d->fft_size);
            d->squelch_count = 0;
        }
    } else {
        if (d->squelch_count > 0)
            d->squelch_count--;
    }
}

#ifdef USE_GPU
/* ---- Internal: run CPU state machine on pre-computed magnitude ---- */

static void process_magnitude_frame(burst_detector_t *d, const float *magnitude) {
    /* Copy GPU-computed magnitudes into detector state */
    memcpy(d->magnitude_shifted, magnitude, sizeof(float) * d->fft_size);

    /* Update filters and detect (same logic as CPU path) */
    if (update_filters_pre(d)) {
        update_bursts(d);
        remove_peaks_around_bursts(d);
        extract_peaks(d);
        delete_gone_bursts(d);
        update_burst_mask(d);
        create_new_bursts(d);
    }
    update_filters_post(d, 0);
}

/* ---- Internal: flush GPU batch and process results ---- */

static void gpu_flush_batch(burst_detector_t *d) {
    if (d->gpu_batch_count == 0)
        return;

    if (gpu_burst_fft_process(d->gpu, d->gpu_batch_input,
                               d->gpu_batch_output,
                               d->gpu_batch_count) != 0) {
        fprintf(stderr, "burst_detect: GPU processing failed\n");
        d->gpu_batch_count = 0;
        return;
    }

    /* Process each frame's magnitude through CPU state machine */
    for (int i = 0; i < d->gpu_batch_count; i++) {
        process_magnitude_frame(d, d->gpu_batch_output + i * d->fft_size);
        d->index += d->fft_size;
    }

    d->gpu_batch_count = 0;
}
#endif

/* ---- Internal: process one FFT frame ---- */

static void process_fft_frame(burst_detector_t *d, const float complex *samples) {
    /* Apply window and copy to FFT input (SIMD-accelerated) */
    simd_window_cf(samples, d->window, d->fft_in, d->fft_size);

    /* Execute FFT */
    fftwf_execute(d->fft_plan);

    /* DC shift (fftshift) + magnitude-squared (SIMD-accelerated) */
    simd_fftshift_mag(d->fft_out, d->magnitude_shifted, d->fft_size);

    /* Update filters and detect */
    if (update_filters_pre(d)) {
        update_bursts(d);
        remove_peaks_around_bursts(d);
        extract_peaks(d);
        delete_gone_bursts(d);
        update_burst_mask(d);
        create_new_bursts(d);
    }
    update_filters_post(d, 0);
}

/* ---- Internal: emit completed bursts ---- */

static void emit_gone_bursts(burst_detector_t *d, burst_callback_t cb, void *user) {
    for (int i = 0; i < d->num_gone_bursts; i++) {
        active_burst_t *ab = &d->gone_bursts[i];

        /* Extract IQ samples from ringbuffer */
        uint64_t extract_start = ab->start;
        uint64_t extract_stop = ab->stop + d->burst_pre_len;
        size_t num_samples;
        float complex *samples = ringbuf_extract(d, extract_start, extract_stop,
                                                  &num_samples);

        if (num_samples == 0) {
            free(samples);
            continue;
        }

        /* Build burst data */
        burst_data_t *bd = malloc(sizeof(*bd));
        bd->info = (burst_info_t){
            .id = ab->id,
            .start = ab->start,
            .stop = ab->stop,
            .last_active = ab->last_active,
            .center_bin = ab->center_bin,
            .magnitude = ab->magnitude,
            .noise = ab->noise,
        };
        bd->center_frequency = d->center_frequency;
        bd->sample_rate = d->sample_rate;
        bd->fft_size = d->fft_size;
        bd->start_time_ns = d->start_time_ns;
        bd->num_samples = num_samples;
        bd->samples = samples;

        cb(bd, user);
        d->n_tagged_bursts++;
        atomic_fetch_add(&stat_n_detected, 1);
    }
    d->num_gone_bursts = 0;
}

/* ---- Public: feed samples ---- */

void burst_detector_feed(burst_detector_t *d, const int8_t *iq,
                         size_t num_samples, burst_callback_t cb, void *user) {
    /* Convert int8 IQ pairs to float complex and store in ringbuffer.
     * Process FFT frames as they become available.
     *
     * We maintain a residual buffer for partial FFT frames.
     */

    /* Track timestamp */
    if (d->start_time_ns == 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        d->start_time_ns = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    }

    /* Convert int8 to float complex and write to ringbuffer */

    if (num_samples > d->convert_buf_size) {
        free(d->convert_buf);
        d->convert_buf_size = num_samples;
        d->convert_buf = aligned_alloc_32(sizeof(float complex) * d->convert_buf_size);
    }

    /* int8 IQ -> float complex (SIMD-accelerated) */
    simd_convert_i8_cf(iq, d->convert_buf, num_samples);

    /* Write to ringbuffer */
    ringbuf_write(d, d->convert_buf, num_samples);
    d->sample_count += num_samples;

    /* Process complete FFT frames */
#ifdef USE_GPU
    if (d->gpu) {
        /* GPU path: accumulate frames into batch, flush when full.
         * Use a local read cursor (read_idx) to track accumulation
         * position. d->index is only advanced by gpu_flush_batch
         * when the state machine actually processes each frame. */
        uint64_t read_idx = d->index;

        while (read_idx + d->fft_size <= d->sample_count) {
            size_t rb_pos = (size_t)(read_idx % d->ringbuf_size);
            float *dst = d->gpu_batch_input
                         + d->gpu_batch_count * d->fft_size * 2;

            /* Copy complex samples as interleaved float pairs */
            if (rb_pos + d->fft_size <= d->ringbuf_size) {
                memcpy(dst, &d->ringbuf[rb_pos],
                       sizeof(float complex) * d->fft_size);
            } else {
                size_t first = d->ringbuf_size - rb_pos;
                memcpy(dst, &d->ringbuf[rb_pos],
                       first * sizeof(float complex));
                memcpy(dst + first * 2, d->ringbuf,
                       (d->fft_size - first) * sizeof(float complex));
            }

            read_idx += d->fft_size;
            d->gpu_batch_count++;

            if (d->gpu_batch_count >= d->gpu_batch_size) {
                gpu_flush_batch(d);
                /* gpu_flush_batch advances d->index by batch_count * fft_size */

                if (d->num_gone_bursts > 0)
                    emit_gone_bursts(d, cb, user);
            }
        }

        /* Flush remaining partial batch */
        if (d->gpu_batch_count > 0)
            gpu_flush_batch(d);
    } else
#endif
    {
        /* CPU path: process one frame at a time */
        while (d->index + d->fft_size <= d->sample_count) {
            size_t rb_pos = (size_t)(d->index % d->ringbuf_size);

            if (rb_pos + d->fft_size <= d->ringbuf_size) {
                process_fft_frame(d, &d->ringbuf[rb_pos]);
            } else {
                float complex tmp[d->fft_size];
                size_t first = d->ringbuf_size - rb_pos;
                memcpy(tmp, &d->ringbuf[rb_pos], first * sizeof(float complex));
                memcpy(tmp + first, d->ringbuf,
                       (d->fft_size - first) * sizeof(float complex));
                process_fft_frame(d, tmp);
            }

            d->index += d->fft_size;
        }
    }

    /* Emit any completed bursts */
    if (d->num_gone_bursts > 0)
        emit_gone_bursts(d, cb, user);
}

/* ---- Public: feed float32 samples (no int8 quantization) ---- */

void burst_detector_feed_cf32(burst_detector_t *d, const float *iq,
                              size_t num_samples, burst_callback_t cb, void *user) {
    /* Track timestamp */
    if (d->start_time_ns == 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        d->start_time_ns = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    }

    /* Convert interleaved float pairs to float complex and write to ringbuffer */
    if (num_samples > d->convert_buf_size) {
        free(d->convert_buf);
        d->convert_buf_size = num_samples;
        d->convert_buf = malloc(sizeof(float complex) * d->convert_buf_size);
    }

    for (size_t i = 0; i < num_samples; i++)
        d->convert_buf[i] = iq[2 * i] + iq[2 * i + 1] * I;

    /* Write to ringbuffer */
    ringbuf_write(d, d->convert_buf, num_samples);
    d->sample_count += num_samples;

    /* Process complete FFT frames (identical to int8 path) */
#ifdef USE_GPU
    if (d->gpu) {
        uint64_t read_idx = d->index;

        while (read_idx + d->fft_size <= d->sample_count) {
            size_t rb_pos = (size_t)(read_idx % d->ringbuf_size);
            float *dst = d->gpu_batch_input
                         + d->gpu_batch_count * d->fft_size * 2;

            if (rb_pos + d->fft_size <= d->ringbuf_size) {
                memcpy(dst, &d->ringbuf[rb_pos],
                       sizeof(float complex) * d->fft_size);
            } else {
                size_t first = d->ringbuf_size - rb_pos;
                memcpy(dst, &d->ringbuf[rb_pos],
                       first * sizeof(float complex));
                memcpy(dst + first * 2, d->ringbuf,
                       (d->fft_size - first) * sizeof(float complex));
            }

            read_idx += d->fft_size;
            d->gpu_batch_count++;

            if (d->gpu_batch_count >= d->gpu_batch_size) {
                gpu_flush_batch(d);
                if (d->num_gone_bursts > 0)
                    emit_gone_bursts(d, cb, user);
            }
        }

        if (d->gpu_batch_count > 0)
            gpu_flush_batch(d);
    } else
#endif
    {
        while (d->index + d->fft_size <= d->sample_count) {
            size_t rb_pos = (size_t)(d->index % d->ringbuf_size);

            if (rb_pos + d->fft_size <= d->ringbuf_size) {
                process_fft_frame(d, &d->ringbuf[rb_pos]);
            } else {
                float complex tmp[d->fft_size];
                size_t first = d->ringbuf_size - rb_pos;
                memcpy(tmp, &d->ringbuf[rb_pos], first * sizeof(float complex));
                memcpy(tmp + first, d->ringbuf,
                       (d->fft_size - first) * sizeof(float complex));
                process_fft_frame(d, tmp);
            }

            d->index += d->fft_size;
        }
    }

    if (d->num_gone_bursts > 0)
        emit_gone_bursts(d, cb, user);
}

/* ---- Thread integration: callback that pushes to burst_queue ---- */

static void burst_to_queue(burst_data_t *burst, void *user) {
    Blocking_Queue *queue = (Blocking_Queue *)user;
    int ret = blocking_queue_put(queue, burst);
    if (ret != 0) {
        free(burst->samples);
        free(burst);
        atomic_fetch_add(&stat_n_dropped, 1);
    }
}

/* ---- Thread function ---- */

void *burst_detector_thread(void *arg) {
    burst_detector_t *det = (burst_detector_t *)arg;

    while (1) {
        sample_buf_t *samples;
        if (blocking_queue_take(&samples_queue, &samples) != 0)
            break;

        if (samples->format == SAMPLE_FMT_FLOAT)
            burst_detector_feed_cf32(det, (const float *)samples->samples,
                                     samples->num, burst_to_queue, &burst_queue);
        else
            burst_detector_feed(det, samples->samples, samples->num,
                               burst_to_queue, &burst_queue);
        free(samples);
    }

    burst_detector_destroy(det);
    return NULL;
}
