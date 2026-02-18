/*
 * Burst downmix pipeline - port of gr-iridium's burst_downmix_impl.cc
 *
 * Coarse CFO correction → LPF + decimation to 250 kHz (10 sps) →
 * Noise-limiting LPF (20 kHz cutoff) → Burst start detection →
 * Fine CFO (squared FFT + quadratic interpolation) → RRC matched filter →
 * FFT-based sync word correlation (DL + UL patterns) → Phase alignment →
 * Frame extraction
 *
 * Original work Copyright 2020 Free Software Foundation, Inc.
 * Modifications Copyright 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * Burst downmix pipeline - port of gr-iridium's burst_downmix_impl
 *
 * Each burst goes through: coarse CFO -> decimate -> find start ->
 * fine CFO -> RRC filter -> sync word correlate -> phase align -> extract
 */

#define _GNU_SOURCE
#include <complex.h>
#include <math.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fftw3.h>

#include "burst_downmix.h"
#include "fftw_lock.h"
#include "fir_filter.h"
#include "iridium.h"
#include "rotator.h"
#include "simd_kernels.h"
#include "window_func.h"

#include "blocking_queue.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* ---- Externs ---- */

extern Blocking_Queue burst_queue;
extern Blocking_Queue frame_queue;
extern volatile sig_atomic_t running;
extern int verbose;
/* ---- Constants ---- */

#define CFO_FFT_OVERSAMPLE  16
#define RRC_NTAPS           51
#define RC_NTAPS            51
#define RRC_ALPHA           0.4f
#define START_THRESHOLD     0.28f
#define PRE_START_US        100  /* microseconds before burst start */

/* ---- Internal state ---- */

struct _burst_downmix {
    /* Configuration */
    int output_sample_rate;
    int search_depth;
    int handle_multiple_frames;
    float samples_per_symbol;

    /* Filters */
    fir_filter_t *input_fir;    /* anti-alias LPF for decimation */
    fir_filter_t *noise_fir;    /* noise-limiting LPF after decimation */
    fir_filter_t *start_fir;    /* magnitude smoothing */
    fir_filter_t *rrc_fir;      /* root-raised-cosine matched filter */
    fir_filter_t *rc_fir;       /* raised-cosine for sync word gen */

    /* CFO estimation FFT */
    int cfo_fft_size;           /* base FFT size */
    int cfo_fft_total;          /* base * oversample factor */
    fftwf_plan cfo_fft_plan;
    float complex *cfo_fft_in;
    float complex *cfo_fft_out;
    float *cfo_window;          /* Blackman window for CFO */

    /* Correlation FFT */
    int corr_fft_size;
    int sync_search_len;
    fftwf_plan corr_fwd_plan;
    float complex *corr_fwd_in;
    float complex *corr_fwd_out;

    fftwf_plan corr_dl_ifft_plan;
    float complex *corr_dl_ifft_in;
    float complex *corr_dl_ifft_out;

    fftwf_plan corr_ul_ifft_plan;
    float complex *corr_ul_ifft_in;
    float complex *corr_ul_ifft_out;

    /* Pre-computed sync word FFTs */
    float complex *dl_sync_fft;
    float complex *ul_sync_fft;
    int dl_sync_len;  /* in samples */
    int ul_sync_len;

    /* Working buffers (sized for max burst) */
    float complex *work_a;
    float complex *work_b;
    float *mag_f;
    float *mag_filtered_f;
    int work_size;

    /* Pre-start samples */
    int pre_start_samples;
};

/* ---- Utility: next power of 2 ---- */

static int next_pow2(int n) {
    int p = 1;
    while (p < n) p <<= 1;
    return p;
}

/* ---- Utility: FFT shift/unshift ---- */

static int fft_unshift_index(int idx, int size) {
    return idx >= size / 2 ? idx - size : idx;
}

static int fft_shift_index(int idx, int size) {
    return idx < 0 ? idx + size : idx;
}

/* ---- Sync word generation ---- */

static void generate_sync_word(burst_downmix_t *dm, const int *uw, int uw_len,
                               int preamble_len, int is_uplink,
                               float complex **fft_out, int *sync_len_out) {
    float sps = dm->samples_per_symbol;

    /* Build symbol sequence: preamble + unique word */
    float complex s0 = 1.0f + 1.0f * I;   /* normalized below */
    float complex s1 = -1.0f - 1.0f * I;

    int total_symbols;
    float complex *symbols;

    if (is_uplink) {
        /* Uplink preamble: alternating s1, s0 pairs */
        total_symbols = preamble_len + uw_len;
        symbols = calloc(total_symbols, sizeof(float complex));
        for (int i = 0; i < preamble_len; i++)
            symbols[i] = (i % 2 == 0) ? s1 : s0;
    } else {
        /* Downlink preamble: all s0 */
        total_symbols = preamble_len + uw_len;
        symbols = calloc(total_symbols, sizeof(float complex));
        for (int i = 0; i < preamble_len; i++)
            symbols[i] = s0;
    }

    /* Add unique word */
    for (int i = 0; i < uw_len; i++) {
        symbols[preamble_len + i] = (uw[i] == 0) ? s0 : s1;
    }

    /* Upsample: insert (sps-1) zeros between each symbol */
    int isps = (int)roundf(sps);
    int padded_len = total_symbols * isps - (isps - 1);
    float complex *padded = calloc(padded_len, sizeof(float complex));
    for (int i = 0; i < total_symbols; i++)
        padded[i * isps] = symbols[i];
    free(symbols);

    /* Apply RC filter (pulse shaping) with padding */
    int half_rc = (dm->rc_fir->ntaps - 1) / 2;
    int buf_len = padded_len + dm->rc_fir->ntaps - 1;
    float complex *buf = calloc(buf_len, sizeof(float complex));
    memcpy(buf + half_rc, padded, padded_len * sizeof(float complex));

    float complex *shaped = malloc(padded_len * sizeof(float complex));
    fir_filter_ccf(dm->rc_fir, shaped, buf, padded_len);
    free(buf);
    free(padded);

    /* Reverse and conjugate for correlation template */
    for (int i = 0; i < padded_len / 2; i++) {
        float complex tmp = shaped[i];
        shaped[i] = conjf(shaped[padded_len - 1 - i]);
        shaped[padded_len - 1 - i] = conjf(tmp);
    }
    if (padded_len % 2)
        shaped[padded_len / 2] = conjf(shaped[padded_len / 2]);

    /* Compute FFT of sync word template (zero-padded to corr_fft_size) */
    float complex *sync_fft_in = fftwf_alloc_complex(dm->corr_fft_size);
    float complex *sync_fft_result = fftwf_alloc_complex(dm->corr_fft_size);
    memset(sync_fft_in, 0, dm->corr_fft_size * sizeof(float complex));
    int copy_len = padded_len < dm->corr_fft_size ? padded_len : dm->corr_fft_size;
    memcpy(sync_fft_in, shaped, copy_len * sizeof(float complex));
    free(shaped);

    fftw_lock();
    fftwf_plan plan = fftwf_plan_dft_1d(dm->corr_fft_size,
                                         sync_fft_in, sync_fft_result,
                                         FFTW_FORWARD, FFTW_ESTIMATE);
    fftw_unlock();
    fftwf_execute(plan);

    fftw_lock();
    fftwf_destroy_plan(plan);
    fftw_unlock();
    fftwf_free(sync_fft_in);

    *fft_out = sync_fft_result;
    *sync_len_out = padded_len;
}

/* ---- Create downmix context ---- */

burst_downmix_t *burst_downmix_create(downmix_config_t *config) {
    burst_downmix_t *dm = calloc(1, sizeof(*dm));

    /* Output sample rate: default = sps * symbol_rate */
    int default_sps = IR_DEFAULT_SPS;  /* ~10 sps as starting point */
    if (config && config->output_sample_rate > 0) {
        dm->output_sample_rate = config->output_sample_rate;
    } else {
        /* gr-iridium uses 153125 Hz for 6.125 sps at 25 ksps.
         * We compute a reasonable rate from sps. */
        dm->output_sample_rate = default_sps * IR_SYMBOLS_PER_SECOND;
    }

    dm->samples_per_symbol = (float)dm->output_sample_rate / IR_SYMBOLS_PER_SECOND;
    dm->search_depth = (config && config->search_depth > 0)
        ? config->search_depth : dm->output_sample_rate;
    dm->handle_multiple_frames = config ? config->handle_multiple_frames : 0;

    dm->pre_start_samples = (int)(PRE_START_US * 1e-6f * dm->output_sample_rate);

    if (verbose) {
        fprintf(stderr, "burst_downmix: output_rate=%d Hz, sps=%.3f, "
                "search_depth=%d, pre_start=%d\n",
                dm->output_sample_rate, dm->samples_per_symbol,
                dm->search_depth, dm->pre_start_samples);
    }

    /* ---- Input anti-alias LPF ---- */
    {
        float cutoff = dm->output_sample_rate * 0.4f;
        float transition = dm->output_sample_rate * 0.2f;
        /* Use a reasonable input sample rate for tap design.
         * The actual decimation ratio depends on the burst's input rate.
         * We design for a generic 10 MHz input. */
        int ntaps;
        float *taps = lpf_taps(&ntaps, 1.0f, 10000000.0f, cutoff, transition);
        dm->input_fir = fir_filter_create(taps, ntaps);
        free(taps);
    }

    /* ---- Noise-limiting LPF (applied after decimation) ---- */
    {
        float burst_width = 40000.0f;  /* Hz, matches IR_DEFAULT_BURST_WIDTH */
        int ntaps;
        float *taps = lpf_taps(&ntaps, 1.0f, (float)dm->output_sample_rate,
                                burst_width / 2.0f, burst_width);
        dm->noise_fir = fir_filter_create(taps, ntaps);
        free(taps);
        if (verbose) {
            fprintf(stderr, "burst_downmix: noise LPF: %d taps, cutoff=%.0f Hz, "
                    "transition=%.0f Hz at %d Hz\n",
                    dm->noise_fir->ntaps, burst_width / 2.0f, burst_width,
                    dm->output_sample_rate);
        }
    }

    /* ---- Magnitude smoothing filter (box filter) ---- */
    {
        int box_len = (int)(dm->samples_per_symbol * 2);
        if (box_len < 3) box_len = 3;
        int ntaps;
        float *taps = box_taps(&ntaps, box_len);
        dm->start_fir = fir_filter_create(taps, ntaps);
        free(taps);
    }

    /* ---- RRC matched filter ---- */
    {
        int ntaps;
        float *taps = rrc_taps(&ntaps, 1.0f, (float)dm->output_sample_rate,
                                (float)IR_SYMBOLS_PER_SECOND, RRC_ALPHA, RRC_NTAPS);
        dm->rrc_fir = fir_filter_create(taps, ntaps);
        free(taps);
    }

    /* ---- RC filter for sync word generation ---- */
    {
        int ntaps;
        float *taps = rc_taps(&ntaps, (float)dm->output_sample_rate,
                               (float)IR_SYMBOLS_PER_SECOND, RRC_ALPHA, RC_NTAPS);
        dm->rc_fir = fir_filter_create(taps, ntaps);
        free(taps);
    }

    /* ---- CFO estimation FFT ---- */
    /* Use floor-to-power-of-2 (like gr-iridium) to keep window within preamble+UW */
    {
        int raw = (int)(dm->samples_per_symbol * 26);
        dm->cfo_fft_size = 1;
        while (dm->cfo_fft_size * 2 <= raw)
            dm->cfo_fft_size *= 2;
    }
    dm->cfo_fft_total = dm->cfo_fft_size * CFO_FFT_OVERSAMPLE;
    dm->cfo_fft_in = fftwf_alloc_complex(dm->cfo_fft_total);
    dm->cfo_fft_out = fftwf_alloc_complex(dm->cfo_fft_total);

    /* CFO Blackman window */
    dm->cfo_window = malloc(sizeof(float) * dm->cfo_fft_size);
    blackman_window(dm->cfo_window, dm->cfo_fft_size);

    /* ---- Correlation FFT ---- */
    int sync_search_symbols = IR_PREAMBLE_LENGTH_LONG + IR_UW_LENGTH + 8;
    dm->sync_search_len = (int)(sync_search_symbols * dm->samples_per_symbol);

    /* Need sync word length to determine corr FFT size. */
    int ul_sync_symbols = IR_PREAMBLE_LENGTH_SHORT + IR_UW_LENGTH;
    int ul_sync_samples = (int)(ul_sync_symbols * dm->samples_per_symbol);
    dm->corr_fft_size = next_pow2(dm->sync_search_len + ul_sync_samples);

    dm->corr_fwd_in = fftwf_alloc_complex(dm->corr_fft_size);
    dm->corr_fwd_out = fftwf_alloc_complex(dm->corr_fft_size);
    dm->corr_dl_ifft_in = fftwf_alloc_complex(dm->corr_fft_size);
    dm->corr_dl_ifft_out = fftwf_alloc_complex(dm->corr_fft_size);
    dm->corr_ul_ifft_in = fftwf_alloc_complex(dm->corr_fft_size);
    dm->corr_ul_ifft_out = fftwf_alloc_complex(dm->corr_fft_size);

    /* All FFTW plan creation must be serialized (not thread-safe) */
    fftw_lock();
    dm->cfo_fft_plan = fftwf_plan_dft_1d(dm->cfo_fft_total,
                                          dm->cfo_fft_in, dm->cfo_fft_out,
                                          FFTW_FORWARD, FFTW_MEASURE);
    dm->corr_fwd_plan = fftwf_plan_dft_1d(dm->corr_fft_size,
                                            dm->corr_fwd_in, dm->corr_fwd_out,
                                            FFTW_FORWARD, FFTW_MEASURE);
    dm->corr_dl_ifft_plan = fftwf_plan_dft_1d(dm->corr_fft_size,
                                                dm->corr_dl_ifft_in,
                                                dm->corr_dl_ifft_out,
                                                FFTW_BACKWARD, FFTW_MEASURE);
    dm->corr_ul_ifft_plan = fftwf_plan_dft_1d(dm->corr_fft_size,
                                                dm->corr_ul_ifft_in,
                                                dm->corr_ul_ifft_out,
                                                FFTW_BACKWARD, FFTW_MEASURE);
    fftw_unlock();

    /* Generate sync word FFTs */
    generate_sync_word(dm, IR_UW_DL, IR_UW_LENGTH,
                       IR_PREAMBLE_LENGTH_SHORT, 0,
                       &dm->dl_sync_fft, &dm->dl_sync_len);
    generate_sync_word(dm, IR_UW_UL, IR_UW_LENGTH,
                       IR_PREAMBLE_LENGTH_SHORT, 1,
                       &dm->ul_sync_fft, &dm->ul_sync_len);

    /* ---- Working buffers (generous size, aligned for SIMD) ---- */
    dm->work_size = 2 * 1024 * 1024;  /* 2M samples max */
    dm->work_a = aligned_alloc_32(sizeof(float complex) * dm->work_size);
    dm->work_b = aligned_alloc_32(sizeof(float complex) * dm->work_size);
    dm->mag_f = aligned_alloc_32(sizeof(float) * dm->work_size);
    dm->mag_filtered_f = aligned_alloc_32(sizeof(float) * dm->work_size);

    return dm;
}

void burst_downmix_destroy(burst_downmix_t *dm) {
    if (!dm) return;

    fir_filter_destroy(dm->input_fir);
    fir_filter_destroy(dm->noise_fir);
    fir_filter_destroy(dm->start_fir);
    fir_filter_destroy(dm->rrc_fir);
    fir_filter_destroy(dm->rc_fir);

    fftw_lock();
    fftwf_destroy_plan(dm->cfo_fft_plan);
    fftwf_destroy_plan(dm->corr_fwd_plan);
    fftwf_destroy_plan(dm->corr_dl_ifft_plan);
    fftwf_destroy_plan(dm->corr_ul_ifft_plan);
    fftw_unlock();

    fftwf_free(dm->cfo_fft_in);
    fftwf_free(dm->cfo_fft_out);
    free(dm->cfo_window);

    fftwf_free(dm->corr_fwd_in);
    fftwf_free(dm->corr_fwd_out);

    fftwf_free(dm->corr_dl_ifft_in);
    fftwf_free(dm->corr_dl_ifft_out);

    fftwf_free(dm->corr_ul_ifft_in);
    fftwf_free(dm->corr_ul_ifft_out);

    fftwf_free(dm->dl_sync_fft);
    fftwf_free(dm->ul_sync_fft);

    free(dm->work_a);
    free(dm->work_b);
    free(dm->mag_f);
    free(dm->mag_filtered_f);

    free(dm);
}

/* ---- Step 2: Decimate ---- */

static int decimate_burst(burst_downmix_t *dm, const float complex *in, int in_len,
                           float complex *out, int in_sample_rate,
                           uint64_t *timestamp) {
    int decimation = (int)roundf((float)in_sample_rate / dm->output_sample_rate);
    if (decimation < 1) decimation = 1;

    int n_out = (in_len - dm->input_fir->ntaps + 1) / decimation;
    if (n_out <= 0) return 0;
    if (n_out > dm->work_size) n_out = dm->work_size;

    fir_filter_ccf_dec(dm->input_fir, out, in, n_out, decimation);

    /* Adjust timestamp for filter delay */
    if (timestamp) {
        uint64_t delay_ns = (uint64_t)((dm->input_fir->ntaps / 2) *
                            1000000000ULL / in_sample_rate);
        *timestamp += delay_ns;
    }

    return n_out;
}

/* ---- Step 3: Find burst start ---- */

static int find_burst_start(burst_downmix_t *dm, const float complex *frame,
                             int frame_len) {
    int search = dm->search_depth;
    if (search > frame_len) search = frame_len;

    int mag_len = search + dm->start_fir->ntaps - 1;
    if (mag_len > frame_len) mag_len = frame_len;

    /* Compute magnitude squared (SIMD-accelerated) */
    simd_mag_squared(frame, dm->mag_f, mag_len);

    /* Smooth magnitude */
    int half_fir = (dm->start_fir->ntaps - 1) / 2;
    int filtered_len = mag_len - dm->start_fir->ntaps + 1;
    if (filtered_len <= 0) return 0;
    if (filtered_len > search) filtered_len = search;

    fir_filter_fff(dm->start_fir, dm->mag_filtered_f, dm->mag_f, filtered_len);

    /* Find peak (SIMD-accelerated) */
    float max_val = simd_max_float(dm->mag_filtered_f, filtered_len);

    /* Find first sample above threshold */
    float threshold = START_THRESHOLD * max_val;
    int start = 0;
    for (start = 0; start < filtered_len; start++) {
        if (dm->mag_filtered_f[start] >= threshold)
            break;
    }

    /* Back up slightly to capture preamble */
    if (start > 0) {
        start = start + half_fir - dm->pre_start_samples;
        if (start < 0) start = 0;
    }

    return start;
}

/* ---- Step 4: Fine CFO estimation ---- */

static float estimate_fine_cfo(burst_downmix_t *dm, const float complex *frame,
                                int frame_len) {
    int n = dm->cfo_fft_size;
    if (n > frame_len) n = frame_len;

    /* Square the signal (removes BPSK, creates tone at 2x CFO) */
    memset(dm->cfo_fft_in, 0, dm->cfo_fft_total * sizeof(float complex));
    simd_csquare_window(frame, dm->cfo_window, dm->cfo_fft_in, n);

    /* FFT */
    fftwf_execute(dm->cfo_fft_plan);

    /* Find peak magnitude */
    float max_mag = 0;
    int max_idx_shifted = 0;
    for (int i = 0; i < dm->cfo_fft_total; i++) {
        float re = crealf(dm->cfo_fft_out[i]);
        float im = cimagf(dm->cfo_fft_out[i]);
        float m = re * re + im * im;
        if (m > max_mag) {
            max_mag = m;
            max_idx_shifted = i;
        }
    }

    int max_idx = fft_unshift_index(max_idx_shifted, dm->cfo_fft_total);

    /* Quadratic interpolation */
    float correction = 0;
    if (max_idx_shifted > 0 && max_idx_shifted < dm->cfo_fft_total - 1) {
        int idx_m1 = fft_shift_index(max_idx - 1, dm->cfo_fft_total);
        int idx_p1 = fft_shift_index(max_idx + 1, dm->cfo_fft_total);

        float re, im;
        re = crealf(dm->cfo_fft_out[idx_m1]);
        im = cimagf(dm->cfo_fft_out[idx_m1]);
        float alpha = re * re + im * im;

        float beta = max_mag;

        re = crealf(dm->cfo_fft_out[idx_p1]);
        im = cimagf(dm->cfo_fft_out[idx_p1]);
        float gamma = re * re + im * im;

        float denom = alpha - 2.0f * beta + gamma;
        if (fabsf(denom) > 1e-10f)
            correction = 0.5f * (alpha - gamma) / denom;
    }

    /* Normalize: divide by FFT size and by 2 (because we squared) */
    float center_offset = (max_idx + correction) / dm->cfo_fft_total / 2.0f;

    return center_offset;
}

/* ---- Step 7: Sync word correlation ---- */

static int correlate_sync(burst_downmix_t *dm, const float complex *frame,
                           int frame_len, ir_direction_t *direction,
                           float *uw_start_correction,
                           float complex *corr_result_out) {
    int search_len = dm->sync_search_len;
    if (search_len > frame_len) search_len = frame_len;

    /* Forward FFT of signal */
    memset(dm->corr_fwd_in, 0, dm->corr_fft_size * sizeof(float complex));
    memcpy(dm->corr_fwd_in, frame, search_len * sizeof(float complex));
    fftwf_execute(dm->corr_fwd_plan);

    /* Frequency-domain multiply: signal_fft * sync_fft */
    /* (sync word is already reversed+conjugated, so this is correlation) */
    for (int i = 0; i < dm->corr_fft_size; i++) {
        dm->corr_dl_ifft_in[i] = dm->corr_fwd_out[i] * dm->dl_sync_fft[i];
        dm->corr_ul_ifft_in[i] = dm->corr_fwd_out[i] * dm->ul_sync_fft[i];
    }

    /* Inverse FFTs */
    fftwf_execute(dm->corr_dl_ifft_plan);
    fftwf_execute(dm->corr_ul_ifft_plan);

    /* Find DL correlation peak */
    float max_dl = 0;
    int offset_dl = 0;
    for (int i = 0; i < search_len; i++) {
        float re = crealf(dm->corr_dl_ifft_out[i]);
        float im = cimagf(dm->corr_dl_ifft_out[i]);
        float m = re * re + im * im;
        if (m > max_dl) {
            max_dl = m;
            offset_dl = i;
        }
    }

    /* Find UL correlation peak */
    float max_ul = 0;
    int offset_ul = 0;
    for (int i = 0; i < search_len; i++) {
        float re = crealf(dm->corr_ul_ifft_out[i]);
        float im = cimagf(dm->corr_ul_ifft_out[i]);
        float m = re * re + im * im;
        if (m > max_ul) {
            max_ul = m;
            offset_ul = i;
        }
    }

    /* Select best direction */
    int corr_offset;
    float complex *ifft_out;
    int sync_len;

    if (max_dl >= max_ul) {
        *direction = DIR_DOWNLINK;
        corr_offset = offset_dl;
        ifft_out = dm->corr_dl_ifft_out;
        sync_len = dm->dl_sync_len;
    } else {
        *direction = DIR_UPLINK;
        corr_offset = offset_ul;
        ifft_out = dm->corr_ul_ifft_out;
        sync_len = dm->ul_sync_len;
    }

    *corr_result_out = ifft_out[corr_offset];

    /* Quadratic interpolation on correlation peak */
    float correction = 0;
    if (corr_offset > 0 && corr_offset < search_len - 1) {
        float re, im;
        re = crealf(ifft_out[corr_offset - 1]);
        im = cimagf(ifft_out[corr_offset - 1]);
        float alpha = re * re + im * im;

        re = crealf(ifft_out[corr_offset]);
        im = cimagf(ifft_out[corr_offset]);
        float beta = re * re + im * im;

        re = crealf(ifft_out[corr_offset + 1]);
        im = cimagf(ifft_out[corr_offset + 1]);
        float gamma = re * re + im * im;

        float denom = alpha - 2.0f * beta + gamma;
        if (fabsf(denom) > 1e-10f)
            correction = 0.5f * (alpha - gamma) / denom;
    }
    *uw_start_correction = correction;

    /* Preamble starts at: corr_offset - sync_len + 1 */
    int preamble_offset = corr_offset - sync_len + 1;

    /* UW starts after preamble (16 symbols for DL, 32 for UL) */
    int preamble_symbols = (*direction == DIR_DOWNLINK)
        ? IR_PREAMBLE_LENGTH_SHORT : 32;
    int uw_start = preamble_offset +
                   (int)(preamble_symbols * dm->samples_per_symbol);

    return uw_start;
}

/* ---- Process one burst ---- */

int burst_downmix_process(burst_downmix_t *dm, burst_data_t *burst,
                          downmix_frame_t **frames_out) {
    if (!burst || burst->num_samples < 100) {
        *frames_out = NULL;
        return 0;
    }

    int n = (int)burst->num_samples;
    if (n > dm->work_size) n = dm->work_size;

    /* Copy burst samples to working buffer */
    memcpy(dm->work_a, burst->samples, n * sizeof(float complex));

    double center_frequency = burst->center_frequency;
    int in_sample_rate = burst->sample_rate;
    /* Compute absolute timestamp: wall clock base + sample offset */
    uint64_t timestamp = burst->start_time_ns +
        (uint64_t)((double)burst->info.start / in_sample_rate * 1e9);

    /* Step 1: Coarse CFO correction */
    float relative_freq = (burst->info.center_bin - burst->fft_size / 2)
                          / (float)burst->fft_size;
    {
        rotator_t r;
        rotator_init(&r);
        float phase_inc = -2.0f * (float)M_PI * relative_freq;
        rotator_set_phase_incr(&r, cexpf(phase_inc * I));
        rotator_rotate_n(&r, dm->work_a, dm->work_a, n);
        center_frequency += relative_freq * in_sample_rate;
    }

    /* Step 2: Decimate to output sample rate */
    int dec_len = decimate_burst(dm, dm->work_a, n, dm->work_b,
                                  in_sample_rate, &timestamp);
    if (dec_len < 100) {
        *frames_out = NULL;
        return 0;
    }

    /* Step 2b: Noise-limiting LPF */
    {
        int nlpf_len = dec_len - dm->noise_fir->ntaps + 1;
        if (nlpf_len > 0) {
            int half_noise = (dm->noise_fir->ntaps - 1) / 2;
            /* Pad for centered convolution */
            int pad_len = dec_len + dm->noise_fir->ntaps - 1;
            if (pad_len > dm->work_size) pad_len = dm->work_size;
            memset(dm->work_a, 0, pad_len * sizeof(float complex));
            memcpy(&dm->work_a[half_noise], dm->work_b,
                   dec_len * sizeof(float complex));
            fir_filter_ccf(dm->noise_fir, dm->work_b, dm->work_a, dec_len);
            memcpy(dm->work_a, dm->work_b, dec_len * sizeof(float complex));
        } else {
            memcpy(dm->work_a, dm->work_b, dec_len * sizeof(float complex));
        }
    }

    /* Step 3: Find burst start */
    int start = find_burst_start(dm, dm->work_a, dec_len);
    if (start >= dec_len - 100) {
        *frames_out = NULL;
        return 0;
    }

    int frame_len = dec_len - start;

    /* Step 4: Fine CFO estimation */
    float center_offset = estimate_fine_cfo(dm, &dm->work_a[start], frame_len);

    /* Step 5: Fine CFO correction */
    {
        rotator_t r;
        rotator_init(&r);
        float phase_inc = -2.0f * (float)M_PI * center_offset;
        rotator_set_phase_incr(&r, cexpf(phase_inc * I));
        rotator_rotate_n(&r, dm->work_b, &dm->work_a[start], frame_len);
        center_frequency += center_offset * dm->output_sample_rate;
    }

    /* Step 6: RRC matched filtering */
    {
        int half_rrc = (dm->rrc_fir->ntaps - 1) / 2;
        int pad_len = frame_len + dm->rrc_fir->ntaps - 1;
        if (pad_len > dm->work_size) pad_len = dm->work_size;

        /* Zero-pad for same-length convolution */
        memset(dm->work_a, 0, pad_len * sizeof(float complex));
        memcpy(&dm->work_a[half_rrc], dm->work_b,
               frame_len * sizeof(float complex));

        fir_filter_ccf(dm->rrc_fir, dm->work_b, dm->work_a, frame_len);
    }

    /* Step 7: Sync word correlation */
    ir_direction_t direction;
    float uw_start_correction;
    float complex corr_result;
    int uw_start = correlate_sync(dm, dm->work_b, frame_len,
                                   &direction, &uw_start_correction,
                                   &corr_result);

    if (uw_start < 0 || uw_start >= frame_len) {
        *frames_out = NULL;
        return 0;
    }

    /* Step 8: Phase alignment */
    {
        float mag = cabsf(corr_result);
        float complex phase_correction = (mag > 0)
            ? conjf(corr_result / mag) : 1.0f;

        rotator_t r;
        rotator_init(&r);
        rotator_set_phase(&r, phase_correction);
        rotator_set_phase_incr(&r, 1.0f);
        rotator_rotate_n(&r, dm->work_a, dm->work_b, frame_len);
    }

    /* Step 9: Frame extraction */
    int max_frame_len, min_frame_len;
    if (center_frequency > IR_SIMPLEX_FREQUENCY_MIN) {
        max_frame_len = (int)(IR_MAX_FRAME_LENGTH_SIMPLEX * dm->samples_per_symbol);
        min_frame_len = (int)(IR_MIN_FRAME_LENGTH_SIMPLEX * dm->samples_per_symbol);
    } else {
        max_frame_len = (int)(IR_MAX_FRAME_LENGTH_NORMAL * dm->samples_per_symbol);
        min_frame_len = (int)(IR_MIN_FRAME_LENGTH_NORMAL * dm->samples_per_symbol);
    }

    int available = frame_len - uw_start;
    if (available < min_frame_len) {
        *frames_out = NULL;
        return 0;
    }

    int extract_len = available < max_frame_len ? available : max_frame_len;

    /* Build output frame */
    downmix_frame_t *frame = malloc(sizeof(*frame));
    frame->id = burst->info.id;
    frame->timestamp = timestamp + (uint64_t)((double)start / dm->output_sample_rate * 1e9);
    frame->center_frequency = center_frequency;
    frame->sample_rate = (float)dm->output_sample_rate;
    frame->samples_per_symbol = dm->samples_per_symbol;
    frame->direction = direction;
    frame->magnitude = burst->info.magnitude;
    frame->noise = burst->info.noise;
    frame->uw_start = uw_start_correction;
    frame->num_samples = extract_len;
    frame->samples = malloc(sizeof(float complex) * extract_len);
    memcpy(frame->samples, &dm->work_a[uw_start], extract_len * sizeof(float complex));

    *frames_out = frame;
    return 1;
}

/* ---- Thread function ---- */

void *burst_downmix_thread(void *arg) {
    burst_downmix_t *dm = (burst_downmix_t *)arg;

    while (1) {
        burst_data_t *burst;
        if (blocking_queue_take(&burst_queue, &burst) != 0)
            break;

        downmix_frame_t *frames = NULL;
        int n_frames = burst_downmix_process(dm, burst, &frames);

        if (n_frames > 0 && frames) {
            /* Push frame to queue (process returns a single malloc'd frame) */
            if (blocking_queue_add(&frame_queue, frames) == BQ_FULL) {
                free(frames->samples);
                free(frames);
            }
        } else {
            free(frames);
        }

        free(burst->samples);
        free(burst);
    }

    burst_downmix_destroy(dm);
    return NULL;
}
