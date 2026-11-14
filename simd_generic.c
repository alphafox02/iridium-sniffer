/*
 * SIMD kernel dispatch + scalar (generic) implementations
 *
 * The scalar versions are the exact same algorithms as the original code,
 * just refactored into standalone functions matching the simd_* API.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <math.h>
#include <stdio.h>
#include <string.h>

#include "simd_kernels.h"

/* ---- Global function pointers ---- */

simd_fir_ccf_fn        simd_fir_ccf        = NULL;
simd_fir_ccf_dec_fn    simd_fir_ccf_dec    = NULL;
simd_fir_fff_fn        simd_fir_fff        = NULL;
simd_window_cf_fn      simd_window_cf      = NULL;
simd_fftshift_mag_fn   simd_fftshift_mag   = NULL;
simd_baseline_update_fn simd_baseline_update = NULL;
simd_relative_mag_fn   simd_relative_mag   = NULL;
simd_convert_i8_cf_fn  simd_convert_i8_cf  = NULL;
simd_mag_squared_fn    simd_mag_squared    = NULL;
simd_max_float_fn      simd_max_float      = NULL;
simd_csquare_window_fn simd_csquare_window = NULL;
simd_rotate_fn         simd_rotate         = generic_rotate;

/* ---- Runtime dispatch ---- */

static void set_scalar(void) {
    simd_fir_ccf        = generic_fir_ccf;
    simd_fir_ccf_dec    = generic_fir_ccf_dec;
    simd_fir_fff        = generic_fir_fff;
    simd_window_cf      = generic_window_cf;
    simd_fftshift_mag   = generic_fftshift_mag;
    simd_baseline_update = generic_baseline_update;
    simd_relative_mag   = generic_relative_mag;
    simd_convert_i8_cf  = generic_convert_i8_cf;
    simd_mag_squared    = generic_mag_squared;
    simd_max_float      = generic_max_float;
    simd_csquare_window = generic_csquare_window;
    simd_rotate         = generic_rotate;
    fprintf(stderr, "iridium-sniffer: using scalar kernels\n");
}

#if defined(__aarch64__) || defined(_M_ARM64)
static void set_neon(void) {
    simd_fir_ccf         = neon_fir_ccf;
    simd_fir_ccf_dec     = neon_fir_ccf_dec;
    simd_fir_fff         = neon_fir_fff;
    simd_window_cf       = neon_window_cf;
    simd_fftshift_mag    = neon_fftshift_mag;
    simd_baseline_update = neon_baseline_update;
    simd_relative_mag    = neon_relative_mag;
    simd_convert_i8_cf   = neon_convert_i8_cf;
    simd_mag_squared     = neon_mag_squared;
    simd_max_float       = neon_max_float;
    simd_csquare_window  = neon_csquare_window;
    simd_rotate          = generic_rotate;
    fprintf(stderr, "iridium-sniffer: using NEON SIMD kernels\n");
}
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
static void set_sse42(void) {
    simd_fir_ccf        = sse42_fir_ccf;
    simd_fir_ccf_dec    = sse42_fir_ccf_dec;
    simd_fir_fff        = sse42_fir_fff;
    simd_window_cf      = sse42_window_cf;
    simd_fftshift_mag   = sse42_fftshift_mag;
    simd_baseline_update = sse42_baseline_update;
    simd_relative_mag   = sse42_relative_mag;
    simd_convert_i8_cf  = sse42_convert_i8_cf;
    simd_mag_squared    = sse42_mag_squared;
    simd_max_float      = sse42_max_float;
    simd_csquare_window = sse42_csquare_window;
    simd_rotate         = generic_rotate;
    fprintf(stderr, "iridium-sniffer: using SSE4.2 SIMD kernels\n");
}

static void set_avx2(void) {
    simd_fir_ccf        = avx2_fir_ccf;
    simd_fir_ccf_dec    = avx2_fir_ccf_dec;
    simd_fir_fff        = avx2_fir_fff;
    simd_window_cf      = avx2_window_cf;
    simd_fftshift_mag   = avx2_fftshift_mag;
    simd_baseline_update = avx2_baseline_update;
    simd_relative_mag   = avx2_relative_mag;
    simd_convert_i8_cf  = avx2_convert_i8_cf;
    simd_mag_squared    = avx2_mag_squared;
    simd_max_float      = avx2_max_float;
    simd_csquare_window = avx2_csquare_window;
    simd_rotate         = avx2_rotate;
    fprintf(stderr, "iridium-sniffer: using AVX2+FMA SIMD kernels\n");
}

static int cpu_has_avx2_fma(void) {
    return __builtin_cpu_supports("avx2") && __builtin_cpu_supports("fma");
}

static int cpu_has_sse42(void) {
    return __builtin_cpu_supports("sse4.2");
}
#endif

void simd_init(int mode) {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    switch ((simd_mode_t)mode) {
    case SIMD_AVX2:
        if (cpu_has_avx2_fma()) { set_avx2(); return; }
        fprintf(stderr, "iridium-sniffer: AVX2+FMA not available, ");
        if (cpu_has_sse42()) { fprintf(stderr, "falling back to SSE4.2\n"); set_sse42(); return; }
        fprintf(stderr, "falling back to scalar\n");
        set_scalar();
        return;
    case SIMD_SSE42:
        if (cpu_has_sse42()) { set_sse42(); return; }
        fprintf(stderr, "iridium-sniffer: SSE4.2 not available, falling back to scalar\n");
        set_scalar();
        return;
    case SIMD_SCALAR:
        set_scalar();
        return;
    case SIMD_AUTO:
    default:
        if (cpu_has_avx2_fma()) { set_avx2(); return; }
        if (cpu_has_sse42())    { set_sse42(); return; }
        set_scalar();
        return;
    }
#elif defined(__aarch64__) || defined(_M_ARM64)
    /* NEON is mandatory on AArch64 — part of the base ISA, always present.
     * Honour explicit --simd=scalar / --no-simd overrides only. */
    if ((simd_mode_t)mode == SIMD_SCALAR) {
        fprintf(stderr, "iridium-sniffer: using scalar kernels (forced)\n");
        set_scalar();
    } else {
        set_neon();
    }
#else
    (void)mode;
    set_scalar();
#endif
}

/* ---- Generic implementations ---- */

void generic_fir_ccf(const float *taps, int ntaps,
                     const float complex *in, float complex *out, int n) {
    for (int i = 0; i < n; i++) {
        float complex acc = 0;
        for (int k = 0; k < ntaps; k++)
            acc += taps[k] * in[i + k];
        out[i] = acc;
    }
}

void generic_fir_ccf_dec(const float *taps, int ntaps,
                         const float complex *in, float complex *out,
                         int n_out, int decimation) {
    for (int i = 0; i < n_out; i++) {
        float complex acc = 0;
        const float complex *p = &in[i * decimation];
        for (int k = 0; k < ntaps; k++)
            acc += taps[k] * p[k];
        out[i] = acc;
    }
}

void generic_fir_fff(const float *taps, int ntaps,
                     const float *in, float *out, int n) {
    for (int i = 0; i < n; i++) {
        float acc = 0;
        for (int k = 0; k < ntaps; k++)
            acc += taps[k] * in[i + k];
        out[i] = acc;
    }
}

void generic_window_cf(const float complex *samples, const float *window,
                       float complex *out, int n) {
    for (int i = 0; i < n; i++)
        out[i] = samples[i] * window[i];
}

void generic_fftshift_mag(const float complex *fft_out,
                          float *mag_shifted, int fft_size) {
    int half = fft_size / 2;
    for (int i = 0; i < half; i++) {
        float re, im;
        re = crealf(fft_out[half + i]);
        im = cimagf(fft_out[half + i]);
        mag_shifted[i] = re * re + im * im;

        re = crealf(fft_out[i]);
        im = cimagf(fft_out[i]);
        mag_shifted[half + i] = re * re + im * im;
    }
}

void generic_baseline_update(float *sum, const float *old_hist,
                             const float *new_mag, int n) {
    for (int i = 0; i < n; i++) {
        sum[i] -= old_hist[i];
        sum[i] += new_mag[i];
    }
}

void generic_relative_mag(const float *mag, const float *baseline,
                          float *out, int n) {
    for (int i = 0; i < n; i++) {
        if (baseline[i] > 0)
            out[i] = mag[i] / baseline[i];
        else
            out[i] = 0;
    }
}

void generic_convert_i8_cf(const int8_t *iq, float complex *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        float re = iq[2 * i] / 128.0f;
        float im = iq[2 * i + 1] / 128.0f;
        out[i] = re + im * I;
    }
}

void generic_mag_squared(const float complex *in, float *out, int n) {
    for (int i = 0; i < n; i++) {
        float re = crealf(in[i]);
        float im = cimagf(in[i]);
        out[i] = re * re + im * im;
    }
}

float generic_max_float(const float *in, int n) {
    float max_val = -1e30f;
    for (int i = 0; i < n; i++) {
        if (in[i] > max_val)
            max_val = in[i];
    }
    return max_val;
}

void generic_csquare_window(const float complex *in, const float *window,
                            float complex *out, int n) {
    for (int i = 0; i < n; i++) {
        float complex s = in[i];
        out[i] = s * s * window[i];
    }
}

/* ---- Frequency rotation ---- */

/* Blocks of ROTATOR_BLOCK with precomputed steps break the serial phase
 * dependency; the phase is renormalized every 64 blocks. */
void generic_rotate(float complex *out, const float complex *in, int n,
                    float complex *phase, float complex incr) {
    float sr[ROTATOR_BLOCK], si[ROTATOR_BLOCK];
    float complex p = 1.0f;
    for (int k = 0; k < ROTATOR_BLOCK; k++) {
        sr[k] = crealf(p);
        si[k] = cimagf(p);
        p *= incr;
    }
    float complex block_incr = p;
    float complex ph = *phase;

    const float *x = (const float *)in;
    float *y = (float *)out;
    int i = 0;
    for (; i + ROTATOR_BLOCK <= n; i += ROTATOR_BLOCK) {
        float pr = crealf(ph), pi = cimagf(ph);
        for (int k = 0; k < ROTATOR_BLOCK; k++) {
            float wr = pr * sr[k] - pi * si[k];
            float wi = pr * si[k] + pi * sr[k];
            float xr = x[2 * (i + k)], xi = x[2 * (i + k) + 1];
            y[2 * (i + k)] = xr * wr - xi * wi;
            y[2 * (i + k) + 1] = xr * wi + xi * wr;
        }
        ph *= block_incr;
        if ((i & (64 * ROTATOR_BLOCK - 1)) == 0) {
            /* |phase| stays near 1: one Newton step for 1/|phase| */
            float m2 = crealf(ph) * crealf(ph) + cimagf(ph) * cimagf(ph);
            ph *= 0.5f * (3.0f - m2);
        }
    }
    for (; i < n; i++) {
        out[i] = in[i] * ph;
        ph *= incr;
    }
    *phase = ph;
}
