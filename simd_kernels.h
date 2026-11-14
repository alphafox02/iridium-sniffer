/*
 * SIMD kernel dispatch - runtime CPU feature detection
 *
 * Call simd_init() once at startup. All function pointers are then set
 * to either AVX2 or scalar implementations based on CPU capabilities.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef __SIMD_KERNELS_H__
#define __SIMD_KERNELS_H__

#include <complex.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ---- Aligned allocation helper ---- */

static inline void *aligned_alloc_32(size_t size) {
    /* Round up to multiple of 32 for AVX2 alignment */
    size = (size + 31) & ~(size_t)31;
    void *p = NULL;
    if (posix_memalign(&p, 32, size) != 0)
        return NULL;
    return p;
}

static inline void *aligned_calloc_32(size_t count, size_t size) {
    size_t total = count * size;
    void *p = aligned_alloc_32(total);
    if (p) memset(p, 0, total);
    return p;
}

/* Round up to next multiple of 8 (for zero-padded tap arrays) */
static inline int pad_to_8(int n) {
    return (n + 7) & ~7;
}

/* ---- Kernel function types ---- */

/* Complex FIR: real taps * complex input -> complex output */
typedef void (*simd_fir_ccf_fn)(const float *taps, int ntaps,
                                 const float complex *in,
                                 float complex *out, int n);

/* Decimating complex FIR */
typedef void (*simd_fir_ccf_dec_fn)(const float *taps, int ntaps,
                                     const float complex *in,
                                     float complex *out, int n_out,
                                     int decimation);

/* Real FIR: real taps * real input -> real output */
typedef void (*simd_fir_fff_fn)(const float *taps, int ntaps,
                                 const float *in, float *out, int n);

/* Complex window multiply: out[i] = samples[i] * window[i] (complex * real) */
typedef void (*simd_window_cf_fn)(const float complex *samples,
                                   const float *window,
                                   float complex *out, int n);

/* fftshift + magnitude-squared combined */
typedef void (*simd_fftshift_mag_fn)(const float complex *fft_out,
                                      float *mag_shifted, int fft_size);

/* Baseline update: sum[i] = sum[i] - old[i] + new[i] */
typedef void (*simd_baseline_update_fn)(float *sum, const float *old_hist,
                                         const float *new_mag, int n);

/* Relative magnitude with zero check: out[i] = mag[i] / base[i] or 0 */
typedef void (*simd_relative_mag_fn)(const float *mag, const float *baseline,
                                      float *out, int n);

/* int8 IQ pairs to float complex: out[i] = iq[2i]/128 + iq[2i+1]/128 * I */
typedef void (*simd_convert_i8_cf_fn)(const int8_t *iq, float complex *out,
                                       size_t n);

/* Magnitude-squared of complex array: out[i] = re*re + im*im */
typedef void (*simd_mag_squared_fn)(const float complex *in, float *out,
                                     int n);

/* Find max float in array */
typedef float (*simd_max_float_fn)(const float *in, int n);

/* Complex square with window: out[i] = in[i]*in[i] * window[i] */
typedef void (*simd_csquare_window_fn)(const float complex *in,
                                        const float *window,
                                        float complex *out, int n);

/* Frequency rotation: out[i] = in[i] * phase; phase *= incr after each
 * sample (*phase is updated). Works in blocks of ROTATOR_BLOCK with
 * precomputed steps; every implementation must match generic_rotate
 * bit for bit, so no FMA contraction. */
#define ROTATOR_BLOCK 8
typedef void (*simd_rotate_fn)(float complex *out, const float complex *in,
                               int n, float complex *phase,
                               float complex incr);

/* ---- Global function pointers (set by simd_init) ---- */

extern simd_fir_ccf_fn        simd_fir_ccf;
extern simd_fir_ccf_dec_fn    simd_fir_ccf_dec;
extern simd_fir_fff_fn        simd_fir_fff;
extern simd_window_cf_fn      simd_window_cf;
extern simd_fftshift_mag_fn   simd_fftshift_mag;
extern simd_baseline_update_fn simd_baseline_update;
extern simd_relative_mag_fn   simd_relative_mag;
extern simd_convert_i8_cf_fn  simd_convert_i8_cf;
extern simd_mag_squared_fn    simd_mag_squared;
extern simd_max_float_fn      simd_max_float;
extern simd_csquare_window_fn simd_csquare_window;
extern simd_rotate_fn         simd_rotate;

/* ---- Initialization ---- */

/* Detect CPU features and set function pointers.
 * If force_generic is nonzero, always use scalar fallback. */
void simd_init(int force_generic);

/* ---- Generic (scalar) implementations ---- */

void generic_fir_ccf(const float *taps, int ntaps,
                     const float complex *in, float complex *out, int n);
void generic_fir_ccf_dec(const float *taps, int ntaps,
                         const float complex *in, float complex *out,
                         int n_out, int decimation);
void generic_fir_fff(const float *taps, int ntaps,
                     const float *in, float *out, int n);
void generic_window_cf(const float complex *samples, const float *window,
                       float complex *out, int n);
void generic_fftshift_mag(const float complex *fft_out,
                          float *mag_shifted, int fft_size);
void generic_baseline_update(float *sum, const float *old_hist,
                             const float *new_mag, int n);
void generic_relative_mag(const float *mag, const float *baseline,
                          float *out, int n);
void generic_convert_i8_cf(const int8_t *iq, float complex *out, size_t n);
void generic_mag_squared(const float complex *in, float *out, int n);
float generic_max_float(const float *in, int n);
void generic_csquare_window(const float complex *in, const float *window,
                            float complex *out, int n);
void generic_rotate(float complex *out, const float complex *in, int n,
                    float complex *phase, float complex incr);

/* ---- ARM NEON implementations (AArch64 only) ---- */
#if defined(__aarch64__) || defined(_M_ARM64)

void neon_fir_ccf(const float *taps, int ntaps,
                  const float complex *in, float complex *out, int n);
void neon_fir_ccf_dec(const float *taps, int ntaps,
                      const float complex *in, float complex *out,
                      int n_out, int decimation);
void neon_fir_fff(const float *taps, int ntaps,
                  const float *in, float *out, int n);
void neon_window_cf(const float complex *samples, const float *window,
                    float complex *out, int n);
void neon_fftshift_mag(const float complex *fft_out,
                       float *mag_shifted, int fft_size);
void neon_baseline_update(float *sum, const float *old_hist,
                          const float *new_mag, int n);
void neon_relative_mag(const float *mag, const float *baseline,
                       float *out, int n);
void neon_convert_i8_cf(const int8_t *iq, float complex *out, size_t n);
void neon_mag_squared(const float complex *in, float *out, int n);
float neon_max_float(const float *in, int n);
void neon_csquare_window(const float complex *in, const float *window,
                         float complex *out, int n);

#endif /* __aarch64__ || _M_ARM64 */

/* ---- SIMD mode selection ---- */
typedef enum {
    SIMD_AUTO = 0,
    SIMD_AVX2,
    SIMD_SSE42,
    SIMD_NEON,
    SIMD_SCALAR,
} simd_mode_t;

/* ---- SSE4.2 implementations (x86 only) ---- */
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)

void sse42_fir_ccf(const float *taps, int ntaps,
                   const float complex *in, float complex *out, int n);
void sse42_fir_ccf_dec(const float *taps, int ntaps,
                       const float complex *in, float complex *out,
                       int n_out, int decimation);
void sse42_fir_fff(const float *taps, int ntaps,
                   const float *in, float *out, int n);
void sse42_window_cf(const float complex *samples, const float *window,
                     float complex *out, int n);
void sse42_fftshift_mag(const float complex *fft_out,
                        float *mag_shifted, int fft_size);
void sse42_baseline_update(float *sum, const float *old_hist,
                           const float *new_mag, int n);
void sse42_relative_mag(const float *mag, const float *baseline,
                        float *out, int n);
void sse42_convert_i8_cf(const int8_t *iq, float complex *out, size_t n);
void sse42_mag_squared(const float complex *in, float *out, int n);
float sse42_max_float(const float *in, int n);
void sse42_csquare_window(const float complex *in, const float *window,
                          float complex *out, int n);

/* ---- AVX2 implementations (x86 only) ---- */

void avx2_fir_ccf(const float *taps, int ntaps,
                   const float complex *in, float complex *out, int n);
void avx2_fir_ccf_dec(const float *taps, int ntaps,
                       const float complex *in, float complex *out,
                       int n_out, int decimation);
void avx2_fir_fff(const float *taps, int ntaps,
                   const float *in, float *out, int n);
void avx2_window_cf(const float complex *samples, const float *window,
                     float complex *out, int n);
void avx2_fftshift_mag(const float complex *fft_out,
                        float *mag_shifted, int fft_size);
void avx2_baseline_update(float *sum, const float *old_hist,
                           const float *new_mag, int n);
void avx2_relative_mag(const float *mag, const float *baseline,
                        float *out, int n);
void avx2_convert_i8_cf(const int8_t *iq, float complex *out, size_t n);
void avx2_mag_squared(const float complex *in, float *out, int n);
float avx2_max_float(const float *in, int n);
void avx2_csquare_window(const float complex *in, const float *window,
                          float complex *out, int n);
void avx2_rotate(float complex *out, const float complex *in, int n,
                 float complex *phase, float complex incr);

#endif /* x86 */

#endif /* __SIMD_KERNELS_H__ */
