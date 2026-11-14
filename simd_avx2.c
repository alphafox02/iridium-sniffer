/*
 * AVX2 + FMA SIMD kernel implementations
 *
 * This file is compiled with -mavx2 -mfma flags.
 * All functions match the signatures in simd_kernels.h.
 *
 * Complex float layout: interleaved [re0, im0, re1, im1, ...]
 * AVX2 __m256 holds 8 floats = 4 complex values.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <immintrin.h>
#include <complex.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "simd_kernels.h"

/* ---- Complex FIR filter (real taps * complex input) ----
 *
 * Strategy: Process 4 complex outputs at a time.
 * For each tap k, broadcast taps[k] to all 8 lanes,
 * load 4 complex inputs [i+k..i+k+3], FMA into accumulator.
 */
void avx2_fir_ccf(const float *taps, int ntaps,
                   const float complex *in, float complex *out, int n) {
    const float *inp = (const float *)in;
    float *outp = (float *)out;

    int i = 0;
    /* Process 4 complex outputs per iteration */
    for (; i + 3 < n; i += 4) {
        __m256 acc = _mm256_setzero_ps();
        for (int k = 0; k < ntaps; k++) {
            __m256 coeff = _mm256_set1_ps(taps[k]);
            __m256 data = _mm256_loadu_ps(&inp[(i + k) * 2]);
            acc = _mm256_fmadd_ps(coeff, data, acc);
        }
        _mm256_storeu_ps(&outp[i * 2], acc);
    }

    /* Scalar tail */
    for (; i < n; i++) {
        float acc_re = 0, acc_im = 0;
        for (int k = 0; k < ntaps; k++) {
            acc_re += taps[k] * inp[(i + k) * 2];
            acc_im += taps[k] * inp[(i + k) * 2 + 1];
        }
        outp[i * 2] = acc_re;
        outp[i * 2 + 1] = acc_im;
    }
}

/* ---- Decimating complex FIR ----
 *
 * Can't batch outputs easily due to stride, so vectorize inner tap loop.
 * Process taps 8 at a time (4 complex values), accumulate horizontally.
 */
void avx2_fir_ccf_dec(const float *taps, int ntaps,
                       const float complex *in, float complex *out,
                       int n_out, int decimation) {
    const float *inp = (const float *)in;
    float *outp = (float *)out;

    for (int i = 0; i < n_out; i++) {
        const float *p = &inp[i * decimation * 2];
        __m256 acc = _mm256_setzero_ps();
        int k = 0;

        /* Process 4 taps at a time (each tap applied to 1 complex = 2 floats,
         * but we pack 4 taps worth: 4 complex values = 8 floats) */
        for (; k + 3 < ntaps; k += 4) {
            /* Load 4 consecutive complex inputs */
            __m256 data = _mm256_loadu_ps(&p[k * 2]);
            /* Interleave coefficients: [t0,t0,t1,t1,t2,t2,t3,t3] */
            __m128 t4 = _mm_loadu_ps(&taps[k]);
            /* Duplicate each float: [t0,t1,t2,t3] -> [t0,t0,t1,t1 | t2,t2,t3,t3] */
            __m128 lo_pair = _mm_unpacklo_ps(t4, t4);
            __m128 hi_pair = _mm_unpackhi_ps(t4, t4);
            __m256 coeff = _mm256_set_m128(hi_pair, lo_pair);

            acc = _mm256_fmadd_ps(coeff, data, acc);
        }

        /* Horizontal sum of 4 complex accumulators -> 1 complex result */
        /* acc = [re0,im0,re1,im1 | re2,im2,re3,im3] */
        __m128 lo = _mm256_castps256_ps128(acc);
        __m128 hi = _mm256_extractf128_ps(acc, 1);
        __m128 sum = _mm_add_ps(lo, hi);  /* [re0+re2, im0+im2, re1+re3, im1+im3] */
        /* Pair-wise add: (re0+re2)+(re1+re3), (im0+im2)+(im1+im3) */
        __m128 pair_hi = _mm_shuffle_ps(sum, sum, _MM_SHUFFLE(3, 2, 3, 2));
        __m128 result = _mm_add_ps(sum, pair_hi);
        /* result[0] = re_total, result[1] = im_total */

        float acc_re = _mm_cvtss_f32(result);
        float acc_im = _mm_cvtss_f32(_mm_shuffle_ps(result, result, 1));

        /* Scalar tail for remaining taps */
        for (; k < ntaps; k++) {
            acc_re += taps[k] * p[k * 2];
            acc_im += taps[k] * p[k * 2 + 1];
        }

        outp[i * 2] = acc_re;
        outp[i * 2 + 1] = acc_im;
    }
}

/* ---- Real FIR filter ----
 *
 * Process 8 outputs at a time. For each tap, broadcast coefficient,
 * load 8 input values, FMA into 8 accumulators.
 */
void avx2_fir_fff(const float *taps, int ntaps,
                   const float *in, float *out, int n) {
    int i = 0;
    /* Process 8 outputs per iteration */
    for (; i + 7 < n; i += 8) {
        __m256 acc = _mm256_setzero_ps();
        for (int k = 0; k < ntaps; k++) {
            __m256 coeff = _mm256_set1_ps(taps[k]);
            __m256 data = _mm256_loadu_ps(&in[i + k]);
            acc = _mm256_fmadd_ps(coeff, data, acc);
        }
        _mm256_storeu_ps(&out[i], acc);
    }

    /* Scalar tail */
    for (; i < n; i++) {
        float acc = 0;
        for (int k = 0; k < ntaps; k++)
            acc += taps[k] * in[i + k];
        out[i] = acc;
    }
}

/* ---- Window multiply: complex * real ----
 *
 * Load 4 complex (8 floats), duplicate 4 window values to 8 lanes
 * [w0,w0,w1,w1,w2,w2,w3,w3], multiply.
 */
void avx2_window_cf(const float complex *samples, const float *window,
                     float complex *out, int n) {
    const float *sp = (const float *)samples;
    float *op = (float *)out;
    int i = 0;

    for (; i + 3 < n; i += 4) {
        __m256 data = _mm256_loadu_ps(&sp[i * 2]);
        /* Load 4 window values and interleave: [w0,w0,w1,w1,w2,w2,w3,w3] */
        __m128 w4 = _mm_loadu_ps(&window[i]);
        __m128 lo = _mm_unpacklo_ps(w4, w4);
        __m128 hi = _mm_unpackhi_ps(w4, w4);
        __m256 coeff = _mm256_set_m128(hi, lo);
        __m256 result = _mm256_mul_ps(data, coeff);
        _mm256_storeu_ps(&op[i * 2], result);
    }

    /* Scalar tail */
    for (; i < n; i++)
        out[i] = samples[i] * window[i];
}

/* ---- fftshift + magnitude-squared ----
 *
 * Input:  fft_out[0..fft_size-1] (complex)
 * Output: mag_shifted[0..fft_size-1] (float)
 *
 * mag_shifted[i] = |fft_out[half+i]|^2  for i < half
 * mag_shifted[half+i] = |fft_out[i]|^2  for i < half
 *
 * Process 4 complex -> 4 magnitudes per iteration.
 */
void avx2_fftshift_mag(const float complex *fft_out,
                        float *mag_shifted, int fft_size) {
    int half = fft_size / 2;
    const float *fp = (const float *)fft_out;
    int i = 0;

    for (; i + 3 < half; i += 4) {
        /* Positive freqs: fft_out[half+i..half+i+3] -> mag_shifted[i..i+3] */
        __m256 pos = _mm256_loadu_ps(&fp[(half + i) * 2]);
        /* Deinterleave: [re0,im0,re1,im1,re2,im2,re3,im3] ->
         * [re0,re1,re2,re3 | im0,im1,im2,im3] */
        __m256i idx_re = _mm256_setr_epi32(0, 2, 4, 6, 1, 3, 5, 7);
        __m256 deint = _mm256_permutevar8x32_ps(pos, idx_re);
        /* deint = [re0,re1,re2,re3 | im0,im1,im2,im3] */
        __m128 re_lo = _mm256_castps256_ps128(deint);
        __m128 im_lo = _mm256_extractf128_ps(deint, 1);
        __m128 mag_pos = _mm_fmadd_ps(re_lo, re_lo,
                                       _mm_mul_ps(im_lo, im_lo));
        _mm_storeu_ps(&mag_shifted[i], mag_pos);

        /* Negative freqs: fft_out[i..i+3] -> mag_shifted[half+i..half+i+3] */
        __m256 neg = _mm256_loadu_ps(&fp[i * 2]);
        __m256 deint_n = _mm256_permutevar8x32_ps(neg, idx_re);
        __m128 re_n = _mm256_castps256_ps128(deint_n);
        __m128 im_n = _mm256_extractf128_ps(deint_n, 1);
        __m128 mag_neg = _mm_fmadd_ps(re_n, re_n,
                                       _mm_mul_ps(im_n, im_n));
        _mm_storeu_ps(&mag_shifted[half + i], mag_neg);
    }

    /* Scalar tail */
    for (; i < half; i++) {
        float re, im;
        re = crealf(fft_out[half + i]);
        im = cimagf(fft_out[half + i]);
        mag_shifted[i] = re * re + im * im;

        re = crealf(fft_out[i]);
        im = cimagf(fft_out[i]);
        mag_shifted[half + i] = re * re + im * im;
    }
}

/* ---- Baseline update: sum[i] = sum[i] - old[i] + new[i] ---- */
void avx2_baseline_update(float *sum, const float *old_hist,
                           const float *new_mag, int n) {
    int i = 0;
    for (; i + 7 < n; i += 8) {
        __m256 s = _mm256_loadu_ps(&sum[i]);
        __m256 o = _mm256_loadu_ps(&old_hist[i]);
        __m256 m = _mm256_loadu_ps(&new_mag[i]);
        s = _mm256_sub_ps(s, o);
        s = _mm256_add_ps(s, m);
        _mm256_storeu_ps(&sum[i], s);
    }
    for (; i < n; i++) {
        sum[i] -= old_hist[i];
        sum[i] += new_mag[i];
    }
}

/* ---- Relative magnitude with zero check ---- */
void avx2_relative_mag(const float *mag, const float *baseline,
                        float *out, int n) {
    __m256 zero = _mm256_setzero_ps();
    int i = 0;
    for (; i + 7 < n; i += 8) {
        __m256 m = _mm256_loadu_ps(&mag[i]);
        __m256 b = _mm256_loadu_ps(&baseline[i]);
        __m256 mask = _mm256_cmp_ps(b, zero, _CMP_GT_OQ);
        __m256 div = _mm256_div_ps(m, b);
        __m256 result = _mm256_and_ps(div, mask);
        _mm256_storeu_ps(&out[i], result);
    }
    for (; i < n; i++) {
        if (baseline[i] > 0)
            out[i] = mag[i] / baseline[i];
        else
            out[i] = 0;
    }
}

/* ---- int8 IQ -> float complex ----
 *
 * Load 16 int8 values (8 IQ pairs), sign-extend to int32,
 * convert to float, multiply by 1/128.
 */
void avx2_convert_i8_cf(const int8_t *iq, float complex *out, size_t n) {
    float *outp = (float *)out;
    __m256 scale = _mm256_set1_ps(1.0f / 128.0f);
    size_t i = 0;

    /* Process 8 complex samples (16 int8 values) per iteration */
    for (; i + 7 < n; i += 8) {
        /* Load 16 bytes (8 IQ pairs) */
        __m128i bytes = _mm_loadu_si128((const __m128i *)&iq[i * 2]);

        /* Sign-extend lower 8 bytes to 32-bit ints */
        __m128i lo8 = bytes;
        __m256i lo32 = _mm256_cvtepi8_epi32(lo8);
        __m256 lo_f = _mm256_cvtepi32_ps(lo32);
        __m256 lo_scaled = _mm256_mul_ps(lo_f, scale);
        _mm256_storeu_ps(&outp[i * 2], lo_scaled);

        /* Sign-extend upper 8 bytes */
        __m128i hi8 = _mm_srli_si128(bytes, 8);
        __m256i hi32 = _mm256_cvtepi8_epi32(hi8);
        __m256 hi_f = _mm256_cvtepi32_ps(hi32);
        __m256 hi_scaled = _mm256_mul_ps(hi_f, scale);
        _mm256_storeu_ps(&outp[(i + 4) * 2], hi_scaled);
    }

    /* Scalar tail */
    for (; i < n; i++) {
        outp[i * 2] = iq[2 * i] / 128.0f;
        outp[i * 2 + 1] = iq[2 * i + 1] / 128.0f;
    }
}

/* ---- Magnitude-squared of complex array ---- */
void avx2_mag_squared(const float complex *in, float *out, int n) {
    const float *inp = (const float *)in;
    __m256i idx_re = _mm256_setr_epi32(0, 2, 4, 6, 1, 3, 5, 7);
    int i = 0;

    for (; i + 3 < n; i += 4) {
        __m256 data = _mm256_loadu_ps(&inp[i * 2]);
        __m256 deint = _mm256_permutevar8x32_ps(data, idx_re);
        __m128 re = _mm256_castps256_ps128(deint);
        __m128 im = _mm256_extractf128_ps(deint, 1);
        __m128 mag = _mm_fmadd_ps(re, re, _mm_mul_ps(im, im));
        _mm_storeu_ps(&out[i], mag);
    }

    for (; i < n; i++) {
        float re = inp[i * 2];
        float im = inp[i * 2 + 1];
        out[i] = re * re + im * im;
    }
}

/* ---- Find max float ---- */
float avx2_max_float(const float *in, int n) {
    __m256 vmax = _mm256_set1_ps(-1e30f);
    int i = 0;
    for (; i + 7 < n; i += 8) {
        __m256 v = _mm256_loadu_ps(&in[i]);
        vmax = _mm256_max_ps(vmax, v);
    }
    /* Horizontal max */
    __m128 lo = _mm256_castps256_ps128(vmax);
    __m128 hi = _mm256_extractf128_ps(vmax, 1);
    __m128 mx = _mm_max_ps(lo, hi);
    mx = _mm_max_ps(mx, _mm_shuffle_ps(mx, mx, _MM_SHUFFLE(1, 0, 3, 2)));
    mx = _mm_max_ps(mx, _mm_shuffle_ps(mx, mx, _MM_SHUFFLE(0, 1, 0, 1)));
    float max_val = _mm_cvtss_f32(mx);
    /* Scalar tail */
    for (; i < n; i++) {
        if (in[i] > max_val) max_val = in[i];
    }
    return max_val;
}

/* ---- Complex square with window: out[i] = in[i]^2 * window[i] ----
 *
 * (a+bi)^2 = (a^2 - b^2) + (2ab)i
 * Then multiply by real window value.
 */
void avx2_csquare_window(const float complex *in, const float *window,
                          float complex *out, int n) {
    const float *inp = (const float *)in;
    float *outp = (float *)out;
    int i = 0;

    for (; i + 3 < n; i += 4) {
        __m256 data = _mm256_loadu_ps(&inp[i * 2]);
        /* data = [re0,im0,re1,im1,re2,im2,re3,im3] */

        /* Separate re and im */
        __m256i idx = _mm256_setr_epi32(0, 2, 4, 6, 1, 3, 5, 7);
        __m256 deint = _mm256_permutevar8x32_ps(data, idx);
        __m128 re = _mm256_castps256_ps128(deint);     /* [re0,re1,re2,re3] */
        __m128 im = _mm256_extractf128_ps(deint, 1);   /* [im0,im1,im2,im3] */

        /* sq_re = re*re - im*im */
        __m128 re2 = _mm_mul_ps(re, re);
        __m128 im2 = _mm_mul_ps(im, im);
        __m128 sq_re = _mm_sub_ps(re2, im2);

        /* sq_im = 2*re*im */
        __m128 two = _mm_set1_ps(2.0f);
        __m128 sq_im = _mm_mul_ps(two, _mm_mul_ps(re, im));

        /* Multiply by window */
        __m128 w = _mm_loadu_ps(&window[i]);
        sq_re = _mm_mul_ps(sq_re, w);
        sq_im = _mm_mul_ps(sq_im, w);

        /* Interleave back: [sq_re0, sq_im0, sq_re1, sq_im1, ...] */
        __m128 lo = _mm_unpacklo_ps(sq_re, sq_im);
        __m128 hi = _mm_unpackhi_ps(sq_re, sq_im);
        _mm_storeu_ps(&outp[i * 2], lo);
        _mm_storeu_ps(&outp[i * 2 + 4], hi);
    }

    for (; i < n; i++) {
        float a = inp[i * 2];
        float b = inp[i * 2 + 1];
        outp[i * 2] = (a * a - b * b) * window[i];
        outp[i * 2 + 1] = (2.0f * a * b) * window[i];
    }
}

/* ---- Frequency rotation ---- */

/* Same operations in the same order as generic_rotate (mul then
 * add/sub, no FMA), so the output is bit-identical. Eight samples per
 * block: two vectors of four interleaved complex values. Contraction is
 * off for this function: under LTO, GCC otherwise fuses the scalar phase
 * updates into FMAs even with -std=c99. */
#if defined(__GNUC__) && !defined(__clang__)
__attribute__((optimize("fp-contract=off")))
#endif
void avx2_rotate(float complex *out, const float complex *in, int n,
                 float complex *phase, float complex incr) {
#if defined(__clang__)
#pragma STDC FP_CONTRACT OFF
#endif
    float s[2 * ROTATOR_BLOCK];
    float complex p = 1.0f;
    for (int k = 0; k < ROTATOR_BLOCK; k++) {
        s[2 * k] = crealf(p);
        s[2 * k + 1] = cimagf(p);
        p *= incr;
    }
    float complex block_incr = p;
    float complex ph = *phase;

    const __m256 s0 = _mm256_loadu_ps(s);
    const __m256 s1 = _mm256_loadu_ps(s + 8);
    const __m256 s0x = _mm256_permute_ps(s0, 0xB1);
    const __m256 s1x = _mm256_permute_ps(s1, 0xB1);

    const float *x = (const float *)in;
    float *y = (float *)out;
    int i = 0;
    for (; i + ROTATOR_BLOCK <= n; i += ROTATOR_BLOCK) {
        __m256 pr = _mm256_set1_ps(crealf(ph));
        __m256 pi = _mm256_set1_ps(cimagf(ph));
        /* w = phase * step: (pr*sr - pi*si, pr*si + pi*sr) */
        __m256 w0 = _mm256_addsub_ps(_mm256_mul_ps(pr, s0), _mm256_mul_ps(pi, s0x));
        __m256 w1 = _mm256_addsub_ps(_mm256_mul_ps(pr, s1), _mm256_mul_ps(pi, s1x));
        __m256 x0 = _mm256_loadu_ps(x + 2 * i);
        __m256 x1 = _mm256_loadu_ps(x + 2 * i + 8);
        /* y = x * w: (xr*wr - xi*wi, xr*wi + xi*wr) */
        __m256 y0 = _mm256_addsub_ps(
            _mm256_mul_ps(_mm256_moveldup_ps(x0), w0),
            _mm256_mul_ps(_mm256_movehdup_ps(x0), _mm256_permute_ps(w0, 0xB1)));
        __m256 y1 = _mm256_addsub_ps(
            _mm256_mul_ps(_mm256_moveldup_ps(x1), w1),
            _mm256_mul_ps(_mm256_movehdup_ps(x1), _mm256_permute_ps(w1, 0xB1)));
        _mm256_storeu_ps(y + 2 * i, y0);
        _mm256_storeu_ps(y + 2 * i + 8, y1);

        ph *= block_incr;
        if ((i & (64 * ROTATOR_BLOCK - 1)) == 0) {
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
