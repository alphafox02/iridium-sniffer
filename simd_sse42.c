/*
 * SSE4.2 SIMD kernel implementations
 *
 * This file is compiled with -msse4.2 flags.
 * All functions match the signatures in simd_kernels.h.
 *
 * Complex float layout: interleaved [re0, im0, re1, im1, ...]
 * SSE __m128 holds 4 floats = 2 complex values.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <smmintrin.h>  /* SSE4.1 */
#include <nmmintrin.h>  /* SSE4.2 */
#include <complex.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "simd_kernels.h"

/* ---- Complex FIR filter (real taps * complex input) ----
 *
 * Strategy: Process 2 complex outputs at a time.
 * For each tap k, broadcast taps[k] to all 4 lanes,
 * load 2 complex inputs [i+k..i+k+1], multiply-add into accumulator.
 */
void sse42_fir_ccf(const float *taps, int ntaps,
                   const float complex *in, float complex *out, int n) {
    const float *inp = (const float *)in;
    float *outp = (float *)out;

    int i = 0;
    /* Process 2 complex outputs per iteration */
    for (; i + 1 < n; i += 2) {
        __m128 acc = _mm_setzero_ps();
        for (int k = 0; k < ntaps; k++) {
            __m128 coeff = _mm_set1_ps(taps[k]);
            __m128 data = _mm_loadu_ps(&inp[(i + k) * 2]);
            acc = _mm_add_ps(acc, _mm_mul_ps(coeff, data));
        }
        _mm_storeu_ps(&outp[i * 2], acc);
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
 * Vectorize inner tap loop: process 2 taps at a time
 * (each tap applied to 1 complex = 2 floats, 2 taps = 4 floats = 1 __m128).
 */
void sse42_fir_ccf_dec(const float *taps, int ntaps,
                       const float complex *in, float complex *out,
                       int n_out, int decimation) {
    const float *inp = (const float *)in;
    float *outp = (float *)out;

    for (int i = 0; i < n_out; i++) {
        const float *p = &inp[i * decimation * 2];
        __m128 acc = _mm_setzero_ps();
        int k = 0;

        /* Process 2 taps at a time (2 complex values = 4 floats) */
        for (; k + 1 < ntaps; k += 2) {
            __m128 data = _mm_loadu_ps(&p[k * 2]);
            /* Interleave coefficients: [t0,t0,t1,t1] */
            __m128 t2 = _mm_set_ps(taps[k + 1], taps[k + 1],
                                   taps[k], taps[k]);
            acc = _mm_add_ps(acc, _mm_mul_ps(t2, data));
        }

        /* Horizontal sum of 2 complex accumulators -> 1 complex result */
        /* acc = [re0,im0,re1,im1] */
        __m128 pair_hi = _mm_shuffle_ps(acc, acc, _MM_SHUFFLE(3, 2, 3, 2));
        __m128 result = _mm_add_ps(acc, pair_hi);
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
 * Process 4 outputs at a time. For each tap, broadcast coefficient,
 * load 4 input values, multiply-add into 4 accumulators.
 */
void sse42_fir_fff(const float *taps, int ntaps,
                   const float *in, float *out, int n) {
    int i = 0;
    /* Process 4 outputs per iteration */
    for (; i + 3 < n; i += 4) {
        __m128 acc = _mm_setzero_ps();
        for (int k = 0; k < ntaps; k++) {
            __m128 coeff = _mm_set1_ps(taps[k]);
            __m128 data = _mm_loadu_ps(&in[i + k]);
            acc = _mm_add_ps(acc, _mm_mul_ps(coeff, data));
        }
        _mm_storeu_ps(&out[i], acc);
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
 * Load 2 complex (4 floats), duplicate 2 window values to 4 lanes
 * [w0,w0,w1,w1], multiply.
 */
void sse42_window_cf(const float complex *samples, const float *window,
                     float complex *out, int n) {
    const float *sp = (const float *)samples;
    float *op = (float *)out;
    int i = 0;

    for (; i + 1 < n; i += 2) {
        __m128 data = _mm_loadu_ps(&sp[i * 2]);
        /* Duplicate window values: [w0,w0,w1,w1] */
        __m128 w2 = _mm_set_ps(window[i + 1], window[i + 1],
                               window[i], window[i]);
        __m128 result = _mm_mul_ps(data, w2);
        _mm_storeu_ps(&op[i * 2], result);
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
 * Process 2 complex -> 2 magnitudes per iteration.
 */
void sse42_fftshift_mag(const float complex *fft_out,
                        float *mag_shifted, int fft_size) {
    int half = fft_size / 2;
    const float *fp = (const float *)fft_out;
    int i = 0;

    for (; i + 1 < half; i += 2) {
        /* Positive freqs: fft_out[half+i..half+i+1] -> mag_shifted[i..i+1] */
        __m128 pos = _mm_loadu_ps(&fp[(half + i) * 2]);
        /* pos = [re0,im0,re1,im1] */
        /* Deinterleave to [re0,re1,im0,im1] */
        __m128 re = _mm_shuffle_ps(pos, pos, _MM_SHUFFLE(2, 0, 2, 0));
        __m128 im = _mm_shuffle_ps(pos, pos, _MM_SHUFFLE(3, 1, 3, 1));
        __m128 mag_pos = _mm_add_ps(_mm_mul_ps(re, re), _mm_mul_ps(im, im));
        /* Store lower 2 floats (only 2 magnitudes valid) */
        _mm_store_sd((double *)&mag_shifted[i],
                     _mm_castps_pd(mag_pos));

        /* Negative freqs: fft_out[i..i+1] -> mag_shifted[half+i..half+i+1] */
        __m128 neg = _mm_loadu_ps(&fp[i * 2]);
        __m128 re_n = _mm_shuffle_ps(neg, neg, _MM_SHUFFLE(2, 0, 2, 0));
        __m128 im_n = _mm_shuffle_ps(neg, neg, _MM_SHUFFLE(3, 1, 3, 1));
        __m128 mag_neg = _mm_add_ps(_mm_mul_ps(re_n, re_n),
                                    _mm_mul_ps(im_n, im_n));
        _mm_store_sd((double *)&mag_shifted[half + i],
                     _mm_castps_pd(mag_neg));
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
void sse42_baseline_update(float *sum, const float *old_hist,
                           const float *new_mag, int n) {
    int i = 0;
    for (; i + 3 < n; i += 4) {
        __m128 s = _mm_loadu_ps(&sum[i]);
        __m128 o = _mm_loadu_ps(&old_hist[i]);
        __m128 m = _mm_loadu_ps(&new_mag[i]);
        s = _mm_sub_ps(s, o);
        s = _mm_add_ps(s, m);
        _mm_storeu_ps(&sum[i], s);
    }
    for (; i < n; i++) {
        sum[i] -= old_hist[i];
        sum[i] += new_mag[i];
    }
}

/* ---- Relative magnitude with zero check ---- */
void sse42_relative_mag(const float *mag, const float *baseline,
                        float *out, int n) {
    __m128 zero = _mm_setzero_ps();
    int i = 0;
    for (; i + 3 < n; i += 4) {
        __m128 m = _mm_loadu_ps(&mag[i]);
        __m128 b = _mm_loadu_ps(&baseline[i]);
        __m128 mask = _mm_cmpgt_ps(b, zero);
        __m128 div = _mm_div_ps(m, b);
        __m128 result = _mm_and_ps(div, mask);
        _mm_storeu_ps(&out[i], result);
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
 * Load 8 int8 values (4 IQ pairs), sign-extend to int32,
 * convert to float, multiply by 1/128.
 */
void sse42_convert_i8_cf(const int8_t *iq, float complex *out, size_t n) {
    float *outp = (float *)out;
    __m128 scale = _mm_set1_ps(1.0f / 128.0f);
    size_t i = 0;

    /* Process 4 complex samples (8 int8 values) per iteration */
    for (; i + 3 < n; i += 4) {
        /* Load 8 bytes (4 IQ pairs) into lower 64 bits */
        __m128i bytes = _mm_loadl_epi64((const __m128i *)&iq[i * 2]);

        /* Sign-extend 8 bytes to 16-bit, then to 32-bit */
        __m128i i16 = _mm_cvtepi8_epi16(bytes);
        __m128i lo32 = _mm_cvtepi16_epi32(i16);
        __m128i hi16 = _mm_srli_si128(i16, 8);
        __m128i hi32 = _mm_cvtepi16_epi32(hi16);

        __m128 lo_f = _mm_cvtepi32_ps(lo32);
        __m128 lo_scaled = _mm_mul_ps(lo_f, scale);
        _mm_storeu_ps(&outp[i * 2], lo_scaled);

        __m128 hi_f = _mm_cvtepi32_ps(hi32);
        __m128 hi_scaled = _mm_mul_ps(hi_f, scale);
        _mm_storeu_ps(&outp[(i + 2) * 2], hi_scaled);
    }

    /* Scalar tail */
    for (; i < n; i++) {
        outp[i * 2] = iq[2 * i] / 128.0f;
        outp[i * 2 + 1] = iq[2 * i + 1] / 128.0f;
    }
}

/* ---- Magnitude-squared of complex array ---- */
void sse42_mag_squared(const float complex *in, float *out, int n) {
    const float *inp = (const float *)in;
    int i = 0;

    for (; i + 1 < n; i += 2) {
        __m128 data = _mm_loadu_ps(&inp[i * 2]);
        /* data = [re0,im0,re1,im1] */
        __m128 re = _mm_shuffle_ps(data, data, _MM_SHUFFLE(2, 0, 2, 0));
        __m128 im = _mm_shuffle_ps(data, data, _MM_SHUFFLE(3, 1, 3, 1));
        __m128 mag = _mm_add_ps(_mm_mul_ps(re, re), _mm_mul_ps(im, im));
        /* Store lower 2 floats */
        _mm_store_sd((double *)&out[i], _mm_castps_pd(mag));
    }

    for (; i < n; i++) {
        float re = inp[i * 2];
        float im = inp[i * 2 + 1];
        out[i] = re * re + im * im;
    }
}

/* ---- Find max float ---- */
float sse42_max_float(const float *in, int n) {
    __m128 vmax = _mm_set1_ps(-1e30f);
    int i = 0;
    for (; i + 3 < n; i += 4) {
        __m128 v = _mm_loadu_ps(&in[i]);
        vmax = _mm_max_ps(vmax, v);
    }
    /* Horizontal max */
    __m128 mx = vmax;
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
 *
 * Process 2 complex at a time.
 */
void sse42_csquare_window(const float complex *in, const float *window,
                          float complex *out, int n) {
    const float *inp = (const float *)in;
    float *outp = (float *)out;
    int i = 0;

    for (; i + 1 < n; i += 2) {
        __m128 data = _mm_loadu_ps(&inp[i * 2]);
        /* data = [re0,im0,re1,im1] */

        /* Separate re and im */
        __m128 re = _mm_shuffle_ps(data, data, _MM_SHUFFLE(2, 0, 2, 0));
        __m128 im = _mm_shuffle_ps(data, data, _MM_SHUFFLE(3, 1, 3, 1));

        /* sq_re = re*re - im*im */
        __m128 re2 = _mm_mul_ps(re, re);
        __m128 im2 = _mm_mul_ps(im, im);
        __m128 sq_re = _mm_sub_ps(re2, im2);

        /* sq_im = 2*re*im */
        __m128 two = _mm_set1_ps(2.0f);
        __m128 sq_im = _mm_mul_ps(two, _mm_mul_ps(re, im));

        /* Multiply by window (match deinterleaved layout: [i, i+1, i, i+1]) */
        __m128 w = _mm_set_ps(window[i + 1], window[i],
                              window[i + 1], window[i]);
        sq_re = _mm_mul_ps(sq_re, w);
        sq_im = _mm_mul_ps(sq_im, w);

        /* Interleave back: [sq_re0, sq_im0, sq_re1, sq_im1] */
        __m128 lo = _mm_unpacklo_ps(sq_re, sq_im);
        _mm_storeu_ps(&outp[i * 2], lo);
    }

    for (; i < n; i++) {
        float a = inp[i * 2];
        float b = inp[i * 2 + 1];
        outp[i * 2] = (a * a - b * b) * window[i];
        outp[i * 2 + 1] = (2.0f * a * b) * window[i];
    }
}

/* ---- Threshold scan ---- */

int sse42_find_above(const float *x, int n, float thr, int *idx) {
    const __m128 t = _mm_set1_ps(thr);
    int c = 0, i = 0;
    for (; i + 4 <= n; i += 4) {
        unsigned m = (unsigned)_mm_movemask_ps(
            _mm_cmpgt_ps(_mm_loadu_ps(x + i), t));
        while (m) {
            idx[c++] = i + __builtin_ctz(m);
            m &= m - 1;
        }
    }
    for (; i < n; i++)
        if (x[i] > thr)
            idx[c++] = i;
    return c;
}
